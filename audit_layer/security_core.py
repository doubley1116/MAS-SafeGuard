"""
SecurityCore — MAS 审核中间层
接收 AuditEvent，对照 YAML 权限策略，返回 AuditDecision

审核流程：
  1. 规则引擎：工具调用者校验 + 消息路径校验 → 计算 rule_score
  2. 根据 rule_score 分流：
     - rule_score >= rule_block(0.90) → 直接拦截，不走 LLM
     - rule_score <  rule_block(0.90) → 全部进入 LLM 语义审核
  3. LLM 审核返回 AuditDecision，综合规则分和 LLM 分给出最终决策
"""

from __future__ import annotations
import yaml
from typing import List
from audit_layer.utils.policy_loader import PolicyLoader
from audit_layer.rule_engine import RuleEngine
from audit_layer.audit_models import AuditEvent, AuditDecision
from audit_layer.llm_reviewer import LLMReviewer
# ══════════════════════════════════════════════════════════════
# SecurityCore 主入口
# ══════════════════════════════════════════════════════════════

class SecurityCore:
    def __init__(self, yaml_path: str):
        self.policy = PolicyLoader(yaml_path)
        self.rule_engine = RuleEngine(self.policy)
        self.llm_reviewer = LLMReviewer()

    def audit(self, event: AuditEvent) -> AuditDecision:
        """主审核入口，对外暴露的唯一方法。"""
        rule_score, risk_types, rule_reason = self.rule_engine.evaluate(event)

        t_block = self.policy.threshold("rule_block")   # 0.90

        # ── 分支 A：规则引擎直接拦截（高置信度违规，无需 LLM 确认）──
        if rule_score >= t_block:
            return AuditDecision(
                allow=False,
                risk_score=rule_score,
                reason=f"[规则拦截] {rule_reason}",
                blocking_risk_types=risk_types,
            )

        # ── 分支 B：所有未被规则拦截的事件，均进入 LLM 语义审核 ──
        llm_decision = self.llm_reviewer.review(event, rule_risk_types=risk_types)

        # 将规则引擎的信息补充到 LLM 决策中
        if risk_types:
            merged_types = list(set(risk_types + llm_decision.blocking_risk_types))
            llm_decision.blocking_risk_types = merged_types

        # 在 reason 中附加规则引擎的上下文
        llm_decision.reason = (
            f"规则分={rule_score:.2f} → {llm_decision.reason}"
        )

        return llm_decision

