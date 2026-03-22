"""
SecurityCore — MAS 审核中间层
接收 AuditEvent，对照 YAML 权限策略，返回 AuditDecision

审核流程：
  1. 规则引擎：工具调用者校验 + 消息路径校验 → 计算 rule_score
  2. 根据 thresholds 分流：
     - rule_score >= rule_block(0.90) → 直接拦截
     - rule_score >= llm_needed(0.40) → TODO: LLM 语义审核（当前返回占位）
     - rule_score <  pass(0.40)       → 直接放行
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
        t_llm   = self.policy.threshold("llm_needed")   # 0.40
        t_human = self.policy.threshold("human_review") # 0.75（无此字段时为 0）

        # 分支 A：规则引擎直接拦截
        if rule_score >= t_block:
            return AuditDecision(
                allow=False,
                risk_score=rule_score,
                reason=f"[规则拦截] {rule_reason}",
                blocking_risk_types=risk_types,
            )

        # 分支 B：进入 LLM 语义审核
        if rule_score >= t_llm:
            llm_score, llm_reason = self.llm_reviewer.review(event)

            # B-1：LLM 判定高风险，转人工
            if t_human > 0 and llm_score >= t_human:
                return AuditDecision(
                    allow=False,
                    risk_score=llm_score,
                    reason=f"[人工审核] 规则分={rule_score:.2f} → LLM分={llm_score:.2f}，{llm_reason}",
                    blocking_risk_types=risk_types,
                    suggested_alternative="请联系合规人员人工审核此操作",
                )

            # B-2：LLM 判定低风险，放行
            return AuditDecision(
                allow=True,
                risk_score=llm_score,
                reason=f"[LLM放行] 规则分={rule_score:.2f} → LLM分={llm_score:.2f}，{llm_reason}",
            )

        # 分支 C：规则分低，直接放行
        return AuditDecision(
            allow=True,
            risk_score=rule_score,
            reason=f"[规则放行] 风险分={rule_score:.2f}，未命中任何规则",
        )

