"""
SecurityCore — MAS 审核中间层
接收 AuditEvent，对照 YAML 权限策略，返回 AuditDecision

审核流程：
  1. 规则引擎 + 角色引擎：结构校验 → rule_score / risk_types
  2. 全部经 LLM 语义审核 + EWMA 融合（不走规则直拦分支）
  3. 规则分作为加权信号参与最终融合决策

增强能力:
  - 角色引擎: 基于通信图拓扑自动发现角色，校验角色序列和邻接合法性
  - 轨迹监控: 基于 EMA 自适应阈值的轻量轨迹异常检测（类比 PID 控制器）
  - 在线学习: 确认正常的 call_path 自动更新 EMA 基线，越用越准
  - 分数融合: llm_score 与 trajectory_score 按路径深度动态加权
"""

from __future__ import annotations

import os
import pickle
from typing import Optional

from audit_layer.utils.policy_loader import PolicyLoader
from audit_layer.rule_engine import RuleEngine
from audit_layer.audit_models import AuditEvent, AuditDecision
from audit_layer.llm_reviewer import LLMReviewer

# 可选依赖：仅在使用相应功能时才需要
try:
    from audit_layer.role_discovery import RoleDiscovery
    from audit_layer.role_engine import RoleEngine
    HAS_ROLE_ENGINE = True
except ImportError:
    HAS_ROLE_ENGINE = False

try:
    from audit_layer.trajectory_model import TrajectoryAnomalyDetector
    HAS_TRAJECTORY = True
except ImportError:
    HAS_TRAJECTORY = False


class SecurityCore:
    """
    MAS 安全审核中间层。

    用法（基础）:
        core = SecurityCore("policy.yaml")
        decision = core.audit(event)

    用法（完整）:
        core = SecurityCore(
            "policy.yaml",
            role_discovery_path="audit_layer/roles/",
            trajectory_detector_path="audit_layer/trajectory_checkpoints/detector.pkl",
        )
        decision = core.audit(event)
    """

    def __init__(
        self,
        yaml_path: str,
        system_prompt: str | None = None,
        user_prompt_template: str | None = None,
        threshold_overrides: dict[str, float] | None = None,
        llm_reviewer=None,
        # 角色引擎
        role_discovery_path: Optional[str] = None,
        role_adjacency: Optional[dict[str, list[str]]] = None,
        # 轨迹检测（EMA 轻量版）
        trajectory_detector_path: Optional[str] = None,
        trajectory_detector: Optional[object] = None,  # 预训练的 TrajectoryAnomalyDetector 实例
        trajectory_online_learning: bool = True,
    ):
        self.policy = PolicyLoader(yaml_path)
        if threshold_overrides:
            self.policy._policy.setdefault("thresholds", {}).update(threshold_overrides)
        self.rule_engine = RuleEngine(self.policy)

        # ── 角色引擎（可选）──
        self.role_engine: Optional[RoleEngine] = None
        self._role_discovery: Optional[RoleDiscovery] = None
        if role_discovery_path and HAS_ROLE_ENGINE:
            self._role_discovery = RoleDiscovery.load(role_discovery_path)
            self.role_engine = RoleEngine(
                self._role_discovery, role_adjacency=role_adjacency
            )
        elif role_adjacency and HAS_ROLE_ENGINE:
            self.role_engine = RoleEngine(role_adjacency=role_adjacency)

        # ── LLM 审核器 ──
        if llm_reviewer is not None:
            self.llm_reviewer = llm_reviewer
        else:
            self.llm_reviewer = LLMReviewer(
                system_prompt=system_prompt,
                user_prompt_template=user_prompt_template,
            )

        # ── 轨迹检测器（EMA 轻量版，可选）──
        self.trajectory_detector: Optional[TrajectoryAnomalyDetector] = None
        self._trajectory_online = trajectory_online_learning

        if trajectory_detector is not None and HAS_TRAJECTORY:
            self.trajectory_detector = trajectory_detector
        elif trajectory_detector_path and HAS_TRAJECTORY:
            self._load_trajectory_detector(trajectory_detector_path)

        # ── Trace 级学习状态 ──
        # 策略：一个 trace 中只要有一个事件异常，整条 trace 的 call_path 都不学习
        self._trace_buffer: list = []        # 待学习的 call_path 列表
        self._trace_clean: bool = True       # 当前 trace 是否有异常
        self._current_trace_id: str = ""     # 用于检测 trace 边界

        # ── 分层门控阈值 ──
        # 每层独立门槛，基于实验测定的精度-召回特性:
        #   Rule: 0.50 (FP=0%, 命中即确信)
        #   EWMA: 0.35 (连续谱打分天生保守, 降门槛换召回)
        #   LLM:  0.50 (语义检测标准门槛)
        self._rule_threshold: float = threshold_overrides.get("rule_threshold", 0.50) if threshold_overrides else 0.50
        self._ewma_threshold: float = threshold_overrides.get("ewma_threshold", 0.35) if threshold_overrides else 0.35
        self._llm_threshold: float = threshold_overrides.get("llm_threshold", 0.50) if threshold_overrides else 0.50

        # ── 层开关（用于消融实验）──
        self._enable_rule: bool = True
        self._enable_ewma: bool = True
        self._enable_llm: bool = True

    # ══════════════════════════════════════════════════════════
    # 主审核入口
    # ══════════════════════════════════════════════════════════

    def audit(self, event: AuditEvent) -> AuditDecision:
        """主审核入口 — 分层门控架构。

        三层独立判决，任意一层触发即拦截:
          Layer 1 (Rule):  score >= 0.50 → BLOCK (0% FP, 命中即确信)
          Layer 2 (EWMA):  score >= 0.35 → BLOCK (连续谱, 较低门槛补偿保守打分)
          Layer 3 (LLM):   score >= 0.50 → BLOCK (语义检测, 标准门槛)
        """
        # ── Trace 边界检测 ──
        if event.trace_id and event.trace_id != self._current_trace_id:
            self._flush_trace()
            self._current_trace_id = event.trace_id
            self._trace_clean = True
            self._trace_buffer = []

        # ── 剥离基础设施节点（与 EWMA 预热/推理保持一致）──
        # 拓扑一致性由预热数据预处理保证：
        # - trading/healthcare/ecommerce: 预热保留 Router（测试数据含 Router）
        # - iov/converged_media: 预热剥离 Router（测试数据几乎无 Router）
        # Tool_Node 不在任何测试数据或预热数据中出现，保留安全剥离。
        clean_path = [n for n in (event.call_path or []) if n not in self._INFRA_NODES]
        if clean_path != event.call_path:
            event = event.with_call_path(clean_path)

        rule_score, risk_types, rule_reason = self.rule_engine.evaluate(event)

        # ── 角色引擎评分（如果启用）──
        if self.role_engine and event.call_path:
            role_score, role_types, role_reason = self.role_engine.evaluate(
                event.call_path,
                tool_name=event.tool_name,
                depth_constraints=self._get_depth_constraints(),
            )
            if role_score > rule_score:
                rule_score = role_score
            if role_types:
                risk_types = list(set(risk_types + role_types))
            if role_reason and rule_score > 0:
                rule_reason = f"{rule_reason} | [角色] {role_reason}"

        # ── LLM 语义审核 ──
        llm_decision = self.llm_reviewer.review(event, rule_risk_types=risk_types)

        if risk_types:
            merged_types = list(set(risk_types + llm_decision.blocking_risk_types))
            llm_decision.blocking_risk_types = merged_types

        # ── 轨迹评分 ──
        trajectory_score = self._compute_trajectory_score(event)
        llm_decision.trajectory_score = round(trajectory_score, 4) if trajectory_score is not None else None

        # ── 分层门控（per-layer thresholds + 消融开关）──
        trigger_layer = None

        # Layer 1: 规则引擎 — 0% FP, 命中直接拦截
        if self._enable_rule and rule_score >= self._rule_threshold:
            trigger_layer = "R"
            llm_decision.risk_score = round(rule_score, 4)
            llm_decision.blocking_risk_types = list(set(
                llm_decision.blocking_risk_types + risk_types
            ))
            llm_decision.reason = (
                f"[R 拦截] {rule_reason} | 规则分={rule_score:.2f}"
            )
            if trajectory_score is not None:
                llm_decision.reason += f" | 轨迹分={trajectory_score:.2f}"

        # Layer 2: EWMA 轨迹检测 — 较低门槛补偿保守打分
        elif (self._enable_ewma
              and trajectory_score is not None
              and trajectory_score >= self._ewma_threshold):
            trigger_layer = "E"
            llm_decision.risk_score = round(trajectory_score, 4)
            llm_decision.reason = (
                f"[E 拦截] 轨迹异常 | 轨迹分={trajectory_score:.2f}"
                f" (阈值={self._ewma_threshold})"
            )
            if rule_score > 0:
                llm_decision.reason += f" | 规则分={rule_score:.2f}"

        # Layer 3: LLM 语义审核
        elif self._enable_llm and llm_decision.risk_score >= self._llm_threshold:
            trigger_layer = "L"
            llm_decision.reason = (
                f"[L 拦截] {llm_decision.reason}"
                f" | 规则分={rule_score:.2f}"
            )
            if trajectory_score is not None:
                llm_decision.reason += f" | 轨迹分={trajectory_score:.2f}"

        else:
            trigger_layer = "-"
            llm_decision.risk_score = round(
                max(rule_score, llm_decision.risk_score,
                    trajectory_score or 0.0), 4
            )
            llm_decision.reason = (
                f"[放行] 规则分={rule_score:.2f}"
                f" | LLM分={llm_decision.risk_score:.2f}"
            )
            if trajectory_score is not None:
                llm_decision.reason += f" | 轨迹分={trajectory_score:.2f}"

        # ── 执行判决 ──
        if trigger_layer != "-":
            llm_decision.allow = False
            self._trace_clean = False
        else:
            self._maybe_learn(event)

        return llm_decision
    # ══════════════════════════════════════════════════════════
    # 轨迹评分
    # ══════════════════════════════════════════════════════════

    # ── 基础设施节点 — Router 不再在此剥离，拓扑一致性由预热数据预处理保证 ──
    _INFRA_NODES = {"Tool_Node"}

    def _compute_trajectory_score(self, event: AuditEvent) -> Optional[float]:
        """
        对当前事件的 call_path 做轨迹异常评分。

        call_path 本身就是一条轨迹——它记录了从入口到当前节点的
        完整路由链。EWMA 检测器直接对它打分。
        """
        if self.trajectory_detector is None:
            return None

        # 剥离基础设施节点，与 warmup 预处理对齐
        path = [n for n in (event.call_path or []) if n not in self._INFRA_NODES]
        if len(path) < 2:
            return None

        return self.trajectory_detector.score(path)

    def _maybe_learn(self, event: AuditEvent) -> None:
        """
        将当前事件的 call_path 加入 trace 缓冲区。
        实际学习在 _flush_trace() 中执行：只有整条 trace 无异常时才提交。
        """
        if not self._trajectory_online:
            return
        if self.trajectory_detector is None:
            return
        if not event.call_path or len(event.call_path) < 2:
            return
        self._trace_buffer.append(event.call_path)

    def _flush_trace(self) -> None:
        """提交或丢弃当前 trace 的缓冲区。只有无异常的 trace 才学习。"""
        if self._trace_clean and self._trace_buffer and self.trajectory_detector:
            for cp in self._trace_buffer:
                self.trajectory_detector.observe(cp)
        self._trace_buffer = []
        self._trace_clean = True

    def flush_trace(self) -> None:
        """外部接口：显式 flush 当前 trace（adapter 在场景结束时调用）。"""
        self._flush_trace()

    def _compute_alpha(self, path_len: int) -> float:
        """
        动态计算 LLM 分数的权重 α。

        call_path 越长 → 轨迹信息越丰富 → 轨迹分权重越高。

          len <= 2: α = 0.9  (几乎完全信任 LLM)
          len 3~4:  α = 0.6
          len 5~7:  α = 0.4
          len > 7:  α = 0.25 (轨迹模式非常可靠)
        """
        if path_len <= 2:
            return 0.9
        elif path_len <= 4:
            return 0.6
        elif path_len <= 7:
            return 0.4
        else:
            return 0.25

    # ══════════════════════════════════════════════════════════
    # 轨迹检测器加载
    # ══════════════════════════════════════════════════════════

    def _load_trajectory_detector(self, path: str) -> None:
        """加载 EMA 轨迹检测器（pickle 格式）."""
        self.trajectory_detector = TrajectoryAnomalyDetector.load(
            path,
            role_discovery=self._role_discovery,
        )

    def save_trajectory_detector(self, path: str) -> None:
        """保存当前轨迹检测器状态到文件。"""
        if self.trajectory_detector is None:
            raise ValueError("没有轨迹检测器可保存")
        self.trajectory_detector.save(path)

    def warmup_trajectory_detector(self, call_paths: list[list[str]]) -> None:
        """用一批正常 call_path 预热轨迹检测器。

        如果检测器尚不存在则自动创建。两趟预热：
        1. 收集所有 agent→agent 转移边
        2. 逐条更新 EWMA 基线
        3. 为 novel_edge_ratio 设置最小方差
        """
        if self.trajectory_detector is None:
            if not HAS_TRAJECTORY:
                return
            self.trajectory_detector = TrajectoryAnomalyDetector(
                role_discovery=self._role_discovery,
            )
        self.trajectory_detector.fit_normal(call_paths)

    def _get_depth_constraints(self) -> dict[str, tuple[int, int]]:
        """从 YAML policy 读取路径深度约束."""
        raw = self.policy.depth_constraints
        return {
            tool: (int(rule["min"]), int(rule["max"]))
            for tool, rule in raw.items()
            if "min" in rule and "max" in rule
        }

    # ══════════════════════════════════════════════════════════
    # 调试与监控
    # ══════════════════════════════════════════════════════════

    def get_trajectory_summary(self) -> Optional[str]:
        """获取轨迹检测器的基线摘要."""
        if self.trajectory_detector is None:
            return None
        return self.trajectory_detector.summary()

    def get_trajectory_observation_count(self) -> int:
        """获取轨迹检测器已学习的正常样本数."""
        if self.trajectory_detector is None:
            return 0
        return self.trajectory_detector.observation_count
