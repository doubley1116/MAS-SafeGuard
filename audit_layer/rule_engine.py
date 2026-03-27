from typing import List
from audit_layer.utils.policy_loader import PolicyLoader
from audit_layer.audit_models import AuditEvent
class RuleEngine:
    """
    只做结构性校验，不做语义判断。
    每条规则命中返回 (score, risk_type, reason)。
    最终 rule_score = 所有命中规则中的最高分（取最严）。
    """

    def __init__(self, policy: PolicyLoader):
        self.policy = policy

    def evaluate(self, event: AuditEvent) -> tuple[float, List[str], str]:
        hits: List[tuple[float, str, str]] = []

        if event.event_type == "tool_call":
            hits += self._check_tool_caller(event)
            hits += self._check_required_path(event)
            hits += self._check_path_rule(event)
            hits += self._check_strict_path(event)
            hits += self._check_blocked_tools(event)
            hits += self._check_intent_confidence_required(event)
            hits += self._check_route_hijack(event)

        elif event.event_type == "message":
            hits += self._check_message_target(event)

        if not hits:
            return 0.0, [], "规则引擎未命中任何规则"

        rule_score = max(h[0] for h in hits)
        risk_types = list({h[1] for h in hits})
        reasons = " | ".join(h[2] for h in hits)

        return rule_score, risk_types, reasons

    # ── 辅助：从 call_path 中去掉末尾的工具名，得到纯 agent 路径 ──

    def _agent_path(self, event: AuditEvent) -> List[str]:
        path = list(event.call_path or [])
        if path and event.tool_name and path[-1] == event.tool_name:
            path = path[:-1]
        return path

    # ── 规则1：工具调用者必须在 allowed_callers 内 ──────────────────

    def _check_tool_caller(self, event: AuditEvent) -> List[tuple]:
        tool_policy = self.policy.get_tool(event.tool_name or "")
        if not tool_policy:
            return []
        allowed_callers = tool_policy.get("allowed_callers", [])
        if allowed_callers and event.sender not in allowed_callers:
            return [(
                0.95,
                "unauthorized_tool_caller",
                f"{event.sender} 无权调用 {event.tool_name}，允许调用方：{allowed_callers}"
            )]
        return []

    # ── 规则2：call_path 必须包含 required_path_contains 中的所有节点 ──

    def _check_required_path(self, event: AuditEvent) -> List[tuple]:
        tool_policy = self.policy.get_tool(event.tool_name or "")
        if not tool_policy:
            return []
        required = tool_policy.get("required_path_contains", [])
        missing = [node for node in required if node not in event.call_path]
        if missing:
            return [(
                0.92,
                "missing_required_path_node",
                f"调用 {event.tool_name} 前缺少必经节点：{missing}，当前路径：{event.call_path}"
            )]
        return []

    # ── 规则3：Agent 的 blocked_tools 不得被调用 ────────────────────

    def _check_blocked_tools(self, event: AuditEvent) -> List[tuple]:
        agent_policy = self.policy.get_agent(event.sender)
        if not agent_policy:
            return []
        blocked = agent_policy.get("blocked_tools", [])
        if event.tool_name in blocked:
            return [(
                0.95,
                "blocked_tool",
                f"{event.sender} 的 blocked_tools 明确禁止调用 {event.tool_name}"
            )]
        return []

    # ── 规则4a：intent_confidence_min — 置信度不足时直接拦截 ────────────
    # event.metadata["intent_confidence"] 由 LangGraph 适配器写入
    # 若低于 YAML 规定最小值 → 路由本身不可信，直接拦截（不交 LLM）
    # 若 metadata 中缺失 intent_confidence（非 LangGraph 场景）→ 推入 LLM 审核

    def _check_intent_confidence_required(self, event: AuditEvent) -> List[tuple]:
        tool_policy = self.policy.get_tool(event.tool_name or "")
        if not tool_policy:
            return []

        min_conf = tool_policy.get("intent_confidence_min")
        if min_conf is None:
            return []

        actual_conf = event.metadata.get("intent_confidence")

        if actual_conf is None:
            # 没有提供置信度：调用方未经过 intent_chain，本身异常，推 LLM
            return [(
                0.45,
                "intent_confidence_missing",
                f"{event.tool_name} 要求 intent_confidence >= {min_conf}，"
                f"metadata 中未提供，交由 LLM 审核"
            )]

        if float(actual_conf) < float(min_conf):
            # 置信度低于阈值：路由结果不可信，直接拦截
            return [(
                0.92,
                "intent_confidence_too_low",
                f"{event.tool_name} 要求 intent_confidence >= {min_conf}，"
                f"实际值 {float(actual_conf):.2f}，路由结果不可信"
            )]

        return []

    # ── 规则4b：route_hijack_check — 标记需要 LLM 做语义验证 ────────────
    # 规则引擎无法判断 intent 分类是否被 prompt 劫持，
    # 打一个基础分推入 llm_needed 区间，由 LLMReviewer 做实际语义比对

    def _check_route_hijack(self, event: AuditEvent) -> List[tuple]:
        tool_policy = self.policy.get_tool(event.tool_name or "")
        if not tool_policy:
            return []
        if tool_policy.get("route_hijack_check"):
            return [(
                0.45,
                "route_hijack_check",
                f"{event.tool_name} 标记 route_hijack_check，"
                f"需要 LLM 验证 intent 分类与 prompt 语义是否一致"
            )]
        return []


    # ── 规则5a：path_rule 路径校验 ──────────────────────────────────
    # 按工具的 path_rule 字段查找路径定义，支持两种模式：
    #   strict=true  → actual_path == sequence（完全相等）
    #   strict=false → 有序子序列匹配（sequence 中的节点必须按顺序出现在 actual_path 中）

    def _check_path_rule(self, event: AuditEvent) -> List[tuple]:
        tool_policy = self.policy.get_tool(event.tool_name or "")
        if not tool_policy:
            return []

        path_rule = tool_policy.get("path_rule")
        if not path_rule:
            return []

        path_def = self.policy.paths.get(path_rule, {})
        sequence = path_def.get("sequence", [])
        strict = path_def.get("strict", False)
        if not sequence:
            return []

        actual_path = self._agent_path(event)
        if not actual_path:
            return [(
                0.92,
                "missing_call_path",
                f"{event.tool_name} 声明了 path_rule={path_rule}，但当前 call_path 为空"
            )]

        if strict:
            if actual_path != sequence:
                return [(
                    0.93,
                    "strict_path_violation",
                    f"{event.tool_name} 要求严格路径 {sequence}，实际路径：{actual_path}"
                )]
            return []

        idx = 0
        for node in actual_path:
            if idx < len(sequence) and node == sequence[idx]:
                idx += 1
        if idx < len(sequence):
            return [(
                0.92,
                "path_rule_violation",
                f"{event.tool_name} 要求路径包含有序序列 {sequence}，实际路径：{actual_path}"
            )]
        return []

    # ── 规则5b：strict=true 路径校验（兜底，仅对未绑定 path_rule 的工具生效）──
    # 如果工具已绑定 path_rule，则由 _check_path_rule 处理，此处跳过避免重复

    def _check_strict_path(self, event: AuditEvent) -> List[tuple]:
        tool_policy = self.policy.get_tool(event.tool_name or "")
        if tool_policy and tool_policy.get("path_rule"):
            return []

        for path_name, path_def in self.policy.paths.items():
            if not path_def.get("strict", False):
                continue
            seq = path_def.get("sequence", [])
            if not seq or seq[-1] != event.sender:
                continue
            expected_prev = seq[-2]
            actual_prev = event.call_path[-2] if len(event.call_path) >= 2 else None
            if actual_prev != expected_prev:
                return [(
                    0.93,
                    "strict_path_violation",
                    f"{path_name} 要求 {event.sender} 只能由 {expected_prev} 直接触发，"
                    f"实际前置节点：{actual_prev}（可能经由中间 Agent 中转）"
                )]
        return []

    # ── 规则5：消息目标必须在 allowed_message_targets 内（AutoGen 场景）──
    # LangGraph / CrewAI 版 YAML 不含此字段时自动跳过

    def _check_message_target(self, event: AuditEvent) -> List[tuple]:
        agent_policy = self.policy.get_agent(event.sender)
        if not agent_policy:
            return []
        allowed_targets = agent_policy.get("allowed_message_targets")
        if allowed_targets is None:
            return []
        if event.receiver and event.receiver not in allowed_targets:
            return [(
                0.91,
                "unauthorized_message_target",
                f"{event.sender} 不允许向 {event.receiver} 发送消息，允许目标：{allowed_targets}"
            )]
        return []