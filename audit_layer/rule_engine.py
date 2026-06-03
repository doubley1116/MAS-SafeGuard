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
            hits += self._check_arg_constraints(event)
            hits += self._check_unknown_agent(event)
            hits += self._check_adjacency(event)

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

    # ── 辅助：判断节点名是否是用户类型（User/UserProxy 等变体）──

    @staticmethod
    def _is_user_node(name: str) -> bool:
        """判断节点名是否是用户/代理类型，用于路径匹配时的容错。"""
        return name.lower() in (
            "user", "userproxy", "user_proxy", "userproxyagent",
            "human", "human_proxy",
        )

    def _normalize_path_for_match(self, actual_path: List[str], sequence: List[str]) -> List[str]:
        """
        对 actual_path 做标准化，确保与 sequence 的用户节点名一致。

        场景：YAML 里写 "UserProxy"，但 adapter 记录的是 "User"（或反过来）。
        策略：如果 sequence 的第一个节点是用户类型，且 actual_path 的第一个节点也是用户类型，
              将 actual_path 的第一个节点替换为 sequence 的第一个节点。
        """
        if not actual_path or not sequence:
            return actual_path

        if self._is_user_node(sequence[0]) and self._is_user_node(actual_path[0]):
            normalized = list(actual_path)
            normalized[0] = sequence[0]
            return normalized

        return actual_path

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
        # 对用户类型节点做容错：如果 required 里有用户节点，
        # call_path 里有任意用户类型节点即视为满足
        call_path_set = set(event.call_path)
        has_user_in_path = any(self._is_user_node(n) for n in event.call_path)
        missing = []
        for node in required:
            if node in call_path_set:
                continue
            if self._is_user_node(node) and has_user_in_path:
                continue
            missing.append(node)
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

        # 标准化用户节点名，防止 User/UserProxy 不一致导致误报
        actual_path = self._normalize_path_for_match(actual_path, sequence)

        if strict:
            if actual_path != sequence:
                return [(
                    0.93,
                    "strict_path_violation",
                    f"{event.tool_name} 要求严格路径 {sequence}，实际路径：{actual_path}"
                )]
            return []

        # 有序子序列匹配
        idx = 0
        for node in actual_path:
            if idx < len(sequence) and node == sequence[idx]:
                idx += 1
        if idx < len(sequence):
            missing = [sequence[i] for i in range(idx, len(sequence))]
            return [(
                0.92,
                "path_rule_violation",
                f"{event.tool_name} 要求路径包含有序序列 {sequence}，"
                f"实际路径：{actual_path}，缺少节点：{missing}"
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
            # 用户节点容错
            if actual_prev != expected_prev:
                if self._is_user_node(expected_prev) and actual_prev and self._is_user_node(actual_prev):
                    continue  # User/UserProxy 视为等价，不报错
                return [(
                    0.93,
                    "strict_path_violation",
                    f"{path_name} 要求 {event.sender} 只能由 {expected_prev} 直接触发，"
                    f"实际前置节点：{actual_prev}（可能经由中间 Agent 中转）"
                )]
        return []

    # ── 规则5：消息目标必须在 allowed_message_targets 内（AutoGen 场景）──
    # LangGraph / CrewAI 版 YAML 不含此字段时自动跳过

    # ── 规则：未定义节点检测（AiTM 中间人攻击）──────────────────
    # 检测 call_path 中是否出现 YAML 未定义的节点

    def _check_unknown_agent(self, event: AuditEvent) -> List[tuple]:
        defined_agents = set(self.policy.agents.keys())
        unknown = [
            node for node in event.call_path
            if node not in defined_agents and not self._is_user_node(node)
        ]
        if unknown:
            return [(
                0.93,
                "unknown_agent_in_path",
                f"call_path 中出现未定义节点：{unknown}，疑似中间人攻击(AiTM)"
            )]
        return []

    # ── 规则：工具参数范围校验（arg_constraints）──────────────────
    # YAML 中为工具定义参数约束，超出范围直接拦截
    # 示例 YAML：
    #   prescribe_tool:
    #     arg_constraints:
    #       dosage_mg: { min: 0, max: 7.5, label: "佐匹克隆剂量(mg)" }
    #       quantity:   { min: 1, max: 30,  label: "开药数量(片)" }

    def _check_arg_constraints(self, event: AuditEvent) -> List[tuple]:
        tool_policy = self.policy.get_tool(event.tool_name or "")
        if not tool_policy:
            return []
        constraints = tool_policy.get("arg_constraints")
        if not constraints or not event.tool_args:
            return []

        hits = []
        for param_name, rule in constraints.items():
            value = event.tool_args.get(param_name)
            if value is None:
                continue
            try:
                num_val = float(value)
            except (ValueError, TypeError):
                # 非数值参数：检查 allowed_values 枚举
                allowed = rule.get("allowed_values")
                if allowed and str(value) not in [str(v) for v in allowed]:
                    label = rule.get("label", param_name)
                    hits.append((
                        0.93,
                        "arg_constraint_violation",
                        f"{label}={value} 不在允许值 {allowed} 中"
                    ))
                continue

            label = rule.get("label", param_name)
            min_val = rule.get("min")
            max_val = rule.get("max")

            if min_val is not None and num_val < float(min_val):
                hits.append((
                    0.93,
                    "arg_constraint_violation",
                    f"{label}={num_val} 低于最小值 {min_val}"
                ))
            if max_val is not None and num_val > float(max_val):
                hits.append((
                    0.93,
                    "arg_constraint_violation",
                    f"{label}={num_val} 超过最大值 {max_val}"
                ))

        return hits

    # ── 规则：邻接矩阵检查 ───────────────────────────────────
    # 检查 call_path 中每一对相邻 agent (vi → vi+1) 是否在允许的邻接表中。
    #
    # YAML 示例:
    #   adjacency:
    #     User: [Triage_Agent]
    #     Triage_Agent: [Diagnosis_Agent, Specialist_Agent]
    #     Diagnosis_Agent: [Review_Agent, Treatment_Agent]
    #
    # 这比 path_rule (有序子序列匹配) 更严格:
    #   - path_rule 只要求 "A 在 B 之前出现过" (非直接相邻也可以)
    #   - adjacency 要求 "A 直接调用 B" (必须紧邻)
    #
    # 能检测:
    #   - 跳级调用: User → Diagnosis_Agent (跳过了 Triage)
    #   - 反向调用: Diagnosis → Triage (回退到上游)
    #   - AiTM 导致的异常邻接

    def _check_adjacency(self, event: AuditEvent) -> List[tuple]:
        adjacency = self.policy.adjacency
        if not adjacency:
            return []

        path = self._agent_path(event)
        if len(path) < 2:
            return []

        hits = []
        for i in range(len(path) - 1):
            src, dst = path[i], path[i + 1]
            allowed = adjacency.get(src, [])
            if not allowed:
                continue  # 源节点无邻接约束定义 → 跳过

            if dst not in allowed:
                # 用户节点容错（User/UserProxy 视为等价）
                if self._is_user_node(src) and self._is_user_node(dst):
                    continue

                hits.append((
                    0.88,
                    "adjacency_violation",
                    f"非法邻接: {src} → {dst}，{src} 允许的下一跳: {allowed}"
                ))

        return hits

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