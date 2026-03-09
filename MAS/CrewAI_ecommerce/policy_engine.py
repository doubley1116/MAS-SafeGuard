class PolicyViolation(Exception):
    pass


class ApprovalRequired(Exception):
    def __init__(self, message: str, approver: str = None, rule_name: str = None):
        super().__init__(message)
        self.approver = approver
        self.rule_name = rule_name


class PolicyEngine:
    def __init__(self, policy: dict):
        self.policy = policy or {}

    def get_agent_policy(self, agent_name: str) -> dict:
        return self.policy.get("agents", {}).get(agent_name, {})

    def get_tool_policy(self, tool_name: str) -> dict:
        return self.policy.get("tools", {}).get(tool_name, {})

    def check_tool_access(self, agent_name: str, tool_name: str):
        agent_policy = self.get_agent_policy(agent_name)
        tool_policy = self.get_tool_policy(tool_name)

        allowed_tools = agent_policy.get("allowed_tools", [])
        blocked_tools = agent_policy.get("blocked_tools", [])
        allowed_callers = tool_policy.get("allowed_callers", [])

        print(
            f"[DEBUG] agent={agent_name}, tool={tool_name}, "
            f"allowed_tools={allowed_tools}, blocked_tools={blocked_tools}, allowed_callers={allowed_callers}",
            flush=True
        )

        if tool_name in blocked_tools:
            raise PolicyViolation(f"角色 {agent_name} 被明确禁止调用工具 {tool_name}")

        if allowed_tools and tool_name not in allowed_tools:
            raise PolicyViolation(f"角色 {agent_name} 不允许调用工具 {tool_name}")

        if allowed_callers and agent_name not in allowed_callers:
            raise PolicyViolation(f"工具 {tool_name} 不允许由 {agent_name} 调用")

    def check_approval_required(self, role: str, context: dict):
        context = context or {}
        tool_name = context.get("tool_name")
        if not tool_name:
            return

        tool_policy = self.policy.get("tools", {}).get(tool_name, {})
        if tool_policy.get("approval_required", False):
            raise ApprovalRequired(
                message=f"操作需要审批: {tool_name}",
                approver=tool_policy.get("approver"),
                rule_name=tool_name
            )


    def check_workflow_path(self, tool_name: str, execution_path: list[str]):
        tool_policy = self.get_tool_policy(tool_name)
        required_path_contains = tool_policy.get("required_path_contains", [])
        path_rule = tool_policy.get("path_rule")

        # 先检查 required_path_contains
        for node in required_path_contains:
            if node not in execution_path:
                raise PolicyViolation(
                    f"执行路径不符合要求，必须包含 {node}，当前路径 {execution_path}"
                )

        # 再检查 path_rule
        if path_rule:
            path_config = self.policy.get("paths", {}).get(path_rule, {})
            sequence = path_config.get("sequence", [])
            strict = path_config.get("strict", False)

            if strict:
                if execution_path != sequence:
                    raise PolicyViolation(
                        f"执行路径不符合严格要求，必须为 {sequence}，当前路径 {execution_path}"
                    )
            else:
                idx = 0
                for role in execution_path:
                    if idx < len(sequence) and role == sequence[idx]:
                        idx += 1
                if idx < len(sequence):
                    raise PolicyViolation(
                        f"执行路径不符合要求，必须包含顺序路径 {sequence}，当前路径 {execution_path}"
                    )
