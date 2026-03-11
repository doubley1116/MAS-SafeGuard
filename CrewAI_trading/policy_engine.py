class PolicyViolation(Exception):
    pass


class PolicyEngine:
    def __init__(self, policy: dict):
        self.policy = policy or {}

    def get_agent_policy(self, agent_name: str) -> dict:
        return self.policy.get("agents", {}).get(agent_name, {})

    def get_tool_policy(self, tool_name: str) -> dict:
        return self.policy.get("tools", {}).get(tool_name, {})

    def check_tool_access(self, agent_name: str, tool_name: str):
        tool_policy = self.get_tool_policy(tool_name)
        allowed_callers = tool_policy.get("allowed_callers", [])
        if allowed_callers and agent_name not in allowed_callers:
            raise PolicyViolation(f"{agent_name} 不允许调用工具 {tool_name}")

    def check_required_path_contains(self, tool_name: str, execution_path: list[str]):
        tool_policy = self.get_tool_policy(tool_name)
        required_nodes = tool_policy.get("required_path_contains", [])

        for node in required_nodes:
            if node not in execution_path:
                raise PolicyViolation(
                    f"工具 {tool_name} 缺少必经节点 {node}，当前路径: {execution_path}"
                )

    def _is_subsequence(self, seq: list[str], path: list[str]) -> bool:
        idx = 0
        for item in path:
            if idx < len(seq) and item == seq[idx]:
                idx += 1
        return idx == len(seq)

    def check_path_rule(self, tool_name: str, execution_path: list[str]):
        tool_policy = self.get_tool_policy(tool_name)
        path_rule_name = tool_policy.get("path_rule")

        if not path_rule_name:
            return

        path_rule = self.policy.get("paths", {}).get(path_rule_name, {})
        required_sequence = path_rule.get("sequence", [])
        strict = path_rule.get("strict", False)

        if not required_sequence:
            return

        if strict:
            if execution_path != required_sequence:
                raise PolicyViolation(
                    f"工具 {tool_name} 执行路径不符合严格路径要求，"
                    f"要求: {required_sequence}，当前: {execution_path}"
                )
        else:
            if not self._is_subsequence(required_sequence, execution_path):
                raise PolicyViolation(
                    f"工具 {tool_name} 执行路径不符合要求，"
                    f"要求包含顺序路径: {required_sequence}，当前: {execution_path}"
                )
