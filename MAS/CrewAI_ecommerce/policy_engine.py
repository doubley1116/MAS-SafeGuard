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

    def get_role_policy(self, role: str) -> dict:
        return self.policy.get("roles", {}).get(role, {})

    def check_tool_access(self, role: str, tool_name: str):
        role_policy = self.get_role_policy(role)
        allowed_tools = role_policy.get("allowed_tools", [])
        if tool_name not in allowed_tools:
            raise PolicyViolation(f"角色 {role} 不允许调用工具 {tool_name}")

    def _eval_condition(self, condition: dict, context: dict) -> bool:
        if not condition:
            return False

        field = condition.get("field")
        operator = condition.get("operator")
        expected = condition.get("value")
        actual = context.get(field)

        if operator == ">":
            return actual is not None and actual > expected
        elif operator == "<":
            return actual is not None and actual < expected
        elif operator == "==":
            return actual == expected
        elif operator == "!=":
            return actual != expected
        elif operator == ">=":
            return actual is not None and actual >= expected
        elif operator == "<=":
            return actual is not None and actual <= expected
        return False

    def check_approval_required(self, role: str, context: dict):
        role_policy = self.get_role_policy(role)
        approval_rule_names = role_policy.get("require_approval_for", [])
        approval_rules = self.policy.get("approval", {})

        for rule_name in approval_rule_names:
            rule = approval_rules.get(rule_name, {})
            condition = rule.get("condition", {})
            approver = rule.get("approver")

            if self._eval_condition(condition, context):
                raise ApprovalRequired(
                    message=f"操作触发审批规则: {rule_name}",
                    approver=approver,
                    rule_name=rule_name
                )

    def check_workflow_path(self, execution_path: list[str]):
        required_path = self.policy.get("workflow", {}).get("required_path", [])
        if not required_path:
            return

        idx = 0
        for role in execution_path:
            if idx < len(required_path) and role == required_path[idx]:
                idx += 1

        if idx < len(required_path):
            raise PolicyViolation(
                f"执行路径不符合要求，必须包含顺序路径 {required_path}，当前路径 {execution_path}"
            )
