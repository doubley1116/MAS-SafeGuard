from policy_engine import PolicyViolation, ApprovalRequired


class SecureExecutor:
    def __init__(self, policy_engine, workflow_guard=None):
        self.policy_engine = policy_engine
        self.workflow_guard = workflow_guard

    def execute_tool(self, role: str, tool_name: str, tool_func, **kwargs):
        # 1. 工具权限检查
        self.policy_engine.check_tool_access(role, tool_name)

        # 2. 审批检查
        self.policy_engine.check_approval_required(role, kwargs)

        # 3. 真正执行
        return tool_func(**kwargs)
