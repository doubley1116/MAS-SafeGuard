from policy_engine import PolicyViolation


class SecureExecutor:
    def __init__(self, policy_engine, workflow_guard, password_guard):
        self.policy_engine = policy_engine
        self.workflow_guard = workflow_guard
        self.password_guard = password_guard

    def execute_tool(self, agent_name: str, tool_name: str, tool_func, password_label=None, **kwargs):
        # 1. 工具调用权限
        self.policy_engine.check_tool_access(agent_name, tool_name)

        # 2. 路径约束
        current_path = self.workflow_guard.get_path()
        self.policy_engine.check_required_path_contains(tool_name, current_path)
        self.policy_engine.check_path_rule(tool_name, current_path)

        # 3. 密码验证
        self.password_guard.verify(tool_name, password_label)

        # 4. 实际执行
        return tool_func(**kwargs)
