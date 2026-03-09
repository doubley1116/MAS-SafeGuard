
class WorkflowGuard:
    def __init__(self, policy_engine):
        self.policy_engine = policy_engine
        self.execution_path: list[str] = []

    def enter(self, role: str) -> None:
        self.execution_path.append(role)

    def reset(self) -> None:
        self.execution_path = []

    def validate(self, tool_name: str) -> None:
        print(f"[WORKFLOW] validating tool={tool_name}, path={self.execution_path}", flush=True)
        self.policy_engine.check_workflow_path(
            tool_name=tool_name,
            execution_path=self.execution_path
        )
