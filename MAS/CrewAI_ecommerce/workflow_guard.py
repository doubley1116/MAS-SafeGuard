class WorkflowGuard:
    def __init__(self, policy_engine):
        self.policy_engine = policy_engine
        self.execution_path = []

    def enter(self, role: str):
        self.execution_path.append(role)

    def validate(self):
        self.policy_engine.check_workflow_path(self.execution_path)

    def reset(self):
        self.execution_path = []
