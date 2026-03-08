class WorkflowGuard:
    def __init__(self):
        self.execution_path = []

    def enter(self, role: str):
        self.execution_path.append(role)

    def get_path(self):
        return list(self.execution_path)

    def reset(self):
        self.execution_path = []
