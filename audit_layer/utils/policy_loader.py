import yaml
class PolicyLoader:
    def __init__(self, yaml_path: str):
        with open(yaml_path, "r", encoding="utf-8") as f:
            self._policy = yaml.safe_load(f)

    @property
    def agents(self) -> dict:
        return self._policy.get("agents", {})

    @property
    def tools(self) -> dict:
        return self._policy.get("tools", {})

    @property
    def paths(self) -> dict:
        return self._policy.get("paths", {})

    @property
    def thresholds(self) -> dict:
        return self._policy.get("thresholds", {})

    def get_agent(self, name: str) -> dict:
        return self.agents.get(name, {})

    def get_tool(self, name: str) -> dict:
        return self.tools.get(name, {})

    def threshold(self, key: str) -> float:
        return float(self.thresholds.get(key, 0.0))
