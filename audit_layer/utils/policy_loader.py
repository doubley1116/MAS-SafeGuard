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
    def adjacency(self) -> dict[str, list[str]]:
        """Agent 级邻接矩阵: {agent_name: [allowed_next_agents]}."""
        return self._policy.get("adjacency", {})

    @property
    def role_adjacency(self) -> dict[str, list[str]]:
        """角色级邻接矩阵: {role_name: [allowed_next_roles]}."""
        return self._policy.get("role_adjacency", {})

    @property
    def depth_constraints(self) -> dict[str, dict]:
        """路径深度约束: {tool_name: {min: int, max: int}}."""
        return self._policy.get("depth_constraints", {})

    @property
    def thresholds(self) -> dict:
        return self._policy.get("thresholds", {})

    def get_agent(self, name: str) -> dict:
        return self.agents.get(name, {})

    def get_tool(self, name: str) -> dict:
        return self.tools.get(name, {})

    def threshold(self, key: str) -> float:
        return float(self.thresholds.get(key, 0.0))
