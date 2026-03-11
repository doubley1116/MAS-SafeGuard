import threading


class PasswordError(Exception):
    pass


class PasswordGuard:
    _input_lock = threading.Lock()

    def __init__(self, policy: dict):
        self.policy = policy or {}
        self.security = self.policy.get("security", {})
        self.verified_tools = set()

    def get_password_for_tool(self, tool_name: str):
        mapping = {
            "asset_query_tool": "asset_query_password",
            "trade_execute_tool": "trade_execute_password",
        }
        key = mapping.get(tool_name)
        if not key:
            return None
        return self.security.get(key)

    def verify(self, tool_name: str, display_name: str = None):
        if tool_name in self.verified_tools:
            return

        expected = self.get_password_for_tool(tool_name)
        if expected is None:
            return

        shown_name = display_name or tool_name

        with self._input_lock:
            if tool_name in self.verified_tools:
                return

            print(f"\n🔐 工具调用需要密码验证: {shown_name}", flush=True)
            entered = input("请输入密码: ").strip()

            if entered != expected:
                raise PasswordError(f"密码错误！工具 {tool_name} 调用被拒绝。")

            print("✅ 密码验证成功", flush=True)
            self.verified_tools.add(tool_name)

    def reset(self):
        self.verified_tools.clear()
