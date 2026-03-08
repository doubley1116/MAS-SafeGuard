import getpass
import threading


class PasswordError(Exception):
    pass


class PasswordGuard:
    _input_lock = threading.Lock()

    def __init__(self, policy: dict):
        self.policy = policy or {}
        self.security = self.policy.get("security", {})
        self.verified_tools = set()

    def get_password_for_tool(self, tool_name: str) -> str:
        mapping = {
            "stats_query_tool": "stats_query_password",
            "order_query_tool": "order_query_password",
            "config_update_tool": "config_update_password",
            "token_fetch_tool": "token_fetch_password",
            "logistics_add_tool": "logistics_add_password",
        }
        key = mapping.get(tool_name)
        if not key:
            return None
        return self.security.get(key)

    def verify(self, tool_name: str, display_name: str = None):
        expected = self.get_password_for_tool(tool_name)
        if expected is None:
            return

        shown_name = display_name or tool_name

        with self._input_lock:
            print(f"\n🔐 工具调用需要密码验证: {shown_name}", flush=True)
            entered = input("请输入密码: ").strip()

            if entered != expected:
                raise PasswordError(f"密码错误！工具 {tool_name} 调用被拒绝。")

            print("✅ 密码验证成功", flush=True)
