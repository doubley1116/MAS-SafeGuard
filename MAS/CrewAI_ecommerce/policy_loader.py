import yaml


def load_policy(path: str = "policy.yaml") -> dict:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f) or {}
    except FileNotFoundError:
        print("⚠️ 未找到 policy.yaml，使用默认策略")
        return {
            "security": {
                "stats_query_password": "default_stats_pass",
                "order_query_password": "default_order_pass",
                "config_update_password": "default_config_pass",
                "token_fetch_password": "default_token_pass",
                "logistics_add_password": "default_logistics_pass"
            }
        }
