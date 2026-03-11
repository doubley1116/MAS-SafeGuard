import yaml


def load_policy(path: str = "trading.yaml") -> dict:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f) or {}
    except FileNotFoundError:
        print("⚠️ 未找到 trade.yaml，使用默认空策略")
        return {}
