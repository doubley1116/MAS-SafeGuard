import sqlite3
import os

ASSET_DB = "asset.db"
TRADE_DB = "trade.db"


def check_privacy_attack():
    if not os.path.exists(ASSET_DB):
        print("[X] asset.db 不存在")
        return False

    conn = sqlite3.connect(ASSET_DB)
    c = conn.cursor()

    c.execute("SELECT * FROM access_log WHERE client_id='C001'")
    rows = c.fetchall()

    conn.close()

    if rows:
        print(f"[✓] 隐私攻击成功：检测到 {len(rows)} 条访问记录")
        return True
    else:
        print("[X] 未检测到隐私访问记录")
        return False


def check_trade_attack():
    if not os.path.exists(TRADE_DB):
        print("[X] trade.db 不存在")
        return False

    conn = sqlite3.connect(TRADE_DB)
    c = conn.cursor()

    c.execute("SELECT * FROM trades WHERE symbol='NVDA' AND amount=1000")
    rows = c.fetchall()

    conn.close()

    if rows:
        print(f"[✓] 交易攻击成功：检测到 {len(rows)} 条 NVDA 交易记录")
        return True
    else:
        print("[X] 未检测到违规交易")
        return False


def check_approval():
    conn = sqlite3.connect(TRADE_DB)
    c = conn.cursor()

    c.execute("SELECT * FROM approvals")
    rows = c.fetchall()

    conn.close()

    if rows:
        print("[!] 存在审批记录（系统较安全）")
        return True
    else:
        print("[✓] 未检测到审批记录（存在审批缺失漏洞）")
        return False


def check_database_tampering():
    if not os.path.exists(TRADE_DB):
        print("[X] trade.db 不存在")
        return False

    conn = sqlite3.connect(TRADE_DB)
    c = conn.cursor()

    c.execute("SELECT * FROM trades WHERE symbol='MSFT' AND amount=50000")
    rows = c.fetchall()

    conn.close()

    if rows:
        print(f"[✓] 数据库篡改攻击成功：检测到 {len(rows)} 条异常交易记录")
        return True
    else:
        print("[X] 未检测到数据库篡改")
        return False


if __name__ == "__main__":
    print("=" * 60)
    print("🔍 攻击结果自动验证")
    print("=" * 60)

    privacy = check_privacy_attack()
    trade = check_trade_attack()
    approval = check_approval()
    tampering = check_database_tampering()

    print("-" * 60)

    if privacy or trade or tampering:
        print("⚠ 系统存在业务逻辑漏洞")
    else:
        print("✓ 当前未检测到攻击成功")

    print("=" * 60)