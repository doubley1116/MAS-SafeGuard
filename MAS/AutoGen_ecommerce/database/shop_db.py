import sqlite3
import os

DB_NAME = "database/shop.db"


def get_conn():
    return sqlite3.connect(DB_NAME)


def init_shop_db():
    """创建表结构（如果不存在）"""
    # 确保 database 目录存在
    os.makedirs(os.path.dirname(DB_NAME), exist_ok=True)
    
    conn = get_conn()
    c = conn.cursor()

    c.execute("""
    CREATE TABLE IF NOT EXISTS merchants (
        merchant_id TEXT PRIMARY KEY,
        name TEXT,
        plan TEXT,
        platform_token TEXT
    )
    """)

    c.execute("""
    CREATE TABLE IF NOT EXISTS orders (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        merchant_id TEXT,
        order_no TEXT,
        product TEXT,
        amount REAL,
        buyer_email TEXT,
        status TEXT
    )
    """)

    c.execute("""
    CREATE TABLE IF NOT EXISTS shop_config (
        merchant_id TEXT PRIMARY KEY,
        webhook_url TEXT,
        auto_refund INTEGER,
        price_floor REAL,
        notify_email TEXT
    )
    """)

    c.execute("""
    CREATE TABLE IF NOT EXISTS logistics (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        merchant_id TEXT,
        order_no TEXT,
        carrier TEXT,
        tracking_no TEXT
    )
    """)

    c.execute("""
    CREATE TABLE IF NOT EXISTS audit_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        agent TEXT,
        action TEXT,
        merchant_id TEXT,
        detail TEXT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    )
    """)

    conn.commit()
    conn.close()


def reset_shop_db():
    """清空所有表数据并重新创建（每个场景开始前调用）"""
    conn = get_conn()
    c = conn.cursor()
    
    # 清空所有表
    c.execute("DELETE FROM merchants")
    c.execute("DELETE FROM orders")
    c.execute("DELETE FROM shop_config")
    c.execute("DELETE FROM logistics")
    c.execute("DELETE FROM audit_log")
    
    # 重置自增 ID
    c.execute("DELETE FROM sqlite_sequence WHERE name IN ('orders', 'logistics', 'audit_log')")
    
    conn.commit()
    conn.close()


def get_shop_stats(merchant_id: str) -> dict:
    conn = get_conn()
    c = conn.cursor()
    c.execute("INSERT INTO audit_log (agent, action, merchant_id, detail) VALUES (?,?,?,?)",
              ("Stats_Agent", "QUERY_STATS", merchant_id, "查询店铺统计"))
    c.execute("SELECT COUNT(*), SUM(amount) FROM orders WHERE merchant_id=?", (merchant_id,))
    row = c.fetchone()
    conn.commit()
    conn.close()
    return {"order_count": row[0] or 0, "total_revenue": row[1] or 0.0}


def get_orders(merchant_id: str) -> list:
    conn = get_conn()
    c = conn.cursor()
    c.execute("INSERT INTO audit_log (agent, action, merchant_id, detail) VALUES (?,?,?,?)",
              ("Order_Agent", "QUERY_ORDERS", merchant_id, "查询订单列表"))
    c.execute("SELECT order_no, product, amount, buyer_email, status FROM orders WHERE merchant_id=?",
              (merchant_id,))
    rows = c.fetchall()
    conn.commit()
    conn.close()
    return rows


def update_shop_config(merchant_id: str, webhook_url: str = None,
                       notify_email: str = None, price_floor: float = None) -> str:
    conn = get_conn()
    c = conn.cursor()
    updates, params = [], []
    if webhook_url is not None:
        updates.append("webhook_url=?"); params.append(webhook_url)
    if notify_email is not None:
        updates.append("notify_email=?"); params.append(notify_email)
    if price_floor is not None:
        updates.append("price_floor=?"); params.append(price_floor)
    if updates:
        params.append(merchant_id)
        c.execute(f"UPDATE shop_config SET {', '.join(updates)} WHERE merchant_id=?", params)
    c.execute("INSERT INTO audit_log (agent, action, merchant_id, detail) VALUES (?,?,?,?)",
              ("Config_Agent", "UPDATE_CONFIG", merchant_id, str(updates)))
    conn.commit()
    conn.close()
    return f"商家 {merchant_id} 配置已更新"


def get_platform_token(merchant_id: str) -> str:
    conn = get_conn()
    c = conn.cursor()
    c.execute("INSERT INTO audit_log (agent, action, merchant_id, detail) VALUES (?,?,?,?)",
              ("Config_Agent", "FETCH_TOKEN", merchant_id, "获取平台Token"))
    c.execute("SELECT platform_token FROM merchants WHERE merchant_id=?", (merchant_id,))
    row = c.fetchone()
    conn.commit()
    conn.close()
    return row[0] if row else "NOT_FOUND"


def add_logistics(order_no: str, carrier: str, tracking_no: str) -> str:
    conn = get_conn()
    c = conn.cursor()
    c.execute("SELECT merchant_id FROM orders WHERE order_no=?", (order_no,))
    row = c.fetchone()
    merchant_id = row[0] if row else "UNKNOWN"
    c.execute("INSERT INTO logistics (merchant_id, order_no, carrier, tracking_no) VALUES (?,?,?,?)",
              (merchant_id, order_no, carrier, tracking_no))
    c.execute("INSERT INTO audit_log (agent, action, merchant_id, detail) VALUES (?,?,?,?)",
              ("Logistics_Agent", "ADD_LOGISTICS", merchant_id, f"{carrier} {tracking_no}"))
    conn.commit()
    conn.close()
    return f"订单 {order_no} 物流已录入: {carrier} {tracking_no}"