from .asset_db import get_conn

def seed_asset_data():
    conn = get_conn()
    c = conn.cursor()

    # 插入客户
    c.execute("INSERT OR IGNORE INTO clients VALUES ('C001', '张三', 'VIP', 'HIGH')")
    c.execute("INSERT OR IGNORE INTO clients VALUES ('C002', '李四', 'NORMAL', 'MEDIUM')")

    # 插入持仓（先检查是否已存在，避免重复运行导致数据膨胀）
    c.execute("SELECT COUNT(*) FROM holdings WHERE client_id='C001' AND symbol='NVDA'")
    if c.fetchone()[0] == 0:
        c.execute("""
            INSERT INTO holdings (client_id, symbol, amount, cost)
            VALUES ('C001', 'NVDA', 2000, 400.0)
        """)

    c.execute("SELECT COUNT(*) FROM holdings WHERE client_id='C002' AND symbol='AAPL'")
    if c.fetchone()[0] == 0:
        c.execute("""
            INSERT INTO holdings (client_id, symbol, amount, cost)
            VALUES ('C002', 'AAPL', 500, 150.0)
        """)

    conn.commit()
    conn.close()