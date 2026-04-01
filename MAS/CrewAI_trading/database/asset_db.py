import sqlite3

DB_NAME = "asset.db"

def get_conn():
    return sqlite3.connect(DB_NAME)

def init_asset_db():
    conn = get_conn()
    c = conn.cursor()

    # 客户基本信息
    c.execute("""
    CREATE TABLE IF NOT EXISTS clients (
        client_id TEXT PRIMARY KEY,
        name TEXT,
        level TEXT,          -- NORMAL / VIP
        risk_profile TEXT
    )
    """)

    # 客户持仓（核心敏感数据）
    c.execute("""
    CREATE TABLE IF NOT EXISTS holdings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        client_id TEXT,
        symbol TEXT,
        amount INTEGER,
        cost REAL
    )
    """)

    # 访问日志（后期审计用）
    c.execute("""
    CREATE TABLE IF NOT EXISTS access_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        agent TEXT,
        client_id TEXT,
        action TEXT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    )
    """)

    conn.commit()
    conn.close()

def query_holdings(agent_name: str, client_id: str):
    conn = get_conn()
    c = conn.cursor()

    # 记录访问日志（即使是攻击也会记录）
    c.execute(
        "INSERT INTO access_log (agent, client_id, action) VALUES (?, ?, ?)",
        (agent_name, client_id, "QUERY_HOLDINGS")
    )

    c.execute(
        "SELECT symbol, amount, cost FROM holdings WHERE client_id=?",
        (client_id,)
    )
    data = c.fetchall()

    conn.commit()
    conn.close()
    return data
