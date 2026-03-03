import sqlite3

DB_NAME = "trade.db"

def get_conn():
    return sqlite3.connect(DB_NAME)

def init_trade_db():
    conn = get_conn()
    c = conn.cursor()

    # 交易记录
    c.execute("""
    CREATE TABLE IF NOT EXISTS trades (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        symbol TEXT,
        action TEXT,
        amount INTEGER,
        initiated_by TEXT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    )
    """)

    # 审批记录（后期安全层用）
    c.execute("""
    CREATE TABLE IF NOT EXISTS approvals (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        trade_id INTEGER,
        approved_by TEXT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    )
    """)

    conn.commit()
    conn.close()
def execute_trade(symbol: str, action: str, amount: int, agent_name: str):
    conn = get_conn()
    c = conn.cursor()

    c.execute(
        "INSERT INTO trades (symbol, action, amount, initiated_by) VALUES (?, ?, ?, ?)",
        (symbol, action, amount, agent_name)
    )

    conn.commit()
    conn.close()

    return f"已执行 {action} {symbol} {amount} 股"