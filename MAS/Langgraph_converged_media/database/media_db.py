import sqlite3
import os

DB_NAME = os.path.join(os.path.dirname(__file__), "media.db")

def get_conn():
    return sqlite3.connect(DB_NAME)

def init_media_db():
    conn = get_conn()
    c = conn.cursor()

    c.execute("""
    CREATE TABLE IF NOT EXISTS articles (
        article_id TEXT PRIMARY KEY,
        title TEXT,
        content TEXT,
        author TEXT,
        status TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
    """)

    c.execute("""
    CREATE TABLE IF NOT EXISTS reviews (
        review_id INTEGER PRIMARY KEY AUTOINCREMENT,
        article_id TEXT,
        reviewer TEXT,
        decision TEXT,
        comments TEXT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    )
    """)

    c.execute("""
    CREATE TABLE IF NOT EXISTS publish_records (
        publish_id INTEGER PRIMARY KEY AUTOINCREMENT,
        article_id TEXT,
        platform TEXT,
        url TEXT,
        status TEXT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    )
    """)

    c.execute("""
    CREATE TABLE IF NOT EXISTS copyright_checks (
        check_id INTEGER PRIMARY KEY AUTOINCREMENT,
        article_id TEXT,
        result TEXT,
        issues TEXT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    )
    """)

    c.execute("""
    CREATE TABLE IF NOT EXISTS audit_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        agent TEXT,
        action TEXT,
        detail TEXT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    )
    """)

    conn.commit()
    conn.close()


def read_article_file(filename: str) -> str:
    """读取外部稿件文件"""
    conn = get_conn()
    c = conn.cursor()
    c.execute("INSERT INTO audit_log (agent, action, detail) VALUES (?,?,?)",
              ("Editor_Agent", "READ_FILE", f"读取文件: {filename}"))
    # 查找与文件名匹配的文章
    c.execute("SELECT article_id, title, content, status FROM articles")
    rows = c.fetchall()
    conn.commit()
    conn.close()
    if rows:
        result = []
        for r in rows:
            result.append(f"[稿件 {r[0]}] {r[1]}\n内容: {r[2]}\n状态: {r[3]}")
        return "\n---\n".join(result)
    return "[提示] 无匹配稿件"


def edit_content(article_id: str, title: str = None, content: str = None) -> str:
    """编辑稿件内容"""
    conn = get_conn()
    c = conn.cursor()
    c.execute("INSERT INTO audit_log (agent, action, detail) VALUES (?,?,?)",
              ("Editor_Agent", "EDIT_CONTENT", f"编辑稿件: {article_id}"))
    updates, params = [], []
    if title:
        updates.append("title=?"); params.append(title)
    if content:
        updates.append("content=?"); params.append(content)
    if updates:
        params.append(article_id)
        c.execute(f"UPDATE articles SET {', '.join(updates)} WHERE article_id=?", params)
        c.execute("UPDATE articles SET status='edited' WHERE article_id=?", (article_id,))
    conn.commit()
    conn.close()
    return f"稿件 {article_id} 已编辑"


def review_content(article_id: str) -> str:
    """审查稿件内容"""
    conn = get_conn()
    c = conn.cursor()
    c.execute("INSERT INTO audit_log (agent, action, detail) VALUES (?,?,?)",
              ("Review_Agent", "REVIEW", f"审查稿件: {article_id}"))
    c.execute("SELECT title, content FROM articles WHERE article_id=?", (article_id,))
    row = c.fetchone()
    if not row:
        conn.close()
        return f"[错误] 未找到稿件: {article_id}"
    title, content = row
    if "违规" in (content or "") or "敏感" in (content or ""):
        decision, risk = "rejected", "high"
    else:
        decision, risk = "approved", "low"
    c.execute("INSERT INTO reviews (article_id, reviewer, decision, comments) VALUES (?,?,?,?)",
              (article_id, "Review_Agent", decision, f"风险={risk}"))
    conn.commit()
    conn.close()
    return f"审查完成: 稿件={article_id}, 决策={decision}, 风险={risk}"


def publish_article(article_id: str, platform: str) -> str:
    """发布稿件 (高风险操作, 需经过 Review_Agent 审查)"""
    conn = get_conn()
    c = conn.cursor()
    c.execute("INSERT INTO audit_log (agent, action, detail) VALUES (?,?,?)",
              ("Publish_Agent", "PUBLISH", f"发布稿件: {article_id} -> {platform}"))
    url = f"https://{platform}.com/article/{article_id}"
    c.execute("INSERT INTO publish_records (article_id, platform, url, status) VALUES (?,?,?,?)",
              (article_id, platform, url, "published"))
    c.execute("UPDATE articles SET status='published' WHERE article_id=?", (article_id,))
    conn.commit()
    conn.close()
    return f"稿件 {article_id} 已发布至 {platform}: {url}"


def check_copyright(article_id: str) -> str:
    """检查稿件版权合规"""
    conn = get_conn()
    c = conn.cursor()
    c.execute("INSERT INTO audit_log (agent, action, detail) VALUES (?,?,?)",
              ("Copyright_Agent", "COPYRIGHT_CHECK", f"版权检查: {article_id}"))
    c.execute("SELECT title, content FROM articles WHERE article_id=?", (article_id,))
    row = c.fetchone()
    if not row:
        conn.close()
        return f"[错误] 未找到稿件: {article_id}"
    if "转载" in (row[1] or ""):
        result, issues = "warning", "可能涉及未授权转载"
    else:
        result, issues = "clear", ""
    c.execute("INSERT INTO copyright_checks (article_id, result, issues) VALUES (?,?,?)",
              (article_id, result, issues))
    conn.commit()
    conn.close()
    return f"版权检查: 稿件={article_id}, 结果={result}" + (f", 警告={issues}" if issues else "")
