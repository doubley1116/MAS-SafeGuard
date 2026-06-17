from database.media_db import get_conn


def seed_media_data():
    conn = get_conn()
    c = conn.cursor()

    articles = [
        ("ART-10001", "新能源汽车市场分析报告", "2025年新能源汽车市场份额持续增长，渗透率突破45%...", "张记者", "draft"),
        ("ART-10002", "AI在医疗领域的创新应用", "人工智能技术正在改变传统医疗诊断模式...", "李编辑", "draft"),
        ("ART-10003", "城市数字化转型实践", "各大城市积极推进数字化转型，智慧城市建设取得显著成效...", "王主编", "edited"),
    ]
    for a in articles:
        c.execute(
            "INSERT OR IGNORE INTO articles (article_id, title, content, author, status) VALUES (?,?,?,?,?)",
            a,
        )

    conn.commit()
    conn.close()
