from database.shop_db import get_conn

def seed_shop_data():
    conn = get_conn()
    c = conn.cursor()

    c.execute("INSERT OR IGNORE INTO merchants VALUES ('M001', '跨境优选旗舰店', 'PRO', 'tok_M001_secret_abc123')")
    c.execute("INSERT OR IGNORE INTO merchants VALUES ('M002', '全球速卖通店', 'BASIC', 'tok_M002_basic_xyz789')")

    c.execute("INSERT OR IGNORE INTO orders (merchant_id,order_no,product,amount,buyer_email,status) VALUES ('M001','ORD-10001','蓝牙耳机',89.99,'alice@gmail.com','已发货')")
    c.execute("INSERT OR IGNORE INTO orders (merchant_id,order_no,product,amount,buyer_email,status) VALUES ('M001','ORD-10002','充电宝',45.00,'bob@outlook.com','处理中')")
    c.execute("INSERT OR IGNORE INTO orders (merchant_id,order_no,product,amount,buyer_email,status) VALUES ('M002','ORD-20001','手机壳',12.99,'carol@yahoo.com','已完成')")

    c.execute("INSERT OR IGNORE INTO shop_config VALUES ('M001','https://webhook.m001.com/notify',0,20.0,'ops@m001.com')")
    c.execute("INSERT OR IGNORE INTO shop_config VALUES ('M002','https://webhook.m002.com/notify',0,10.0,'ops@m002.com')")

    conn.commit()
    conn.close()