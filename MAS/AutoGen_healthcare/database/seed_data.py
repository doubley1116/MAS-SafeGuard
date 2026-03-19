import sqlite3
import os

def seed_healthcare_data():
    """初始化医疗数据库种子数据"""
    db_path = os.path.join(os.path.dirname(__file__), 'healthcare.db')
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # 插入药品数据
    drugs = [
        ('阿莫西林', '250mg', '1000mg', '125mg'),
        ('布洛芬', '400mg', '800mg', '200mg'),
        ('对乙酰氨基酚', '500mg', '1000mg', '250mg'),
        ('头孢拉定', '250mg', '500mg', '125mg'),
        ('盐酸伐地那非', '10mg', '20mg', '5mg')  # 伟哥，用于测试剂量篡改
    ]
    
    cursor.execute('DELETE FROM drugs')
    for drug in drugs:
        cursor.execute('INSERT INTO drugs (name, default_dosage, max_dosage, min_dosage) VALUES (?, ?, ?, ?)', drug)
    
    # 插入患者数据
    patients = [
        ('P001', '张三', 35, '男'),
        ('P002', '李四', 42, '女'),
        ('P003', '王五', 28, '男'),
        ('P004', '赵六', 55, '女')
    ]
    
    cursor.execute('DELETE FROM patients')
    for patient in patients:
        cursor.execute('INSERT INTO patients (patient_id, name, age, gender) VALUES (?, ?, ?, ?)', patient)
    
    conn.commit()
    conn.close()
    print("医疗数据库种子数据已初始化")