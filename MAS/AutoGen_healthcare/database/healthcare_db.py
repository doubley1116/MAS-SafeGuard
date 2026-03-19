import sqlite3
import os

def init_healthcare_db():
    """初始化医疗数据库"""
    db_path = os.path.join(os.path.dirname(__file__), 'healthcare.db')
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # 创建药品表
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS drugs (
        id INTEGER PRIMARY KEY,
        name TEXT NOT NULL,
        default_dosage TEXT NOT NULL,
        max_dosage TEXT NOT NULL,
        min_dosage TEXT NOT NULL
    )''')
    
    # 创建患者表
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS patients (
        id INTEGER PRIMARY KEY,
        patient_id TEXT NOT NULL UNIQUE,
        name TEXT NOT NULL,
        age INTEGER NOT NULL,
        gender TEXT NOT NULL
    )''')
    
    # 创建处方表
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS prescriptions (
        id INTEGER PRIMARY KEY,
        prescription_id TEXT NOT NULL UNIQUE,
        patient_id TEXT NOT NULL,
        drug_name TEXT NOT NULL,
        dosage TEXT NOT NULL,
        frequency TEXT NOT NULL,
        doctor_id TEXT NOT NULL,
        review_status TEXT NOT NULL DEFAULT 'PENDING'
    )''')
    
    # 创建诊断表
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS diagnoses (
        id INTEGER PRIMARY KEY,
        diagnosis_id TEXT NOT NULL UNIQUE,
        patient_id TEXT NOT NULL,
        symptoms TEXT NOT NULL,
        diagnosis TEXT NOT NULL,
        doctor_id TEXT NOT NULL
    )''')
    
    conn.commit()
    conn.close()

def get_drug_info(drug_name):
    """获取药品信息"""
    db_path = os.path.join(os.path.dirname(__file__), 'healthcare.db')
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    cursor.execute('SELECT * FROM drugs WHERE name = ?', (drug_name,))
    drug = cursor.fetchone()
    
    conn.close()
    return drug

def add_prescription(prescription_id, patient_id, drug_name, dosage, frequency, doctor_id):
    """添加处方"""
    db_path = os.path.join(os.path.dirname(__file__), 'healthcare.db')
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    try:
        cursor.execute('''
        INSERT INTO prescriptions (prescription_id, patient_id, drug_name, dosage, frequency, doctor_id, review_status)
        VALUES (?, ?, ?, ?, ?, ?, 'PENDING')
        ''', (prescription_id, patient_id, drug_name, dosage, frequency, doctor_id))
        conn.commit()
        return f"处方已添加: {prescription_id}"
    except sqlite3.IntegrityError:
        return "处方ID已存在"
    finally:
        conn.close()

def update_prescription_status(prescription_id, status):
    """更新处方状态"""
    db_path = os.path.join(os.path.dirname(__file__), 'healthcare.db')
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    cursor.execute('UPDATE prescriptions SET review_status = ? WHERE prescription_id = ?', (status, prescription_id))
    conn.commit()
    conn.close()
    return f"处方状态已更新为: {status}"

def add_diagnosis(diagnosis_id, patient_id, symptoms, diagnosis, doctor_id):
    """添加诊断"""
    db_path = os.path.join(os.path.dirname(__file__), 'healthcare.db')
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    try:
        cursor.execute('''
        INSERT INTO diagnoses (diagnosis_id, patient_id, symptoms, diagnosis, doctor_id)
        VALUES (?, ?, ?, ?, ?)
        ''', (diagnosis_id, patient_id, symptoms, diagnosis, doctor_id))
        conn.commit()
        return f"诊断已添加: {diagnosis_id}"
    except sqlite3.IntegrityError:
        return "诊断ID已存在"
    finally:
        conn.close()

def get_patient_info(patient_id):
    """获取患者信息"""
    db_path = os.path.join(os.path.dirname(__file__), 'healthcare.db')
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    cursor.execute('SELECT * FROM patients WHERE patient_id = ?', (patient_id,))
    patient = cursor.fetchone()
    
    conn.close()
    return patient

def get_prescription(prescription_id):
    """获取处方信息"""
    db_path = os.path.join(os.path.dirname(__file__), 'healthcare.db')
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    cursor.execute('SELECT * FROM prescriptions WHERE prescription_id = ?', (prescription_id,))
    prescription = cursor.fetchone()
    
    conn.close()
    return prescription