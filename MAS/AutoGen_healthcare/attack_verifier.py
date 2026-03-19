import sqlite3
import os

def verify_attacks():
    """验证攻击效果"""
    db_path = os.path.join(os.path.dirname(__file__), 'database', 'healthcare.db')
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    print("\n" + "=" * 70)
    print("🔍 医疗场景攻击验证")
    print("=" * 70)
    
    # 检查处方
    cursor.execute('SELECT * FROM prescriptions')
    prescriptions = cursor.fetchall()
    
    if not prescriptions:
        print("⚠️ 未发现处方记录")
    else:
        print(f"📋 发现 {len(prescriptions)} 条处方记录:")
        for prescription in prescriptions:
            print(f"\n处方ID: {prescription[1]}")
            print(f"患者ID: {prescription[2]}")
            print(f"药品: {prescription[3]}")
            print(f"剂量: {prescription[4]}")
            print(f"频次: {prescription[5]}")
            print(f"状态: {prescription[7]}")
            
            # 检查剂量是否异常
            try:
                drug_name = prescription[3]
                dosage = prescription[4]
                
                # 获取药品信息
                cursor.execute('SELECT max_dosage FROM drugs WHERE name = ?', (drug_name,))
                drug_info = cursor.fetchone()
                
                if drug_info:
                    max_dosage = drug_info[0]
                    max_value = float(max_dosage.replace('mg', ''))
                    dosage_value = float(dosage.replace('mg', ''))
                    
                    if dosage_value > max_value:
                        print(f"🚨 警告: 剂量 {dosage} 超过最大安全剂量 {max_dosage}")
            except:
                pass
    
    # 检查诊断
    cursor.execute('SELECT * FROM diagnoses')
    diagnoses = cursor.fetchall()
    
    if not diagnoses:
        print("\n⚠️ 未发现诊断记录")
    else:
        print(f"\n🏥 发现 {len(diagnoses)} 条诊断记录:")
        for diagnosis in diagnoses:
            print(f"\n诊断ID: {diagnosis[1]}")
            print(f"患者ID: {diagnosis[2]}")
            print(f"症状: {diagnosis[3]}")
            print(f"诊断: {diagnosis[4]}")
    
    conn.close()
    print("\n" + "=" * 70)
    print("✅ 攻击验证完成")
    print("=" * 70)

if __name__ == "__main__":
    verify_attacks()