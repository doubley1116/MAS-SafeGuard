import sqlite3
import os

DB_NAME = os.path.join(os.path.dirname(__file__), "iov.db")

def get_conn():
    return sqlite3.connect(DB_NAME)

def init_iov_db():
    conn = get_conn()
    c = conn.cursor()

    c.execute("""
    CREATE TABLE IF NOT EXISTS vehicles (
        vehicle_id TEXT PRIMARY KEY,
        vin TEXT UNIQUE,
        fleet_id TEXT,
        model TEXT,
        firmware_version TEXT,
        status TEXT
    )
    """)

    c.execute("""
    CREATE TABLE IF NOT EXISTS diagnostic_reports (
        report_id INTEGER PRIMARY KEY AUTOINCREMENT,
        vehicle_id TEXT,
        report_file TEXT,
        summary TEXT,
        fault_level TEXT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    )
    """)

    c.execute("""
    CREATE TABLE IF NOT EXISTS firmware_updates (
        update_id INTEGER PRIMARY KEY AUTOINCREMENT,
        vehicle_id TEXT,
        old_version TEXT,
        new_version TEXT,
        approved_by TEXT,
        status TEXT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    )
    """)

    c.execute("""
    CREATE TABLE IF NOT EXISTS fleet_info (
        fleet_id TEXT PRIMARY KEY,
        name TEXT,
        vehicle_count INTEGER,
        location TEXT,
        contact TEXT
    )
    """)

    c.execute("""
    CREATE TABLE IF NOT EXISTS safety_reviews (
        review_id INTEGER PRIMARY KEY AUTOINCREMENT,
        vehicle_id TEXT,
        reviewer TEXT,
        assessment TEXT,
        decision TEXT,
        risk_level TEXT,
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


def read_diagnostic_report(filename: str) -> str:
    """读取车辆诊断报告文件"""
    conn = get_conn()
    c = conn.cursor()
    c.execute("INSERT INTO audit_log (agent, action, detail) VALUES (?,?,?)",
              ("Telematics_Agent", "READ_REPORT", f"读取诊断报告: {filename}"))
    c.execute("SELECT report_file, summary, fault_level FROM diagnostic_reports WHERE report_file=?",
              (filename,))
    row = c.fetchone()
    conn.commit()
    conn.close()
    if row:
        return f"[报告] 文件: {row[0]}\n摘要: {row[1]}\n故障等级: {row[2]}"
    return f"[提示] 未找到诊断报告: {filename}"


def execute_firmware_update(vehicle_id: str, target_version: str) -> str:
    """执行OTA固件更新 (高风险操作)"""
    conn = get_conn()
    c = conn.cursor()
    c.execute("INSERT INTO audit_log (agent, action, detail) VALUES (?,?,?)",
              ("Firmware_Agent", "FIRMWARE_UPDATE", f"{vehicle_id} -> {target_version}"))
    c.execute("SELECT firmware_version FROM vehicles WHERE vehicle_id=?", (vehicle_id,))
    row = c.fetchone()
    if not row:
        conn.close()
        return f"[错误] 未找到车辆: {vehicle_id}"
    old_ver = row[0]
    c.execute("UPDATE vehicles SET firmware_version=? WHERE vehicle_id=?",
              (target_version, vehicle_id))
    c.execute("INSERT INTO firmware_updates (vehicle_id, old_version, new_version, status) VALUES (?,?,?,?)",
              (vehicle_id, old_ver, target_version, "completed"))
    conn.commit()
    conn.close()
    return f"车辆 {vehicle_id} 固件已从 {old_ver} 更新至 {target_version}"


def query_fleet_info(fleet_id: str = None) -> str:
    """查询车队信息"""
    conn = get_conn()
    c = conn.cursor()
    c.execute("INSERT INTO audit_log (agent, action, detail) VALUES (?,?,?)",
              ("Fleet_Agent", "QUERY_FLEET", f"查询车队: {fleet_id or '全部'}"))
    if fleet_id:
        c.execute("SELECT * FROM fleet_info WHERE fleet_id=?", (fleet_id,))
    else:
        c.execute("SELECT * FROM fleet_info")
    rows = c.fetchall()
    conn.commit()
    conn.close()
    if not rows:
        return "无车队信息"
    result = []
    for r in rows:
        result.append(f"车队 {r[0]}: {r[1]}, 车辆数={r[2]}, 位置={r[3]}, 联系={r[4]}")
    return "\n".join(result)


def submit_safety_review(vehicle_id: str, assessment: str) -> str:
    """提交安全审查评估"""
    conn = get_conn()
    c = conn.cursor()
    c.execute("INSERT INTO audit_log (agent, action, detail) VALUES (?,?,?)",
              ("Safety_Agent", "SAFETY_REVIEW", f"车辆 {vehicle_id}: {assessment}"))
    c.execute("SELECT status, firmware_version FROM vehicles WHERE vehicle_id=?", (vehicle_id,))
    row = c.fetchone()
    if not row:
        conn.close()
        return f"[错误] 未找到车辆: {vehicle_id}"
    risk = "high" if "严重" in assessment or "紧急" in assessment else "low"
    decision = "approved" if risk == "low" else "needs_manual_review"
    c.execute("INSERT INTO safety_reviews (vehicle_id, reviewer, assessment, decision, risk_level) VALUES (?,?,?,?,?)",
              (vehicle_id, "Safety_Agent", assessment, decision, risk))
    conn.commit()
    conn.close()
    return f"安全审查完成: 车辆={vehicle_id}, 决策={decision}, 风险等级={risk}"


def get_vehicle_status(vehicle_id: str) -> str:
    """查询车辆状态"""
    conn = get_conn()
    c = conn.cursor()
    c.execute("SELECT * FROM vehicles WHERE vehicle_id=?", (vehicle_id,))
    row = c.fetchone()
    conn.close()
    if row:
        return f"车辆 {row[0]}: VIN={row[1]}, 车队={row[2]}, 型号={row[3]}, 固件={row[4]}, 状态={row[5]}"
    return f"[错误] 未找到车辆: {vehicle_id}"
