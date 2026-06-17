from database.iov_db import get_conn


def seed_iov_data():
    conn = get_conn()
    c = conn.cursor()

    # 车辆数据
    vehicles = [
        ("VEH-FL-88422", "LSVD-AZ21-4875", "FL-007", "Tesla Model 3", "FW-v3.2.1-20250317", "active"),
        ("VEH-FL-99015", "LSVD-BX33-9210", "FL-007", "BYD Han EV", "FW-v3.3.0-20250401", "active"),
        ("VEH-FL-77103", "LSVD-CY45-1836", "FL-003", "NIO ET5", "FW-v2.8.5-20250115", "maintenance"),
    ]
    for v in vehicles:
        c.execute(
            "INSERT OR IGNORE INTO vehicles (vehicle_id, vin, fleet_id, model, firmware_version, status) VALUES (?,?,?,?,?,?)",
            v,
        )

    # 诊断报告
    reports = [
        (1, "VEH-FL-88422", "vehicle_diag_report_VEH-FL-88422.txt",
         "电气系统故障，自动驾驶功能暂时失效，需立即修复", "critical"),
        (2, "VEH-FL-99015", "vehicle_diag_report_VEH-FL-99015.txt",
         "电池管理系统异常，充电效率下降15%", "warning"),
        (3, "VEH-FL-77103", "vehicle_diag_report_VEH-FL-77103.txt",
         "制动系统磨损预警，建议8000km内更换刹车片", "warning"),
    ]
    for r in reports:
        c.execute(
            "INSERT OR IGNORE INTO diagnostic_reports (report_id, vehicle_id, report_file, summary, fault_level) VALUES (?,?,?,?,?)",
            r,
        )

    # 车队信息
    fleets = [
        ("FL-007", "上海第七车队", 12, "上海市浦东新区", "李队长 138xxxx"),
        ("FL-003", "北京第三车队", 8, "北京市海淀区", "王队长 139xxxx"),
    ]
    for fl in fleets:
        c.execute(
            "INSERT OR IGNORE INTO fleet_info (fleet_id, name, vehicle_count, location, contact) VALUES (?,?,?,?,?)",
            fl,
        )

    conn.commit()
    conn.close()
