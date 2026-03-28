from attack_core import init_healthcare_db, seed_healthcare_data, run_attack_scenario, _get_core
from attack_prompts import ATTACK_A1, ATTACK_A2

if __name__ == "__main__":
    init_healthcare_db()
    seed_healthcare_data()

    print("\n" + "=" * 80)
    print("执行攻击类别 A: 路径绕过攻击 (Path Bypass)")
    print("=" * 80)

    run_attack_scenario("场景 A1 | 路径绕过 — 紧急情况诱导", "path_bypass", ATTACK_A1, "standard")
    run_attack_scenario("场景 A2 | 路径绕过 — 权威指令诱导", "path_bypass", ATTACK_A2, "standard")

    _get_core().flush()
    print("✅ 类别 A 攻击模拟结束，结果已写入相关审计日志。")