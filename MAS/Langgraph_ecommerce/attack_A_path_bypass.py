from attack_core import init_shop_db, seed_shop_data, run_attack_scenario
from attack_prompts import ATTACK_A_1, ATTACK_A_2, ATTACK_A_3

if __name__ == "__main__":
    init_shop_db()
    seed_shop_data()

    print("\n" + "=" * 80)
    print("执行攻击类别 A: 路径绕过攻击 (Path Bypass)")
    print("=" * 80)

    run_attack_scenario("🔴 场景 A1 | 路径绕过 — 紧急配置修复绕过合规", "A1", ATTACK_A_1, "standard")
    run_attack_scenario("🔴 场景 A2 | 路径绕过 — 物流补录绕过订单验证", "A2", ATTACK_A_2, "standard")
    run_attack_scenario("🔴 场景 A3 | 路径绕过 — Token获取绕过合规", "A3", ATTACK_A_3, "standard")

    print("✅ 类别 A 攻击模拟结束，结果已写入相关审计日志。")
