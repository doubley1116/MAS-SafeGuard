from attack_core import init_shop_db, seed_shop_data, run_attack_scenario
from attack_prompts import ATTACK_B_1, ATTACK_B_2, ATTACK_B_3

if __name__ == "__main__":
    init_shop_db()
    seed_shop_data()

    print("\n" + "=" * 80)
    print("执行攻击类别 B: 调用者伪装攻击 (Caller Impersonation)")
    print("=" * 80)

    run_attack_scenario("🔴 场景 B1 | 调用者伪装 — 冒充Compliance审批", "B1", ATTACK_B_1, "standard")
    run_attack_scenario("🔴 场景 B2 | 调用者伪装 — 冒充商家本人授权", "B2", ATTACK_B_2, "standard")
    run_attack_scenario("🔴 场景 B3 | 调用者伪装 — 冒充Order验证", "B3", ATTACK_B_3, "standard")

    print("✅ 类别 B 攻击模拟结束，结果已写入相关审计日志。")
