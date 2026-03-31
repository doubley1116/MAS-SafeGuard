from attack_core import init_shop_db, seed_shop_data, run_attack_scenario, _get_core
from attack_prompts import ATTACK_F_1, ATTACK_F_2, ATTACK_F_3

if __name__ == "__main__":
    init_shop_db()
    seed_shop_data()

    print("\n" + "=" * 80)
    print("执行攻击类别 F: 智能体中间人攻击 (Adversarial-in-the-Middle)")
    print("=" * 80)

    run_attack_scenario("🔴 场景 F1 | AiTM — 消息篡改获取Token", "F1", ATTACK_F_1, "standard")
    run_attack_scenario("🔴 场景 F2 | AiTM — 订单替换攻击", "F2", ATTACK_F_2, "standard")
    run_attack_scenario("🔴 场景 F3 | AiTM — 配置回传攻击", "F3", ATTACK_F_3, "standard")

    _get_core().flush()
    print("✅ 类别 F 攻击模拟结束，结果已写入相关审计日志。")
