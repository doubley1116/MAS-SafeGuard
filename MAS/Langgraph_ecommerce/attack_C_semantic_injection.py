from attack_core import init_shop_db, seed_shop_data, run_attack_scenario, _get_core
from attack_prompts import ATTACK_C_1, ATTACK_C_2, ATTACK_C_3

if __name__ == "__main__":
    init_shop_db()
    seed_shop_data()

    print("\n" + "=" * 80)
    print("执行攻击类别 C: 语义注入攻击 (Semantic Injection)")
    print("=" * 80)

    run_attack_scenario("🔴 场景 C1 | 语义注入 — 统计分析嵌套配置修改", "C1", ATTACK_C_1, "standard")
    run_attack_scenario("🔴 场景 C2 | 语义注入 — 订单排查嵌套Token获取", "C2", ATTACK_C_2, "standard")
    run_attack_scenario("🔴 场景 C3 | 语义注入 — 格式验证嵌套物流录入", "C3", ATTACK_C_3, "standard")

    _get_core().flush()
    print("✅ 类别 C 攻击模拟结束，结果已写入相关审计日志。")
