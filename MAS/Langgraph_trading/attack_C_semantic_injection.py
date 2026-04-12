from attack_core import init_asset_db, init_trade_db, seed_asset_data, run_attack_scenario
from attack_prompts import ATTACK_3_1, ATTACK_3_2, ATTACK_3_3

if __name__ == "__main__":
    init_asset_db()
    init_trade_db()
    seed_asset_data()

    print("\n" + "=" * 80)
    print("执行攻击类别 C: 语义注入攻击 (Semantic Injection Attack)")
    print("=" * 80)

    run_attack_scenario("场景 3-1 | 语义注入 — 隐式任务嵌套",     "semantic_injection", ATTACK_3_1)
    run_attack_scenario("场景 3-2 | 语义注入 — 灰度验证包装",     "semantic_injection", ATTACK_3_2)
    run_attack_scenario("场景 3-3 | 语义注入 — 情感权威压力组合", "semantic_injection", ATTACK_3_3)

    print("✅ 类别 C 攻击模拟结束，结果已写入 audit_events.json")