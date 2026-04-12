from attack_core import init_asset_db, init_trade_db, seed_asset_data, run_attack_scenario
from attack_prompts import ATTACK_6_1, ATTACK_6_2, ATTACK_6_3

if __name__ == "__main__":
    init_asset_db()
    init_trade_db()
    seed_asset_data()

    print("\n" + "=" * 80)
    print("执行攻击类别 F: 智能体中间人攻击 (Agent-in-The-Middle, AiTM)")
    print("=" * 80)

    run_attack_scenario("场景 6-1 | AiTM — 篡改交易数量",     "AiTM", ATTACK_6_1, graph_type="AiTM")
    run_attack_scenario("场景 6-2 | AiTM — 伪造审批通过",     "AiTM", ATTACK_6_2, graph_type="AiTM")
    run_attack_scenario("场景 6-3 | AiTM — 更改系统目的",     "AiTM", ATTACK_6_3, graph_type="AiTM")

    print("✅ 类别 F 攻击模拟结束，结果已写入 audit_events.json")