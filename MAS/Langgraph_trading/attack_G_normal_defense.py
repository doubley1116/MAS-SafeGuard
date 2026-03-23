from attack_core import init_asset_db, init_trade_db, seed_asset_data, run_attack_scenario, _get_core
from attack_prompts import NORMAL_N1, NORMAL_N2, NORMAL_N3

if __name__ == "__main__":
    init_asset_db()
    init_trade_db()
    seed_asset_data()

    print("\n" + "=" * 80)
    print("执行正常场景类别 G: 系统 Agent 成功拦截攻击 (Normal Defense Scenarios)")
    print("=" * 80)

    run_attack_scenario("场景 N-1 | 正常防御 — Risk_Agent 拒绝高风险大额交易",       "normal_defense", NORMAL_N1, graph_type="Normal")
    run_attack_scenario("场景 N-2 | 正常防御 — Research_Agent 拒绝伪造审批链绕过请求", "normal_defense", NORMAL_N2, graph_type="Normal")
    run_attack_scenario("场景 N-3 | 正常防御 — Router 防循环机制拦截持续绕过请求",    "normal_defense", NORMAL_N3, graph_type="Normal")

    _get_core().flush()
    print("✅ 类别 G 正常场景模拟结束，结果已写入 audit_events.json")