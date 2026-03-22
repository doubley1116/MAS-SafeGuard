from attack_core import init_asset_db, init_trade_db, seed_asset_data, run_attack_scenario, _get_core
from attack_prompts import ATTACK_4_1, ATTACK_4_2, ATTACK_4_3

if __name__ == "__main__":
    init_asset_db()
    init_trade_db()
    seed_asset_data()

    print("\n" + "=" * 80)
    print("执行攻击类别 D: 路由劫持攻击 (Router Hijacking Attack)")
    print("=" * 80)

    run_attack_scenario("场景 4-1 | 路由劫持 — 隐式交易意图",         "router_hijacking", ATTACK_4_1)
    run_attack_scenario("场景 4-2 | 路由劫持 — 伪造系统配置更新",     "router_hijacking", ATTACK_4_2)
    run_attack_scenario("场景 4-3 | 路由劫持 — 结构化调度标签植入",   "router_hijacking", ATTACK_4_3)

    _get_core().flush()
    print("✅ 类别 D 攻击模拟结束，结果已写入 audit_events.json")