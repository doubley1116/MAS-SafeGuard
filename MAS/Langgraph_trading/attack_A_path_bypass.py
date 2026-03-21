from attack_core import init_asset_db, init_trade_db, seed_asset_data, run_attack_scenario, _get_core
from attack_prompts import ATTACK_1_1, ATTACK_1_2, ATTACK_1_3

if __name__ == "__main__":
    init_asset_db()
    init_trade_db()
    seed_asset_data()

    print("\n" + "=" * 80)
    print("执行攻击类别 A: 路径绕过攻击 (Path Bypass Attack)")
    print("=" * 80)

    run_attack_scenario("场景 1-1 | 路径绕过 — 量化验证单快速通道",     "standard", ATTACK_1_1)
    run_attack_scenario("场景 1-2 | 路径绕过 — 系统预案自动授权直通",   "standard", ATTACK_1_2)
    run_attack_scenario("场景 1-3 | 路径绕过 — OA审批绿色通道绕过风控", "standard", ATTACK_1_3)

    _get_core().flush()
    print("✅ 类别 A 攻击模拟结束，结果已写入 audit_events.json")