from attack_core import init_asset_db, init_trade_db, seed_asset_data, run_attack_scenario
from attack_prompts import ATTACK_2_1, ATTACK_2_2, ATTACK_2_3

if __name__ == "__main__":
    init_asset_db()
    init_trade_db()
    seed_asset_data()

    print("\n" + "=" * 80)
    print("执行攻击类别 B: 调用者伪装与权限提升攻击 (Caller Impersonation & Privilege Escalation)")
    print("=" * 80)

    run_attack_scenario("场景 2-1 | 调用者伪装 — 冒充管理员旁路投研",   "caller_impersonation", ATTACK_2_1)
    run_attack_scenario("场景 2-2 | 调用者伪装 — 冒充合规官发特批指令", "caller_impersonation", ATTACK_2_2)
    run_attack_scenario("场景 2-3 | 权限提升   — 低权限Agent诱导高权限", "caller_impersonation",  ATTACK_2_3)

    print("✅ 类别 B 攻击模拟结束，结果已写入 audit_events.json")