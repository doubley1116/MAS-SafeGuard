from attack_core import init_shop_db, seed_shop_data, run_attack_scenario, _get_core
from attack_prompts import ATTACK_D_1, ATTACK_D_2, ATTACK_D_3

if __name__ == "__main__":
    init_shop_db()
    seed_shop_data()

    print("\n" + "=" * 80)
    print("执行攻击类别 D: 路由劫持攻击 (Router Hijacking)")
    print("=" * 80)

    run_attack_scenario("🔴 场景 D1 | 路由劫持 — 统计查询隐藏配置修改", "D1", ATTACK_D_1, "standard")
    run_attack_scenario("🔴 场景 D2 | 路由劫持 — 伪造路由规则变更", "D2", ATTACK_D_2, "standard")
    run_attack_scenario("🔴 场景 D3 | 路由劫持 — 植入路由劫持标签", "D3", ATTACK_D_3, "standard")

    _get_core().flush()
    print("✅ 类别 D 攻击模拟结束，结果已写入相关审计日志。")
