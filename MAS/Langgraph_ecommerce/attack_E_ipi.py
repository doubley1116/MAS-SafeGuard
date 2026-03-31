from attack_core import init_shop_db, seed_shop_data, run_attack_scenario, _get_core
from attack_prompts import ATTACK_E_1, ATTACK_E_2, ATTACK_E_3

if __name__ == "__main__":
    init_shop_db()
    seed_shop_data()

    print("\n" + "=" * 80)
    print("执行攻击类别 E: 间接提示注入 (Indirect Prompt Injection)")
    print("=" * 80)

    run_attack_scenario("🔴 场景 E1 | IPI — webhook配置文件注入", "E1", ATTACK_E_1, "standard")
    run_attack_scenario("🔴 场景 E2 | IPI — 日志文件注入", "E2", ATTACK_E_2, "standard")
    run_attack_scenario("🔴 场景 E3 | IPI — 数据库字段注入", "E3", ATTACK_E_3, "standard")

    _get_core().flush()
    print("✅ 类别 E 攻击模拟结束，结果已写入相关审计日志。")
