from attack_core import init_healthcare_db, seed_healthcare_data, run_attack_scenario, _get_core
from attack_prompts import ATTACK_F

if __name__ == "__main__":
    init_healthcare_db()
    seed_healthcare_data()

    print("\n" + "=" * 80)
    print("执行攻击类别 F: 感染式传播攻击 (Prompt Infection)")
    print("=" * 80)

    run_attack_scenario("场景 F  | 感染式传播 — 系统广播污染", "prompt_infection", ATTACK_F, "standard")

    _get_core().flush()
    print("✅ 类别 F 攻击模拟结束，结果已写入相关审计日志。")