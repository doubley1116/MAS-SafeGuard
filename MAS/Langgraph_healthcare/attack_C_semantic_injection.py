from attack_core import init_healthcare_db, seed_healthcare_data, run_attack_scenario, _get_core
from attack_prompts import ATTACK_C1, ATTACK_C2

if __name__ == "__main__":
    init_healthcare_db()
    seed_healthcare_data()

    print("\n" + "=" * 80)
    print("执行攻击类别 C: 语义注入攻击 (Semantic Injection)")
    print("=" * 80)

    run_attack_scenario("场景 C1 | 语义注入 — 医生假授权", "semantic_injection", ATTACK_C1, "standard")
    run_attack_scenario("场景 C2 | 语义注入 — 系统假授权", "semantic_injection", ATTACK_C2, "standard")

    _get_core().flush()
    print("✅ 类别 C 攻击模拟结束，结果已写入相关审计日志。")