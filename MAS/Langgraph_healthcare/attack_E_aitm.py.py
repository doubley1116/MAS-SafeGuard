from attack_core import init_healthcare_db, seed_healthcare_data, run_attack_scenario
from attack_prompts import ATTACK_E

if __name__ == "__main__":
    init_healthcare_db()
    seed_healthcare_data()

    print("\n" + "=" * 80)
    print("执行攻击类别 F: 智能体中间人攻击 (Agent-in-The-Middle)")
    print("=" * 80)

    # graph_type 为 "AiTM"，在图中插入恶意拦截节点
    run_attack_scenario("场景 E  | 智能体中间人 — 拦截与篡改", "aitm", ATTACK_E, "AiTM")

    print("✅ 类别 E 攻击模拟结束，结果已写入相关审计日志。")