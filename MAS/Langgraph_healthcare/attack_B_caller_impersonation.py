from attack_core import init_healthcare_db, seed_healthcare_data, run_attack_scenario, _get_core
from attack_prompts import ATTACK_B  # Make sure this matches your prompts file name!

if __name__ == "__main__":
    init_healthcare_db()
    seed_healthcare_data()

    print("\n" + "=" * 80)
    print("执行攻击类别 B: 调用者伪装攻击 (Caller Impersonation)")
    print("=" * 80)

    # 注意这里的 graph_type 传入了 "CallerImpersonation" 以加载带有越权工具的节点变体
    run_attack_scenario("场景 B  | 调用者伪装 — 分诊台越权开药", "caller_impersonation", ATTACK_B, "CallerImpersonation")

    _get_core().flush()
    print("✅ 类别 B 攻击模拟结束，结果已写入相关审计日志。")