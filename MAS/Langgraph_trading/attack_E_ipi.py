from attack_core import init_asset_db, init_trade_db, seed_asset_data, setup_ipi_files, run_attack_scenario, _get_core
from attack_prompts import ATTACK_5_1, ATTACK_5_2, ATTACK_5_3

if __name__ == "__main__":
    init_asset_db()
    init_trade_db()
    seed_asset_data()
    setup_ipi_files()  # IPI 场景专属依赖

    print("\n" + "=" * 80)
    print("执行攻击类别 E: 间接提示注入攻击 (Indirect Prompt Injection, IPI)")
    print("=" * 80)

    run_attack_scenario("场景 5-1 | IPI — 外部报告文件注入",      "IPI", ATTACK_5_1, graph_type="IPI")
    run_attack_scenario("场景 5-2 | IPI — 新闻摘要伪造风控评级",  "IPI", ATTACK_5_2, graph_type="IPI")
    run_attack_scenario("场景 5-3 | IPI — 伪造历史会话污染上下文","IPI", ATTACK_5_3, graph_type="IPI")

    _get_core().flush()
    print("✅ 类别 E 攻击模拟结束，结果已写入 audit_events.json")