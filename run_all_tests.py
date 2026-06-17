"""
run_all_tests.py — 完整实验执行脚本

包含:
  Layer 1: Rule Engine 白盒测试 (22个用例)
  Layer 1: EWMA 白盒测试 (5个用例)
  Layer 2: Rule Engine + EWMA 消融实验

用法:
    python run_all_tests.py                    # 运行所有测试
    python run_all_tests.py --skip-normal-runs # 跳过MAS正常场景运行(使用已有数据)
    python run_all_tests.py --domains iov,converged_media  # 只测试指定领域
"""
import os, sys, subprocess, datetime, argparse
from collections import defaultdict

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
os.chdir(SCRIPT_DIR)
sys.path.insert(0, SCRIPT_DIR)


def run_normal_scenarios(rounds=5):
    """为 iov 和 converged_media 运行真实 MAS 正常场景(LLM驱动)"""
    print("=" * 70)
    print("Step 0: 运行 MAS 正常业务场景 (LLM 驱动, 用于 EWMA 预热)")
    print("=" * 70)

    for domain, mas_name in [("iov", "Langgraph_iov"), ("converged_media", "Langgraph_converged_media")]:
        mas_dir = os.path.join(SCRIPT_DIR, "MAS", mas_name)
        output_dir = os.path.join(mas_dir, "data", "workflows", f"{domain}_normal")
        os.makedirs(output_dir, exist_ok=True)

        jsonl_files = [f for f in os.listdir(output_dir) if f.endswith('.jsonl')] if os.path.isdir(output_dir) else []
        if len(jsonl_files) >= 30:
            print(f"  [{domain}] 已有 {len(jsonl_files)} 个trace文件，跳过运行")
            continue

        # Clean old synthetic data if present
        for old_file in os.listdir(output_dir):
            if 'synthetic' in old_file:
                os.remove(os.path.join(output_dir, old_file))

        print(f"  [{domain}] 运行 {rounds} 轮 MAS 正常场景...")
        run_script = os.path.join(mas_dir, "run_normal_scenarios.py")
        result = subprocess.run(
            [sys.executable, run_script, "--rounds", str(rounds)],
            capture_output=True, text=True, cwd=mas_dir
        )
        # Print last lines of output
        for line in result.stdout.strip().split('\n')[-5:]:
            print(f"    {line}")
        if result.stderr:
            print(f"    ERR: {result.stderr[-200]}")


def run_layer1_tests():
    """Step 1: Layer 1 white-box correctness tests"""
    print("\n" + "=" * 70)
    print("Step 1: Layer 1 白盒测试")
    print("=" * 70)

    results = {}

    # Rule Engine tests
    print("\n--- Rule Engine Tests ---")
    rule_path = os.path.join(SCRIPT_DIR, "tests", "test_rule_engine.py")
    result = subprocess.run(
        [sys.executable, rule_path], capture_output=True, text=True
    )
    print(result.stdout[-500:] if len(result.stdout) > 500 else result.stdout)
    results["rule_engine"] = "PASS" if result.returncode == 0 else "FAIL"

    # EWMA tests
    print("\n--- EWMA Tests ---")
    ewma_path = os.path.join(SCRIPT_DIR, "tests", "test_ewma.py")
    result = subprocess.run(
        [sys.executable, ewma_path], capture_output=True, text=True
    )
    for line in result.stdout.split('\n'):
        if any(kw in line for kw in ['PASS', 'FAIL', 'Layer', 'Total', 'Domain', 'Results']):
            print(line)
    results["ewma"] = "PASS" if result.returncode == 0 else "FAIL"

    return results


def run_layer2_tests(domains_filter=None):
    """Step 2: Layer 2 ablation experiments"""
    print("\n" + "=" * 70)
    print("Step 2: Layer 2 消融实验 (分层门控)")
    print("=" * 70)

    combined_path = os.path.join(SCRIPT_DIR, "tests", "test_combined.py")

    env = os.environ.copy()
    if domains_filter:
        env["TEST_DOMAINS"] = ",".join(domains_filter)

    result = subprocess.run(
        [sys.executable, combined_path], capture_output=True, text=True, env=env
    )
    print(result.stdout[-2000:] if len(result.stdout) > 2000 else result.stdout)

    return result.returncode == 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="完整实验执行脚本")
    parser.add_argument("--skip-normal-runs", action="store_true",
                        help="跳过MAS正常场景运行")
    parser.add_argument("--domains", type=str, default=None,
                        help="只测试指定领域 (逗号分隔)")
    args = parser.parse_args()

    domains_filter = None
    if args.domains:
        domains_filter = [d.strip() for d in args.domains.split(",")]

    print("=" * 70)
    print("Zero Trust MAS Audit Pipeline — 完整实验")
    print(f"时间: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 70)

    if not args.skip_normal_runs:
        run_normal_scenarios(rounds=5)

    l1_results = run_layer1_tests()
    l2_passed = run_layer2_tests(domains_filter)

    print("\n" + "=" * 70)
    print("实验完成！")
    print(f"  Layer 1 Rule Engine: {l1_results.get('rule_engine', 'N/A')}")
    print(f"  Layer 1 EWMA: {l1_results.get('ewma', 'N/A')}")
    print(f"  Layer 2 Combined: {'PASS' if l2_passed else 'FAIL (see above)'}")
    print("=" * 70)
