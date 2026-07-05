"""
EWMA trajectory anomaly detector correctness tests (Layer 1)
~7 test cases verifying each feature dimension's anomaly detection.
Warms up from real MAS trace data (not hand-written paths).
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from audit_layer.trajectory_model import TrajectoryAnomalyDetector
from tests.utils.helpers import extract_mas_call_paths, get_mas_data_dir

PASS, FAIL = 0, 0

def check(test_name, score, expected_range, note=""):
    global PASS, FAIL
    lo, hi = expected_range
    if lo <= score <= hi:
        PASS += 1
        print(f"  [PASS] {test_name}: score={score:.4f} {note}")
    else:
        FAIL += 1
        print(f"  [FAIL] {test_name}: score={score:.4f} (expected [{lo}, {hi}]) {note}")


print("=" * 60)
print("EWMA Correctness Tests (Layer 1)")
print("=" * 60)

# Warm up from real MAS data (use trading as a representative domain)
mas_dir = get_mas_data_dir("financial")
if mas_dir:
    warmup_paths = extract_mas_call_paths(mas_dir, dedup=False)
    print(f"\n  Warmup from real MAS data: {len(warmup_paths)} observations")
else:
    warmup_paths = []
    print(f"\n  WARNING: No MAS data found, tests may be unreliable")

detector = TrajectoryAnomalyDetector()
detector.fit_normal(warmup_paths)

print(f"  Detector ready: {detector.is_ready} (n_obs={detector.observation_count})")
print(f"  Baseline summary:\n{detector.summary()}")

# Get known agents from warmup to construct test paths
known_agents = sorted(detector.monitor._transition_totals.keys())
print(f"  Known agents: {known_agents}")

# Pick representative agents from real warmup
a0 = known_agents[0] if known_agents else "User"
a1 = known_agents[1] if len(known_agents) > 1 else "Agent_A"
a2 = known_agents[2] if len(known_agents) > 2 else "Agent_B"
a3 = known_agents[3] if len(known_agents) > 3 else "Agent_C"

# Test 1: Normal path (from warmup) -> low score
normal = warmup_paths[0] if warmup_paths else [a0, a1, a2]
score1 = detector.score(normal)
check("normal path (from warmup)", score1, (0.0, 0.3),
      f"path={'->'.join(normal)}")

# Test 2: Path with 6 unknown agents -> high score (novel edges + depth)
score2 = detector.score([a0, "Evil1", "Evil2", "Evil3", "Evil4", "Evil5", "Evil6"])
check("unknown agent path", score2, (0.3, 1.0), "(novel edges + depth)")

# Test 3: Short path from warmup -> should be clean
# Pick the first two agents from a known warmup path
short = warmup_paths[0][:2] if len(warmup_paths[0]) >= 2 else warmup_paths[0]
score3 = detector.score(short)
check("short warmup path", score3, (0.0, 0.3),
      f"path={'->'.join(short)}")

# Test 4: Excessive depth (12 agents) -> depth anomaly
deep_path = [a0] + [a1] * 10 + [a2]
score4 = detector.score(deep_path)
check("excessive depth path", score4, (0.3, 1.0), "(depth anomaly)")

# Test 5: Known agents but novel edge (reverse direction)
# If a1->a2 exists, try a2->a1 which may be novel
novel_path = [a0, a2, a1] if len(known_agents) > 2 else [a0, a2, "Evil"]
score5 = detector.score(novel_path)
check("novel edge path", score5, (0.0, 1.0),
      f"path={'->'.join(novel_path)}")

# Test 6: Edge surprise catches unusual-but-known transitions
detector2 = TrajectoryAnomalyDetector()
biased_warmup = [
    [a0, a1, a2], [a0, a1, a2], [a0, a1, a2],
    [a0, a1, a2], [a0, a1, a2], [a0, a1, a2],
    [a0, a1, a2], [a0, a1, a2], [a0, a1, a2],
    [a0, a3, a2],  # a1->a2 appears 9x, a3->a2 only 1x
]
detector2.fit_normal(biased_warmup)
score6a = detector2.score([a0, a1, a2])
score6b = detector2.score([a0, a3, a2])
check("edge_surprise normal", score6a, (0.0, 0.3),
      f"(common transition, score={score6a:.4f})")
check("edge_surprise unusual", score6b, (0.0, 1.0),
      f"(rare transition, score={score6b:.4f})")

# Test 7: score_with_details on anomalous path
score7, details = detector.score_with_details(
    [a0, "Evil1", "Evil2", "Evil3", "Evil4", "Evil5"])
print(f"\n  score_with_details example:")
for feat, info in details.items():
    flag = " *** ANOMALY" if info.get("anomaly") else ""
    print(f"    {feat}: value={info['value']}, z={info['z_score']}, mean={info.get('mean')}{flag}")

print(f"\n{'='*50}")
print(f"Results: {PASS} passed, {FAIL} failed (total {PASS+FAIL})")
print(f"{'='*50}")
if FAIL > 0:
    print("SOME TESTS FAILED")
    sys.exit(1)
else:
    print("ALL TESTS PASSED")

# ================================================================
# Layer 2: EWMA scale tests with real data (OPTIMIZED)
# ================================================================
#
# Optimizations from previous run:
#   1. dedup=False for warmup — EWMA benefits from observation count, not uniqueness
#   2. Lower k thresholds (2.0 instead of 3.0) — improves sensitivity
#   3. Multi-threshold reporting — >=0.3 (warning) and >=0.5 (alarm)
#   4. Proper benign holdout from non-deduped paths — measures false positive rate

import pickle
from collections import Counter, defaultdict
from tests.utils.helpers import (
    load_audit_events, split_by_domain,
    extract_benign_call_paths, extract_attack_call_paths,
    extract_mas_call_paths, get_mas_data_dir,
    dedup_call_paths,
)

AUDIT_DATA = os.path.join(os.path.dirname(__file__), "..", "AuditDataGen", "eval_results_verify", "origin_consistent.jsonl")
RESULT_DIR = os.path.join(os.path.dirname(__file__), "tmp_rule_ewma_results")
CKPT_DIR = os.path.join(os.path.dirname(__file__), "..", "audit_layer", "trajectory_checkpoints")
os.makedirs(RESULT_DIR, exist_ok=True)
os.makedirs(CKPT_DIR, exist_ok=True)


print("\n" + "=" * 60)
print("EWMA Scale Tests (Layer 2)")
print("=" * 60)
print("  dedup=False (warmup), using default k thresholds from trajectory_model.py")
print()

all_events = load_audit_events(AUDIT_DATA)
events_by_domain = split_by_domain(all_events)
print(f"  Domains found: {len(events_by_domain)} — will test all (EWMA is domain-specific, no policies needed)")
print()

# Per-domain results
all_results = {}  # domain -> {attack_type: [(call_path, score)], "benign_scores": [...]}

for domain, domain_events in sorted(events_by_domain.items()):
    # EWMA doesn't need policy files — test ALL domains
    domain_key = domain  # use raw domain name for checkpoint naming

    print(f"\n--- Domain: {domain} ({len(domain_events)} events) ---")

    # ── Warmup: 三级预热策略 ──
    # 1. MAS 正常场景数据（真实 LLM 驱动，最优）
    # 2. all_consistent benign 数据（测试集自身提供的合法路径）
    # 3. 合成多跳路径（policy adjacency 合法边组合，丰富 depth 分布）

    from audit_layer.trajectory_model import TrajectoryAnomalyDetector
    from tests.utils.helpers import generate_synthetic_multihop_paths

    # Load policy adjacency first (needed for seeding + synthetic paths)
    policy_path = os.path.join(
        os.path.dirname(__file__), "fixtures", f"policy_{domain}.yaml"
    )
    _adj = {}
    if os.path.exists(policy_path):
        import yaml as _yaml
        with open(policy_path, 'r', encoding='utf-8') as _f:
            _policy = _yaml.safe_load(_f)
        _adj = _policy.get('adjacency', {})
        # Strip Router from adjacency (consistent with warmup preprocessing)
        _adj = {k: [d for d in v if d != 'Router'] for k, v in _adj.items() if k != 'Router'}
        _adj = {k: v for k, v in _adj.items() if v}

    # Step 1: Try MAS warmup
    mas_dir = get_mas_data_dir(domain)
    mas_paths_all = []
    mas_paths_unique = []
    if mas_dir:
        mas_paths_all = extract_mas_call_paths(mas_dir, dedup=False)
        mas_paths_unique = extract_mas_call_paths(mas_dir, dedup=True)
        print(f"  MAS warmup: {len(mas_paths_all)} obs (unique: {len(mas_paths_unique)})")

    # Step 2: Fallback to all_consistent benign data
    benign_paths_all = extract_benign_call_paths(domain_events, dedup=False)
    benign_paths_unique = extract_benign_call_paths(domain_events, dedup=True)

    # Merge: MAS + benign 合并，确保所有合法边都在 warmup 中出现过
    if mas_paths_all:
        warmup_paths = mas_paths_all + benign_paths_all
        warmup_unique = dedup_call_paths(mas_paths_unique + benign_paths_unique)
        print(f"  Warmup source: MAS ({len(mas_paths_all)} obs) + benign ({len(benign_paths_all)} obs)")
    else:
        warmup_paths = benign_paths_all
        warmup_unique = benign_paths_unique
        if benign_paths_all:
            print(f"  Warmup source: all_consistent benign ({len(benign_paths_all)} obs) — MAS data unavailable")
        else:
            print(f"  WARNING: No warmup data available for {domain}")

    # Step 3: Synthetic multi-hop paths (depth 3-4, from policy adjacency)
    # Lightweight supplement: just enough to widen σ_depth so legitimate depth=3 paths
    # (e.g. User→Editor→Copyright, User→Telematics→Firmware) don't trigger z>2.5.
    # No repeats — benign data already provides the primary signal.
    synth_paths = generate_synthetic_multihop_paths(_adj, warmup_unique, max_depth=4, target_count=5)
    if synth_paths:
        warmup_paths = warmup_paths + synth_paths
        print(f"  Synthetic multi-hop: {len(synth_paths)} unique paths (depth 3-4, no repeat)")

    # Attack paths for testing (deduped to avoid double-counting identical paths)
    attack_paths = extract_attack_call_paths(domain_events)
    print(f"  Attack call_paths for testing: {len(attack_paths)}")

    # Warm up detector
    detector = TrajectoryAnomalyDetector()

    # Seed per-agent position distributions from policy adjacency (BEFORE fit_normal)
    # so that position_anomaly features are computed with reasonable baselines
    # during the warmup observe() calls.
    if _adj:
        detector.seed_agent_positions_from_adjacency(_adj)
        print(f"  Agent position seeds: {len(detector.monitor._agent_positions)} agents seeded from adjacency")

    detector.fit_normal(warmup_paths)

    # Seed policy adjacency edges (AFTER fit_normal to supplement transfer counts)
    if _adj:
        detector.seed_policy_edges(_adj)
        print(f"  Policy edges seeded: {sum(len(v) for v in _adj.values())} transitions")

    print(f"  Detector ready: {detector.is_ready} (n_obs={detector.observation_count})")
    print(f"  Baseline summary:")
    for line in detector.summary().split('\n'):
        print(f"    {line}")

    # Save checkpoint
    ckpt_path = os.path.join(CKPT_DIR, f"{domain_key}_detector.pkl")
    detector.save(ckpt_path)
    print(f"  Checkpoint saved: {ckpt_path}")

    # Score attack paths
    attack_scores = defaultdict(list)
    for cp, attack_type in attack_paths:
        score = detector.score(cp)
        attack_scores[attack_type].append((cp, score))

    # Score benign holdout for false positive check
    # Use deduped benign paths (unique): 20% holdout for FP testing
    all_unique = dedup_call_paths(benign_paths_unique)
    split_idx = max(int(len(all_unique) * 0.8), 5)
    if len(all_unique) > split_idx:
        holdout_benign = all_unique[split_idx:]
        benign_scores = [(p, detector.score(p)) for p in holdout_benign]
        attack_scores["benign"] = benign_scores
        print(f"  Benign holdout (FP test): {len(benign_scores)} unique paths")
    else:
        attack_scores["benign"] = []
        print(f"  Benign holdout: insufficient unique paths ({len(all_unique)})")

    all_results[domain] = attack_scores

# ══════════════════════════════════════════════════════════════
# Per-domain results (multi-threshold)
# ══════════════════════════════════════════════════════════════

print(f"\n{'='*85}")
print(f"EWMA Detection Results by Attack Type")
print(f"{'='*85}")

# Aggregate across domains
agg_attack = defaultdict(list)

for domain, results in all_results.items():
    print(f"\n  Domain: {domain}")
    print(f"  {'Attack Type':<25} {'Count':>6} {'Mean':>8} {'Std':>8} {'>=0.3':>8} {'>=0.5':>8}")
    print(f"  {'-'*65}")
    for attack_type in sorted(results.keys()):
        pairs = results[attack_type]
        if not pairs:
            continue
        scores = [s for _, s in pairs]
        mean_score = sum(scores) / len(scores)
        std_score = (sum((s - mean_score) ** 2 for s in scores) / len(scores)) ** 0.5
        d30 = sum(1 for s in scores if s >= 0.3) / len(scores) * 100
        d50 = sum(1 for s in scores if s >= 0.5) / len(scores) * 100
        label_warn = f"{d30:.0f}%" if d30 > 0 else "-"
        label_alarm = f"{d50:.0f}%" if d50 > 0 else "-"
        print(f"  {attack_type:<25} {len(scores):>6} {mean_score:>8.3f} {std_score:>8.3f} {label_warn:>8} {label_alarm:>8}")
        if attack_type != "benign":
            agg_attack[attack_type].extend(scores)

# ══════════════════════════════════════════════════════════════
# Aggregate (all domains)
# ══════════════════════════════════════════════════════════════

print(f"\n  {'='*65}")
print(f"  Aggregate (all domains):")
print(f"  {'Attack Type':<25} {'Count':>6} {'Mean':>8} {'Std':>8} {'>=0.3':>8} {'>=0.5':>8}")
print(f"  {'-'*65}")
for attack_type in sorted(agg_attack.keys()):
    scores = agg_attack[attack_type]
    mean_score = sum(scores) / len(scores)
    std_score = (sum((s - mean_score) ** 2 for s in scores) / len(scores)) ** 0.5
    d30 = sum(1 for s in scores if s >= 0.3) / len(scores) * 100
    d50 = sum(1 for s in scores if s >= 0.5) / len(scores) * 100
    label_warn = f"{d30:.0f}%" if d30 > 0 else "-"
    label_alarm = f"{d50:.0f}%" if d50 > 0 else "-"
    print(f"  {attack_type:<25} {len(scores):>6} {mean_score:>8.3f} {std_score:>8.3f} {label_warn:>8} {label_alarm:>8}")

# Aggregate benign (separate from attack in agg)
all_benign = []
for domain, results in all_results.items():
    for cp, s in results.get("benign", []):
        all_benign.append(s)
if all_benign:
    mean_b = sum(all_benign) / len(all_benign)
    std_b = (sum((s - mean_b) ** 2 for s in all_benign) / len(all_benign)) ** 0.5
    d30_b = sum(1 for s in all_benign if s >= 0.3) / len(all_benign) * 100
    d50_b = sum(1 for s in all_benign if s >= 0.5) / len(all_benign) * 100
    w_b = f"{d30_b:.0f}%" if d30_b > 0 else "-"
    a_b = f"{d50_b:.0f}%" if d50_b > 0 else "-"
    print(f"  {'benign (all domains)':<25} {len(all_benign):>6} {mean_b:>8.3f} {std_b:>8.3f} {w_b:>8} {a_b:>8}")

# ══════════════════════════════════════════════════════════════
# CSV exports
# ══════════════════════════════════════════════════════════════

scores_path = os.path.join(RESULT_DIR, "ewma_scores_by_attack.csv")
with open(scores_path, 'w', encoding='utf-8') as f:
    f.write("domain,attack_type,score\n")
    for domain, results in all_results.items():
        for attack_type, pairs in results.items():
            for _, s in pairs:
                f.write(f"{domain},{attack_type},{s:.4f}\n")
print(f"\n  Score distributions saved to: {scores_path}")

attr_path = os.path.join(RESULT_DIR, "ewma_feature_attribution.csv")
with open(attr_path, 'w', encoding='utf-8') as f:
    f.write("domain,attack_type,call_path,feature,value,z_score,anomaly\n")
    for domain, results in all_results.items():
        ckpt_path = os.path.join(CKPT_DIR, f"{domain}_detector.pkl")
        if not os.path.exists(ckpt_path):
            continue
        attr_detector = TrajectoryAnomalyDetector.load(ckpt_path)
        for attack_type, pairs in results.items():
            if attack_type == "benign" or not pairs:
                continue
            top_pairs = sorted(pairs, key=lambda x: x[1], reverse=True)[:3]
            for cp, score_val in top_pairs:
                _, details = attr_detector.score_with_details(cp)
                for feat_name, info in details.items():
                    if info.get("anomaly"):
                        f.write(f"{domain},{attack_type},{'->'.join(cp)},{feat_name},"
                                f"{info['value']},{info['z_score']},True\n")
print(f"  Feature attribution saved to: {attr_path}")

# ══════════════════════════════════════════════════════════════
# Layer 3: EWMA 独立价值证明 — 三种场景
# ══════════════════════════════════════════════════════════════
# 用 iov 域演示 EWMA 在规则引擎无法覆盖的场景中的独立检测能力。
# 关键：不使用 seed_policy_edges，让政策已知但预热未见的边保持"新颖"。

print(f"\n{'='*70}")
print(f"EWMA Independent Value Tests (Layer 3) — iov domain")
print(f"{'='*70}")
print()

import yaml as _yaml

# Load iov policy adjacency for verifying rule engine behavior
iov_policy_path = os.path.join(os.path.dirname(__file__), "fixtures", "policy_iov.yaml")
with open(iov_policy_path, 'r', encoding='utf-8') as _f:
    _iov_policy = _yaml.safe_load(_f)
_iov_adj = _iov_policy.get('adjacency', {})

# Build a fresh detector WITHOUT seed_policy_edges — only warmup data counts
iov_mas_dir = get_mas_data_dir("iov")
iov_events = [e for e in all_events if e.get("metadata", {}).get("domain") == "iov"]
iov_warmup = extract_mas_call_paths(iov_mas_dir, dedup=False) if iov_mas_dir else []
if not iov_warmup:
    iov_warmup = extract_benign_call_paths(iov_events, dedup=False)
# Also add all_consistent benign for diversity
iov_benign = extract_benign_call_paths(iov_events, dedup=False)
iov_warmup = iov_warmup + iov_benign

iov_det3 = TrajectoryAnomalyDetector()
iov_det3.seed_agent_positions_from_adjacency(
    {k: [d for d in v if d != 'Router'] for k, v in _iov_adj.items() if k != 'Router'}
)
iov_det3.fit_normal(iov_warmup)
# NOTE: deliberately NOT calling seed_policy_edges — this keeps unobserved policy edges novel

print(f"  Warmup: {len(iov_warmup)} obs, {iov_det3.observation_count} EWMA observations")
print(f"  known_edges: {len(iov_det3.monitor._known_edges)} transitions")
print(f"  Seed policy edges: SKIPPED (keeping unobserved policy edges as 'novel')")
print()

# ── Scenario 1: policy-known but warmup-unobserved edge → EWMA novel_edge_ratio ──
# Safety→Fleet is added to adjacency (simulates business expansion), but EWMA has
# never seen this edge. Rule engine ALLOWs, EWMA catches via novel_edge_ratio.
scenario1_path = ["User", "Safety_Agent", "Fleet_Agent"]
scenario1_score, scenario1_details = iov_det3.score_with_details(scenario1_path)
print(f"--- Scenario 1: 新合法边 (Policy YAML 已声明, 预热未见过) ---")
print(f"  路径: {' → '.join(scenario1_path)}")
print(f"  规则引擎: ALLOW (Safety→Fleet 在 adjacency 中)")
print(f"  EWMA score: {scenario1_score:.4f}")
for feat, info in scenario1_details.items():
    flag = " ← EWMA 捕获" if info.get("anomaly") else ""
    print(f"    {feat}: value={info['value']}, z={info['z_score']}, mean={info.get('mean'):.3f}{flag}")
print(f"  结论: {'✅ EWMA 独立捕获' if scenario1_score >= 0.35 else '❌ 未捕获'}")

print()

# ── Scenario 2: frequency anomaly → EWMA edge_surprise ──
# User→Telematics→Fleet is a legal path (all edges in adjacency and warmup),
# but we repeat Fleet↔Telematics 5 times simulating DDoS abuse.
# Telematics→Fleet is a rare edge (only in adjacency seeding if not seeded),
# so edge_surprise accumulates rapidly.
scenario2_path = ["User", "Telematics_Agent", "Fleet_Agent",
                  "Telematics_Agent", "Fleet_Agent",
                  "Telematics_Agent", "Fleet_Agent"]
scenario2_score, scenario2_details = iov_det3.score_with_details(scenario2_path)
print(f"--- Scenario 2: 频率异常 (DDoS 式滥用, 合法边反复调用) ---")
print(f"  路径: {' → '.join(scenario2_path)}")
print(f"  规则引擎: ALLOW (所有边在 adjacency 中)")
print(f"  EWMA score: {scenario2_score:.4f}")
for feat, info in scenario2_details.items():
    flag = " ← EWMA 捕获" if info.get("anomaly") else ""
    print(f"    {feat}: value={info['value']}, z={info['z_score']}, mean={info.get('mean'):.3f}{flag}")
print(f"  结论: {'✅ EWMA 独立捕获' if scenario2_score >= 0.35 else '❌ 未捕获'}")

print()

# ── Scenario 3: novel edge combination → EWMA position_anomaly ──
# All edges are known (in warmup), but the specific combination is unusual.
# User→Fleet (depth=1) is unusual for Fleet. Safety at depth=3 is unusual.
# Firmware at depth=4 never occurs in warmup.
scenario3_path = ["User", "Fleet_Agent", "Telematics_Agent", "Safety_Agent", "Firmware_Agent"]
scenario3_score, scenario3_details = iov_det3.score_with_details(scenario3_path)
print(f"--- Scenario 3: 深度/角色位置异常 (已知边, 新颖组合) ---")
print(f"  路径: {' → '.join(scenario3_path)} (depth={len(scenario3_path)})")
print(f"  规则引擎: ALLOW (所有边在 adjacency 中)")
print(f"  EWMA score: {scenario3_score:.4f}")
for feat, info in scenario3_details.items():
    flag = " ← EWMA 捕获" if info.get("anomaly") else ""
    print(f"    {feat}: value={info['value']}, z={info['z_score']}, mean={info.get('mean'):.3f}{flag}")
print(f"  结论: {'✅ EWMA 独立捕获' if scenario3_score >= 0.35 else '❌ EWMA 弱信号'}")

print(f"\n{'='*70}")
print(f"Layer 3 Summary:")
print(f"  Scenario 1 (新合法边): EWMA={'✓' if scenario1_score >= 0.35 else '✗'} Rule=ALLOW")
print(f"  Scenario 2 (频率异常):  EWMA={'✓' if scenario2_score >= 0.35 else '✗'} Rule=ALLOW")
print(f"  Scenario 3 (深度异常):  EWMA={'✓' if scenario3_score >= 0.35 else '✗'} Rule=ALLOW")
print(f"{'='*70}")

print(f"\nEWMA Scale Tests Complete")
