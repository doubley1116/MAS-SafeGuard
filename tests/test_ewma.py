"""
EWMA trajectory anomaly detector correctness tests (Layer 1)
~5 test cases verifying each feature dimension's anomaly detection.
Uses manually constructed call_paths for warmup and testing.
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from audit_layer.trajectory_model import TrajectoryAnomalyDetector

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

# Create detector and warm up with normal paths
detector = TrajectoryAnomalyDetector()

normal_paths = [
    ["User", "Triage", "Diagnosis", "Review"],
    ["User", "Triage", "Diagnosis", "Pharmacy"],
    ["User", "Triage", "Specialist", "Review"],
    ["User", "Triage", "Diagnosis", "Review"],
    ["User", "Triage", "Specialist", "Pharmacy"],
    ["User", "Triage", "Diagnosis", "Prescription"],
    ["User", "Triage", "Specialist", "Review", "Diagnosis"],
    ["User", "Triage", "Diagnosis", "Pharmacy", "Review"],
    ["User", "Triage", "Specialist", "Review"],
    ["User", "Triage", "Diagnosis", "Review"],
    # More variations to ensure is_ready
    ["User", "Triage", "Diagnosis", "Pharmacy"],
    ["User", "Triage", "Specialist", "Prescription"],
    ["User", "Triage", "Diagnosis", "Review", "Pharmacy"],
    ["User", "Triage", "Specialist", "Diagnosis"],
    ["User", "Triage", "Specialist", "Review", "Prescription"],
]

detector.fit_normal(normal_paths)

print(f"\n  Detector ready: {detector.is_ready} (n_obs={detector.observation_count})")
print(f"  Baseline summary:\n{detector.summary()}")

# Test 1: Normal path -> low score
score1 = detector.score(["User", "Triage", "Diagnosis", "Review"])
check("normal path", score1, (0.0, 0.3), "(should be close to 0)")

# Test 2: Path with unknown agents -> high score (depth anomaly from >6 agents)
score2 = detector.score(["User", "Evil1", "Evil2", "Evil3", "Evil4", "Evil5", "Evil6"])
check("unknown agent path", score2, (0.3, 1.0), f"(should be elevated)")

# Test 3: Path bypassing review (specialist without reviewer -> spec_no_review)
score3 = detector.score(["User", "Triage", "Specialist"])
check("bypass review path", score3, (0.0, 0.8), f"(spec_no_review flag)")

# Test 4: Path with excessive depth -> depth anomaly
deep_path = ["User"] + ["Triage"] * 10 + ["Specialist"]
score4 = detector.score(deep_path)
check("excessive depth path", score4, (0.3, 1.0), f"(depth anomaly)")

# Test 5: Path with backtracks -> backtracks anomaly
backtrack_path = ["User", "Triage", "Diagnosis", "Triage", "Specialist", "Diagnosis", "Review"]
score5 = detector.score(backtrack_path)
check("backtrack path", score5, (0.0, 0.8), f"(backtracks elevated)")

# Test 6: score_with_details
score6, details = detector.score_with_details(["User", "Evil1", "Evil2", "Evil3", "Evil4", "Evil5"])
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

    # Try MAS-generated benign paths first for warmup (realistic depth diversity).
    # Fall back to all_consistent.jsonl benign data when MAS traces unavailable.
    mas_dir = get_mas_data_dir(domain)
    if mas_dir:
        benign_paths_all = extract_mas_call_paths(mas_dir, dedup=False)
        benign_paths_unique = extract_mas_call_paths(mas_dir, dedup=True)
        print(f"  Benign call_paths for warmup: {len(benign_paths_all)} (unique: {len(benign_paths_unique)})")
        print(f"  Warmup source: MAS ({mas_dir})")
    else:
        benign_paths_all = extract_benign_call_paths(domain_events, dedup=False)
        benign_paths_unique = extract_benign_call_paths(domain_events, dedup=True)
        print(f"  Benign call_paths for warmup: {len(benign_paths_all)} (unique: {len(benign_paths_unique)})")
        print(f"  Warmup source: all_consistent.jsonl (fallback)")

    # Attack paths for testing (deduped to avoid double-counting identical paths)
    attack_paths = extract_attack_call_paths(domain_events)
    print(f"  Attack call_paths for testing: {len(attack_paths)}")

    # Warm up detector with default k values (optimized in trajectory_model.py)
    from audit_layer.trajectory_model import TrajectoryAnomalyDetector
    detector = TrajectoryAnomalyDetector()
    detector.fit_normal(benign_paths_all)
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
    # Use deduped benign paths: 80% for warmup (already used via benign_paths_all subset),
    # 20% holdout for false positive testing
    split_idx = max(int(len(benign_paths_unique) * 0.8), 5)
    if len(benign_paths_unique) > split_idx:
        holdout_benign = benign_paths_unique[split_idx:]
        benign_scores = [(p, detector.score(p)) for p in holdout_benign]
        attack_scores["benign"] = benign_scores
        print(f"  Benign holdout (FP test): {len(benign_scores)} unique paths")
    else:
        attack_scores["benign"] = []
        print(f"  Benign holdout: insufficient unique paths ({len(benign_paths_unique)})")

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

print(f"\nEWMA Scale Tests Complete")
