"""
Combined tests: Rule Engine + EWMA synergy + Ablation experiments.
Tests full SecurityCore pipeline with mock LLM using cascading OR-gate.
Compares: R-only, E-only, R+E, Full configurations via layer switches.
"""
import sys, os, json
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from collections import defaultdict
from audit_layer.security_core import SecurityCore
from tests.utils.helpers import (
    load_audit_events, split_by_domain,
    MockLLMReviewer, make_audit_event,
)

AUDIT_DATA = os.path.join(os.path.dirname(__file__), "..", "AuditDataGen", "eval_results_verify", "origin_consistent.jsonl")
RESULT_DIR = os.path.join(os.path.dirname(__file__), "tmp_rule_ewma_results")
CKPT_DIR = os.path.join(os.path.dirname(__file__), "..", "audit_layer", "trajectory_checkpoints")
os.makedirs(RESULT_DIR, exist_ok=True)

DOMAIN_MAP = {
    "financial": "trading",
    "healthcare": "healthcare",
    "ecommerce": "ecommerce",
    "iov": "iov",
    "converged_media": "converged_media",
}

print("=" * 60)
print("Combined Tests + Ablation (Cascading OR-Gate)")
print("=" * 60)

all_events = load_audit_events(AUDIT_DATA)
events_by_domain = split_by_domain(all_events)

# Results: config -> attack_type -> {blocked, total}
configs = ["R", "E", "R+E", "Full"]
ablation_results = {cfg: defaultdict(lambda: {"blocked": 0, "total": 0}) for cfg in configs}

for domain, domain_events in events_by_domain.items():
    test_domain = DOMAIN_MAP.get(domain)
    if not test_domain:
        continue

    print(f"\n--- Domain: {domain} ---")

    policy_path = os.path.join(
        os.path.dirname(__file__), "fixtures", f"policy_{test_domain}.yaml"
    )
    ckpt_path = os.path.join(CKPT_DIR, f"{domain}_detector.pkl")

    if not os.path.exists(policy_path):
        print(f"  SKIP: policy not found at {policy_path}")
        continue
    if not os.path.exists(ckpt_path):
        print(f"  SKIP: detector checkpoint not found at {ckpt_path}")
        continue

    mock_llm = MockLLMReviewer()

    # ---- Config: R (rule engine only) ----
    core_R = SecurityCore(
        yaml_path=policy_path,
        llm_reviewer=mock_llm,
        trajectory_detector_path=ckpt_path,
        trajectory_online_learning=False,
    )
    core_R._enable_ewma = False
    core_R._enable_llm = False

    # ---- Config: E (EWMA only) ----
    core_E = SecurityCore(
        yaml_path=policy_path,
        llm_reviewer=mock_llm,
        trajectory_detector_path=ckpt_path,
        trajectory_online_learning=False,
    )
    core_E._enable_rule = False
    core_E._enable_llm = False

    # ---- Config: R+E (rule + EWMA) ----
    core_RE = SecurityCore(
        yaml_path=policy_path,
        llm_reviewer=mock_llm,
        trajectory_detector_path=ckpt_path,
        trajectory_online_learning=False,
    )
    core_RE._enable_llm = False

    # ---- Config: Full (Rule + EWMA + LLM) ----
    core_Full = SecurityCore(
        yaml_path=policy_path,
        llm_reviewer=mock_llm,
        trajectory_detector_path=ckpt_path,
        trajectory_online_learning=False,
    )

    for e in domain_events:
        event = make_audit_event(
            event_type=e.get("event_type", "tool_call"),
            sender=e.get("sender", ""),
            receiver=e.get("receiver"),
            tool_name=e.get("tool_name"),
            tool_args=e.get("tool_args", {}),
            call_path=e.get("call_path", []),
            content=e.get("content", ""),
            metadata=e.get("metadata", {}),
        )

        attack_type = e.get("metadata", {}).get("scenario", "benign")

        # All configs use audit() with layer switches for clean isolation
        for cfg_name, core in [("R", core_R), ("E", core_E), ("R+E", core_RE), ("Full", core_Full)]:
            decision = core.audit(event)
            ablation_results[cfg_name][attack_type]["total"] += 1
            if not decision.allow:
                ablation_results[cfg_name][attack_type]["blocked"] += 1

# Print ablation summary table
print(f"\n{'='*75}")
print("Ablation Study Summary")
print(f"{'='*75}")

for cfg in configs:
    print(f"\n  Configuration: {cfg}")
    print(f"  {'Attack Type':<25} {'Total':>6} {'Blocked':>8} {'Rate':>8}")
    print(f"  {'-'*48}")
    total_blocked = 0
    total_events = 0
    for attack_type in sorted(ablation_results[cfg].keys()):
        r = ablation_results[cfg][attack_type]
        if r["total"] == 0:
            continue
        rate = r["blocked"] / r["total"] * 100
        total_blocked += r["blocked"]
        total_events += r["total"]
        print(f"  {attack_type:<25} {r['total']:>6} {r['blocked']:>8} {rate:>7.1f}%")
    if total_events > 0:
        overall = total_blocked / total_events * 100
        print(f"  {'-'*48}")
        print(f"  {'OVERALL':<25} {total_events:>6} {total_blocked:>8} {overall:>7.1f}%")

# Save ablation results to CSV
ablation_path = os.path.join(RESULT_DIR, "ablation_summary.csv")
with open(ablation_path, 'w', encoding='utf-8') as f:
    f.write("configuration,attack_type,total,blocked,rate\n")
    for cfg in configs:
        for attack_type in sorted(ablation_results[cfg].keys()):
            r = ablation_results[cfg][attack_type]
            if r["total"] == 0:
                continue
            rate = r["blocked"] / r["total"] * 100
            f.write(f"{cfg},{attack_type},{r['total']},{r['blocked']},{rate:.1f}\n")

print(f"\n  Ablation results saved to: {ablation_path}")

# Key findings summary
print(f"\n{'='*60}")
print("Key Findings:")
print(f"{'='*60}")

for attack_key in ["IPI", "AiTM", "PathBypass", "CallerImpersonation"]:
    r_rate = (
        ablation_results["R"].get(attack_key, {}).get("blocked", 0)
        / max(ablation_results["R"].get(attack_key, {}).get("total", 1), 1)
        * 100
    )
    e_rate = (
        ablation_results["E"].get(attack_key, {}).get("blocked", 0)
        / max(ablation_results["E"].get(attack_key, {}).get("total", 1), 1)
        * 100
    )
    full_rate = (
        ablation_results["Full"].get(attack_key, {}).get("blocked", 0)
        / max(ablation_results["Full"].get(attack_key, {}).get("total", 1), 1)
        * 100
    )
    if r_rate < 20 and e_rate < 20 and full_rate > 50:
        dominant = "LLM主导"
    elif r_rate > 30:
        dominant = "规则主导"
    elif e_rate > 30:
        dominant = "EWMA主导"
    else:
        dominant = "多重覆盖"
    print(f"  {attack_key}: R={r_rate:.1f}%, E={e_rate:.1f}%, Full={full_rate:.1f}% -> {dominant}")

print(f"\nCombined Tests Complete")
