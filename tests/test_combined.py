"""
Combined tests: Rule Engine + EWMA synergy + Ablation experiments.
Tests full SecurityCore pipeline with mock LLM.
Compares: R-only, E-only, R+E, Full configurations.
"""
import sys, os, json
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from collections import defaultdict
from audit_layer.security_core import SecurityCore
from tests.utils.helpers import (
    load_audit_events, split_by_domain,
    MockLLMReviewer, make_audit_event,
)

AUDIT_DATA = os.path.join(os.path.dirname(__file__), "..", "AuditDataGen", "data", "all_consistent.jsonl")
RESULT_DIR = os.path.join(os.path.dirname(__file__), "tmp_rule_ewma_results")
CKPT_DIR = os.path.join(os.path.dirname(__file__), "..", "audit_layer", "trajectory_checkpoints")
os.makedirs(RESULT_DIR, exist_ok=True)

DOMAIN_MAP = {"financial": "trading", "healthcare": "healthcare", "ecommerce": "ecommerce"}

print("=" * 60)
print("Combined Tests + Ablation")
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
    )
    # Disable trajectory in this core
    core_R.trajectory_detector = None

    # ---- Config: E (EWMA only) ----
    core_E = SecurityCore(
        yaml_path=policy_path,
        llm_reviewer=mock_llm,
        trajectory_detector_path=ckpt_path,
        trajectory_online_learning=False,
    )

    # ---- Config: R+E (rule + EWMA) ----
    core_RE = SecurityCore(
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

        # R-only: rule engine score alone
        rule_score, rule_risk_types, _ = core_R.rule_engine.evaluate(event)
        rule_blocked = rule_score >= 0.5
        ablation_results["R"][attack_type]["total"] += 1
        if rule_blocked:
            ablation_results["R"][attack_type]["blocked"] += 1

        # E-only: EWMA trajectory score alone
        traj_score = core_E._compute_trajectory_score(event)
        ewma_blocked = (traj_score or 0.0) >= 0.5
        ablation_results["E"][attack_type]["total"] += 1
        if ewma_blocked:
            ablation_results["E"][attack_type]["blocked"] += 1

        # R+E: fused without LLM influence (rule + EWMA only)
        if traj_score is not None and traj_score > 0:
            path_len = len(event.call_path) if event.call_path else 0
            alpha = core_RE._compute_alpha(path_len)
            fused = alpha * rule_score + (1 - alpha) * traj_score
            fused = max(fused, rule_score)
            re_blocked = fused >= 0.5
        else:
            re_blocked = rule_blocked
        ablation_results["R+E"][attack_type]["total"] += 1
        if re_blocked:
            ablation_results["R+E"][attack_type]["blocked"] += 1

        # Full: SecurityCore.audit() with mock LLM (R+E+LLM)
        decision = core_RE.audit(event)
        ablation_results["Full"][attack_type]["total"] += 1
        if not decision.allow:
            ablation_results["Full"][attack_type]["blocked"] += 1

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
