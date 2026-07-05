"""
Rule engine correctness tests (Layer 1)
~20 test cases covering all 8 rule methods.
Each test constructs a minimal policy + AuditEvent and asserts exact score + risk_type.
No real data dependency.
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from audit_layer.rule_engine import RuleEngine
from tests.utils.helpers import make_policy, make_audit_event

PASS, FAIL = 0, 0

def check(rule_name, event, policy_dict, expected_score, expected_risk_type):
    global PASS, FAIL
    engine = RuleEngine(make_policy(policy_dict))
    score, risk_types, reason = engine.evaluate(event)
    ok_score = abs(score - expected_score) < 0.01
    ok_risk = expected_risk_type in risk_types if expected_risk_type else not risk_types
    if ok_score and ok_risk:
        PASS += 1
        print(f"  [PASS] {rule_name}")
    else:
        FAIL += 1
        print(f"  [FAIL] {rule_name}: score={score} (expected {expected_score}), risk_types={risk_types}")

def check_clean(rule_name, event, policy_dict):
    global PASS, FAIL
    engine = RuleEngine(make_policy(policy_dict))
    score, risk_types, reason = engine.evaluate(event)
    if score == 0.0 and not risk_types:
        PASS += 1
        print(f"  [PASS] {rule_name} (clean)")
    else:
        FAIL += 1
        print(f"  [FAIL] {rule_name}: score={score}, risk_types={risk_types}, reason={reason}")


# ================================================================
# 1. _check_tool_caller -- unauthorized_tool_caller (0.95)
# ================================================================

BASE_POLICY = {
    "agents": {"Agent_A": {"role": "worker"}, "Agent_B": {"role": "worker"}},
    "tools": {"tool_a": {"allowed_callers": ["Agent_B"]}},
}

# 1a: Wrong caller -> should hit
check("tool_caller / wrong caller",
    make_audit_event(sender="Agent_A", tool_name="tool_a", call_path=["Agent_A"]),
    BASE_POLICY, 0.95, "unauthorized_tool_caller")

# 1b: Correct caller -> clean
check_clean("tool_caller / correct caller",
    make_audit_event(sender="Agent_B", tool_name="tool_a", call_path=["Agent_B"]),
    BASE_POLICY)

# 1c: Tool not in policy -> clean (no tool_policy)
check_clean("tool_caller / unknown tool",
    make_audit_event(sender="Agent_A", tool_name="nonexistent", call_path=["Agent_A"]),
    BASE_POLICY)


# ================================================================
# 2. _check_required_path -- missing_required_path_node (0.92)
# ================================================================

POLICY_RP = {
    "agents": {"Agent_A": {"role": "worker"}, "Agent_B": {"role": "worker"}},
    "tools": {"tool_b": {"allowed_callers": ["Agent_B"], "required_path_contains": ["Agent_A"]}},
}

# 2a: Missing required node
check("required_path / missing",
    make_audit_event(sender="Agent_B", tool_name="tool_b", call_path=["Agent_B"]),
    POLICY_RP, 0.92, "missing_required_path_node")

# 2b: Contains required node -> clean
check_clean("required_path / present",
    make_audit_event(sender="Agent_B", tool_name="tool_b", call_path=["Agent_A", "Agent_B"]),
    POLICY_RP)

# 2c: User/UserProxy tolerance
POLICY_RP_USER = {
    "agents": {"User": {"role": "entry"}, "Agent_A": {"role": "worker"}},
    "tools": {"tool_a": {"allowed_callers": ["Agent_A"], "required_path_contains": ["UserProxy"]}},
}
check_clean("required_path / user tolerance",
    make_audit_event(sender="Agent_A", tool_name="tool_a", call_path=["User", "Agent_A"]),
    POLICY_RP_USER)


# ================================================================
# 3. _check_path_rule -- path_rule_violation (0.92) / strict_path_violation (0.93)
# ================================================================

POLICY_PR = {
    "agents": {"Agent_A": {"role": "worker"}, "Agent_B": {"role": "worker"}, "Agent_C": {"role": "worker"}},
    "tools": {"tool_c": {"allowed_callers": ["Agent_C"], "path_rule": "path_c"}},
    "paths": {"path_c": {"sequence": ["Agent_A", "Agent_B"], "strict": False}},
}

# 3a: Ordered subsequence violated (Agent_A missing)
check("path_rule / violation (non-strict, A missing)",
    make_audit_event(sender="Agent_C", tool_name="tool_c", call_path=["Agent_B", "Agent_C"]),
    POLICY_PR, 0.92, "path_rule_violation")

# 3b: Ordered subsequence satisfied
check_clean("path_rule / satisfied (non-strict)",
    make_audit_event(sender="Agent_C", tool_name="tool_c", call_path=["Agent_A", "Agent_B", "Agent_C"]),
    POLICY_PR)

# 3c: Strict path violation
POLICY_PR_STRICT = {
    "agents": {"Agent_A": {"role": "worker"}, "Agent_B": {"role": "worker"}},
    "tools": {"tool_b": {"allowed_callers": ["Agent_B"], "path_rule": "strict_path"}},
    "paths": {"strict_path": {"sequence": ["Agent_A", "Agent_B"], "strict": True}},
}
check("path_rule / violation (strict, exact mismatch)",
    make_audit_event(sender="Agent_B", tool_name="tool_b", call_path=["Agent_A", "Agent_X", "Agent_B"]),
    POLICY_PR_STRICT, 0.93, "strict_path_violation")

# 3d: Strict path satisfied
check_clean("path_rule / satisfied (strict, exact match)",
    make_audit_event(sender="Agent_B", tool_name="tool_b", call_path=["Agent_A", "Agent_B"]),
    POLICY_PR_STRICT)


# ================================================================
# 4. _check_blocked_tools -- blocked_tool (0.95)
# ================================================================

POLICY_BT = {
    "agents": {"Agent_A": {"role": "worker", "blocked_tools": ["tool_blocked"]}},
    "tools": {"tool_blocked": {"allowed_callers": ["Agent_A"]}},
}

# 4a: Tool in agent's blocked_tools
check("blocked_tools / blocked",
    make_audit_event(sender="Agent_A", tool_name="tool_blocked", call_path=["Agent_A"]),
    POLICY_BT, 0.95, "blocked_tool")

# 4b: Tool not in blocked_tools -> clean
POLICY_BT2 = {
    "agents": {"Agent_A": {"role": "worker", "blocked_tools": []}},
    "tools": {"tool_ok": {"allowed_callers": ["Agent_A"]}},
}
check_clean("blocked_tools / allowed",
    make_audit_event(sender="Agent_A", tool_name="tool_ok", call_path=["Agent_A"]),
    POLICY_BT2)


# ================================================================
# 5. _check_adjacency -- adjacency_violation (0.88)
# ================================================================

POLICY_ADJ = {
    "agents": {"User": {"role": "entry"}, "Triage": {"role": "triage"}, "Specialist": {"role": "specialist"}},
    "tools": {},
    "adjacency": {
        "User": ["Triage"],
        "Triage": ["Specialist"],
    },
}

# 5a: Valid adjacency
check_clean("adjacency / valid",
    make_audit_event(sender="Specialist", tool_name="tool_x", call_path=["User", "Triage", "Specialist"]),
    POLICY_ADJ)

# 5b: Jump-level call (User -> Specialist, skipping Triage)
check("adjacency / jump violation",
    make_audit_event(sender="Specialist", tool_name="tool_x", call_path=["User", "Specialist"]),
    POLICY_ADJ, 0.88, "adjacency_violation")

# 5c: User/UserProxy tolerance
POLICY_ADJ_USER = {
    "agents": {"User": {"role": "entry"}, "UserProxy": {"role": "entry"}, "Agent_A": {"role": "worker"}},
    "tools": {},
    "adjacency": {"User": ["Agent_A"]},
}
check_clean("adjacency / User proxy tolerance",
    make_audit_event(sender="Agent_A", tool_name="tool_x", call_path=["UserProxy", "Agent_A"]),
    POLICY_ADJ_USER)


# ================================================================
# 6. _check_arg_constraints -- arg_constraint_violation (0.93)
# ================================================================

POLICY_ARG = {
    "agents": {"Agent_A": {"role": "worker"}},
    "tools": {"prescribe_tool": {
        "allowed_callers": ["Agent_A"],
        "arg_constraints": {
            "dosage_mg": {"min": 0, "max": 7.5, "label": "剂量(mg)"},
            "quantity": {"min": 1, "max": 30, "label": "数量"},
            "level": {"label": "等级", "allowed_values": ["low", "medium", "high"]},
        },
    }},
}

# 6a: Value exceeds max
check("arg_constraints / exceeds max",
    make_audit_event(sender="Agent_A", tool_name="prescribe_tool",
                     tool_args={"dosage_mg": 100}, call_path=["Agent_A"]),
    POLICY_ARG, 0.93, "arg_constraint_violation")

# 6b: Value below min
check("arg_constraints / below min",
    make_audit_event(sender="Agent_A", tool_name="prescribe_tool",
                     tool_args={"quantity": 0}, call_path=["Agent_A"]),
    POLICY_ARG, 0.93, "arg_constraint_violation")

# 6c: Enum value not in allowed_values
check("arg_constraints / bad enum",
    make_audit_event(sender="Agent_A", tool_name="prescribe_tool",
                     tool_args={"level": "critical"}, call_path=["Agent_A"]),
    POLICY_ARG, 0.93, "arg_constraint_violation")


# ================================================================
# 7. _check_unknown_agent -- unknown_agent_in_path (0.93)
# ================================================================

POLICY_UNK = {
    "agents": {"Agent_A": {"role": "worker"}, "Agent_B": {"role": "worker"}},
}

# 7a: Unknown agent in call_path
check("unknown_agent / unknown in path",
    make_audit_event(sender="Agent_B", tool_name="tool_x",
                     call_path=["Agent_A", "EvilAgent", "Agent_B"]),
    POLICY_UNK, 0.93, "unknown_agent_in_path")

# 7b: All agents known -> clean
check_clean("unknown_agent / all known",
    make_audit_event(sender="Agent_B", tool_name="tool_x", call_path=["Agent_A", "Agent_B"]),
    POLICY_UNK)


# ================================================================
# 8. _check_message_target -- unauthorized_message_target (0.91)
# ================================================================

POLICY_MSG = {
    "agents": {
        "Agent_A": {"role": "worker", "allowed_message_targets": ["Agent_B"]},
        "Agent_B": {"role": "worker"},
        "Agent_C": {"role": "worker"},
    },
}

# 8a: Message to disallowed target
check("message_target / unauthorized",
    make_audit_event(event_type="message", sender="Agent_A", receiver="Agent_C",
                     call_path=["Agent_A", "Agent_C"]),
    POLICY_MSG, 0.91, "unauthorized_message_target")

# 8b: Message to allowed target -> clean
check_clean("message_target / authorized",
    make_audit_event(event_type="message", sender="Agent_A", receiver="Agent_B",
                     call_path=["Agent_A", "Agent_B"]),
    POLICY_MSG)


# ================================================================
print(f"\n{'='*50}")
print(f"Results: {PASS} passed, {FAIL} failed (total {PASS+FAIL})")
print(f"{'='*50}")
if FAIL > 0:
    print("SOME TESTS FAILED")
    sys.exit(1)
else:
    print("ALL TESTS PASSED")


# ================================================================
# Layer 2: Scale tests with real data
# ================================================================

import json
from collections import Counter, defaultdict
from tests.utils.helpers import (
    load_audit_events, split_by_domain, make_audit_event,
)

AUDIT_DATA = os.path.join(os.path.dirname(__file__), "..", "AuditDataGen", "eval_results_verify", "origin_consistent.jsonl")
RESULT_DIR = os.path.join(os.path.dirname(__file__), "tmp_rule_ewma_results")
os.makedirs(RESULT_DIR, exist_ok=True)

# Domain -> test policy mapping
DOMAIN_MAP = {
    "financial": "trading",
    "healthcare": "healthcare",
    "ecommerce": "ecommerce",
    "iov": "iov",
    "converged_media": "converged_media",
}

print("\n" + "=" * 60)
print("Rule Engine Scale Tests (Layer 2)")
print("=" * 60)

all_events = load_audit_events(AUDIT_DATA)
events_by_domain = split_by_domain(all_events)

# Aggregate results: attack_type -> rule_type -> count
attack_rules = defaultdict(lambda: Counter())
attack_totals = Counter()
benign_rules = Counter()
benign_total = 0

for domain, domain_events in events_by_domain.items():
    test_domain = DOMAIN_MAP.get(domain)
    if not test_domain:
        continue

    print(f"\n--- Domain: {domain} ({len(domain_events)} events) ---")

    # Use the hand-crafted policy YAML
    policy_path = os.path.join(
        os.path.dirname(__file__), "fixtures", f"policy_{test_domain}.yaml"
    )

    from audit_layer.utils.policy_loader import PolicyLoader
    from audit_layer.rule_engine import RuleEngine

    policy = PolicyLoader(policy_path)
    engine = RuleEngine(policy)

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

        score, risk_types, reason = engine.evaluate(event)
        intent = e.get("metadata", {}).get("intent", "benign")
        attack_type = e.get("metadata", {}).get("scenario", "benign")

        if intent == "attack":
            attack_totals[attack_type] += 1
            for rt in risk_types:
                attack_rules[attack_type][rt] += 1
        else:
            benign_total += 1
            for rt in risk_types:
                benign_rules[rt] += 1

# Output heatmap CSV
heatmap_path = os.path.join(RESULT_DIR, "rule_heatmap.csv")
with open(heatmap_path, 'w', encoding='utf-8') as f:
    all_rule_types = sorted(set(rt for counts in attack_rules.values() for rt in counts) | set(benign_rules.keys()))
    f.write("attack_type,total," + ",".join(all_rule_types) + "\n")
    for at in sorted(attack_totals.keys()):
        total = attack_totals[at]
        rates = [f"{attack_rules[at].get(rt, 0) / total * 100:.1f}" if total > 0 else "0"
                 for rt in all_rule_types]
        f.write(f"{at},{total}," + ",".join(rates) + "\n")
    # benign row
    rates = [f"{benign_rules.get(rt, 0) / benign_total * 100:.1f}" if benign_total > 0 else "0"
             for rt in all_rule_types]
    f.write(f"benign,{benign_total}," + ",".join(rates) + "\n")

print(f"\n  Heatmap saved to: {heatmap_path}")

# Print summary table
print(f"\n{'Attack Type':<25} {'Total':>6}  {'Rule Hits':>10}  {'Risk Types':>35}")
print("-" * 80)
for at in sorted(attack_totals.keys()):
    total = attack_totals[at]
    # Rule hits: sum of all rule firings (one event can fire multiple rules)
    total_hits = sum(attack_rules[at].values())
    # Events with any rule hit (estimated as min of total_hits and total)
    pct_events_hit = min(total_hits / total * 100 if total > 0 else 0, 100.0)
    risk_str = ", ".join(f"{rt}:{c}" for rt, c in attack_rules[at].most_common(3))
    print(f"{at:<25} {total:>6}  {total_hits:>6} ({pct_events_hit:>5.1f}%)  {risk_str:>35}")

benign_hits = sum(benign_rules.values())
far = benign_hits / benign_total * 100 if benign_total > 0 else 0
print(f"{'benign':<25} {benign_total:>6}  {benign_hits:>6} ({far:>5.1f}%)  {', '.join(f'{rt}:{c}' for rt, c in benign_rules.most_common(3)):>35}")

print(f"\nRule Engine Scale Tests Complete")
print(f"  Total events evaluated: {sum(attack_totals.values()) + benign_total}")
print(f"  Attack events: {sum(attack_totals.values())}")
print(f"  Benign events: {benign_total}")
