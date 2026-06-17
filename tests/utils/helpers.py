"""Shared utilities for rule engine + EWMA testing."""
import json
import os
import sys
import tempfile
from collections import Counter
from typing import Optional

import yaml

# Ensure project root is on path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from audit_layer.utils.policy_loader import PolicyLoader
from audit_layer.audit_models import AuditEvent, AuditDecision


def make_policy(policy_dict: dict) -> PolicyLoader:
    """
    Create a PolicyLoader from a dict by writing to a temp YAML file.
    The temp file is deleted immediately after PolicyLoader loads it
    (PolicyLoader reads everything on init, so the file isn't needed after).
    """
    tmp = tempfile.NamedTemporaryFile(
        mode='w', suffix='.yaml', delete=False, encoding='utf-8'
    )
    yaml.dump(policy_dict, tmp, allow_unicode=True)
    tmp.close()
    loader = PolicyLoader(tmp.name)
    os.unlink(tmp.name)
    return loader


def make_audit_event(
    event_type: str = "tool_call",
    sender: str = "",
    receiver: Optional[str] = None,
    tool_name: Optional[str] = None,
    tool_args: Optional[dict] = None,
    call_path: Optional[list] = None,
    content: Optional[str] = None,
    metadata: Optional[dict] = None,
    **kwargs,
) -> AuditEvent:
    """Create an AuditEvent with minimal boilerplate for testing."""
    return AuditEvent(
        event_type=event_type,
        sender=sender,
        receiver=receiver,
        tool_name=tool_name,
        tool_args=tool_args or {},
        call_path=call_path or [],
        content=content,
        history_summary="",
        task="test_task",
        metadata=metadata or {},
        **kwargs,
    )


class MockLLMReviewer:
    """
    Replacement for LLMReviewer that returns fixed scores.
    Used in combined tests so we don't need OpenAI API access.
    Simulates three behaviors:
        - safe (0.05): tool not marked as sensitive
        - suspicious (0.55): route_hijack_check flagged, no other risks
        - dangerous (0.85): semantic injection detected, IPI content mismatch
    """

    def review(self, event: AuditEvent, rule_risk_types: Optional[list] = None):
        risk_types = rule_risk_types or []
        risk_score = 0.05

        # If rule engine flagged route hijack -> suspicious
        if "route_hijack_check" in risk_types:
            risk_score = 0.55
        # If semantic injection indicators in metadata -> dangerous
        if event.metadata.get("scenario") in ("SemanticInjection", "PromptInfection", "IPI"):
            risk_score = 0.85

        return AuditDecision(
            allow=True,
            risk_score=risk_score,
            reason=f"mock LLM decision (risk_types={risk_types})",
            blocking_risk_types=list(risk_types),
        )


def load_audit_events(jsonl_path: str) -> list[dict]:
    """Load all events from a JSONL file. Handles both raw events and
    {"original": {...}, "audit_result": {...}} wrappers (unwraps to original)."""
    events = []
    with open(jsonl_path, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                if "original" in obj:
                    events.append(obj["original"])
                else:
                    events.append(obj)
            except json.JSONDecodeError:
                continue
    return events


def dedup_call_paths(paths: list[list[str]]) -> list[list[str]]:
    """
    Deduplicate call_paths by exact match.
    Returns unique paths preserving order of first occurrence.
    """
    seen = set()
    unique = []
    for p in paths:
        key = tuple(p)
        if key not in seen:
            seen.add(key)
            unique.append(p)
    return unique


def split_by_domain(events: list[dict]) -> dict[str, list[dict]]:
    """Group events by metadata.domain."""
    groups = {}
    for e in events:
        domain = e.get("metadata", {}).get("domain", "unknown")
        groups.setdefault(domain, []).append(e)
    return groups


def extract_benign_call_paths(
    events: list[dict],
    min_path_len: int = 2,
    dedup: bool = True,
) -> list[list[str]]:
    """
    Extract call_paths from events with intent=benign.
    Includes attack trace events BEFORE the attack injection point.
    Set dedup=False for EWMA warmup (EWMA benefits from more observations).
    """
    # First pass: identify attack traces by trace_id
    attack_trace_ids = set()
    for e in events:
        if e.get("metadata", {}).get("intent") == "attack":
            attack_trace_ids.add(e.get("trace_id", ""))

    # Group by trace
    traces = {}
    for e in events:
        tid = e.get("trace_id", "")
        traces.setdefault(tid, []).append(e)

    paths = []
    for tid, trace_events in traces.items():
        if tid in attack_trace_ids:
            # Attack trace: take call_paths from events BEFORE first attack
            for e in sorted(trace_events, key=lambda x: x.get("timestamp", "")):
                if e.get("metadata", {}).get("intent") != "attack":
                    cp = e.get("call_path", [])
                    if len(cp) >= min_path_len:
                        paths.append(cp)
                else:
                    break  # Stop at first attack event
        else:
            # Pure benign trace: take all call_paths
            for e in trace_events:
                cp = e.get("call_path", [])
                if len(cp) >= min_path_len:
                    paths.append(cp)

    return dedup_call_paths(paths) if dedup else paths


def extract_attack_call_paths(
    events: list[dict],
    min_path_len: int = 2,
) -> list[tuple[list[str], str]]:
    """
    Extract call_paths from attack events.
    Returns list of (call_path, attack_type).
    Attack type is metadata.scenario.
    """
    results = []
    for e in events:
        if e.get("metadata", {}).get("intent") == "attack":
            cp = e.get("call_path", [])
            if len(cp) >= min_path_len:
                attack_type = e.get("metadata", {}).get("scenario", "unknown")
                results.append((cp, attack_type))
    return results


def generate_test_policy(
    events: list[dict],
    output_path: str,
    policy_name: str = "test_policy",
) -> str:
    """
    Generate a test policy YAML from audit data.
    Inspects event data to extract:
        - agent names (from call_path and sender)
        - tool names and their typical callers
        - call_path patterns for path_rule definitions
    Returns the output path.
    """
    # Collect agents from call_paths and senders
    agents_in_paths = Counter()
    senders = Counter()
    tool_callers = {}  # tool_name -> set of senders
    tool_names = set()
    receivers = Counter()

    for e in events:
        for a in e.get("call_path", []):
            agents_in_paths[a] += 1
        s = e.get("sender", "")
        if s:
            senders[s] += 1
        t = e.get("tool_name")
        if t:
            tool_names.add(t)
            if s:
                tool_callers.setdefault(t, set()).add(s)
        r = e.get("receiver", "")
        if r:
            receivers[r] += 1
        if e.get("event_type") == "tool_result":
            # tool_result sender is the tool itself
            pass

    # Build policy dict
    policy = {
        "version": "2.0",
        "description": f"Auto-generated test policy for {policy_name}",
        "agents": {},
        "tools": {},
        "paths": {},
        "adjacency": {},
        "thresholds": {
            "rule_block": 0.90,
            "human_review": 0.75,
        },
    }

    # Agents: all unique agents found in data
    all_agent_names = set(agents_in_paths.keys()) | set(senders.keys()) | set(receivers.keys())
    # Filter out tool names that appear as senders (tool_result events)
    all_agent_names = {a for a in all_agent_names if a not in ("read_file_tool", "read_external_file_tool", "lab_query_tool")}

    for agent_name in sorted(all_agent_names):
        policy["agents"][agent_name] = {
            "role": "worker_agent",
            "can_initiate": agent_name == "User",
            "allowed_tools": [],
            "blocked_tools": [],
            "allowed_message_targets": sorted(all_agent_names - {agent_name}),
        }

    # Tools: each tool with callers from data
    for tool_name in sorted(tool_names):
        callers = sorted(tool_callers.get(tool_name, set()))
        policy["tools"][tool_name] = {
            "allowed_callers": callers if callers else sorted(all_agent_names),
            "required_path_contains": [],
            "path_rule": "",
        }

    # Adjacency: built from consecutive pairs in call_paths
    adj = {}
    for e in events:
        cp = e.get("call_path", [])
        for i in range(len(cp) - 1):
            src, dst = cp[i], cp[i + 1]
            if src in all_agent_names and dst in all_agent_names:
                adj.setdefault(src, set()).add(dst)
    policy["adjacency"] = {k: sorted(v) for k, v in adj.items()}

    # Write
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, 'w', encoding='utf-8') as f:
        yaml.dump(policy, f, allow_unicode=True, default_flow_style=False)

    print(f"  Generated test policy: {output_path}")
    print(f"    Agents: {len(policy['agents'])}")
    print(f"    Tools: {len(policy['tools'])}")
    print(f"    Adjacency entries: {len(policy['adjacency'])}")
    return output_path
