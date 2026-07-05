#!/usr/bin/env python3
"""
重构 call_path，使其完整连接每个 trace 中出现的所有 sender→receiver 对。
兼容 tool_call / tool_result（工具节点不加入 call_path）。
"""

import argparse
import json
import shutil
from collections import defaultdict


def is_agent(name: str) -> bool:
    """判断节点名是否为真实 Agent（非工具）。"""
    if name is None:
        return False
    return (
        name == "User"
        or name == "AiTM_Interceptor"
        or name == "Router"
        or "_Agent" in name
        or "Agent" in name  # 兼容 StatsAgent / ComplianceAgent 等无下划线命名
    )


def rebuild_call_paths(events: list[dict]) -> tuple[list[dict], int]:
    """重建所有 trace 的 call_path，返回 (events, 修改数)。"""
    traces: dict[str, list[dict]] = defaultdict(list)
    for e in events:
        traces[e["trace_id"]].append(e)
    for tid in traces:
        traces[tid].sort(key=lambda e: e["timestamp"])

    changed = 0
    for tid, trace in traces.items():
        path: list[str] = []
        for event in trace:
            # tool_call / tool_result 不扩展 call_path
            etype = event.get("event_type", "")
            if etype in ("tool_call", "tool_result"):
                event["call_path"] = list(path)
                continue

            sender = event.get("sender")
            receiver = event.get("receiver")

            # sender 入链
            if is_agent(sender) and (not path or path[-1] != sender):
                path.append(sender)

            # receiver 入链
            if is_agent(receiver):
                path.append(receiver)

            new_path = list(path)
            if event.get("call_path") != new_path:
                event["call_path"] = new_path
                changed += 1

    return events, changed


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="重构 call_path 为完整 sender→receiver 链路")
    parser.add_argument("--input", "-i", required=True, help="输入 audit.jsonl 路径")
    parser.add_argument("--output", "-o", help="输出路径（默认覆盖输入，自动备份）")
    args = parser.parse_args()

    # 备份
    out = args.output
    if out is None:
        backup = args.input.replace(".jsonl", "_cp_backup.jsonl")
        shutil.copy(args.input, backup)
        print(f"📦 备份: {backup}")
        out = args.input

    with open(args.input, "r", encoding="utf-8") as f:
        events = [json.loads(line) for line in f if line.strip()]

    events, changed = rebuild_call_paths(events)

    with open(out, "w", encoding="utf-8") as f:
        for e in events:
            f.write(json.dumps(e, ensure_ascii=False) + "\n")

    print(f"共 {len(events)} 条事件, {changed} 条 call_path 被修正")
