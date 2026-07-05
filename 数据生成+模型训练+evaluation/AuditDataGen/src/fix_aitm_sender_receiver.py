#!/usr/bin/env python3
"""
修复 AiTM 骨架 trace 中因中间人伪装导致 sender == receiver 的问题。

原因：AiTM_Interceptor 伪装为下游 Agent（如 Pharmacy_Agent）发消息时，
该消息的 sender 和 receiver 都指向同一节点。修复策略：
  将 receiver 改为 call_path 中倒数第二个节点，并在 call_path 末尾追加该 receiver。
"""

import argparse
import json
import shutil
from collections import defaultdict


def fix_aitm_events(input_path: str, output_path: str):
    # 读取事件
    with open(input_path, "r", encoding="utf-8") as f:
        events = [json.loads(line) for line in f if line.strip()]

    # 按 trace_id 分组
    traces: dict[str, list[dict]] = defaultdict(list)
    for e in events:
        traces[e["trace_id"]].append(e)
    for tid in traces:
        traces[tid].sort(key=lambda e: e["timestamp"])

    fixed_count = 0
    for tid, trace in traces.items():
        # 只处理 AiTM
        if not trace or trace[0]["metadata"].get("scenario") != "AiTM":
            continue

        for i, event in enumerate(trace):
            sender = event.get("sender", "")
            receiver = event.get("receiver", "")
            call_path = event.get("call_path", [])

            if sender and sender == receiver and len(call_path) >= 2:
                # receiver 改为 call_path 倒数第二个
                new_receiver = call_path[-2]
                event["receiver"] = new_receiver
                # call_path 追加新 receiver
                event["call_path"] = call_path + [new_receiver]
                fixed_count += 1

    # 写回（保持原始顺序）
    with open(output_path, "w", encoding="utf-8") as f:
        for e in events:
            f.write(json.dumps(e, ensure_ascii=False) + "\n")

    print(f"共 {len(events)} 条事件, {len(traces)} 个 trace")
    print(f"修复 sender == receiver: {fixed_count} 处")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="修复 AiTM trace 中 sender==receiver 问题")
    parser.add_argument("--input", "-i", required=True, help="输入 audit.jsonl 路径")
    parser.add_argument("--output", "-o", help="输出路径（默认覆盖输入，自动备份）")
    args = parser.parse_args()

    out = args.output
    if out is None:
        backup = args.input.replace(".jsonl", "_before_fix.jsonl")
        shutil.copy(args.input, backup)
        print(f"📦 备份: {backup}")
        out = args.input

    fix_aitm_events(args.input, out)
