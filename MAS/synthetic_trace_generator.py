"""
synthetic_trace_generator.py — 合成轨迹生成器

无需LLM API，模拟LangGraph MAS行为生成真实的call_path轨迹。
用于EWMA快速预热训练。

用法:
    python synthetic_trace_generator.py --domain iov --rounds 5
    python synthetic_trace_generator.py --domain converged_media --rounds 5
"""

import os, sys, json, uuid, datetime, argparse

# ============================================================
# IoV 场景定义
# ============================================================

IOV_NORMAL_TEMPLATES = [
    # (prompt, agent_sequence_without_router, final_tool, weight)
    ("读取车辆诊断报告VEH-FL-88422", ["Telematics_Agent"], "read_external_file_tool", 15),
    ("查询车辆VEH-FL-99015的状态", ["Telematics_Agent"], "vehicle_status_tool", 10),
    ("查询车队FL-007信息", ["Fleet_Agent"], "fleet_query_tool", 10),
    ("诊断报告→安全审查", ["Telematics_Agent", "Safety_Agent"], "safety_review_tool", 15),
    ("完整固件更新流程:诊断→审查→更新", ["Telematics_Agent", "Safety_Agent", "Firmware_Agent"], "firmware_update_tool", 20),
    ("查询车队→检查车辆状态", ["Fleet_Agent", "Telematics_Agent"], "vehicle_status_tool", 10),
    ("诊断后查询车队状况", ["Telematics_Agent", "Fleet_Agent"], "fleet_query_tool", 10),
    ("安全审查通过后执行固件更新", ["Safety_Agent", "Firmware_Agent"], "firmware_update_tool", 10),
    # 反向边: 审查结果回传 (修复 benign FP — Safety→Telematics)
    ("安全审查结果回传", ["Safety_Agent", "Telematics_Agent"], "vehicle_status_tool", 12),
    # 含回溯的完整诊断-审查-回传路径 (修复 depth=4 benign FP)
    ("诊断→安全审查→结果回传", ["Telematics_Agent", "Safety_Agent", "Telematics_Agent"], "vehicle_status_tool", 10),
    # 直接查询固件/车队状态 (User→终端Agent 正常路径)
    ("查询固件版本状态", ["Firmware_Agent"], "vehicle_status_tool", 5),
]

# ============================================================
# Converged Media 场景定义
# ============================================================

MEDIA_NORMAL_TEMPLATES = [
    ("编辑稿件ART-10001的标题", ["Editor_Agent"], "content_edit_tool", 15),
    ("读取系统中的稿件文件", ["Editor_Agent"], "read_external_file_tool", 10),
    ("审查稿件ART-10002内容合规性", ["Review_Agent"], "content_review_tool", 10),
    ("检查稿件ART-10001版权", ["Copyright_Agent"], "copyright_check_tool", 10),
    ("编辑后审查稿件合规性", ["Editor_Agent", "Review_Agent"], "content_review_tool", 15),
    ("完整发布流程:编辑→审查→发布", ["Editor_Agent", "Review_Agent", "Publish_Agent"], "publish_tool", 15),
    ("编辑后检查版权合规", ["Editor_Agent", "Copyright_Agent"], "copyright_check_tool", 10),
    ("版权检查→审查→发布流程", ["Copyright_Agent", "Review_Agent", "Publish_Agent"], "publish_tool", 10),
    ("审查通过后发布到平台", ["Review_Agent", "Publish_Agent"], "publish_tool", 5),
    # 反向边: 审查反馈回传 (修复 benign FP — Review→Editor)
    ("审查反馈发送给编辑", ["Review_Agent", "Editor_Agent"], "content_review_tool", 12),
    # 含回溯的完整编辑-审查-回传路径 (修复 depth=4 benign FP)
    ("编辑→审查→反馈回传", ["Editor_Agent", "Review_Agent", "Editor_Agent"], "content_edit_tool", 10),
    # 版权检查→编辑反馈 + User直接查询发布状态
    ("版权检查结果反馈编辑", ["Copyright_Agent", "Editor_Agent"], "copyright_check_tool", 8),
    ("查询发布状态", ["Publish_Agent"], "publish_tool", 5),
]


def generate_synthetic_traces(domain: str, rounds: int = 5, output_dir: str = None):
    """生成合成轨迹JSONL文件"""
    if domain == "iov":
        templates = IOV_NORMAL_TEMPLATES
    elif domain == "converged_media":
        templates = MEDIA_NORMAL_TEMPLATES
    else:
        raise ValueError(f"Unknown domain: {domain}")

    if output_dir is None:
        output_dir = os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            f"Langgraph_{domain}", "data", "workflows", f"{domain}_normal"
        )

    os.makedirs(output_dir, exist_ok=True)

    total_events = 0
    for round_num in range(1, rounds + 1):
        for i, (prompt, agent_seq, final_tool, weight) in enumerate(templates):
            trace_id = str(uuid.uuid4())
            # Spread timestamps across days to make them distinguishable
            ts_base = datetime.datetime(2026, 6, 1, 10, 0, 0) + datetime.timedelta(
                hours=round_num * 24 + i * 2
            )

            events = []

            # Build the full call_path step by step
            # Start with User
            call_path = ["User"]
            events.append(_make_event("message", "User", agent_seq[0],
                                       call_path, prompt, trace_id, ts_base, domain))
            ts_base += datetime.timedelta(seconds=2)

            # Router receives and routes to first agent
            call_path = ["User", "Router"]
            events.append(_make_event("message", "Router", agent_seq[0],
                                       call_path, f"Router → {agent_seq[0]}",
                                       trace_id, ts_base, domain))
            ts_base += datetime.timedelta(seconds=1)

            # For each agent in the sequence
            for step_idx, agent_name in enumerate(agent_seq):
                # Agent is now in the path
                call_path = ["User", "Router"] + agent_seq[:step_idx + 1]

                # Determine tool for this agent
                if step_idx == len(agent_seq) - 1:
                    tool = final_tool
                else:
                    # Intermediate agents use their default tool
                    if domain == "iov":
                        tool_map = {
                            "Telematics_Agent": "read_external_file_tool",
                            "Safety_Agent": "safety_review_tool",
                            "Firmware_Agent": "firmware_update_tool",
                            "Fleet_Agent": "fleet_query_tool",
                        }
                    else:
                        tool_map = {
                            "Editor_Agent": "content_edit_tool",
                            "Review_Agent": "content_review_tool",
                            "Publish_Agent": "publish_tool",
                            "Copyright_Agent": "copyright_check_tool",
                        }
                    tool = tool_map.get(agent_name, "unknown_tool")

                # Agent calls tool
                events.append(_make_event("tool_call", agent_name, None,
                                           call_path, None, trace_id, ts_base, domain,
                                           tool_name=tool, tool_args={"task": prompt}))
                ts_base += datetime.timedelta(seconds=1)

                # Tool returns result
                events.append(_make_event("tool_result", tool, agent_name,
                                           call_path, f"工具 {tool} 执行完成",
                                           trace_id, ts_base, domain))
                ts_base += datetime.timedelta(seconds=1)

                # If there's a next agent, Router routes to it
                if step_idx < len(agent_seq) - 1:
                    # Tool_Node returns to Router
                    call_path_router = call_path + ["Tool_Node", "Router"]
                    events.append(_make_event("message", "Router", agent_seq[step_idx + 1],
                                               call_path_router,
                                               f"Router → {agent_seq[step_idx + 1]}",
                                               trace_id, ts_base, domain))
                    ts_base += datetime.timedelta(seconds=1)

            # Write to JSONL
            fname = f"normal_synthetic_{domain}_r{round_num:02d}_t{i:03d}.jsonl"
            fpath = os.path.join(output_dir, fname)
            with open(fpath, "w", encoding="utf-8") as f:
                for event in events:
                    f.write(json.dumps(event, ensure_ascii=False) + "\n")

            total_events += len(events)

    print(f"[{domain}] 生成 {rounds * len(templates)} 个trace, {total_events} 个事件")
    print(f"  输出目录: {output_dir}")


def _make_event(event_type, sender, receiver, call_path, content,
                trace_id, ts_base, domain, tool_name=None, tool_args=None):
    """构建单个审计事件"""
    return {
        "event_type": event_type,
        "sender": sender,
        "receiver": receiver,
        "tool_name": tool_name,
        "tool_args": tool_args,
        "call_path": list(call_path),
        "content": content,
        "history_summary": "",
        "task": content if content else "system operation",
        "event_id": str(uuid.uuid4()),
        "trace_id": trace_id,
        "timestamp": ts_base.isoformat(),
        "metadata": {
            "scenario": "benign",
            "domain": domain,
            "intent": "benign",
        }
    }


def main():
    parser = argparse.ArgumentParser(description="合成轨迹生成器")
    parser.add_argument("--domain", type=str, required=True,
                        choices=["iov", "converged_media"],
                        help="目标领域")
    parser.add_argument("--rounds", type=int, default=5,
                        help="每个模板重复轮数")
    args = parser.parse_args()

    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    generate_synthetic_traces(args.domain, args.rounds)


if __name__ == "__main__":
    main()
