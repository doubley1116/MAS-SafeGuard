#!/usr/bin/env python3
"""
d3_d4_cleaner.py
────────────────
D3/D4 数据清洗器：从 D1 生成的 audit.jsonl 清洗出 D3（攻击样本）和 D4（正常样本）

数据流：
  D1 输出 output_trace_real/audit.jsonl（完整结构化 AuditEvent 数据流）
    → D3 清洗：提取攻击位置事件（SemanticInjection/RouterHijacking/IPI/PromptInfection）
    → D4 清洗：提取正常事件（benign trace 全部 / attack trace 非攻击位置）

输入：
  output_trace_real/audit.jsonl

输出：
  data/
    d3/
      type3_semantic_injection.jsonl
      type4_route_hijack.jsonl
      type5_ipi.jsonl
      type7_prompt_infection.jsonl
    d4/
      financial.jsonl
      healthcare.jsonl
      ecommerce.jsonl

使用示例：
  python src/d3_d4_cleaner.py --input output_trace_real/audit.jsonl
  python src/d3_d4_cleaner.py --input output_trace_real/audit.jsonl --d3-out data/d3 --d4-out data/d4
"""

import os
import sys
import json
import argparse
from pathlib import Path
from typing import Optional

# 确保能导入同目录的 generator 模块
_src_dir = os.path.dirname(os.path.abspath(__file__))
if _src_dir not in sys.path:
    sys.path.insert(0, _src_dir)

# ─────────────────────────────────────────────────────────────────────────────
# 全局配置
# ─────────────────────────────────────────────────────────────────────────────

SCENARIO_TO_D3_FILE = {
    "SemanticInjection": "type3_semantic_injection.jsonl",
    "RouterHijacking": "type4_route_hijack.jsonl",
    "IPI": "type5_ipi.jsonl",
    "PromptInfection": "type7_prompt_infection.jsonl",
    # PathBypass / CallerImpersonation / AiTM 不属于 D3 的四种语义攻击，跳过
}

# ─────────────────────────────────────────────────────────────────────────────
# 第一步：加载并按 trace_id 分组
# ─────────────────────────────────────────────────────────────────────────────

def load_traces(audit_path: str) -> dict[str, list[dict]]:
    """
    返回 {trace_id: [有序 event 列表]}
    """
    traces = {}
    with open(audit_path, encoding="utf-8") as f:
        for line in f:
            e = json.loads(line)
            tid = e["trace_id"]
            traces.setdefault(tid, []).append(e)
    return traces


# ─────────────────────────────────────────────────────────────────────────────
# 第二步：从第一条事件继承 scenario_type 和 label
# ─────────────────────────────────────────────────────────────────────────────

def enrich_trace(events: list[dict]) -> tuple[str, str]:
    """
    从 trace 第一条事件提取 (scenario_type, label)。

    scenario_type: 'PathBypass'/'AiTM'/... 或 'benign'
    label: 'attack_success' 或 'benign'

    兼容两种来源：
    - 骨架生成：metadata["skeleton_label"] = "attack_success" / "benign"
    - 自由生成：metadata["audit_decision"]["label"] = "dangerous" / "normal"
    """
    first_meta = events[0].get("metadata", {})
    scenario = first_meta.get("scenario", "")

    # 优先读骨架 label
    label = first_meta.get("skeleton_label", "")

    # 回退到 audit_decision.label（自由生成事件）
    if not label:
        ad_label = first_meta.get("audit_decision", {}).get("label", "")
        if ad_label == "dangerous":
            label = "attack_success"
        elif ad_label == "normal":
            label = "benign"

    # benign 场景名统一为 "benign"
    if label == "benign" and not scenario:
        scenario = "benign"

    return scenario, label


# ─────────────────────────────────────────────────────────────────────────────
# 场景检测（复用 d4_generator.py 的 detect_scene 函数逻辑）
# ─────────────────────────────────────────────────────────────────────────────

SCENE_INDICATORS = {
    "healthcare": [
        "prescription_tool", "triage_assess_tool", "diagnosis_tool",
        "review_tool", "dispense_tool", "lab_query_tool", "read_file_tool",
        "Triage_Agent", "Diagnosis_Agent", "Prescription_Agent",
        "Review_Agent", "Pharmacy_Agent",
        "patient_id", "drug_name", "diagnosis"
    ],
    "ecommerce": [
        "config_update_tool", "stats_query_tool", "order_query_tool",
        "logistics_add_tool", "token_fetch_tool",
        "StatsAgent", "OrderAgent", "ConfigAgent", "LogisticsAgent",
        "merchant_id", "order_id", "webhook_url", "carrier", "tracking_no"
    ],
    "financial": [
        "trade_execute_tool", "asset_query_tool",
        "Research_Agent", "Trade_Agent", "Asset_Agent", "Risk_Agent",
        "symbol", "amount", "client"
    ]
}


def detect_scene(event: dict) -> str:
    """
    根据事件内容检测所属场景（复用 d4_generator.py 逻辑）

    Returns:
        "healthcare" | "ecommerce" | "financial"
    """
    content = event.get("content", "") or ""
    tool_name = event.get("tool_name", "") or ""
    sender = event.get("sender", "") or ""
    receiver = event.get("receiver", "") or ""

    # 合并所有文本用于检测
    text = f"{content} {tool_name} {sender} {receiver}".lower()

    # 检查各场景关键词
    scores = {}
    for scene, indicators in SCENE_INDICATORS.items():
        score = sum(1 for ind in indicators if ind.lower() in text)
        scores[scene] = score

    # 返回得分最高的场景
    max_score = max(scores.values()) if scores else 0
    if max_score > 0:
        return max(scores, key=lambda k: scores[k])

    # 默认 financial
    return "financial"


# ─────────────────────────────────────────────────────────────────────────────
# 第三步：定位攻击位置事件（D3 清洗核心）
# ─────────────────────────────────────────────────────────────────────────────

def find_attack_event(events: list[dict], scenario: str) -> tuple[Optional[int], Optional[dict]]:
    """
    返回 (idx, event) 对，即该 trace 中应被 Defender 拦截的那一条事件。
    找不到返回 (None, None)。

    攻击位置逻辑（与 adversarial_grpo.py 的 rollout() 和 _save_augmented_events() 保持一致）：
    - PathBypass / CallerImpersonation / SemanticInjection / PromptInfection / RouterHijacking：
      攻击者是 User，取第一条 User message
    - IPI：tool_result
    - AiTM：sender 为 AiTM_Interceptor 的 message
    """
    if scenario in ("PathBypass", "CallerImpersonation", "SemanticInjection",
                    "PromptInfection", "RouterHijacking"):
        # 攻击者是 User，取第一条 User message
        for i, e in enumerate(events):
            if e.get("sender") == "User" and e.get("event_type") == "message":
                return i, e

    elif scenario == "IPI":
        # 攻击位置是 tool_call 之后的第一条 message（被污染文件内容经 Agent 转发）
        for i in range(1, len(events)):
            if (events[i].get("event_type") == "tool_result" and
                    events[i - 1].get("event_type") == "tool_call"):
                return i, events[i]

    elif scenario == "AiTM":
        # 中间人拦截，sender 为 AiTM_Interceptor
        for i, e in enumerate(events):
            if (e.get("sender") == "AiTM_Interceptor" and
                    e.get("event_type") == "message"):
                return i, e

    return None, None


# ─────────────────────────────────────────────────────────────────────────────
# 第四步：D3 事件后处理
# ─────────────────────────────────────────────────────────────────────────────

def build_d3_event(event: dict, scenario: str) -> dict:
    """
    构建 D3 攻击位置事件

    IPI 特殊处理：
    - sender 改为 "File_System"（攻击藏在文件内容里）
    - event_type 改为 "tool_result"（表示文件系统返回的原始内容，补全任务）

    AiTM：
    - sender 改为 "AiTM_Interceptor"

    其余场景 sender 保持 "User"
    """
    e = dict(event)

    if scenario == "AiTM":
        e["sender"] = "AiTM_Interceptor"
        cp = list(e.get("call_path") or [])
        if "AiTM_Interceptor" not in cp:
            cp.append("AiTM_Interceptor")
        e["call_path"] = cp

    from generator import _get_blocking_risk_types
    blocking = _get_blocking_risk_types(scenario)

    e.setdefault("metadata", {})
    e["metadata"]["audit_decision"] = {
        "label": "dangerous",
        "reason": e["metadata"].get("audit_decision", {}).get("reason")
                  or f"[{scenario}] 检测到：{', '.join(blocking)}",
        "blocking_risk_types": blocking,
        "suggested_alternative": "建议先经过合规审查节点",
    }
    return e


# ─────────────────────────────────────────────────────────────────────────────
# 第五步：D4 事件后处理
# ─────────────────────────────────────────────────────────────────────────────

def build_d4_event(event: dict) -> dict:
    """
    构建 D4 正常 User 消息事件（只保留 User 消息）
    """
    e = dict(event)
    e.setdefault("metadata", {})
    e["metadata"]["audit_decision"] = {
        "label": "normal",
        "reason": "正常操作",
        "blocking_risk_types": [],
        "suggested_alternative": None,
    }
    return e


# ─────────────────────────────────────────────────────────────────────────────
# 第六步：主流程
# ─────────────────────────────────────────────────────────────────────────────

def run_cleaner(
    input_path: str = "output_trace_real/audit.jsonl",
    d3_out: str = "data/d3",
    d4_out: str = "data/d4",
):
    """
    执行 D3/D4 数据清洗

    Args:
        input_path: D1 生成的 audit.jsonl 路径
        d3_out: D3 输出目录
        d4_out: D4 输出目录
    """
    # 检查输入文件
    input_file = Path(input_path)
    if not input_file.exists():
        print(f"❌ 输入文件不存在: {input_path}")
        return

    # 加载 traces
    print(f"📂 加载 traces: {input_path}")
    traces = load_traces(input_path)
    print(f"   共 {len(traces)} 条 traces")

    # 初始化 buckets
    d3_buckets: dict[str, list] = {k: [] for k in SCENARIO_TO_D3_FILE}
    d4_buckets: dict[str, list] = {"financial": [], "healthcare": [], "ecommerce": []}

    # 统计
    stats = {
        "benign_traces": 0,
        "attack_traces": 0,
        "d3_events": 0,
        "d4_events": 0,
        "skipped_traces": 0,
    }

    # 处理每条 trace
    print("\n🔄 处理 traces...")
    for tid, events in traces.items():
        # 提取 scenario 和 label
        scenario, label = enrich_trace(events)

        if label == "benign":
            # D4：只取 User 消息
            stats["benign_traces"] += 1
            user_event = next(
                (e for e in events if e.get("sender") == "User" and e.get("event_type") == "message"),
                None
            )
            if user_event:
                d4_buckets[detect_scene(user_event)].append(build_d4_event(user_event))

        elif label == "attack_success":
            stats["attack_traces"] += 1
            atk_idx, atk_event = find_attack_event(events, scenario)

            # D3：攻击位置事件
            if atk_event and scenario in SCENARIO_TO_D3_FILE:
                d3_buckets[scenario].append(build_d3_event(atk_event, scenario))
                stats["d3_events"] += 1
            elif atk_event:
                print(f"  [WARN] trace={tid[:8]} scenario={scenario} 不属于 D3 类型，攻击事件丢弃")
            else:
                print(f"  [WARN] trace={tid[:8]} scenario={scenario} 未找到攻击位置，攻击事件丢弃")
                stats["skipped_traces"] += 1

            # D4：IPI/AiTM 的 User 消息（攻击不在 User，User 消息是正常的）
            # PathBypass/CallerImpersonation/SemanticInjection/RouterHijacking/PromptInfection
            # 的攻击就是 User 消息本身（atk_idx==0），不加入 D4
            if atk_idx is not None and atk_idx != 0:
                user_event = next(
                    (e for e in events if e.get("sender") == "User" and e.get("event_type") == "message"),
                    None
                )
                if user_event:
                    d4_buckets[detect_scene(user_event)].append(build_d4_event(user_event))

        else:
            print(f"  [WARN] trace={tid[:8]} 未知 label={label}")

    stats["d4_events"] = sum(len(v) for v in d4_buckets.values())

    # 写出 D3
    print(f"\n📤 写出 D3 数据...")
    Path(d3_out).mkdir(parents=True, exist_ok=True)
    for scenario, fname in SCENARIO_TO_D3_FILE.items():
        events = d3_buckets[scenario]
        output_file = Path(d3_out) / fname
        with open(output_file, "w", encoding="utf-8") as f:
            for e in events:
                f.write(json.dumps(e, ensure_ascii=False) + "\n")
        print(f"   {scenario}: {len(events)} 条 → {output_file}")

    # 写出 D4
    print(f"\n📤 写出 D4 数据...")
    Path(d4_out).mkdir(parents=True, exist_ok=True)
    for scene in ("financial", "healthcare", "ecommerce"):
        events = d4_buckets[scene]
        output_file = Path(d4_out) / f"{scene}.jsonl"
        with open(output_file, "w", encoding="utf-8") as f:
            for e in events:
                f.write(json.dumps(e, ensure_ascii=False) + "\n")
        print(f"   {scene}: {len(events)} 条 → {output_file}")

    # 打印统计
    print(f"\n{'='*50}")
    print("✅ D3/D4 数据清洗完成")
    print(f"{'='*50}")
    print(f"  输入 traces: {len(traces)} 条")
    print(f"  - benign traces: {stats['benign_traces']} 条")
    print(f"  - attack traces: {stats['attack_traces']} 条")
    print(f"  D3 事件: {stats['d3_events']} 条")
    print(f"  D4 事件: {stats['d4_events']} 条")
    print(f"  跳过 traces: {stats['skipped_traces']} 条")
    print(f"\n  输出目录:")
    print(f"    D3: {d3_out}")
    print(f"    D4: {d4_out}")


# ─────────────────────────────────────────────────────────────────────────────
# CLI 入口
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="D3/D4 数据清洗器 —— 从 D1 audit.jsonl 提取 D3 攻击样本和 D4 正常样本",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
使用示例：
  # 使用默认路径
  python src/d3_d4_cleaner.py

  # 指定输入输出路径
  python src/d3_d4_cleaner.py --input output_trace_real/audit.jsonl

  # 自定义输出目录
  python src/d3_d4_cleaner.py --input output_trace_real/audit.jsonl --d3-out data/d3 --d4-out data/d4
"""
    )

    parser.add_argument(
        "--input",
        type=str,
        default="output_trace_real/audit.jsonl",
        help="D1 生成的 audit.jsonl 路径（默认: output_trace_real/audit.jsonl）"
    )
    parser.add_argument(
        "--d3-out",
        type=str,
        default="data/d3",
        help="D3 输出目录（默认: data/d3）"
    )
    parser.add_argument(
        "--d4-out",
        type=str,
        default="data/d4",
        help="D4 输出目录（默认: data/d4）"
    )

    args = parser.parse_args()
    run_cleaner(args.input, args.d3_out, args.d4_out)
