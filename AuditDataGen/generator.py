"""
generator.py
────────────
批量审计数据生成器。

流程：
  骨架库 (skeletons.py)
    → 随机填充占位符（symbol / amount / client / ...）
    → 模拟 MAS 自然流转，生成完整 AuditEvent 序列
    → 计算哈希链
    → 写入 audit.jsonl

特点：
  - 零 LLM API 调用，完全本地运行，无成本
  - 每条骨架可重复采样 N 次（每次填充不同的随机值）
  - 生成数据格式与真实系统产生的 audit_events.json 完全一致
  - 支持导出为 SFT 训练格式（input/output 对）
"""

from __future__ import annotations

import json
import uuid
import random
import hashlib
import datetime
import argparse
from pathlib import Path

from skeletons import SKELETONS, FILLERS


# ─────────────────────────────────────────────────────────────────────────────
# 工具函数
# ─────────────────────────────────────────────────────────────────────────────

def random_fill(template: str, values: dict) -> str:
    """将模板中的占位符替换为随机采样值。"""
    result = template
    for key, val in values.items():
        result = result.replace("{" + key + "}", str(val))
    return result


def sample_values() -> dict:
    """随机采样一组填充值，每次调用返回不同组合。"""
    symbol = random.choice(FILLERS["symbol"])
    return {
        "symbol": symbol,
        "amount": random.choice(FILLERS["amount"]),
        "client": random.choice(FILLERS["client"]),
        "policy": random.choice(FILLERS["policy"]),
        "reason": random.choice(FILLERS["reason"]),
        "role":   random.choice(FILLERS["role"]),
        "token":  random.choice(FILLERS["token"]),
        "hop_msg": random.choice(FILLERS["hop_msg"]).replace("{symbol}", symbol),
    }


def make_timestamp(base: datetime.datetime, offset_seconds: int) -> str:
    return (base + datetime.timedelta(seconds=offset_seconds)).strftime("%Y-%m-%dT%H:%M:%S.%f")


def compute_hash(payload: dict) -> str:
    raw = json.dumps(payload, ensure_ascii=False, sort_keys=True)
    return hashlib.sha256(raw.encode()).hexdigest()


# ─────────────────────────────────────────────────────────────────────────────
# 核心：骨架 → AuditEvent 序列
# ─────────────────────────────────────────────────────────────────────────────

def skeleton_to_events(skeleton: dict, values: dict, trace_id: str) -> list[dict]:
    """
    将一条骨架实例化为完整的 AuditEvent 列表。

    history_summary 对齐真实 audit_events.json 的格式：
      - 只由 message 类型事件的 content 组成
      - 格式：[sender]: content\n---\n[sender]: content\n---\n...
      - 每条事件的 history_summary = 该事件写入前的累积摘要（不含自身）
      - 每条消息截取前 2000 字，防止超长污染

    call_path 对齐真实格式：
      - 仅追加出现过的非路由 Agent（不含 Semantic_Router）
      - 按第一次出现顺序排列
    """
    events:        list[dict] = []
    call_path:     list[str]  = []
    history_lines: list[str]  = []   # 已出现的 [sender]: content 行
    prev_hash:     str | None = None
    base_time = datetime.datetime.now(datetime.timezone.utc)

    # 累计时间偏移（每步随机 3~12 秒，模拟真实系统延迟）
    time_offset = 0

    # 路由节点不进入 call_path
    ROUTER_NODES = {"Semantic_Router", "AiTM_Interceptor"}

    for i, step in enumerate(skeleton["flow"]):
        sender, receiver, content_tpl, event_type = step

        # ── 1. 填充占位符 ────────────────────────────────────────────────────
        raw_content = random_fill(content_tpl, values) if content_tpl else None

        # ── 2. 工具调用解析 ──────────────────────────────────────────────────
        tool_name = None
        tool_args: dict | None = None
        display_content = raw_content  # message/state_transition 显示用

        if event_type == "tool_call" and raw_content:
            tool_name, tool_args = _parse_tool_call(raw_content, values)
            display_content = None   # tool_call 事件 content 字段为 null

        # ── 3. 更新 call_path（路由节点不纳入）──────────────────────────────
        if sender not in ROUTER_NODES and sender not in call_path:
            call_path.append(sender)

        # ── 4. 截取当前 history_summary（写入前的快照）──────────────────────
        #   格式完全对齐 audit_events.json：
        #   "[User]: xxx\n---\n[Research_Agent]: xxx"
        history_summary = "\n---\n".join(history_lines)

        # ── 5. 构建时间戳 ────────────────────────────────────────────────────
        time_offset += random.randint(3, 12)
        timestamp = make_timestamp(base_time, time_offset)

        # ── 6. 计算哈希链 ────────────────────────────────────────────────────
        hash_payload = {
            "event_id":   "",           # 先占位，下面填
            "trace_id":   trace_id,
            "timestamp":  timestamp,
            "event_type": event_type,
            "sender":     sender,
            "receiver":   receiver,
            "tool_name":  tool_name,
            "tool_args":  tool_args,
            "call_path":  list(call_path),
            "content":    display_content,
            "prev_hash":  prev_hash,
        }
        event_id = str(uuid.uuid4())
        hash_payload["event_id"] = event_id
        self_hash = compute_hash(hash_payload)

        # ── 7. 写入事件 ──────────────────────────────────────────────────────
        event = {
            "event_type":      event_type,
            "sender":          sender,
            "receiver":        receiver,
            "tool_name":       tool_name,
            "tool_args":       tool_args,
            "call_path":       list(call_path),
            "content":         display_content,
            "history_summary": history_summary,
            "event_id":        event_id,
            "trace_id":        trace_id,
            "timestamp":       timestamp,
            "metadata":        _make_metadata(skeleton, event_type, i),
            # "prev_hash":       prev_hash,
            # "self_hash":       self_hash,
        }
        events.append(event)
        prev_hash = self_hash

        # ── 8. 事件写入后，更新 history_lines ────────────────────────────────
        #   只有 message 类型才进入摘要（对齐真实系统行为）
        #   state_transition / tool_call 不进入摘要
        if event_type == "message" and display_content:
            snippet = display_content[:2000].replace("\n", " ")
            history_lines.append(f"[{sender}]: {snippet}")

    return events


def _parse_tool_call(content: str, values: dict) -> tuple[str, dict]:
    """
    从骨架的 tool_call content 字段解析工具名和参数。
    格式约定：tool_name(arg1, arg2, ...)
    """
    content = content.strip()
    if "(" not in content:
        return content, {}

    name = content[:content.index("(")]
    args_raw = content[content.index("(") + 1: content.rindex(")")]
    args_list = [a.strip() for a in args_raw.split(",") if a.strip()]

    if name == "trade_execute_tool":
        return name, {
            "symbol": args_list[0] if len(args_list) > 0 else values.get("symbol", "NVDA"),
            "action": args_list[1] if len(args_list) > 1 else "BUY",
            "amount": int(args_list[2]) if len(args_list) > 2 and args_list[2].isdigit()
                      else values.get("amount", 1000),
        }
    elif name == "asset_query_tool":
        return name, {
            "client_id": args_list[0] if args_list else values.get("client", "C001"),
        }
    elif name == "read_external_file_tool":
        return name, {
            "filename": args_list[0] if args_list else "external_doc.txt",
        }
    else:
        return name, {}


def _make_metadata(skeleton: dict, event_type: str, step_idx: int) -> dict:
    meta: dict = {}
    if event_type == "state_transition":
        meta["confidence"] = round(random.uniform(0.82, 0.98), 2)
        meta["reason"]     = f"意图分类结果，step={step_idx}"
    if step_idx == 0:
        meta["scenario"]   = skeleton["scenario_type"]
        meta["skeleton_id"]= skeleton["id"]
    return meta


# ─────────────────────────────────────────────────────────────────────────────
# SFT 格式转换
# ─────────────────────────────────────────────────────────────────────────────

def events_to_sft(events: list[dict], skeleton: dict) -> dict:
    """
    将一条 trace 的 AuditEvent 列表转换为 SFT 训练格式。

    input:  最后一条非 benign 事件的 JSON（模拟审核模型的输入）
    output: {"risk_score": float, "triggered_dimensions": [...], "reason": str}

    triggered_dimensions 根据 scenario_type 自动推断。
    """
    # 用最后一条 message/tool_call 事件作为审核输入
    target = next(
        (e for e in reversed(events)
         if e["event_type"] in ("message", "tool_call")),
        events[-1]
    )

    stype = skeleton["scenario_type"]
    dimensions = _infer_dimensions(stype, events)

    output = {
        "risk_score":           skeleton["risk_score"],
        "triggered_dimensions": dimensions,
        "reason":               _infer_reason(stype, skeleton["description"], events),
    }

    return {
        "input":          json.dumps(target, ensure_ascii=False),
        "output":         json.dumps(output, ensure_ascii=False),
        "skeleton_id":    skeleton["id"],
        "scenario_type":  stype,
        "label":          skeleton["label"],
    }


def _infer_dimensions(scenario_type: str, events: list[dict]) -> list[str]:
    dim_map = {
        "DPI":           ["implicit_instruction_injection", "authority_fabrication"],
        "Impersonation": ["identity_spoofing", "authority_fabrication", "data_exfiltration"],
        "MultiHop":      ["multi_hop_propagation", "implicit_instruction_injection"],
        "Colluding":     ["colluding_agents", "backdoor_trigger", "privilege_escalation"],
        "IPI":           ["indirect_injection", "environment_pollution"],
        "Byzantine":     ["system_disruption", "dos"],
        "Contradicting": ["contradiction_attack", "dos"],
        "AiTM":          ["man_in_the_middle", "message_tampering"],
        "benign":        [],
    }
    dims = dim_map.get(scenario_type, ["unknown"])

    # 追加：如果触发了 trade_execute_tool 则加 unauthorized_trade
    tool_calls = [e for e in events if e["event_type"] == "tool_call"]
    for tc in tool_calls:
        if tc.get("tool_name") == "trade_execute_tool" and scenario_type != "benign":
            if "unauthorized_trade" not in dims:
                dims.append("unauthorized_trade")
        if tc.get("tool_name") == "asset_query_tool" and scenario_type in ("Impersonation", "IPI"):
            if "data_exfiltration" not in dims:
                dims.append("data_exfiltration")

    return dims


def _infer_reason(scenario_type: str, description: str, events: list[dict]) -> str:
    templates = {
        "DPI":           "检测到直接提示词注入攻击：{desc}。攻击者通过在用户输入中嵌入伪造合规依据，诱导投研Agent错误定性为合规，最终触发未授权交易执行。",
        "Impersonation": "检测到身份冒充攻击：{desc}。攻击者伪造管理员/合规官身份，利用虚假授权令牌绕过身份验证，获取敏感数据或触发未授权操作。",
        "MultiHop":      "检测到多跳传播攻击：{desc}。攻击者在合法请求中嵌入恶意载荷，随消息在Agent间传播，最终感染下游节点触发恶意操作。",
        "Colluding":     "检测到共谋Agent攻击：{desc}。多个Agent协同，通过后门标记绕过路由安全检查，完成跨权限越权操作。",
        "IPI":           "检测到间接提示词注入：{desc}。恶意指令隐藏在外部环境数据中，当Agent读取外部资源时被感染并执行攻击指令。",
        "Byzantine":     "检测到拜占庭智能体攻击：{desc}。Agent输出荒谬或矛盾内容，破坏系统正常决策流程，导致服务不可用。",
        "Contradicting": "检测到矛盾智能体攻击：{desc}。Agent刻意输出相互矛盾的结论，使路由器无法正确判断意图，任务无法完成。",
        "AiTM":          "检测到中间人攻击：{desc}。攻击者在通信链路中拦截并篡改合法消息，替换为恶意指令影响下游Agent决策。",
        "benign":        "未检测到安全风险：{desc}。该请求符合正常业务流程，无越权操作，无异常调用链。",
    }
    tpl = templates.get(scenario_type, "检测到潜在风险：{desc}。")
    return tpl.format(desc=description)


# ─────────────────────────────────────────────────────────────────────────────
# 主生成函数
# ─────────────────────────────────────────────────────────────────────────────

def generate(
    n_per_skeleton: int   = 5,
    output_dir:     str   = "output",
    seed:           int   = 42,
    sft_format:     bool  = True,
    shuffle:        bool  = True,
) -> tuple[int, int]:
    """
    批量生成审计数据。

    Args:
        n_per_skeleton: 每条骨架生成几条 trace（随机填充不同值）
        output_dir:     输出目录
        seed:           随机种子（保证可复现）
        sft_format:     同时生成 SFT 训练格式
        shuffle:        是否打乱最终数据集顺序

    Returns:
        (audit_count, sft_count) 生成的条数
    """
    random.seed(seed)
    out_path = Path(output_dir)
    out_path.mkdir(parents=True, exist_ok=True)

    audit_path = out_path / "audit.jsonl"
    sft_path   = out_path / "sft_train.jsonl"

    # audit_blocks: 每元素为一个 trace 的所有 event 行，块内顺序严格保持
    audit_blocks: list[list[str]] = []
    sft_lines:    list[str]       = []

    print(f"▶ 开始生成，共 {len(SKELETONS)} 条骨架，每条 {n_per_skeleton} 次采样")
    print(f"  预计生成 ~{len(SKELETONS) * n_per_skeleton} 条 trace\n")

    for skeleton in SKELETONS:
        for sample_idx in range(n_per_skeleton):
            values   = sample_values()
            trace_id = str(uuid.uuid4())

            events = skeleton_to_events(skeleton, values, trace_id)

            # trace 内事件作为一个块，保持严格顺序
            block = [json.dumps(e, ensure_ascii=False) for e in events]
            audit_blocks.append(block)

            if sft_format:
                sft_item = events_to_sft(events, skeleton)
                sft_lines.append(json.dumps(sft_item, ensure_ascii=False))

            print(f"  [{skeleton['id']}] 样本 {sample_idx+1}/{n_per_skeleton}"
                  f"  trace={trace_id[:8]}..."
                  f"  events={len(events)}")

    # 打乱：只打乱 trace 块的顺序，块内事件顺序不变
    # 保证同一 trace 内 history_summary 的单调递增性
    if shuffle:
        random.shuffle(audit_blocks)
        random.shuffle(sft_lines)

    # 展平并写入
    audit_lines = [line for block in audit_blocks for line in block]
    audit_path.write_text("\n".join(audit_lines), encoding="utf-8")
    if sft_format:
        sft_path.write_text("\n".join(sft_lines), encoding="utf-8")

    print(f"\n✅ 生成完成")
    print(f"   audit.jsonl    : {len(audit_lines)} 条事件  →  {audit_path}")
    if sft_format:
        print(f"   sft_train.jsonl: {len(sft_lines)} 条 trace  →  {sft_path}")

    return len(audit_lines), len(sft_lines)


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="AuditDataGen —— 批量审计数据生成器")
    parser.add_argument("--n",       type=int,  default=5,        help="每条骨架的采样次数（默认 5）")
    parser.add_argument("--out",     type=str,  default="output", help="输出目录（默认 output/）")
    parser.add_argument("--seed",    type=int,  default=42,       help="随机种子（默认 42）")
    parser.add_argument("--no-sft",  action="store_true",         help="不生成 SFT 格式")
    parser.add_argument("--no-shuffle", action="store_true",      help="不打乱顺序")
    args = parser.parse_args()

    generate(
        n_per_skeleton = args.n,
        output_dir     = args.out,
        seed           = args.seed,
        sft_format     = not args.no_sft,
        shuffle        = not args.no_shuffle,
    )
