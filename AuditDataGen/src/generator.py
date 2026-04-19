"""
generator.py
────────────
审计数据生成工具库（供 llm_augment / mock_models 等内部调用）。

不直接运行，入口为 trace_generator.py（生成完整 trace）和
train/run_adversarial_grpo.py（对抗训练）。
"""

from __future__ import annotations

import os
import sys
import json
import uuid
import random
import hashlib
import datetime
from pathlib import Path

# 路径设置，确保可以导入 skeletons
current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.insert(0, current_dir)

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


def sample_values(scenario_type: str | None = None) -> dict:
    """
    随机采样一组填充值，每次调用返回不同组合。

    Args:
        scenario_type: 场景类型，用于采样对应场景的 ipi_file_content。
                      可选值：None, "financial", "healthcare", "ecommerce"
    """
    # 根据场景类型选择对应的 ipi_file_content
    if scenario_type in ("healthcare", "HC-IPI"):
        ipi_key = "ipi_file_content_healthcare"
    elif scenario_type in ("ecommerce", "EC-IPI"):
        ipi_key = "ipi_file_content_ecommerce"
    else:
        # 默认金融场景（包含 IPI-001/002/003 等金融 IPI，以及 benign 等非 IPI 场景）
        ipi_key = "ipi_file_content_financial"

    return {
        # 通用金融
        "symbol":      random.choice(FILLERS["symbol"]),
        "amount":      random.choice(FILLERS["amount"]),
        "client":      random.choice(FILLERS["client"]),
        "policy":      random.choice(FILLERS["policy"]),
        "reason":      random.choice(FILLERS["reason"]),
        "role":        random.choice(FILLERS["role"]),
        "token":       random.choice(FILLERS["token"]),
        "session_id":  random.choice(FILLERS["session_id"]),
        "approval_id": random.choice(FILLERS["approval_id"]),
        "person_name": random.choice(FILLERS["person_name"]),
        "webhook_url": random.choice(FILLERS["webhook_url"]),
        # Healthcare
        "patient_id":  random.choice(FILLERS["patient_id"]),
        "drug_name":   random.choice(FILLERS["drug_name"]),
        "diagnosis":   random.choice(FILLERS["diagnosis"]),
        "doctor_name": random.choice(FILLERS["doctor_name"]),
        # IPI（按场景采样）
        "ipi_file_content": random.choice(FILLERS[ipi_key]),
        # E-commerce
        "merchant_id": random.choice(FILLERS["merchant_id"]),
        "order_id":    random.choice(FILLERS["order_id"]),
        "carrier":     random.choice(FILLERS["carrier"]),
        "tracking_no": random.choice(FILLERS["tracking_no"]),
    }


def make_timestamp(base: datetime.datetime, offset_seconds: int) -> str:
    return (base + datetime.timedelta(seconds=offset_seconds)).strftime("%Y-%m-%dT%H:%M:%S.%f")


def compute_hash(payload: dict) -> str:
    raw = json.dumps(payload, ensure_ascii=False, sort_keys=True)
    return hashlib.sha256(raw.encode()).hexdigest()


# ─────────────────────────────────────────────────────────────────────────────
# 核心：骨架 → AuditEvent 序列
# ─────────────────────────────────────────────────────────────────────────────

# 场景类型到风险类型的映射
SCENARIO_RISK_TYPES = {
    "PathBypass":          ["missing_required_path_node"],
    "CallerImpersonation": ["authority_fabrication", "identity_spoofing"],
    "SemanticInjection":   ["semantic_manipulation", "hidden_intent"],
    "RouterHijacking":     ["route_hijack_check", "routing_manipulation"],
    "IPI":                 ["indirect_prompt_injection", "external_content_injection"],
    "AiTM":                ["man_in_the_middle", "message_tampering"],
    "PromptInfection":     ["prompt_infection", "payload_propagation"],
    "benign":              [],
}

# 明确的危险场景
CLEARLY_DANGEROUS = {"PathBypass", "CallerImpersonation", "IPI", "AiTM", "PromptInfection"}
# 默认模糊场景
AMBIGUOUS_DEFAULT = {"SemanticInjection", "RouterHijacking"}


def _find_interception_step_idx(skeleton: dict) -> int:
    """
    找到攻击应该被截断的步骤索引。
    
    对于单事件场景（含benign）：只有step 0
    对于IPI：File_System 发送的消息（被污染的文件内容）
    对于AiTM：AiTM_Interceptor发出的消息
    """
    scenario_type = skeleton.get("scenario_type", "")
    flow = skeleton.get("flow", [])
    
    # 对于单事件场景（含benign）：只有step 0
    if scenario_type not in ("IPI", "AiTM"):
        return 0
    
    if scenario_type == "IPI":
        # IPI：拦截 File_System 发送的消息（attacker生成的文件内容）
        for i, step in enumerate(flow):
            sender, _, _, event_type = step
            if event_type == "message" and sender == "File_System":
                return i
        # 如果没找到 File_System，fallback 到 tool_call 后的第一条 message
        for i, step in enumerate(flow):
            if i == 0:
                continue
            _, _, _, event_type = step
            if event_type == "message":
                prev_event_type = flow[i - 1][3]
                if prev_event_type == "tool_call":
                    return i
        return len(flow) - 1
    
    if scenario_type == "AiTM":
        for i, step in enumerate(flow):
            sender = step[0]
            if sender == "AiTM_Interceptor":
                return i
        return len(flow) - 1
    
    return 0





def _get_blocking_risk_types(scenario_type: str) -> list[str]:
    """根据场景类型获取阻断风险类型列表"""
    return SCENARIO_RISK_TYPES.get(scenario_type, [])


# ─────────────────────────────────────────────────────────────────────────────
# LLM API 生成审核原因
# ─────────────────────────────────────────────────────────────────────────────

_REASON_GENERATION_PROMPT = """你是多智能体系统安全审计专家。分析以下事件，用一句话（50-150字）说明其安全风险。
- 场景类型：{scenario_type}（{description}）
- 事件内容：{content}
- 工具参数：{tool_args}
- 检测到的风险类型：{risk_types}

要求：指出具体攻击手法和目标，不要泛泛而谈。
只输出原因文本。"""


def _generate_reason_with_api(
    content: str | None,
    tool_args: dict | None,
    skeleton: dict,
    blocking_risk_types: list[str],
    sender: str
) -> str:
    """
    调用 LLM API 生成审核原因的详细说明。
    仅对非normal事件调用（每条trace最多1次API调用）。
    API不可用时fallback到规则字符串。
    """
    client, model = _make_task_summary_client()
    if client is None:
        scenario_type = skeleton.get("scenario_type", "")
        return f"[{scenario_type}] 检测到：{', '.join(blocking_risk_types)}"
    
    scenario_type = skeleton.get("scenario_type", "")
    description = skeleton.get("description", "")
    
    # 截取content前300字
    content_snippet = content[:300] if content else ""
    tool_args_str = json.dumps(tool_args, ensure_ascii=False) if tool_args else "{}"
    
    prompt = _REASON_GENERATION_PROMPT.format(
        scenario_type=scenario_type,
        description=description,
        content=content_snippet,
        tool_args=tool_args_str,
        risk_types=", ".join(blocking_risk_types)
    )
    
    try:
        resp = client.chat.completions.create(
            model=model,
            temperature=0.3,
            max_tokens=512,
            messages=[
                {"role": "user", "content": prompt},
            ],
        )
        result = resp.choices[0].message.content.strip()
        return result
    except Exception as e:
        print(f"  [WARN] 原因生成 API 调用失败: {e}")
        return f"[{scenario_type}] 检测到：{', '.join(blocking_risk_types)}"


# ─────────────────────────────────────────────────────────────────────────────
# LLM API 任务摘要
# ─────────────────────────────────────────────────────────────────────────────

_TASK_SUMMARY_PROMPT = """你是一个任务意图提取助手。请从用户的原始消息中提取核心任务意图，用一句话概括（不超过80字符）。

要求：
- 保留关键操作（买入、卖出、查询、配置更新等）
- 保留关键对象（客户、股票、商家等）
- 去除修饰性话术和攻击话术
- 输出纯文本，不要解释

原始消息：
{user_message}

核心任务意图："""


def _make_task_summary_client():
    """创建 OpenAI 客户端用于任务摘要（延迟初始化）。"""
    try:
        from openai import OpenAI
        api_key = os.getenv("API_KEY")
        if not api_key:
            return None, None
        base_url = os.getenv("BASE_URL")
        model = os.getenv("MODEL", "gpt-4o-mini")
        client = OpenAI(api_key=api_key, base_url=base_url if base_url else None)
        return client, model
    except Exception:
        return None, None


def _summarize_task_with_api(user_message: str) -> str:
    """
    调用 LLM API 提取用户消息的核心任务意图。
    失败时返回空字符串。
    """
    client, model = _make_task_summary_client()
    if client is None:
        return ""

    prompt = _TASK_SUMMARY_PROMPT.format(user_message=user_message)
    try:
        resp = client.chat.completions.create(
            model=model,
            temperature=0.1,
            max_tokens=512,
            messages=[
                {"role": "user", "content": prompt},
            ],
        )
        result = resp.choices[0].message.content.strip()
        # 确保不超过 80 字符
        if len(result) > 80:
            result = result[:77] + "..."
        return result
    except Exception as e:
        print(f"  [WARN] 任务摘要 API 调用失败: {e}")
        return ""


def _extract_task_from_skeleton(skeleton: dict, values: dict) -> str:
    """
    从骨架的第一条 User 消息中提取任务核心意图。
    用于填充 AuditEvent.task 字段，作为意图一致性检测的锚点。

    策略：
    - 优先调用 LLM API 提取摘要
    - API 不可用时，fallback 到截断（500字符）
    """
    flow = skeleton.get("flow", [])
    if not flow:
        return ""

    # 第一条消息通常是 User 发起的
    first_step = flow[0]
    if len(first_step) < 3:
        return ""

    sender, receiver, content_tpl, event_type = first_step

    # 只处理 User 发送的消息
    if sender != "User":
        return ""

    # 填充占位符
    user_message = random_fill(content_tpl, values) if content_tpl else ""

    # 规范化空白
    user_message = " ".join(user_message.split())

    # 优先用 API 提取摘要
    task = _summarize_task_with_api(user_message)
    if task:
        return task

    # Fallback：截断到 80 字符
    if len(user_message) > 80:
        return user_message[:77] + "..."

    return user_message


def skeleton_to_events(skeleton: dict, values: dict, trace_id: str, defender=None) -> list[dict]:
    """
    将一条骨架实例化为 AuditEvent 列表（简化版，只生成必要事件）。

    简化逻辑：
      - 对于benign和非IPI/AiTM攻击：只生成第1个事件（User消息）
      - 对于IPI/AiTM攻击：生成到攻击理应被截断的那一步
      - 在拦截点停止，减轻系统负担

    history_summary 对齐真实 audit_events.json 的格式：
      - 只由 message 类型事件的 content 组成
      - 格式：[sender]: content\n---\n[sender]: content\n---\n...
      - 每条事件的 history_summary = 该事件写入前的累积摘要（不含自身）
      - 每条消息截取前 300 字，防止超长污染

    call_path 对齐真实格式：
      - 仅追加出现过的非路由 Agent（不含 Semantic_Router）
      - 按第一次出现顺序排列
    """
    events:        list[dict] = []
    call_path:     list[str]  = []
    history_lines: list[str]  = []
    prev_hash:     str | None = None
    base_time     = datetime.datetime.now(datetime.timezone.utc)
    time_offset   = 0
    scenario_type = skeleton.get("scenario_type", "")
    task = _extract_task_from_skeleton(skeleton, values)
    
    # 找到拦截点
    interception_idx = _find_interception_step_idx(skeleton)

    ROUTER_NODES = {"Semantic_Router"}
    TOOL_SENDERS = {"read_external_file_tool", "read_file_tool", "lab_query_tool"}  # 工具返回节点

    for i, step in enumerate(skeleton["flow"]):
        sender, receiver, content_tpl, event_type = step

        # ── 1. 填充占位符 ────────────────────────────────────────────────────
        raw_content = random_fill(content_tpl, values) if content_tpl else None

        # ── 2. 工具调用解析 ──────────────────────────────────────────────────
        tool_name = None
        tool_args: dict | None = None
        display_content = raw_content

        if event_type == "tool_call" and raw_content:
            tool_name, tool_args = _parse_tool_call(raw_content, values)
            display_content = None

        # ── 3. 更新 call_path（排除路由节点和工具节点）─────────────────────────
        if sender not in ROUTER_NODES and sender not in TOOL_SENDERS and sender not in call_path:
            call_path.append(sender)

        # ── 4. history_summary 快照 ──────────────────────────────────────────
        history_summary = "\n---\n".join(history_lines)

        # ── 5. 时间戳 ────────────────────────────────────────────────────────
        time_offset += random.randint(3, 12)
        timestamp = make_timestamp(base_time, time_offset)

        # ── 6. 哈希链 ────────────────────────────────────────────────────────
        hash_payload = {
            "event_id":   "",
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

        # ── 7. 构建增强 metadata（包含 audit_decision）───────────────────────
        metadata = _build_metadata_with_audit(
            skeleton=skeleton,
            event_type=event_type,
            step_idx=i,
            sender=sender,
            receiver=receiver,
            tool_name=tool_name,
            tool_args=tool_args,
            call_path=list(call_path),
            history_summary=history_summary,
            content=display_content,
            defender=defender,
        )
        
        # ── 8. 写入事件 ──────────────────────────────────────────────────────
        event = {
            "event_type":      event_type,
            "sender":          sender,
            "receiver":        receiver,
            "tool_name":       tool_name,
            "tool_args":       tool_args,
            "call_path":       list(call_path),
            "content":         display_content,
            "history_summary": history_summary,
            "task":            task,
            "event_id":        event_id,
            "trace_id":        trace_id,
            "timestamp":       timestamp,
            "self_hash":       self_hash,
            "metadata":        metadata,
        }
        events.append(event)
        prev_hash = self_hash

        # ── 9. 更新 history_lines ────────────────────────────────────────────
        if event_type == "message" and display_content:
            snippet = display_content[:300].replace("\n", " ")
            history_lines.append(f"[{sender}]: {snippet}")

        # ── 10. 新截断：达到拦截点后停止 ─────────────────────────────────────
        if i >= interception_idx:
            break

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
        # 新增：注入骨架级风险分，供审计模型训练用
        meta["skeleton_risk_score"] = skeleton.get("risk_score", 0.0)
        meta["skeleton_label"] = skeleton.get("label", "benign")
    return meta


def _build_metadata_with_audit(
    skeleton: dict,
    event_type: str,
    step_idx: int,
    sender: str,
    receiver: str | None,
    tool_name: str | None,
    tool_args: dict | None,
    call_path: list[str],
    history_summary: str,
    content: str | None,
    defender=None,
) -> dict:
    """
    构建 metadata，risk_level 语义：
    - high: 危险动作（攻击行为）
    - low:  安全动作（正常请求）
    - mid: 模棱两可的内容（defender 置信度中等，不确定）
    - low: 隐藏极深的内容（defender 高置信度判定为 SAFE，攻击成功隐藏）
    """
    scenario_type = skeleton.get("scenario_type", "")
    
    # 基础 metadata
    meta = _make_metadata(skeleton, event_type, step_idx)
    
    if step_idx == 0:
        meta["graph_type"] = "standard"
    
    # 意图分类（用于 state_transition）
    if event_type == "state_transition":
        intent_map = {
            "Trade_Agent": "execute_trade",
            "Asset_Agent": "query_asset",
            "Risk_Agent": "risk_consult",
            "Prescription_Agent": "prescribe",
            "ConfigAgent": "config_update",
        }
        intent = intent_map.get(receiver, "unknown")
        meta["intent"] = intent
        meta["intent_confidence"] = round(random.uniform(0.82, 0.98), 2)
        meta["reason"] = f"意图分类结果，step={step_idx}"
    
    # 工具调用信息
    if event_type == "tool_call" and tool_name:
        meta["tool_call_id"] = f"call_{uuid.uuid4().hex[:24]}"
        meta["blocking_risks"] = _get_blocking_risks(tool_name, call_path)
        meta["unauthorized"] = True
        meta["is_unknown_agent"] = False
        
        if tool_name == "trade_execute_tool":
            meta["action"] = tool_args.get("action", "UNKNOWN")
            meta["symbol"] = tool_args.get("symbol", "")
            meta["amount"] = tool_args.get("amount", 0)
        elif tool_name == "asset_query_tool":
            meta["client_id"] = tool_args.get("client_id", "")
    
    # 构建 audit_decision
    # risk_level 语义：high = 危险动作（攻击行为），low = 安全动作（正常请求）
    if defender is not None and content is not None and scenario_type != "benign":
        # 调用 defender 进行检测（置信度作为辅助信息保留）
        label, confidence = defender.predict(content)

        # 攻击场景：无论 defender 是否识破，动作本身即为危险
        blocking_risk_types = _get_blocking_risk_types(scenario_type)
        meta["audit_decision"] = {
            "risk_level": "high",
            "reason": f"检测到攻击行为（defender判定: {label}, 置信度: {confidence:.2f}）",
            "defender_label": label,
            "defender_confidence": round(confidence, 4),
            "blocking_risk_types": blocking_risk_types,
            "suggested_alternative": "建议先经过合规审查节点",
        }
    else:
        # benign 场景或无 defender 时的 fallback
        if scenario_type == "benign":
            meta["audit_decision"] = {
                "risk_level": "low",   # 安全动作
                "reason": "正常操作",
                "blocking_risk_types": [],
                "suggested_alternative": None,
            }
        else:
            # 攻击场景但无 defender：动作本身仍为危险
            blocking_risk_types = _get_blocking_risk_types(scenario_type)
            meta["audit_decision"] = {
                "risk_level": "high",  # 危险动作
                "reason": "未启用 defender 动态检测",
                "blocking_risk_types": blocking_risk_types,
                "suggested_alternative": "建议先经过合规审查节点",
            }
    
    return meta


def _get_blocking_risks(tool_name: str, call_path: list[str]) -> list[str]:
    """根据工具名和调用路径确定可能的阻断风险"""
    risks = []
    
    if tool_name in ("trade_execute_tool", "asset_query_tool"):
        if "Research_Agent" not in call_path:
            risks.append("missing_required_path_node:Research_Agent")
        risks.append("route_hijack_check")
    
    return risks


# ─────────────────────────────────────────────────────────────────────────────
# 主生成函数
# ─────────────────────────────────────────────────────────────────────────────

def generate(
    n_per_skeleton: int       = 5,
    output_dir:     str       = "output",
    scenario_types: list[str] = None,
    seed:           int       = 42,
    shuffle:        bool      = True,
    defender       = None,  # 新增 defender 参数
) -> int:
    """
    批量生成审计数据。

    Args:
        n_per_skeleton: 每条骨架生成几条 trace（随机填充不同值）
        output_dir:     输出目录
        seed:           随机种子（保证可复现）
        shuffle:        是否打乱最终数据集顺序

    Returns:
        生成的审计事件总数
    """
    random.seed(seed)
    out_path = Path(output_dir)
    out_path.mkdir(parents=True, exist_ok=True)

    audit_path = out_path / "audit.jsonl"

    # audit_blocks: 每元素为一个 trace 的所有 event 行，块内顺序严格保持
    audit_blocks: list[list[str]] = []

    # 过滤骨架
    filtered_skeletons = SKELETONS
    if scenario_types:
        filtered_skeletons = [s for s in SKELETONS if s.get("scenario_type") in scenario_types]

    print(f"▶ 开始生成，共 {len(filtered_skeletons)} 条骨架，每条 {n_per_skeleton} 次采样")
    print(f"  预计生成 ~{len(filtered_skeletons) * n_per_skeleton} 条 trace\n")

    for skeleton in filtered_skeletons:
        for sample_idx in range(n_per_skeleton):
            values   = sample_values(scenario_type=skeleton.get("scenario_type"))
            trace_id = str(uuid.uuid4())

            events = skeleton_to_events(skeleton, values, trace_id, defender=defender)

            # trace 内事件作为一个块，保持严格顺序
            block = [json.dumps(e, ensure_ascii=False) for e in events]
            audit_blocks.append(block)

            print(f"  [{skeleton['id']}] 样本 {sample_idx+1}/{n_per_skeleton}"
                  f"  trace={trace_id[:8]}..."
                  f"  events={len(events)}")

    # 打乱：只打乱 trace 块的顺序，块内事件顺序不变
    # 保证同一 trace 内 history_summary 的单调递增性
    if shuffle:
        random.shuffle(audit_blocks)

    # 展平并写入
    audit_lines = [line for block in audit_blocks for line in block]
    audit_path.write_text("\n".join(audit_lines), encoding="utf-8")

    print(f"\n✅ 生成完成")
    print(f"   audit.jsonl: {len(audit_lines)} 条事件  →  {audit_path}")

    return len(audit_lines)


