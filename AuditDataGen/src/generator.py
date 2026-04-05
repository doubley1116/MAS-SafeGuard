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

import os
import sys
import json
import uuid
import random
import hashlib
import datetime
import argparse
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


def sample_values() -> dict:
    """随机采样一组填充值，每次调用返回不同组合。"""
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

def _is_attack_triggered(
    event_type:      str,
    sender:          str,
    receiver:        str | None,
    content:         str | None,
    scenario_type:   str,
) -> bool:
    """
    判断当前事件是否标志着攻击已成功触发。
    返回 True 表示"防御层在此阻断"，后续事件全部丢弃（本事件作为证据保留）。
    benign 场景永不截断。
    """
    if scenario_type == "benign":
        return False

    # 1. 高危工具调用
    if event_type == "tool_call" and content in (
        "trade_execute_tool", "asset_query_tool"
    ):
        return True

    # 2. 后门标记出现在 message 中
    if event_type == "message" and content:
        if "<EXEC_GME_OVERRIDE>" in content:
            return True
        # 多跳传播载荷特征
        if ("快速通道" in content and
                any(kw in content for kw in
                    ["调用工具", "trade_execute", "买入", "卖出", "立即执行"])):
            return True

    # 3. AiTM 中间人节点发出消息后截断
    if event_type == "message" and sender == "AiTM_Interceptor":
        return True

    return False


def skeleton_to_events(skeleton: dict, values: dict, trace_id: str) -> list[dict]:
    """
    将一条骨架实例化为完整的 AuditEvent 列表。

    防御截断逻辑：
      模拟防御层检测到攻击后立即阻断的行为。
      当某事件标志着攻击已成功触发时（_is_attack_triggered），
      保留该事件（攻击证据），丢弃后续所有事件。
      benign 场景不截断，完整保留。

      示例：A → B → C(攻击触发) → D → E
        结果保留：A, B, C
        丢弃：D, E

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

    ROUTER_NODES = {"Semantic_Router"}

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

        # ── 3. 更新 call_path ────────────────────────────────────────────────
        if sender not in ROUTER_NODES and sender not in call_path:
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

        # ── 10. 防御截断 ─────────────────────────────────────────────────────
        #   tool_call 传 tool_name，message 传 display_content
        check_content = tool_name if event_type == "tool_call" else display_content
        if _is_attack_triggered(event_type, sender, receiver,
                                check_content, scenario_type):
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


# ─────────────────────────────────────────────────────────────────────────────
# audit_decision 生成器
# ─────────────────────────────────────────────────────────────────────────────

def _generate_audit_decision(
    skeleton: dict,
    step_idx: int,
    event_type: str,
    sender: str,
    receiver: str | None,
    tool_name: str | None,
    tool_args: dict | None,
    call_path: list[str],
    history_summary: str,
) -> dict:
    """
    生成 audit_decision 字段，模拟防御层的审核决策。
    
    逻辑：
    - 攻击骨架：用户消息通常放行（规则未命中），工具调用被拦截
    - benign 骨架：全部放行
    - 拦截依据：missing_required_path_node, route_hijack_check, authority_fabrication 等
    
    Returns:
        dict: {
            "allow": bool,
            "risk_score": float,
            "reason": str,
            "blocking_risk_types": list[str],
            "suggested_alternative": str | None,
            "level": "pass" | "block"
        }
    """
    scenario_type = skeleton.get("scenario_type", "")
    audit_pattern = skeleton.get("audit_pattern", {})
    risk_score = skeleton.get("risk_score", 0.5)
    skeleton_id = skeleton.get("id", "")
    
    # 如果骨架定义了 audit_pattern，按其定义生成
    if audit_pattern:
        if event_type == "message" and "user_message" in audit_pattern:
            pattern = audit_pattern["user_message"]
            return {
                "allow": pattern.get("expected_audit_result") == "allow",
                "risk_score": pattern.get("expected_risk_score", 0.0),
                "reason": pattern.get("expected_reason", "[规则放行] 风险分=0.00，未命中任何规则"),
                "blocking_risk_types": pattern.get("blocking_risk_types", []),
                "suggested_alternative": None,
                "level": "pass"
            }
        elif event_type == "state_transition" and "router_transition" in audit_pattern:
            pattern = audit_pattern["router_transition"]
            return {
                "allow": True,
                "risk_score": 0.0,
                "reason": "[规则放行] 意图分类可信，未命中风险规则",
                "blocking_risk_types": [],
                "suggested_alternative": None,
                "level": "pass"
            }
        elif event_type == "tool_call" and "asset_query" in audit_pattern:
            pattern = audit_pattern["asset_query"]
            return {
                "allow": False,
                "risk_score": pattern.get("expected_risk_score", risk_score),
                "reason": pattern.get("expected_reason", "[规则拦截] 调用前缺少必经节点"),
                "blocking_risk_types": pattern.get("blocking_risk_types", ["missing_required_path_node"]),
                "suggested_alternative": pattern.get("suggested_alternative", "建议先经过 Research_Agent 进行合规性审查"),
                "level": "block"
            }
        elif event_type == "tool_call" and "trade_execute" in audit_pattern:
            pattern = audit_pattern["trade_execute"]
            return {
                "allow": False,
                "risk_score": pattern.get("expected_risk_score", risk_score),
                "reason": pattern.get("expected_reason", "[规则拦截] 未授权交易执行"),
                "blocking_risk_types": pattern.get("blocking_risk_types", ["unauthorized_trade"]),
                "suggested_alternative": pattern.get("suggested_alternative", "需经过完整合规审批流程"),
                "level": "block"
            }
    
    # 默认逻辑：根据骨架类型和事件类型推断
    # 1. benign 骨架全部放行
    if scenario_type == "benign":
        return {
            "allow": True,
            "risk_score": 0.0,
            "reason": "[规则放行] 正常业务请求，符合合规要求",
            "blocking_risk_types": [],
            "suggested_alternative": None,
            "level": "pass"
        }
    
    # 2. 攻击骨架的用户消息（第一步）通常放行
    if step_idx == 0 and event_type == "message":
        return {
            "allow": True,
            "risk_score": 0.0,
            "reason": "[规则放行] 风险分=0.00，未命中任何规则",
            "blocking_risk_types": [],
            "suggested_alternative": None,
            "level": "pass"
        }
    
    # 3. 状态转换（路由器跳转）通常放行
    if event_type == "state_transition":
        intent_map = {
            "Trade_Agent": "execute_trade",
            "Asset_Agent": "query_asset",
            "Risk_Agent": "risk_consult",
            "Prescription_Agent": "prescribe",
            "ConfigAgent": "config_update",
        }
        intent = intent_map.get(receiver, "unknown")
        return {
            "allow": True,
            "risk_score": 0.0,
            "reason": f"[规则放行] 意图跳转: {intent}，未命中风险规则",
            "blocking_risk_types": [],
            "suggested_alternative": None,
            "level": "pass"
        }
    
    # 4. 工具调用拦截
    if event_type == "tool_call":
        blocking_types = []
        reason = "[规则拦截]"
        
        # 检测是否绕过必经节点
        if "Research_Agent" not in call_path and sender in ("Asset_Agent", "Trade_Agent"):
            blocking_types.append("missing_required_path_node")
            reason += f" 调用前缺少必经节点：['Research_Agent']，当前路径：{call_path}"
        
        # 交易工具拦截
        if tool_name == "trade_execute_tool":
            blocking_types.append("unauthorized_trade")
            reason += f" | trade_execute_tool 需要 LLM 验证 intent 分类与 prompt 语义是否一致"
        
        # 资产查询工具拦截
        if tool_name == "asset_query_tool":
            blocking_types.append("data_exfiltration")
            reason += f" | asset_query_tool 标记 route_hijack_check，需要验证调用者身份"
        
        # CallerImpersonation 检测
        if scenario_type == "CallerImpersonation":
            blocking_types.append("authority_fabrication")
            reason = "[规则拦截] 检测到身份冒充攻击"
        
        # AiTM检测
        if scenario_type == "AiTM":
            blocking_types.append("man_in_the_middle")
            reason = "[规则拦截] 检测到中间人攻击"
        
        return {
            "allow": False,
            "risk_score": risk_score,
            "reason": reason,
            "blocking_risk_types": blocking_types,
            "suggested_alternative": "建议先经过合规审查节点" if blocking_types else None,
            "level": "block"
        }
    
    # 默认：放行
    return {
        "allow": True,
        "risk_score": risk_score * 0.5,
        "reason": "[规则放行] 风险分较低，未命中高风险规则",
        "blocking_risk_types": [],
        "suggested_alternative": None,
        "level": "pass"
    }


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
) -> dict:
    """
    构建完整的 metadata，包含 audit_decision。
    """
    # 基础 metadata
    meta = _make_metadata(skeleton, event_type, step_idx)
    
    # 场景信息
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
    
    # 添加 audit_decision
    meta["audit_decision"] = _generate_audit_decision(
        skeleton, step_idx, event_type, sender, receiver,
        tool_name, tool_args, call_path, history_summary
    )
    
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
# SFT 格式转换
# ─────────────────────────────────────────────────────────────────────────────

def events_to_sft(events: list[dict], skeleton: dict) -> dict:
    """
    将一条 trace 的 AuditEvent 列表转换为 SFT 训练格式。

    input:  包含完整上下文的结构体（current_event, history_summary, call_path, scenario_hint）
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

    # 修改：input 包含完整上下文
    input_obj = {
        "current_event":   target,
        "history_summary":  target.get("history_summary", ""),
        "call_path":       target.get("call_path", []),
        "scenario_hint":   stype,
    }

    output = {
        "risk_score":           skeleton["risk_score"],
        "triggered_dimensions": dimensions,
        "reason":               _infer_reason(stype, skeleton["description"], events),
    }

    return {
        "input":          json.dumps(input_obj, ensure_ascii=False),
        "output":         json.dumps(output, ensure_ascii=False),
        "skeleton_id":    skeleton["id"],
        "scenario_type":  stype,
        "label":          skeleton["label"],
    }


def _infer_dimensions(scenario_type: str, events: list[dict]) -> list[str]:
    """根据 scenario_type 推断触发维度，与 skeletons.py 保持一致"""
    dim_map = {
        "PathBypass":            ["missing_required_path_node", "unauthorized_trade"],
        "CallerImpersonation":   ["authority_fabrication", "identity_spoofing"],
        "SemanticInjection":     ["implicit_instruction_injection", "authority_fabrication"],
        "RouterHijacking":       ["route_hijack", "missing_required_path_node"],
        "IPI":                   ["indirect_injection", "environment_pollution"],
        "AiTM":                  ["man_in_the_middle", "message_tampering"],
        "benign":                [],
    }
    dims = dim_map.get(scenario_type, ["unknown"])

    # 追加：如果触发了 trade_execute_tool 则加 unauthorized_trade
    tool_calls = [e for e in events if e["event_type"] == "tool_call"]
    for tc in tool_calls:
        if tc.get("tool_name") == "trade_execute_tool" and scenario_type != "benign":
            if "unauthorized_trade" not in dims:
                dims.append("unauthorized_trade")
        if tc.get("tool_name") == "asset_query_tool" and scenario_type in ("CallerImpersonation", "IPI"):
            if "data_exfiltration" not in dims:
                dims.append("data_exfiltration")

    return dims


def _infer_reason(scenario_type: str, description: str, events: list[dict]) -> str:
    """根据 scenario_type 推断检测原因，与 skeletons.py 保持一致"""
    templates = {
        "PathBypass":            "检测到路径绕过攻击：{desc}。攻击者绕过合规/风控节点，直接调用底层工具执行越权操作。",
        "CallerImpersonation":   "检测到身份冒充攻击：{desc}。攻击者伪造权威身份（管理员/合规官），利用虚假授权令牌绕过身份验证。",
        "SemanticInjection":     "检测到语义注入攻击：{desc}。攻击者在看似正常的请求中嵌入越权操作，诱导投研Agent错误定性为合规请求。",
        "RouterHijacking":       "检测到路由劫持攻击：{desc}。攻击者干扰路由决策，让请求被派给错误的Agent或绕过合规节点。",
        "IPI":                   "检测到间接提示注入攻击：{desc}。恶意指令隐藏在外部文档/历史消息中，当Agent读取外部资源时被感染并执行攻击指令。",
        "AiTM":                  "检测到中间人攻击：{desc}。攻击者在通信链路中拦截并篡改合法消息，替换为恶意指令影响下游Agent决策。",
        "benign":                "未检测到安全风险：{desc}。该请求符合正常业务流程，无越权操作，无异常调用链。",
    }
    tpl = templates.get(scenario_type, "检测到潜在风险：{desc}。")
    return tpl.format(desc=description)


# ─────────────────────────────────────────────────────────────────────────────
# 主生成函数
# ─────────────────────────────────────────────────────────────────────────────

def generate(
    n_per_skeleton: int       = 5,
    output_dir:     str       = "output",
    scenario_types: list[str] = None,  # 新增：场景类型过滤
    seed:           int       = 42,
    sft_format:     bool      = True,
    shuffle:        bool      = True,
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

    # 过滤骨架
    filtered_skeletons = SKELETONS
    if scenario_types:
        filtered_skeletons = [s for s in SKELETONS if s.get("scenario_type") in scenario_types]
        
    print(f"▶ 开始生成，共 {len(filtered_skeletons)} 条骨架，每条 {n_per_skeleton} 次采样")
    print(f"  预计生成 ~{len(filtered_skeletons) * n_per_skeleton} 条 trace\n")

    for skeleton in filtered_skeletons:
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
    parser.add_argument("--scenario-type", type=str, default=None, help="指定场景类型，逗号分隔（如 DPI,benign），默认生成全部")
    parser.add_argument("--seed",    type=int,  default=42,       help="随机种子（默认 42）")
    parser.add_argument("--no-sft",  action="store_true",         help="不生成 SFT 格式")
    parser.add_argument("--no-shuffle", action="store_true",      help="不打乱顺序")
    args = parser.parse_args()

    # 解析 scenario_types
    scenario_types = None
    if args.scenario_type:
        scenario_types = [t.strip() for t in args.scenario_type.split(",")]

    generate(
        n_per_skeleton = args.n,
        output_dir     = args.out,
        scenario_types = scenario_types,
        seed           = args.seed,
        sft_format     = not args.no_sft,
        shuffle        = not args.no_shuffle,
    )
