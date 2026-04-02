from __future__ import annotations
# ════════════════════════════════════════════════════════════════
# 审核开关 — 设为 False 则跳过所有 SecurityCore 审核，直接放行
# ════════════════════════════════════════════════════════════════
AUDIT_ENABLED: bool = False

import json
import uuid
import functools
import inspect
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Callable
import sys
import os

# 把项目根目录加入路径
sys.path.append(str(Path(__file__).parents[2])) 
from audit_layer.security_core import SecurityCore
from audit_layer.audit_models import AuditEvent, AuditDecision

# ════════════════════════════════════════════════════════════════
# 权限配置
# ════════════════════════════════════════════════════════════════

ALLOWED_CALLERS: dict[str, list[str]] = {
    "triage_assess_tool":    ["Triage_Agent"],
    "diagnosis_tool":        ["Diagnosis_Agent"],
    "lab_query_tool":        ["Diagnosis_Agent"],
    "review_tool":           ["Review_Agent"],
    "prescription_tool":     ["Prescription_Agent"],
    "dispense_tool":         ["Pharmacy_Agent"],
}

REQUIRED_PATH_NODES: dict[str, list[str]] = {
    "prescription_tool": ["Review_Agent"],
    "dispense_tool":     ["Prescription_Agent"],
}

LEGAL_AGENTS = {
    "Patient_Proxy", "Triage_Agent", "Diagnosis_Agent", "Review_Agent", 
    "Prescription_Agent", "Pharmacy_Agent"
}


# ── 场景计数器（按 attack_name 分组，自动递增编号） ──────────────────
_scenario_counters: dict[str, int] = {}

# ── 全局工具拦截标志：SecurityCore 判定拦截时置 True，工具函数检查此标志 ──
TOOL_EXECUTION_BLOCKED: bool = False


# ════════════════════════════════════════════════════════════════
# 辅助函数
# ════════════════════════════════════════════════════════════════

def _now() -> str:
    return datetime.utcnow().isoformat()


def _extend_path(path: list[str], *nodes: str | None) -> list[str]:
    """
    将 nodes 中不为 None、不已经是路径末尾的节点追加到 path。
    允许同一节点在路径中出现多次，但不追加连续重复。
    返回 path 本身（原地修改）。
    """
    for node in nodes:
        if node is not None and (not path or path[-1] != node):
            path.append(node)
    return path


# ════════════════════════════════════════════════════════════════
# 序列化
# ════════════════════════════════════════════════════════════════

def _event_to_dict(ev: AuditEvent) -> dict:
    from dataclasses import asdict
    d = asdict(ev)
    safe_meta: dict = {}
    for k, v in d.get("metadata", {}).items():
        try:
            json.dumps(v)
            safe_meta[k] = v
        except (TypeError, ValueError):
            safe_meta[k] = str(v)
    d["metadata"] = safe_meta
    return d


# ════════════════════════════════════════════════════════════════
# AdapterCore 主类
# ════════════════════════════════════════════════════════════════

class AdapterCore:
    """
    AutoGen 安全审核适配器（v3）。
    基于audit_events.json格式和CrewAI设计模式，实现完整的审计功能
    """

    def __init__(self, yaml_path: str = "healthcare.yaml"):
        # 初始化 SecurityCore（Audit_layer 审核层）
        current_dir = Path(__file__).parent
        yaml_file = current_dir / yaml_path
        self.audit_layer = SecurityCore(str(yaml_file))
        
        # 对话历史记录
        self.conversation_history: List[Dict[str, str]] = []
        self.call_path: List[str] = []

    def sanitize_payload(self, payload: Any) -> Any:
        """递归净化数据，防止复杂对象导致JSON序列化崩溃"""
        if isinstance(payload, (str, int, float, bool, type(None))):
            return payload
        elif isinstance(payload, dict):
            return {str(k): self.sanitize_payload(v) for k, v in payload.items()}
        elif isinstance(payload, list):
            return [self.sanitize_payload(item) for item in payload]
        else:
            return f"<Object: {type(payload).__name__}>"

    def build_history_summary(self) -> str:
        """构建完整的对话历史摘要（基于audit_events.json格式）"""
        if not self.conversation_history:
            return ""
        
        history_lines = []
        for entry in self.conversation_history:
            sender = entry.get('sender', 'Unknown')
            content = entry.get('content', '')
            # 使用audit_events.json中的格式：[Agent]: 内容
            history_lines.append(f"[{sender}]: {content}")
        
        return "\n---\n".join(history_lines)

    def add_conversation_entry(self, sender: str, content: str):
        """添加对话历史条目"""
        self.conversation_history.append({
            'sender': sender,
            'content': content,
            'timestamp': _now()
        })

    def update_call_path(self, agent_name: str):
        """更新调用路径"""
        if agent_name not in self.call_path:
            self.call_path.append(agent_name)

    def emit_message(self, 
                     sender: str, 
                     receiver: str, 
                     content: str,
                     call_path: Optional[List[str]] = None,
                     history_summary: Optional[str] = None,
                     metadata: Optional[Dict[str, Any]] = None) -> AuditEvent:
        """发送消息事件（基于audit_events.json格式）"""
        
        # 更新调用路径和对话历史
        self.update_call_path(sender)
        self.add_conversation_entry(sender, content)
        
        # 使用传入参数或默认值
        final_call_path = call_path or self.call_path.copy()
        final_history_summary = history_summary or self.build_history_summary()
        
        event = AuditEvent(
            event_type="message",
            sender=sender,
            receiver=receiver,
            tool_name=None,
            tool_args=None,
            call_path=final_call_path,
            content=content,
            history_summary=final_history_summary,
            trace_id=f"healthcare_{uuid.uuid4().hex[:8]}",
            metadata=metadata or {}
        )
        
        # 添加event_id和timestamp（符合audit_events.json格式）
        event.event_id = str(uuid.uuid4())
        event.timestamp = _now()
        
        self.print_audit(event, f"消息监控 ({sender} -> {receiver})")
        return event

    def emit_tool_call(self,
                       sender: str,
                       tool_name: str,
                       tool_args: Optional[Dict[str, Any]] = None,
                       call_path: Optional[List[str]] = None,
                       content: Optional[str] = None,
                       history_summary: Optional[str] = None,
                       metadata: Optional[Dict[str, Any]] = None) -> AuditEvent:
        """发送工具调用事件（基于audit_events.json格式）"""
        
        # 净化工具参数
        clean_args = self.sanitize_payload(tool_args or {})
        
        # 更新调用路径
        self.update_call_path(sender)
        
        # 使用传入参数或默认值
        final_call_path = call_path or self.call_path.copy()
        final_history_summary = history_summary or self.build_history_summary()
        
        event = AuditEvent(
            event_type="tool_call",
            sender=sender,
            receiver=None,
            tool_name=tool_name,
            tool_args=clean_args,
            call_path=final_call_path,
            content=content,
            history_summary=final_history_summary,
            trace_id=f"healthcare_{uuid.uuid4().hex[:8]}",
            metadata=metadata or {}
        )
        
        # 添加event_id和timestamp
        event.event_id = str(uuid.uuid4())
        event.timestamp = _now()
        
        self.print_audit(event, f"工具调用监控 ({sender} -> {tool_name})")
        return event

    def emit_tool_result(self,
                         sender: str,
                         tool_name: str,
                         result: Any,
                         call_path: Optional[List[str]] = None,
                         content: Optional[str] = None,
                         history_summary: Optional[str] = None,
                         metadata: Optional[Dict[str, Any]] = None) -> AuditEvent:
        """发送工具执行结果事件（基于audit_events.json格式）"""
        
        # 更新调用路径和对话历史
        self.update_call_path(sender)
        self.add_conversation_entry(sender, str(result))
        
        # 使用传入参数或默认值
        final_call_path = call_path or self.call_path.copy()
        final_content = content or str(result)
        final_history_summary = history_summary or self.build_history_summary()
        
        event = AuditEvent(
            event_type="tool_result",
            sender=sender,
            receiver=None,
            tool_name=tool_name,
            tool_args=None,
            call_path=final_call_path,
            content=final_content,
            history_summary=final_history_summary,
            trace_id=f"healthcare_{uuid.uuid4().hex[:8]}",
            metadata=metadata or {}
        )
        
        # 添加event_id和timestamp
        event.event_id = str(uuid.uuid4())
        event.timestamp = _now()
        
        self.print_audit(event, f"工具结果监控 ({sender} -> {tool_name})")
        return event

    def print_audit(self, event: AuditEvent, prefix: str):
        """将标准化事件输出到终端（基于audit_events.json格式）"""
        print(f"\n[ 审计系统 | {prefix} ] ->")
        
        # 构建完整的JSON输出（符合audit_events.json格式）
        audit_data = {
            "event_type": event.event_type,
            "sender": event.sender,
            "receiver": event.receiver,
            "tool_name": event.tool_name,
            "tool_args": event.tool_args,
            "call_path": event.call_path,
            "content": event.content,
            "history_summary": event.history_summary,
            "event_id": getattr(event, 'event_id', str(uuid.uuid4())),
            "trace_id": event.trace_id,
            "timestamp": getattr(event, 'timestamp', _now()),
            "metadata": event.metadata
        }
        
        print(json.dumps(audit_data, indent=2, ensure_ascii=False))
        print("-" * 50)

    def audit_tool_call(self, tool_name: str, caller: str, tool_args: Dict[str, Any], call_path: List[str], content: str = "", history_summary: str = "") -> AuditDecision:
        """审核工具调用"""
        event = self.emit_tool_call(
            sender=caller,
            tool_name=tool_name,
            tool_args=tool_args,
            call_path=call_path,
            content=content,
            history_summary=history_summary,
            metadata={
                "scenario":       "healthcare",
                "graph_type":     "AutoGen",
                "node_name":      caller,
                "skeleton_id":    f"LLM-{uuid.uuid4()}",
            }
        )
        decision = self.audit_layer.audit(event)
        
        # 添加审核决策到事件元数据
        event.metadata["audit_decision"] = {
            "allow": decision.allow,
            "risk_score": decision.risk_score,
            "reason": decision.reason,
            "blocking_risk_types": decision.blocking_risk_types,
            "suggested_alternative": decision.suggested_alternative
        }
        
        return decision

    def audit_message(self, sender: str, receiver: str, content: str, call_path: List[str], history_summary: str = "") -> AuditDecision:
        """审核消息传递"""
        event = self.emit_message(
            sender=sender,
            receiver=receiver,
            content=content,
            call_path=call_path,
            history_summary=history_summary,
            metadata={
                "scenario":       "healthcare",
                "graph_type":     "AutoGen",
                "node_name":      sender,
                "skeleton_id":    f"LLM-{uuid.uuid4()}",
            }
        )
        decision = self.audit_layer.audit(event)
        
        # 添加审核决策到事件元数据
        event.metadata["audit_decision"] = {
            "allow": decision.allow,
            "risk_score": decision.risk_score,
            "reason": decision.reason,
            "blocking_risk_types": decision.blocking_risk_types,
            "suggested_alternative": decision.suggested_alternative
        }
        
        return decision

# ════════════════════════════════════════════════════════════════
# 全局适配器实例
# ════════════════════════════════════════════════════════════════
_adapter: AdapterCore | None = None

def get_adapter() -> AdapterCore:
    global _adapter
    if _adapter is None:
        _adapter = AdapterCore(yaml_path="healthcare.yaml")
    return _adapter

# ════════════════════════════════════════════════════════════════
# 工具包装器
# ════════════════════════════════════════════════════════════════

def audit_tool_wrapper(tool_func, agent_name: str):
    """工具包装器，用于审核工具调用"""
    def wrapper(*args, **kwargs):
        if not AUDIT_ENABLED:
            return tool_func(*args, **kwargs)
        
        # 获取调用上下文
        caller = agent_name
        tool_name = tool_func.__name__
        tool_args = kwargs
        call_path = kwargs.get('call_path', [])
        content = kwargs.get('content', '')
        history_summary = kwargs.get('history_summary', '')
        
        # 执行审核
        adapter = get_adapter()
        decision = adapter.audit_tool_call(tool_name, caller, tool_args, call_path, content, history_summary)
        
        if not decision.allow:
            global TOOL_EXECUTION_BLOCKED
            TOOL_EXECUTION_BLOCKED = True
            print(f"\n🛑 工具调用被拦截: {decision.reason}")
            sys.exit(1)
        
        # 审核通过，执行工具
        result = tool_func(*args, **kwargs)
        
        # 发送工具结果事件
        adapter.emit_tool_result(
            sender=caller,
            tool_name=tool_name,
            result=result,
            call_path=call_path,
            content=content,
            history_summary=history_summary
        )
        
        return result
    return wrapper

# ════════════════════════════════════════════════════════════════
# 消息拦截器
# ════════════════════════════════════════════════════════════════

def audit_message(sender: str, receiver: str, content: str, call_path: List[str], history_summary: str = "") -> bool:
    """审核消息传递 - 增强版，与工具调用具有相同拦截强度"""
    if not AUDIT_ENABLED:
        return True
    
    adapter = get_adapter()
    decision = adapter.audit_message(sender, receiver, content, call_path, history_summary)
    
    if not decision.allow:
        global TOOL_EXECUTION_BLOCKED
        TOOL_EXECUTION_BLOCKED = True
        print(f"\n🛑 消息被拦截: {sender} → {receiver}")
        print(f"   拦截原因: {decision.reason}")
        print(f"   风险分: {decision.risk_score:.2f}")
        if decision.blocking_risk_types:
            print(f"   风险类型: {decision.blocking_risk_types}")
        
        # 与工具调用拦截保持一致的行为 - 退出程序
        sys.exit(1)
    
    return True

# ════════════════════════════════════════════════════════════════
# 消息包装器（新增）
# ════════════════════════════════════════════════════════════════

def message_wrapper(original_send_func):
    """消息发送包装器，用于拦截危险的消息传递"""
    def wrapper(self, message, recipient, request_reply, silent):
        if not AUDIT_ENABLED:
            return original_send_func(self, message, recipient, request_reply, silent)
        
        # 获取发送者和接收者名称
        sender_name = getattr(self, 'name', 'Unknown_Sender')
        receiver_name = getattr(recipient, 'name', 'Unknown_Receiver') if hasattr(recipient, 'name') else str(recipient)
        
        # 获取消息内容
        message_content = ""
        if hasattr(message, 'content'):
            message_content = message.content or ""
        elif hasattr(message, '__str__'):
            message_content = str(message)
        else:
            message_content = f"<Message of type {type(message).__name__}>"
        
        # 执行消息审核
        if not audit_message(sender_name, receiver_name, message_content, [], ""):
            # 如果审核不通过，返回空消息或拦截消息
            return None
        
        # 审核通过，继续发送消息
        return original_send_func(self, message, recipient, request_reply, silent)
    
    return wrapper
