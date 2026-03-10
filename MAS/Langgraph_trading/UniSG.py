"""
通用多智能体安全网关 (Universal Security Gateway)
支持任意基于 LangGraph 和 LangChain 架构的 MAS 系统。
无侵入式设计，通过底层基类代理实现全局拦截。
"""

import json
import os
import uuid
import functools
import contextvars
from dataclasses import asdict
from typing import Optional, Dict, Any

# ================= 导入基类与审计模型 =================
from audit_models import AuditEvent, AuditDecision
from langchain_core.tools import BaseTool
from langgraph.graph.state import CompiledStateGraph

class SecurityBlockException(Exception):
    """当安全网关拒绝操作时抛出的阻断异常"""
    pass

AUDIT_LOG_FILE = "universal_audit_events.json"

if os.path.exists(AUDIT_LOG_FILE):
    os.remove(AUDIT_LOG_FILE)
with open(AUDIT_LOG_FILE, 'w', encoding='utf-8') as f:
    json.dump([], f)

# ================= 并发安全的上下文追踪 (ContextVars) =================
# 即使有 1000 个用户并发调用图网络，每个请求的上下文也完全隔离
cv_trace_id = contextvars.ContextVar("trace_id", default="")
cv_call_path = contextvars.ContextVar("call_path", default=[])
cv_dialogue_history = contextvars.ContextVar("dialogue_history", default=[])

def start_new_trace(prompt: str):
    """每次启动新流程前，初始化独立的追踪上下文"""
    cv_trace_id.set(str(uuid.uuid4()))
    cv_call_path.set(["User"])
    cv_dialogue_history.set([f"[User]: {prompt.strip()}"])

def get_history_summary(n: int = 3) -> str:
    """获取当前上下文最近 N 条对话记录摘要"""
    history = cv_dialogue_history.get()
    if not history:
        return ""
    return "\n---\n".join(history[-n:])

# ================= 核心网关裁决逻辑 =================
def evaluate_audit_event(event: AuditEvent, prefix: str) -> AuditDecision:
    event_dict = asdict(event)
    print(f"\n[ 通用网关 | {prefix}] -> 捕获事件:\n{json.dumps(event_dict, indent=2, ensure_ascii=False)}")
    
    try:
        with open(AUDIT_LOG_FILE, 'r', encoding='utf-8') as f:
            events = json.load(f)
    except (json.JSONDecodeError, FileNotFoundError):
        events = []
        
    events.append(event_dict)
    
    with open(AUDIT_LOG_FILE, 'w', encoding='utf-8') as f:
        json.dump(events, f, indent=2, ensure_ascii=False)

    decision = AuditDecision(
        allow=True,
        risk_score=0.1,  
        reason="验证阶段：记录 Event 并放行",
        blocking_risk_types=[]
    )
    return decision

# ================= 脏数据清洗 =================
def sanitize_payload(payload):
    if isinstance(payload, (str, int, float, bool, type(None))):
        return payload
    elif isinstance(payload, dict):
        ignored_keys = {"run_manager", "config", "callbacks", "tags", "metadata"}
        return {str(k): sanitize_payload(v) for k, v in payload.items() if k not in ignored_keys}
    elif isinstance(payload, list):
        return [sanitize_payload(item) for item in payload]
    else:
        return f"<Object: {type(payload).__name__}>"

# ================= 拦截点 A：代理任意 LangChain 工具 =================
original_base_tool_invoke = BaseTool.invoke

def universal_secure_tool_invoke(self, input: Any, config: Optional[Any] = None, **kwargs: Any) -> Any:
    # self.name 将自动捕获子类工具的名称
    raw_args = input if input else kwargs
    args_to_log = sanitize_payload(raw_args)
    
    current_path = cv_call_path.get()
    sender_agent = current_path[-1] if current_path else "Unknown"
    
    event = AuditEvent(
        event_type="tool_call",
        sender=sender_agent, 
        receiver=None,
        tool_name=self.name,
        tool_args=args_to_log if isinstance(args_to_log, dict) else {"input": args_to_log},
        call_path=list(current_path),
        trace_id=cv_trace_id.get(),
        history_summary=get_history_summary(n=3)
    )
    
    decision = evaluate_audit_event(event, f"工具调用 ({self.name})")
    if not decision.allow:
        raise SecurityBlockException(f"工具调用已被网关拦截: {decision.reason}")
    
    return original_base_tool_invoke(self, input, config, **kwargs)

# 注入基类
BaseTool.invoke = universal_secure_tool_invoke


# ================= 拦截点 B：代理任意 LangGraph 状态图流转 =================
original_graph_stream = CompiledStateGraph.stream

def universal_secure_stream(self, input: Any, config: Optional[Any] = None, **kwargs: Any) -> Any:
    # 消费原有的图事件生成器
    for event_data in original_graph_stream(self, input, config, **kwargs):
        
        # 1. 兼容性适配：LangGraph 在不同 stream_mode 下产生的 event_data 格式不同
        items_to_check = []
        if isinstance(event_data, dict):
            # 默认 stream_mode="updates" 时，格式为 {"node_name": state_dict}
            items_to_check = event_data.items()
        elif isinstance(event_data, tuple) and len(event_data) == 2 and isinstance(event_data[0], str):
            # 内部 invoke 隐式调用时，数据可能是元组 (node_name, state)
            items_to_check = [event_data]
            
        # 2. 遍历并执行网关逻辑
        for node_name, node_state in items_to_check:
            # 过滤掉内部变量，只处理带有 messages 的有效节点状态
            if isinstance(node_state, dict) and "messages" in node_state and node_state["messages"]:
                last_msg = node_state["messages"][-1]
                
                # 动态更新调用链
                current_path = list(cv_call_path.get())
                if node_name not in current_path:
                    current_path.append(node_name)
                    cv_call_path.set(current_path)

                if hasattr(last_msg, "tool_calls") and last_msg.tool_calls:
                    receiver_name = "ToolNode"
                    tool_names = ", ".join([tc["name"] for tc in last_msg.tool_calls])
                    content_info = f"[{len(last_msg.tool_calls)} 个工具调用请求: {tool_names}]"
                else:
                    receiver_name = "System"  # 通用流转不知具体下一站，设为通用接收方
                    content_info = last_msg.content
                    # 只有 Agent 输出实质文本时，才加入到历史摘要中
                    if last_msg.content:
                        history = list(cv_dialogue_history.get())
                        history.append(f"[{node_name}]: {last_msg.content}")
                        cv_dialogue_history.set(history)

                audit_event = AuditEvent(
                    event_type="message",
                    sender=node_name,
                    receiver=receiver_name,
                    tool_name=None,
                    content=content_info,
                    call_path=list(current_path),
                    trace_id=cv_trace_id.get(),
                    history_summary=get_history_summary(n=3)
                )
                
                decision = evaluate_audit_event(audit_event, f"节点通信 ({node_name})")
                if not decision.allow:
                    raise SecurityBlockException(f"Agent 通信已被网关拦截: {decision.reason}")
                
        # 无论是否拦截记录，都将原始事件放行给业务代码
        yield event_data

# 注入基类
CompiledStateGraph.stream = universal_secure_stream


# ================= 提供通用封装装饰器供外部使用 =================
def secure_scenario_runner(func):
    """
    一个装饰器，用于包裹任意系统的主运行入口函数。
    自动注入 start_new_trace 并处理阻断异常。
    """
    @functools.wraps(func)
    def wrapper(prompt_text, *args, **kwargs):
        start_new_trace(prompt_text)
        try:
            return func(prompt_text, *args, **kwargs)
        except SecurityBlockException as e:
            print(f"\n❌ [安全阻断] 流程中止: {e}")
    return wrapper