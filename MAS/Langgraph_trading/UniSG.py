"""
通用多智能体安全网关 (Universal Security Gateway) - 全覆盖强化版
支持任意基于 LangGraph 和 LangChain 架构的 MAS 系统。
采用基类入口重定向 + 全局 Callback 注入机制，实现真正的 100% 盲区覆盖。
"""

import json
import os
import uuid
import functools
import contextvars
import inspect
from dataclasses import asdict
from typing import Optional, Dict, Any, List

# ================= 导入基类与审计模型 =================
from audit_models import AuditEvent, AuditDecision
from langchain_core.tools import BaseTool
from langgraph.graph.state import CompiledStateGraph
from langchain_core.callbacks import BaseCallbackHandler, AsyncCallbackHandler

class SecurityBlockException(Exception):
    """当安全网关拒绝操作时抛出的阻断异常"""
    pass

AUDIT_LOG_FILE = "universal_audit_events.json"

if os.path.exists(AUDIT_LOG_FILE):
    os.remove(AUDIT_LOG_FILE)
with open(AUDIT_LOG_FILE, 'w', encoding='utf-8') as f:
    json.dump([], f)

# ================= 并发安全的上下文追踪 (ContextVars) =================
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
    print(f"\n🛡️[ 通用网关 | {prefix}] -> 捕获事件:\n{json.dumps(event_dict, indent=2, ensure_ascii=False)}")
    
    try:
        with open(AUDIT_LOG_FILE, 'r', encoding='utf-8') as f:
            events = json.load(f)
    except (json.JSONDecodeError, FileNotFoundError):
        events =[]
        
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

# ================= 统一的动作审计中心 =================
def _audit_action(event_type: str, name: str, payload: Any):
    """统一构建和触发审计逻辑的核心函数"""
    # 【改动 1】：原地获取列表引用，不加 list()
    current_path = cv_call_path.get()
    sender = current_path[-1] if current_path else "System"

    if event_type == "llm_request" and isinstance(payload, str) and payload.strip():
        # 【改动 2】：原地获取历史列表引用，直接 append 并通过 pop 维持长度，不调用 set()
        history = cv_dialogue_history.get()
        safe_payload = payload if len(payload) <= 1000 else payload[:1000] + "..."
        history.append(f"[{sender} -> LLM]: {safe_payload}")
        while len(history) > 6:
            history.pop(0)

    event = AuditEvent(
        event_type=event_type,
        sender=sender,
        receiver=name if event_type != "llm_request" else "LLM",
        tool_name=name if event_type == "tool_call" else None,
        content=str(payload)[:2000] if event_type != "tool_call" else None,
        tool_args=payload if event_type == "tool_call" else None,
        call_path=list(current_path), # 这里用 list() 拷贝一份存盘，防止后续被修改
        trace_id=cv_trace_id.get() or str(uuid.uuid4()),
        history_summary=get_history_summary(n=3)
    )

    decision = evaluate_audit_event(event, f"{event_type.upper()} - {name}")
    if not decision.allow:
        raise SecurityBlockException(f"[{event_type}] {name} 已被网关拦截: {decision.reason}")

# ================= 全局系统级 Callback Handlers =================
class SyncSecurityCallback(BaseCallbackHandler):
    """处理同步执行的回调"""
    raise_error: bool = True 

    #监听工具调用
    def on_tool_start(self, serialized: Optional[Dict[str, Any]], input_str: str, **kwargs: Any) -> Any:
        serialized = serialized or {}
        tool_name = serialized.get("name") or kwargs.get("name") or "UnknownTool"
        payload = sanitize_payload(kwargs.get("inputs", input_str))
        _audit_action("tool_call", tool_name, payload)

    #监听节点流转
    def on_chain_start(self, serialized: Optional[Dict[str, Any]], inputs: Dict[str, Any], **kwargs: Any) -> Any:
        serialized = serialized or {}
        name = serialized.get("name") or kwargs.get("name") or "UnknownNode"
        
        if name in ("LangGraph", "Pregel") or name.startswith("__") or name.startswith("Runnable"):
            return
            
        # 【改动 3】：原地修改路径，不调用 set()
        current_path = cv_call_path.get()
        if not current_path or current_path[-1] != name:
            current_path.append(name)

        _audit_action("node_state", name, sanitize_payload(inputs))

    #监听大模型输入
    def on_chat_model_start(self, serialized: Optional[Dict[str, Any]], messages: List[List[Any]], **kwargs: Any) -> Any:
        last_msg = messages[0][-1] if messages and messages[0] else None
        content = getattr(last_msg, "content", str(last_msg)) if last_msg else ""
        _audit_action("llm_request", "ChatModel", content)

    #监听大模型输出
    def on_chat_model_end(self, response: Any, **kwargs: Any) -> Any:
        if response.generations and response.generations[0]:
            text = response.generations[0][0].text
            if text:
                # 【改动 4】：原地修改大模型输出历史，不调用 set()
                history = cv_dialogue_history.get()
                safe_text = text if len(text) <= 1000 else text[:1000] + "..."
                history.append(f"[LLM -> Agent]: {safe_text}")
                while len(history) > 6:
                    history.pop(0)


class AsyncSecurityCallback(AsyncCallbackHandler):
    """处理异步执行的回调 (与同步逻辑保持镜像一致)"""
    raise_error: bool = True

    async def on_tool_start(self, serialized: Optional[Dict[str, Any]], input_str: str, **kwargs: Any) -> Any:
        serialized = serialized or {}
        tool_name = serialized.get("name") or kwargs.get("name") or "UnknownTool"
        payload = sanitize_payload(kwargs.get("inputs", input_str))
        _audit_action("tool_call", tool_name, payload)

    async def on_chain_start(self, serialized: Optional[Dict[str, Any]], inputs: Dict[str, Any], **kwargs: Any) -> Any:
        serialized = serialized or {}
        name = serialized.get("name") or kwargs.get("name") or "UnknownNode"
        
        if name in ("LangGraph", "Pregel") or name.startswith("__") or name.startswith("Runnable"):
            return
            
        # 原地修改路径
        current_path = cv_call_path.get()
        if not current_path or current_path[-1] != name:
            current_path.append(name)

        _audit_action("node_state", name, sanitize_payload(inputs))

    async def on_chat_model_start(self, serialized: Optional[Dict[str, Any]], messages: List[List[Any]], **kwargs: Any) -> Any:
        last_msg = messages[0][-1] if messages and messages[0] else None
        content = getattr(last_msg, "content", str(last_msg)) if last_msg else ""
        _audit_action("llm_request", "ChatModel", content)

    async def on_chat_model_end(self, response: Any, **kwargs: Any) -> Any:
        if response.generations and response.generations[0]:
            text = response.generations[0][0].text
            if text:
                # 原地修改历史
                history = cv_dialogue_history.get()
                safe_text = text if len(text) <= 1000 else text[:1000] + "..."
                history.append(f"[LLM -> Agent]: {safe_text}")
                while len(history) > 6:
                    history.pop(0)

# ================= 核心：Config 级联注入器 =================
def _inject_security_callback(config: Optional[Any], is_async: bool) -> Any:
    """透明地将网关 Callback 塞进 LangChain 运行时配置中"""
    
    # 如果使用batch或abatch同时处理多个请求，config可能是一个列表，我们需要对每个元素都进行注入
    if isinstance(config, list):
        return [_inject_security_callback(c, is_async) for c in config]
        
    #窃听器
    handler = AsyncSecurityCallback() if is_async else SyncSecurityCallback()
    
    if config is None:
        return {"callbacks": [handler]}
        
    if isinstance(config, dict):
        new_config = config.copy()
        raw_callbacks = new_config.get("callbacks")
        
        # 安全展平 Callback 列表，防止把 CallbackManager 当作 Handler 处理
        handlers =[]
        if raw_callbacks is None:
            handlers =[]
        elif isinstance(raw_callbacks, list):
            #如果是列表
            handlers = list(raw_callbacks)
        elif hasattr(raw_callbacks, "handlers"): 
            # 如果是 LangChain 的 CallbackManager，提取出它内部的 handlers 列表
            handlers = list(raw_callbacks.handlers)
        else: 
            # 如果是单个普通的 BaseCallbackHandler
            handlers = [raw_callbacks]
            
        # 防止Agent调用subAgent注入函数触发两次（复读）
        if not any(isinstance(c, (SyncSecurityCallback, AsyncSecurityCallback)) for c in handlers):
            handlers.append(handler)
            
        new_config["callbacks"] = handlers
        return new_config
        
    return config

# ================= 底层入口猴子补丁 (Monkey Patching) =================
# 1. 代理 CompiledStateGraph 的所有入口
original_cg_invoke = CompiledStateGraph.invoke #同步单次调用
original_cg_ainvoke = CompiledStateGraph.ainvoke #异步单次调用
original_cg_stream = CompiledStateGraph.stream #同步流式输出
original_cg_astream = CompiledStateGraph.astream #异步流式输出

def secure_cg_invoke(self, input: Any, config: Optional[Any] = None, **kwargs: Any) -> Any:
    return original_cg_invoke(self, input, _inject_security_callback(config, False), **kwargs)

async def secure_cg_ainvoke(self, input: Any, config: Optional[Any] = None, **kwargs: Any) -> Any:
    return await original_cg_ainvoke(self, input, _inject_security_callback(config, True), **kwargs)

def secure_cg_stream(self, input: Any, config: Optional[Any] = None, **kwargs: Any) -> Any:
    for item in original_cg_stream(self, input, _inject_security_callback(config, False), **kwargs):
        yield item

async def secure_cg_astream(self, input: Any, config: Optional[Any] = None, **kwargs: Any) -> Any:
    async for item in original_cg_astream(self, input, _inject_security_callback(config, True), **kwargs):
        yield item

CompiledStateGraph.invoke = secure_cg_invoke
CompiledStateGraph.ainvoke = secure_cg_ainvoke
CompiledStateGraph.stream = secure_cg_stream
CompiledStateGraph.astream = secure_cg_astream

# (可选扩展) 覆盖 细粒度事件流 
if hasattr(CompiledStateGraph, "astream_events"):
    original_cg_astream_events = CompiledStateGraph.astream_events
    async def secure_cg_astream_events(self, input: Any, config: Optional[Any] = None, **kwargs: Any) -> Any:
        async for item in original_cg_astream_events(self, input, _inject_security_callback(config, True), **kwargs):
            yield item
    CompiledStateGraph.astream_events = secure_cg_astream_events

# 2. 代理 BaseTool 直接调用的游离入口
original_tool_invoke = BaseTool.invoke
original_tool_ainvoke = BaseTool.ainvoke

def secure_tool_invoke(self, input: Any, config: Optional[Any] = None, **kwargs: Any) -> Any:
    return original_tool_invoke(self, input, _inject_security_callback(config, False), **kwargs)

async def secure_tool_ainvoke(self, input: Any, config: Optional[Any] = None, **kwargs: Any) -> Any:
    return await original_tool_ainvoke(self, input, _inject_security_callback(config, True), **kwargs)

BaseTool.invoke = secure_tool_invoke
BaseTool.ainvoke = secure_tool_ainvoke

# ================= 提供通用封装装饰器供外部使用 =================
def secure_scenario_runner(func):
    """
    一个装饰器，用于包裹任意系统的主运行入口函数。
    自动注入 start_new_trace 并处理阻断异常。
    兼容同步和异步的执行主函数。
    """
    # 使用 inspect 而不是 functools 来判断是否为异步函数
    if inspect.iscoroutinefunction(func):
        @functools.wraps(func)
        async def async_wrapper(prompt_text, *args, **kwargs):
            start_new_trace(prompt_text)
            try:
                return await func(prompt_text, *args, **kwargs)
            except SecurityBlockException as e:
                print(f"\n❌[安全阻断] 流程中止: {e}")
        return async_wrapper
    else:
        @functools.wraps(func)
        def sync_wrapper(prompt_text, *args, **kwargs):
            start_new_trace(prompt_text)
            try:
                return func(prompt_text, *args, **kwargs)
            except SecurityBlockException as e:
                print(f"\n❌[安全阻断] 流程中止: {e}")
        return sync_wrapper