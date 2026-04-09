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
from audit_layer.audit_models import AuditEvent, AuditDecision
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
cv_user_task = contextvars.ContextVar("user_task", default="")
cv_pending_events = contextvars.ContextVar("pending_events", default=[])
# 追踪最近一次 Router 的路由决策（从 state 中提取）
cv_last_router_decision = contextvars.ContextVar("last_router_decision", default=None)
# 追踪最后一个活跃的 Agent 节点（用于 tool_call 的 sender）
cv_last_agent_node = contextvars.ContextVar("last_agent_node", default=None)

def start_new_trace(prompt: str):
    """每次启动新流程前，初始化独立的追踪上下文"""
    cv_trace_id.set(str(uuid.uuid4()))
    cv_call_path.set(["User"])
    cv_dialogue_history.set([f"[User]: {prompt.strip()}"])
    # 从 prompt 中提取核心任务作为 task 字段（取前80字符）
    cv_user_task.set(prompt.strip()[:80] if prompt else "")
    cv_pending_events.set([])
    cv_last_router_decision.set(None)
    cv_last_agent_node.set(None)

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

    # 先暂存到上下文，flush 时统一过滤再落盘
    pending = cv_pending_events.get()
    pending.append(event_dict)

    decision = AuditDecision(
        allow=True,
        risk_score=0.1,
        reason="验证阶段：记录 Event 并放行",
        blocking_risk_types=[]
    )
    return decision

def flush_filtered_events():
    """对当前 trace 的事件应用过滤，然后写入 AUDIT_LOG_FILE"""
    pending = cv_pending_events.get()
    if not pending:
        return

    # 将 dict 转回 AuditEvent 以便过滤
    events = []
    for d in pending:
        clean = {
            "event_type": d.get("event_type", "message"),
            "sender": d.get("sender", "Unknown"),
            "receiver": d.get("receiver"),
            "tool_name": d.get("tool_name"),
            "tool_args": d.get("tool_args"),
            "call_path": d.get("call_path", []),
            "content": d.get("content"),
            "history_summary": d.get("history_summary", ""),
            "task": d.get("task", ""),
            "event_id": d.get("event_id", str(uuid.uuid4())),
            "trace_id": d.get("trace_id", cv_trace_id.get() or ""),
            "timestamp": d.get("timestamp", ""),
            "metadata": d.get("metadata", {}),
        }
        try:
            events.append(AuditEvent(**clean))
        except Exception as e:
            print(f"  ⚠️ 跳过无法解析的事件: {e}")
            continue

    # 第一步：粗过滤 - 丢弃明确是内部 LangChain 函数的事件
    INTERNAL_SENDERS = INTERNAL_NODES | {"ChatPromptTemplate", "ChatModel", "JsonOutputParser",
                                           "StrOutputParser", "RunnableSequence", "RunnableParallel",
                                           "RunnableAssign", "_llm", "llm", "parser", "chain"}
    coarse_events = [
        ev for ev in events
        if ev.sender not in INTERNAL_SENDERS
        or ev.event_type in ("tool_call", "tool_result")
    ]

    # 第二步：后处理 - 修复 tool_result 的 sender 应该是 Tool_Node
    for ev in coarse_events:
        if ev.event_type == "tool_result" and ev.tool_name:
            ev.sender = "Tool_Node"

    # 第三步：应用路径过滤
    filtered = filter_audit_events(coarse_events)

    # 转回 dict 写入
    filtered_dicts = [asdict(ev) for ev in filtered]
    with open(AUDIT_LOG_FILE, 'w', encoding='utf-8') as f:
        json.dump(filtered_dicts, f, indent=2, ensure_ascii=False)

    print(f"\n📋 [通用网关] 原始事件 {len(pending)} 条，粗过滤后 {len(coarse_events)} 条，最终 {len(filtered)} 条")

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

# ================= 事件流过滤（通用） =================
# 用于确定哪些 Agent 是"必要的"——在 sender/receiver 链或 call_path 中出现过的
NECESSARY_AGENTS: set[str] = {
    "User", "Router", "FINISH", "Tool_Node",
    "Research_Agent", "Asset_Agent", "Trade_Agent", "Risk_Agent",
    "AiTM_Interceptor",
}

# 内部/基础设施节点（LangChain 内部组件），应在 call_path 和事件中排除
INTERNAL_NODES: set[str] = {
    "ChatPromptTemplate", "JsonOutputParser", "StrOutputParser",
    "RunnableSequence", "RunnableAssign", "RunnableParallel",
    "should_continue", "should_continue_check", "cond_func",
    "ChatModel", "_llm", "llm", "parser", "chain",
    "LangGraph", "Pregel", "Start", "End", "__start__", "__end__",
    "Root", "RootNode", "IntegratedTimers", "TimerLogger",
    "Agent", "BasicRunner", "Task", "TaskResult",
}

def _collect_agents_from_events(events: list[AuditEvent]) -> set[str]:
    """从事件集合中收集所有出现过的 agent 名称"""
    agents: set[str] = set()
    for ev in events:
        if ev.sender:
            agents.add(ev.sender)
        if ev.receiver:
            agents.add(ev.receiver)
        for node in ev.call_path:
            agents.add(node)
    return agents

def _build_receiver_graph(events: list[AuditEvent]) -> dict[str, list[str]]:
    """
    从事件中构建 sender -> [receivers] 的有向图（一个 sender 可对应多个 receiver）。
    返回 dict: sender -> [receiver1, receiver2, ...]
    """
    graph: dict[str, list[str]] = {}
    for ev in events:
        if ev.sender and ev.receiver:
            if ev.sender not in graph:
                graph[ev.sender] = []
            if ev.receiver not in graph[ev.sender]:
                graph[ev.sender].append(ev.receiver)
    return graph

def _is_path_connected(agents_in_use: set[str], receiver_graph: dict[str, list[str]]) -> bool:
    """
    检查是否存在一条从 User 到 FINISH 的完整路径。
    如果路径断裂，说明有事件是孤立的需要被过滤。
    """
    if "User" not in agents_in_use or "FINISH" not in agents_in_use:
        return False

    # BFS/DFS 从 User 走到 FINISH
    visited: set[str] = set()
    queue = ["User"]
    while queue:
        node = queue.pop(0)
        if node == "FINISH":
            return True
        if node in visited:
            continue
        visited.add(node)
        if node in receiver_graph:
            for next_node in receiver_graph[node]:
                if next_node in agents_in_use and next_node not in visited:
                    queue.append(next_node)
    return False

def filter_audit_events(events: list[AuditEvent]) -> list[AuditEvent]:
    """
    对事件流进行过滤，确保：
    1. 清理 call_path 中的内部节点（ChatPromptTemplate, should_continue 等）
    2. 去重：同一 (sender, receiver) 的 state_transition 只保留第一个
    3. 只保留必要的 agent（在 NECESSARY_AGENTS 中的，或在业务事件中出现的）
    4. sender -> receiver 能连成完整路径（User 到 FINISH）

    这是通用过滤，不绑定特定场景。
    """
    if not events:
        return events

    # 第一步：深度复制事件并清理 call_path
    cleaned_events: list[AuditEvent] = []
    for ev in events:
        ev_copy = AuditEvent(
            event_type=ev.event_type,
            sender=ev.sender,
            receiver=ev.receiver,
            tool_name=ev.tool_name,
            tool_args=ev.tool_args,
            call_path=[n for n in ev.call_path if n not in INTERNAL_NODES],
            content=ev.content,
            history_summary=ev.history_summary,
            task=ev.task,
            event_id=ev.event_id,
            trace_id=ev.trace_id,
            timestamp=ev.timestamp,
            metadata=dict(ev.metadata),
        )
        cleaned_events.append(ev_copy)

    # 第二步：不做去重（底层回调每次都会生成事件，这是预期行为）
    deduped = cleaned_events

    # 第三步：收集所有出现过的 agent（已清理 call_path）
    all_agents = _collect_agents_from_events(deduped)
    for ev in deduped:
        if ev.sender:
            all_agents.add(ev.sender)
        if ev.receiver:
            all_agents.add(ev.receiver)

    # 第四步：构建 receiver_graph 并做 BFS 检查连通性
    receiver_graph = _build_receiver_graph(deduped)

    agents_on_path: set[str] = set()
    visited: set[str] = set()
    queue = ["User"]
    while queue:
        node = queue.pop(0)
        if node in visited:
            continue
        visited.add(node)
        agents_on_path.add(node)
        if node in receiver_graph:
            for nxt in receiver_graph[node]:
                if nxt not in visited:
                    queue.append(nxt)

    # 如果路径不完整，退回到只过滤内部节点
    if "FINISH" not in agents_on_path:
        print(f"  ⚠️ 路径不完整，仅做内部节点清理")
        return deduped

    # 第五步：过滤，只保留与连通路径相关的事件
    filtered: list[AuditEvent] = []
    for ev in deduped:
        keep = False
        if ev.sender in agents_on_path:
            keep = True
        elif ev.receiver and ev.receiver in agents_on_path:
            keep = True
        elif any(n in agents_on_path for n in ev.call_path):
            keep = True

        if keep:
            ev.call_path = [n for n in ev.call_path if n in agents_on_path]
            filtered.append(ev)

    return filtered

# ================= 统一的动作审计中心 =================
# 工具调用上下文：tool_call_id -> (caller_agent, tool_name, tool_args)
cv_tool_call_context = contextvars.ContextVar("tool_call_context", default={})

def _audit_action(event_type: str, name: str, payload: Any, receiver: str = None):
    """
    统一构建和触发审计逻辑的核心函数。
    - event_type: message | tool_call | tool_result | state_transition
    - name: 节点/工具名称
    - payload: 内容或参数
    - receiver: 显式指定接收方（用于 state_transition）
    """
    current_path = cv_call_path.get()
    sender = current_path[-1] if current_path else "System"

    # 消息类型事件
    if event_type == "message" and isinstance(payload, str) and payload.strip():
        history = cv_dialogue_history.get()
        safe_payload = payload if len(payload) <= 1000 else payload[:1000] + "..."
        history.append(f"[{sender} -> LLM]: {safe_payload}")
        while len(history) > 6:
            history.pop(0)

    # state_transition 类型：检查是否是 Router 的状态转移
    if event_type == "state_transition":
        # 尝试从 payload 中提取 next 字段（Router 的路由决策）
        routing_target = None
        if isinstance(payload, dict):
            routing_target = payload.get("next") or cv_last_router_decision.get()
            # 同时检查 intent_confidence 和 reason
            conf = payload.get("intent_confidence")
            reason = payload.get("reason", "")
            if routing_target:
                cv_last_router_decision.set(routing_target)
        else:
            routing_target = cv_last_router_decision.get()

        if routing_target and routing_target != "FINISH":
            # 更新 call_path，追加路由目标
            if not current_path or current_path[-1] != routing_target:
                current_path = current_path + [routing_target]
            receiver = routing_target
        elif routing_target == "FINISH":
            receiver = "FINISH"
        else:
            receiver = receiver or "LLM"

    event = AuditEvent(
        event_type=event_type,
        sender=sender,
        receiver=receiver if receiver else (name if event_type in ("tool_call", "tool_result") else "LLM"),
        tool_name=name if event_type in ("tool_call", "tool_result") else None,
        # 结果或消息放 content，工具参数放 tool_args
        content=str(payload)[:2000] if event_type != "tool_call" else None,
        tool_args=payload if event_type == "tool_call" else None,
        call_path=list(current_path),
        trace_id=cv_trace_id.get() or str(uuid.uuid4()),
        history_summary=get_history_summary(n=3),
        task=cv_user_task.get() or ""
    )

    decision = evaluate_audit_event(event, f"{event_type.upper()} - {name}")
    if not decision.allow:
        raise SecurityBlockException(f"[{event_type}] {name} 已被网关拦截: {decision.reason}")
    
# ================= 全局系统级 Callback Handlers =================
class SyncSecurityCallback(BaseCallbackHandler):
    """处理同步执行的回调"""
    raise_error: bool = True 

    def on_tool_start(self, serialized: Optional[Dict[str, Any]], input_str: str, **kwargs: Any) -> Any:
        serialized = serialized or {}
        tool_name = serialized.get("name") or kwargs.get("name") or "UnknownTool"
        payload = sanitize_payload(kwargs.get("inputs", input_str))
        # sender 应该是调用工具的 Agent，而不是 Tool_Node
        agent_sender = cv_last_agent_node.get()
        if not agent_sender:
            # 尝试从 kwargs config 中获取 active_agent
            config = kwargs.get("config") or {}
            configurable = config.get("configurable", {}) if isinstance(config, dict) else {}
            agent_sender = configurable.get("active_agent")

        if agent_sender and agent_sender not in ("Tool_Node", "LLM"):
            # 修正 call_path：移除 Tool_Node，用 Agent 作为最后节点
            current_path = cv_call_path.get()
            if current_path and current_path[-1] == "Tool_Node" and len(current_path) >= 2:
                corrected_path = current_path[:-1]
                cv_call_path.set(corrected_path)
            # 用 Agent 作为 sender
            _audit_action("tool_call", tool_name, payload, receiver=None)
        else:
            _audit_action("tool_call", tool_name, payload)

    # [新增] 处理工具执行结果
    def on_tool_end(self, output: str, **kwargs: Any) -> Any:
        tool_name = kwargs.get("name") or "UnknownTool"
        # sender 是 Tool_Node，receiver 是调用工具的 Agent
        agent_receiver = cv_last_agent_node.get()
        if not agent_receiver:
            config = kwargs.get("config") or {}
            configurable = config.get("configurable", {}) if isinstance(config, dict) else {}
            agent_receiver = configurable.get("active_agent")
        _audit_action("tool_result", tool_name, sanitize_payload(output),
                     receiver=agent_receiver if agent_receiver and agent_receiver not in ("Tool_Node", "LLM") else None)

    def on_chain_start(self, serialized: Optional[Dict[str, Any]], inputs: Dict[str, Any], **kwargs: Any) -> Any:
        serialized = serialized or {}
        name = serialized.get("name") or kwargs.get("name") or "UnknownNode"

        if name in ("LangGraph", "Pregel") or name.startswith("__") or name.startswith("Runnable"):
            return

        # 跳过 LangGraph 内部条件函数（如 should_continue）
        if name.startswith("should_") or name.startswith("cond_"):
            return

        current_path = cv_call_path.get()

        # Router 节点：特殊处理，只在决策改变时生成 state_transition
        # prev=None 时不生成（第一次执行，next 还未被 LLM 计算出）
        if name == "Router":
            routing_target = None
            if isinstance(inputs, dict):
                routing_target = inputs.get("next")

            prev = cv_last_router_decision.get()
            if routing_target and routing_target != prev:
                # 路由决策改变，生成新的 state_transition
                cv_last_router_decision.set(routing_target)
                if routing_target != "FINISH":
                    new_path = current_path + [routing_target]
                else:
                    new_path = current_path + ["FINISH"]
                cv_call_path.set(new_path)
                _audit_action("state_transition", name, sanitize_payload(inputs),
                             receiver=routing_target if routing_target != "FINISH" else "FINISH")
            elif routing_target and prev is not None and routing_target == prev:
                # 决策未变，仅更新 path 中 Router 的位置
                if current_path and current_path[-1] == "Router":
                    pass
                elif not current_path or current_path[-1] != "Router":
                    current_path = current_path + ["Router"]
                    cv_call_path.set(current_path)
            # prev=None 且 routing_target=None/空：Router 初始执行，不更新 path，不生成事件
            return

        # Agent 节点（不包括 Router 本身）
        REAL_AGENT_NODES = {"Research_Agent", "Asset_Agent", "Trade_Agent", "Risk_Agent",
                            "AiTM_Interceptor"}
        if name in REAL_AGENT_NODES:
            # 记录最后一个活跃 Agent（用于 tool_call 的 sender）
            cv_last_agent_node.set(name)
            routing_target = None
            if isinstance(inputs, dict):
                routing_target = inputs.get("next")
            if routing_target and routing_target != current_path[-1]:
                if routing_target != "FINISH":
                    current_path = current_path + [routing_target]
                else:
                    current_path = current_path + ["FINISH"]
                cv_call_path.set(current_path)
                _audit_action("state_transition", name, sanitize_payload(inputs),
                             receiver=routing_target if routing_target != "FINISH" else "FINISH")
                return

        if not current_path or current_path[-1] != name:
            current_path.append(name)

        # 节点状态转移映射为 state_transition
        _audit_action("state_transition", name, sanitize_payload(inputs))

    def on_chat_model_start(self, serialized: Optional[Dict[str, Any]], messages: List[List[Any]], **kwargs: Any) -> Any:
        last_msg = messages[0][-1] if messages and messages[0] else None
        content = getattr(last_msg, "content", str(last_msg)) if last_msg else ""
        # 语言模型请求映射为消息传递 message
        _audit_action("message", "ChatModel", content)

    def on_chat_model_end(self, response: Any, **kwargs: Any) -> Any:
        if response.generations and response.generations[0]:
            text = response.generations[0][0].text
            if text:
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
        agent_sender = cv_last_agent_node.get()
        if not agent_sender:
            config = kwargs.get("config") or {}
            configurable = config.get("configurable", {}) if isinstance(config, dict) else {}
            agent_sender = configurable.get("active_agent")
        if agent_sender and agent_sender not in ("Tool_Node", "LLM"):
            current_path = cv_call_path.get()
            if current_path and current_path[-1] == "Tool_Node" and len(current_path) >= 2:
                corrected_path = current_path[:-1]
                cv_call_path.set(corrected_path)
            _audit_action("tool_call", tool_name, payload, receiver=None)
        else:
            _audit_action("tool_call", tool_name, payload)

    # [新增] 处理异步工具执行结果
    async def on_tool_end(self, output: str, **kwargs: Any) -> Any:
        tool_name = kwargs.get("name") or "UnknownTool"
        agent_receiver = cv_last_agent_node.get()
        if not agent_receiver:
            config = kwargs.get("config") or {}
            configurable = config.get("configurable", {}) if isinstance(config, dict) else {}
            agent_receiver = configurable.get("active_agent")
        _audit_action("tool_result", tool_name, sanitize_payload(output),
                     receiver=agent_receiver if agent_receiver and agent_receiver not in ("Tool_Node", "LLM") else None)

    async def on_chain_start(self, serialized: Optional[Dict[str, Any]], inputs: Dict[str, Any], **kwargs: Any) -> Any:
        serialized = serialized or {}
        name = serialized.get("name") or kwargs.get("name") or "UnknownNode"

        if name in ("LangGraph", "Pregel") or name.startswith("__") or name.startswith("Runnable"):
            return

        # 跳过 LangGraph 内部条件函数（如 should_continue）
        if name.startswith("should_") or name.startswith("cond_"):
            return

        current_path = cv_call_path.get()

        # Router 节点：特殊处理，只在决策改变时生成 state_transition
        # prev=None 时不生成（第一次执行，next 还未被 LLM 计算出）
        if name == "Router":
            routing_target = None
            if isinstance(inputs, dict):
                routing_target = inputs.get("next")

            prev = cv_last_router_decision.get()
            if routing_target and routing_target != prev:
                cv_last_router_decision.set(routing_target)
                if routing_target != "FINISH":
                    new_path = current_path + [routing_target]
                else:
                    new_path = current_path + ["FINISH"]
                cv_call_path.set(new_path)
                _audit_action("state_transition", name, sanitize_payload(inputs),
                             receiver=routing_target if routing_target != "FINISH" else "FINISH")
            elif routing_target and prev is not None and routing_target == prev:
                if current_path and current_path[-1] == "Router":
                    pass
                elif not current_path or current_path[-1] != "Router":
                    current_path = current_path + ["Router"]
                    cv_call_path.set(current_path)
            return

        # Agent 节点（不包括 Router 本身）
        REAL_AGENT_NODES = {"Research_Agent", "Asset_Agent", "Trade_Agent", "Risk_Agent",
                            "AiTM_Interceptor"}
        if name in REAL_AGENT_NODES:
            cv_last_agent_node.set(name)
            routing_target = None
            if isinstance(inputs, dict):
                routing_target = inputs.get("next")
            if routing_target and routing_target != current_path[-1]:
                if routing_target != "FINISH":
                    current_path = current_path + [routing_target]
                else:
                    current_path = current_path + ["FINISH"]
                cv_call_path.set(current_path)
                _audit_action("state_transition", name, sanitize_payload(inputs),
                             receiver=routing_target if routing_target != "FINISH" else "FINISH")
                return

        if not current_path or current_path[-1] != name:
            current_path.append(name)

        _audit_action("state_transition", name, sanitize_payload(inputs))

    async def on_chat_model_start(self, serialized: Optional[Dict[str, Any]], messages: List[List[Any]], **kwargs: Any) -> Any:
        last_msg = messages[0][-1] if messages and messages[0] else None
        content = getattr(last_msg, "content", str(last_msg)) if last_msg else ""
        _audit_action("message", "ChatModel", content)

    async def on_chat_model_end(self, response: Any, **kwargs: Any) -> Any:
        if response.generations and response.generations[0]:
            text = response.generations[0][0].text
            if text:
                history = cv_dialogue_history.get()
                safe_text = text if len(text) <= 1000 else text[:1000] + "..."
                history.append(f"[LLM -> Agent]: {safe_text}")
                while len(history) > 6:
                    history.pop(0)
                    
# ================= 核心：Config 级联注入器 =================
def _inject_security_callback(config: Optional[Any], is_async: bool) -> Any:
    """透明地将网关 Callback 塞进 LangChain 运行时配置中"""
    # 批量执行场景
    if isinstance(config, list):
        return [_inject_security_callback(c, is_async) for c in config]
        
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
            handlers = list(raw_callbacks)
        elif hasattr(raw_callbacks, "handlers"): 
            # 如果是 LangChain 的 CallbackManager，提取出它内部的 handlers 列表
            handlers = list(raw_callbacks.handlers)
        else: 
            # 如果是单个普通的 BaseCallbackHandler
            handlers = [raw_callbacks]
            
        # 防止网关 Callback 被重复注入
        if not any(isinstance(c, (SyncSecurityCallback, AsyncSecurityCallback)) for c in handlers):
            handlers.append(handler)
            
        new_config["callbacks"] = handlers
        return new_config
        
    return config

# ================= 底层入口猴子补丁 (Monkey Patching) =================
# 1. 代理 CompiledStateGraph 的所有入口
original_cg_invoke = CompiledStateGraph.invoke
original_cg_ainvoke = CompiledStateGraph.ainvoke
original_cg_stream = CompiledStateGraph.stream
original_cg_astream = CompiledStateGraph.astream

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

# (可选扩展) 覆盖 astream_events 事件流
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
            finally:
                flush_filtered_events()
        return async_wrapper
    else:
        @functools.wraps(func)
        def sync_wrapper(prompt_text, *args, **kwargs):
            start_new_trace(prompt_text)
            try:
                return func(prompt_text, *args, **kwargs)
            except SecurityBlockException as e:
                print(f"\n❌[安全阻断] 流程中止: {e}")
            finally:
                flush_filtered_events()
        return sync_wrapper