"""
audited_graph.py — 带审计的 LangGraph 图执行包装器
"""
from __future__ import annotations
import os, sys
from typing import Any, Dict, Iterator, Optional

from langchain_core.callbacks import BaseCallbackHandler
from langchain_core.runnables import RunnableConfig
from langchain_core.messages import AIMessage, ToolMessage, HumanMessage
from langgraph.graph.state import CompiledStateGraph

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from langgraph_adapter import LangGraphAuditAdapter, WorkflowBlocked

_LG_INTERNAL: frozenset = frozenset({
    "LangGraph", "RunnableSequence", "RunnableLambda",
    "ChannelWrite", "ChannelRead", "ChannelWriteEntry",
    "__start__", "__end__", "start", "end",
})


class _PathTrackingCallback(BaseCallbackHandler):
    def __init__(self, adapter: LangGraphAuditAdapter, known_nodes: frozenset) -> None:
        super().__init__()
        self._adapter = adapter
        self._known_nodes = known_nodes
        self._prev_node: Optional[str] = None

    def on_chain_start(self, serialized: Dict[str, Any], inputs: Dict[str, Any], **kwargs: Any) -> None:
        name: str = (serialized or {}).get("name", "")
        if not name or name not in self._known_nodes:
            return
        # Emit transition BEFORE updating call_path (invoke processes output after callback fires)
        if self._prev_node and self._prev_node != name:
            try:
                self._adapter.emit_node_transition(self._prev_node, name)
            except WorkflowBlocked:
                raise
        self._adapter.update_call_path(name)
        self._prev_node = name

    def on_chain_end(self, outputs: Dict[str, Any], **kwargs: Any) -> None:
        pass

    def on_chain_error(self, error: Exception, **kwargs: Any) -> None:
        pass


class AuditedGraph:
    def __init__(self, graph: CompiledStateGraph, audit_adapter: LangGraphAuditAdapter) -> None:
        self._graph = graph
        self._adapter = audit_adapter
        self._node_names: frozenset = frozenset(
            k for k in graph.nodes.keys() if k not in _LG_INTERNAL
        )
        self._emitted_msg_ids: set = set()

    def set_scene_info(self, scene_name: str, trace_id: str) -> None:
        self._emitted_msg_ids.clear()
        self._adapter.set_scene_info(scene_name, trace_id)

    def invoke(self, input: Dict[str, Any], config: Optional[RunnableConfig] = None, **kwargs: Any) -> Dict[str, Any]:
        self._maybe_set_user_task(input)
        callback = _PathTrackingCallback(self._adapter, self._node_names)
        merged = self._merge_config(config, callback)

        final_state = {}
        for chunk in self._graph.stream(input, merged, **kwargs):
            for node_name, node_output in chunk.items():
                if node_name in _LG_INTERNAL:
                    continue

                # Extract messages from node output and emit as message events
                if isinstance(node_output, dict) and "messages" in node_output:
                    for msg in node_output["messages"]:
                        self._emit_message_event(msg, node_name)

                if isinstance(node_output, dict):
                    final_state.update(node_output)
        return final_state

    def _emit_message_event(self, msg: Any, node_name: str) -> None:
        """Extract and emit message events from node output (skip duplicates and tool results)."""
        msg_id = id(msg)
        if msg_id in self._emitted_msg_ids:
            return
        self._emitted_msg_ids.add(msg_id)

        content = getattr(msg, "content", "")
        if not content:
            return
        # Tool results are handled by audit_tool decorator, skip to avoid duplication
        if isinstance(msg, ToolMessage):
            return
        sender = node_name
        if hasattr(msg, "name") and msg.name:
            sender = msg.name
        elif isinstance(msg, HumanMessage):
            sender = "User"
        try:
            self._adapter.emit_message(
                sender=sender,
                receiver="",
                content=content,
            )
        except WorkflowBlocked:
            pass

    def stream(self, input: Dict[str, Any], config: Optional[RunnableConfig] = None, **kwargs: Any) -> Iterator:
        self._maybe_set_user_task(input)
        callback = _PathTrackingCallback(self._adapter, self._node_names)
        merged = self._merge_config(config, callback)
        return self._graph.stream(input, merged, **kwargs)

    def _maybe_set_user_task(self, input: Dict[str, Any]) -> None:
        if self._adapter._user_task:
            return
        messages = input.get("messages", [])
        if not messages:
            return
        first = messages[0]
        if hasattr(first, "content"):
            content = first.content
        elif isinstance(first, dict):
            content = first.get("content", "")
        else:
            return
        if content:
            self._adapter.set_user_task(str(content), sender="User")
            # Emit the user's original message as a message event
            try:
                self._adapter.emit_message(sender="User", receiver="Router", content=str(content))
            except WorkflowBlocked:
                pass

    def _merge_config(self, config: Optional[RunnableConfig], callback: _PathTrackingCallback) -> RunnableConfig:
        base: Dict[str, Any] = dict(config or {})
        existing = base.get("callbacks") or []
        base["callbacks"] = list(existing) + [callback]
        return base
