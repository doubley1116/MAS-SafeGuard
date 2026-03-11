# crewai_adapter.py
from __future__ import annotations

from typing import Optional, Dict, Any, List

from audit_models import AuditEvent
from audit_sink import AuditSink


class CrewAIAuditAdapter:
    """
    只负责：
        Framework / CrewAI 内部行为 -> AuditEvent

    不负责：
        - 权限决策
        - 策略判断
        - 拦截执行
    """

    def __init__(self, sink: AuditSink, trace_id: str) -> None:
        self.sink = sink
        self.trace_id = trace_id

    def emit_task_delegation(
        self,
        sender: str,
        receiver: str,
        task_description: str,
        call_path: Optional[List[str]] = None,
        history_summary: str = "",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> AuditEvent:
        event = AuditEvent(
            event_type="task_delegation",
            sender=sender,
            receiver=receiver,
            tool_name=None,
            tool_args=None,
            call_path=call_path or [],
            content=task_description,
            history_summary=history_summary,
            trace_id=self.trace_id,
            metadata=metadata or {},
        )
        self.sink.emit(event)
        return event

    def emit_message(
        self,
        sender: str,
        receiver: str,
        content: str,
        call_path: Optional[List[str]] = None,
        history_summary: str = "",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> AuditEvent:
        event = AuditEvent(
            event_type="message",
            sender=sender,
            receiver=receiver,
            tool_name=None,
            tool_args=None,
            call_path=call_path or [],
            content=content,
            history_summary=history_summary,
            trace_id=self.trace_id,
            metadata=metadata or {},
        )
        self.sink.emit(event)
        return event

    def emit_tool_call(
        self,
        sender: str,
        tool_name: str,
        tool_args: Optional[Dict[str, Any]] = None,
        call_path: Optional[List[str]] = None,
        content: Optional[str] = None,
        history_summary: str = "",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> AuditEvent:
        event = AuditEvent(
            event_type="tool_call",
            sender=sender,
            receiver=None,
            tool_name=tool_name,
            tool_args=tool_args or {},
            call_path=call_path or [],
            content=content,
            history_summary=history_summary,
            trace_id=self.trace_id,
            metadata=metadata or {},
        )
        self.sink.emit(event)
        return event

    def emit_tool_result(
        self,
        sender: str,
        tool_name: str,
        result: Any,
        call_path: Optional[List[str]] = None,
        history_summary: str = "",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> AuditEvent:
        event = AuditEvent(
            event_type="tool_result",
            sender=sender,
            receiver=None,
            tool_name=tool_name,
            tool_args=None,
            call_path=call_path or [],
            content=str(result),
            history_summary=history_summary,
            trace_id=self.trace_id,
            metadata=metadata or {},
        )
        self.sink.emit(event)
        return event
