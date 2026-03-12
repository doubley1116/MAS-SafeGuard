# crewai_adapter.py
from __future__ import annotations

import json
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

    def _emit(
        self,
        event_type: str,
        sender: str,
        receiver: Optional[str],
        tool_name: Optional[str] = None,
        tool_args: Optional[Dict[str, Any]] = None,
        call_path: Optional[List[str]] = None,
        content: Optional[str] = None,
        history_summary: str = "",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> AuditEvent:
        event = AuditEvent(
            event_type=event_type,  # type: ignore[arg-type]
            sender=sender,
            receiver=receiver,
            tool_name=tool_name,
            tool_args=tool_args,
            call_path=call_path or [],
            content=content,
            history_summary=history_summary,
            trace_id=self.trace_id,
            metadata=metadata or {},
        )
        self.sink.emit(event)
        return event

    def emit_task_delegation(
        self,
        sender: str,
        receiver: str,
        task_description: str,
        call_path: Optional[List[str]] = None,
        history_summary: str = "",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> AuditEvent:
        return self._emit(
            event_type="task_delegation",
            sender=sender,
            receiver=receiver,
            tool_name=None,
            tool_args=None,
            call_path=call_path,
            content=task_description,
            history_summary=history_summary,
            metadata=metadata,
        )

    def emit_message(
        self,
        sender: str,
        receiver: str,
        content: str,
        call_path: Optional[List[str]] = None,
        history_summary: str = "",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> AuditEvent:
        return self._emit(
            event_type="message",
            sender=sender,
            receiver=receiver,
            tool_name=None,
            tool_args=None,
            call_path=call_path,
            content=content,
            history_summary=history_summary,
            metadata=metadata,
        )

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
        return self._emit(
            event_type="tool_call",
            sender=sender,
            receiver=None,
            tool_name=tool_name,
            tool_args=tool_args or {},
            call_path=call_path,
            content=content,
            history_summary=history_summary,
            metadata=metadata,
        )

    def emit_tool_result(
        self,
        sender: str,
        tool_name: str,
        result: Any,
        call_path: Optional[List[str]] = None,
        history_summary: str = "",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> AuditEvent:
        return self._emit(
            event_type="tool_result",
            sender=sender,
            receiver=None,
            tool_name=tool_name,
            tool_args=None,
            call_path=call_path,
            content=str(result),
            history_summary=history_summary,
            metadata=metadata,
        )

    def emit_state_transition(
        self,
        sender: str,
        receiver: Optional[str],
        content: str,
        call_path: Optional[List[str]] = None,
        history_summary: str = "",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> AuditEvent:
        return self._emit(
            event_type="state_transition",
            sender=sender,
            receiver=receiver,
            tool_name=None,
            tool_args=None,
            call_path=call_path,
            content=content,
            history_summary=history_summary,
            metadata=metadata,
        )

    # -----------------------------
    # CrewAI 常用语义化辅助方法
    # -----------------------------

    def emit_kickoff_input(
        self,
        inputs: Any,
        manager_name: str = "manager",
        call_path: Optional[List[str]] = None,
        history_summary: str = "",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> AuditEvent:
        """
        记录用户/上游输入进入 Crew 的入口事件。
        """
        return self.emit_message(
            sender="user",
            receiver=manager_name,
            content=str(inputs),
            call_path=call_path or ["user", manager_name],
            history_summary=history_summary,
            metadata={
                "framework": "crewai",
                "stage": "kickoff",
                **(metadata or {}),
            },
        )

    def emit_final_output(
        self,
        content: Any,
        manager_name: str = "manager",
        receiver: str = "final_output",
        call_path: Optional[List[str]] = None,
        history_summary: str = "",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> AuditEvent:
        """
        记录 Crew 最终输出事件。
        """
        return self.emit_message(
            sender=manager_name,
            receiver=receiver,
            content=str(content),
            call_path=call_path or ["user", manager_name, receiver],
            history_summary=history_summary,
            metadata={
                "framework": "crewai",
                "stage": "final_output",
                **(metadata or {}),
            },
        )

    # -----------------------------
    # StreamChunk -> AuditEvent
    # -----------------------------

    def from_stream_chunk(
        self,
        chunk: Any,
        receiver_for_text: str = "stream",
        history_summary: str = "",
        base_call_path: Optional[List[str]] = None,
    ) -> AuditEvent:
        """
        将 CrewAI 的 StreamChunk 映射为 AuditEvent。

        约定：
        - TEXT chunk -> message
        - TOOL_CALL chunk -> tool_call
        """
        agent_role = getattr(chunk, "agent_role", "") or "unknown_agent"
        chunk_type_obj = getattr(chunk, "chunk_type", None)
        chunk_type = getattr(chunk_type_obj, "value", None) or str(chunk_type_obj)

        task_index = getattr(chunk, "task_index", 0)
        task_name = getattr(chunk, "task_name", "")
        task_id = getattr(chunk, "task_id", "")
        agent_id = getattr(chunk, "agent_id", "")

        metadata = {
            "framework": "crewai",
            "source": "stream_chunk",
            "task_index": task_index,
            "task_name": task_name,
            "task_id": task_id,
            "agent_id": agent_id,
        }

        if chunk_type == "tool_call" and getattr(chunk, "tool_call", None):
            tc = chunk.tool_call
            tool_name = tc.tool_name or "unknown_tool"
            tool_args = self._safe_parse_tool_args(tc.arguments)

            return self.emit_tool_call(
                sender=agent_role,
                tool_name=tool_name,
                tool_args=tool_args,
                call_path=base_call_path or [agent_role, tool_name],
                history_summary=history_summary,
                metadata={
                    **metadata,
                    "tool_id": getattr(tc, "tool_id", None),
                    "tool_index": getattr(tc, "index", None),
                    "chunk_content": getattr(chunk, "content", ""),
                },
            )

        return self.emit_message(
            sender=agent_role,
            receiver=receiver_for_text,
            content=getattr(chunk, "content", "") or "",
            call_path=base_call_path or [agent_role],
            history_summary=history_summary,
            metadata={
                **metadata,
                "chunk_type": chunk_type,
            },
        )

    @staticmethod
    def _safe_parse_tool_args(raw: Any) -> Dict[str, Any]:
        if raw is None:
            return {}

        if isinstance(raw, dict):
            return raw

        if not isinstance(raw, str):
            return {"_raw": raw}

        raw = raw.strip()
        if not raw:
            return {}

        try:
            parsed = json.loads(raw)
            if isinstance(parsed, dict):
                return parsed
            return {"_raw": parsed}
        except Exception:
            return {"_raw": raw}
