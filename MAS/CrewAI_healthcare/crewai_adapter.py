from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from crewai import Agent
import os
import sys
REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from audit_layer.audit_models import AuditEvent
from audit_sink import AuditSink, WorkflowBlocked


BLOCKED_WORKFLOW_MESSAGE = "[会话已终止] SecurityCore 已阻断本次工作流，后续操作全部短路。"

HistorySummaryGetter = Callable[[], str]
MetadataGetter = Callable[[], Dict[str, Any]]
CallPathGetter = Callable[[], List[str]]
RoleCallPathGetter = Callable[[str], List[str]]
RoleHook = Callable[[str], None]


def _safe_str(value: Any) -> str:
    try:
        return str(value)
    except Exception:
        return "<unserializable>"


def _safe_preview(value: Any, limit: int = 160) -> str:
    text = _safe_str(value).replace("\n", "\\n")
    return text[:limit] + ("..." if len(text) > limit else "")


def _safe_serialize(value: Any) -> Any:
    if value is None or isinstance(value, (str, int, float, bool)):
        return value

    if isinstance(value, list):
        return [_safe_serialize(item) for item in value]

    if isinstance(value, tuple):
        return [_safe_serialize(item) for item in value]

    if isinstance(value, set):
        return [_safe_serialize(item) for item in value]

    if isinstance(value, dict):
        return {str(key): _safe_serialize(item) for key, item in value.items()}

    return _safe_str(value)


def _resolve_tool_name(tool: Callable[..., Any], explicit_name: Optional[str]) -> str:
    return (
        explicit_name
        or getattr(tool, "name", None)
        or getattr(tool, "__name__", None)
        or tool.__class__.__name__
    )


def _get_agent_role(agent: Any) -> str:
    role = (
        getattr(agent, "role", None)
        or getattr(agent, "name", None)
        or agent.__class__.__name__
    )
    return _safe_str(role)


def _get_task_description(task: Any) -> str:
    return _safe_str(
        getattr(task, "description", None)
        or getattr(task, "name", None)
        or task
    )


def _get_task_expected_output(task: Any) -> str:
    return _safe_str(getattr(task, "expected_output", None) or "")


def _build_task_metadata(task: Any) -> Dict[str, Any]:
    metadata = {
        "framework": "crewai",
        "source": "Agent.execute_task",
        "task_id": _safe_str(getattr(task, "id", None)),
        "task_name": getattr(task, "name", None),
        "task_description": getattr(task, "description", None),
        "expected_output": getattr(task, "expected_output", None),
    }
    return {key: value for key, value in metadata.items() if value is not None}


class CrewAIAuditAdapter:
    """
    只负责把 CrewAI 内部行为映射成 AuditEvent。
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
            call_path=list(call_path or []),
            content=content,
            history_summary=history_summary,
            trace_id=self.trace_id,
            metadata=dict(metadata or {}),
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
            content=task_description,
            call_path=call_path,
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
            content=content,
            call_path=call_path,
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
            content=_safe_str(result),
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
            content=content,
            call_path=call_path,
            history_summary=history_summary,
            metadata=metadata,
        )

    def emit_kickoff_input(
        self,
        inputs: Any,
        manager_name: str = "manager",
        call_path: Optional[List[str]] = None,
        history_summary: str = "",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> AuditEvent:
        return self.emit_message(
            sender="user",
            receiver=manager_name,
            content=_safe_str(inputs),
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
        return self.emit_message(
            sender=manager_name,
            receiver=receiver,
            content=_safe_str(content),
            call_path=call_path or ["user", manager_name, receiver],
            history_summary=history_summary,
            metadata={
                "framework": "crewai",
                "stage": "final_output",
                **(metadata or {}),
            },
        )

    def from_stream_chunk(
        self,
        chunk: Any,
        receiver_for_text: str = "stream",
        history_summary: str = "",
        base_call_path: Optional[List[str]] = None,
    ) -> AuditEvent:
        agent_role = getattr(chunk, "agent_role", "") or "unknown_agent"
        chunk_type_obj = getattr(chunk, "chunk_type", None)
        chunk_type = getattr(chunk_type_obj, "value", None) or _safe_str(chunk_type_obj)

        metadata = {
            "framework": "crewai",
            "source": "stream_chunk",
            "task_index": getattr(chunk, "task_index", 0),
            "task_name": getattr(chunk, "task_name", ""),
            "task_id": getattr(chunk, "task_id", ""),
            "agent_id": getattr(chunk, "agent_id", ""),
        }

        if chunk_type == "tool_call" and getattr(chunk, "tool_call", None):
            tool_call = chunk.tool_call
            tool_name = getattr(tool_call, "tool_name", None) or "unknown_tool"
            tool_args = self._safe_parse_tool_args(getattr(tool_call, "arguments", None))
            return self.emit_tool_call(
                sender=agent_role,
                tool_name=tool_name,
                tool_args=tool_args,
                call_path=base_call_path or [agent_role, tool_name],
                history_summary=history_summary,
                metadata={
                    **metadata,
                    "tool_id": getattr(tool_call, "tool_id", None),
                    "tool_index": getattr(tool_call, "index", None),
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

        text = raw.strip()
        if not text:
            return {}

        try:
            parsed = json.loads(text)
        except Exception:
            return {"_raw": text}

        if isinstance(parsed, dict):
            return parsed
        return {"_raw": parsed}


@dataclass(frozen=True)
class IPIConfig:
    enabled: bool = False
    target_tools: frozenset[str] = field(default_factory=frozenset)
    file_path: Optional[str] = None
    append_field: str = "attachment_text"

    def applies_to(self, tool_name: str) -> bool:
        if not self.enabled or not self.file_path:
            return False
        return not self.target_tools or tool_name in self.target_tools


@dataclass
class _ToolInvocationContext:
    sender: str
    agent_call_path: List[str]
    tool_call_path: List[str]
    history_summary: str
    metadata: Dict[str, Any]
    safe_tool_args: Dict[str, Any]


class AuditedToolWrapper:
    """
    任意工具的审计包装器。
    """

    def __init__(
        self,
        tool: Callable[..., Any],
        adapter: CrewAIAuditAdapter,
        agent_name_getter: Callable[[], str],
        call_path_getter: CallPathGetter,
        history_summary_getter: Optional[HistorySummaryGetter] = None,
        metadata_getter: Optional[MetadataGetter] = None,
        tool_name: Optional[str] = None,
        ipi_enabled: bool = False,
        ipi_target_tools: Optional[List[str]] = None,
        ipi_file_path: Optional[str] = None,
        ipi_append_field: str = "attachment_text",
    ) -> None:
        self.tool = tool
        self.adapter = adapter
        self.agent_name_getter = agent_name_getter
        self.call_path_getter = call_path_getter
        self.history_summary_getter = history_summary_getter or (lambda: "")
        self.metadata_getter = metadata_getter or (lambda: {})
        self.tool_name = _resolve_tool_name(tool, tool_name)
        self.ipi_config = IPIConfig(
            enabled=ipi_enabled,
            target_tools=frozenset(ipi_target_tools or []),
            file_path=ipi_file_path,
            append_field=ipi_append_field,
        )

    def __call__(self, *args, **kwargs) -> Any:
        context = self._build_context(args, kwargs)
        self.adapter.emit_tool_call(
            sender=context.sender,
            tool_name=self.tool_name,
            tool_args=context.safe_tool_args,
            call_path=context.tool_call_path,
            history_summary=context.history_summary,
            metadata={
                **context.metadata,
                "wrapper": "AuditedToolWrapper",
                "agent_call_path": context.agent_call_path,
            },
        )

        try:
            result = self.tool(*args, **kwargs)
            result, inject_metadata = self._maybe_inject_ipi_result(result)
            self._emit_tool_result(
                context=context,
                result=result,
                metadata={
                    **inject_metadata,
                    "status": "success",
                },
            )
            return result

        except WorkflowBlocked:
            raise

        except Exception as exc:
            try:
                self._emit_tool_result(
                    context=context,
                    result=f"{type(exc).__name__}: {_safe_str(exc)}",
                    metadata={
                        "status": "error",
                        "exception_type": type(exc).__name__,
                        "exception_message": _safe_str(exc),
                    },
                )
            except WorkflowBlocked:
                raise
            except Exception:
                pass
            raise

    def _build_context(self, args: tuple[Any, ...], kwargs: Dict[str, Any]) -> _ToolInvocationContext:
        sender = self.agent_name_getter()
        agent_call_path = list(self.call_path_getter() or [])
        tool_call_path = list(agent_call_path)
        if not tool_call_path or tool_call_path[-1] != self.tool_name:
            tool_call_path.append(self.tool_name)

        return _ToolInvocationContext(
            sender=sender,
            agent_call_path=agent_call_path,
            tool_call_path=tool_call_path,
            history_summary=self.history_summary_getter(),
            metadata=dict(self.metadata_getter() or {}),
            safe_tool_args={
                "args": [_safe_serialize(value) for value in args],
                "kwargs": {key: _safe_serialize(value) for key, value in kwargs.items()},
            },
        )

    def _emit_tool_result(
        self,
        context: _ToolInvocationContext,
        result: Any,
        metadata: Dict[str, Any],
    ) -> None:
        self.adapter.emit_tool_result(
            sender=context.sender,
            tool_name=self.tool_name,
            result=_safe_serialize(result),
            call_path=context.tool_call_path,
            history_summary=self.history_summary_getter(),
            metadata={
                **context.metadata,
                **metadata,
                "wrapper": "AuditedToolWrapper",
                "agent_call_path": context.agent_call_path,
                "tool_args_snapshot": context.safe_tool_args,
            },
        )

    def _maybe_inject_ipi_result(self, result: Any) -> Tuple[Any, Dict[str, Any]]:
        if not self.ipi_config.applies_to(self.tool_name):
            return result, {}

        file_text = self._safe_read_file(self.ipi_config.file_path)
        if not file_text:
            return result, {
                "ipi_enabled": True,
                "ipi_applied": False,
                "ipi_reason": "file_empty_or_unreadable",
                "source": "external",
                "source_type": "file",
                "file_path": self.ipi_config.file_path,
            }

        return self._append_external_content(result, file_text), {
            "ipi_enabled": True,
            "ipi_applied": True,
            "source": "external",
            "source_type": "file",
            "file_path": self.ipi_config.file_path,
            "ipi_tool_name": self.tool_name,
        }

    def _append_external_content(self, result: Any, file_text: str) -> Any:
        marker = "\n\n[ExternalFileContent]\n"

        if isinstance(result, str):
            return result + marker + file_text

        if isinstance(result, dict):
            merged = dict(result)
            existing = merged.get(self.ipi_config.append_field, "")
            merged[self.ipi_config.append_field] = (
                f"{existing}{marker}{file_text}" if existing else file_text
            )
            return merged

        return f"{_safe_str(result)}{marker}{file_text}"

    @staticmethod
    def _safe_read_file(file_path: Optional[str]) -> str:
        if not file_path:
            return ""

        try:
            path = Path(file_path)
            if not path.exists() or not path.is_file():
                return ""
            return path.read_text(encoding="utf-8").strip()
        except Exception:
            return ""

    @staticmethod
    def _safe_serialize(value: Any) -> Any:
        return _safe_serialize(value)


@dataclass
class _ExecuteTaskSnapshot:
    role: str
    is_manager: bool
    task_description: str
    expected_output: str
    history_summary: str
    task_metadata: Dict[str, Any]


@dataclass
class _ExecuteTaskPatchContext:
    adapter: CrewAIAuditAdapter
    original_execute_task: Callable[..., Any]
    manager_name: str = "manager"
    call_path_getter: Optional[RoleCallPathGetter] = None
    history_summary_getter: Optional[HistorySummaryGetter] = None
    include_manager_events: bool = False
    debug: bool = True
    on_execute_task_start: Optional[RoleHook] = None
    on_execute_task_end: Optional[RoleHook] = None
    is_blocked_checker: Optional[Callable[[], bool]] = None

    def dbg(self, message: str) -> None:
        if self.debug:
            print(f"[AUDIT_DEBUG] {message}")

    def safe_history_summary(self) -> str:
        if self.history_summary_getter is None:
            return ""
        try:
            return _safe_str(self.history_summary_getter())
        except Exception as exc:
            self.dbg(f"history_summary_getter failed: {type(exc).__name__}: {exc}")
            return ""

    def safe_call_path(self, role: str, fallback: Optional[List[str]] = None) -> List[str]:
        if self.call_path_getter is None:
            return list(fallback or [self.manager_name, role])

        try:
            value = self.call_path_getter(role)
            if isinstance(value, list):
                return list(value)
            self.dbg(
                f"call_path_getter returned non-list for role={role}: {type(value).__name__}"
            )
        except Exception as exc:
            self.dbg(f"call_path_getter failed for role={role}: {type(exc).__name__}: {exc}")

        return list(fallback or [self.manager_name, role])

    def is_blocked(self) -> bool:
        if self.is_blocked_checker is None:
            return False
        try:
            return bool(self.is_blocked_checker())
        except Exception as exc:
            self.dbg(f"is_blocked_checker failed: {type(exc).__name__}: {exc}")
            return False

    def call_hook(self, hook: Optional[RoleHook], hook_name: str, role: str) -> None:
        if hook is None:
            return
        try:
            hook(role)
        except Exception as exc:
            self.dbg(f"{hook_name} failed role={role!r}: {type(exc).__name__}: {exc}")

    def build_snapshot(self, agent: Any, task: Any) -> _ExecuteTaskSnapshot:
        role = _get_agent_role(agent)
        return _ExecuteTaskSnapshot(
            role=role,
            is_manager=role == self.manager_name,
            task_description=_get_task_description(task),
            expected_output=_get_task_expected_output(task),
            history_summary=self.safe_history_summary(),
            task_metadata=_build_task_metadata(task),
        )

    def emit_task_delegation(
        self,
        snapshot: _ExecuteTaskSnapshot,
        args: tuple[Any, ...],
        kwargs: Dict[str, Any],
    ) -> None:
        if snapshot.is_manager and not self.include_manager_events:
            return

        call_path = self.safe_call_path(
            snapshot.role,
            fallback=[self.manager_name, snapshot.role] if not snapshot.is_manager else [snapshot.role],
        )
        sender = self.manager_name if not snapshot.is_manager else "system"

        self.dbg(
            "emit_task_delegation "
            f"sender={sender!r} receiver={snapshot.role!r} call_path={call_path}"
        )

        try:
            self.adapter.emit_task_delegation(
                sender=sender,
                receiver=snapshot.role,
                task_description=snapshot.task_description,
                call_path=call_path,
                history_summary=snapshot.history_summary,
                metadata={
                    **snapshot.task_metadata,
                    "stage": "execute_task_begin",
                    "agent_role": snapshot.role,
                    "is_manager": snapshot.is_manager,
                    "kwargs_keys": list(kwargs.keys()),
                    "args_count": len(args),
                    "expected_output": snapshot.expected_output,
                },
            )
        except WorkflowBlocked:
            self.dbg(f"emit_task_delegation BLOCKED role={snapshot.role!r}")
            raise
        except Exception as exc:
            self.dbg(
                f"emit_task_delegation FAILED role={snapshot.role!r}: {type(exc).__name__}: {exc}"
            )

    def emit_result_message(self, snapshot: _ExecuteTaskSnapshot, result: Any) -> None:
        call_path = self.safe_call_path(
            snapshot.role,
            fallback=[self.manager_name, snapshot.role, self.manager_name],
        )
        self.dbg(
            "about to emit_message "
            f"sender={snapshot.role!r} receiver={self.manager_name!r} call_path={call_path}"
        )

        try:
            self.adapter.emit_message(
                sender=snapshot.role,
                receiver=self.manager_name,
                content=_safe_str(result),
                call_path=call_path,
                history_summary=snapshot.history_summary,
                metadata={
                    **snapshot.task_metadata,
                    "stage": "execute_task_end",
                    "agent_role": snapshot.role,
                    "is_manager": False,
                    "result_type": type(result).__name__,
                },
            )
            self.dbg(f"emit_message DONE sender={snapshot.role!r} receiver={self.manager_name!r}")
        except WorkflowBlocked:
            self.dbg(f"emit_message BLOCKED sender={snapshot.role!r} receiver={self.manager_name!r}")
            raise
        except Exception as exc:
            self.dbg(f"emit_message FAILED sender={snapshot.role!r}: {type(exc).__name__}: {exc}")

    def emit_manager_final_message(self, snapshot: _ExecuteTaskSnapshot, result: Any) -> None:
        self.dbg("about to emit manager final message")
        try:
            self.adapter.emit_message(
                sender=snapshot.role,
                receiver="final_output",
                content=_safe_str(result),
                call_path=[snapshot.role, "final_output"],
                history_summary=snapshot.history_summary,
                metadata={
                    **snapshot.task_metadata,
                    "stage": "manager_execute_task_end",
                    "agent_role": snapshot.role,
                    "is_manager": True,
                    "result_type": type(result).__name__,
                },
            )
            self.dbg("emit manager final message DONE")
        except WorkflowBlocked:
            self.dbg("emit manager final message BLOCKED")
            raise
        except Exception as exc:
            self.dbg(f"emit manager final message FAILED: {type(exc).__name__}: {exc}")

    def emit_error_transition(self, snapshot: _ExecuteTaskSnapshot, exc: Exception) -> None:
        call_path = self.safe_call_path(
            snapshot.role,
            fallback=[self.manager_name, snapshot.role] if not snapshot.is_manager else [snapshot.role],
        )
        self.dbg(
            "ERROR execute_task "
            f"role={snapshot.role!r} is_manager={snapshot.is_manager} "
            f"error_type={type(exc).__name__} error={exc}"
        )

        try:
            self.adapter.emit_state_transition(
                sender=snapshot.role,
                receiver=self.manager_name if not snapshot.is_manager else None,
                content="execute_task_error",
                call_path=call_path,
                history_summary=snapshot.history_summary,
                metadata={
                    **snapshot.task_metadata,
                    "stage": "execute_task_error",
                    "agent_role": snapshot.role,
                    "is_manager": snapshot.is_manager,
                    "error_type": type(exc).__name__,
                    "error": _safe_str(exc),
                },
            )
            self.dbg(f"emit_state_transition DONE role={snapshot.role!r}")
        except WorkflowBlocked:
            raise
        except Exception as emit_exc:
            self.dbg(
                "emit_state_transition FAILED "
                f"role={snapshot.role!r}: {type(emit_exc).__name__}: {emit_exc}"
            )


def patch_agent_execute_task(
    adapter: CrewAIAuditAdapter,
    manager_name: str = "manager",
    call_path_getter: Optional[RoleCallPathGetter] = None,
    history_summary_getter: Optional[HistorySummaryGetter] = None,
    include_manager_events: bool = False,
    debug: bool = True,
    on_execute_task_start: Optional[RoleHook] = None,
    on_execute_task_end: Optional[RoleHook] = None,
    is_blocked_checker: Optional[Callable[[], bool]] = None,
):
    if getattr(Agent.execute_task, "_audit_patched", False):
        if debug:
            print("[AUDIT_DEBUG] Agent.execute_task already patched, skip")
        return Agent.execute_task

    original_execute_task = Agent.execute_task
    context = _ExecuteTaskPatchContext(
        adapter=adapter,
        original_execute_task=original_execute_task,
        manager_name=manager_name,
        call_path_getter=call_path_getter,
        history_summary_getter=history_summary_getter,
        include_manager_events=include_manager_events,
        debug=debug,
        on_execute_task_start=on_execute_task_start,
        on_execute_task_end=on_execute_task_end,
        is_blocked_checker=is_blocked_checker,
    )

    def patched_execute_task(self, task, *args, **kwargs):
        snapshot = context.build_snapshot(self, task)

        if context.is_blocked():
            context.dbg(
                f"SHORT_CIRCUIT execute_task role={snapshot.role!r} — SecurityCore 已阻断"
            )
            return BLOCKED_WORKFLOW_MESSAGE

        context.call_hook(context.on_execute_task_start, "on_execute_task_start", snapshot.role)
        context.dbg(
            "HIT execute_task "
            f"role={snapshot.role!r} is_manager={snapshot.is_manager} "
            f"task={_safe_preview(snapshot.task_description)} "
            f"args_count={len(args)} kwargs_keys={list(kwargs.keys())}"
        )

        try:
            context.emit_task_delegation(snapshot, args, kwargs)

            result = context.original_execute_task(self, task, *args, **kwargs)
            context.dbg(
                "RETURN execute_task "
                f"role={snapshot.role!r} is_manager={snapshot.is_manager} "
                f"result_type={type(result).__name__} "
                f"result_preview={_safe_preview(result)}"
            )

            if not snapshot.is_manager:
                context.emit_result_message(snapshot, result)
            elif context.include_manager_events:
                context.emit_manager_final_message(snapshot, result)

            return result

        except WorkflowBlocked:
            context.dbg(
                "BLOCKED execute_task "
                f"role={snapshot.role!r} is_manager={snapshot.is_manager}"
            )
            raise

        except Exception as exc:
            context.emit_error_transition(snapshot, exc)
            raise

        finally:
            context.call_hook(context.on_execute_task_end, "on_execute_task_end", snapshot.role)

    patched_execute_task._audit_patched = True  # type: ignore[attr-defined]
    patched_execute_task._original_execute_task = original_execute_task  # type: ignore[attr-defined]

    Agent.execute_task = patched_execute_task
    context.dbg("Agent.execute_task patched successfully")
    return original_execute_task


def unpatch_agent_execute_task() -> None:
    current = Agent.execute_task
    original = getattr(current, "_original_execute_task", None)
    if original is not None:
        Agent.execute_task = original
        print("[AUDIT_DEBUG] Agent.execute_task restored")
