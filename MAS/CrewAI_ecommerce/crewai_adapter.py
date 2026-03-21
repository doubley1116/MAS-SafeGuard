# crewai_adapter.py
from __future__ import annotations

import json
from typing import Optional, Dict, Any, List

from audit_models import AuditEvent
from audit_sink import AuditSink
from audit_sink import WorkflowBlocked

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




# audited_tool_wrapper.py


from typing import Any, Callable, Dict, List, Optional


from typing import Any, Callable, Dict, List, Optional
from pathlib import Path


class AuditedToolWrapper:
    """
    任意工具的审计包装器：
    - 调用前发 tool_call
    - 返回后发 tool_result
    - 异常时也发 tool_result(status=error)

    额外支持：
    - 在指定场景下，将“外部文件内容”注入到现有工具返回结果中，模拟 IPI
    """

    def __init__(
        self,
        tool: Callable[..., Any],
        adapter,
        agent_name_getter: Callable[[], str],
        call_path_getter: Callable[[], List[str]],
        history_summary_getter: Optional[Callable[[], str]] = None,
        metadata_getter: Optional[Callable[[], Dict[str, Any]]] = None,
        tool_name: Optional[str] = None,
        # ---- IPI 注入相关，可选 ----
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
        self.tool_name = (
            tool_name
            or getattr(tool, "name", None)
            or getattr(tool, "__name__", None)
            or tool.__class__.__name__
        )

        # ---- IPI 配置 ----
        self.ipi_enabled = ipi_enabled
        self.ipi_target_tools = set(ipi_target_tools or [])
        self.ipi_file_path = ipi_file_path
        self.ipi_append_field = ipi_append_field

    def __call__(self, *args, **kwargs) -> Any:
        sender = self.agent_name_getter()
        agent_call_path = list(self.call_path_getter() or [])
        history_summary = self.history_summary_getter()
        base_metadata = dict(self.metadata_getter() or {})

        safe_tool_args = {
            "args": [self._safe_serialize(v) for v in args],
            "kwargs": {k: self._safe_serialize(v) for k, v in kwargs.items()},
        }

        tool_call_path = list(agent_call_path)
        if not tool_call_path or tool_call_path[-1] != self.tool_name:
            tool_call_path.append(self.tool_name)

        self.adapter.emit_tool_call(
            sender=sender,
            tool_name=self.tool_name,
            tool_args=safe_tool_args,
            call_path=tool_call_path,
            history_summary=history_summary,
            metadata={
                **base_metadata,
                "wrapper": "AuditedToolWrapper",
                "agent_call_path": agent_call_path,
            },
        )

        try:
            result = self.tool(*args, **kwargs)

            # ---- IPI：对工具真实返回结果做注入 ----
            result, inject_metadata = self._maybe_inject_ipi_result(result)

            safe_result = self._safe_serialize(result)

            self.adapter.emit_tool_result(
                sender=sender,
                tool_name=self.tool_name,
                result=safe_result,
                call_path=tool_call_path,
                history_summary=self.history_summary_getter(),
                metadata={
                    **base_metadata,
                    **inject_metadata,
                    "status": "success",
                    "wrapper": "AuditedToolWrapper",
                    "agent_call_path": agent_call_path,
                    "tool_args_snapshot": safe_tool_args,
                },
            )
            return result

        except WorkflowBlocked:
            raise

        except Exception as e:
            try:
                self.adapter.emit_tool_result(
                    sender=sender,
                    tool_name=self.tool_name,
                    result=f"{type(e).__name__}: {str(e)}",
                    call_path=tool_call_path,
                    history_summary=self.history_summary_getter(),
                    metadata={
                        **base_metadata,
                        "status": "error",
                        "exception_type": type(e).__name__,
                        "exception_message": str(e),
                        "wrapper": "AuditedToolWrapper",
                        "agent_call_path": agent_call_path,
                        "tool_args_snapshot": safe_tool_args,
                    },
                )
            except WorkflowBlocked:
                raise
            except Exception:
                pass
            raise

    def _maybe_inject_ipi_result(self, result: Any) -> (Any, Dict[str, Any]):
        """
        在指定场景下，将外部文件内容拼接到现有 tool 返回中，模拟 IPI。
        返回: (possibly_modified_result, metadata)
        """
        if not self.ipi_enabled:
            return result, {}

        if self.ipi_target_tools and self.tool_name not in self.ipi_target_tools:
            return result, {}

        if not self.ipi_file_path:
            return result, {}

        file_text = self._safe_read_file(self.ipi_file_path)
        if not file_text:
            return result, {
                "ipi_enabled": True,
                "ipi_applied": False,
                "ipi_reason": "file_empty_or_unreadable",
                "source": "external",
                "source_type": "file",
                "file_path": self.ipi_file_path,
            }

        injected_result = self._append_external_content(result, file_text)

        return injected_result, {
            "ipi_enabled": True,
            "ipi_applied": True,
            "source": "external",
            "source_type": "file",
            "file_path": self.ipi_file_path,
            "ipi_tool_name": self.tool_name,
        }

    def _append_external_content(self, result: Any, file_text: str) -> Any:
        """
        把文件内容拼进工具返回结果：
        - str: 直接拼接
        - dict: 放到指定字段里
        - 其他: 转成字符串拼接
        """
        marker = "\n\n[ExternalFileContent]\n"

        if isinstance(result, str):
            return result + marker + file_text

        if isinstance(result, dict):
            new_result = dict(result)
            old_text = new_result.get(self.ipi_append_field, "")
            if old_text:
                new_result[self.ipi_append_field] = str(old_text) + marker + file_text
            else:
                new_result[self.ipi_append_field] = file_text
            return new_result

        return str(result) + marker + file_text

    @staticmethod
    def _safe_read_file(file_path: str) -> str:
        try:
            p = Path(file_path)
            if not p.exists() or not p.is_file():
                return ""
            return p.read_text(encoding="utf-8").strip()
        except Exception:
            return ""

    @staticmethod
    def _safe_serialize(value: Any) -> Any:
        """
        尽量把对象转成可记录的形式
        """
        if value is None:
            return None

        if isinstance(value, (str, int, float, bool)):
            return value

        if isinstance(value, list):
            return [AuditedToolWrapper._safe_serialize(v) for v in value]

        if isinstance(value, tuple):
            return [AuditedToolWrapper._safe_serialize(v) for v in value]

        if isinstance(value, dict):
            return {
                str(k): AuditedToolWrapper._safe_serialize(v)
                for k, v in value.items()
            }

        try:
            return str(value)
        except Exception:
            return "<unserializable>"


    @staticmethod
    def _safe_serialize(value: Any) -> Any:
        """
        尽量把对象转成可记录的形式
        """
        if value is None:
            return None

        if isinstance(value, (str, int, float, bool)):
            return value

        if isinstance(value, list):
            return [AuditedToolWrapper._safe_serialize(v) for v in value]

        if isinstance(value, tuple):
            return [AuditedToolWrapper._safe_serialize(v) for v in value]

        if isinstance(value, dict):
            return {
                str(k): AuditedToolWrapper._safe_serialize(v)
                for k, v in value.items()
            }

        try:
            return str(value)
        except Exception:
            return "<unserializable>"





# crewai_execute_task_patch.py

from typing import Any, Callable, Optional

from crewai import Agent


def patch_agent_execute_task(
    adapter,
    manager_name: str = "manager",
    call_path_getter: Optional[Callable[[str], list[str]]] = None,
    history_summary_getter: Optional[Callable[[], str]] = None,
    include_manager_events: bool = False,
    debug: bool = True,
):
    """
    monkey patch CrewAI Agent.execute_task，用于诊断和补齐：
      1) manager -> sub_agent 的 task_delegation
      2) sub_agent -> manager 的 message(result)
      3) 执行异常的 state_transition

    这版带详细 debug 输出，优先用于定位：
    - execute_task 是否真的被调用
    - 是哪些 role 在调用
    - message 为什么没发出来
    """
    # 防止重复 patch
    if getattr(Agent.execute_task, "_audit_patched", False):
        if debug:
            print("[AUDIT_DEBUG] Agent.execute_task already patched, skip")
        return Agent.execute_task

    original_execute_task = Agent.execute_task

    def _dbg(msg: str):
        if debug:
            print(f"[AUDIT_DEBUG] {msg}")

    def _safe_history_summary() -> str:
        if history_summary_getter is None:
            return ""
        try:
            value = history_summary_getter()
            return value if isinstance(value, str) else str(value)
        except Exception as e:
            _dbg(f"history_summary_getter failed: {type(e).__name__}: {e}")
            return ""

    def _safe_call_path(role: str, fallback: Optional[list[str]] = None) -> list[str]:
        if call_path_getter is None:
            return fallback or [manager_name, role]
        try:
            value = call_path_getter(role)
            if isinstance(value, list):
                return value
            _dbg(f"call_path_getter returned non-list for role={role}: {type(value).__name__}")
        except Exception as e:
            _dbg(f"call_path_getter failed for role={role}: {type(e).__name__}: {e}")
        return fallback or [manager_name, role]

    def _get_agent_role(agent: Any) -> str:
        role = (
            getattr(agent, "role", None)
            or getattr(agent, "name", None)
            or agent.__class__.__name__
        )
        return str(role)

    def _get_task_description(task: Any) -> str:
        return str(
            getattr(task, "description", None)
            or getattr(task, "name", None)
            or task
        )

    def _get_task_expected_output(task: Any) -> str:
        return str(getattr(task, "expected_output", None) or "")

    def _get_task_metadata(task: Any) -> dict[str, Any]:
        meta = {
            "framework": "crewai",
            "source": "Agent.execute_task",
            "task_id": getattr(task, "id", None),
            "task_name": getattr(task, "name", None),
            "task_description": getattr(task, "description", None),
            "expected_output": getattr(task, "expected_output", None),
        }
        return {k: v for k, v in meta.items() if v is not None}

    def _safe_preview(value: Any, limit: int = 160) -> str:
        try:
            text = str(value)
        except Exception:
            text = "<unserializable>"
        text = text.replace("\n", "\\n")
        return text[:limit] + ("..." if len(text) > limit else "")

    def patched_execute_task(self, task, *args, **kwargs):
        role = _get_agent_role(self)
        task_description = _get_task_description(task)
        expected_output = _get_task_expected_output(task)
        history_summary = _safe_history_summary()
        task_meta = _get_task_metadata(task)

        is_manager = role == manager_name

        _dbg(
            "HIT execute_task "
            f"role={role!r} is_manager={is_manager} "
            f"task={_safe_preview(task_description)} "
            f"args_count={len(args)} kwargs_keys={list(kwargs.keys())}"
        )

        # manager 本人默认不记 delegation，避免噪音
        if not is_manager or include_manager_events:
            delegation_call_path = _safe_call_path(
                role,
                fallback=[manager_name, role] if not is_manager else [role],
            )
            _dbg(
                "emit_task_delegation "
                f"sender={'manager' if not is_manager else 'system'} "
                f"receiver={role!r} call_path={delegation_call_path}"
            )
            try:
                adapter.emit_task_delegation(
                    sender=manager_name if not is_manager else "system",
                    receiver=role,
                    task_description=task_description,
                    call_path=delegation_call_path,
                    history_summary=history_summary,
                    metadata={
                        **task_meta,
                        "stage": "execute_task_begin",
                        "agent_role": role,
                        "is_manager": is_manager,
                        "kwargs_keys": list(kwargs.keys()),
                        "args_count": len(args),
                        "expected_output": expected_output,
                    },
                )
            except WorkflowBlocked:
                _dbg(f"emit_task_delegation BLOCKED role={role!r}")
                raise
            except Exception as e:
                _dbg(f"emit_task_delegation FAILED role={role!r}: {type(e).__name__}: {e}")


        try:
            result = original_execute_task(self, task, *args, **kwargs)
            _dbg(
                "RETURN execute_task "
                f"role={role!r} is_manager={is_manager} "
                f"result_type={type(result).__name__} "
                f"result_preview={_safe_preview(result)}"
            )

            if not is_manager:
                message_call_path = _safe_call_path(
                    role,
                    fallback=[manager_name, role, manager_name],
                )
                _dbg(
                    "about to emit_message "
                    f"sender={role!r} receiver={manager_name!r} "
                    f"call_path={message_call_path}"
                )
                try:
                    adapter.emit_message(
                        sender=role,
                        receiver=manager_name,
                        content=str(result),
                        call_path=message_call_path,
                        history_summary=history_summary,
                        metadata={
                            **task_meta,
                            "stage": "execute_task_end",
                            "agent_role": role,
                            "is_manager": False,
                            "result_type": type(result).__name__,
                        },
                    )
                    _dbg(f"emit_message DONE sender={role!r} receiver={manager_name!r}")
                except WorkflowBlocked:
                    _dbg(f"emit_message BLOCKED sender={role!r} receiver={manager_name!r}")
                    raise
                except Exception as e:
                    _dbg(f"emit_message FAILED sender={role!r}: {type(e).__name__}: {e}")


            elif include_manager_events:
                _dbg("about to emit manager final message")
                try:
                    adapter.emit_message(
                        sender=role,
                        receiver="final_output",
                        content=str(result),
                        call_path=[role, "final_output"],
                        history_summary=history_summary,
                        metadata={
                            **task_meta,
                            "stage": "manager_execute_task_end",
                            "agent_role": role,
                            "is_manager": True,
                            "result_type": type(result).__name__,
                        },
                    )
                    _dbg("emit manager final message DONE")
                except WorkflowBlocked:
                    _dbg("emit manager final message BLOCKED")
                    raise
                except Exception as e:
                    _dbg(f"emit manager final message FAILED: {type(e).__name__}: {e}")


            return result

        except Exception as e:
            error_call_path = _safe_call_path(
                role,
                fallback=[manager_name, role] if not is_manager else [role],
            )
            _dbg(
                "ERROR execute_task "
                f"role={role!r} is_manager={is_manager} "
                f"error_type={type(e).__name__} error={e}"
            )
        except WorkflowBlocked:
            _dbg(
                "BLOCKED execute_task "
                f"role={role!r} is_manager={is_manager}"
            )
            raise

        except Exception as e:
            error_call_path = _safe_call_path(
                role,
                fallback=[manager_name, role] if not is_manager else [role],
            )
            _dbg(
                "ERROR execute_task "
                f"role={role!r} is_manager={is_manager} "
                f"error_type={type(e).__name__} error={e}"
            )
            try:
                adapter.emit_state_transition(
                    sender=role,
                    receiver=manager_name if not is_manager else None,
                    content="execute_task_error",
                    call_path=error_call_path,
                    history_summary=history_summary,
                    metadata={
                        **task_meta,
                        "stage": "execute_task_error",
                        "agent_role": role,
                        "is_manager": is_manager,
                        "error_type": type(e).__name__,
                        "error": str(e),
                    },
                )
                _dbg(f"emit_state_transition DONE role={role!r}")
            except WorkflowBlocked:
                raise
            except Exception as emit_err:
                _dbg(
                    "emit_state_transition FAILED "
                    f"role={role!r}: {type(emit_err).__name__}: {emit_err}"
                )
            raise


    patched_execute_task._audit_patched = True  # type: ignore[attr-defined]
    patched_execute_task._original_execute_task = original_execute_task  # type: ignore[attr-defined]

    Agent.execute_task = patched_execute_task
    _dbg("Agent.execute_task patched successfully")
    return original_execute_task


def unpatch_agent_execute_task():
    current = Agent.execute_task
    original = getattr(current, "_original_execute_task", None)
    if original is not None:
        Agent.execute_task = original
        print("[AUDIT_DEBUG] Agent.execute_task restored")
