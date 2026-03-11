# crewai_execute_task_patch.py
from __future__ import annotations

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
