# audited_tool_wrapper.py
from __future__ import annotations

from typing import Any, Callable, Dict, List, Optional


class AuditedToolWrapper:
    """
    任意工具的审计包装器：
    - 调用前发 tool_call
    - 返回后发 tool_result
    - 异常时也发 tool_result(status=error)

    注意：
    本类不做权限判断，不做拦截，只发 AuditEvent
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
            safe_result = self._safe_serialize(result)

            self.adapter.emit_tool_result(
                sender=sender,
                tool_name=self.tool_name,
                result=safe_result,
                call_path=tool_call_path,
                history_summary=self.history_summary_getter(),
                metadata={
                    **base_metadata,
                    "status": "success",
                    "wrapper": "AuditedToolWrapper",
                    "agent_call_path": agent_call_path,
                    "tool_args_snapshot": safe_tool_args,
                },
            )
            return result

        except Exception as e:
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
            raise

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
