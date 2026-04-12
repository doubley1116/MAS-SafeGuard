"""
audit_tool.py — 工具审计装饰器

与 AutoGenAuditor/audit_tool.py API 完全一致。

用法：
  @audited_tool(adapter=adapter, sender="Stats_Node", tool_name="stats_query_tool")
  def stats_query_tool(merchant_id: str) -> str:
      return f"商家 {merchant_id} 的统计数据"
"""
from __future__ import annotations
import functools
from typing import Any, Callable

import os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from langgraph_adapter import LangGraphAuditAdapter, WorkflowBlocked, BLOCKED_WORKFLOW_MESSAGE


def audited_tool(
    adapter: LangGraphAuditAdapter,
    sender: str,
    tool_name: str,
) -> Callable:
    """
    工具审计装饰器。

    自动在工具调用前后执行审计检查：
      1. 检查工作流是否已被阻断
      2. emit_tool_call — 调用前审计
      3. 执行原始工具函数
      4. emit_tool_result — 调用后审计

    Args:
        adapter:    LangGraphAuditAdapter 实例（与 AuditedGraph 共享）
        sender:     调用此工具的节点名称（与 policy.yaml nodes: 键一致）
        tool_name:  工具名称（与 policy.yaml tools: 键一致）
    """
    def decorator(func: Callable) -> Callable:
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            if adapter.is_blocked():
                return BLOCKED_WORKFLOW_MESSAGE

            tool_args = kwargs if kwargs else (
                {f"arg_{i}": v for i, v in enumerate(args)} if args else {}
            )
            try:
                adapter.emit_tool_call(
                    sender=sender,
                    tool_name=tool_name,
                    tool_args=tool_args,
                )
            except WorkflowBlocked as e:
                return f"[阻断] {e}"

            result = func(*args, **kwargs)

            try:
                adapter.emit_tool_result(
                    sender=sender,
                    tool_name=tool_name,
                    result=result,
                )
            except WorkflowBlocked as e:
                return f"[阻断] {e}"

            return result
        # Set __name__ before @tool decorator extracts it - avoids __wrapped__
        # which causes inspect.signature to follow chain into StructuredTool
        wrapper.__name__ = tool_name
        wrapper.__doc__ = getattr(func, '__doc__', None)
        return wrapper
    return decorator
