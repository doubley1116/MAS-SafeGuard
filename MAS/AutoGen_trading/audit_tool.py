"""
audit_tool.py — 工具审计装饰器

提供 @audited_tool 装饰器，让用户用一行代码就能给工具函数加上审计能力，
无需在每个工具函数内手动调用 emit_tool_call / emit_tool_result。

用法：
  from audit_tool import audited_tool

  @audited_tool(adapter=audit_adapter, sender="Stats_Agent", tool_name="stats_query_tool")
  def stats_query_tool(merchant_id: str) -> str:
      return f"商家 {merchant_id} 的统计数据..."
"""

from __future__ import annotations

import functools
from typing import Any, Callable, Optional

from autogen_adapter import AutoGenAuditAdapter, WorkflowBlocked, BLOCKED_WORKFLOW_MESSAGE


def audited_tool(
    adapter: AutoGenAuditAdapter,
    sender: str,
    tool_name: str,
) -> Callable:
    """
    工具审计装饰器。

    自动在工具调用前后执行审计检查：
      1. 检查工作流是否已被阻断
      2. emit_tool_call —— 调用前审计（检查调用权限）
      3. 执行原始工具函数
      4. emit_tool_result —— 调用后审计（检查返回结果）

    Args:
        adapter:    AutoGenAuditAdapter 实例（与 AuditedGroupChatManager 共享）
        sender:     调用此工具的 Agent 名称
        tool_name:  工具名称（与 policy.yaml 中定义的一致）

    Returns:
        装饰后的函数，签名与原函数一致
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs) -> Any:
            # 1. 已阻断则直接短路
            if adapter.is_blocked():
                return BLOCKED_WORKFLOW_MESSAGE

            # 2. 调用前审计
            try:
                adapter.emit_tool_call(
                    sender=sender,
                    tool_name=tool_name,
                    tool_args=kwargs if kwargs else (
                        {f"arg_{i}": v for i, v in enumerate(args)} if args else {}
                    ),
                )
            except WorkflowBlocked as e:
                return f"[阻断] {e}"

            # 3. 执行原始工具函数
            result = func(*args, **kwargs)

            # 4. 调用后审计
            try:
                adapter.emit_tool_result(
                    sender=sender,
                    tool_name=tool_name,
                    result=result,
                )
            except WorkflowBlocked as e:
                return f"[阻断] {e}"

            return result

        return wrapper
    return decorator
