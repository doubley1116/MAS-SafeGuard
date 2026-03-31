"""
autogen_adapter.py — AutoGen 框架通用审计适配器（修复版）

修复内容：
  1. call_path 不再包含工具名（工具是 Agent 的一部分）
  2. 移除密码验证相关代码
  3. 添加工作流审计事件保存到文件
  4. AuditDecision 与 audit_models 保持一致
"""

from __future__ import annotations

import json
import os
import sys
from dataclasses import asdict
from pathlib import Path
from typing import Any, Dict, List, Optional
from datetime import datetime

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from audit_layer.audit_models import AuditEvent, AuditDecision
from audit_layer.security_core import SecurityCore

BLOCKED_WORKFLOW_MESSAGE = "[会话已终止] SecurityCore 已阻断本次工作流，后续操作全部短路。"


class WorkflowBlocked(Exception):
    """SecurityCore 判定不允许时抛出，用于终止 AutoGen 工作流。"""

    def __init__(self, message: str, decision: AuditDecision = None, event: AuditEvent = None) -> None:
        super().__init__(message)
        self.decision = decision
        self.event = event


def _safe_serialize(value: Any) -> Any:
    """递归净化数据，防止复杂对象 JSON 序列化失败。"""
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, dict):
        return {str(k): _safe_serialize(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_safe_serialize(i) for i in value]
    return str(value)


class AutoGenAuditAdapter:
    """
    AutoGen 框架通用审计适配器。

    使用方式：
      adapter = AutoGenAuditAdapter()                              # 仅记录，不拦截
      adapter = AutoGenAuditAdapter(yaml_path="ecommerce.yaml")   # 启用 SecurityCore 拦截

    当 yaml_path 设置且审核不通过时：
      - 设置 adapter._blocked = True
      - 抛出 WorkflowBlocked 异常
    """

    def __init__(
        self,
        yaml_path: Optional[str] = None,
        trace_id: str = "",
        jsonl_path: str = "database/audit_log.jsonl",
        workflow_dir: str = "workflow_AuditEvents",
        verbose: bool = True,
    ) -> None:
        """
        Args:
            yaml_path: 安全策略文件路径（可选，None 则仅记录不拦截）
            trace_id: 追踪 ID
            jsonl_path: 审计日志文件路径
            workflow_dir: 工作流审计事件保存目录
            verbose: 是否打印详细日志
        """
        self.security_core = SecurityCore(yaml_path) if yaml_path else None
        self.trace_id = trace_id
        self.verbose = verbose
        self._blocked: bool = False
        self._blocked_reason: str = ""
        self.call_path: List[str] = []
        self.conversation_history: List[Dict[str, Any]] = []
        
        # 日志文件
        self._jsonl_path = Path(jsonl_path)
        self._jsonl_path.parent.mkdir(parents=True, exist_ok=True)
        
        # 工作流事件保存目录
        self._workflow_dir = Path(workflow_dir)
        self._workflow_dir.mkdir(parents=True, exist_ok=True)
        
        # 当前工作流的事件列表
        self._workflow_events: List[Dict[str, Any]] = []
        self._workflow_decisions: List[Dict[str, Any]] = []

    # ── 状态管理 ──────────────────────────────────────────────────────────

    def reset_state(self, trace_id: str = "") -> None:
        """每个场景开始前调用，清除调用路径、对话历史和阻断状态。"""
        # 先保存上一个工作流（如果有）
        if self.trace_id and self._workflow_events:
            self._save_workflow()
        
        self.trace_id = trace_id
        self._blocked = False
        self._blocked_reason = ""
        self.call_path = []
        self.conversation_history = []
        self._workflow_events = []
        self._workflow_decisions = []

    def is_blocked(self) -> bool:
        """检查工作流是否已被阻断。"""
        return self._blocked

    def update_call_path(self, agent_name: str) -> None:
        """更新调用链路（只包含 Agent，不包含工具）。"""
        if not self.call_path or self.call_path[-1] != agent_name:
            self.call_path.append(agent_name)

    def build_history_summary(self) -> str:
        """构建对话历史摘要。"""
        if not self.conversation_history:
            return ""
        lines = []
        for entry in self.conversation_history[-10:]:  # 最近 10 条
            sender = entry.get("sender", "?")
            receiver = entry.get("receiver", "?")
            content = str(entry.get("content", ""))[:100]
            lines.append(f"[{sender} -> {receiver}]: {content}")
        return "\n".join(lines)

    # ── 工作流保存 ────────────────────────────────────────────────────────

    def _save_workflow(self) -> None:
        """保存当前工作流的所有审计事件到文件。"""
        if not self.trace_id or not self._workflow_events:
            return
        
        workflow_file = self._workflow_dir / f"{self.trace_id}.json"
        workflow_data = {
            "trace_id": self.trace_id,
            "timestamp": datetime.now().isoformat(),
            "event_count": len(self._workflow_events),
            "blocked": self._blocked,
            "blocked_reason": self._blocked_reason if self._blocked else None,
            "events": self._workflow_events,
            "decisions": self._workflow_decisions,
        }
        
        with workflow_file.open("w", encoding="utf-8") as f:
            json.dump(workflow_data, f, indent=2, ensure_ascii=False, default=str)
        
        if self.verbose:
            print(f"\n[WORKFLOW] 已保存工作流审计事件到: {workflow_file}")

    def finalize_workflow(self) -> None:
        """手动结束并保存当前工作流（场景结束时调用）。"""
        self._save_workflow()

    # ── 内部核心：构建事件、写日志、安全检查 ─────────────────────────────

    def _emit(
        self,
        event_type: str,
        sender: str,
        receiver: Optional[str],
        tool_name: Optional[str] = None,
        tool_args: Optional[Dict[str, Any]] = None,
        call_path: Optional[List[str]] = None,
        content: Optional[str] = None,
        history_summary: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> AuditEvent:
        """构建并处理审计事件。"""
        # call_path 只包含 Agent，不包含工具名
        final_call_path = list(call_path or self.call_path)
        
        event = AuditEvent(
            event_type=event_type,
            sender=sender,
            receiver=receiver,
            tool_name=tool_name,
            tool_args=tool_args,
            call_path=final_call_path,
            content=content,
            history_summary=(
                history_summary
                if history_summary is not None
                else self.build_history_summary()
            ),
            trace_id=self.trace_id,
            metadata=dict(metadata or {}),
        )
        
        self._log(event)
        decision = self._check(event)
        
        # 保存到工作流事件列表
        self._workflow_events.append(asdict(event))
        if decision:
            self._workflow_decisions.append(asdict(decision))
        
        return event

    def _log(self, event: AuditEvent) -> None:
        """打印到控制台并追加到 JSONL 文件。"""
        data = asdict(event)
        target = event.receiver or event.tool_name or "?"
        
        if self.verbose:
            print(f"\n[AUDIT | {event.event_type}] {event.sender} -> {target}")
            print(json.dumps(data, indent=2, ensure_ascii=False, default=str))
            print("-" * 50)
        
        with self._jsonl_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(data, ensure_ascii=False, default=str) + "\n")

    def _check(self, event: AuditEvent) -> Optional[AuditDecision]:
        """
        若 security_core 已设置，则对事件执行安全审核。
        审核不通过时设置 _blocked 标志并抛出 WorkflowBlocked。
        
        Returns:
            AuditDecision 或 None（如果没有 security_core）
        """
        if self.security_core is None:
            return None

        decision = self.security_core.audit(event)
        
        if self.verbose:
            print(
                f"[SecurityCore] {event.event_type} | sender={event.sender} | "
                f"allow={decision.allow} | risk={decision.risk_score:.2f} | {decision.reason}"
            )

        if not decision.allow:
            self._blocked = True
            self._blocked_reason = f"SecurityCore 阻断工作流: {decision.reason}"
            raise WorkflowBlocked(
                message=self._blocked_reason,
                decision=decision,
                event=event,
            )
        
        return decision

    # ── 公开 emit 方法 ─────────────────────────────────────────────────────

    def emit_message(
        self,
        sender: str,
        receiver: str,
        content: str = "",
        call_path: Optional[List[str]] = None,
        history_summary: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> AuditEvent:
        """
        发送 message 类型事件（Agent 间消息传递）。

        Args:
            sender: 发送者 Agent 名称
            receiver: 接收者 Agent 名称（由 AuditedGroupChatManager 提供确切值）
            content: 消息内容
            call_path: 调用链路（可选）
            history_summary: 历史摘要（可选）
            metadata: 附加元数据（可选）
        """
        if self._blocked:
            raise WorkflowBlocked(self._blocked_reason or BLOCKED_WORKFLOW_MESSAGE)

        self.update_call_path(sender)

        # 记录到对话历史
        self.conversation_history.append({
            "sender": sender,
            "receiver": receiver,
            "content": content,
        })

        return self._emit(
            "message", sender, receiver,
            call_path=call_path, content=content,
            history_summary=history_summary, metadata=metadata,
        )

    def emit_tool_call(
        self,
        sender: str,
        tool_name: str,
        tool_args: Optional[Dict[str, Any]] = None,
        call_path: Optional[List[str]] = None,
        content: Optional[str] = None,
        history_summary: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> AuditEvent:
        """
        发送 tool_call 类型事件（工具调用前检查）。
        
        注意：call_path 只包含 Agent，不包含工具名。
        工具信息通过 tool_name 字段单独记录。
        """
        if self._blocked:
            raise WorkflowBlocked(self._blocked_reason or BLOCKED_WORKFLOW_MESSAGE)
        
        self.update_call_path(sender)
        
        # call_path 只包含 Agent，不追加工具名
        final_call_path = list(call_path or self.call_path)
        
        return self._emit(
            "tool_call", sender, None,
            tool_name=tool_name,
            tool_args=_safe_serialize(tool_args or {}),
            call_path=final_call_path,
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
        content: Optional[str] = None,
        history_summary: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> AuditEvent:
        """
        发送 tool_result 类型事件（工具执行后审核结果）。
        
        注意：call_path 只包含 Agent，不包含工具名。
        """
        if self._blocked:
            raise WorkflowBlocked(self._blocked_reason or BLOCKED_WORKFLOW_MESSAGE)
        
        self.update_call_path(sender)
        
        # call_path 只包含 Agent，不追加工具名
        final_call_path = list(call_path or self.call_path)
        
        return self._emit(
            "tool_result", sender, None,
            tool_name=tool_name,
            call_path=final_call_path,
            content=str(result),
            history_summary=history_summary,
            metadata=metadata,
        )