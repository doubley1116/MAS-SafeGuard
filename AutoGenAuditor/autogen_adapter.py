"""
autogen_adapter.py — AutoGen 框架通用审计适配器

提供 AutoGenAuditAdapter 类，将 AutoGen 工作流中的消息传递和工具调用
接入 Zero_Trust 审计层（audit_layer）进行安全审核。

用法：
  # 仅记录，不拦截
  adapter = AutoGenAuditAdapter()

  # 启用 SecurityCore 拦截
  adapter = AutoGenAuditAdapter(yaml_path="policy.yaml")
"""

from __future__ import annotations

import json
import os
import sys
from dataclasses import asdict
from pathlib import Path
from typing import Any, Dict, List, Optional
from datetime import datetime
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))  # 添加项目根目录
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

    核心功能：
      - emit_message():    审计 Agent 间消息传递
      - emit_tool_call():  审计工具调用（调用前）
      - emit_tool_result(): 审计工具执行结果（调用后）

    当 yaml_path 设置且审核不通过时：
      - 设置 adapter._blocked = True
      - 抛出 WorkflowBlocked 异常
    """

    def __init__(
        self,
        yaml_path: Optional[str] = None,
        trace_id: str = "",
        jsonl_path: str = "audit_logs/audit_log.jsonl",
        workflow_dir: str = "audit_logs/workflows",
        verbose: bool = True,
    ) -> None:
        """
        Args:
            yaml_path:     安全策略 YAML 文件路径（None 则仅记录不拦截）
            trace_id:      追踪 ID
            jsonl_path:    审计日志文件路径
            workflow_dir:  工作流审计事件保存目录
            verbose:       是否打印详细日志
        """
        self.security_core = SecurityCore(yaml_path) if yaml_path else None
        self.trace_id = trace_id
        self.scenario_id: str = ""
        self.verbose = verbose
        self._blocked: bool = False
        self._blocked_reason: str = ""
        self.call_path: List[str] = []
        self.conversation_history: List[Dict[str, Any]] = []

        self._jsonl_path = Path(jsonl_path)
        self._jsonl_path.parent.mkdir(parents=True, exist_ok=True)

        self._workflow_dir = Path(workflow_dir)
        self._workflow_dir.mkdir(parents=True, exist_ok=True)

        self._workflow_events: List[Dict[str, Any]] = []
        self._workflow_decisions: List[Dict[str, Any]] = []

    # ── 状态管理 ──────────────────────────────────────────────

    def reset_state(self, trace_id: str = "", scenario_id: str = "") -> None:
        """每个场景开始前调用，清除调用路径、对话历史和阻断状态。"""
        if self.trace_id and self._workflow_events:
            self._save_workflow()

        self.trace_id = trace_id
        self.scenario_id = scenario_id
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
        """构建对话历史摘要（最近 10 条）。"""
        if not self.conversation_history:
            return ""
        lines = []
        for entry in self.conversation_history[-10:]:
            sender = entry.get("sender", "?")
            receiver = entry.get("receiver", "?")
            content = str(entry.get("content", ""))[:100]
            lines.append(f"[{sender} -> {receiver}]: {content}")
        return "\n".join(lines)

    # ── 工作流保存 ────────────────────────────────────────────

    def _save_workflow(self) -> None:
        """保存当前工作流的所有审计事件到 JSON 文件。"""
        if not self.trace_id or not self._workflow_events:
            return

        filename = self.scenario_id if self.scenario_id else self.trace_id
        workflow_file = self._workflow_dir / f"{filename}.json"
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

    def finalize_workflow(self) -> None:
        """手动结束并保存当前工作流（场景结束时调用）。"""
        self._save_workflow()

    # ── 内部核心 ──────────────────────────────────────────────

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
        """构建审计事件，写日志，执行安全检查。"""
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

        self._workflow_events.append(asdict(event))
        if decision:
            self._workflow_decisions.append(asdict(decision))

        return event

    def _log(self, event: AuditEvent) -> None:
        """追加到 JSONL 审计日志文件。"""
        data = asdict(event)
        with self._jsonl_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(data, ensure_ascii=False, default=str) + "\n")

    def _check(self, event: AuditEvent) -> Optional[AuditDecision]:
        """安全审核：规则引擎 + LLM 语义审核。不通过时抛出 WorkflowBlocked。"""
        if self.security_core is None:
            return None

        decision = self.security_core.audit(event)

        if not decision.allow:
            self._blocked = True
            self._blocked_reason = f"SecurityCore 阻断工作流: {decision.reason}"
            print("\n" + "=" * 60)
            print("[SecurityCore] 工作流已拦截")
            print("=" * 60)
            print(json.dumps(asdict(decision), indent=2, ensure_ascii=False, default=str))
            print("=" * 60)
            raise WorkflowBlocked(
                message=self._blocked_reason,
                decision=decision,
                event=event,
            )

        return decision

    # ── 公开 emit 方法 ────────────────────────────────────────

    def emit_message(
        self,
        sender: str,
        receiver: str,
        content: str = "",
        call_path: Optional[List[str]] = None,
        history_summary: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> AuditEvent:
        """审计 Agent 间消息传递事件。"""
        if self._blocked:
            raise WorkflowBlocked(self._blocked_reason or BLOCKED_WORKFLOW_MESSAGE)

        self.update_call_path(sender)
        self.conversation_history.append({
            "sender": sender, "receiver": receiver, "content": content,
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
        """审计工具调用事件（调用前检查）。"""
        if self._blocked:
            raise WorkflowBlocked(self._blocked_reason or BLOCKED_WORKFLOW_MESSAGE)

        self.update_call_path(sender)
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
        """审计工具执行结果事件（调用后审核）。"""
        if self._blocked:
            raise WorkflowBlocked(self._blocked_reason or BLOCKED_WORKFLOW_MESSAGE)

        self.update_call_path(sender)
        final_call_path = list(call_path or self.call_path)

        return self._emit(
            "tool_result", sender, None,
            tool_name=tool_name,
            call_path=final_call_path,
            content=str(result),
            history_summary=history_summary,
            metadata=metadata,
        )
