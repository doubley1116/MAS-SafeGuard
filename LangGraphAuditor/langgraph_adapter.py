"""
langgraph_adapter.py — LangGraph 框架通用审计适配器

镜像 AutoGenAuditor/autogen_adapter.py，为 LangGraph StateGraph 提供
零信任审计能力。与 AutoGenAuditAdapter 的 API 完全对齐。

用法：
  # 仅记录，不拦截
  adapter = LangGraphAuditAdapter()

  # 启用 SecurityCore 拦截
  adapter = LangGraphAuditAdapter(yaml_path="policy.yaml")

全局开关 AUDIT_ENABLED = False 可关闭审批层拦截（只记录不拦截）。
"""

from __future__ import annotations

import json
import os
import sys
from dataclasses import asdict
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from audit_layer.audit_models import AuditDecision, AuditEvent

# 全局开关：环境变量 LANGGRAPH_AUDIT_ENABLED=false 关闭审批层拦截

AUDIT_ENABLED = False

from audit_layer.security_core import SecurityCore

BLOCKED_WORKFLOW_MESSAGE = "[会话已终止] SecurityCore 已阻断本次工作流，后续操作全部短路。"


class WorkflowBlocked(Exception):
    """SecurityCore 判定不允许时抛出，用于终止 LangGraph 工作流。"""

    def __init__(
        self,
        message: str,
        decision: AuditDecision = None,
        event: AuditEvent = None,
    ) -> None:
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


class LangGraphAuditAdapter:
    """
    LangGraph 框架通用审计适配器。

    核心功能：
      - emit_message():         审计节点间消息传递
      - emit_tool_call():       审计工具调用（调用前）
      - emit_tool_result():     审计工具执行结果（调用后）
      - emit_node_transition(): 审计节点切换（task_delegation）

    当 yaml_path 设置且审核不通过时：
      - 设置 adapter._blocked = True
      - 抛出 WorkflowBlocked 异常
    """

    MAX_HISTORY_ENTRIES: int = 30

    def __init__(
        self,
        yaml_path: Optional[str] = None,
        trace_id: str = "",
        jsonl_path: Optional[str] = "audit_logs/audit_log.jsonl",
        workflow_dir: Optional[str] = "audit_logs/workflows",
        verbose: bool = True,
        audit_enabled: Optional[bool] = None,
    ) -> None:
        self.security_core = SecurityCore(yaml_path) if yaml_path else None
        self.trace_id = trace_id
        self.scenario_id: str = ""
        self.verbose = verbose
        self.audit_enabled = (
            audit_enabled if audit_enabled is not None else AUDIT_ENABLED
        )
        self._blocked: bool = False
        self._blocked_reason: str = ""
        self.call_path: List[str] = []
        self.conversation_history: List[Dict[str, Any]] = []
        self._user_task: str = ""

        if jsonl_path is not None:
            self._jsonl_path: Optional[Path] = Path(jsonl_path)
            self._jsonl_path.parent.mkdir(parents=True, exist_ok=True)
        else:
            self._jsonl_path = None

        if workflow_dir is not None:
            self._workflow_dir: Optional[Path] = Path(workflow_dir)
            self._workflow_dir.mkdir(parents=True, exist_ok=True)
        else:
            self._workflow_dir = None

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
        self._user_task = ""
        self._workflow_events = []
        self._workflow_decisions = []

    def set_scene_info(self, scene_name: str, trace_id: str) -> None:
        """每个场景开始前调用：等价于 reset_state，API 对齐 AuditedGroupChatManager。"""
        self.reset_state(trace_id=trace_id, scenario_id=scene_name)

    def is_blocked(self) -> bool:
        """检查工作流是否已被阻断。"""
        return self._blocked

    def update_call_path(self, node_name: str) -> None:
        """更新调用链路。由 AuditedGraph 的回调在节点进入时调用。"""
        if not self.call_path or self.call_path[-1] != node_name:
            self.call_path.append(node_name)

    def set_user_task(self, task_content: str, sender: str = "User") -> None:
        """记录用户原始任务指令，提取核心意图作为锚点。"""
        if len(task_content) <= 80:
            self._user_task = task_content.replace("\n", " ")
        else:
            self._user_task = (
                self._llm_extract_task(task_content)
                or self._rule_based_extract(task_content)
            )

        self.update_call_path(sender)
        self.conversation_history.insert(0, {
            "type": "user_task",
            "sender": sender,
            "content": task_content,
        })

    def _llm_extract_task(self, long_text: str) -> str:
        if not self.security_core:
            return ""
        try:
            client = self.security_core.llm_reviewer.client
            model = self.security_core.llm_reviewer.model
            response = client.chat.completions.create(
                model=model,
                messages=[{
                    "role": "user",
                    "content": (
                        "用一句话概括以下任务的核心目的（不超过30字）。\n"
                        "只说用户要做什么操作和对什么对象，"
                        "不要包含角色设定、操作步骤、注意事项、委派规则。\n\n"
                        f"{long_text[:500]}"
                    ),
                }],
                max_tokens=50,
                temperature=0,
            )
            result = response.choices[0].message.content.strip()
            if result and len(result) <= 80:
                return result
        except Exception:
            pass
        return ""

    @staticmethod
    def _rule_based_extract(text: str) -> str:
        import re
        lines = [l.strip() for l in text.strip().split("\n") if l.strip()]
        candidates = []
        for line in lines:
            if line.startswith(("你是", "You are", "作为", "As a", "As an")):
                continue
            if line.startswith(("-", "*", "•", "1.", "2.", "3.")):
                continue
            if line.startswith(("注意", "要求", "说明", "Note", "Warning")):
                continue
            if line.startswith(("[", "{", "```", "import ", "def ", "class ")):
                continue
            if len(line) < 8:
                continue
            candidates.append(line)
        if not candidates:
            return text[:80]
        scored = []
        for line in candidates:
            score = 0
            for verb in ["查询", "分析", "修改", "更新", "执行", "检查", "统计",
                         "query", "analyze", "check", "update", "execute"]:
                if verb in line:
                    score += 2
                    break
            scored.append((score, line))
        scored.sort(key=lambda x: x[0], reverse=True)
        return scored[0][1][:80]

    def build_history_summary(self) -> str:
        """安全感知的分层上下文压缩（不含 task 字段）。"""
        if not self.conversation_history:
            return ""

        parts = []
        actions = [e for e in self.conversation_history if e.get("type") != "user_task"]

        if len(actions) <= 10:
            for entry in actions:
                parts.append(self._format_action(entry))
        else:
            critical = [e for e in actions if self._is_security_critical(e)]
            if critical:
                parts.append("[关键]" + " → ".join(self._format_action(e) for e in critical))
            recent = actions[-5:]
            critical_set = {id(e) for e in critical}
            recent_filtered = [e for e in recent if id(e) not in critical_set]
            if recent_filtered:
                parts.append("[近期]" + " → ".join(self._format_action(e) for e in recent_filtered))

        return " | ".join(parts)

    def _is_security_critical(self, entry: dict) -> bool:
        etype = entry.get("type", "")
        content = str(entry.get("content", "")).lower()
        tool = entry.get("tool_name", "") or ""
        if tool in ("fetch_url", "read_file", "execute_trade", "update_config",
                    "config_update_tool", "delete_record"):
            return True
        if etype == "tool_result" and any(
            kw in content for kw in ["error", "denied", "失败", "拒绝", "blocked"]
        ):
            return True
        if any(kw in content for kw in ["授权", "审批", "approve", "bypass", "override"]):
            return True
        return False

    def _format_action(self, entry: dict) -> str:
        """格式: sender: content（不含当前事件）"""
        etype = entry.get("type", "message")
        sender = entry.get("sender", "?")
        content = str(entry.get("content", ""))

        if etype == "tool_call":
            tool = entry.get("tool_name", "?")
            args = entry.get("tool_args") or {}
            key_args = ",".join(f"{k}={v}" for k, v in list(args.items())[:3])
            return f"{sender}: 发起调用 {tool}({key_args})"

        elif etype == "tool_result":
            tool = entry.get("tool_name", "?")
            compressed = content[:30].replace("\n", " ") if content else "ok"
            return f"{tool}: 返回 {compressed}"

        else:
            # message / user_task
            display_content = content[:40].replace("\n", " ") if content else ""
            return f"{sender}: {display_content}"

    # ── 工作流保存 ────────────────────────────────────────────

    def _save_workflow(self) -> None:
        if not self.trace_id or not self._workflow_events or self._workflow_dir is None:
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
                history_summary if history_summary is not None
                else self.build_history_summary()
            ),
            task=self._user_task,
            trace_id=self.trace_id,
            metadata=dict(metadata or {}),
        )
        self._log(event)
        self._workflow_events.append(asdict(event))
        decision = self._check(event)
        if decision:
            self._workflow_decisions.append(asdict(decision))
        return event

    def _log(self, event: AuditEvent) -> None:
        if self._jsonl_path is None:
            return
        data = asdict(event)
        with self._jsonl_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(data, ensure_ascii=False, default=str) + "\n")

    def _check(self, event: AuditEvent) -> Optional[AuditDecision]:
        if not self.audit_enabled:
            return None
        if self.security_core is None:
            return None
        decision = self.security_core.audit(event)
        if not decision.allow:
            self._blocked = True
            self._blocked_reason = f"SecurityCore 阻断工作流: {decision.reason}"
            if self.verbose:
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
        """审计节点间消息传递事件。"""
        if self._blocked:
            raise WorkflowBlocked(self._blocked_reason or BLOCKED_WORKFLOW_MESSAGE)
        self.update_call_path(sender)
        self.conversation_history.append({
            "type": "message",
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
        """审计工具调用事件（调用前检查）。"""
        if self._blocked:
            raise WorkflowBlocked(self._blocked_reason or BLOCKED_WORKFLOW_MESSAGE)
        self.update_call_path(sender)
        final_call_path = list(call_path or self.call_path)
        self.conversation_history.append({
            "type": "tool_call",
            "sender": sender,
            "tool_name": tool_name,
            "tool_args": _safe_serialize(tool_args or {}),
            "content": content or str(_safe_serialize(tool_args or {}))[:200],
        })
        return self._emit(
            "tool_call", sender, tool_name,
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
        """审计工具执行结果事件（调用后）。"""
        if self._blocked:
            raise WorkflowBlocked(self._blocked_reason or BLOCKED_WORKFLOW_MESSAGE)
        final_call_path = list(call_path or self.call_path)
        self.conversation_history.append({
            "type": "tool_result",
            "sender": tool_name,
            "receiver": sender,
            "tool_name": tool_name,
            "content": str(result)[:200],
        })
        return self._emit(
            "tool_result",
            tool_name,
            sender,
            tool_name=tool_name,
            call_path=final_call_path,
            content=content or str(result),
            history_summary=history_summary,
            metadata=metadata,
        )

    def emit_node_transition(
        self,
        from_node: str,
        to_node: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> AuditEvent:
        """
        审计节点切换事件，写为 state_transition 类型。
        content = "意图跳转: {to_node}"
        """
        if self._blocked:
            raise WorkflowBlocked(self._blocked_reason or BLOCKED_WORKFLOW_MESSAGE)
        content = f"意图跳转: {to_node}"
        self.conversation_history.append({
            "type": "state_transition",
            "sender": from_node,
            "receiver": to_node,
            "content": content,
        })
        return self._emit(
            "state_transition", from_node, to_node,
            content=content,
            metadata=metadata,
        )
