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
import uuid
from dataclasses import asdict
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

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
        jsonl_path: Optional[str] = None,
        workflow_dir: Optional[str] = None,
        verbose: bool = True,
        audit_enabled: Optional[bool] = None,
        # ── 场景适配器参数 ──────────────────────────────────────
        output_dir: Optional[str] = None,
        scenario_prefix: str = "",
        allowed_callers: Optional[Dict[str, List[str]]] = None,
        required_path_nodes: Optional[Dict[str, List[str]]] = None,
        legal_agents: Optional[Set[str]] = None,
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

        # ── 场景适配器字段 ──────────────────────────────────────
        self._allowed_callers: Dict[str, List[str]] = allowed_callers or {}
        self._required_path_nodes: Dict[str, List[str]] = required_path_nodes or {}
        self._legal_agents: Set[str] = legal_agents or set()
        self._scenario_prefix: str = scenario_prefix
        self._scenario_counters: Dict[str, int] = {}
        self._all_trace_events: Dict[str, List[AuditEvent]] = {}

        if output_dir is not None:
            self._output_dir: Optional[Path] = Path(output_dir)
            self._output_dir.mkdir(parents=True, exist_ok=True)
        else:
            self._output_dir = None

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

    # ── 场景适配器：权限检查辅助 ──────────────────────────────

    def _is_unauthorized_caller(self, tool_name: str, caller: str) -> bool:
        allowed = self._allowed_callers.get(tool_name, [])
        return bool(allowed) and caller not in allowed

    def _missing_required_nodes(self, tool_name: str, call_path: List[str]) -> List[str]:
        required = self._required_path_nodes.get(tool_name, [])
        return [n for n in required if n not in call_path]

    def _is_unknown_agent(self, agent_name: str) -> bool:
        if not self._legal_agents:
            return False
        return agent_name not in self._legal_agents and agent_name not in ("User", "AiTM_Interceptor")

    # ── 场景适配器：事件提取 ──────────────────────────────────

    def _extract_audit_events(
        self,
        stream_events: List[Dict[str, Any]],
        trace_id: str,
        scenario_title: str,
        graph_type: str,
        user_prompt: str = "",
        task_intent: str = "",
    ) -> List[AuditEvent]:
        from langchain_core.messages import AIMessage, HumanMessage, ToolMessage

        audit_events: List[AuditEvent] = []
        skeleton_id = f"LLM-{trace_id}"
        accumulated: List[Any] = []
        call_path: List[str] = ["User"]
        pending_tool_calls: Dict[str, tuple] = {}
        router_ctx: Dict[str, Any] = {}
        emitted_transitions: Set[str] = set()

        def _now() -> str:
            return datetime.utcnow().isoformat()

        def _mk(**kwargs) -> AuditEvent:
            return AuditEvent(task=task_intent, **kwargs)  # type: ignore[arg-type]

        def _hs() -> str:
            recent = [m for m in accumulated if hasattr(m, "content") and m.content][-4:]
            parts = []
            for m in recent:
                if isinstance(m, HumanMessage):
                    role = "User"
                elif isinstance(m, ToolMessage):
                    role = m.name or "tool"
                else:
                    role = getattr(m, "name", None) or m.__class__.__name__
                raw = m.content if isinstance(m.content, str) else " ".join(
                    p.get("text", "") if isinstance(p, dict) else str(p) for p in (m.content or [])
                )
                parts.append(f"[{role}]: {raw[:500].replace(chr(10), ' ')}")
            return "\n---\n".join(parts)[:2048]

        def _ext(*nodes) -> None:
            for node in nodes:
                if node is not None and (not call_path or call_path[-1] != node):
                    call_path.append(node)

        if user_prompt:
            accumulated.append(HumanMessage(content=user_prompt))
            _ext("User", "Router")
            audit_events.append(_mk(
                event_type="message", sender="User", receiver="Router",
                tool_name=None, tool_args=None,
                call_path=list(call_path), content=user_prompt[:500],
                history_summary="", trace_id=trace_id, timestamp=_now(),
                metadata={"scenario": scenario_title, "graph_type": graph_type,
                          "node_name": "HumanMessage", "skeleton_id": skeleton_id},
            ))

        for stream_event in stream_events:
            for node_name, node_state in stream_event.items():
                if "messages" not in node_state:
                    if node_name == "Router":
                        nxt = node_state.get("next", "")
                        if nxt:
                            router_ctx.update({
                                "next": nxt,
                                "intent_confidence": node_state.get("intent_confidence", 0.0),
                                "reason": node_state.get("reason", ""),
                            })
                            if nxt not in emitted_transitions:
                                emitted_transitions.add(nxt)
                                _ext("Router", nxt if nxt != "FINISH" else None)
                                audit_events.append(_mk(
                                    event_type="state_transition",
                                    sender="Router", receiver=nxt,
                                    tool_name=None, tool_args=None,
                                    call_path=list(call_path),
                                    content=f"意图跳转: {nxt.lower()}",
                                    history_summary=_hs(), trace_id=trace_id, timestamp=_now(),
                                    metadata={"scenario": scenario_title, "graph_type": graph_type,
                                              "node_name": "Router", "skeleton_id": skeleton_id,
                                              "intent": nxt.lower(),
                                              "intent_confidence": router_ctx.get("intent_confidence", 0.0),
                                              "reason": router_ctx.get("reason", "")},
                                ))
                    continue

                msgs = node_state["messages"]

                if node_name == "Router":
                    nxt = node_state.get("next") or router_ctx.get("next", "")
                    router_ctx.update({
                        "next": nxt,
                        "intent_confidence": node_state.get("intent_confidence", router_ctx.get("intent_confidence", 0.0)),
                        "reason": node_state.get("reason", router_ctx.get("reason", "")),
                    })
                    if nxt and nxt not in emitted_transitions:
                        emitted_transitions.add(nxt)
                        _ext("Router", nxt if nxt != "FINISH" else None)
                        audit_events.append(_mk(
                            event_type="state_transition",
                            sender="Router", receiver=nxt,
                            tool_name=None, tool_args=None,
                            call_path=list(call_path),
                            content=f"意图跳转: {nxt.lower()}",
                            history_summary=_hs(), trace_id=trace_id, timestamp=_now(),
                            metadata={"scenario": scenario_title, "graph_type": graph_type,
                                      "node_name": "Router", "skeleton_id": skeleton_id,
                                      "intent": nxt.lower(),
                                      "intent_confidence": router_ctx.get("intent_confidence", 0.0),
                                      "reason": router_ctx.get("reason", "")},
                        ))
                    for m in msgs:
                        if m not in accumulated:
                            accumulated.append(m)
                    continue

                if node_name == "AiTM_Interceptor":
                    for msg in msgs:
                        if not isinstance(msg, HumanMessage):
                            continue
                        _ext("AiTM_Interceptor")
                        audit_events.append(_mk(
                            event_type="message",
                            sender="AiTM_Interceptor", receiver="Router",
                            tool_name=None, tool_args=None,
                            call_path=list(call_path), content=(msg.content or "")[:500],
                            history_summary=_hs(), trace_id=trace_id, timestamp=_now(),
                            metadata={"scenario": scenario_title, "graph_type": graph_type,
                                      "node_name": "AiTM_Interceptor", "skeleton_id": skeleton_id,
                                      "is_tampered": True},
                        ))
                        accumulated.append(msg)
                    continue

                if node_name == "__end__":
                    continue

                if node_name == "Tool_Node":
                    for msg in msgs:
                        if not isinstance(msg, ToolMessage):
                            continue
                        tname = msg.name or "unknown_tool"
                        tc_id = getattr(msg, "tool_call_id", "")
                        caller, _, _ = pending_tool_calls.get(tc_id, ("unknown", tname, {}))
                        snap = list(call_path)
                        blk: List[str] = []
                        if self._is_unauthorized_caller(tname, caller):
                            blk.append("unauthorized_tool_caller")
                        missing = self._missing_required_nodes(tname, snap)
                        if missing:
                            blk.append("missing_required_path_node")
                        audit_events.append(_mk(
                            event_type="tool_result",
                            sender="Tool_Node", receiver=caller,
                            tool_name=tname, tool_args=None,
                            call_path=snap, content=str(msg.content or "")[:300],
                            history_summary=_hs(), trace_id=trace_id, timestamp=_now(),
                            metadata={"scenario": scenario_title, "graph_type": graph_type,
                                      "node_name": node_name, "skeleton_id": skeleton_id,
                                      "tool_call_id": tc_id, "blocking_risks": blk,
                                      "unauthorized": bool(blk),
                                      "intent_confidence": router_ctx.get("intent_confidence", 0.0),
                                      "reason": router_ctx.get("reason", "")},
                        ))
                    accumulated.extend(msgs)
                    continue

                # Agent 节点
                for msg in msgs:
                    if not isinstance(msg, AIMessage):
                        if msg not in accumulated:
                            accumulated.append(msg)
                        continue
                    if msg in accumulated:
                        continue

                    agent_name = getattr(msg, "name", None) or node_name
                    if agent_name not in call_path:
                        call_path.append(agent_name)
                    snap = list(call_path)
                    is_unknown = self._is_unknown_agent(agent_name)
                    content_text = msg.content or ""
                    if isinstance(content_text, list):
                        content_text = " ".join(
                            p.get("text", "") for p in content_text if isinstance(p, dict)
                        )
                    hs = _hs()

                    for tc in (msg.tool_calls or []):
                        t_name = tc.get("name", "unknown")
                        t_args = tc.get("args", {})
                        tc_id = tc.get("id") or str(uuid.uuid4())
                        pending_tool_calls[tc_id] = (agent_name, t_name, t_args)
                        blk = []
                        if self._is_unauthorized_caller(t_name, agent_name):
                            blk.append("unauthorized_tool_caller")
                        missing = self._missing_required_nodes(t_name, snap)
                        if missing:
                            blk.append(f"missing_required_path_node:{','.join(missing)}")
                        if is_unknown:
                            blk.append("unknown_agent_in_path")
                        audit_events.append(_mk(
                            event_type="tool_call",
                            sender=agent_name, receiver=None,
                            tool_name=t_name, tool_args=t_args,
                            call_path=snap, content=content_text[:300] or None,
                            history_summary=hs, trace_id=trace_id, timestamp=_now(),
                            metadata={"scenario": scenario_title, "graph_type": graph_type,
                                      "node_name": node_name, "skeleton_id": skeleton_id,
                                      "tool_call_id": tc_id, "blocking_risks": blk,
                                      "unauthorized": bool(blk), "is_unknown_agent": is_unknown,
                                      "intent_confidence": router_ctx.get("intent_confidence", 0.0),
                                      "reason": router_ctx.get("reason", "")},
                        ))

                    if content_text.strip():
                        blk = []
                        if is_unknown:
                            blk.append("unknown_agent_in_path")
                        _ext("Router")
                        audit_events.append(_mk(
                            event_type="message",
                            sender=agent_name, receiver="Router",
                            tool_name=None, tool_args=None,
                            call_path=list(call_path), content=content_text[:500],
                            history_summary=hs, trace_id=trace_id, timestamp=_now(),
                            metadata={"scenario": scenario_title, "graph_type": graph_type,
                                      "node_name": node_name, "skeleton_id": skeleton_id,
                                      "blocking_risks": blk, "is_unknown_agent": is_unknown,
                                      "has_tool_calls": bool(msg.tool_calls)},
                        ))

                    accumulated.append(msg)

        return audit_events

    # ── 场景适配器：run_scenario / flush ──────────────────────

    def run_scenario(
        self,
        title: str,
        graph_type: str,
        graph: Any,
        prompt: str,
        attack_name: str = "attack",
        recursion_limit: int = 30,
    ) -> None:
        """运行攻击场景：提取 AuditEvent，写入 per-trace JSONL。"""
        from langchain_core.messages import AIMessage, HumanMessage, ToolMessage

        self._scenario_counters[attack_name] = self._scenario_counters.get(attack_name, 0) + 1
        seq = f"{self._scenario_counters[attack_name]:03d}"
        prefix = self._scenario_prefix or "scenario"
        trace_id = f"{prefix}_{attack_name}_{seq}"

        self.set_scene_info(scene_name=attack_name, trace_id=trace_id)
        self.set_user_task(prompt)
        task_intent = self._user_task

        raw_stream: List[Dict[str, Any]] = []
        tool_calls_log: List[Dict[str, Any]] = []

        print(f"\n{'='*80}\n{title}\n{'='*80}")
        print(f"[Attacker_Input]:\n{prompt.strip()}\n")

        for event in graph.stream(
            {"messages": [HumanMessage(content=prompt)], "next": "Router"},
            {"recursion_limit": recursion_limit},
        ):
            raw_stream.append(event)
            for node_name, node_state in event.items():
                if "messages" not in node_state:
                    continue
                if node_name == "Tool_Node":
                    for msg in node_state["messages"]:
                        if isinstance(msg, ToolMessage):
                            tool_calls_log.append({"tool": msg.name or "", "result": str(msg.content)[:120]})
                    continue
                if node_name in ("Router", "__end__"):
                    continue
                for msg in node_state["messages"]:
                    if not isinstance(msg, AIMessage):
                        continue
                    if getattr(msg, "name", None) != node_name:
                        continue
                    content_str = msg.content or ""
                    if isinstance(content_str, list):
                        content_str = " ".join(
                            p.get("text", "") for p in content_str if isinstance(p, dict)
                        )
                    if content_str.strip():
                        print(f"\n[{node_name}]:\n{content_str}")

        events = self._extract_audit_events(
            stream_events=raw_stream,
            trace_id=trace_id,
            scenario_title=title,
            graph_type=graph_type,
            user_prompt=prompt,
            task_intent=task_intent,
        )

        if self.security_core:
            t_block = self.security_core.policy.threshold("rule_block")
            t_human = self.security_core.policy.threshold("human_review")
            t_llm   = self.security_core.policy.threshold("llm_needed")
            for ev in events:
                if "audit_decision" in ev.metadata:
                    continue
                try:
                    decision: AuditDecision = self.security_core.audit(ev)
                    score = decision.risk_score
                    level = ("block" if score >= t_block else
                             "human_review" if t_human > 0 and score >= t_human else
                             "llm_needed" if score >= t_llm else "pass")
                    ev.metadata["audit_decision"] = {
                        "allow": decision.allow, "risk_score": score,
                        "reason": decision.reason,
                        "blocking_risk_types": decision.blocking_risk_types,
                        "suggested_alternative": decision.suggested_alternative,
                        "level": level,
                    }
                except Exception as exc:
                    ev.metadata["audit_decision"] = {"error": str(exc)}

        self._all_trace_events.setdefault(trace_id, []).extend(events)

        sep = "-" * 60
        print(f"\n{sep}\n[攻击结果摘要]")
        if tool_calls_log:
            print(f"  触发工具调用: {len(tool_calls_log)} 次")
            for i, tc in enumerate(tool_calls_log, 1):
                print(f"    {i}. {tc['tool']} → {tc['result']}")
        else:
            print("  ✅ 攻击被防御 — 未触发任何工具调用")
        print(f"  📋 AuditEvent 生成: {len(events)} 条  (trace_id: {trace_id})")
        print(sep)

    def flush(self) -> None:
        """将所有已收集的 trace 写入 JSONL 文件（每个 trace 一个文件）。"""
        if not self._output_dir:
            return
        written = []
        for tid, evts in self._all_trace_events.items():
            path = self._output_dir / (tid + ".jsonl")
            lines = [json.dumps(self._event_to_dict(ev), ensure_ascii=False) for ev in evts]
            path.write_text("\n".join(lines) + "\n", encoding="utf-8")
            written.append((path.name, len(evts)))
        print(f"\n{'='*60}")
        print(f"📁 工作流写入完成，共 {len(written)} 个场景")
        print(f"   输出目录: {self._output_dir}")
        for name, n in written:
            print(f"   • {name}  ({n} events)")
        print(f"{'='*60}")

    @staticmethod
    def _event_to_dict(ev: AuditEvent) -> Dict[str, Any]:
        d = asdict(ev)
        safe_meta: Dict[str, Any] = {}
        for k, v in d.get("metadata", {}).items():
            try:
                json.dumps(v)
                safe_meta[k] = v
            except (TypeError, ValueError):
                safe_meta[k] = str(v)
        d["metadata"] = safe_meta
        return d
