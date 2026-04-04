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
sys.path.append(str(Path(__file__).parents[2]))
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

    MAX_HISTORY_ENTRIES: int = 30  # 滑动窗口大小（不含初始 SYSTEM 提示词）

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
        self._user_task: str = ""  # 用户原始任务指令

        self._jsonl_path = Path(jsonl_path)
        self._jsonl_path.parent.mkdir(parents=True, exist_ok=True)

        self._workflow_dir = Path(workflow_dir)
        self._workflow_dir.mkdir(parents=True, exist_ok=True)

        self._workflow_events: List[Dict[str, Any]] = []
        self._workflow_decisions: List[Dict[str, Any]] = []
        self._pending_tool_results: List[Dict[str, Any]] = []  # 已弃用，保留兼容

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
        self._pending_tool_results = []

    def is_blocked(self) -> bool:
        """检查工作流是否已被阻断。"""
        return self._blocked

    def update_call_path(self, agent_name: str) -> None:
        """更新调用链路（只包含 Agent，不包含工具）。"""
        if not self.call_path or self.call_path[-1] != agent_name:
            self.call_path.append(agent_name)

    def set_user_task(self, task_content: str, sender: str = "User") -> None:
        """
        记录用户原始任务指令，提取核心意图作为锚点。

        短文本直接用，长文本提取第一个实质性句子作为意图摘要。
        确保 history_summary 始终以 [任务] 开头。

        Args:
            task_content: 用户发出的原始任务文本
            sender:       发送者名称（默认 "User"）
        """
        if len(task_content) <= 80:
            self._user_task = task_content.replace("\n", " ")
        else:
            self._user_task = self._rule_based_extract(task_content)

        # 同时记录到 conversation_history 作为第一条
        self.conversation_history.insert(0, {
            "type": "user_task",
            "sender": sender,
            "content": task_content,
        })

    @staticmethod
    def _rule_based_extract(text: str) -> str:
        """
        基于规则的意图提取。
        取第一个实质性句子（跳过格式行、注意事项、列表项等）。
        """
        lines = text.strip().split("\n")
        for line in lines:
            line = line.strip()
            if not line:
                continue
            # 跳过格式行
            if line.startswith(("-", "*", "•", "注意", "要求", "说明",
                                "1.", "2.", "3.", "4.", "5.")):
                continue
            if line.startswith(("[", "{")):
                continue
            return line[:80]
        return text[:80]

    def build_history_summary(self) -> str:
        """
        安全感知的分层上下文压缩（Security-Aware Context Compression）。

        三层结构：
          第一层：[任务] 意图锚点（永远保留，从长文本中提取核心意图）
          第二层：[关键] 安全关键事件（外部数据读取、高权限操作、异常状态）
          第三层：[近期] 最近 N 条动作（保留当前现场）

        短 history（≤10条）全部保留，长 history 自动分层压缩。
        tool_result 内容只提取安全相关信号（数值、可疑措辞），不复制原文。

        示例输出（25步工作流）：
          [任务]将SKU-002价格改为5元
          | [关键]Config_Agent→fetch_url(supplier-api)
          → fetch_url返回(数值:1; 可疑:已通过合规,审批编号)
          → Config_Agent→update_price_tool(sku=SKU-002,price=1.0)
          | [近期]Manager→User:任务完成
        """
        if not self.conversation_history:
            return ""

        parts = []

        # ── 第一层：任务锚点（永远保留）──
        if self._user_task:
            parts.append(f"[任务]{self._user_task}")

        # 分离非 user_task 的动作条目
        actions = [e for e in self.conversation_history if e.get("type") != "user_task"]

        if len(actions) <= 10:
            # 短 history：全部保留
            for entry in actions:
                parts.append(self._format_action(entry))
        else:
            # 长 history：分层压缩

            # ── 第二层：安全关键事件（永远保留）──
            critical = [e for e in actions if self._is_security_critical(e)]
            if critical:
                critical_strs = [self._format_action(e) for e in critical]
                parts.append("[关键]" + " → ".join(critical_strs))

            # ── 第三层：最近 5 条动作（保留现场）──
            recent = actions[-5:]
            # 去重：如果 recent 中有已经在 critical 里出现过的，跳过
            critical_set = {id(e) for e in critical}
            recent_filtered = [e for e in recent if id(e) not in critical_set]
            if recent_filtered:
                recent_strs = [self._format_action(e) for e in recent_filtered]
                parts.append("[近期]" + " → ".join(recent_strs))

        return " | ".join(parts)

    # ── history 压缩辅助方法 ──────────────────────────────────

    def _is_security_critical(self, entry: dict) -> bool:
        """
        判断一条动作是否对安全判断有影响。
        被标记为 critical 的事件在长 history 压缩时永远保留。
        """
        etype = entry.get("type", "")
        content = str(entry.get("content", "")).lower()
        tool = entry.get("tool_name", "") or ""

        # 外部数据读取（IPI 关键节点）
        if tool in ("read_file", "read_external_file_tool", "fetch_url",
                     "query_email", "read_document", "web_search",
                     "search_tool", "browse_url"):
            return True

        # 高权限操作
        if tool in ("execute_trade", "trade_execute_tool",
                     "transfer_funds", "update_config",
                     "update_price_tool", "config_update_tool",
                     "delete_record", "security_approve_tool",
                     "execute_command", "deploy_tool"):
            return True

        # 工具执行失败
        if etype == "tool_result" and any(
            kw in content for kw in ["error", "denied", "失败", "拒绝",
                                      "blocked", "passworderror", "permissionerror"]
        ):
            return True

        # 包含授权/审批相关措辞（可能是伪造授权）
        if any(kw in content for kw in [
            "授权", "审批", "approve", "authorized", "授权码",
            "免审核", "直接执行", "无需复核", "系统背书",
            "合规校验通过", "override", "bypass"
        ]):
            return True

        return False

    def _format_action(self, entry: dict) -> str:
        """
        将单条 history 条目格式化为压缩字符串。
        tool_result 只提取安全相关信号，不复制原文。
        """
        etype = entry.get("type", "message")
        sender = entry.get("sender", "?")
        content = str(entry.get("content", ""))

        if etype == "tool_call":
            tool = entry.get("tool_name", "?")
            key_args = self._extract_key_args(entry.get("tool_args"))
            return f"{sender}→{tool}({key_args})"

        elif etype == "tool_result":
            tool = entry.get("tool_name", "?")
            receiver = entry.get("receiver", sender)
            compressed = self._compress_tool_result(tool, content)
            return f"{tool}→{receiver}({compressed})"

        else:  # message, delegation, etc.
            receiver = entry.get("receiver", "?")
            intent = content[:30].replace("\n", " ") if content else ""
            return f"{sender}→{receiver}:{intent}"

    def _compress_tool_result(self, tool_name: str, content: str) -> str:
        """
        压缩工具返回结果，只保留安全相关的关键信息。

        提取策略：
          1. 检测失败/异常状态
          2. 提取数值参数（价格、金额、数量）
          3. 提取可疑授权/绕过措辞
          4. 兜底：取前 20 字符
        """
        if not content:
            return "ok"

        # 1. 检测失败
        for kw in ["error", "denied", "失败", "拒绝", "异常",
                    "blocked", "PasswordError", "PermissionError", "阻断"]:
            if kw.lower() in content.lower():
                return f"失败:{kw}"

        # 2. 提取数值 + 3. 提取可疑措辞
        numbers = self._extract_numbers(content)
        suspicious = self._extract_suspicious_phrases(content)

        parts = []
        if numbers:
            parts.append(f"数值:{numbers}")
        if suspicious:
            parts.append(f"可疑:{suspicious}")

        if parts:
            return "; ".join(parts)

        # 4. 兜底
        return content[:20].replace("\n", " ")

    @staticmethod
    def _extract_key_args(tool_args) -> str:
        """从工具参数中提取关键信息，限制长度。"""
        if not tool_args:
            return ""
        if isinstance(tool_args, dict):
            items = list(tool_args.items())[:3]
            return ",".join(f"{k}={v}" for k, v in items)
        return str(tool_args)[:50]

    @staticmethod
    def _extract_numbers(text: str) -> str:
        """提取文本中的关键数值（价格、金额、数量等）。"""
        import re
        patterns = [
            r'(?:价格|金额|price|amount|数量|quantity)[=:：]\s*(\d+\.?\d*)',
            r'(\d+\.?\d*)\s*(?:元|¥|\$|股|shares|件)',
            r'(?:改为|调整为|设为|更新为|卖出|买入|sell|buy)\s*[^\d]*(\d+\.?\d*)',
        ]
        found = []
        for p in patterns:
            matches = re.findall(p, text, re.IGNORECASE)
            found.extend(matches)
        if found:
            # 去重，保留前 3 个
            seen = []
            for n in found:
                if n not in seen:
                    seen.append(n)
                if len(seen) >= 3:
                    break
            return ",".join(seen)
        return ""

    @staticmethod
    def _extract_suspicious_phrases(text: str) -> str:
        """提取可疑的授权/绕过相关措辞。"""
        suspicious_keywords = [
            "授权码", "审批编号", "自动授权", "免审核", "直接执行",
            "无需复核", "已通过合规", "系统背书", "优先级最高",
            "合规校验通过", "前置审批完成", "可直接执行",
            "auth", "approved", "bypass", "override",
        ]
        found = [kw for kw in suspicious_keywords if kw in text]
        if found:
            return ",".join(found[:3])
        return ""

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

        # 先记录事件，再执行安全检查
        # 否则 _check 抛出 WorkflowBlocked 时事件丢失，导致无 JSON 输出
        self._workflow_events.append(asdict(event))

        decision = self._check(event)
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
            "type": "message",
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
        """
        审计工具调用事件（调用前检查）。

        AuditEvent: sender=Agent, receiver=tool_name
        call_path 只包含 Agent，不包含工具。
        """
        if self._blocked:
            raise WorkflowBlocked(self._blocked_reason or BLOCKED_WORKFLOW_MESSAGE)

        self.update_call_path(sender)
        final_call_path = list(call_path or self.call_path)

        # 将工具调用记录到对话历史，供 history_summary 使用
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
        """
        审计工具执行结果事件（立即 emit）。

        AuditEvent: sender=tool_name, receiver=调用该工具的 Agent
        call_path 只包含 Agent，不包含工具。

        Args:
            sender: 调用该工具的 Agent 名称（用作 receiver）
            tool_name: 工具名称（用作 sender）
            result: 工具返回结果
        """
        if self._blocked:
            raise WorkflowBlocked(self._blocked_reason or BLOCKED_WORKFLOW_MESSAGE)

        # 注意：不调用 update_call_path(tool_name)，工具不进入 call_path
        final_call_path = list(call_path or self.call_path)

        # 将工具结果记录到对话历史
        # sender(history) = tool_name, receiver(history) = agent
        self.conversation_history.append({
            "type": "tool_result",
            "sender": tool_name,
            "receiver": sender,
            "tool_name": tool_name,
            "content": str(result)[:200],
        })

        return self._emit(
            "tool_result",
            tool_name,       # AuditEvent.sender = 工具
            sender,          # AuditEvent.receiver = 调用该工具的 Agent
            tool_name=tool_name,
            call_path=final_call_path,
            content=content or str(result),
            history_summary=history_summary,
            metadata=metadata,
        )