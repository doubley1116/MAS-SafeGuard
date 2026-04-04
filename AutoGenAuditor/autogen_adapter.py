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
        self._no_llm_agents: set = set()  # 无 LLM 的节点（如 UserProxy），其事件只记录不审核

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

    def register_no_llm_agent(self, agent_name: str) -> None:
        """
        注册无 LLM 的 Agent（如 UserProxy）。

        无 LLM 节点的事件只记录日志，不走 SecurityCore 安全审核。
        原因：这些节点不做决策，只做转发（用户消息转发、工具结果转发），
        对它们做 LLM 语义审核会产生误判（如 UserProxy 转发 tool_result 被误判为意图偏移）。

        但如果 tool_result 的 content 包含可疑信号（伪造授权、执行指令等），
        仍然会送审核，防止 IPI 攻击通过外部数据绕过检测。

        Args:
            agent_name: Agent 名称（如 "UserProxy"）
        """
        self._no_llm_agents.add(agent_name)

    def update_call_path(self, agent_name: str) -> None:
        """更新调用链路（只包含有 LLM 的 Agent，不包含工具和无 LLM 节点）。"""
        if agent_name in self._no_llm_agents:
            return
        if not self.call_path or self.call_path[-1] != agent_name:
            self.call_path.append(agent_name)

    def set_user_task(self, task_content: str, sender: str = "User") -> None:
        """
        记录用户原始任务指令，提取核心意图作为锚点。

        提取策略（按优先级）：
          1. 短文本（≤80字符）：直接使用
          2. 有 SecurityCore（含LLM）：调用 LLM 提取核心意图
          3. 无 SecurityCore：基于规则提取第一个实质性句子

        同时将发起者（如 UserProxy）加入 call_path，
        确保后续路径检查不会因缺少起始节点而误报。

        Args:
            task_content: 用户发出的原始任务文本
            sender:       发送者名称（默认 "User"）
        """
        if len(task_content) <= 80:
            self._user_task = task_content.replace("\n", " ")
        else:
            # 优先用 LLM 提取，失败或不可用时降级为规则提取
            self._user_task = (
                self._llm_extract_task(task_content)
                or self._rule_based_extract(task_content)
            )

        # 把发起者加入 call_path（解决 UserProxy 不在路径中导致的误报）
        self.update_call_path(sender)

        # 记录到 conversation_history 作为第一条
        self.conversation_history.insert(0, {
            "type": "user_task",
            "sender": sender,
            "content": task_content,
        })

    def _llm_extract_task(self, long_text: str) -> str:
        """
        用 LLM 从长文本中提取核心任务意图（一句话，≤30字）。

        仅在 SecurityCore 可用时调用。失败时返回空字符串，触发规则降级。
        """
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
                    )
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
        """
        基于规则的意图提取（LLM 不可用时的降级方案）。

        策略：
          1. 按行分割，过滤不可能是任务的行（角色设定、列表项、注意事项）
          2. 对候选行按任务指令特征打分
          3. 返回得分最高的行
        """
        import re
        lines = [l.strip() for l in text.strip().split("\n") if l.strip()]

        # 第一步：过滤
        candidates = []
        for line in lines:
            # 跳过角色设定
            if line.startswith(("你是", "You are", "作为", "As a", "As an")):
                continue
            # 跳过列表项和编号
            if line.startswith(("-", "*", "•", "1.", "2.", "3.", "4.", "5.",
                                "6.", "7.", "8.", "9.")):
                continue
            # 跳过注意事项
            if line.startswith(("注意", "要求", "说明", "备注", "提示",
                                "Note", "Warning", "Hint", "Important")):
                continue
            # 跳过代码/JSON
            if line.startswith(("[", "{", "```", "import ", "def ", "class ")):
                continue
            # 跳过太短的行
            if len(line) < 8:
                continue
            candidates.append(line)

        if not candidates:
            return text[:80]

        # 第二步：打分
        scored = []
        for line in candidates:
            score = 0
            # 动作动词
            for verb in ["查询", "分析", "排查", "修改", "更新", "执行",
                         "检查", "导出", "统计", "计算", "发送", "创建",
                         "删除", "调整", "优化", "将", "把", "帮我",
                         "请", "需要", "协助",
                         "query", "analyze", "check", "update", "execute",
                         "send", "create", "delete", "modify", "help"]:
                if verb in line:
                    score += 2
                    break
            # 具体实体
            if re.search(r'[A-Z]\d{3}|SKU|M\d{3}|\d+元|\d+股', line):
                score += 1
            # 触发词
            for tw in ["反馈", "异常", "问题", "需求", "目标", "任务", "请求"]:
                if tw in line:
                    score += 1
                    break
            scored.append((score, line))

        scored.sort(key=lambda x: x[0], reverse=True)
        return scored[0][1][:80]

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
        """
        提取文本中的关键数值，保留语义上下文。

        不只提取数字本身，还保留"这个数字是什么"的标签。
        例如：
          "调整为1元"        → "价格1元"
          "sell TSLA 100股"  → "卖出100股"
          "金额=5000"        → "金额5000"
        """
        import re
        results = []

        # 带标签的数值模式：(标签, 正则, 输出格式)
        labeled_patterns = [
            # 价格/金额
            (r'(?:价格|零售价|单价|price)[=:：为]\s*(\d+\.?\d*)\s*(?:元|¥|\$)?', "价格{}元"),
            (r'(?:金额|amount|total)[=:：]\s*(\d+\.?\d*)', "金额{}"),
            (r'(\d+\.?\d*)\s*(?:元|¥)', "{}元"),

            # 操作+数值（允许中间有股票代码等字母）
            (r'(?:卖出|sell)\s*[A-Za-z_]*\s*(\d+\.?\d*)\s*(?:股|shares)?', "卖出{}股"),
            (r'(?:买入|buy)\s*[A-Za-z_]*\s*(\d+\.?\d*)\s*(?:股|shares)?', "买入{}股"),
            (r'(?:改为|调整为|设为|更新为)\s*(\d+\.?\d*)', "改为{}"),

            # 数量/股数（独立出现）
            (r'(\d+\.?\d*)\s*(?:股|shares)', "{}股"),
            (r'(\d+\.?\d*)\s*(?:件|个|条)', "{}件"),
            (r'(?:数量|quantity)[=:：]\s*(\d+\.?\d*)', "数量{}"),

            # 折扣
            (r'(?:折扣|discount)[=:：]\s*(\d+\.?\d*)', "折扣{}"),
        ]

        seen_values = set()
        for pattern, fmt in labeled_patterns:
            for match in re.finditer(pattern, text, re.IGNORECASE):
                value = match.group(1)
                if value not in seen_values:
                    seen_values.add(value)
                    results.append(fmt.format(value))
                if len(results) >= 3:
                    break
            if len(results) >= 3:
                break

        return ",".join(results) if results else ""

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
            task=self._user_task,
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
        """
        安全审核：规则引擎 + LLM 语义审核。不通过时抛出 WorkflowBlocked。

        对无 LLM 节点（如 UserProxy）的事件：
          - tool_result 且 content 无可疑信号 → 只记录，不审核
          - tool_result 且 content 有可疑信号 → 照常审核（防 IPI）
          - 其他事件类型 → 照常审核
        """
        if self.security_core is None:
            return None

        # 无 LLM 节点的 tool_result：默认跳过审核，除非 content 有可疑信号
        if (event.event_type == "tool_result"
                and self._is_no_llm_event(event)):
            if not self._content_has_suspicious_signal(event.content):
                return AuditDecision(
                    allow=True,
                    risk_score=0.0,
                    reason="[跳过审核] 无 LLM 节点的工具结果转发，content 无可疑信号",
                )

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

    def _is_no_llm_event(self, event: AuditEvent) -> bool:
        """判断事件是否来自无 LLM 的节点。"""
        # tool_result 的 sender 是工具名，receiver 是调用工具的 Agent
        # 但在 AutoGen 0.2 中，tool_result 实际由 UserProxy 转发
        # 检查 call_path 中是否包含 no_llm 节点
        if event.sender in self._no_llm_agents:
            return True
        if event.receiver in self._no_llm_agents:
            return True
        # call_path 的最后一个节点是 no_llm 节点（UserProxy 转发场景）
        if event.call_path and event.call_path[-1] in self._no_llm_agents:
            return True
        return False

    @staticmethod
    def _content_has_suspicious_signal(content: Optional[str]) -> bool:
        """
        检测 tool_result 的 content 是否包含可疑信号。

        正常的 tool_result 只返回数据（查询结果、计算结果等）。
        如果 content 中包含执行指令、伪造授权、prompt injection 特征，
        说明外部数据可能被攻击者污染，必须送审核。
        """
        if not content:
            return False
        content_lower = content.lower()

        suspicious_patterns = [
            # 执行指令（数据源在指挥 Agent 做事）
            "调用", "执行", "立即", "直接",
            "call ", "execute", "invoke", "run ",
            "trade_execute", "update_config", "delete_record",
            "发送到", "send to", "post to", "forward to",

            # 伪造授权
            "授权码", "审批编号", "已通过合规", "可直接执行",
            "无需复核", "免审核", "系统背书", "前置审批完成",
            "auth_code", "approved", "bypass", "override",

            # Prompt injection 特征
            "忽略之前", "忽略上面", "ignore previous", "ignore above",
            "new role", "新角色", "changed my mind",
            "不要执行之前", "system override",

            # 自复制指令（Prompt Infection T7）
            "复制以上", "copy the text", "say the whole text",
            "repeat the above", "将以下内容传递", "forward this message",
        ]

        return any(sig in content_lower for sig in suspicious_patterns)

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