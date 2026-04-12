"""
audited_manager.py — 带审计的 GroupChatManager

通过重写 _process_received_message 拦截所有消息，保证：
  1. initiate_chat 的 prompt 作为 SYSTEM 事件记入 history
  2. Agent 间路由产生 message 事件（A → B）
  3. 工具结果由 UserProxy 转发时不产生冗余路由事件

用法：
  manager = AuditedGroupChatManager(
      groupchat=groupchat,
      llm_config=llm_config,
      audit_adapter=adapter,
  )
  manager.set_scene_info("scene_name", "trace_id")
  user_proxy.initiate_chat(manager, message="...")
"""

import autogen
from autogen_adapter import WorkflowBlocked, BLOCKED_WORKFLOW_MESSAGE


class AuditedGroupChatManager(autogen.GroupChatManager):
    """
    带审计功能的群聊管理器。

    消息捕获策略（通过 _process_received_message）：
      - 第一条消息：记录为 SYSTEM 初始提示词（set_user_task）
      - AssistantAgent 发言：若与上一个 Assistant 不同，emit 路由 message（A → B）
      - UserProxyAgent 转发工具结果：跳过路由（已由 tool_result 事件覆盖）

    关键设计：
      - audit_adapter 通过构造函数传入，确保与工具函数共享同一个实例
      - 不依赖 monkey-patch select_speaker，而是在 _process_received_message 中可靠捕获
    """

    def __init__(self, *args, audit_adapter=None, **kwargs):
        """
        Args:
            audit_adapter: AutoGenAuditAdapter 实例（必需）
            *args, **kwargs: 传递给父类 GroupChatManager
        """
        super().__init__(*args, **kwargs)
        if audit_adapter is None:
            raise ValueError("audit_adapter 参数是必需的！请传入与工具函数相同的 adapter 实例。")
        self._audit_adapter = audit_adapter
        self.scene_name = ""
        self.trace_id = ""

        # 路由追踪状态
        self._initial_sender: str = ""          # initiate_chat 的发起者
        self._last_assistant_name: str = ""     # 最近发言的非 Proxy Agent
        self._last_assistant_content: str = ""  # 该 Agent 的最后一条消息内容

    def set_scene_info(self, scene_name: str, trace_id: str):
        """每个场景开始前调用：重置适配器状态和路由追踪。"""
        self.scene_name = scene_name
        self.trace_id = trace_id
        self._audit_adapter.reset_state(trace_id=trace_id, scenario_id=scene_name)
        self._initial_sender = ""
        self._last_assistant_name = ""
        self._last_assistant_content = ""

    def _extract_content(self, message) -> str:
        """从消息中提取内容文本。"""
        if isinstance(message, dict):
            return message.get("content", "") or ""
        elif isinstance(message, str):
            return message
        elif hasattr(message, "content"):
            return message.content or ""
        return str(message)

    def _is_tool_call_message(self, message) -> bool:
        """判断消息是否为工具调用（content 可能为空，但含 tool_calls/function_call）。"""
        if isinstance(message, dict):
            if message.get("tool_calls") or message.get("function_call"):
                return True
        return False

    def _get_last_agent_output(self, agent_name: str) -> str:
        """
        从 adapter 对话历史中获取指定 Agent 的最后有效输出。

        优先查找该 Agent 收到的 tool_result（工具执行结果），
        其次查找该 Agent 发出的 message 内容。
        用于路由事件 content，确保描述的是 Agent 的实际产出而非工具调用本身。
        """
        for entry in reversed(self._audit_adapter.conversation_history):
            etype = entry.get("type", "")
            if etype == "tool_result" and entry.get("receiver") == agent_name:
                content = entry.get("content", "")
                if content:
                    return content
            if etype == "message" and entry.get("sender") == agent_name:
                content = entry.get("content", "")
                if content:
                    return content
        return ""

    def _get_agent_name(self, agent) -> str:
        """获取 Agent 名称。"""
        if hasattr(agent, "name"):
            return agent.name
        return str(agent)

    def _process_received_message(self, message, sender, silent):
        """
        核心审计入口：AutoGen 中每条消息必经此方法。

        事件发射逻辑：
          1. 首条消息 → set_user_task（SYSTEM 初始提示词）
          2. 新的 AssistantAgent 发言 → emit message（路由事件 A → B）
          3. UserProxyAgent 转发工具结果 → 不 emit（避免与 tool_result 重复）
        """
        if self._audit_adapter._blocked:
            raise WorkflowBlocked(self._audit_adapter._blocked_reason or BLOCKED_WORKFLOW_MESSAGE)

        sender_name = self._get_agent_name(sender)
        content = self._extract_content(message)
        is_proxy = isinstance(sender, autogen.UserProxyAgent)

        # ── 1. 捕获初始提示词（initiate_chat 的 prompt）──
        if not self._audit_adapter._user_task and content:
            self._audit_adapter.set_user_task(content, sender=sender_name)
            self._initial_sender = sender_name

        # ── 2. 非 Proxy Agent 发言 → 检测路由变化，emit message ──
        is_tool_call = self._is_tool_call_message(message)

        if not is_proxy and (content and content.strip()):
            # 有文本内容的 Agent 发言 → 检测路由变化，emit message
            routing_from = self._last_assistant_name or self._initial_sender

            if routing_from and routing_from != sender_name:
                # 路由事件 content：优先用上一个 Agent 的文本消息，
                # 若为空则从对话历史中查找该 Agent 的最后有效输出（如 tool_result）
                route_content = self._last_assistant_content
                if not route_content and routing_from:
                    route_content = self._get_last_agent_output(routing_from)

                self._audit_adapter.emit_message(
                    sender=routing_from,
                    receiver=sender_name,
                    content=route_content[:500] if route_content else "",
                    metadata={
                        "scene": self.scene_name,
                        "direction": "routed",
                    },
                )

            # 更新追踪状态
            self._last_assistant_name = sender_name
            self._last_assistant_content = content

        elif not is_proxy and is_tool_call:
            # 工具调用消息（content 为空但有 tool_calls）→ 仅更新 Agent 名称
            # 不更新 _last_assistant_content，路由时从对话历史获取实际输出
            self._last_assistant_name = sender_name

        return super()._process_received_message(message, sender, silent)
