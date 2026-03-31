"""
audited_manager.py — 带审计的 GroupChatManager

在 AutoGen GroupChat 的 select_speaker 环节自动注入审计，
记录 Agent 间的消息路由并执行安全检查。

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
from typing import List, Dict, Any, Optional
from autogen_adapter import WorkflowBlocked, BLOCKED_WORKFLOW_MESSAGE


class AuditedGroupChatManager(autogen.GroupChatManager):
    """
    带审计功能的群聊管理器。

    审计策略：
      - 在 Manager 选定下一个发言者后进行审计
      - 记录格式：last_speaker -> next_speaker
      - receiver 直接从 next_speaker 获取，完全泛化

    关键设计：
      - audit_adapter 通过构造函数传入，确保与工具函数共享同一个实例
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

    def set_scene_info(self, scene_name: str, trace_id: str):
        """每个场景开始前调用：重置适配器状态。"""
        self.scene_name = scene_name
        self.trace_id = trace_id
        self._audit_adapter.reset_state(trace_id=trace_id, scenario_id=scene_name)

    def _extract_content(self, message) -> str:
        """从消息中提取内容文本。"""
        if isinstance(message, dict):
            return message.get("content", "") or ""
        elif isinstance(message, str):
            return message
        elif hasattr(message, "content"):
            return message.content or ""
        return str(message)

    def _get_agent_name(self, agent) -> str:
        """获取 Agent 名称。"""
        if hasattr(agent, "name"):
            return agent.name
        return str(agent)

    def _process_received_message(self, message, sender, silent):
        """接收消息时检查阻断状态。"""
        if self._audit_adapter._blocked:
            raise WorkflowBlocked(self._audit_adapter._blocked_reason or BLOCKED_WORKFLOW_MESSAGE)
        return super()._process_received_message(message, sender, silent)

    def run_chat(
        self,
        messages: Optional[List[Dict]] = None,
        sender: Optional[autogen.Agent] = None,
        config: Optional[Any] = None,
    ):
        """
        运行群聊，在 speaker 选择后自动进行审计。

        流程：
          1. 调用原始 select_speaker 选定下一个发言者
          2. 获取 last_speaker 和 next_speaker
          3. 调用 audit_adapter.emit_message() 进行安全审核
          4. 审计不通过则抛出 WorkflowBlocked
        """
        if self._audit_adapter._blocked:
            return True, BLOCKED_WORKFLOW_MESSAGE

        original_select_speaker = self.groupchat.select_speaker

        def audited_select_speaker(last_speaker, selector):
            next_speaker = original_select_speaker(last_speaker, selector)

            if next_speaker:
                last_name = self._get_agent_name(last_speaker)
                next_name = self._get_agent_name(next_speaker)

                content = ""
                if self.groupchat.messages:
                    content = self._extract_content(self.groupchat.messages[-1])

                try:
                    self._audit_adapter.emit_message(
                        sender=last_name,
                        receiver=next_name,
                        content=content[:500],
                        metadata={"scene": self.scene_name, "direction": "routed"},
                    )
                except WorkflowBlocked:
                    raise

            return next_speaker

        self.groupchat.select_speaker = audited_select_speaker

        try:
            return super().run_chat(messages=messages, sender=sender, config=config)
        finally:
            self.groupchat.select_speaker = original_select_speaker
