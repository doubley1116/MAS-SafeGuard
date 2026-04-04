"""
example.py — 最小可运行示例

演示如何使用 AutoGenAuditor 搭建一个带零信任审计的多智能体系统。

运行前准备：
  1. cp .env.template .env  并填入你的 API Key
  2. cp policy.yaml.template policy.yaml  并根据你的场景修改
  3. pip install -r requirements.txt

运行：
  python example.py
"""

import os
import sys
import uuid
import autogen
from dotenv import load_dotenv

from autogen_adapter import AutoGenAuditAdapter, WorkflowBlocked, BLOCKED_WORKFLOW_MESSAGE
from audited_manager import AuditedGroupChatManager
from audit_tool import audited_tool

# ═══════════════════════════════════════════════════════════════
# 1. 环境初始化
# ═══════════════════════════════════════════════════════════════

load_dotenv()

API_KEY = os.getenv("API_KEY")
BASE_URL = os.getenv("BASE_URL")
MODEL = os.getenv("MODEL")

if not API_KEY or not BASE_URL or not MODEL:
    print("请先配置 .env 文件（参考 .env.template）")
    sys.exit(1)

config_list = [{"model": MODEL, "api_key": API_KEY, "base_url": BASE_URL}]
llm_config = {"config_list": config_list, "temperature": 0, "timeout": 120}


# ═══════════════════════════════════════════════════════════════
# 2. 创建审计适配器（全局唯一，所有组件共享）
# ═══════════════════════════════════════════════════════════════

audit_adapter = AutoGenAuditAdapter(
    yaml_path="policy.yaml",   # 传入你的安全策略文件
    trace_id="2026",               # 每个场景开始时通过 reset_state 设置
)
audit_adapter.register_no_llm_agent("UserProxy")  

# ═══════════════════════════════════════════════════════════════
# 3. 定义工具函数（使用 @audited_tool 装饰器自动审计）
# ══════════════════════════════════════
# 工具的 OpenAI function calling schema
tool_a_schema = [{"type": "function", "function": {
    "name": "tool_a",
    "description": "Agent A 的查询工具",
    "parameters": {
        "type": "object",
        "properties": {"query": {"type": "string", "description": "查询内容"}},
        "required": ["query"],
    },
}}]

tool_b_schema = [{"type": "function", "function": {
    "name": "tool_b",
    "description": "Agent B 的敏感操作工具（需要 Agent A 前置审批）",
    "parameters": {
        "type": "object",
        "properties": {"action": {"type": "string", "description": "操作内容"}},
        "required": ["action"],
    },
}}]


# 使用 @audited_tool 装饰器 —— 一行代码完成审计包装
@audited_tool(adapter=audit_adapter, sender="Agent_A", tool_name="tool_a")
def tool_a(query: str) -> str:
    """Agent A 的查询工具"""
    return f"查询结果：{query} 的数据已返回"


@audited_tool(adapter=audit_adapter, sender="Agent_B", tool_name="tool_b")
def tool_b(action: str) -> str:
    """Agent B 的敏感操作工具"""
    return f"操作完成：{action}"


# ═══════════════════════════════════════════════════════════════
# 4. 定义 Agent
# ═══════════════════════════════════════════════════════════════

user_proxy = autogen.UserProxyAgent(
    name="UserProxy",
    human_input_mode="NEVER",
    max_consecutive_auto_reply=10,
    code_execution_config=False,
    system_message="你是用户代理，负责发起业务请求。",
    function_map={
        "tool_a": tool_a,
        "tool_b": tool_b,
    },
)

agent_a = autogen.AssistantAgent(
    name="Agent_A",
    llm_config={**llm_config, "tools": tool_a_schema},
    system_message="你是 Agent A，只能使用 tool_a 进行查询操作。查询完成后汇报给 UserProxy。",
)

agent_b = autogen.AssistantAgent(
    name="Agent_B",
    llm_config={**llm_config, "tools": tool_b_schema},
    system_message="你是 Agent B，只能在 Agent_A 审批通过后使用 tool_b 执行敏感操作。",
)


# ═══════════════════════════════════════════════════════════════
# 5. 组装 GroupChat + AuditedGroupChatManager
# ═══════════════════════════════════════════════════════════════

groupchat = autogen.GroupChat(
    agents=[user_proxy, agent_a, agent_b],
    messages=[],
    max_round=10,
    speaker_selection_method="auto",
)

manager = AuditedGroupChatManager(
    groupchat=groupchat,
    llm_config=llm_config,
    audit_adapter=audit_adapter,     # 传入共享的 adapter
)


# ═══════════════════════════════════════════════════════════════
# 6. 运行
# ═══════════════════════════════════════════════════════════════

if __name__ == "__main__":
    trace_id = str(uuid.uuid4())
    manager.set_scene_info(scene_name="demo", trace_id=trace_id)

    print("=" * 60)
    print("AutoGenAuditor 示例")
    print(f"Trace ID: {trace_id}")
    print("=" * 60)

    try:
        user_proxy.initiate_chat(
            manager,
            message="请帮我查询商品 A 的销售数据，如果查询成功，再进行AgentB的工具调用，调用tool_b",
            clear_history=True,
        )
    except WorkflowBlocked:
        print("\n[审计层] 工作流已被安全策略拦截")

    audit_adapter.finalize_workflow()

    print("\n" + "=" * 60)
    print("运行完毕，审计日志已保存到 audit_logs/ 目录")
    print("=" * 60)
