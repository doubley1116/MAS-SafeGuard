"""
example.py — LangGraphAuditor 最小可运行示例（电商场景）

运行前准备：
  1. cd LangGraphAuditor
  2. cp .env.template .env  并填入你的 API Key
  3. cp policy.yaml.template policy.yaml
  4. pip install -r requirements.txt
  5. python example.py
"""

import os
import sys
import uuid

from dotenv import load_dotenv
from langchain_core.messages import HumanMessage
from langchain_openai import ChatOpenAI
from langgraph.graph import END, START, StateGraph
from langgraph.prebuilt import ToolNode
from typing import Annotated, TypedDict
from langgraph.graph.message import add_messages

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)                     # LangGraphAuditor/ — 本地模块
sys.path.insert(0, os.path.dirname(_HERE))    # 项目根目录 — audit_layer

from audit_tool import audited_tool
from audited_graph import AuditedGraph
from langgraph_adapter import LangGraphAuditAdapter, WorkflowBlocked

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


# ═══════════════════════════════════════════════════════════════
# 2. 创建审计适配器
# ═══════════════════════════════════════════════════════════════

audit_adapter = LangGraphAuditAdapter(
    yaml_path="policy.yaml",
)


# ═══════════════════════════════════════════════════════════════
# 3. 定义工具（使用 @audited_tool 自动审计）
# ═══════════════════════════════════════════════════════════════

@audited_tool(adapter=audit_adapter, sender="Stats_Node", tool_name="stats_query_tool")
def stats_query_tool(merchant_id: str) -> str:
    """查询商家的统计数据。"""
    return f"商家 {merchant_id} 的统计数据：销售额 12,000 元，订单量 58 单"


@audited_tool(adapter=audit_adapter, sender="Config_Node", tool_name="config_update_tool")
def config_update_tool(merchant_id: str, discount: float) -> str:
    """更新商家折扣配置（敏感操作）。"""
    return f"商家 {merchant_id} 折扣已更新为 {discount}"


# ═══════════════════════════════════════════════════════════════
# 4. 构建 LangGraph 图
# ═══════════════════════════════════════════════════════════════

class State(TypedDict):
    messages: Annotated[list, add_messages]


stats_llm = ChatOpenAI(
    model=MODEL, base_url=BASE_URL, api_key=API_KEY, temperature=0,
).bind_tools([stats_query_tool])

config_llm = ChatOpenAI(
    model=MODEL, base_url=BASE_URL, api_key=API_KEY, temperature=0,
).bind_tools([config_update_tool])


def stats_node(state: State) -> dict:
    response = stats_llm.invoke(state["messages"])
    return {"messages": [response]}


def config_node(state: State) -> dict:
    response = config_llm.invoke(state["messages"])
    return {"messages": [response]}


def should_continue(state: State) -> str:
    last = state["messages"][-1]
    if hasattr(last, "tool_calls") and last.tool_calls:
        return "tools"
    return END


tool_executor = ToolNode([stats_query_tool, config_update_tool])

builder = StateGraph(State)
builder.add_node("Stats_Node", stats_node)
builder.add_node("Config_Node", config_node)
builder.add_node("tools", tool_executor)
builder.add_edge(START, "Stats_Node")
builder.add_conditional_edges("Stats_Node", should_continue)
builder.add_conditional_edges("Config_Node", should_continue)
builder.add_edge("tools", END)
graph = builder.compile()


# ═══════════════════════════════════════════════════════════════
# 5. 用 AuditedGraph 包装
# ═══════════════════════════════════════════════════════════════

audited_graph = AuditedGraph(graph=graph, audit_adapter=audit_adapter)


# ═══════════════════════════════════════════════════════════════
# 6. 运行场景
# ═══════════════════════════════════════════════════════════════

def run_scene(name: str, message: str) -> None:
    trace_id = str(uuid.uuid4())
    audited_graph.set_scene_info(scene_name=name, trace_id=trace_id)

    print("\n" + "=" * 60)
    print(f"场景: {name}")
    print(f"用户输入: {message}")
    print(f"Trace ID: {trace_id}")
    print("=" * 60)

    try:
        result = audited_graph.invoke({"messages": [HumanMessage(content=message)]})
        last_msg = result["messages"][-1]
        print(f"结果: {getattr(last_msg, 'content', str(last_msg))}")
    except WorkflowBlocked as e:
        print(f"[审计层] 工作流已被安全策略拦截: {e}")
    finally:
        audit_adapter.finalize_workflow()
        print(f"调用路径: {audit_adapter.call_path}")


if __name__ == "__main__":
    run_scene(
        name="正常查询",
        message="请查询商家 M001 的销售统计数据",
    )
    run_scene(
        name="配置修改",
        message="请将商家 M001 的折扣更新为 0.9",
    )

    print("\n" + "=" * 60)
    print("运行完毕，审计日志已保存到 audit_logs/ 目录")
    print("=" * 60)
