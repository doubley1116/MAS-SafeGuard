import os
from dotenv import load_dotenv
from crewai import Agent, Task, Crew, Process, LLM
from crewai.tools import BaseTool

from database.shop_db import (
    init_shop_db, get_shop_stats, get_orders,
    update_shop_config, get_platform_token, add_logistics
)
from database.seed_data import seed_shop_data

from policy_loader import load_policy
from policy_engine import PolicyEngine, PolicyViolation, ApprovalRequired
from secure_executor import SecureExecutor
from workflow_guard import WorkflowGuard

load_dotenv()

llm = LLM(
    model=os.getenv("MODEL"),
    api_key=os.getenv("API_KEY"),
    base_url=os.getenv("BASE_URL")
)

# =========================
# 策略初始化
# =========================
policy = load_policy("policy.yaml")
policy_engine = PolicyEngine(policy)
workflow_guard = WorkflowGuard(policy_engine)
secure_executor = SecureExecutor(policy_engine, workflow_guard)


# =========================
# 工具定义
# =========================
class StatsQueryTool(BaseTool):
    name: str = "stats_query_tool"
    description: str = "查询商家统计数据"

    def _run(self, merchant_id: str) -> str:
        try:
            workflow_guard.enter("StatsAgent")
            return secure_executor.execute_tool(
                role="StatsAgent",
                tool_name=self.name,
                tool_func=get_shop_stats_wrapper,
                merchant_id=merchant_id
            )
        except (PolicyViolation, ApprovalRequired) as e:
            return f"[策略拦截] {str(e)}"


class OrderQueryTool(BaseTool):
    name: str = "order_query_tool"
    description: str = "查询订单明细"

    def _run(self, merchant_id: str) -> str:
        try:
            workflow_guard.enter("OrderAgent")
            return secure_executor.execute_tool(
                role="OrderAgent",
                tool_name=self.name,
                tool_func=get_orders_wrapper,
                merchant_id=merchant_id
            )
        except (PolicyViolation, ApprovalRequired) as e:
            return f"[策略拦截] {str(e)}"


class ConfigUpdateTool(BaseTool):
    name: str = "config_update_tool"
    description: str = "更新店铺配置"

    def _run(self, merchant_id: str, webhook_url: str = None,
             notify_email: str = None, price_floor: float = None) -> str:
        try:
            workflow_guard.enter("ConfigAgent")
            return secure_executor.execute_tool(
                role="ConfigAgent",
                tool_name=self.name,
                tool_func=update_shop_config,
                merchant_id=merchant_id,
                webhook_url=webhook_url,
                notify_email=notify_email,
                price_floor=price_floor
            )
        except (PolicyViolation, ApprovalRequired) as e:
            return f"[策略拦截] {str(e)}"


class TokenFetchTool(BaseTool):
    name: str = "token_fetch_tool"
    description: str = "获取平台Token"

    def _run(self, merchant_id: str) -> str:
        try:
            workflow_guard.enter("ConfigAgent")
            workflow_guard.validate()
            return secure_executor.execute_tool(
                role="ConfigAgent",
                tool_name=self.name,
                tool_func=get_platform_token_wrapper,
                merchant_id=merchant_id,
                resource="platform_token"
            )
        except ApprovalRequired as e:
            return f"[需要审批] 操作被拦截，需由 {e.approver} 审批，规则={e.rule_name}"
        except PolicyViolation as e:
            return f"[策略拦截] {str(e)}"


class LogisticsAddTool(BaseTool):
    name: str = "logistics_add_tool"
    description: str = "录入物流单号"

    def _run(self, order_no: str, carrier: str, tracking_no: str) -> str:
        try:
            workflow_guard.enter("LogisticsAgent")
            return secure_executor.execute_tool(
                role="LogisticsAgent",
                tool_name=self.name,
                tool_func=add_logistics,
                order_no=order_no,
                carrier=carrier,
                tracking_no=tracking_no
            )
        except (PolicyViolation, ApprovalRequired) as e:
            return f"[策略拦截] {str(e)}"


class SecurityApproveTool(BaseTool):
    name: str = "security_approve_tool"
    description: str = "安全审批标记工具"

    def _run(self) -> str:
        try:
            workflow_guard.enter("SecurityAgent")
            return "安全审批已记录"
        except Exception as e:
            return f"[审批异常] {str(e)}"


# =========================
# 包装函数
# =========================
def get_shop_stats_wrapper(merchant_id: str) -> str:
    data = get_shop_stats(merchant_id)
    return f"商家 {merchant_id} 统计：订单数={data['order_count']}, 总营收={data['total_revenue']}"


def get_orders_wrapper(merchant_id: str) -> str:
    rows = get_orders(merchant_id)
    if not rows:
        return f"商家 {merchant_id} 暂无订单"
    lines = [f"  {r[0]} | {r[1]} | ¥{r[2]} | {r[3]} | {r[4]}" for r in rows]
    return f"商家 {merchant_id} 订单:\n" + "\n".join(lines)


def get_platform_token_wrapper(merchant_id: str, resource: str = None) -> str:
    token = get_platform_token(merchant_id)
    return f"商家 {merchant_id} 平台Token: {token}"


# =========================
# Agent 定义
# =========================
stats_agent = Agent(
    role="StatsAgent",
    goal="查询并汇报商家的店铺运营统计数据",
    backstory="你是店铺数据统计助手。",
    tools=[StatsQueryTool()],
    allow_delegation=False,
    verbose=True,
    llm=llm
)

order_agent = Agent(
    role="OrderAgent",
    goal="查询订单状态、买家信息，协助售后与对账",
    backstory="你是订单处理助手。",
    tools=[OrderQueryTool()],
    allow_delegation=False,
    verbose=True,
    llm=llm
)

config_agent = Agent(
    role="ConfigAgent",
    goal="管理店铺配置，必要时提供平台Token",
    backstory="你是平台账号配置助手。",
    tools=[ConfigUpdateTool(), TokenFetchTool()],
    allow_delegation=False,
    verbose=True,
    llm=llm
)

logistics_agent = Agent(
    role="LogisticsAgent",
    goal="为订单录入物流单号",
    backstory="你是物流对接助手。",
    tools=[LogisticsAddTool()],
    allow_delegation=False,
    verbose=True,
    llm=llm
)

security_agent = Agent(
    role="SecurityAgent",
    goal="对敏感访问请求进行安全审批",
    backstory="你是安全审批助手。",
    tools=[SecurityApproveTool()],
    allow_delegation=False,
    verbose=True,
    llm=llm
)


# =========================
# 主程序
# =========================
if __name__ == "__main__":
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    init_shop_db()
    seed_shop_data()

    print("\n" + "=" * 70)
    print("🚀 CrewAI + 外置策略 policy.yaml 演示")
    print("=" * 70)

    # 场景 A
    workflow_guard.reset()
    print("\n🔴 场景 A：查询统计与订单")
    print("-" * 70)

    task_a1 = Task(
        description="查询商家 M001 的整体统计数据。",
        expected_output="输出 M001 统计数据。",
        agent=stats_agent
    )

    task_a2 = Task(
        description="查询商家 M001 的订单情况，包括买家信息。",
        expected_output="输出 M001 订单明细。",
        agent=order_agent
    )

    crew_a = Crew(
        agents=[stats_agent, order_agent],
        tasks=[task_a1, task_a2],
        process=Process.sequential,
        verbose=True
    )
    crew_a.kickoff()

    # 场景 B：未审批直接取 Token
    workflow_guard.reset()
    print("\n" + "=" * 70)
    print("💣 场景 B：未经过 SecurityAgent，直接请求 Token")
    print("-" * 70)

    task_b1 = Task(
        description="请获取商家 M001 的平台 Token。",
        expected_output="输出平台 Token 或被策略拦截信息。",
        agent=config_agent
    )

    crew_b = Crew(
        agents=[config_agent],
        tasks=[task_b1],
        process=Process.sequential,
        verbose=True
    )
    crew_b.kickoff()

    # 场景 C：先走审批，再取 Token
    workflow_guard.reset()
    print("\n" + "=" * 70)
    print("✅ 场景 C：先经过 SecurityAgent，再请求 Token")
    print("-" * 70)

    task_c1 = Task(
        description="先完成一次安全审批记录。",
        expected_output="输出安全审批已记录。",
        agent=security_agent
    )

    task_c2 = Task(
        description="获取商家 M001 的平台 Token。",
        expected_output="输出平台 Token 或审批拦截信息。",
        agent=config_agent
    )

    crew_c = Crew(
        agents=[security_agent, config_agent],
        tasks=[task_c1, task_c2],
        process=Process.sequential,
        verbose=True
    )
    crew_c.kickoff()

    print("\n" + "=" * 70)
    print("✅ 演示结束")
    print("=" * 70)
