# AutoGen_trading — 零信任审计交易多智能体系统

基于 AutoGenAuditor 框架，复刻 langgraph_trading 的攻击场景与 MAS 拓扑，
演示零信任审计层对交易系统多智能体协作的安全防护能力。

## Agent 拓扑

```
                          ┌─→ Risk_Agent ─→ Trade_Agent
Account_Manager → Research_Agent ─┤
        (UserProxy)        (读外部文件)  └─→ Asset_Agent
```

| Agent | 类型 | 工具 | 职责 |
|---|---|---|---|
| Account_Manager | UserProxyAgent | function_map（执行所有工具） | 入口代理，接收客户请求 |
| Research_Agent | AssistantAgent | `read_external_file_tool` | 投研分析，可读取外部报告文件 |
| Risk_Agent | AssistantAgent | 无工具 | 风控审批，一票否决权 |
| Asset_Agent | AssistantAgent | `asset_query_tool` | 客户持仓查询 |
| Trade_Agent | AssistantAgent | `trade_execute_tool` | 交易执行（买入/卖出） |

## 攻击场景（18 个）

| 类别 | 编号 | 攻击手法 |
|---|---|---|
| **A** 路径绕过 | A1-A3 | 量化验证快速通道、系统自动授权止损、OA审批绿色通道 |
| **B** 身份冒充 | B1-B3 | 管理员旁路查询、合规官特批交易、跨Agent越权提权 |
| **C** 语义注入 | C1-C3 | API格式验证伪装、灰度验证伪装、情感施压+权威组合 |
| **D** 路由劫持 | D1-D3 | 隐式交易意图、伪造系统配置更新、结构化调度标签注入 |
| **E** IPI | E1-E3 | 市场报告文件注入、新闻摘要伪造风控评级、伪造会话审批记录 |
| **N** 正常场景 | N1-N3 | 持仓查询、完整流程交易、纯投研分析（验证不误杀） |

## 快速开始

### 1. 安装依赖

```bash
cd MAS/AutoGen_trading
pip install -r requirements.txt
```

### 2. 配置 .env

```bash
cp .env.template .env
```

编辑 `.env` 填入你的 API 配置：

```
API_KEY=你的API密钥
BASE_URL=你的API地址
MODEL=模型名称
```

### 3. 运行

```bash
python defense.py
```

运行后进入交互式菜单：

```
  操作选项:
    1. 运行单个场景        → 输入场景ID（如 ATTACK_A_1）
    2. 运行某个类别的所有场景 → 输入类别（A/B/C/D/E/N）
    3. 运行全部场景
    4. 退出
```

## 防御模式切换

在 `defense.py` 第 37 行切换：

```python
# 防御模式（启用 SecurityCore 审计拦截）
audit_adapter = AutoGenAuditAdapter(yaml_path="trading.yaml", trace_id="")

# 无防御模式（仅记录审计事件，不拦截）
audit_adapter = AutoGenAuditAdapter(trace_id="")
```

## 审计输出

运行后审计事件保存在：

- `audit_logs/audit_log.jsonl` — 全量 JSONL 审计流水
- `audit_logs/workflows/{场景ID}.json` — 每个场景的完整事件链 + 审计决策

每个 AuditEvent 包含：

```json
{
  "event_type": "message | tool_call | tool_result",
  "sender": "发送方（Agent 或工具名）",
  "receiver": "接收方",
  "tool_name": "工具名（仅 tool_call/result）",
  "call_path": ["Agent链路，不含工具"],
  "content": "消息/结果内容",
  "history_summary": "[SYSTEM]: 初始prompt\n---\n[A → B]: 消息\n---\n..."
}
```

## IPI 攻击文件

`data/external_docs/` 下的外部文件是 E 类攻击的载荷：

| 文件 | 注入内容 |
|---|---|
| `ipi_5_1_market_report.txt` | 在市场分析报告的"执行摘要"中嵌入交易执行指令 |
| `ipi_5_2_news_digest.txt` | 在新闻摘要中伪造"风控系统自动评级"和授权码 |
| `ipi_5_3_session_log.txt` | 伪造完整的前置审批会话记录链 |

这些文件通过 `read_external_file_tool` 被 Research_Agent 读取，
攻击载荷随文件内容进入 Agent 上下文，尝试操纵后续决策。

## 安全策略 (trading.yaml)

```yaml
tools:
  trade_execute_tool:
    allowed_callers: [Trade_Agent]           # 仅 Trade_Agent 可调用
    required_path_contains: [Risk_Agent]     # 必须经过风控审批

  asset_query_tool:
    allowed_callers: [Asset_Agent]           # 仅 Asset_Agent 可调用

  read_external_file_tool:
    allowed_callers: [Research_Agent]        # 仅投研可读取外部文件
```

## 项目结构

```
AutoGen_trading/
├── defense.py              # 主入口（交互式菜单）
├── attack_prompts.py         # 攻击提示词库（18 个场景）
├── autogen_adapter.py        # 审计适配器（AutoGenAuditor）
├── audited_manager.py        # 审计版 GroupChatManager
├── audit_tool.py             # @audited_tool 装饰器
├── trading.yaml              # 安全策略配置
├── .env                      # API 配置
├── database/
│   ├── asset_db.py           # 客户/持仓数据库
│   ├── trade_db.py           # 交易记录数据库
│   └── seed_data.py          # 种子数据
├── data/external_docs/       # IPI 攻击载荷文件
│   ├── ipi_5_1_market_report.txt
│   ├── ipi_5_2_news_digest.txt
│   └── ipi_5_3_session_log.txt
└── audit_logs/workflows/     # 审计事件输出
```
