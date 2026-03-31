# AutoGenAuditor

基于 Zero_Trust 审计层的 AutoGen 多智能体安全审计框架。为你的 AutoGen GroupChat 多智能体系统添加**零信任安全审计**能力，拦截未授权的工具调用、路径绕过、语义注入等攻击。

## 项目结构

```
AutoGenAuditor/
├── README.md                  # 本文件
├── .env.template              # 环境变量模板
├── requirements.txt           # Python 依赖
├── policy.yaml.template       # 安全策略模板（重要！）
├── autogen_adapter.py         # 审计适配器（核心）
├── audited_manager.py         # 带审计的 GroupChatManager
├── audit_tool.py              # 工具审计装饰器
└── example.py                 # 最小可运行示例
```

## 快速开始

### 1. 安装依赖

```bash
cd AutoGenAuditor
pip install -r requirements.txt
```

### 2. 配置环境变量

```bash
cp .env.template .env
```

编辑 `.env`，填入你的 LLM API 配置：

```env
API_KEY=your_api_key_here
BASE_URL=https://dashscope.aliyuncs.com/compatible-mode/v1
MODEL=qwen-plus
```

> 支持所有 OpenAI 兼容接口（阿里云 DashScope、DeepSeek、OpenAI 等）。

### 3. 编写安全策略

```bash
cp policy.yaml.template policy.yaml
```

根据你的业务场景修改 `policy.yaml`，定义：

- **agents** — 每个 Agent 的角色、可用工具、消息目标
- **tools** — 每个工具的允许调用者、前置路径要求
- **paths** — 合法的 Agent 调用链路
- **thresholds** — 风险评分阈值

### 4. 运行示例

```bash
python example.py
```

## 核心用法

### Step 1：创建审计适配器（全局共享）

```python
from autogen_adapter import AutoGenAuditAdapter

audit_adapter = AutoGenAuditAdapter(
    yaml_path="policy.yaml",    # 安全策略文件路径，None 则仅记录不拦截
    trace_id="",                # 每个场景通过 reset_state() 设置
)
```

### Step 2：用装饰器包装工具函数

```python
from audit_tool import audited_tool

@audited_tool(adapter=audit_adapter, sender="Stats_Agent", tool_name="stats_query_tool")
def stats_query_tool(merchant_id: str) -> str:
    """查询商家统计数据"""
    return f"商家 {merchant_id} 的统计数据..."
```

`@audited_tool` 自动完成：
1. 检查工作流是否已被阻断
2. 调用前审计（`emit_tool_call`）
3. 执行原始函数
4. 调用后审计（`emit_tool_result`）

**无需手动编写任何审计代码。**

### Step 3：使用 AuditedGroupChatManager

```python
import autogen
from audited_manager import AuditedGroupChatManager

groupchat = autogen.GroupChat(
    agents=[user_proxy, agent_a, agent_b],
    messages=[],
    max_round=10,
    speaker_selection_method="auto",
)

# 关键：传入 audit_adapter 参数
manager = AuditedGroupChatManager(
    groupchat=groupchat,
    llm_config=llm_config,
    audit_adapter=audit_adapter,
)
```

### Step 4：运行并捕获阻断

```python
import uuid
from autogen_adapter import WorkflowBlocked

trace_id = str(uuid.uuid4())
manager.set_scene_info(scene_name="my_scene", trace_id=trace_id)

try:
    user_proxy.initiate_chat(manager, message="请帮我查询数据", clear_history=True)
except WorkflowBlocked:
    print("工作流已被安全策略拦截")
finally:
    audit_adapter.finalize_workflow()  # 保存审计日志
```

## 安全策略详解（policy.yaml）

### Agent 定义

```yaml
agents:
  Stats_Agent:
    role: stats_agent
    can_initiate: false
    allowed_tools:             # 允许调用的工具
      - stats_query_tool
    blocked_tools:             # 明确禁止的工具
      - config_update_tool
    allowed_message_targets:   # 可以发消息给哪些 Agent
      - Operator
```

### 工具规则

```yaml
tools:
  config_update_tool:
    allowed_callers:           # 只有这些 Agent 可以调用
      - Config_Agent
    required_path_contains:    # 调用路径中必须包含这些 Agent
      - Operator
      - Compliance_Agent       # 必须先经过合规审批
    path_rule: valid_config_path
```

### 路径规则

```yaml
paths:
  valid_config_path:
    sequence:                  # Agent 必须按此顺序出现在调用链中
      - Operator
      - Compliance_Agent
      - Config_Agent
    strict: false              # false = 只需包含，true = 严格按序
```

### 风险阈值

```yaml
thresholds:
  rule_block:   0.90   # 规则引擎分 >= 0.90 → 直接拦截，不走 LLM
  human_review: 0.75   # LLM 分 >= 0.75 → 转人工审核
  # 规则引擎分 < 0.90 的事件全部进入 LLM 语义审核
```

## 审计日志

运行后审计日志保存在 `audit_logs/` 目录下：

```
audit_logs/
├── audit_log.jsonl            # 所有审计事件（JSONL 格式，每行一条）
└── workflows/
    └── {scene_name}.json      # 每个场景的完整工作流记录
```

### JSONL 日志格式

```json
{
  "event_type": "tool_call",
  "sender": "Config_Agent",
  "receiver": null,
  "tool_name": "config_update_tool",
  "tool_args": {"merchant_id": "M001", "webhook_url": "https://evil.com"},
  "call_path": ["Operator", "Config_Agent"],
  "content": null,
  "trace_id": "abc-123",
  "timestamp": "2025-01-01T12:00:00"
}
```

### 工作流 JSON 格式

```json
{
  "trace_id": "abc-123",
  "timestamp": "2025-01-01T12:00:00",
  "event_count": 5,
  "blocked": true,
  "blocked_reason": "SecurityCore 阻断工作流: [规则拦截] 调用者不在允许列表",
  "events": [...],
  "decisions": [...]
}
```

## 安全审核流程

```
                    AuditEvent
                        │
                  ┌─────▼─────┐
                  │  规则引擎   │  结构化校验（调用者身份、路径、权限）
                  └─────┬─────┘
                        │
              ┌─────────┴─────────┐
              │                   │
         score≥0.90          score<0.90
              │                   │
          直接拦截           LLM 语义审核
        （不走 LLM）       （规则通过也要过 LLM）
                                  │
                            ┌─────▼─────┐
                            │  LLM 审核  │  6 维度语义分析
                            └─────┬─────┘
                                  │
                            ┌─────┼─────┐
                            │           │
                       score≥0.75   score<0.75
                            │           │
                        转人工审核    LLM 放行
```

**规则引擎检测项：**
- 工具调用者身份校验
- 调用路径包含必要节点
- 路径顺序合规
- 消息目标白名单

**LLM 语义审核 6 维度：**
1. 虚假授权构造
2. 数据外泄风险
3. 权限提升
4. 敏感数据越权
5. 间接提示注入
6. 资源滥用

## 完整示例：电商场景

参考 `MAS/AutoGen_ecommerce/` 目录下的实现，包含：

- 6 个业务 Agent（运营、统计、订单、合规、配置、物流）
- 5 个带审计的工具函数
- 21 个攻击场景测试（路径绕过、身份伪装、语义注入等）
- 完整的 YAML 安全策略

## 常见问题

### Q: 不想拦截，只想记录怎么办？

```python
# yaml_path 传 None 即可，只记录不拦截
adapter = AutoGenAuditAdapter(yaml_path=None)
```

### Q: 如何自定义审计日志路径？

```python
adapter = AutoGenAuditAdapter(
    yaml_path="policy.yaml",
    jsonl_path="my_logs/audit.jsonl",
    workflow_dir="my_logs/workflows",
)
```

### Q: 支持哪些 LLM？

任何兼容 OpenAI API 格式的模型都可以，包括：
- 阿里云 DashScope（通义千问系列）
- DeepSeek
- OpenAI GPT 系列
- 本地部署的 vLLM / Ollama（需提供 base_url）
