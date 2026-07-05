# MAS-SafeGuard —— 面向多智能体通信层的零信任安全防护系统

MAS-SafeGuard 是面向多智能体系统（MAS）通信层的零信任安全防护系统，以"默认不信任、最小权限、全链路审计"为核心原则，将 Agent 间消息传递、任务委派和工具调用统一建模为 `AuditEvent`，通过**规则引擎 + EWMA 轨迹检测 + LLM 语义审核**三层级联或门实现实时安全研判。

## 架构概览

```
Agent A → Adapter → SecurityCore → Adapter → Agent B
                        ↓
              ┌─────────────────┐
              │   规则引擎 (R)   │ ← YAML 策略文件，确定性结构校验
              │   score ≥ 0.50  │
              └────────┬────────┘
                       │ 未触发
              ┌────────▼────────┐
              │  EWMA 轨迹层 (E) │ ← 7 维轨迹特征，统计异常检测
              │   score ≥ 0.35  │
              └────────┬────────┘
                       │ 未触发
              ┌────────▼────────┐
              │  LLM 语义层 (L)  │ ← SFT 微调模型，语义风险研判
              │   score ≥ 0.50  │
              └────────┬────────┘
                       ↓
                 AuditDecision → AuditLogger
```

**级联或门决策**：任意一层触发拦截则阻断，三层均未触发才放行。优先顺序：R → E → L。

## 七类攻击覆盖

| 类别 | 攻击类型 | 检测层 | 核心方法 |
|------|---------|--------|---------|
| 结构类 | 路径绕过 (Path Bypass) | 规则层 | missing_required_path_node |
| 结构类 | 调用者伪装与权限提升 (Caller Impersonation) | 规则层 + LLM | unauthorized_tool_caller / blocked_tool |
| 结构类 | 路由劫持 (Route Hijack) | 规则层 | intent_confidence + route_hijack_check |
| 结构类 | 智能体中间人 (AiTM) | 规则层 + EWMA | unknown_agent / novel_edge_ratio |
| 语义类 | 语义注入 (Semantic Injection) | LLM 层 | 虚假授权 / 恶意指令嵌入 |
| 语义类 | 间接提示注入 (IPI) | 轨迹层 + LLM | read_file → execute 异常跳转 |
| 语义类 | 感染式传播 (Prompt Infection) | 轨迹层 + LLM | 跨 Agent 自复制语义检测 |

## 目录结构

```
Zero_Trust/
├── audit_layer/                  # SecurityCore 核心 + 适配层
│   ├── security_core.py          # 分层安全审核引擎
│   ├── rule_engine.py            # 规则引擎（YAML 策略驱动）
│   ├── trajectory_model.py       # EWMA 轨迹异常检测
│   ├── llm_reviewer.py           # LLM 语义审核
│   ├── role_engine.py            # 角色引擎（可选）
│   └── utils/policy_loader.py    # YAML 策略加载
├── MAS/                          # 多框架场景样例
│   ├── AutoGen_trading/          # AutoGen 金融交易
│   ├── AutoGen_ecommerce/        # AutoGen 电子商务
│   ├── AutoGen_healthcare/       # AutoGen 医疗辅助
│   ├── CrewAI_trading/           # CrewAI 金融交易
│   ├── CrewAI_ecommerce/         # CrewAI 电子商务
│   ├── CrewAI_healthcare/        # CrewAI 医疗辅助
│   ├── Langgraph_trading/        # LangGraph 金融交易
│   ├── Langgraph_ecommerce/      # LangGraph 电子商务
│   ├── Langgraph_healthcare/     # LangGraph 医疗辅助
│   ├── Langgraph_iov/            # LangGraph 车联网
│   └── Langgraph_converged_media/# LangGraph 融媒体
├── AutoGenAuditor/               # AutoGen 框架适配器
├── LangGraphAuditor/             # LangGraph 框架适配器
├── 数据生成+模型训练+evaluation/  # 数据生成与模型训练模块
│   ├── AuditDataGen/             # 生成管线（骨架/自由形式/LLM 增强）
│   ├── SFT/                      # SFT 训练与评估
│   ├── data/                     # 数据集（origin/split/merged）
│   └── data_verify/              # 数据清洗与验证
├── frontend_showcase/            # 可视化前端展示台
├── inference_server/             # SFT 模型推理服务
└── tests/                        # 测试用例
```

## 快速开始

### 环境要求

- Python 3.10+
- 各 MAS 框架子目录有独立的 `requirements.txt`

### 运行安全审核

```bash
cd audit_layer
cp .env.template .env   # 填写 API Key
python security_core.py
```

### 运行场景样例

```bash
# 以 AutoGen 金融交易场景为例
cd MAS/AutoGen_trading
cp .env.template .env
pip install -r requirements.txt
python main.py
```

### 前端展示台

```bash
cd frontend_showcase
npm install
node server.js
```

## 创新点

1. **通信层零信任防护**：在 Agent 间通信边界部署安全能力，不依赖单个 Agent 自行判断
2. **规则-轨迹-语义三层互补检测**：确定性校验 + 统计异常 + 语义研判，兼顾可解释性与覆盖率
3. **跨框架低侵入适配**：AutoGen / CrewAI / LangGraph 统一 AuditEvent 抽象
4. **对抗式数据生成与专用审核模型**：GRPO 训练的 Attacker + SFT 微调的 Reviewer 形成闭环

## 许可

本作品为第十九届全国大学生信息安全竞赛（作品赛）参赛项目。
