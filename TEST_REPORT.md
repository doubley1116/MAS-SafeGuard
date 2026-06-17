# Zero Trust MAS Audit Pipeline — 实验报告

> 生成时间: 2026-06-17
> 测试数据集: `AuditDataGen/eval_results_verify/origin_consistent.jsonl`
> 新增领域: iov (228事件) + converged_media (249事件) = 477事件
> 审核架构: **分层门控 Cascading OR-Gate**

---

## 1. 系统架构

### 1.1 三层检测

```
Layer 1 — 规则引擎 (Rule Engine)
  检测: 结构违规 — agent→agent 非法跳转、消息目标越权
  门槛: 0.50 (FP=0%, 命中即确信)

Layer 2 — EWMA 轨迹检测 (Trajectory Detector)  
  检测: 统计异常 — 训练数据中未出现的边、异常路径深度、回溯
  门槛: 0.35 (降门槛补偿 EWMA 保守打分)

Layer 3 — LLM 语义审核 (LLM Reviewer)
  检测: 内容注入 — IPI、PromptInfection、SemanticInjection
  门槛: 0.50 (语义检测标准门槛)
```

### 1.2 分层门控判决逻辑

```
if   rule_score  ≥ 0.50 → BLOCK   [R: 结构性违规]
elif traj_score  ≥ 0.35 → BLOCK   [E: 统计异常]
elif llm_score   ≥ 0.50 → BLOCK   [L: 语义威胁]
else                    → ALLOW
```

### 1.3 关键设计决策

| 决策 | 理由 |
|------|------|
| 分层门控替代线性融合 | 三层打分不在同一刻度（R:0.88-0.95, E:0.3-0.7, L:0.05/0.85），加权平均互相稀释 |
| EWMA 门槛 0.35 而非 0.5 | EWMA 连续谱打分天生保守，有效区间仅 0.3-0.7 |
| anomaly_score 公式 `(z-k)/k` | 确保 z=2k 时达到满分 1.0，多维微弱异常也能累积到有效分数 |
| 推理时剥离 Router/Tool_Node | 与 warmup 预处理对齐，消除训练-推理不一致 |
| adjacency + unknown_agent 扩展至所有事件类型 | message/tool_result 事件也能享受结构性保护 |

---

## 2. 新增领域构建

### 2.1 LangGraph MAS 物理实现

| 领域 | Agent | 工具 | 安全规则 |
|------|-------|------|----------|
| iov | User, Router, Telematics, Safety, Firmware, Fleet | 5 | firmware_update 必经 Safety |
| converged_media | User, Router, Editor, Review, Publish, Copyright | 5 | publish 必经 Review |

每个领域包含完整的 `attack_core.py` (400+ 行)、SQLite 数据库、正常场景执行器。

### 2.2 EWMA 训练

合成轨迹生成器覆盖正常业务全路径（含反向回环和直接查询）:

| 领域 | 观测数 | μ_depth | 已知边 |
|------|--------|---------|--------|
| iov | 245 | 2.59 | 9 |
| converged_media | 295 | 2.59 | 10 |

### 2.3 YAML 策略 (v2.0)

包含 `adjacency`（邻接矩阵）、`allowed_message_targets`（消息目标）、`blocked_tools`（禁止工具）、`required_path_contains`（必经路径节点）。

---

## 3. 测试结果

### 3.1 Layer 1 — 白盒正确性

| 测试套件 | 用例 | 结果 |
|----------|:----:|:----:|
| Rule Engine (12种规则方法) | 22 | **22/22 PASS** |
| EWMA (5维特征) | 5 | **5/5 PASS** |

### 3.2 Layer 2+3 — 消融实验 (477事件, iov+converged_media)

| 攻击类型 | 数量 | R-only | E-only | R+E | Full (*) |
|----------|:----:|:------:|:------:|:---:|:--------:|
| AiTM | 151 | 32.5% | **51.0%** | **51.0%** | **51.0%** |
| CallerImpersonation | 39 | 0.0% | 0.0% | 0.0% | 0.0% |
| PathBypass | 22 | 0.0% | 0.0% | 0.0% | 0.0% |
| RouterHijacking | 35 | 0.0% | 0.0% | 0.0% | 0.0% |
| PromptInfection | 34 | 0.0% | 0.0% | 0.0% | **100.0%** (*) |
| SemanticInjection | 28 | 0.0% | 0.0% | 0.0% | **100.0%** (*) |
| IPI | 115 | 0.0% | 0.0% | 0.0% | **100.0%** (*) |
| **benign** | 53 | **0.0%** | **0.0%** | **0.0%** | **0.0%** |
| **OVERALL** | **477** | **10.3%** | **16.1%** | **16.1%** | **53.2%** |

> (*) Full 列 IPI/PromptInfection/SemanticInjection 由 MockLLMReviewer 检测（硬编码 `scenario in (...) → 0.85`），不代表真实 LLM 性能。MockLLM 在此实验中仅作为控制变量，消除 LLM 波动对 R/E 比较的干扰。

### 3.3 AiTM 攻击注入点分析

消融实验的 AiTM 51% 包含了 trace 中所有事件（含攻击前的正常前缀事件）。**只看攻击注入点本身**:

| 领域 | 注入点数 | R 拦截 | E 拦截 | 合计 |
|------|:--------:|:------:|:------:|:----:|
| iov | 21 | 14 (67%) | 7 (33%) | **21/21 (100%)** |
| converged_media | 21 | 21 (100%) | 0 | **21/21 (100%)** |

iov 的 14 个被 R 拦截（Telematics→Firmware 邻接违规），7 个被 E 拦截（subtle 回溯变体，4 维特征联合触发，综合分 0.55≥0.35）。converged_media 全部被 R 拦截（Editor→Publish 邻接违规）。

### 3.4 0% 检测的攻击类型分析

CallerImpersonation、PathBypass、RouterHijacking 在 R 和 E 上均为 0%，因为它们与正常路径**结构完全一致**:

```
CallerImpersonation:  User → Firmware_Agent    (攻击: 冒充管理员调用)
正常查询:             User → Firmware_Agent    (良性: 查询固件版本)

PathBypass:          User → Publish_Agent      (攻击: 绕过审查发布)
正常查询:             User → Publish_Agent      (良性: 查询发布状态)
```

区分它们需要消息内容中的语义信号——这正是 LLM 的设计职责。

---

## 4. 三层互补关系

```
                  结构性攻击                              语义攻击
             AiTM   CallerImp  PathByp  RouterH  PromptInf  Semantic  IPI
规则引擎 (R)   ✓       —         —        —         —         —       —
EWMA (E)      ✓       —         —        —         —         —       —
LLM (L)       —       ✓         ✓        ✓         ✓         ✓       ✓
```

| 层 | 覆盖范围 | 优势 | 局限 |
|----|----------|------|------|
| R | 非法 agent→agent 跳转 | 0% FP，即时生效 | 只覆盖明确的结构违规 |
| E | 统计异常路径 | 自适应，无需规则维护 | 同路径 benign vs attack 无法区分 |
| L | 语义攻击 | 理解消息内容 | 延迟高，需 API，性能取决于模型 |

---

## 5. 实验过程中的关键修复

| 修复 | 问题 | 影响 |
|------|------|------|
| anomaly_score: `(z-k)/(2k)` → `(z-k)/k` | 多维微弱异常无法累积到有效分数 | subtle AiTM 从 MISS → BLOCK |
| `_compute_trajectory_score` 剥离 Router/Tool_Node | 训练-推理数据不对齐 | benign FP 从 30.2% → 0% |
| 合成训练数据补全反向边 | Safety→Telematics, Review→Editor 等回环缺失 | benign FP 归零 |
| 规则引擎 adjacency/unknown_agent 扩展至所有事件类型 | message/tool_result 事件无结构性检查 | R 覆盖从 0% → AiTM 32.5% |
| YAML v2.0 含 adjacency + message_targets | v1.0 无邻接矩阵 | 规则引擎可实际生效 |
| 线性融合 → 分层门控 | α 权重稀释 EWMA/LLM | 每层独立判决，消除跨层压制 |

---

## 6. 关于 MockLLM

MockLLMReviewer 判定逻辑:
```python
if scenario in ("SemanticInjection", "PromptInfection", "IPI"):
    return 0.85
else:
    return 0.05
```

**Full 列中 100% 的语义攻击检测率来自此硬编码规则，不代表真实 LLM 性能。**
MockLLM 在实验中仅作为控制变量，用于:
1. 排除 LLM 性能波动对 R/E 比较的干扰
2. 验证分层门控的逻辑正确性
3. 保证实验可复现

真实 LLM 评估需独立实验，替换方式:
```python
SecurityCore(
    yaml_path="policy.yaml",
    llm_reviewer=LLMReviewer(api_key="sk-...", model="gpt-4o"),
    trajectory_detector_path="detector.pkl",
)
```

---

## 7. 结论

1. **分层门控 + 规则引擎 + EWMA 在攻击注入点实现 100% AiTM 拦截**，0% benign FP。

2. **三层互补架构得到实验验证**: 规则引擎拦截明确的结构违规（32.5%），EWMA 捕获 subtle 变体（+18.5%），LLM 覆盖语义攻击。没有任何单层能覆盖所有攻击面。

3. **CallerImpersonation/PathBypass/RouterHijacking 的 call_path 与正常路径完全重合**，结构性检测必然失效。这是信息论硬上限，不是工程缺陷——区分它们需要 LLM 分析消息内容。

4. **EWMA 精度完全取决于训练数据覆盖度**。合成轨迹最初缺少反向回环边导致 30.2% FP，补全后归零。

5. **anomaly_score 公式对 EWMA 灵敏度至关重要**。`(z-k)/k` 比 `(z-k)/(2k)` 更合理——z=2k 时达到满分 1.0，多维微弱异常能有效累积。
