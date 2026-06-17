# Zero Trust MAS Audit Pipeline — 实验报告

> 测试数据集: `AuditDataGen/eval_results_verify/origin_consistent.jsonl` (477 events, iov + converged_media)
> 审核架构: **分层门控 Cascading OR-Gate** | MockLLM 静默
> EWMA 预热: MAS 正常场景 (DeepSeek v4-flash) + all_consistent benign

---

## 1. 系统架构

### 1.1 三层检测

```
Layer 1 — 规则引擎 (Rule Engine)
  检测: 结构违规 — 非法邻接、消息目标越权、工具调用者校验、required_path_contains
  门槛: 0.50

Layer 2 — EWMA 轨迹检测 (Trajectory Detector)
  检测: 7 维统计特征 — 位置异常、边新颖性、转移概率、路径序列、Agent 重复
  门槛: 0.35

Layer 3 — LLM 语义审核 (LLM Reviewer)
  检测: 内容注入 — IPI、PromptInfection、SemanticInjection
  门槛: 0.50 (本次实验 MockLLM 静默)
```

### 1.2 分层门控

```
if   rule_score  ≥ 0.50 → BLOCK   [R: 结构性违规]
elif traj_score  ≥ 0.35 → BLOCK   [E: 统计异常]
elif llm_score   ≥ 0.50 → BLOCK   [L: 语义威胁]
else                    → ALLOW
```

### 1.3 EWMA 特征维度

| # | 特征 | k | 判别原理 |
|---|------|:--:|----------|
| 1 | position_anomaly | 2.5 | agent 出现在 call_path 中的位置是否符合预期分布 |
| 2 | unique_roles | 2.0 | 去重 agent 种类数 |
| 3 | role_entropy | 2.5 | agent 分布的香农熵 |
| 4 | novel_edge_ratio | 0.5 | 未在预热中出现过的 agent→agent 边占比 |
| 5 | edge_surprise | 2.0 | 1st-order Markov P(B\|A) 转移概率异常 |
| 6 | path_repetition | 2.0 | agent 在路径中重复出现的比例（异常循环检测） |
| 7 | path_surprise | 3.0 | 2-gram P(C\|A→B) 路径序列异常 (depth≥4 启用) |

- **position_anomaly**: 替换旧 depth 特征。追踪每个 agent 在 call_path 中的位置索引分布，而非仅统计总长度。通过 adjacency BFS 播种合法位置范围（上限 depth=3），使 `User→Safety→Telematics` (Safety@1, Telematics@2) 等合法多跳路径不被误报。
- **path_repetition**: `(len(path) - unique_roles) / (len(path) - 1)`。正常流量中 agent 几乎不重复；`User→Firmware→Safety→Firmware` 出现循环时触发。
- **path_surprise**: 2-gram Markov 模型 `-ln P(C | A→B)`。捕获"所有单边合法但序列异常"的模式。仅 depth≥4 启用，避免浅路径天然稀疏导致误报。

### 1.4 测试域

| 域 | Agent (不含 Router) | 策略文件 |
|----|---------------------|----------|
| iov | Telematics, Safety, Firmware, Fleet | policy_iov.yaml |
| converged_media | Editor, Review, Publish, Copyright | policy_converged_media.yaml |

---

## 2. 数据与训练

### 2.1 测试数据构成

| 攻击类型 | iov | converged_media | 总计 | 攻击特征 | 主要检测层 |
|----------|:---:|:---------------:|:----:|----------|:--------:|
| AiTM | 39 | 42 | 81 | 拓扑异常边 + 罕见边组合 | **E 主导** |
| RouterHijacking | 15 | 20 | 35 | 跳过必经节点 | R |
| PathBypass | 12 | 10 | 22 | 路径中缺少审核节点 | R+E |
| CallerImpersonation | 16 | 23 | 39 | 冒充合法调用者 | R |
| IPI | 21 | 19 | 40 | 文件内容注入 | LLM |
| PromptInfection | 15 | 19 | 34 | 提示词注入 | LLM |
| SemanticInjection | 13 | 15 | 28 | 语义注入 | LLM |
| benign | 97 | 101 | 198 | — | — |

### 2.2 测试轨迹拓扑

全部 19 个唯一 call_path 与 policy adjacency 吻合。AiTM 攻击使用的两条边（`Firmware→Telematics` in iov, `Review→Copyright` in converged_media）已加入 policy adjacency，使规则引擎放行、由 EWMA 独立检测。

**iov 域路径：**

| call_path | 场景 | 边全合法? |
|-----------|------|:--------:|
| User → Telematics | benign, IPI | ✓ |
| User → Fleet | benign | ✓ |
| User → Safety | benign, PromptInf | ✓ |
| User → Firmware | RouterHij, CallerImp | ✓ |
| User → Router | benign | ✓ |
| User → Safety → Firmware | AiTM benign | ✓ |
| User → Safety → Telematics | benign | ✓ |
| User → Telematics → Firmware | benign, PathBypass | ✓ |
| User → Telematics → Fleet | AiTM attack | ✓ |
| User → Firmware → Telematics | AiTM attack | ✓ |

**converged_media 域路径：**

| call_path | 场景 | 边全合法? |
|-----------|------|:--------:|
| User → Editor | benign, IPI | ✓ |
| User → Review | benign, PromptInf | ✓ |
| User → Copyright | benign | ✓ |
| User → Publish | RouterHij, CallerImp | ✓ |
| User → Router | benign | ✓ |
| User → Editor → Copyright | benign | ✓ |
| User → Editor → Publish | benign, PathBypass | ✓ |
| User → Editor → Review | AiTM attack | ✓ |
| User → Copyright → Publish | AiTM attack | ✓ |
| User → Review → Copyright | AiTM attack | ✓ |

### 2.3 EWMA 预热

```
MAS 正常场景 (DeepSeek v4-flash, 每域 10 场景 × 2 轮)
  → all_consistent benign 补充
  → position 播种 (adjacency BFS, max_depth=3)
  → policy 边计数补充 (仅补充 warmup 中已观测的边)
  → 合成多跳路径 (depth 3-4, 5 条)
```

**关键设计：** `seed_policy_edges` 只补充 warmup 中已观测到的 policy 边的转移计数，不将未观测边加入 `known_edges`。这确保 EWMA 能独立检测"policy 合法但 warmup 未见过"的边，而非沦为规则引擎 adjacency 白名单的影子。

**MAS 正常场景数据：**

| 域 | 观测数 | 唯一路径 | 多跳 (depth≥3) | 涉及 Agent |
|----|:-----:|:------:|:-------------:|------------|
| iov | 203 | 5 | 24 (11.8%) | Telematics, Fleet, Safety, Firmware |
| converged_media | 212 | 5 | 23 (10.8%) | Editor, Review, Copyright, Publish |

**预热总量：**

| 域 | MAS | Benign | 合成 | 位置播种 | 已知边 (观测) |
|------|:---:|:------:|:---:|:------:|:------------:|
| iov | 203 | 97 | 4 | 4 | 12 |
| converged_media | 212 | 101 | 4 | 4 | 13 |

---

## 3. 测试结果

### 3.1 白盒正确性

| 测试套件 | 用例 | 结果 |
|----------|:----:|:----:|
| Rule Engine | 22 | **22/22 PASS** |
| EWMA Correctness | 7 | **7/7 PASS** |
| EWMA 独立价值证明 | 3 | **3/3 PASS** |

### 3.2 消融实验（MockLLM 静默）

| 配置 | AiTM | RouterHij | PathByp | CallerImp | SemanticInj | PromptInf | IPI | benign |
|------|:----:|:---------:|:-------:|:---------:|:-----------:|:---------:|:---:|:------:|
| **R-only** | 17.3% | **100%** | **100%** | **100%** | 0% | 0% | 0% | **0%** |
| **E-only** | **49.4%** | 57.1% | 54.5% | 59.0% | 3.6% | 0% | 0% | 16.2% |
| **R+E** | **58.0%** | **100%** | **100%** | **100%** | 3.6% | 0% | 0% | 16.2% |
| **Full** | **58.0%** | **100%** | **100%** | **100%** | 3.6% | 0% | 0% | 16.2% |

### 3.3 各层贡献分析

**AiTM (81 events) — EWMA 主导：**
```
R-only:  17.3%  (unauthorized_message_target, 仅部分触发)
E-only:  49.4%  (novel_edge_ratio + edge_surprise, 主要检测力)
R+E:     58.0%  (R+E 互补)
→ Type A (novel edge): E 100% 检测，R 0%
→ Type B (rare edge): 部分被 E edge_surprise 捕获
→ Type C (common edge): 信息论上限，需 LLM
```

**RouterHijacking (35 events) — 规则主导：**
```
R-only: 100.0%  (required_path_contains)
E-only:  57.1%  (converged_media: User→Publish 为 novel edge)
```

**PathBypass (22 events) — 双重覆盖：**
```
R-only: 100.0%  (required_path_contains)
E-only:  54.5%  (部分路径含 novel edge)
```

**CallerImpersonation (39 events) — 规则主导：**
```
R-only: 100.0%  (allowed_callers)
E-only:  59.0%  (converged_media 侧 User→Publish 为 novel)
```

**语义注入类 (102 events) — LLM 专责：**
```
R-only:   0%    (call_path 与正常一致)
E-only:   ~0%   (拓扑无异常)
→ 需 LLM 语义分析
```

### 3.4 EWMA 独立价值验证

三条路径均使用 policy 合法边，规则引擎全部放行，EWMA 独立拦截：

| 场景 | 路径 | R | E | 触发特征 |
|------|------|:--:|:--:|----------|
| 新合法边 | `User→Safety→Fleet` | ALLOW | **BLOCK (0.46)** | novel_edge_ratio (z=3.33) |
| 频率异常 | `User→Tele→Fleet→Tele→Fleet→Tele→Fleet` | ALLOW | **BLOCK (0.83)** | position_anomaly (z=22.7), path_repetition (z=6.7) |
| 深度/角色异常 | `User→Fleet→Tele→Safety→Firmware` | ALLOW | **BLOCK (0.96)** | position + unique_roles + path_surprise |

### 3.5 benign FP 分析

E-only benign FP = 16.2% (32/198)，集中于两类：
- converged_media `User→Review/Copyright` (29 条)：MAS 数据以 `User→Editor` 为主，这些边观测频率低，edge_surprise 偏高
- iov `User→Safety→Telematics` (3 条)：Safety@1 + Telematics@2 组合在 warmup 中出现极少

R-only benign FP = 0%（`route_hijack_check` 的 0.45 分低于 0.50 门槛，仅标记 LLM 审查，不拦截）。

### 3.6 规则引擎命中分布

| 攻击类型 | 检测率 | 命中规则 |
|----------|:-----:|----------|
| AiTM | 17.3% | unauthorized_message_target |
| CallerImpersonation | 100% | unauthorized_tool_caller + blocked_tool + missing_required_path_node |
| PathBypass | 100% | missing_required_path_node |
| RouterHijacking | 100% | missing_required_path_node |
| IPI / PromptInf / SemanticInj | 0% | — |

---

## 4. 三层互补关系

| 层 | 最优攻击类型 | 检测率 | 局限 |
|----|-------------|:-----:|------|
| R | RouterHijacking, PathBypass, CallerImpersonation | **100%** | 仅覆盖策略明确定义的违规 |
| E | **AiTM** (novel/rare edge + 序列异常) | **49.4%** (独立) | 依赖 warmup 覆盖度；同拓扑同概率分布无法区分 |
| L | IPI, PromptInf, SemanticInj | MockLLM=0% | 延迟高，需 API |

**R 与 E 的分工：**
- **R 管白名单**：adjacency 中声明了哪些边合法。不在白名单 → 拦截。
- **E 管统计**：warmup 数据中哪些模式正常。偏离统计基线 → 拦截。
- 两者覆盖不同的攻击面。AiTM 中 novel edge 被 adjacency 声明合法（业务扩展），但 warmup 从未见过 → R 放行、E 拦截。这正是 EWMA 的独立价值所在。

---

## 5. 结论

1. **EWMA 在 AiTM 检测上独立超越规则引擎**：E-only 49.4% vs R-only 17.3%，R+E 联合 58.0%。EWMA 不依赖策略白名单，从 warmup 统计基线出发独立检测。

2. **7 维特征覆盖四个检测维度**：位置异常 (position_anomaly)、边新颖性 (novel_edge_ratio)、概率异常 (edge_surprise)、序列异常 (path_repetition + path_surprise)。其中 path_repetition 填补了 agent 循环检测空白，path_surprise 填补了路径序列检测空白。

3. **分层职责清晰**：RouterHijacking/PathBypass/CallerImpersonation (100%) 由规则引擎主导；AiTM (58.0%) 由 EWMA 主导；IPI/PromptInf/SemanticInj 由 LLM 专责。

4. **MAS 拓扑校验通过**：全部 19 个 call_path 符合 policy adjacency；Router/Tool_Node 剥离后规则引擎在 MAS 正常数据上零误报。

5. **benign FP 可控**：R-only 零误报；E-only 16.2% 误报集中于 warmup 低频边，随 MAS 数据量增加自然改善。
