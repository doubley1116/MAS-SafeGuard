# SFT（监督微调）数据生成流程

> 基于 `/data` 目录下的脚本和文件，使用 **DeepSeek V3 Thinking** 模型进行安全审计补全，并通过 `filter.py` 筛选数据不一致的样本。

---

## 目录

1. [流程概览](#一流程概览)
2. [Step 0：数据清洗与分类（d3_d4_cleaner.py）](#step-0数据清洗与分类d3_d4_cleanerpy)
3. [Step 1：模型审计补全（audit_decision_completer.py）](#step-1模型审计补全audit_decision_completerpy)
4. [Step 2：数据筛选（filter.py）](#step-2数据筛选filterpy)
5. [Step 3：验证集提取（extract_validation.py）](#step-3验证集提取extract_validationpy)
6. [Step 4：格式转换（convert_to_sft.py）](#step-4格式转换convert_to_sftpy)
7. [数据文件说明](#三数据文件说明)
8. [完整流程命令](#四完整流程命令)

---

## 一、流程概览

```
原始数据 (all.jsonl / origin.jsonl)
    │
    ▼
┌─────────────────────────────────────────────────────┐
│  Step 0: d3_d4_cleaner.py                           │
│  按 metadata.intent 分类 D3(攻击) / D4(正常)         │
│  输出: origin/, split/, merged/, all/               │
└─────────────────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────────────────┐
│  Step 1: audit_decision_completer.py                │
│  使用 DeepSeek V3 Thinking 模型进行安全审计补全      │
│  输入: all.jsonl → 输出: all_audit.jsonl            │
│  (填充 metadata.audit_decision 中的 label/analysis/reason) │
└─────────────────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────────────────┐
│  Step 2: filter.py                                  │
│  对比 ground truth (metadata.intent) 与 审计结果     │
│  ├── 保留一致数据 → all_consistent.jsonl (训练用)    │
│  └── 保留不一致数据 → all_inconsistent.jsonl (错误分析)│
└─────────────────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────────────────┐
│  Step 3: extract_validation.py                      │
│  从一致数据中按比例提取验证集                        │
│  输出: validation_set.jsonl + validation_set_meta.json│
└─────────────────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────────────────┐
│  Step 4: convert_to_sft.py                          │
│  转换为 SFT 训练格式 (Alpaca / ShareGPT)            │
│  输出: train_data.jsonl                             │
└─────────────────────────────────────────────────────┘
```

---

## Step 0：数据清洗与分类（d3_d4_cleaner.py）

**文件位置**: `data/d3_d4_cleaner.py`（`data_verify/d3_d4_cleaner.py` 为副本）

**功能**: 将原始审计数据按 `metadata.intent` 硬编码字段分类，不依赖模型盲审 label。

### 分类规则

| 字段 | 值 | 分类 |
|:---|:---|:---|
| `metadata.intent` | `attack` | **D3（攻击样本）** |
| `metadata.intent` | `benign` | **D4（正常样本）** |
| 无 intent 字段 | 按 `metadata.scenario` 推断 | 非空且非 `benign` → D3 |

### 输出目录结构

```
data/
├── origin/
│   └── origin.jsonl          # 原始顺序，未打乱
├── split/
│   ├── d3/
│   │   ├── PromptInfection.jsonl   # 按 scenario 细分
│   │   ├── AiTM.jsonl
│   │   ├── IPI.jsonl
│   │   └── ...
│   └── d4/
│       ├── financial.jsonl         # 按 domain 细分
│       ├── healthcare.jsonl
│       ├── ecommerce.jsonl
│       └── ...
├── merged/
│   ├── d3.jsonl              # 所有攻击样本（打乱）
│   └── d4.jsonl              # 所有正常样本（打乱）
└── all/
    └── all.jsonl             # 全部数据混合（打乱）
```

### 使用命令

```bash
python d3_d4_cleaner.py --input output_trace_real/audit.jsonl --out data
```

---

## Step 1：模型审计补全（audit_decision_completer.py）

**文件位置**: `data/audit_decision_completer.py`

**核心功能**: 使用 **DeepSeek V3 Thinking** 模型（通过 `deepseek-reasoner` API）对每条消息进行安全审计，补全 `metadata.audit_decision` 中的 `label`、`analysis`、`reason` 字段。

### 审计 Prompt 设计

系统使用 **COT_AUDIT_PROMPT**（Chain-of-Thought 审计提示），包含：

1. **核心约束**: 仅依据 `task` 和 `content` 两个字段判断，不知道权限配置/拓扑结构/预设标签
2. **危险信号检测**（5 大类）:
   - 授权异常（伪造审批、无凭证的紧急要求）
   - 逻辑矛盾（任务与内容意图冲突）
   - 指令注入特征（强制语气、跳过流程）
   - 越权特征（敏感操作、绕过正常流程）
   - 身份可疑（冒充系统通知、无凭证的授权声明）
3. **任务类型判断**: 分析/查询/执行/咨询
4. **标签定义**:
   - `normal`: 正常请求，无风险
   - `ambiguous`: 模糊可疑，需复核
   - `dangerous`: 明确攻击

### 输出格式

每条审计结果包含：
```json
{
  "line_num": 1,
  "original_data": { ... },
  "audit": {
    "label": "normal|ambiguous|dangerous",
    "analysis": "50-300字分析",
    "reason": "100-200字详细理由"
  }
}
```

### 使用命令

```bash
# 基本用法（多线程，默认5线程）
python audit_decision_completer.py all.jsonl

# 指定输出文件
python audit_decision_completer.py all.jsonl -o all_audit.jsonl

# 最大思考模式（深度推理）
python audit_decision_completer.py all.jsonl -t thinking_max

# 限制测试行数
python audit_decision_completer.py all.jsonl -n 10

# 单线程模式
python audit_decision_completer.py all.jsonl --single-thread

# 指定并发数
python audit_decision_completer.py all.jsonl -w 10
```

### 参数说明

| 参数 | 说明 | 默认值 |
|:---|:---|:---|
| `input_file` | 输入 JSONL 文件路径 | 必填 |
| `-o, --output` | 输出文件路径 | `{输入名}_audit.jsonl` |
| `-n, --max-lines` | 最大处理行数 | 全部 |
| `-t, --thinking` | 思考模式: `non-thinking`/`thinking`/`thinking_max` | `thinking` |
| `-w, --workers` | 并发线程数 | 5 |
| `--single-thread` | 使用单线程模式 | 否 |

### 环境配置

在 `.env` 文件中配置 API Key：
```
DEEPSEEK_API_KEY=sk-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

API 端点：`https://api.deepseek.com`

---

## Step 2：数据筛选（filter.py）

**文件位置**: `data/filter.py`（`data_verify/filter.py` 为副本）

**核心功能**: 对比 **真实标签（ground truth）** 与 **模型审计结果**，筛选出数据一致的样本（用于训练）和不一致的样本（用于错误分析）。

### 标签映射

| 原始 `metadata.intent` | Ground Truth |
|:---|:---|
| `benign` | `normal` |
| `attack` | `dangerous` |
| 其他 | `unknown` |

### 不一致判定逻辑

只统计 `normal ↔ dangerous` 之间的不一致：
- **误报（False Positive）**: ground truth = `normal`，预测 = `dangerous`
- **漏报（False Negative）**: ground truth = `dangerous`，预测 = `normal`

`ambiguous` 和 `unknown` 标签不计入不一致统计，默认保留。

### 输出格式

```json
{
  "original": { ... },           // 原始数据
  "audit_result": {
    "label": "normal|dangerous",
    "analysis": "...",
    "reason": "..."
  }
}
```

### 使用命令

```bash
# 保留一致数据（用于训练）
python filter.py all.jsonl all_audit.jsonl
# 输出: all_consistent.jsonl

# 保留不一致数据（用于错误分析）
python filter.py all.jsonl all_audit.jsonl --keep-inconsistent
# 输出: all_inconsistent.jsonl

# 指定输出文件
python filter.py all.jsonl all_audit.jsonl -o output.jsonl

# 仅查看统计信息
python filter.py all.jsonl all_audit.jsonl --stats-only

# 仅清理文件中的 reasoning 字段
python filter.py --clean-only input.jsonl -o output.jsonl
```

### 统计信息示例

```
============================================================
筛选完成！
============================================================
原始文件: all.jsonl
审计文件: all_audit.jsonl
输出文件: all_consistent.jsonl

统计信息:
  总匹配行数:           1000
  一致 (保留):          850
  不一致 (删除):        150
    - 误报 (normal→dangerous): 45
    - 漏报 (dangerous→normal): 105
  预测 ambiguous:       20
  真实标签 unknown:     10

性能指标:
  准确率 (Accuracy): 85.0%
  精确率 (Precision): 90.0%
  召回率 (Recall): 80.0%
  F1 分数: 84.7%

输出文件包含: 870 条数据
============================================================
```

---

## Step 3：验证集提取（extract_validation.py）

**文件位置**: `data/extract_validation.py`

**功能**: 从筛选后的一致数据中按比例提取固定的验证集。

### 过滤逻辑

提取前会执行与 SFT 训练脚本相同的过滤条件：
1. `audit_result.label` 必须是 `safe`/`suspicious`/`dangerous` 之一
2. `audit_result.analysis` 不能为空
3. `audit_result.reason` 不能为空

### 使用命令

```bash
# 基本用法（从 all_consistent.jsonl 提取 10% 作为验证集）
python extract_validation.py --data all_consistent.jsonl --output validation_set.jsonl

# 自定义比例和随机种子
python extract_validation.py --data all_consistent.jsonl --output validation_set.jsonl --split 0.15 --seed 123

# 不执行过滤
python extract_validation.py --data all_consistent.jsonl --output validation_set.jsonl --no-filter
```

### 输出

| 文件 | 说明 |
|:---|:---|
| `validation_set.jsonl` | 验证集数据（JSONL 格式） |
| `validation_set_meta.json` | 元信息（源文件、比例、种子、各集合大小） |

### 当前数据统计（来自 validation_set_meta.json）

| 指标 | 数值 |
|:---|:---|
| 源文件 | `all_consistent.jsonl` |
| 原始数据量 | 9,582 条 |
| 过滤后 | 9,575 条 |
| 验证集 (10%) | 958 条 |
| 训练集 (90%) | 8,617 条 |

---

## Step 4：格式转换（convert_to_sft.py）

**文件位置**: `data/convert_to_sft.py`

**功能**: 将 `filter.py` 的输出转换为 SFT 训练格式。

### 支持的输出格式

#### Alpaca 格式（默认）

```json
{
  "instruction": "任务目标：{task}\n\n消息内容：{content}",
  "output": "标签：{label}\n\n分析：{analysis}\n\n理由：{reason}"
}
```

#### ShareGPT 格式

```json
{
  "conversations": [
    {
      "from": "human",
      "value": "任务目标：{task}\n\n消息内容：{content}"
    },
    {
      "from": "gpt",
      "value": "{\"label\": \"...\", \"analysis\": \"...\", \"reason\": \"...\"}"
    }
  ]
}
```

### 使用命令

```bash
# 转换为 Alpaca 格式（默认）
python convert_to_sft.py all_consistent.jsonl train_data.jsonl

# 转换为 ShareGPT 格式
python convert_to_sft.py all_consistent.jsonl train_data.jsonl --format sharegpt
```

---

## 三、数据文件说明

### `/data/` 目录文件清单

| 文件 | 大小 | 说明 |
|:---|:---|:---|
| `all/all.jsonl` | ~6.9 MB | 全部数据混合（打乱），包含 `metadata.intent` 标签 |
| `origin/origin.jsonl` | - | 原始顺序数据（未打乱） |
| `merged/d3.jsonl` | - | 所有攻击样本（打乱） |
| `merged/d4.jsonl` | - | 所有正常样本（打乱） |
| `decision_result.jsonl` | ~10.2 MB | **审计结果**：DeepSeek 模型审计后的完整结果 |
| `all_consistent.jsonl` | ~9.1 MB | **一致数据**：ground truth 与审计结果一致（训练用） |
| `all_inconsistent.jsonl` | ~960 KB | **不一致数据**：ground truth 与审计结果不一致（错误分析用） |
| `validation_set.jsonl` | ~945 KB | **验证集**：从一致数据中提取的 10% 验证数据 |
| `validation_set_meta.json` | - | 验证集元信息 |
| `audit_decision_completer.py` | - | Step 1：模型审计补全脚本 |
| `filter.py` | - | Step 2：数据筛选脚本 |
| `extract_validation.py` | - | Step 3：验证集提取脚本 |
| `convert_to_sft.py` | - | Step 4：格式转换脚本 |
| `d3_d4_cleaner.py` | - | Step 0：数据清洗分类脚本 |
| `test_api.py` | - | DeepSeek API 测试脚本 |
| `.env` | - | API Key 配置文件 |

### 数据字段说明

原始数据（`all.jsonl`）每条记录包含：

| 字段 | 说明 |
|:---|:---|
| `event_type` | 事件类型（固定为 `message`） |
| `sender` | 发送者（User / Agent 名称） |
| `receiver` | 接收者（Agent 名称） |
| `content` | 消息内容 |
| `task` | 任务目标 |
| `history_summary` | 历史对话摘要 |
| `metadata.scenario` | 攻击场景（如 AiTM, IPI, PromptInfection 等） |
| `metadata.domain` | 业务领域（如 financial, healthcare, ecommerce 等） |
| `metadata.intent` | **真实标签**：`attack`（攻击）或 `benign`（正常） |
| `metadata.audit_decision` | 审计决策（初始为空，由 Step 1 补全） |

---

## 四、完整流程命令

### 一键式完整流程

```bash
# 切换到 data 目录
cd /path/to/data

# Step 0: 数据清洗分类（如需要）
python d3_d4_cleaner.py --input output_trace_real/audit.jsonl --out data

# Step 1: 使用 DeepSeek V3 Thinking 进行安全审计
python audit_decision_completer.py all.jsonl -o decision_result.jsonl -t thinking

# Step 2: 筛选一致数据（训练用）
python filter.py all.jsonl decision_result.jsonl -o all_consistent.jsonl

# Step 2 (可选): 筛选不一致数据（错误分析用）
python filter.py all.jsonl decision_result.jsonl --keep-inconsistent -o all_inconsistent.jsonl

# Step 2 (可选): 查看审计统计
python filter.py all.jsonl decision_result.jsonl --stats-only

# Step 3: 提取验证集
python extract_validation.py --data all_consistent.jsonl --output validation_set.jsonl

# Step 4: 转换为 SFT 训练格式
python convert_to_sft.py all_consistent.jsonl train_data.jsonl --format sharegpt
```

### 快速测试流程（小样本验证）

```bash
# 只审计前 10 条数据
python audit_decision_completer.py all.jsonl -n 10 -o test_audit.jsonl

# 筛选
python filter.py all.jsonl test_audit.jsonl -o test_consistent.jsonl

# 查看统计
python filter.py all.jsonl test_audit.jsonl --stats-only
```

---

## 五、关键设计要点

### 1. 标签体系

| 层级 | 字段 | 值 |
|:---|:---|:---|
| Ground Truth | `metadata.intent` | `attack` / `benign` |
| 统一标签 | filter.py 映射 | `dangerous` / `normal` |
| 模型预测 | `audit.label` | `dangerous` / `normal` / `ambiguous` |
| SFT 标签 | convert_to_sft.py 映射 | `dangerous` / `normal` / `ambiguous` |

### 2. 不一致筛选逻辑

- **只统计** `normal ↔ dangerous` 之间的不一致
- `ambiguous` 预测和 `unknown` 真实标签不计入不一致统计
- 默认模式下，`ambiguous`/`unknown` 数据会被保留（不删除）

### 3. 数据规模

| 数据集 | 数量 |
|:---|:---|
| 原始数据总量 | ~9,582 条 |
| 过滤后有效数据 | ~9,575 条 |
| 训练集 (90%) | ~8,617 条 |
| 验证集 (10%) | ~958 条 |

---

*文档生成时间: 2026-07-03*
