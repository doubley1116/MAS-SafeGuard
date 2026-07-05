# 数据审计与筛选工具使用说明

## 一、数据审计     (audit_decision_completer.py)

使用 DeepSeek-V4 对消息进行安全审计。

### 使用方法

```bash
# 基本用法
python audit_decision_completer.py data.jsonl

# 最大思考模式（深度推理）
python audit_decision_completer.py data.jsonl -t thinking_max

# 限制10行测试
python audit_decision_completer.py data.jsonl -n 10

# 指定输出文件
python audit_decision_completer.py data.jsonl -o result.jsonl

# 测试模式
python audit_decision_completer.py
```

### 参数说明

| 参数 | 说明 | 默认值 |
|:---|:---|:---|
| `input_file` | 输入文件路径 | 必填 |
| `-o, --output` | 输出文件路径 | `输入名_audit.jsonl` |
| `-n, --max-lines` | 最大处理行数 | 全部 |
| `-t, --thinking` | 思考模式：`non-thinking`/`thinking`/`thinking_max` | `thinking` |

---

## 二、数据筛选 (filter.py)

对比真实标签（`metadata.intent`）与审计结果，筛选一致/不一致数据。

### 使用方法

```bash
# 保留一致数据（用于训练）
python filter.py all.jsonl all_audit.jsonl

# 保留不一致数据（用于错误分析）
python filter.py all.jsonl all_audit.jsonl --keep-inconsistent

# 指定输出文件
python filter.py all.jsonl all_audit.jsonl -o output.jsonl

# 仅查看统计
python filter.py all.jsonl all_audit.jsonl --stats-only
```

### 参数说明

| 参数 | 说明 | 默认值 |
|:---|:---|:---|
| `original_file` | 原始文件（含 `metadata.intent`） | 必填 |
| `audit_file` | 审计结果文件 | 必填 |
| `-o, --output` | 输出文件路径 | 自动生成 |
| `--keep-inconsistent` | 保留不一致数据 | `False`（保留一致） |
| `--stats-only` | 仅显示统计 | `False` |

### 输出文件命名

| 模式 | 默认文件名 |
|:---|:---|
| 保留一致 | `{原名}_consistent.jsonl` |
| 保留不一致 | `{原名}_inconsistent.jsonl` |

### 统计信息示例

```
============================================================
统计信息:
  总匹配行数:           1000
  一致:                 850
  不一致:               150
    - 误报 (normal→dangerous): 45
    - 漏报 (dangerous→normal): 105
  准确率: 85.0%
============================================================
```

### 标签映射

| 原始 `metadata.intent` | Ground Truth |
|:---|:---|
| `benign` | `normal` |
| `attack` | `dangerous` |

---

## 三、完整流程

```bash
# Step 1: 审计原始数据
python audit_decision_completer.py all.jsonl

# Step 2: 筛选一致数据（用于训练）
python filter.py all.jsonl all_audit.jsonl

# Step 3: 查看不一致数据（错误分析）
python filter.py all.jsonl all_audit.jsonl --keep-inconsistent -o errors.jsonl

# Step 4: 查看统计
python filter.py all.jsonl all_audit.jsonl --stats-only
```

### 流程图

```
原始数据 (all.jsonl)
       │
       ▼
audit_decision_completer.py
       │
       ▼
审计结果 (all_audit.jsonl) ──┬── filter.py ──► 一致数据 (训练用)
                            │
                            └── filter.py --keep-inconsistent ──► 不一致数据 (错误分析)
```

---

