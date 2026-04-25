# AuditDataGen

MAS-SafeBench 数据生成模块，负责生成 D3（攻击样本）和 D4（正常样本）以及用于模型训练的 audit/SFT 数据。

## 环境安装

```bash
pip install -r requirements.txt
```

---

## 模型训练

### 对抗 GRPO 训练（Attacker vs Defender）

```bash
python train/run_adversarial_grpo.py --config configs/adversarial_grpo_config.yaml
```

本地轻量测试配置：

```bash
python train/run_adversarial_grpo.py --config configs/local_1_5B_test_config.yaml
```

训练产物保存至 `output/`（可在 config 中修改 `output.dir`），目录结构：

```text
output/
  checkpoint_0020/
    attacker/   # LoRA adapter
    defender/   # HF 分类器
    samples.jsonl
  final_model/
    attacker/
    defender/
```

---

## 使用训练好的 Attacker 生成完整 trace

`trace_generator.py` 生成的是完整多步 AuditEvent 序列（用于 D1 风格数据）。生成策略分为两类：

| 生成策略           | 覆盖场景                                                     | 说明                                                         |
| ------------------ | ------------------------------------------------------------ | ------------------------------------------------------------ |
| **骨架多步生成**   | `IPI`、`AiTM`                                                | 基于 `skeletons.py` 中预定义的 80 条骨架，逐 step 生成完整 trace。攻击位置由 Attacker 模型生成，其余位置由 API 补全或模板填充。 |
| **无骨架自由生成** | `PathBypass`、`CallerImpersonation`、`SemanticInjection`、`RouterHijacking`、`PromptInfection` | 不依赖骨架，直接调用 LLM API 从攻击意图生成单条 User 消息。  |

### 前置环境

在 `.env` 文件中配置（示例见 `.env.template`）：

```bash
API_KEY=your_api_key
BASE_URL=https://api.openai.com/v1  # 可选，使用第三方平台时填写
MODEL=gpt-4o-mini                    # 可选，默认 gpt-4o-mini
```

> **注意**：自由生成**必须**配置 `API_KEY`；骨架生成中若 `API_KEY` 缺失，非攻击位置会回退到模板填充，不影响主要功能。

### 参数说明

| 参数           | 默认值         | 说明                                                         |
| -------------- | -------------- | ------------------------------------------------------------ |
| `--model-dir`  | `None`         | 训练好的 Attacker 模型目录。仅骨架生成（`IPI` / `AiTM`）会使用该模型生成攻击内容；`None` 时回退到 MockAttacker。 |
| `--n`          | `3`            | 每条骨架生成的 trace 数。仅影响 `IPI`、`AiTM`、`benign`。    |
| `--n-freeform` | `50`           | 自由生成的总条数。仅影响 `PathBypass` 等无骨架攻击类型。     |
| `--scenario`   | `None`         | 逗号分隔的场景过滤，如 `IPI,AiTM` 或 `PathBypass,benign`。不传则生成全部类型。 |
| `--domain`     | `None`         | 逗号分隔的领域过滤，如 `financial,healthcare,ecommerce`。仅对自由生生效。 |
| `--api-model`  | `env MODEL`    | API 补全/自由生成使用的模型名，默认从 `.env` 的 `MODEL` 读取。 |
| `--out`        | `output_trace` | 输出目录，最终生成 `audit.jsonl`。                           |
| `--seed`       | `42`           | 随机种子。                                                   |
| `--gpus`       | `None`         | 逗号分隔的 GPU 编号，如 `0,1,2,3`。指定多于 1 张时自动启用多卡并行模式；仅指定 1 张时等同于单卡并指定设备；不传则交互询问。 |

### 使用示例

**使用训练好的 Attacker 生成全部数据**

```bash
python src/trace_generator.py  --model-dir output/final_model/attacker --n 3 --n-freeform 50 --gpus 0 --out output_trace_real
```
```bash
python src/trace_generator.py  --model-dir output/final_model/attacker --n 12 --n-freeform 1500 --gpus 0,1,2,3 --out output_trace_real
```
> 同时生成：
>
> - 骨架场景（`IPI` / `AiTM` / `benign`）：19 条骨架 × 3 次
> - 自由生成场景：50 条单条攻击事件

**只生成骨架中的 IPI **

```bash
python src/trace_generator.py \
  --model-dir output/final_model/attacker \
  --scenario IPI \
  --n 5 \
  --n-freeform 0 \
  --out output_trace_skeleton
```

**只生成自由场景（金融领域的 PathBypass）**

```bash
python src/trace_generator.py \
  --scenario PathBypass \
  --domain financial \
  --n-freeform 50 \
  --n 0 \
  --out output_trace_freeform
```

**指定 API 模型和种子**

```bash
python src/trace_generator.py \
  --model-dir output/final_model/attacker \
  --api-model gpt-4o \
  --seed 2024 \
  --n 5 \
  --out output_trace_seed2024
```

### 多卡并行生成

通过 `--gpus` 指定多张 GPU，程序会为每张卡启动一个独立子进程，各自加载一份 Attacker 模型，并行完成骨架任务和自由生成任务，结果实时写入同一个 `audit.jsonl`。

#### 架构说明

```text
Worker 0 (GPU 0) ─┐
Worker 1 (GPU 1) ─┼── 文件锁 ──► audit.jsonl（边生成边写入）
Worker 2 (GPU 2) ─┤
Worker 3 (GPU 3) ─┘
```

- **骨架任务**按轮询（round-robin）分配给各 worker，保证负载均衡
- **自由生成任务**按数量均分，余数补给前几个 worker
- 每个 worker 使用不同的随机种子偏移，保证生成多样性
- 采用 `multiprocessing.spawn` 启动，CUDA 上下文完全隔离，无冲突

#### 多卡命令示例

4 卡满载生成（推荐）：

```bash
python src/trace_generator.py \
  --model-dir output/final_model/attacker \
  --n 16 --n-freeform 4200 \
  --gpus 0,1,2,3 \
  --out output_trace_real
```

仅使用 2 张卡：

```bash
python src/trace_generator.py \
  --model-dir output/final_model/attacker \
  --n 8 --n-freeform 2000 \
  --gpus 0,1 \
  --out output_trace_real
```

指定单张卡（跳过交互询问）：

```bash
python src/trace_generator.py \
  --model-dir output/final_model/attacker \
  --n 16 --n-freeform 4200 \
  --gpus 2 \
  --out output_trace_real
```

> **注意**：多卡模式下不支持打乱输出顺序（incremental save 决定写入顺序）。如需打乱，在生成完成后对 `audit.jsonl` 做后处理。

---

## 数据清洗

### D3 / D4：从 D1 数据清洗（推荐）

D3（攻击样本）和 D4（正常样本）直接从 D1 生成的完整 trace 数据清洗得到，保留完整的 `history_summary`、`call_path` 和结构化字段，质量远高于模板生成方式。

**前置条件**：先完成 D1 trace 生成（见"使用训练好的 Attacker 生成完整 trace"）。

```bash
python src/d3_d4_cleaner.py --input output_trace_real/audit.jsonl
```

D3 输出（T3/T4/T5/T7 四种语义攻击，每条为攻击应被拦截的单条 AuditEvent）：

```text
data/d3/
  type3_semantic_injection.jsonl
  type4_route_hijack.jsonl
  type5_ipi.jsonl
  type7_prompt_infection.jsonl
```

D4 输出（benign trace 全部事件 + attack trace 中的非攻击步骤）：

```text
data/d4/
  financial.jsonl
  healthcare.jsonl
  ecommerce.jsonl
```

参数说明：

| 参数 | 默认值 | 说明 |
| --- | --- | --- |
| `--input` | `output_trace_real/audit.jsonl` | D1 数据文件路径 |
| `--d3-out` | `data/d3` | D3 输出目录 |
| `--d4-out` | `data/d4` | D4 输出目录 |

## 
## 补充修复 audit.jsonl 中的缺失 label / reason

`trace_generator.py` 在生成时会调用 API 盲审每个事件，产出 `audit_decision.label` 和 `audit_decision.reason`。如果 API 未配置或调用异常，这些字段会出现以下三种问题：

1. `label == ""` 且 `reason == ""`（API 客户端未初始化）
2. `reason == "检测到潜在攻击行为"`（API 调用异常时的硬编码 fallback）
3. `label == ""`（API 返回了空 label）

`src/fix_audit_labels.py` 用于**事后补充修复**这些问题记录，对已有正常 reason 的事件完全不动。

### 前置条件

需要与生成时相同的 API 环境变量（脚本不会自动加载 `.env`）：

```bash
export API_KEY=your_api_key
export BASE_URL=https://dashscope.aliyuncs.com/compatible-mode/v1  # 可选
export MODEL=qwen-plus                                             # 可选
```

Windows PowerShell：

```powershell
$env:API_KEY="your_api_key"
$env:BASE_URL="https://dashscope.aliyuncs.com/compatible-mode/v1"
$env:MODEL="qwen-plus"
```

### 用法

**直接覆盖原文件：**

```bash
cd AuditDataGen
python src/fix_audit_labels.py --input output_trace_real/audit.jsonl
```

**输出到新文件（推荐先试用）：**

```bash
python src/fix_audit_labels.py --input output_trace_real/audit.jsonl --output output_trace_real/audit_fixed.jsonl
```

### 参数说明

| 参数 | 默认值 | 说明 |
| --- | --- | --- |
| `--input` | `output_trace_real/audit.jsonl` | 待修复的 audit.jsonl 路径 |
| `--output` | `None`（覆盖输入文件） | 修复后输出路径 |
| `--model` | `env MODEL` 或 `qwen-plus` | API 盲审使用的模型 |
| `--batch-save` | `100` | 每处理 N 条保存一次中间结果，防止中断丢失进度 |

### 修复逻辑

- **只修复**满足以下任一条件的记录，其他记录完全不动：
  - `label == ""`
  - `reason == ""`
  - `reason == "检测到潜在攻击行为"`
- **盲审 prompt**：复用 `free_form_generator.py` 中的 `_AUDITOR_PROMPT`，不告知攻击类型，保持与原始生成一致的盲审特性。
- **content 长度**：放宽到 800 字（原始生成仅截断 300 字），让 LLM 能看到更多上下文。
- **API 失败时**：`label` 和 `reason` 保持为空，不插入任何兜底文本，便于下次重跑。
- **进度保存**：每 100 条自动写入 `.tmp` 临时文件，中断后可直接用该临时文件继续。
