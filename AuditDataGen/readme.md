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
| `--no-shuffle` | `False`        | 不打乱输出顺序。                                             |

### 使用示例

**使用训练好的 Attacker 生成全部数据**

```bash
python src/trace_generator.py \
  --model-dir output/final_model/attacker \
  --n 3 \
  --n-freeform 50 \
  --out output_trace_real
```

> 同时生成：
>
> - 骨架场景（`IPI` / `AiTM` / `benign`）：80 条骨架 × 3 次 = 240 条 trace
> - 自由生成场景：50 条单条攻击事件

**只生成骨架中的 IPI 和 AiTM**

```bash
python src/trace_generator.py \
  --model-dir output/final_model/attacker \
  --scenario IPI,AiTM \
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
