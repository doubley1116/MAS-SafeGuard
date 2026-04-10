# AuditDataGen

MAS-SafeBench 数据生成模块，负责生成 D3（攻击样本）和 D4（正常样本）以及用于模型训练的 audit/SFT 数据。

## 环境安装

```bash
pip install -r requirements.txt
```

---

## 数据生成

### D3 / D4：从 D1 数据清洗（推荐）

D3（攻击样本）和 D4（正常样本）直接从 D1 生成的完整 trace 数据清洗得到，保留完整的 `history_summary`、`call_path` 和结构化字段，质量远高于模板生成方式。

**前置条件**：先完成 D1 trace 生成（见下方"使用训练好的 Attacker 生成完整 trace"）。

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

#### 模型加载参数说明

所有模型超参均在 YAML 的 `models.attacker` / `models.defender` 节配置，无需修改代码：

**Attacker（`models.attacker`）：**

| 参数 | 默认值 | 说明 |
| --- | --- | --- |
| `type` | `"mock"` | 模型类型：`mock` / `qwen` |
| `name` | — | HuggingFace 模型 ID 或本地路径 |
| `device` | `"cpu"` | 设备，支持 `cuda:N` |
| `dtype` | `"bfloat16"` | 推理精度：`bfloat16` / `float16` / `float32` |
| `attn_impl` | `"sdpa"` | 注意力实现：`sdpa` / `flash_attention_2` / `eager` |
| `max_new_tokens` | `150` | 生成最大 token 数 |
| `top_p` | `0.9` | 采样 top-p |
| `temperature` | `0.8` | 采样温度 |
| `lora.r` | `32` | LoRA 秩 |
| `lora.alpha` | `64` | LoRA 缩放系数 |
| `lora.dropout` | `0.05` | LoRA Dropout |

**Defender（`models.defender`）：**

| 参数 | 默认值 | 说明 |
| --- | --- | --- |
| `type` | `"mock"` | 模型类型：`mock` / `hf` |
| `name` | — | HuggingFace 模型 ID 或本地路径 |
| `device` | `"cpu"` | 设备，支持 `cuda:N` |
| `dtype` | `"bfloat16"` | 推理精度：`bfloat16` / `float16` / `float32` |
| `attn_impl` | `"sdpa"` | 注意力实现：`sdpa` / `flash_attention_2` / `eager` |
| `max_length` | `1024` | 分类器最大输入长度 |
| `num_labels` | `2` | 分类标签数（`SAFE` / `MALICIOUS`） |

模型加载优先级：本地 HuggingFace 缓存 → 联网下载。`name` 填写 HF 模型 ID（如 `Qwen/Qwen2.5-1.5B-Instruct`）时自动查找本地缓存，无需手动指定路径。

---

## 使用训练好的 Attacker 生成完整 trace

trace_generator 生成的是完整多步 AuditEvent 序列（用于 D1 风格数据）：

```bash
# Mock 模式测试
python src/trace_generator.py --n 1 --out output_trace

# 真实 Attacker + 指定场景
python src/trace_generator.py --model-dir output/final_model/attacker --n 1 --out output_trace_real

# 需要 API 补全非攻击位置时，在 .env 中设置 API_KEY / BASE_URL / MODEL
```

---

## 骨架覆盖说明

```bash
python -c "
from src.skeletons import SKELETONS
from collections import Counter
types = Counter(s['scenario_type'] for s in SKELETONS)
for k,v in sorted(types.items()): print(f'{k}: {v}')
print(f'Total: {len(SKELETONS)}')
"
```

当前共 **80 条骨架**，覆盖：

| 攻击类型 | Trading | Healthcare | E-commerce | 合计 |
| --- | --- | --- | --- | --- |
| PathBypass | 5 | 4 | 3 | 12 |
| CallerImpersonation | 4 | 3 | 3 | 10 |
| SemanticInjection | 4 | 4 | 3 | 11 |
| RouterHijacking | 3 | 3 | 3 | 9 |
| IPI | 3 | 3 | 3 | 9 |
| AiTM | 4 | 3 | 3 | 10 |
| PromptInfection | 4 | 3 | 3 | 10 |
| benign | 3 | 3 | 3 | 9 |
