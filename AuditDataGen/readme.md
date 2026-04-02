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
|------|--------|------|
| `--input` | `output_trace_real/audit.jsonl` | D1 数据文件路径 |
| `--d3-out` | `data/d3` | D3 输出目录 |
| `--d4-out` | `data/d4` | D4 输出目录 |

---

### model_data：规则填充全量数据（用于模型训练预热）

不依赖 LLM，完全本地运行，覆盖全部 42 条骨架（7 类攻击 × Trading/Healthcare/Ecommerce + benign）。

```bash
python src/generator.py --n 5 --out model_data --seed 42
```

输出：

- `model_data/audit.jsonl`：完整 AuditEvent 序列（含 hash chain、history_summary、audit_decision）
- `model_data/sft_train.jsonl`：SFT 训练格式（input 包含 current_event + history_summary + call_path）

常用参数：

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `--n` | 5 | 每条骨架采样次数 |
| `--scenario-type` | 全部 | 逗号分隔，如 `SemanticInjection,IPI` |
| `--no-sft` | - | 不生成 sft_train.jsonl |
| `--no-shuffle` | - | 不打乱顺序 |

---

## 模型训练

### 对抗 PPO 训练（Attacker vs Defender）

```bash
python train/run_adversarial_ppo.py --config configs/adversarial_ppo_config.yaml
```

本地轻量测试配置：

```bash
python train/run_adversarial_ppo.py --config configs/local_1_5B_test_config.yaml
```

训练产物保存至 `output_local_test/`，目录结构：

```text
output_local_test/
  checkpoint_0005/
    attacker/   # LoRA adapter
    defender/   # BERT-based defender
    samples.jsonl
  final_model/
    attacker/
    defender/
```

---

## 使用训练好的 Attacker 生成完整 trace

trace_generator 生成的是完整多步 AuditEvent 序列（用于 D1 风格数据）：

```bash
# Mock 模式测试
python src/trace_generator.py --n 2 --out output_trace

# 真实 Attacker + 指定场景
python src/trace_generator.py --model-dir output_local_test/final_model/attacker --n 10 --out output_trace_real 

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

当前共 **42 条骨架**，覆盖：

| 攻击类型 | Trading | Healthcare | Ecommerce |
| --- | --- | --- | --- |
| PathBypass | 3+1支路 | 1 | 1 |
| CallerImpersonation | 3 | 1 | 1 |
| SemanticInjection | 3+1支路 | 1 | 1 |
| RouterHijacking | 3 | 1 | 1 |
| IPI | 3 | 1 | 1 |
| AiTM | 3 | 1 | 1 |
| PromptInfection | 3 | 1 | 1 |
| benign | 3 | 1 | 1 |
