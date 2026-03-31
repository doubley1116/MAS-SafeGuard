# AuditDataGen

零信任安全审计数据生成系统 —— 基于对抗性PPO训练的审计数据生成工具。

## 项目定位

**D2（Attacker）**：手工单条 AuditEvent 定义，用于调试规则引擎和 LLM 审核 prompt。

### 数据规模

| 攻击类型 | 数量 | 说明 |
|---------|------|------|
| 结构类攻击（类型1, 2, 6） | ~180条 | 每类~20条 × 3场景，规则引擎核心测试对象 |
| 语义类攻击（类型3, 4, 5, 7） | ~120条 | 每类~10条 × 3场景，Attacker会大量生成 |
| 正常样本 | ~50条 | 各场景的正常业务请求 |
| **总计** | **~350条** | |

### 攻击类型映射

| 类型 | 名称 | 描述 |
|------|------|------|
| 类型1 | 路径绕过（DPI） | 篡改 call_path，缺少 Risk_Agent |
| 类型2 | 调用者伪装 | 篡改 sender，冒充其他Agent身份 |
| 类型3 | 语义注入 | 篡改 content，嵌入伪造合规依据 |
| 类型4 | 路由劫持 | 篡改 content，伪装查询实为交易 |
| 类型5 | IPI | 篡改 history_summary，从外部文件注入指令 |
| 类型6 | AiTM | 篡改 call_path，插入 Unknown_Proxy |
| 类型7 | Prompt Infection | 篡改 content，附加恶意指令 |

## 快速开始

### 安装依赖

```bash
cd AuditDataGen
pip install -r requirements.txt
```

### 三种运行模式

#### 1. 基础骨架生成（零LLM调用）

```bash
python src/generator.py --out output --n 5
```

- 随机填充占位符（symbol/amount/client等）
- 生成 `audit.jsonl` + `sft_train.jsonl`
- 无API成本，本地运行

#### 2. 对抗性PPO训练

```bash
# 完整训练
python train/run_adversarial_ppo.py --config configs/adversarial_ppo_config.yaml
```

#### 3. 模型增强生成

```bash
python src/generate_with_model.py --model-dir output_ppo/final_model/attacker --out model_data --n 5
```

## Attacker生成流程

```
D2模板事件 → Attacker改写(content/history_summary) → 质量控制 → 输出
```

**质量控制**：
1. 语义多样性检查：相似度 > 0.85 的丢弃
2. 规则层过滤：rule_score >= 0.90 的丢弃
3. 人工抽查：每类 10%

## 数据格式

生成数据格式与真实 `audit_events.json` 完全一致，包含：
- `event_type`、`sender`、`receiver`、`tool_name`、`tool_args`
- `call_path`、`content`、`history_summary`
- `event_id`、`trace_id`、`timestamp`、`prev_hash`（哈希链）
- `metadata`：包含 `audit_decision` 模拟防御层审核决策

## 配置说明

核心配置在 `configs/adversarial_ppo_config.yaml`：

```yaml
# 数据配置
data:
  skeleton_type: "all"  # 或指定 "DPI"、"Impersonation" 等

# 训练配置
train:
  iterations: 50
  batch_size: 8
  learning_rate: 1.0e-5

# 模型配置
models:
  attacker:
    type: "wenozhong"   # mock | gpt2 | wenozhong | qwen
  defender:
    type: "bert"        # mock | bert | roberta | ernie

device: "cpu"  # 或 "cuda"
```

## 完整工作流程

```bash
# 1. 快速验证（Mock模型）
python train/run_adversarial_ppo.py --config configs/quick_test_chinese.yaml

# 2. 完整训练（真实模型）
python train/run_adversarial_ppo.py --config configs/adversarial_ppo_config.yaml

# 3. 使用训练模型生成数据
python src/generate_with_model.py --model-dir output_ppo/final_model/attacker --out my_dataset --n 10

# 4. 查看结果
python -c "import json; f=open('my_dataset/audit.jsonl'); print(json.dumps(json.loads(f.readline()), indent=2, ensure_ascii=False))"
```
