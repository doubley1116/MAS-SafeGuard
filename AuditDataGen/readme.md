# AuditDataGen

## 1. 环境安装

```bash
pip install -r requirements.txt
```

## 2. 基础骨架生成

```bash
python src/generator.py --out output --n 5
```

## 3. 对抗性 PPO 训练

```bash
python train/run_adversarial_ppo.py --config configs/adversarial_ppo_config.yaml
```

## 4. 使用训好的 Attacker 批量生成攻击数据集

```bash
python src/trace_generator.py --model-dir output/final_model/attacker --scenario all --out model_data --n 1000
```
