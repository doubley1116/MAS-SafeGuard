# 安装

```bash
pip install -r requirements.txt
```

# 运行

```bash
# 骨架生成
python src/generator.py --out output --n 5

# PPO训练
python train/run_adversarial_ppo.py --config configs/adversarial_ppo_config.yaml

# 模型生成
python src/generate_with_model.py --model-dir output/final_model/attacker --out model_data --n 5
```
