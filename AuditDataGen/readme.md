# 1. 环境安装
pip install -r requirements.txt

# 2. 基础骨架生成 
python src/generator.py --out output --n 5

# 3. 对抗性 PPO 训练 
python train/run_adversarial_ppo.py --config configs/adversarial_ppo_config.yaml

# 4. 使用训好的 Attacker 批量生成 D3 攻击数据集
python src/generate_with_model.py --model-dir output/final_model/attacker --scenario-type all --out model_data --n 1000