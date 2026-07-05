# 训练
python sft_train.py --data all_consistent.jsonl

# 显存不足时加 4bit 量化
python sft_train.py --data all_consistent.jsonl --use-4bit

# 测试推理
python sft_train.py --test --model-path ./qwen-sft-output/final_model