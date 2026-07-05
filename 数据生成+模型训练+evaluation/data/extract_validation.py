#!/usr/bin/env python3
"""
extract_validation.py - 从原始数据中提取固定的验证集（JSONL）
================================================================
用法示例：
    python extract_validation.py --data all_consistent.jsonl --output validation_set.jsonl

参数说明：
    --data      : 原始数据文件路径（默认 all_consistent.jsonl）
    --output    : 输出的验证集文件路径（默认 validation_set.jsonl）
    --split     : 验证集比例，默认 0.1（10%）
    --seed      : 随机种子，默认 42
    --no-filter : 不加过滤（默认会执行与原脚本相同的过滤）
================================================================
"""

import os
import json
import argparse
from datasets import load_dataset

# ========== 与原脚本完全相同的标签映射和过滤逻辑 ==========
LABEL_MAP = {
    "normal": "safe", "benign": "safe", "safe": "safe",
    "ambiguous": "suspicious", "suspicious": "suspicious",
    "dangerous": "dangerous",
}
VALID_LABELS = {"safe", "suspicious", "dangerous"}


def is_valid(example):
    """与原脚本完全相同的过滤条件"""
    audit = example.get("audit_result", {})
    raw_label = audit.get("label", "")
    label = LABEL_MAP.get(raw_label.lower().strip(), "")
    if label not in VALID_LABELS:
        return False
    if not audit.get("analysis", "").strip():
        return False
    if not audit.get("reason", "").strip():
        return False
    return True


def extract_validation_set(data_path, output_path, split_ratio=0.1, seed=42, apply_filter=True):
    print("=" * 60)
    print("开始提取固定验证集")
    print(f"数据文件: {data_path}")
    print(f"验证集比例: {split_ratio} | 随机种子: {seed}")
    print(f"应用过滤: {apply_filter}")
    print("=" * 60)

    # 加载原始数据
    dataset = load_dataset("json", data_files=data_path, split="train")
    original_len = len(dataset)
    print(f"原始数据总量: {original_len} 条")

    if apply_filter:
        dataset = dataset.filter(is_valid)
        filtered_len = len(dataset)
        print(f"过滤后剩余: {filtered_len} 条 (过滤掉 {original_len - filtered_len} 条)")

        # 统计过滤后的标签分布
        label_stats = {}
        for ex in dataset:
            raw = ex["audit_result"]["label"]
            lbl = LABEL_MAP.get(raw.lower().strip(), raw)
            label_stats[lbl] = label_stats.get(lbl, 0) + 1
        # ✅ 修复1：打印中文正常
        print(f"过滤后标签分布: {json.dumps(label_stats, indent=2, ensure_ascii=False)}")
    else:
        print("跳过过滤，使用全部原始数据")

    # 划分训练/验证集
    split = dataset.train_test_split(test_size=split_ratio, seed=seed)
    train_ds = split["train"]
    eval_ds = split["test"]

    print(f"训练集大小: {len(train_ds)}")
    print(f"验证集大小: {len(eval_ds)}")

    # ✅ 修复2：手动保存 JSONL，保证中文正常（替换原来的 to_json）
    with open(output_path, "w", encoding="utf-8") as f:
        for example in eval_ds:
            f.write(json.dumps(example, ensure_ascii=False) + "\n")

    print(f"\n✅ 验证集已保存至: {os.path.abspath(output_path)}")
    print(f"共 {len(eval_ds)} 条数据，可直接用于 SFTTrainer 的 eval_dataset 参数。")

    # 可选：同时保存一个验证集元信息文件
    meta = {
        "source_file": data_path,
        "split_ratio": split_ratio,
        "seed": seed,
        "filter_applied": apply_filter,
        "original_size": original_len,
        "filtered_size": len(dataset) if apply_filter else original_len,
        "validation_size": len(eval_ds),
        "train_size": len(train_ds),
    }
    meta_path = output_path.replace(".jsonl", "_meta.json")
    with open(meta_path, "w", encoding="utf-8") as f:
        # ✅ 修复3：meta 文件也正常显示中文
        json.dump(meta, f, indent=2, ensure_ascii=False)
    print(f"元信息已保存至: {meta_path}")

    return eval_ds


def main():
    parser = argparse.ArgumentParser(description="从原始数据中提取固定的验证集（JSONL格式）")
    parser.add_argument("--data", type=str, default="all_consistent.jsonl",
                        help="原始数据文件路径（JSONL）")
    parser.add_argument("--output", type=str, default="validation_set.jsonl",
                        help="输出的验证集文件路径（JSONL）")
    parser.add_argument("--split", type=float, default=0.1,
                        help="验证集比例，默认 0.1")
    parser.add_argument("--seed", type=int, default=42,
                        help="随机种子，默认 42")
    parser.add_argument("--no-filter", action="store_true",
                        help="不执行过滤（默认会执行与原脚本相同的过滤）")
    args = parser.parse_args()

    extract_validation_set(
        data_path=args.data,
        output_path=args.output,
        split_ratio=args.split,
        seed=args.seed,
        apply_filter=not args.no_filter,
    )


if __name__ == "__main__":
    main()