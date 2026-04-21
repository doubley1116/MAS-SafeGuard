#!/usr/bin/env python3
"""
d3_d4_cleaner.py
────────────────
D3/D4 数据清洗器：从 D1 生成的 audit.jsonl 清洗出攻击样本（D3）和正常样本（D4）

分类核心原则（按 metadata 硬编码字段，不依赖盲审 label）：
  - 按 metadata.intent 区分攻击/正常："attack" → D3，"benign" → D4
  - D3 细分按 metadata.scenario（PathBypass / IPI / AiTM / ...）
  - D4 细分按 metadata.domain（financial / healthcare / ...）
  - 不修改任何 event 字段，不硬编码场景/域名映射表

输出结构：
  out_dir/
    split/                    # 文件夹一：按类别分开
      d3/
        {scenario}.jsonl      # 每种攻击类型一个文件
      d4/
        {domain}.jsonl        # 每种场景域名一个文件
    merged/                   # 文件夹二：不细分
      d3.jsonl
      d4.jsonl
    all/                      # 文件夹三：全部混在一起
      all.jsonl

使用示例：
  python src/d3_d4_cleaner.py --input output_trace_real/audit.jsonl --out data
"""

import json
import argparse
from pathlib import Path


def is_attack_event(event: dict) -> bool:
    """根据 metadata.intent 判断是否为攻击事件。"""
    intent = event.get("metadata", {}).get("intent")
    if intent == "attack":
        return True
    if intent == "benign":
        return False
    # fallback：旧数据没有 intent 字段时，根据 scenario 推断
    scenario = event.get("metadata", {}).get("scenario", "")
    return scenario not in ("", "benign")


def get_d3_category(event: dict) -> str:
    """返回 D3 细分类别名（metadata.scenario），为空则返回 unknown。"""
    return event.get("metadata", {}).get("scenario") or "unknown"


def get_d4_category(event: dict) -> str:
    """返回 D4 细分类别名（metadata.domain），为空则返回 unknown。"""
    return event.get("metadata", {}).get("domain") or "unknown"


def run_cleaner(
    input_path: str = "output_trace_real/audit.jsonl",
    out_dir: str = "data",
):
    input_file = Path(input_path)
    if not input_file.exists():
        print(f"❌ 输入文件不存在: {input_path}")
        return

    # 收集器
    d3_split: dict[str, list[dict]] = {}
    d4_split: dict[str, list[dict]] = {}
    d3_merged: list[dict] = []
    d4_merged: list[dict] = []
    all_events: list[dict] = []

    stats = {"total": 0, "d3": 0, "d4": 0}

    print(f"📂 读取: {input_path}")
    with open(input_file, encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue
            event = json.loads(line)
            all_events.append(event)
            stats["total"] += 1

            if is_attack_event(event):
                d3_merged.append(event)
                cat = get_d3_category(event)
                d3_split.setdefault(cat, []).append(event)
                stats["d3"] += 1
            else:
                d4_merged.append(event)
                cat = get_d4_category(event)
                d4_split.setdefault(cat, []).append(event)
                stats["d4"] += 1

    out = Path(out_dir)

    # ── 文件夹一：split ──
    (out / "split" / "d3").mkdir(parents=True, exist_ok=True)
    for cat, events in d3_split.items():
        fpath = out / "split" / "d3" / f"{cat}.jsonl"
        with open(fpath, "w", encoding="utf-8") as f:
            for e in events:
                f.write(json.dumps(e, ensure_ascii=False) + "\n")
        print(f"   split/d3/{cat}.jsonl: {len(events)} 条")

    (out / "split" / "d4").mkdir(parents=True, exist_ok=True)
    for cat, events in d4_split.items():
        fpath = out / "split" / "d4" / f"{cat}.jsonl"
        with open(fpath, "w", encoding="utf-8") as f:
            for e in events:
                f.write(json.dumps(e, ensure_ascii=False) + "\n")
        print(f"   split/d4/{cat}.jsonl: {len(events)} 条")

    # ── 文件夹二：merged ──
    (out / "merged").mkdir(parents=True, exist_ok=True)
    for name, events in (("d3", d3_merged), ("d4", d4_merged)):
        fpath = out / "merged" / f"{name}.jsonl"
        with open(fpath, "w", encoding="utf-8") as f:
            for e in events:
                f.write(json.dumps(e, ensure_ascii=False) + "\n")
        print(f"   merged/{name}.jsonl: {len(events)} 条")

    # ── 文件夹三：all ──
    (out / "all").mkdir(parents=True, exist_ok=True)
    fpath = out / "all" / "all.jsonl"
    with open(fpath, "w", encoding="utf-8") as f:
        for e in all_events:
            f.write(json.dumps(e, ensure_ascii=False) + "\n")
    print(f"   all/all.jsonl: {len(all_events)} 条")

    print(f"\n{'='*50}")
    print("✅ D3/D4 数据清洗完成")
    print(f"{'='*50}")
    print(f"  总事件: {stats['total']} 条")
    print(f"  D3（攻击）: {stats['d3']} 条")
    print(f"  D4（正常）: {stats['d4']} 条")
    print(f"\n  输出目录: {out_dir}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="D3/D4 数据清洗器 —— 按 metadata.intent/scenario/domain 分类，不修改数据",
    )
    parser.add_argument("--input", type=str, default="output_trace_real/audit.jsonl",
                        help="输入 audit.jsonl 路径")
    parser.add_argument("--out", type=str, default="data",
                        help="输出根目录（默认: data）")
    args = parser.parse_args()
    run_cleaner(args.input, args.out)
