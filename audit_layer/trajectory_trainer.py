"""
trajectory_trainer.py — 轨迹检测器初始化脚本

从历史 JSONL 日志中提取正常 call_path，初始化 EMA 基线。
不需要 GPU，不需要训练循环，纯统计计算。

用法:
    python -m audit_layer.trajectory_trainer \
        --data AuditDataGen/data/all_consistent.jsonl \
        --roles audit_layer/roles/ \
        --output audit_layer/trajectory_checkpoints/detector.pkl
"""

from __future__ import annotations

import argparse
import json
import os
from collections import defaultdict
from typing import Optional

from audit_layer.trajectory_model import TrajectoryAnomalyDetector


def extract_call_paths(
    jsonl_paths: list[str],
    benign_only: bool = True,
    min_path_len: int = 2,
) -> list[list[str]]:
    """
    从 JSONL 日志中提取所有 call_path。

    同时收集最后一条 call_path（代表完整 trace 的最终路由状态）
    和每条事件自带的 call_path。
    """
    paths: list[list[str]] = []

    for filepath in jsonl_paths:
        with open(filepath, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    continue

                obj = event.get("original", event)
                metadata = obj.get("metadata", {})

                if benign_only and metadata.get("intent") == "attack":
                    continue

                call_path = obj.get("call_path", [])
                if len(call_path) >= min_path_len:
                    paths.append(call_path)

    return paths


def build_trajectory_pipeline(
    jsonl_paths: list[str],
    output_path: str,
    role_discovery_path: Optional[str] = None,
    alpha: float = 0.05,
) -> TrajectoryAnomalyDetector:
    """
    从 JSONL 数据初始化轨迹检测器。

    1. 提取正常 call_path
    2. 喂给检测器建立 EMA 基线
    3. 保存
    """
    print("=" * 60)
    print("轨迹检测器初始化（EMA + 角色抽象）")
    print("=" * 60)

    # 1. 加载角色模型（可选）
    rd = None
    if role_discovery_path:
        from audit_layer.role_discovery import RoleDiscovery
        rd = RoleDiscovery.load(role_discovery_path)
        print(f"\n[1/3] 角色模型已加载: {role_discovery_path}")
        print(f"  Agent 数: {len(rd.agents)}")
        print(f"  角色数: {len(rd.role_names)}")
    else:
        print("\n[1/3] 未指定角色模型，将使用 agent 名称作为特征")

    # 2. 提取正常 call_path
    print("\n[2/3] 提取正常 call_path...")
    paths = extract_call_paths(jsonl_paths)
    print(f"  正常轨迹数: {len(paths)}")
    if paths:
        lengths = [len(p) for p in paths]
        print(f"  路径深度: min={min(lengths)}, max={max(lengths)}, "
              f"mean={sum(lengths)/len(lengths):.1f}")

    # 3. 初始化检测器
    print(f"\n[3/3] 初始化 EMA 基线 (alpha={alpha})...")
    detector = TrajectoryAnomalyDetector(role_discovery=rd, alpha=alpha)
    detector.fit_normal(paths)

    print(f"\n  基线统计 (n={detector.observation_count}):")
    print(detector.summary())

    # 保存
    detector.save(output_path)
    print(f"\n检测器已保存到: {output_path}")
    print("=" * 60)

    return detector


# ══════════════════════════════════════════════════════════════
# CLI
# ══════════════════════════════════════════════════════════════

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="轨迹检测器初始化（EMA + 角色抽象）"
    )
    parser.add_argument("--data", required=True, nargs="+",
                        help="JSONL 数据路径")
    parser.add_argument("--roles", default=None,
                        help="角色发现模型目录（可选）")
    parser.add_argument("--output", default="audit_layer/trajectory_checkpoints/detector.pkl",
                        help="输出路径 (.pkl)")
    parser.add_argument("--alpha", type=float, default=0.05,
                        help="EMA 学习率 (默认 0.05)")
    args = parser.parse_args()

    os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)

    build_trajectory_pipeline(
        jsonl_paths=args.data,
        output_path=args.output,
        role_discovery_path=args.roles,
        alpha=args.alpha,
    )
    print("\n初始化完成!")
