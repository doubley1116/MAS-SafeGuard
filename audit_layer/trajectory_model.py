"""
trajectory_model.py — 基于 EWMA + 角色抽象的轻量轨迹监控器

原理（类比 PID 控制器 / 风扇调速）：
  - 维护每个轨迹特征（深度、角色熵、非法跳数……）的 EWMA 均值和方差
  - 每次观察到正常 call_path 时，以 α=0.05 的速率更新基线
  - 新 call_path 偏离基线超过 k 倍标准差 → 异常

与深度学习方案的本质区别：
  - 不是"训练一个模型来编码轨迹"，而是"维护一组统计量的自适应阈值"
  - 在线学习：每看到一条正常轨迹就更新一次，越用越准
  - 零外部依赖（仅需 numpy），推理 < 0.01ms
  - 完全可解释：每个告警都能追溯到具体哪个特征异常

特征维度（全部从 call_path + 角色映射中提取）：
  depth          — 路径深度（agent 数量）
  unique_roles   — 去重后的角色种类数
  role_entropy   — 角色分布的香农熵
  illegal_jumps  — 转移概率为 0 的角色跳数
  backtracks     — 回到之前出现过的角色的次数
  max_gap        — 同一角色在路径中的最大间隔
"""

from __future__ import annotations

import os
import pickle
from collections import Counter
from typing import Optional

import numpy as np


# ══════════════════════════════════════════════════════════════
# 在线高斯估计器
# ══════════════════════════════════════════════════════════════

class OnlineGaussian:
    """
    EWMA 维护的在线高斯分布。

    每 observe(x) 一次，均值和方差向 x 移动 α 步。
    不需要存储任何历史数据 —— O(1) 内存，O(1) 更新。

    alpha 的含义：
      - 大 (0.3): 快速适应，但对噪声敏感
      - 小 (0.01): 稳定，但适应慢
      - 默认 0.05: 约 20 次观测后旧数据权重衰减到 ~36%
    """

    def __init__(self, alpha: float = 0.05, k: float = 3.0):
        self.alpha = alpha
        self.k = k          # 几倍标准差算异常
        self.mean: Optional[float] = None
        self.var: float = 0.0
        self.n_obs: int = 0

    def observe(self, x: float) -> None:
        """用新观测更新 EWMA 均值和方差."""
        self.n_obs += 1
        if self.mean is None:
            self.mean = x
            self.var = 0.0
        else:
            delta = x - self.mean
            self.mean += self.alpha * delta
            # Welford-style EWMA 方差更新
            self.var = (1 - self.alpha) * (self.var + self.alpha * delta ** 2)

    def z_score(self, x: float) -> float:
        """返回 x 偏离均值的标准差倍数."""
        if self.mean is None or self.var < 1e-10:
            return 0.0
        return abs(x - self.mean) / (self.var ** 0.5)

    def is_anomaly(self, x: float) -> bool:
        """x 是否超过 k 倍标准差."""
        return self.z_score(x) > self.k

    def anomaly_score(self, x: float) -> float:
        """
        返回归一化的异常分 [0, 1]。
        0 = 完全在正常范围内，1 = 严重偏离。
        """
        z = self.z_score(x)
        if z <= self.k:
            return 0.0
        return min(1.0, (z - self.k) / (self.k * 2))

    def to_dict(self) -> dict:
        return {
            "alpha": self.alpha, "k": self.k,
            "mean": self.mean, "var": self.var, "n_obs": self.n_obs,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "OnlineGaussian":
        obj = cls(alpha=d["alpha"], k=d["k"])
        obj.mean = d["mean"]
        obj.var = d["var"]
        obj.n_obs = d["n_obs"]
        return obj


# ══════════════════════════════════════════════════════════════
# 基于角色抽象的轨迹监控器
# ══════════════════════════════════════════════════════════════

class RoleAdaptiveMonitor:
    """
    基于角色抽象 + EWMA 的轨迹监控器。

    - observe(call_path): 用正常轨迹更新 EWMA 基线
    - score(call_path): 返回 [0,1] 异常分
    - 内部维护 6 个 OnlineGaussian，每个管一个特征维度
    """

    def __init__(
        self,
        role_discovery=None,  # RoleDiscovery 实例，可选
        alpha: float = 0.05,
        k_depth: float = 3.0,
        k_roles: float = 2.5,
        k_entropy: float = 3.5,
        k_jumps: float = 2.0,
        k_backtracks: float = 2.5,
        k_gap: float = 2.0,
        k_missing: float = 1.5,
    ):
        self.rd = role_discovery

        self._stats = {
            "depth":        OnlineGaussian(alpha, k_depth),
            "unique_roles": OnlineGaussian(alpha, k_roles),
            "role_entropy": OnlineGaussian(alpha, k_entropy),
            "illegal_jumps": OnlineGaussian(alpha, k_jumps),
            "backtracks":   OnlineGaussian(alpha, k_backtracks),
            "max_gap":      OnlineGaussian(alpha, k_gap),
            "spec_no_review": OnlineGaussian(alpha, k_missing),
        }

    # ── 特征提取 ──

    def _extract(self, call_path: list[str]) -> dict[str, float]:
        """从一条 call_path 中提取 6 个标量特征."""
        n = len(call_path)

        # 角色序列
        if self.rd is not None:
            roles = [self.rd.get_role(a) for a in call_path]
        else:
            roles = call_path  # 无角色模型时退化为 agent 名

        # 角色熵
        role_counts = Counter(roles)
        total = sum(role_counts.values())
        entropy = -sum(
            (c / total) * np.log(c / total + 1e-10)
            for c in role_counts.values()
        )

        # 非法角色跳数
        illegal = 0
        if self.rd is not None:
            for i in range(len(roles) - 1):
                if self.rd.transition_prob(roles[i], roles[i + 1]) == 0.0:
                    illegal += 1

        # 回退数（回到之前出现过的角色，但不包括连续重复）
        backtracks = 0
        for i in range(2, len(roles)):
            if roles[i] in roles[:i - 1] and roles[i] != roles[i - 1]:
                backtracks += 1

        # 最大角色跨度
        first_occ: dict[str, int] = {}
        max_gap = 0
        for i, r in enumerate(roles):
            if r not in first_occ:
                first_occ[r] = i
            max_gap = max(max_gap, i - first_occ[r])

        # specialist 出现但 reviewer 缺席 → 典型路径绕过信号
        unique_roles_set = set(roles)
        spec_no_review = 1.0 if ("specialist" in unique_roles_set
                                 and "reviewer" not in unique_roles_set) else 0.0

        return {
            "depth": float(n),
            "unique_roles": float(len(unique_roles_set)),
            "role_entropy": float(entropy),
            "illegal_jumps": float(illegal),
            "backtracks": float(backtracks),
            "max_gap": float(max_gap),
            "spec_no_review": spec_no_review,
        }

    # ── 在线学习 ──

    def observe(self, call_path: list[str]) -> None:
        """用一条正常 call_path 更新所有 EWMA 基线."""
        feats = self._extract(call_path)
        for name, value in feats.items():
            self._stats[name].observe(value)

    def observe_batch(self, call_paths: list[list[str]]) -> None:
        """批量观察正常轨迹以快速建立基线."""
        for path in call_paths:
            self.observe(path)

    # ── 异常评分 ──

    def score(self, call_path: list[str]) -> tuple[float, dict]:
        """
        对一条 call_path 打分。

        Returns:
            (anomaly_score, details)
            anomaly_score ∈ [0, 1]，所有异常维度的平均值
            details: {feature_name: {"value": ..., "z_score": ..., "anomaly": bool}}
        """
        feats = self._extract(call_path)
        details = {}
        anomaly_scores = []

        for name, value in feats.items():
            stat = self._stats[name]
            z = stat.z_score(value)
            details[name] = {
                "value": round(value, 3),
                "mean": round(stat.mean, 3) if stat.mean is not None else None,
                "z_score": round(z, 2),
                "anomaly": z > stat.k,
            }
            if z > stat.k:
                anomaly_scores.append(stat.anomaly_score(value))

        if not anomaly_scores:
            return 0.0, details

        return round(float(np.mean(anomaly_scores)), 4), details

    def score_simple(self, call_path: list[str]) -> float:
        """只返回异常分，不返回详情."""
        score_val, _ = self.score(call_path)
        return score_val

    # ── 状态查询 ──

    @property
    def is_ready(self) -> bool:
        """是否已有足够的观测来产生有意义的评分."""
        return all(s.n_obs >= 10 for s in self._stats.values())

    @property
    def observation_count(self) -> int:
        return max(s.n_obs for s in self._stats.values())

    def summary(self) -> str:
        """返回人类可读的基线摘要."""
        lines = []
        for name, stat in self._stats.items():
            if stat.mean is not None:
                lines.append(
                    f"  {name:15s}: μ={stat.mean:6.3f}, σ={stat.var**0.5:6.3f}, "
                    f"阈值=[{stat.mean - stat.k * stat.var**0.5:.3f}, "
                    f"{stat.mean + stat.k * stat.var**0.5:.3f}], n={stat.n_obs}"
                )
        return "\n".join(lines)


# ══════════════════════════════════════════════════════════════
# 轨迹异常检测器（对外接口，与旧版保持兼容）
# ══════════════════════════════════════════════════════════════

class TrajectoryAnomalyDetector:
    """
    轨迹异常检测器 — SecurityCore 的接入点。

    封装 RoleAdaptiveMonitor，提供 save/load 和简化的 score 接口。

    用法:
        # 方式 1: 从历史数据初始化
        detector = TrajectoryAnomalyDetector(role_discovery=rd)
        detector.fit_normal(normal_paths)

        # 方式 2: 加载已保存的检测器
        detector = TrajectoryAnomalyDetector.load("detector.pkl", role_discovery=rd)

        # 推理
        score = detector.score(["User", "Triage", "Diagnosis", "Review"])

        # 在线学习（确认正常后调用）
        detector.observe(["User", "Triage", "Diagnosis", "Review"])
    """

    def __init__(
        self,
        role_discovery=None,
        alpha: float = 0.05,
        **kwargs,
    ):
        self.monitor = RoleAdaptiveMonitor(
            role_discovery=role_discovery,
            alpha=alpha,
            **kwargs,
        )

    def fit_normal(self, call_paths: list[list[str]]) -> "TrajectoryAnomalyDetector":
        """用历史正常 call_path 批量初始化基线."""
        self.monitor.observe_batch(call_paths)
        return self

    def score(self, call_path: list[str]) -> float:
        """返回单条 call_path 的异常分 [0, 1]."""
        return self.monitor.score_simple(call_path)

    def score_with_details(self, call_path: list[str]) -> tuple[float, dict]:
        """返回异常分 + 每个特征的详细信息."""
        return self.monitor.score(call_path)

    def observe(self, call_path: list[str]) -> None:
        """在线学习：用确认正常的 call_path 更新基线."""
        self.monitor.observe(call_path)

    @property
    def is_ready(self) -> bool:
        return self.monitor.is_ready

    @property
    def observation_count(self) -> int:
        return self.monitor.observation_count

    def summary(self) -> str:
        return self.monitor.summary()

    def save(self, path: str) -> None:
        """保存检测器状态（pickle 格式）."""
        state = {
            name: stat.to_dict()
            for name, stat in self.monitor._stats.items()
        }
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        with open(path, "wb") as f:
            pickle.dump(state, f)

    @classmethod
    def load(cls, path: str, role_discovery=None) -> "TrajectoryAnomalyDetector":
        """加载检测器状态."""
        with open(path, "rb") as f:
            state = pickle.load(f)

        obj = cls(role_discovery=role_discovery)
        for name, d in state.items():
            if name in obj.monitor._stats:
                obj.monitor._stats[name] = OnlineGaussian.from_dict(d)
        return obj
