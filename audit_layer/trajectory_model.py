"""
trajectory_model.py — 基于 EWMA + 角色抽象的轻量轨迹监控器

原理（类比 PID 控制器 / 风扇调速）：
  - 维护每个轨迹特征（深度、角色熵、新颖边…）的 EWMA 均值和方差
  - 每次观察到正常 call_path 时，以 α=0.05 的速率更新基线
  - 新 call_path 偏离基线超过 k 倍标准差 → 异常

与深度学习方案的本质区别：
  - 不是"训练一个模型来编码轨迹"，而是"维护一组统计量的自适应阈值"
  - 在线学习：每看到一条正常轨迹就更新一次，越用越准
  - 零外部依赖（仅需 numpy），推理 < 0.01ms
  - 完全可解释：每个告警都能追溯到具体哪个特征异常

特征维度（全部从 call_path 中提取）：
  depth           — 路径深度（agent 数量）
  unique_roles    — 去重后的 agent 种类数
  role_entropy    — agent 分布的香农熵
  novel_edge_ratio — 未在预热中出现过的 agent→agent 边占比
  edge_surprise   — 基于转移概率的边信息量均值（-ln P(B|A)）
"""

from __future__ import annotations

import os
import pickle
from collections import Counter, defaultdict
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

    def __init__(self, alpha: float = 0.05, k: float = 2.0):
        self.alpha = alpha
        self.k = k          # 几倍标准差算异常（2.0: ~5%的正常观测落在界外）
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
        0 = 完全在正常范围内，1 = 严重偏离（z >= 2*k）。
        """
        z = self.z_score(x)
        if z <= self.k:
            return 0.0
        return min(1.0, (z - self.k) / self.k)

    def ensure_variance(self, min_var: float = 0.01) -> None:
        """确保方差至少为 min_var，防止零方差导致 z_score 失效。"""
        if self.var < min_var:
            self.var = min_var

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
    - 内部维护 5 个 OnlineGaussian，每个管一个特征维度
    """

    def __init__(
        self,
        role_discovery=None,  # RoleDiscovery 实例，可选
        alpha: float = 0.05,
        k_position: float = 2.5,
        k_roles: float = 2.0,
        k_entropy: float = 2.5,
        k_novel_edge: float = 0.5,
        k_edge_surprise: float = 2.0,
        k_repetition: float = 2.0,
        k_path_surprise: float = 3.0,
    ):
        self.rd = role_discovery
        self._known_edges: set[tuple[str, str]] = set()  # agent→agent transitions seen during warmup
        self._transitions: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
        self._transition_totals: dict[str, int] = defaultdict(int)

        # 2-gram (bigram) 转移计数: (A,B) → C 的次数
        self._bigrams: dict[tuple[str, str], dict[str, int]] = defaultdict(lambda: defaultdict(int))
        self._bigram_totals: dict[tuple[str, str], int] = defaultdict(int)

        self._stats = {
            "position_anomaly": OnlineGaussian(alpha, k_position),
            "unique_roles":     OnlineGaussian(alpha, k_roles),
            "role_entropy":     OnlineGaussian(alpha, k_entropy),
            "novel_edge_ratio": OnlineGaussian(alpha, k_novel_edge),
            "edge_surprise":    OnlineGaussian(alpha, k_edge_surprise),
            "path_repetition":  OnlineGaussian(alpha, k_repetition),
            "path_surprise":    OnlineGaussian(alpha, k_path_surprise),
        }

        # Per-agent position distribution tracking
        # key = agent name, value = OnlineGaussian tracking position indices
        self._agent_positions: dict[str, OnlineGaussian] = {}

    # ── 位置种子：从 adjacency 推导每个 agent 的合法位置范围 ──

    @staticmethod
    def _compute_reachable_positions(
        adjacency: dict[str, list[str]], max_depth: int = 4
    ) -> dict[str, set[int]]:
        """BFS 从 User 出发遍历 adjacency 图，返回每个 agent 可达的深度集合。"""
        from collections import deque

        reachable: dict[str, set[int]] = {}
        queue = deque([("User", 0)])
        reachable["User"] = {0}

        while queue:
            node, depth = queue.popleft()
            if depth >= max_depth:
                continue
            for neighbor in adjacency.get(node, []):
                if neighbor == "Router":
                    continue
                depths = reachable.setdefault(neighbor, set())
                if depth + 1 not in depths:
                    depths.add(depth + 1)
                    queue.append((neighbor, depth + 1))

        return reachable

    def seed_agent_positions(
        self, adjacency: dict[str, list[str]], base_count: int = 5, max_seed_depth: int = 3
    ) -> None:
        """用 adjacency 图中每个 agent 的合法深度为位置分布播种。

        仅播种到 max_seed_depth，避免将均值拖向 adjacency 理论可达但实际
        从未出现过的深度。例如 adjacency BFS 可能算出 Safety 可达深度 4，
        但实际场景中从未超过 3，播种深度 4 会让 Safety@1 看起来异常。
        """
        reachable = self._compute_reachable_positions(adjacency)
        for agent, depths in reachable.items():
            if agent == "User":
                continue
            if agent not in self._agent_positions:
                self._agent_positions[agent] = OnlineGaussian(self._stats["position_anomaly"].alpha, 2.5)
            stat = self._agent_positions[agent]
            for depth in sorted(depths):
                if depth > max_seed_depth:
                    continue
                for _ in range(base_count):
                    stat.observe(float(depth))

    # ── 转移概率建模 ──

    def _edge_surprise(self, call_path: list[str]) -> float:
        """每条边 -ln(P(B|A)) 的均值，Laplace 平滑。

        P(B|A) = (count(A→B) + 1) / (total_out(A) + |V|)
        未见过边: ~ln(|V|)，常见边: ~0.5-1.0，罕见边: ~2-4。
        """
        n = len(call_path) - 1
        if n <= 0:
            return 0.0
        V = max(len(set(self._transition_totals.keys()) |
                     {a for a in call_path}), 1)
        total_surprise = 0.0
        for i in range(n):
            src, dst = call_path[i], call_path[i + 1]
            count_ab = self._transitions.get(src, {}).get(dst, 0)
            total_a = self._transition_totals.get(src, 0)
            prob = (count_ab + 1) / (total_a + V) if total_a > 0 else 1.0 / V
            total_surprise += -np.log(max(prob, 1e-10))
        return float(total_surprise / n)

    def _path_surprise(self, call_path: list[str]) -> float:
        """2-gram (bigram) 路径意外度：-ln P(C | A→B) 的均值。

        与 edge_surprise (1st-order Markov) 不同，path_surprise 建模的是
        "给定前两个 agent，第三个 agent 出现的概率"。这能捕获：
          - User→Firmware→Safety→Firmware: (Firm,Safety)→Firmware 极少见 → 循环检测

        仅对 depth ≥ 4 的路径计算。depth=3 的路径在 warmup 中天然稀疏，
        每条路径的 bigram 都独一无二，会导致大量误报。
        """
        n = len(call_path)
        if n < 4:
            return 0.0
        # V = 所有可能作为 bigram 后继的 agent 数
        all_agents = set(call_path)
        for (a, b), dsts in self._bigrams.items():
            all_agents.update(dsts.keys())
            all_agents.add(a)
            all_agents.add(b)
        V = max(len(all_agents), 1)
        total_surprise = 0.0
        k = 0  # 实际计算的 bigram 数
        for i in range(2, n):
            prefix = (call_path[i - 2], call_path[i - 1])
            next_agent = call_path[i]
            count_abc = self._bigrams.get(prefix, {}).get(next_agent, 0)
            total_ab = self._bigram_totals.get(prefix, 0)
            prob = (count_abc + 1) / (total_ab + V) if total_ab > 0 else 1.0 / V
            total_surprise += -np.log(max(prob, 1e-10))
            k += 1
        return float(total_surprise / k) if k > 0 else 0.0

    # ── 特征提取 ──

    def _extract(self, call_path: list[str]) -> dict[str, float]:
        """从一条 call_path 中提取 7 个标量特征."""
        n = len(call_path)
        unique_roles_set = set(call_path)

        # 角色熵
        agent_counts = Counter(call_path)
        total = sum(agent_counts.values())
        entropy = -sum(
            (c / total) * np.log(c / total + 1e-10)
            for c in agent_counts.values()
        )

        # 新颖边比例：从未在预热中出现过的 agent→agent 转移边
        total_edges = n - 1
        if total_edges > 0 and self._known_edges:
            novel_count = sum(
                1 for i in range(total_edges)
                if (call_path[i], call_path[i + 1]) not in self._known_edges
            )
            novel_edge_ratio = novel_count / total_edges
        else:
            novel_edge_ratio = 0.0

        # 位置异常：对路径中每个 agent，查其位置分布的 z-score，取最大值
        max_pos_z = 0.0
        for idx, agent in enumerate(call_path):
            pos_stat = self._agent_positions.get(agent)
            if pos_stat is not None and pos_stat.n_obs > 0:
                z = pos_stat.z_score(float(idx))
            else:
                # 未知 agent: 视为异常位置（z 取一个保守偏高的值）
                z = 3.0
            if z > max_pos_z:
                max_pos_z = z

        # Agent 重复比例：同一 agent 在路径中重复出现的程度
        # 0 = 全部唯一（正常），0.5 = 一半 agent 是重复的（异常循环）
        if n > 1:
            repetition = (n - len(unique_roles_set)) / (n - 1)
        else:
            repetition = 0.0

        # 2-gram 路径意外度：基于 bigram P(C | A→B) 的平均信息量
        # 仅对 depth ≥ 3 的路径有效，捕获"合法边 + 非法序列"的模式
        path_surprise_val = self._path_surprise(call_path)

        return {
            "position_anomaly": float(max_pos_z),
            "unique_roles": float(len(unique_roles_set)),
            "role_entropy": float(entropy),
            "novel_edge_ratio": float(novel_edge_ratio),
            "edge_surprise": float(self._edge_surprise(call_path)),
            "path_repetition": float(repetition),
            "path_surprise": float(path_surprise_val),
        }

    # ── 在线学习 ──

    def observe(self, call_path: list[str]) -> None:
        """用一条正常 call_path 更新所有 EWMA 基线."""
        # 更新 per-agent 位置分布
        for idx, agent in enumerate(call_path):
            if agent not in self._agent_positions:
                self._agent_positions[agent] = OnlineGaussian(
                    self._stats["position_anomaly"].alpha, 2.5
                )
            self._agent_positions[agent].observe(float(idx))

        feats = self._extract(call_path)
        for name, value in feats.items():
            self._stats[name].observe(value)
        # 将本条路径的边加入已知集和转移计数（在线扩展基线）
        for i in range(len(call_path) - 1):
            src, dst = call_path[i], call_path[i + 1]
            self._known_edges.add((src, dst))
            self._transitions[src][dst] += 1
            self._transition_totals[src] += 1
        # 更新 bigram 计数: P(C | A→B)
        for i in range(2, len(call_path)):
            prefix = (call_path[i - 2], call_path[i - 1])
            next_agent = call_path[i]
            self._bigrams[prefix][next_agent] += 1
            self._bigram_totals[prefix] += 1

    def observe_batch(self, call_paths: list[list[str]]) -> None:
        """批量观察正常轨迹以快速建立基线."""
        for path in call_paths:
            self.observe(path)

    def _collect_edges(self, call_paths: list[list[str]]) -> None:
        """收集边到 _known_edges 并建立转移计数矩阵，不更新 EWMA 统计."""
        for path in call_paths:
            for i in range(len(path) - 1):
                src, dst = path[i], path[i + 1]
                self._known_edges.add((src, dst))
                self._transitions[src][dst] += 1
                self._transition_totals[src] += 1
            # 同时收集 bigram 计数
            for i in range(2, len(path)):
                prefix = (path[i - 2], path[i - 1])
                next_agent = path[i]
                self._bigrams[prefix][next_agent] += 1
                self._bigram_totals[prefix] += 1

    def _warmup_finalize(self) -> None:
        """预热收尾：为 novel_edge_ratio 和 edge_surprise 设置最小方差。

        所有预热路径的 novel_edge_ratio=0（edges 已全量收集），
        但 EWMA 需要非零方差才能对测试路径的新颖边产生 z-score。
        设置 σ=0.15 意味着 1 条新颖边在 4 边路径中 (ratio=0.25)
        产生 z≈1.67 > k_novel_edge=0.5，触发异常。

        edge_surprise 同理：预热路径 surprise≈0.5-1.0，
        设置 σ=0.3 确保测试路径 surprise>1.5 能触发 z>k_edge_surprise=1.5。

        position_anomaly 及 per-agent 位置分布同理：
        设置 σ=0.15 (min_var=0.0225) 确保所有合法位置都能产生有效 z-score。
        """
        self._stats["novel_edge_ratio"].ensure_variance(min_var=0.0225)  # σ=0.15
        self._stats["edge_surprise"].ensure_variance(min_var=0.09)       # σ=0.3
        self._stats["position_anomaly"].ensure_variance(min_var=0.0225)  # σ=0.15
        self._stats["path_repetition"].ensure_variance(min_var=0.01)     # σ=0.1
        self._stats["path_surprise"].ensure_variance(min_var=0.09)       # σ=0.3
        for stat in self._agent_positions.values():
            stat.ensure_variance(min_var=0.0225)  # σ=0.15

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
                    f"  {name:18s}: μ={stat.mean:6.3f}, σ={stat.var**0.5:6.3f}, "
                    f"阈值=[{stat.mean - stat.k * stat.var**0.5:.3f}, "
                    f"{stat.mean + stat.k * stat.var**0.5:.3f}], n={stat.n_obs}"
                )
        # 追加 per-agent 位置摘要（前 5 个 agent）
        sorted_agents = sorted(
            self._agent_positions.items(),
            key=lambda x: x[1].n_obs, reverse=True,
        )
        for agent, stat in sorted_agents[:5]:
            if stat.mean is not None:
                lines.append(
                    f"  pos[{agent:15s}]: μ={stat.mean:6.3f}, σ={stat.var**0.5:6.3f}, "
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
        """用历史正常 call_path 批量初始化基线。

        两阶段预热：
        1. 收集所有 agent→agent 转移边到已知集
        2. 逐条观察更新 EWMA（此时 novel_edge_ratio 全为 0）
        3. 为 novel_edge_ratio 设置最小方差以启用 z-score 检测
        """
        self.monitor._collect_edges(call_paths)
        self.monitor.observe_batch(call_paths)
        self.monitor._warmup_finalize()
        return self

    def seed_agent_positions_from_adjacency(
        self, adjacency: dict[str, list[str]], base_count: int = 5
    ) -> "TrajectoryAnomalyDetector":
        """用 policy adjacency 图为每个 agent 的合法位置分布播种。"""
        self.monitor.seed_agent_positions(adjacency, base_count)
        return self

    def seed_policy_edges(self, adjacency: dict[str, list[str]],
                          base_count: int = 5) -> "TrajectoryAnomalyDetector":
        """补充 policy 合法边的转移计数，但不将未见边加入 known_edges。

        关键设计：只对 warmup 中已观测到的合法边补充计数（防止低频边
        edge_surprise 虚高）；warmup 中未出现的合法边保持"新颖"状态，
        让 EWMA 的 novel_edge_ratio 能独立检测。这样 EWMA 不会沦为
        规则引擎 adjacency 白名单的影子。
        """
        # 计算每个源 agent 的平均出边观测数（仅用于已观测边的计数补充）
        avg_observed = {}
        for src in adjacency:
            counts = [
                self.monitor._transitions[src].get(dst, 0)
                for dst in adjacency[src]
            ]
            nonzero = [c for c in counts if c > 0]
            avg_observed[src] = int(sum(nonzero) / len(nonzero)) if nonzero else base_count

        for src, dsts in adjacency.items():
            for dst in dsts:
                prev = self.monitor._transitions[src][dst]
                # 只对 warmup 中已观测到的边补充计数
                if prev > 0:
                    self.monitor._known_edges.add((src, dst))
                    seed = max(base_count, avg_observed.get(src, base_count))
                    if prev < seed:
                        delta = seed - prev
                        self.monitor._transitions[src][dst] = seed
                        self.monitor._transition_totals[src] += delta
                # prev == 0: 该边在 warmup 中从未出现 → 不加入 known_edges
                # → novel_edge_ratio 将在推理时捕获它
        return self

    def warmup_from_mas_dir(
        self,
        mas_dir: str,
        strip_nodes: list[str] | None = None,
        min_path_len: int = 2,
    ) -> int:
        """从 MAS 生成的 JSONL trace 目录预热检测器。

        读取目录下所有 .jsonl 文件，提取 call_path，
        剥离基础设施节点（默认 Router、Tool_Node），
        然后调用 fit_normal() 建立基线。

        Returns:
            提取到的 call_path 数量。
        """
        import json as _json

        if strip_nodes is None:
            strip_nodes = ["Router", "Tool_Node"]

        paths: list[list[str]] = []
        if not os.path.isdir(mas_dir):
            return 0

        for fname in sorted(os.listdir(mas_dir)):
            if not fname.endswith(".jsonl"):
                continue
            with open(os.path.join(mas_dir, fname), "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        obj = _json.loads(line)
                    except Exception:
                        continue
                    cp = obj.get("call_path", [])
                    cp_clean = [n for n in cp if n not in strip_nodes]
                    if len(cp_clean) >= min_path_len:
                        paths.append(cp_clean)

        if paths:
            self.fit_normal(paths)
        return len(paths)

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
            "stats": {
                name: stat.to_dict()
                for name, stat in self.monitor._stats.items()
            },
            "known_edges": list(self.monitor._known_edges),
            "transitions": {src: dict(dsts) for src, dsts in self.monitor._transitions.items()},
            "transition_totals": dict(self.monitor._transition_totals),
            "bigrams": {f"{a}|{b}": dict(dsts) for (a, b), dsts in self.monitor._bigrams.items()},
            "bigram_totals": {f"{a}|{b}": t for (a, b), t in self.monitor._bigram_totals.items()},
            "agent_positions": {
                agent: stat.to_dict()
                for agent, stat in self.monitor._agent_positions.items()
            },
        }
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        with open(path, "wb") as f:
            pickle.dump(state, f)

    @classmethod
    def load(cls, path: str, role_discovery=None) -> "TrajectoryAnomalyDetector":
        """加载检测器状态."""
        with open(path, "rb") as f:
            state = pickle.load(f)

        # 兼容旧格式（仅 stats dict，无 known_edges 包装）
        if "stats" in state:
            stats_data = state["stats"]
            known_edges = set(state.get("known_edges", []))
            transitions = state.get("transitions", {})
            transition_totals = state.get("transition_totals", {})
            agent_positions_data = state.get("agent_positions", {})
        else:
            stats_data = state
            known_edges = set()
            transitions = {}
            transition_totals = {}
            agent_positions_data = {}

        obj = cls(role_discovery=role_discovery)
        for name, d in stats_data.items():
            if name in obj.monitor._stats:
                obj.monitor._stats[name] = OnlineGaussian.from_dict(d)
        obj.monitor._known_edges = known_edges
        obj.monitor._transitions = defaultdict(lambda: defaultdict(int),
            {src: defaultdict(int, dsts) for src, dsts in transitions.items()})
        obj.monitor._transition_totals = defaultdict(int, transition_totals)

        # 恢复 bigram 计数
        bigrams_data = state.get("bigrams", {})
        bigram_totals_data = state.get("bigram_totals", {})
        for key, dsts in bigrams_data.items():
            a, b = key.split("|", 1)
            obj.monitor._bigrams[(a, b)] = defaultdict(int, dsts)
        for key, total in bigram_totals_data.items():
            a, b = key.split("|", 1)
            obj.monitor._bigram_totals[(a, b)] = total

        # 恢复 per-agent 位置分布
        for agent, d in agent_positions_data.items():
            obj.monitor._agent_positions[agent] = OnlineGaussian.from_dict(d)

        return obj
