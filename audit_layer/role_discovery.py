"""
role_discovery.py — 基于通信图的无监督角色发现

从历史 call_path 数据中自动学习：
1. Agent 通信图拓扑结构
2. Agent 的结构嵌入（Node2Vec / 谱嵌入）
3. 角色聚类（KMeans / HDBSCAN）
4. 角色转移概率矩阵

原理：不依赖 YAML 中手工标注的 agent role，而是从 "谁和谁通信"
这一纯拓扑信号中推断每个 agent 在 MAS 中的结构角色。
两个在通信图中占据相似结构位置的 agent 会被分到同一角色——
这恰好对应 "triage_agent" / "specialist_agent" / "reviewer_agent" 等
功能分类，且可以跨域泛化。
"""

from __future__ import annotations

import json
import os
import pickle
import random
from collections import defaultdict, Counter
from pathlib import Path
from typing import Optional

import numpy as np
from sklearn.cluster import KMeans
from sklearn.decomposition import TruncatedSVD
from sklearn.preprocessing import normalize


class RoleDiscovery:
    """
    无监督角色发现。

    用法:
        rd = RoleDiscovery()
        rd.fit_from_jsonl(["data/all_consistent.jsonl"])
        rd.save("roles_output/")

        # 加载已学好的角色
        rd = RoleDiscovery.load("roles_output/")
        role = rd.get_role("Diagnosis_Agent")  # -> "Role_2"
        score = rd.transition_prob("triage", "specialist")  # -> 0.87
    """

    def __init__(
        self,
        embedding_dim: int = 64,
        num_roles: int = 6,
        walk_length: int = 10,
        num_walks: int = 200,
        p: float = 0.5,   # return parameter (<1 鼓励回溯，capture 双向通信)
        q: float = 0.5,   # in-out parameter (<1 鼓励远跳，capture 全局位置)
        window_size: int = 5,
        seed: int = 42,
    ):
        self.embedding_dim = embedding_dim
        self.num_roles = num_roles
        self.walk_length = walk_length
        self.num_walks = num_walks
        self.p = p
        self.q = q
        self.window_size = window_size
        self.seed = seed

        # 学习结果
        self.agents: list[str] = []
        self.agent_to_idx: dict[str, int] = {}
        self.embeddings: Optional[np.ndarray] = None     # [n_agents, dim]
        self.role_labels: Optional[np.ndarray] = None     # [n_agents]
        self.role_names: dict[int, str] = {}              # cluster_id -> human label
        self.agent_role: dict[str, str] = {}              # agent_name -> role_name
        self.transition_matrix: Optional[np.ndarray] = None  # [n_roles, n_roles]
        self._role_to_idx: dict[str, int] = {}

    # ══════════════════════════════════════════════════════════
    # 主流程
    # ══════════════════════════════════════════════════════════

    def fit_from_jsonl(
        self,
        jsonl_paths: list[str],
        event_filter: Optional[callable] = None,
    ) -> "RoleDiscovery":
        G, pos_stats = self._build_graph(jsonl_paths, event_filter)
        return self.fit_from_graph(G, pos_stats)

    def fit_from_graph(
        self, G: dict[str, list[str]], pos_stats: dict[str, dict] | None = None
    ) -> "RoleDiscovery":
        self.agents = sorted(G.keys())
        self.agent_to_idx = {a: i for i, a in enumerate(self.agents)}

        walks = self._generate_walks(G)
        self.embeddings = self._learn_embeddings_svd(walks)
        if pos_stats:
            self.embeddings = self._augment_with_position(self.embeddings, pos_stats)
        self.role_labels, self.role_names = self._cluster_roles(self.embeddings)

        for agent, label in zip(self.agents, self.role_labels):
            self.agent_role[agent] = self.role_names[label]

        self.transition_matrix, self._role_to_idx = self._compute_transitions(G)
        return self

    # ══════════════════════════════════════════════════════════
    # Step 1: 构建通信图
    # ══════════════════════════════════════════════════════════

    def _build_graph(
        self,
        jsonl_paths: list[str],
        event_filter: Optional[callable] = None,
    ) -> tuple[dict[str, list[str]], dict[str, dict]]:
        """从 JSONL 中提取 call_path，构建通信图 + 位置统计。"""
        adj = defaultdict(Counter)
        # 位置统计: {agent: {"positions": [所有出现位置], "tool_calls": bool}}
        pos_data: dict[str, dict] = defaultdict(lambda: {"positions": [], "has_tool": False})

        for path in jsonl_paths:
            with open(path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        event = json.loads(line)
                    except json.JSONDecodeError:
                        continue

                    if event_filter and not event_filter(event):
                        continue

                    obj = event.get("original", event)
                    call_path = obj.get("call_path", [])
                    if not call_path or len(call_path) < 2:
                        continue

                    # 邻接边
                    for i in range(len(call_path) - 1):
                        src, dst = call_path[i], call_path[i + 1]
                        if src and dst:
                            adj[src][dst] += 1

                    # 位置统计：记录每个 agent 在路径中的位置
                    for pos, agent in enumerate(call_path):
                        if agent:
                            pos_data[agent]["positions"].append(pos)
                            # 最后一个元素如果是 tool 名（非 agent）不影响

                    # 是否发起过 tool_call
                    if obj.get("event_type") == "tool_call":
                        sender = obj.get("sender", "")
                        if sender:
                            pos_data[sender]["has_tool"] = True

        # 转为 {agent: [neighbors]}，按权重降序
        G = {src: [dst for dst, _ in targets.most_common()]
             for src, targets in adj.items()}

        # 计算平均位置和标准差，归一化到 [0,1]
        pos_stats = {}
        max_pos = max(
            (max(v["positions"]) for v in pos_data.values() if v["positions"]),
            default=1
        )
        import math
        for agent, data in pos_data.items():
            if data["positions"]:
                positions = data["positions"]
                avg_pos = sum(positions) / len(positions)
                variance = sum((p - avg_pos) ** 2 for p in positions) / len(positions)
                pos_stats[agent] = {
                    "avg_pos_norm": avg_pos / max(max_pos, 1),
                    "pos_std": math.sqrt(variance) / max(max_pos, 1),
                    "has_tool": 1.0 if data["has_tool"] else 0.0,
                }

        return G, pos_stats

    # ══════════════════════════════════════════════════════════
    # Step 2: Node2Vec 风格的随机游走
    # ══════════════════════════════════════════════════════════

    def _generate_walks(self, G: dict[str, list[str]]) -> list[list[str]]:
        """
        Node2Vec 二阶随机游走。
        p 控制"回退"概率, q 控制"探索"概率。
        p < 1: 鼓励回溯（双向通信模式）
        q < 1: 鼓励 DFS 远跳（capture 全局拓扑位置）
        """
        random.seed(self.seed)
        walks = []

        nodes = list(G.keys())
        if len(nodes) < 2:
            return walks

        for _ in range(self.num_walks):
            random.shuffle(nodes)
            for start in nodes:
                walk = [start]
                for _ in range(self.walk_length - 1):
                    cur = walk[-1]
                    neighbors = G.get(cur, [])
                    if not neighbors:
                        break

                    if len(walk) == 1:
                        walk.append(random.choice(neighbors))
                    else:
                        prev = walk[-2]
                        # 计算每个邻居的转移概率（含 p, q 偏置）
                        probs = []
                        for nxt in neighbors:
                            if nxt == prev:
                                probs.append(1.0 / self.p)
                            elif nxt in G.get(prev, []):
                                probs.append(1.0)
                            else:
                                probs.append(1.0 / self.q)

                        total = sum(probs)
                        probs = [p_val / total for p_val in probs]
                        walk.append(
                            random.choices(neighbors, weights=probs, k=1)[0]
                        )

                if len(walk) >= 2:
                    walks.append(walk)

        return walks

    # ══════════════════════════════════════════════════════════
    # Step 3: SVD 嵌入（PMI 矩阵降维）
    # ══════════════════════════════════════════════════════════

    def _learn_embeddings_svd(self, walks: list[list[str]]) -> np.ndarray:
        """
        从随机游走中学习嵌入。

        方法：构建 PMI 矩阵 → TruncatedSVD → 归一化
        这是 NetMF 的简化版，等价于 DeepWalk 的矩阵分解形式。
        """
        n = len(self.agents)
        co_occur = np.zeros((n, n), dtype=np.float32)

        for walk in walks:
            for ci in range(len(walk)):
                a_idx = self.agent_to_idx.get(walk[ci])
                if a_idx is None:
                    continue
                start = max(0, ci - self.window_size)
                end = min(len(walk), ci + self.window_size + 1)
                for cj in range(start, end):
                    if ci == cj:
                        continue
                    b_idx = self.agent_to_idx.get(walk[cj])
                    if b_idx is not None:
                        co_occur[a_idx, b_idx] += 1.0

        # Shifted PPMI
        total = co_occur.sum()
        if total == 0:
            return np.random.randn(n, self.embedding_dim).astype(np.float32) * 0.01

        row_sum = co_occur.sum(axis=1, keepdims=True) + 1e-10
        col_sum = co_occur.sum(axis=0, keepdims=True) + 1e-10

        # PMI(i,j) = log(p(i,j) / (p(i) * p(j)))
        p_ij = co_occur / total
        p_i = row_sum / total
        p_j = col_sum / total

        pmi = np.log((p_ij + 1e-10) / (p_i * p_j + 1e-10))
        pmi = np.maximum(pmi, 0)  # PPMI: clip negatives

        dim = min(self.embedding_dim, n - 1)
        if dim < 2:
            return np.random.randn(n, self.embedding_dim).astype(np.float32) * 0.01

        svd = TruncatedSVD(n_components=dim, random_state=self.seed)
        embeddings = svd.fit_transform(pmi)
        embeddings = normalize(embeddings, norm="l2")

        return embeddings.astype(np.float32)

    # ══════════════════════════════════════════════════════════
    # Step 3.5: 位置信息增强
    # ══════════════════════════════════════════════════════════

    def _augment_with_position(
        self, embeddings: np.ndarray, pos_stats: dict[str, dict]
    ) -> np.ndarray:
        """
        拼接入口/审核/执行的区分特征（加权）。

        avg_pos_norm: 0=入口, 0.3=审核, 0.35=路由, 0.5+=执行
        pos_std: 位置标准差（User=0, Compliance=小, Router=大）
        has_tool: 是否发起工具调用（审核/路由=0, 执行者=1）
        """
        n = len(self.agents)
        w = max(1.0, self.embedding_dim / 4)  # 增强维度权重
        aug = np.zeros((n, 3), dtype=np.float32)
        for i, agent in enumerate(self.agents):
            stats = pos_stats.get(agent, {})
            aug[i, 0] = stats.get("avg_pos_norm", 0.5) * w
            aug[i, 1] = stats.get("pos_std", 0.0) * w
            aug[i, 2] = stats.get("has_tool", 0.0) * w
        return np.concatenate([embeddings, aug], axis=1)

    # ══════════════════════════════════════════════════════════
    # Step 4: 聚类发现角色
    # ══════════════════════════════════════════════════════════

    def _cluster_roles(
        self, embeddings: np.ndarray
    ) -> tuple[np.ndarray, dict[int, str]]:
        """
        聚类发现角色。

        小图（≤8 Agent）：直接根据嵌入向量中的"位置+工具"信号分配角色，
        不需要 KMeans——星型拓扑下纯邻接嵌入没有区分度。
        大图：KMeans 聚类。
        """
        n = len(embeddings)
        if n <= 8:
            return self._cluster_by_behavior(embeddings)
        return self._cluster_by_kmeans(embeddings)

    def _cluster_by_behavior(
        self, embeddings: np.ndarray
    ) -> tuple[np.ndarray, dict[int, str]]:
        """
        小型 MAS：利用审核 Agent 的独有特征分配角色。

        每个 Agent 的嵌入向量最后 3 维是增强特征：
          [-3]: avg_pos_norm * scale（0=入口, ~0.3=审核, ~0.35=路由, 0.5+=执行）
          [-2]: pos_std * scale（0=固定位置, >0=位置变化大 → 路由节点）
          [-1]: has_tool * scale（0=不调工具, >0=调工具 → 执行者）

        规则：
          pos≈0, std≈0, no_tool → entry (User)
          有tool调用 → specialist (执行Agent)
          no_tool, pos中等, std小 → reviewer (审核Agent: 固定位置, 不调工具)
          no_tool, std大 → triage (路由: 到处出现)
        """
        labels = np.zeros(len(embeddings), dtype=int)
        # 提取增强特征（最后 3 维）: [avg_pos*scale, pos_std*scale, has_tool*scale]
        aug = embeddings[:, -3:]
        has_tool = aug[:, 2]
        avg_pos = aug[:, 0]
        pos_std = aug[:, 1]

        role_map: dict[int, str] = {}
        next_id = 0

        # specialist: 有 tool 调用 → 执行者
        spec_mask = has_tool > 0.1
        if spec_mask.any():
            labels[spec_mask] = next_id
            role_map[next_id] = "specialist"
            next_id += 1

        # 剩余: 无 tool 调用的节点 → 按"位置稳定性"区分
        # reviewer 位置固定(CV小), triage 到处出现(CV大), entry 位置最靠前
        remaining = ~spec_mask
        if remaining.any():
            rem_indices = np.where(remaining)[0]
            rem_avg = avg_pos[remaining]
            rem_std = pos_std[remaining]
            # 变异系数: std/avg, 衡量位置稳定性. reviewer≈0.13, router≈0.64
            cv = np.divide(rem_std, rem_avg, out=np.zeros_like(rem_avg), where=rem_avg > 0.01)

            # entry: 位置最低且CV小 (User: avg≈0)
            is_entry = rem_avg < (rem_avg.min() + np.ptp(rem_avg) * 0.15)
            # reviewer: 位置固定(CV < 0.3)但不是entry
            is_reviewer = (~is_entry) & (cv < 0.3)
            # triage: 其余(位置变化大)
            is_triage = (~is_entry) & (~is_reviewer)

            if is_entry.any():
                labels[rem_indices[is_entry]] = next_id
                role_map[next_id] = "entry"
                next_id += 1
            if is_reviewer.any():
                labels[rem_indices[is_reviewer]] = next_id
                role_map[next_id] = "reviewer"
                next_id += 1
            if is_triage.any():
                labels[rem_indices[is_triage]] = next_id
                role_map[next_id] = "triage"
                next_id += 1

        role_names = {k: v for k, v in role_map.items()}
        return labels, role_names

    def _cluster_by_kmeans(
        self, embeddings: np.ndarray
    ) -> tuple[np.ndarray, dict[int, str]]:
        """大图：传统 KMeans 聚类。"""
        n = len(embeddings)
        n_clusters = min(self.num_roles, max(2, n // 2))
        n_clusters = max(2, n_clusters)

        kmeans = KMeans(
            n_clusters=n_clusters,
            random_state=self.seed,
            n_init="auto",
        )
        labels = kmeans.fit_predict(embeddings)

        centroids = kmeans.cluster_centers_
        centroid_norms = np.linalg.norm(centroids, axis=1)
        ordering = np.argsort(centroid_norms)

        semantic_names = [
            "entry", "triage", "specialist",
            "reviewer", "executor", "observer",
        ]
        role_names: dict[int, str] = {}
        for rank, cluster_id in enumerate(ordering):
            name = semantic_names[rank] if rank < len(semantic_names) else f"role_{rank}"
            role_names[cluster_id] = name

        return labels, role_names

    # ══════════════════════════════════════════════════════════
    # Step 5: 角色转移概率矩阵
    # ══════════════════════════════════════════════════════════

    def _compute_transitions(
        self, G: dict[str, list[str]]
    ) -> tuple[np.ndarray, dict[str, int]]:
        """从通信图和角色分配计算角色间的转移概率。"""
        n_roles = len(self.role_names)
        role_idx = {name: i for i, name in self.role_names.items()}
        role_to_idx: dict[str, int] = {
            self.agent_role.get(a, "unknown"): role_idx[self.agent_role[a]]
            for a in self.agents if a in self.agent_role
        }

        counts = np.zeros((n_roles, n_roles), dtype=np.float32)

        for src, neighbors in G.items():
            src_role = self.agent_role.get(src)
            if src_role is None:
                continue
            si = role_idx.get(src_role)
            if si is None:
                continue
            for dst in neighbors:
                dst_role = self.agent_role.get(dst)
                if dst_role is None:
                    continue
                di = role_idx.get(dst_role)
                if di is None:
                    continue
                counts[si, di] += 1.0

        # 行归一化 → 概率
        row_sum = counts.sum(axis=1, keepdims=True) + 1e-10
        prob = counts / row_sum

        return prob, role_to_idx

    # ══════════════════════════════════════════════════════════
    # 查询接口
    # ══════════════════════════════════════════════════════════

    def get_role(self, agent: str) -> str:
        """返回 agent 的角色名，未知 agent 返回 "unknown"."""
        return self.agent_role.get(agent, "unknown")

    def get_embedding(self, agent: str) -> Optional[np.ndarray]:
        """返回 agent 的嵌入向量."""
        idx = self.agent_to_idx.get(agent)
        if idx is None or self.embeddings is None:
            return None
        return self.embeddings[idx]

    def transition_prob(self, role_src: str, role_dst: str) -> float:
        """返回角色间的转移概率 P(dst | src)."""
        if self.transition_matrix is None:
            return 0.0
        si = self._role_to_idx.get(role_src)
        di = self._role_to_idx.get(role_dst)
        if si is None or di is None:
            return 0.0
        return float(self.transition_matrix[si, di])

    def score_path(self, call_path: list[str]) -> dict:
        """
        对一条 call_path 计算：

        - adjacency_anomalies: 非法邻接跳数（概率为 0 的跳）
        - mean_log_prob: 平均对数转移概率（越高越正常）
        - min_prob: 最小转移概率（路径中最可疑的一跳）
        - anomaly_score: 综合异常分 [0, 1]，越高越可疑
        """
        if len(call_path) < 2:
            return {
                "adjacency_anomalies": 0,
                "mean_log_prob": 0.0,
                "min_prob": 0.0,
                "anomaly_score": 0.0,
            }

        anomalies = 0
        log_probs = []
        min_prob = 1.0

        for i in range(len(call_path) - 1):
            src_role = self.get_role(call_path[i])
            dst_role = self.get_role(call_path[i + 1])
            prob = self.transition_prob(src_role, dst_role)

            if prob == 0.0:
                anomalies += 1
                min_prob = 0.0
            else:
                log_probs.append(np.log(prob))
                min_prob = min(min_prob, prob)

        mean_log_prob = float(np.mean(log_probs)) if log_probs else -10.0

        # 综合异常分: 同时考虑非法跳数和低概率跳
        n = len(call_path) - 1
        anomaly_score = (anomalies / n) * 0.7 + max(0, -mean_log_prob / 5.0) * 0.3
        anomaly_score = min(1.0, anomaly_score)

        return {
            "adjacency_anomalies": anomalies,
            "mean_log_prob": mean_log_prob,
            "min_prob": min_prob,
            "anomaly_score": anomaly_score,
        }

    # ══════════════════════════════════════════════════════════
    # 持久化
    # ══════════════════════════════════════════════════════════

    def save(self, directory: str) -> None:
        """保存学习结果到目录."""
        os.makedirs(directory, exist_ok=True)

        data = {
            "agents": self.agents,
            "agent_to_idx": self.agent_to_idx,
            "embeddings": self.embeddings,
            "role_labels": self.role_labels,
            "role_names": self.role_names,
            "agent_role": self.agent_role,
            "transition_matrix": self.transition_matrix,
            "_role_to_idx": self._role_to_idx,
            "config": {
                "embedding_dim": self.embedding_dim,
                "num_roles": self.num_roles,
                "walk_length": self.walk_length,
                "num_walks": self.num_walks,
                "p": self.p,
                "q": self.q,
                "window_size": self.window_size,
                "seed": self.seed,
            },
        }
        with open(os.path.join(directory, "role_model.pkl"), "wb") as f:
            pickle.dump(data, f)

    @classmethod
    def load(cls, directory: str) -> "RoleDiscovery":
        """从目录加载已学习的角色模型."""
        path = os.path.join(directory, "role_model.pkl")
        if not os.path.exists(path):
            raise FileNotFoundError(f"角色模型不存在: {path}")

        with open(path, "rb") as f:
            data = pickle.load(f)

        cfg = data["config"]
        obj = cls(
            embedding_dim=cfg["embedding_dim"],
            num_roles=cfg.get("num_roles", 6),
            walk_length=cfg["walk_length"],
            num_walks=cfg["num_walks"],
            p=cfg["p"],
            q=cfg["q"],
            window_size=cfg["window_size"],
            seed=cfg["seed"],
        )
        obj.agents = data["agents"]
        obj.agent_to_idx = data["agent_to_idx"]
        obj.embeddings = data["embeddings"]
        obj.role_labels = data["role_labels"]
        obj.role_names = data["role_names"]
        obj.agent_role = data["agent_role"]
        obj.transition_matrix = data["transition_matrix"]
        obj._role_to_idx = data["_role_to_idx"]
        return obj


# ══════════════════════════════════════════════════════════════
# 便捷函数
# ══════════════════════════════════════════════════════════════

def discover_roles_from_data(
    jsonl_paths: list[str],
    output_dir: str = "audit_layer/roles",
    **kwargs,
) -> RoleDiscovery:
    """
    一键角色发现：从 JSONL 数据中学习角色并保存。

    Args:
        jsonl_paths: JSONL 数据文件路径列表
        output_dir: 输出目录
        **kwargs: 传递给 RoleDiscovery 的参数
    """
    rd = RoleDiscovery(**kwargs)
    rd.fit_from_jsonl(jsonl_paths)
    rd.save(output_dir)
    return rd
