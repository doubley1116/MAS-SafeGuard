"""
role_engine.py — 基于角色的路径校验引擎

使用 RoleDiscovery 学习到的角色模型，对 AuditEvent 的 call_path 做：
1. 角色序列校验（转移概率是否正常）
2. 邻接矩阵校验（agent 间直接通信是否合法）
3. 路径深度-角色绑定（特定操作需要足够深度的角色链）

输出：风险分数组[0,1]，可独立使用或与 RuleEngine 融合。
"""

from __future__ import annotations

from typing import Optional
import numpy as np

from audit_layer.role_discovery import RoleDiscovery


class RoleEngine:
    """
    基于角色的路径校验引擎。

    用法:
        rd = RoleDiscovery.load("roles/")
        engine = RoleEngine(rd)

        result = engine.evaluate(call_path=["User", "Triage_Agent", "Diagnosis_Agent"])
        # result = {"risk_score": 0.12, "anomalies": [...], "role_sequence": [...]}
    """

    def __init__(
        self,
        role_discovery: Optional[RoleDiscovery] = None,
        adjacency_matrix: Optional[dict[str, list[str]]] = None,
        role_adjacency: Optional[dict[str, list[str]]] = None,
    ):
        """
        Args:
            role_discovery: 已学习的 RoleDiscovery 模型（自动生成邻接矩阵）
            adjacency_matrix: 手动定义的 agent 级邻接矩阵 {"AgentA": ["AgentB", ...]}
            role_adjacency: 手动定义的角色级邻接矩阵 {"triage": ["specialist", ...]}
        """
        self.rd = role_discovery
        self._adjacency = adjacency_matrix or {}
        self._role_adjacency = role_adjacency or {}

        if role_discovery is not None:
            self._build_from_discovery()

    def _build_from_discovery(self) -> None:
        """从 RoleDiscovery 模型构建邻接约束."""
        if self.rd is None or self.rd.transition_matrix is None:
            return

        # Agent 级邻接：概率 > 0 的转移视为合法
        for agent in self.rd.agents:
            role = self.rd.get_role(agent)
            allowed = set()
            for other in self.rd.agents:
                if other == agent:
                    continue
                other_role = self.rd.get_role(other)
                prob = self.rd.transition_prob(role, other_role)
                if prob > 0.0:
                    allowed.add(other)
            if allowed:
                self._adjacency[agent] = list(allowed)

        # 角色级邻接
        role_names = list(self.rd.role_names.values())
        for src_role in role_names:
            allowed = []
            for dst_role in role_names:
                prob = self.rd.transition_prob(src_role, dst_role)
                if prob > 0.0:
                    allowed.append(dst_role)
            if allowed:
                self._role_adjacency[src_role] = allowed

    # ══════════════════════════════════════════════════════════
    # 规则 1: Agent 邻接检查
    # ══════════════════════════════════════════════════════════

    def check_adjacency(self, call_path: list[str]) -> dict:
        """
        检查 call_path 中每个相邻对是否合法。

        Returns:
            {"hits": [...], "violation_count": int, "score": float}
        """
        hits = []
        violation_count = 0

        for i in range(len(call_path) - 1):
            src, dst = call_path[i], call_path[i + 1]
            allowed = self._adjacency.get(src, [])

            if allowed and dst not in allowed:
                violation_count += 1
                hits.append({
                    "position": i,
                    "src": src,
                    "dst": dst,
                    "allowed": allowed,
                    "reason": f"非法邻接: {src} → {dst}，{src} 允许直达: {allowed}",
                })

        # 分数：违规跳数 / 总跳数
        n = max(1, len(call_path) - 1)
        score = min(0.95, violation_count / n * 0.90)

        return {
            "hits": hits,
            "violation_count": violation_count,
            "score": score,
        }

    # ══════════════════════════════════════════════════════════
    # 规则 2: 角色序列概率检查
    # ══════════════════════════════════════════════════════════

    def check_role_sequence(self, call_path: list[str]) -> dict:
        """
        将 call_path 映射为角色序列，检查每跳的转移概率。

        低概率角色转移 → 推高 risk_score。
        """
        if self.rd is None:
            return {"hits": [], "anomaly_score": 0.0, "role_sequence": []}

        result = self.rd.score_path(call_path)
        role_sequence = [self.rd.get_role(a) for a in call_path]

        hits = []
        if result["anomaly_score"] > 0.3:
            hits.append({
                "type": "role_sequence_anomaly",
                "role_sequence": role_sequence,
                "anomaly_score": result["anomaly_score"],
                "reason": (
                    f"角色序列异常: {' → '.join(role_sequence)}，"
                    f"异常分={result['anomaly_score']:.2f}，"
                    f"非法跳数={result['adjacency_anomalies']}"
                ),
            })

        return {
            "hits": hits,
            "anomaly_score": result["anomaly_score"],
            "role_sequence": role_sequence,
            "adjacency_anomalies": result["adjacency_anomalies"],
        }

    # ══════════════════════════════════════════════════════════
    # 规则 3: 路径深度-工具绑定
    # ══════════════════════════════════════════════════════════

    def check_path_depth(
        self,
        call_path: list[str],
        tool_name: str,
        depth_constraints: Optional[dict[str, tuple[int, int]]] = None,
    ) -> dict:
        """
        检查工具调用的路径深度是否在合法范围内。

        Args:
            call_path: agent 调用路径
            tool_name: 被调用的工具名
            depth_constraints: {tool_name: (min_depth, max_depth)}

        原理：敏感工具（如 drug_tool, trade_tool）需要经过足够多的审批节点，
        但也不应经过过多的节点（可能暗示 AiTM 中间人增加跳数）。
        """
        if depth_constraints is None:
            return {"hits": [], "score": 0.0}

        constraint = depth_constraints.get(tool_name)
        if constraint is None:
            return {"hits": [], "score": 0.0}

        min_depth, max_depth = constraint
        depth = len(call_path)

        hits = []
        score = 0.0

        if depth < min_depth:
            score = max(score, 0.85)
            hits.append({
                "type": "path_too_shallow",
                "depth": depth,
                "min_required": min_depth,
                "reason": f"{tool_name} 要求路径深度≥{min_depth}，实际深度={depth}，疑似路径绕过",
            })

        if depth > max_depth:
            score = max(score, 0.70)
            hits.append({
                "type": "path_too_deep",
                "depth": depth,
                "max_allowed": max_depth,
                "reason": f"{tool_name} 要求路径深度≤{max_depth}，实际深度={depth}，疑似 AiTM 中间人增加跳数",
            })

        return {"hits": hits, "score": score}

    # ══════════════════════════════════════════════════════════
    # 综合评估
    # ══════════════════════════════════════════════════════════

    def evaluate(
        self,
        call_path: list[str],
        tool_name: Optional[str] = None,
        depth_constraints: Optional[dict[str, tuple[int, int]]] = None,
    ) -> tuple[float, list[str], str]:
        """
        综合评估一条 call_path。

        Returns:
            (risk_score, risk_types, reason)  — 与 RuleEngine.evaluate() 格式一致
        """
        all_hits: list[tuple[float, str, str]] = []

        # 1. Agent 邻接检查
        adj_result = self.check_adjacency(call_path)
        for hit in adj_result["hits"]:
            all_hits.append((adj_result["score"], "adjacency_violation", hit["reason"]))

        # 2. 角色序列检查
        role_result = self.check_role_sequence(call_path)
        for hit in role_result["hits"]:
            all_hits.append((role_result["anomaly_score"], hit["type"], hit["reason"]))

        # 3. 路径深度检查
        if tool_name and depth_constraints:
            depth_result = self.check_path_depth(
                call_path, tool_name, depth_constraints
            )
            for hit in depth_result["hits"]:
                all_hits.append((depth_result["score"], hit["type"], hit["reason"]))

        if not all_hits:
            return 0.0, [], "角色引擎未命中任何规则"

        rule_score = max(h[0] for h in all_hits)
        risk_types = list({h[1] for h in all_hits})
        reasons = " | ".join(h[2] for h in all_hits)

        return rule_score, risk_types, reasons


# ══════════════════════════════════════════════════════════════
# 基于角色相似度的异常检测
# ══════════════════════════════════════════════════════════════

def detect_role_anomaly(
    role_discovery: RoleDiscovery,
    call_path: list[str],
    threshold: float = 2.0,
) -> tuple[float, str]:
    """
    基于角色嵌入的异常检测。

    原理：
    1. 将 call_path 中每个 agent 映射到其角色嵌入（簇中心）
    2. 计算"路径嵌入" = 角色嵌入序列的加权平均
    3. 计算该路径嵌入与最近簇中心的距离
    4. 如果距离 > threshold * 平均簇内距离 → 异常

    这个方法不依赖预定义的转移矩阵，纯粹从拓扑嵌入出发检测异常路径。
    比规则方法更灵活——可以发现未知的异常模式。

    Returns:
        (anomaly_score, reason)
    """
    if role_discovery.embeddings is None or role_discovery.role_labels is None:
        return 0.0, "角色嵌入未初始化"

    # 采集路径中每个 agent 的嵌入
    path_embeddings = []
    unknown_count = 0
    for agent in call_path:
        emb = role_discovery.get_embedding(agent)
        if emb is not None:
            path_embeddings.append(emb)
        else:
            unknown_count += 1

    if len(path_embeddings) < 2:
        return float(min(1.0, unknown_count * 0.3)), (
            f"路径中可识别 agent 不足 ({len(path_embeddings)}/{len(call_path)})"
        )

    # 路径嵌入 = 均值池化
    path_emb = np.mean(path_embeddings, axis=0)
    path_emb = path_emb / (np.linalg.norm(path_emb) + 1e-10)

    # 计算各角色簇中心
    embeddings = role_discovery.embeddings
    labels = role_discovery.role_labels
    unique_labels = np.unique(labels)

    centroids = {}
    cluster_dists = {}
    for label in unique_labels:
        mask = labels == label
        cluster_embs = embeddings[mask]
        centroid = np.mean(cluster_embs, axis=0)
        centroid = centroid / (np.linalg.norm(centroid) + 1e-10)
        centroids[label] = centroid
        # 簇内平均距离
        if len(cluster_embs) > 1:
            dists = np.linalg.norm(cluster_embs - centroid, axis=1)
            cluster_dists[label] = float(np.mean(dists))
        else:
            cluster_dists[label] = 0.1

    # 找最近簇，同时记录 cluster label
    min_dist = float("inf")
    nearest_label = None
    nearest_role = None
    for label, centroid in centroids.items():
        dist = float(np.linalg.norm(path_emb - centroid))
        if dist < min_dist:
            min_dist = dist
            nearest_label = label
            nearest_role = role_discovery.role_names.get(label, str(label))

    avg_intra_dist = cluster_dists.get(nearest_label, 0.1)

    if avg_intra_dist > 0 and min_dist > threshold * avg_intra_dist:
        anomaly_score = min(1.0, (min_dist / (avg_intra_dist + 1e-10) - 1) / threshold)
        return anomaly_score, (
            f"路径嵌入与最近角色簇 '{nearest_role}' 的距离 ({min_dist:.3f}) "
            f"显著大于簇内平均距离 ({avg_intra_dist:.3f})"
        )

    return 0.0, f"路径嵌入与角色簇 '{nearest_role}' 距离正常 ({min_dist:.3f})"
