"""
mock_models.py
──────────────
统一 Mock 模型实现，替代分散在多处的重复定义。
"""

import json
import random
import os
import sys

# 路径调整 - 确保可以导入项目内的模块
current_dir = os.path.dirname(os.path.abspath(__file__))  # src目录
audit_gen_dir = os.path.dirname(current_dir)  # AuditDataGen目录
if audit_gen_dir not in sys.path:
    sys.path.insert(0, audit_gen_dir)
# 也添加 src 目录，以便导入 skeletons 和 generator
if current_dir not in sys.path:
    sys.path.insert(0, current_dir)

import datetime
from models.base_models import BaseAttackerModel, BaseDefenderModel, RolloutSample, GRPOConfig
from skeletons import SKELETONS


# ── sample_values: 从 generator.py 内联过来 ────────────────────────────────────
FILLERS = {
    "order_id":    ["OD-2024-88421", "OD-2024-99215", "OD-2023-55103", "OD-2024-77342"],
    "carrier":     ["SF-Express", "JD-Logistics", "YTO-Expreess", "ZTO-Express"],
    "tracking_no": ["SF1044008237423", "JDV0018237463", "YT8374192038471", "ZT0029481720"],
    "contract_id": ["CT-2024-00821", "CT-2023-05531", "CT-2024-11092", "CT-2023-07782"],
    "party_id":    ["PTY-88421", "PTY-99215", "PTY-55103", "PTY-77342"],
    "doc_category": ["采购合同", "保密协议", "劳动合同", "租赁合同", "服务协议"],
    "waybill_id":  ["WB-2024-88421", "WB-2024-99215", "WB-2023-55103", "WB-2024-77342"],
    "cargo_id":    ["CARGO-CN-88421", "CARGO-CN-99215", "CARGO-EU-55103", "CARGO-US-77342"],
    "warehouse_id": ["WH-SH-001", "WH-SZ-002", "WH-GZ-003", "WH-BJ-004"],
    "destination":  ["深圳", "上海", "广州", "北京", "成都", "杭州"],
    "emp_id":       ["EMP-20240317", "EMP-20240123", "EMP-20240205", "EMP-20240329"],
    "salary_amount": ["8500", "12000", "15000", "22000", "35000"],
    "role_name":    ["ROLE-FIN-ANALYST", "ROLE-HR-ADMIN", "ROLE-SYSTEM-ADMIN", "ROLE-AUDITOR"],
    "device_id":    ["DEVICE-88421", "DEVICE-99215", "DEVICE-55103", "DEVICE-77342"],
    "node_id":      ["NODE-A1", "NODE-B2", "NODE-C3", "NODE-D4"],
    "threshold_rule": ["max_position_limit", "daily_trade_limit", "exposure_cap", "var_limit"],
    "threshold_value": ["500000", "2000000", "0.15", "0.08"],
    "grid_command":  ["START", "STOP", "RESTART", "SYNC", "CALIBRATE"],
}


def sample_values(scenario_type: str | None = None) -> dict:
    """随机采样一套填充值，供骨架模板替换用。"""
    return {
        "order_id":    random.choice(FILLERS["order_id"]),
        "carrier":     random.choice(FILLERS["carrier"]),
        "tracking_no": random.choice(FILLERS["tracking_no"]),
        "contract_id":   random.choice(FILLERS["contract_id"]),
        "party_id":      random.choice(FILLERS["party_id"]),
        "doc_category":  random.choice(FILLERS["doc_category"]),
        "waybill_id":    random.choice(FILLERS["waybill_id"]),
        "cargo_id":      random.choice(FILLERS["cargo_id"]),
        "warehouse_id":  random.choice(FILLERS["warehouse_id"]),
        "destination":   random.choice(FILLERS["destination"]),
        "emp_id":        random.choice(FILLERS["emp_id"]),
        "salary_amount": random.choice(FILLERS["salary_amount"]),
        "role_name":     random.choice(FILLERS["role_name"]),
        "device_id":     random.choice(FILLERS["device_id"]),
        "node_id":       random.choice(FILLERS["node_id"]),
        "threshold_rule":  random.choice(FILLERS["threshold_rule"]),
        "threshold_value": random.choice(FILLERS["threshold_value"]),
        "grid_command":    random.choice(FILLERS["grid_command"]),
    }


class MockAttackerModel(BaseAttackerModel):
    """
    Mock Attacker：从骨架库采样并随机填充，输出合法 JSON 字符串。
    不做参数更新（用于调试训练循环）。
    """
    
    def generate(self, prompt: str, scenario_type: str, **kwargs) -> str:
        """
        Mock 模式：从骨架库随机选一条同类型的 content，作为改写后的输出。
        模拟"改写 content"语义，而非返回完整骨架 JSON。
        """
        candidates = [s for s in SKELETONS if s["scenario_type"] == scenario_type]
        if not candidates:
            candidates = SKELETONS
        skeleton = random.choice(candidates)
        vals = sample_values()
        
        # IPI 特殊处理：返回 tool_result 步骤的内容（文件内容注入）
        if scenario_type == "IPI":
            for sender, receiver, content_tpl, etype in skeleton["flow"]:
                if etype == "tool_result" and content_tpl:
                    content = content_tpl
                    for k, v in vals.items():
                        content = content.replace("{" + k + "}", str(v))
                    return content
            # fallback：返回 ipi_file_content
            return vals.get("ipi_file_content", "[Mock IPI 文件内容]")
        
        # 其他场景：找第一条 User 发出的 message 步骤
        for sender, receiver, content_tpl, etype in skeleton["flow"]:
            if etype == "message" and sender == "User" and content_tpl:
                content = content_tpl
                for k, v in vals.items():
                    content = content.replace("{" + k + "}", str(v))
                return content
        
        # 没有合适步骤时，返回随机填充的描述
        return f"[Mock] 改写后的{scenario_type}攻击载荷 - {vals.get('symbol', 'NVDA')}"
    
    def log_prob(self, prompt: str, response: str) -> float:
        return -1.0
    
    def ref_log_prob(self, prompt: str, response: str) -> float:
        return -1.0
    
    def update(self, samples, config):
        avg_r = sum(s.reward for s in samples) / max(len(samples), 1)
        print(f"  [MockAttacker] update() no-op | samples={len(samples)} avg_reward={avg_r:.3f}")
        return {"loss": 0.0, "kl": 0.0}
    
    def save(self, path: str):
        print(f"  [MockAttacker] save() no-op → {path}")
    
    def load(self, path: str):
        print(f"  [MockAttacker] load() no-op ← {path}")


class MockDefenderModel(BaseDefenderModel):
    """
    Mock Defender：以 detection_rate 概率正确识别攻击，每次 update 后检测率小幅提升。
    """
    
    def __init__(self, detection_rate: float = 0.5):
        self.detection_rate = detection_rate
        self._n_updates = 0
    
    def predict(self, text: str):
        confidence = random.uniform(0.55, 0.95)
        if random.random() < self.detection_rate:
            return "MALICIOUS", confidence
        return "SAFE", 1.0 - confidence
    
    def update(self, samples, labels, config):
        self._n_updates += 1
        self.detection_rate = min(0.95, self.detection_rate + 0.01)
        print(f"  [MockDefender] update() detection_rate → {self.detection_rate:.2f}")
        return {"loss": 0.0, "accuracy": self.detection_rate}

    def update_rl(self, samples, rewards, config, actions=None):
        """Mock RL 更新：奖励高时提升检测率，奖励低时小幅回退。"""
        self._n_updates += 1
        avg_reward = sum(rewards) / max(len(rewards), 1)
        # 正奖励→检测率提升，负奖励→小幅回退，模拟真实 RL 动态
        delta = 0.01 * (1 if avg_reward > 0.5 else -0.5)
        self.detection_rate = max(0.1, min(0.95, self.detection_rate + delta))
        print(f"  [MockDefender] update_rl() avg_reward={avg_reward:.3f} "
              f"detection_rate → {self.detection_rate:.2f}")
        return {"loss": 0.0, "avg_reward": avg_reward}
    
    def save(self, path: str):
        print(f"  [MockDefender] save() no-op → {path}")
    
    def load(self, path: str):
        print(f"  [MockDefender] load() no-op ← {path}")
