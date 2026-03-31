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

from models.base_models import BaseAttackerModel, BaseDefenderModel, RolloutSample, PPOConfig
from skeletons import SKELETONS
from generator import sample_values


class MockAttackerModel(BaseAttackerModel):
    """
    Mock Attacker：从骨架库采样并随机填充，输出合法 JSON 字符串。
    不做参数更新（用于调试训练循环）。
    """
    
    def generate(self, prompt: str, scenario_type: str, **kwargs) -> str:
        candidates = [s for s in SKELETONS if s["scenario_type"] == scenario_type]
        if not candidates:
            candidates = SKELETONS
        skeleton = random.choice(candidates)
        vals = sample_values()
        filled_flow = []
        for sender, receiver, content_tpl, etype in skeleton["flow"]:
            content = content_tpl or ""
            for k, v in vals.items():
                content = content.replace("{" + k + "}", str(v))
            filled_flow.append([sender, receiver, content, etype])
        output = {
            "scenario_type": skeleton["scenario_type"],
            "label": skeleton["label"],
            "risk_score": skeleton["risk_score"],
            "description": skeleton["description"],
            "flow": filled_flow,
        }
        return json.dumps(output, ensure_ascii=False)
    
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
    
    def save(self, path: str):
        print(f"  [MockDefender] save() no-op → {path}")
    
    def load(self, path: str):
        print(f"  [MockDefender] load() no-op ← {path}")
