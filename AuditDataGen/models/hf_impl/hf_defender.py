"""
hf_defender.py
--------------
HuggingFace Defender 模型实现
支持 Qwen2.5-7B-Instruct 作为二分类器 + 原生 SDPA (Scaled Dot Product Attention)
"""
import os
import torch
import torch.nn as nn
from typing import List, Tuple
from transformers import AutoModelForSequenceClassification, AutoTokenizer
from torch.optim import AdamW

# 兼容直接运行和包导入
try:
    from ..base_models import BaseDefenderModel
except ImportError:
    import sys, os
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))
    from models.base_models import BaseDefenderModel


def _resolve_model_path(model_name: str) -> str:
    """
    将 HuggingFace 模型名解析为本地缓存的实际路径。
    - 若已是本地路径，直接返回。
    - 若在 HF 缓存中存在，返回 snapshot 目录路径（绕过网络握手）。
    - 否则返回原始模型名（交给 from_pretrained 走联网下载）。
    """
    if os.path.exists(model_name):
        return model_name

    try:
        from huggingface_hub import snapshot_download
        path = snapshot_download(model_name, local_files_only=True)
        print(f"[OK] 本地缓存命中: {path}")
        return path
    except Exception:
        print(f"[INFO] 本地缓存未命中，将联网下载: {model_name}")
        return model_name


_DTYPE_MAP = {
    "bfloat16": torch.bfloat16,
    "float16":  torch.float16,
    "float32":  torch.float32,
}


class HFDefenderModel(BaseDefenderModel):
    """
    Defender 模型：使用 Qwen2.5 系列 Instruct 模型作为二分类器。

    所有超参均可通过 YAML 的 models.defender 节注入，无需修改代码。
    """

    def __init__(
        self,
        model_name: str = "Qwen/Qwen2.5-7B-Instruct",
        device: str = "cuda",
        dtype: str = "bfloat16",
        attn_impl: str = "sdpa",
        max_length: int = 1024,
        num_labels: int = 2,
    ):
        self.model_name = model_name
        self.device = device
        self.max_length = max_length

        torch_dtype = _DTYPE_MAP.get(dtype, torch.bfloat16)

        # ── 解析模型路径（优先本地缓存，找不到才联网）─────────────────────
        resolved = _resolve_model_path(model_name)
        is_local_path = os.path.exists(resolved)

        # 加载 tokenizer
        self.tokenizer = AutoTokenizer.from_pretrained(
            resolved,
            trust_remote_code=True,
            local_files_only=is_local_path,
        )

        if self.tokenizer.pad_token is None:
            self.tokenizer.pad_token = self.tokenizer.eos_token

        # ── 加载序列分类模型 ──────────────────────────────────────────────
        self.model = AutoModelForSequenceClassification.from_pretrained(
            resolved,
            num_labels=num_labels,
            torch_dtype=torch_dtype,
            attn_implementation=attn_impl,
            trust_remote_code=True,
            device_map=device,
            local_files_only=is_local_path,
        )

        self.model.config.pad_token_id = self.tokenizer.pad_token_id
        self.model.eval()

        self.optimizer = AdamW(self.model.parameters(), lr=1e-5)
        self.loss_fn = nn.CrossEntropyLoss()

        self.label_map = {"SAFE": 0, "MALICIOUS": 1}
        self.reverse_label_map = {0: "SAFE", 1: "MALICIOUS"}

        print(f"[OK] HFDefender 初始化: {model_name}")
        print(f"     - dtype={dtype}, attn={attn_impl}, max_length={max_length}, num_labels={num_labels}")
        print(f"     - pad_token_id: {self.tokenizer.pad_token_id}")
    
    def predict(self, text: str) -> Tuple[str, float]:
        """
        预测文本类别和置信度
        
        Returns:
            Tuple[标签, 置信度]
            标签: "SAFE" 或 "MALICIOUS"
        """
        inputs = self.tokenizer(
            text,
            padding=True,
            truncation=True,
            max_length=self.max_length,
            return_tensors="pt"
        ).to(self.device)
        
        with torch.no_grad():
            outputs = self.model(**inputs)
            logits = outputs.logits
            probs = torch.softmax(logits, dim=-1)[0]
            
        max_prob, pred_class = torch.max(probs, dim=0)
        label = self.reverse_label_map[pred_class.item()]
        confidence = max_prob.item()
        
        return label, confidence
    
    def predict_batch(self, texts: List[str]) -> List[Tuple[str, float]]:
        """
        批量预测（更高效）
        
        Args:
            texts: 文本列表
        Returns:
            List[Tuple[标签, 置信度]]
        """
        if not texts:
            return []
        
        inputs = self.tokenizer(
            texts,
            padding=True,
            truncation=True,
            max_length=self.max_length,
            return_tensors="pt"
        ).to(self.device)
        
        with torch.no_grad():
            outputs = self.model(**inputs)
            logits = outputs.logits
            probs = torch.softmax(logits, dim=-1)
            
        results = []
        for i in range(len(texts)):
            max_prob, pred_class = torch.max(probs[i], dim=0)
            label = self.reverse_label_map[pred_class.item()]
            results.append((label, max_prob.item()))
        
        return results
    
    def update(self, samples: List[str], labels: List[str], config: dict):
        """
        更新防御模型（对抗训练中让 Defender 进化）
        
        Args:
            samples: 文本列表
            labels: 标签列表 ["SAFE", "MALICIOUS"]
            config: 配置字典，包含 lr 等参数
        """
        if not samples:
            return
            
        # 设置学习率
        lr = config.get("lr", 1e-5)
        for param_group in self.optimizer.param_groups:
            param_group['lr'] = lr
        
        # 准备数据
        encoded = self.tokenizer(
            samples,
            padding=True,
            truncation=True,
            max_length=1024,
            return_tensors="pt"
        )
        # 单卡严格绑定
        input_ids = encoded['input_ids'].to(self.device)
        attention_mask = encoded['attention_mask'].to(self.device)
        label_ids = torch.tensor(
            [self.label_map[label] for label in labels]
        ).to(self.device)
        
        # 训练模式
        self.model.train()
        
        # 前向传播
        outputs = self.model(input_ids, attention_mask=attention_mask)
        logits = outputs.logits
        
        # 计算损失
        loss = self.loss_fn(logits, label_ids)
        
        # 反向传播
        self.optimizer.zero_grad()
        loss.backward()
        self.optimizer.step()
        
        # 计算准确率
        preds = torch.argmax(logits, dim=1)
        correct = (preds == label_ids).sum().item()
        accuracy = correct / len(samples)
        
        print(f"[INFO] 防御者更新: loss={loss.item():.4f}, accuracy={accuracy:.2f}")
        
        return {"loss": loss.item(), "accuracy": accuracy}
    
    def update_rl(self, samples: List[str], rewards: List[float], config: dict):
        """
        REINFORCE 策略梯度更新 Defender。

        使用 Categorical 分布采样动作，计算 log_prob * reward 的梯度。
        与攻击场景奖励对称（attacker_r + defender_r = 1.0），
        让 defender 直接从博弈对抗结果中学习，而不依赖 ground truth 标签。
        """
        if not samples or not rewards:
            return

        lr = config.get("lr", 1e-5)
        for param_group in self.optimizer.param_groups:
            param_group['lr'] = lr

        encoded = self.tokenizer(
            samples,
            padding=True,
            truncation=True,
            max_length=1024,
            return_tensors="pt"
        )
        input_ids = encoded['input_ids'].to(self.device)
        attention_mask = encoded['attention_mask'].to(self.device)
        rewards_tensor = torch.tensor(rewards, dtype=torch.float32).to(self.device)

        self.model.train()
        outputs = self.model(input_ids, attention_mask=attention_mask)
        logits = outputs.logits  # [B, 2]

        # 标准 REINFORCE：从策略分布中采样动作并计算 log_prob
        dist = torch.distributions.Categorical(logits=logits)
        actions = dist.sample()  # [B]
        log_probs = dist.log_prob(actions)  # [B]

        loss = -(log_probs * rewards_tensor).mean()

        self.optimizer.zero_grad()
        loss.backward()
        torch.nn.utils.clip_grad_norm_(self.model.parameters(), max_norm=1.0)
        self.optimizer.step()

        self.model.eval()

        avg_reward = rewards_tensor.mean().item()
        correct_rate = (rewards_tensor > 0.5).float().mean().item()
        print(f"[INFO] Defender RL: loss={loss.item():.4f}, "
              f"avg_reward={avg_reward:.4f}, correct_rate={correct_rate:.2f}")
        return {"loss": loss.item(), "avg_reward": avg_reward}

    def save(self, path: str):
        """保存模型"""
        self.model.save_pretrained(path)
        self.tokenizer.save_pretrained(path)
        print(f"[OK] 防御者模型保存到: {path}")
    
    def load(self, path: str):
        """加载模型"""
        # 单卡严格绑定
        self.model = AutoModelForSequenceClassification.from_pretrained(
            path,
            torch_dtype=torch.bfloat16,
            attn_implementation="sdpa",  # 跨平台兼容
            device_map=self.device,     # 单卡严格绑定
            trust_remote_code=True,
            local_files_only=True
        )
        self.model.eval()

        self.tokenizer = AutoTokenizer.from_pretrained(path, trust_remote_code=True, local_files_only=True)
        if self.tokenizer.pad_token is None:
            self.tokenizer.pad_token = self.tokenizer.eos_token
        self.model.config.pad_token_id = self.tokenizer.pad_token_id
        
        print(f"[OK] 防御者模型从 {path} 加载")
