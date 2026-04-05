"""
hf_defender.py
--------------
HuggingFace Defender 模型实现
支持 Qwen2.5-7B-Instruct 作为二分类器 + 原生 SDPA (Scaled Dot Product Attention)
"""
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


class HFDefenderModel(BaseDefenderModel):
    """
    Defender 模型：使用 Qwen2.5-7B-Instruct 作为二分类器
    
    H100 优化特性：
    - Flash Attention 2 加速
    - bfloat16 半精度
    - Pad Token 修复（批量打分兼容性）
    """
    
    def __init__(self, model_name: str = "Qwen/Qwen2.5-7B-Instruct", device: str = "cuda"):
        self.model_name = model_name
        self.device = device
        
        # 加载 tokenizer（local_files_only=False 支持首次下载或离线缓存）
        self.tokenizer = AutoTokenizer.from_pretrained(
            model_name,
            trust_remote_code=True,
            local_files_only=False
        )
        
        # 【关键修复】Pad Token 问题：大模型默认没有 pad_token
        if self.tokenizer.pad_token is None:
            self.tokenizer.pad_token = self.tokenizer.eos_token
        
        # ── SDPA 加速：跨平台原生注意力机制 ──────────────────────────────
        # 使用 PyTorch 2.0 原生的 Scaled Dot Product Attention (SDPA)
        # 优势：全平台支持（Windows/Linux）、速度快、不依赖 flash-attn 库
        self.model = AutoModelForSequenceClassification.from_pretrained(
            model_name,
            num_labels=2,                     # 二分类：SAFE vs MALICIOUS
            torch_dtype=torch.bfloat16,       # bfloat16 半精度
            attn_implementation="sdpa",       # 跨平台兼容，比 flash_attention_2 更广泛支持
            trust_remote_code=True,
            device_map=device,                # 单卡严格绑定
            local_files_only=False
        )
        
        # 【关键修复】同步 pad_token_id
        self.model.config.pad_token_id = self.tokenizer.pad_token_id
        
        # 推理模式（不保存梯度）
        self.model.eval()
        
        # 优化器
        self.optimizer = AdamW(self.model.parameters(), lr=1e-5)
        self.loss_fn = nn.CrossEntropyLoss()
        
        # 类别映射
        self.label_map = {"SAFE": 0, "MALICIOUS": 1}
        self.reverse_label_map = {0: "SAFE", 1: "MALICIOUS"}
        
        print(f"[OK] HFDefender 初始化: {model_name}")
        print(f"     - SDPA: 已启用 (跨平台兼容)")
        print(f"     - bfloat16: 已启用")
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
            max_length=1024,      # 7B模型支持更长上下文
            return_tensors="pt"
        ).to(self.device)  # 单卡严格绑定
        
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
            max_length=1024,
            return_tensors="pt"
        ).to(self.device)  # 单卡严格绑定
        
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

        Defender 的"策略"是分类分布 P(label | text)。
        "动作"是 argmax 预测的标签，log_prob 是该标签的对数概率。
        loss = -mean(log_prob(predicted_label) * reward)

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

        # log P(label | text) for each label
        log_probs = torch.log_softmax(logits, dim=-1)  # [B, 2]

        # 取 argmax（实际预测的动作）对应的 log_prob
        predicted_classes = torch.argmax(logits, dim=-1)  # [B]
        selected_log_probs = log_probs.gather(
            1, predicted_classes.unsqueeze(1)
        ).squeeze(1)  # [B]

        # REINFORCE loss: -log_prob * reward（梯度裁剪防止爆炸）
        loss = -(selected_log_probs * rewards_tensor).mean()

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
