import torch
import torch.nn as nn
from typing import List, Tuple
from transformers import BertForSequenceClassification, BertTokenizer
from torch.optim import AdamW  # 使用 torch.optim 的 AdamW

# 兼容直接运行和包导入两种场景
try:
    from ..base_models import BaseDefenderModel
except ImportError:
    import sys, os
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))
    from models.base_models import BaseDefenderModel

class BERTDefenderModel(BaseDefenderModel):
    def __init__(self, model_name: str = "bert-base-chinese", device: str = "cuda"):
        self.model_name = model_name
        self.device = device
        self.tokenizer = BertTokenizer.from_pretrained(model_name)
        
        # 加载预训练模型（bf16 半精度优化 + 显存节省）
        self.model = BertForSequenceClassification.from_pretrained(
            model_name,
            num_labels=2,
            output_attentions=False,
            output_hidden_states=False,
            torch_dtype=torch.bfloat16,  # bf16 显存优化
        ).to(device)
        
        # 推理模式（不保存梯度）
        self.model.eval()
        
        # 优化器
        self.optimizer = AdamW(self.model.parameters(), lr=1e-5)
        self.loss_fn = nn.CrossEntropyLoss()
        
        # 类别映射
        self.label_map = {"SAFE": 0, "MALICIOUS": 1}
    
    def predict(self, text: str) -> Tuple[str, float]:
        inputs = self.tokenizer(
            text,
            padding=True,
            truncation=True,
            max_length=512,
            return_tensors="pt"
        ).to(self.device)
        
        with torch.no_grad():
            outputs = self.model(**inputs)
            logits = outputs.logits
            probs = torch.softmax(logits, dim=-1)[0]
            
        max_prob, pred_class = torch.max(probs, dim=0)
        label = "SAFE" if pred_class.item() == 0 else "MALICIOUS"
        confidence = max_prob.item()
        
        return label, confidence
    
    def update(self, samples: List[str], labels: List[str], config: dict):
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
            max_length=512,
            return_tensors="pt"
        )
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
        
        print(f"防御者更新: loss={loss.item():.4f}, accuracy={accuracy:.2f}")
    
    def save(self, path: str):
        self.model.save_pretrained(path)
        self.tokenizer.save_pretrained(path)
        print(f"防御者模型保存到: {path}")
    
    def load(self, path: str):
        self.model = BertForSequenceClassification.from_pretrained(path).to(self.device)
        self.tokenizer = BertTokenizer.from_pretrained(path)
        print(f"防御者模型从{path}加载")