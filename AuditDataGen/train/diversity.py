import torch
import numpy as np
from sentence_transformers import SentenceTransformer
from sentence_transformers.util import cos_sim

class DiversityReward:
    def __init__(self, model_name='paraphrase-MiniLM-L6-v2'):
        """初始化多样性奖励计算器
        Args:
            model_name: 使用的embedding模型
        """
        # 强制使用 GPU 计算，防止 GPU 0% 利用率问题
        device = 'cuda' if torch.cuda.is_available() else 'cpu'
        self.device = device
        self.history_embeddings = []
        self._use_fallback = False

        try:
            self.model = SentenceTransformer(model_name, device=device, local_files_only=True)
            print(f"[DiversityReward] 加载本地缓存模型: {model_name}")
        except Exception:
            try:
                self.model = SentenceTransformer(model_name, device=device)
                print(f"[DiversityReward] 在线下载模型: {model_name}")
            except Exception as e:
                print(f"[DiversityReward][WARN] 无法加载 SentenceTransformer ({e})，降级为词袋相似度")
                self.model = None
                self._use_fallback = True
        
    def calculate(self, new_content: str, history_contents: list, threshold=0.85) -> float:
        """计算多样性奖励值
        Args:
            new_content: 新生成的内容
            history_contents: 历史内容列表
            threshold: 相似度阈值
        Returns:
            多样性奖励值
        """
        if self._use_fallback:
            return self._fallback_diversity(new_content, history_contents, threshold)
        
        # 编码新内容
        new_embedding = self.model.encode(new_content, convert_to_tensor=True)
        
        # 首次生成无历史记录
        if not history_contents:
            return 0.5
            
        # 编码历史内容
        history_embeddings = self.model.encode(history_contents, convert_to_tensor=True)
        
        # 计算与历史内容的最大相似度
        similarities = cos_sim(new_embedding, history_embeddings)
        max_similarity = torch.max(similarities).item()
        
        # 根据相似度返回奖励值
        if max_similarity > threshold:
            return -0.5  # 重复内容惩罚
        else:
            return 0.5 * (1 - max_similarity)  # 创新内容奖励

    def _fallback_diversity(self, new_content: str, history_contents: list, threshold=0.85) -> float:
        """基于词集合的 Jaccard 相似度，不依赖模型"""
        if not history_contents:
            return 0.5
        new_tokens = set(new_content.lower().split())
        max_sim = 0.0
        for h in history_contents:
            h_tokens = set(h.lower().split())
            union = new_tokens | h_tokens
            if not union:
                continue
            sim = len(new_tokens & h_tokens) / len(union)
            if sim > max_sim:
                max_sim = sim
        if max_sim > threshold:
            return -0.5
        return 0.5 * (1 - max_sim)
