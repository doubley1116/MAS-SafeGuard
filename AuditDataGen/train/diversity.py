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
        self.model = SentenceTransformer(model_name)
        self.history_embeddings = []
        
    def calculate(self, new_content: str, history_contents: list, threshold=0.85) -> float:
        """计算多样性奖励值
        Args:
            new_content: 新生成的内容
            history_contents: 历史内容列表
            threshold: 相似度阈值
        Returns:
            多样性奖励值
        """
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
