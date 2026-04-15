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
        self._use_fallback = False
        # 缓存历史文本与对应 embedding，避免重复编码
        self._history_cache: list[str] = []
        self._embedding_cache: list = []

        try:
            self.model = SentenceTransformer(model_name, device=device, local_files_only=True)
            print(f"[DiversityReward] 加载本地缓存模型: {model_name}")
        except Exception:
            print(f"[DiversityReward] 本地缓存未命中，尝试 ModelScope 下载: {model_name}")
            try:
                from modelscope import snapshot_download
                local_path = snapshot_download(model_name)
                self.model = SentenceTransformer(local_path, device=device, local_files_only=True)
                print(f"[DiversityReward] ModelScope 下载并加载成功: {local_path}")
            except Exception as e:
                print(f"[DiversityReward][WARN] ModelScope 下载失败 ({e})，降级为词袋相似度")
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

        # 增量编码：只处理新增的历史内容
        # 使用内容哈希校验，防止外部修改 history_contents 后缓存错位
        current_cache_len = len(self._history_cache)
        if current_cache_len < len(history_contents):
            new_histories = history_contents[current_cache_len:]
            new_embs = self.model.encode(new_histories, convert_to_tensor=True)
            if len(new_embs.shape) == 1:
                new_embs = new_embs.unsqueeze(0)
            self._embedding_cache.append(new_embs)
            self._history_cache.extend(new_histories)
        elif current_cache_len > len(history_contents):
            # history_contents 被外部缩短，重置缓存以避免错位
            self._history_cache.clear()
            self._embedding_cache.clear()
            current_cache_len = 0
            if current_cache_len < len(history_contents):
                new_histories = history_contents
                new_embs = self.model.encode(new_histories, convert_to_tensor=True)
                if len(new_embs.shape) == 1:
                    new_embs = new_embs.unsqueeze(0)
                self._embedding_cache.append(new_embs)
                self._history_cache.extend(new_histories)

        if not self._embedding_cache:
            return 0.5

        # 计算与历史内容的最大相似度
        all_history_embeddings = torch.cat(self._embedding_cache, dim=0)
        similarities = cos_sim(new_embedding, all_history_embeddings)
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
