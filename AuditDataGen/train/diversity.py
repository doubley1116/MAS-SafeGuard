import torch
import numpy as np
from sentence_transformers import SentenceTransformer
from sentence_transformers.util import cos_sim

class DiversityReward:
    # 类级别共享模型缓存：所有实例共用同一个 SentenceTransformer，只加载一次
    _shared_model = None
    _shared_model_name: str = ""
    _shared_use_fallback: bool = False

    @classmethod
    def _load_shared_model(cls, model_name: str, device: str):
        """首次调用时加载模型并缓存到类变量，后续实例直接复用。"""
        if cls._shared_model is not None and cls._shared_model_name == model_name:
            return  # 已加载，直接返回
        try:
            cls._shared_model = SentenceTransformer(model_name, device=device, local_files_only=True)
            cls._shared_model_name = model_name
            cls._shared_use_fallback = False
            print(f"[DiversityReward] 加载本地缓存模型: {model_name}")
        except Exception:
            print(f"[DiversityReward] 本地缓存未命中，尝试 ModelScope 下载: {model_name}")
            try:
                from modelscope import snapshot_download
                local_path = snapshot_download(model_name)
                cls._shared_model = SentenceTransformer(local_path, device=device, local_files_only=True)
                cls._shared_model_name = model_name
                cls._shared_use_fallback = False
                print(f"[DiversityReward] ModelScope 下载并加载成功: {local_path}")
            except Exception as e:
                print(f"[DiversityReward][WARN] ModelScope 下载失败 ({e})，降级为词袋相似度")
                cls._shared_model = None
                cls._shared_model_name = model_name
                cls._shared_use_fallback = True

    def __init__(self, model_name='paraphrase-MiniLM-L6-v2'):
        """初始化多样性奖励计算器
        Args:
            model_name: 使用的embedding模型
        """
        device = 'cuda' if torch.cuda.is_available() else 'cpu'
        self.device = device
        # 确保共享模型已加载
        DiversityReward._load_shared_model(model_name, device)
        self.model = DiversityReward._shared_model
        self._use_fallback = DiversityReward._shared_use_fallback
        # 每个实例独立维护自己的历史缓存（不同 attack_type 的历史不共享）
        self._history_cache: list[str] = []
        self._embedding_cache: list = []

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
