import torch
import numpy as np
from sentence_transformers import SentenceTransformer
from sentence_transformers.util import cos_sim


class DiversityReward:
    _shared_model = None
    _shared_model_name: str = ""

    @classmethod
    def _load_shared_model(cls, model_name: str, device: str):
        if cls._shared_model is not None and cls._shared_model_name == model_name:
            return

        # 1) 本地缓存
        try:
            cls._shared_model = SentenceTransformer(model_name, device=device, local_files_only=True)
            cls._shared_model_name = model_name
            print(f"[DiversityReward] 加载本地缓存模型: {model_name}")
            return
        except Exception:
            pass

        # 2) HuggingFace 自动下载
        print(f"[DiversityReward] 本地缓存未命中，尝试 HuggingFace 下载: {model_name}")
        try:
            cls._shared_model = SentenceTransformer(model_name, device=device, local_files_only=False)
            cls._shared_model_name = model_name
            print(f"[DiversityReward] HuggingFace 下载并加载成功: {model_name}")
            return
        except Exception:
            pass

        # 3) ModelScope 兜底
        ms_model = f"sentence-transformers/{model_name}" if "/" not in model_name else model_name
        from modelscope import snapshot_download
        local_path = snapshot_download(ms_model)
        cls._shared_model = SentenceTransformer(local_path, device=device, local_files_only=True)
        cls._shared_model_name = model_name
        print(f"[DiversityReward] ModelScope 下载并加载成功: {local_path}")

    def __init__(self, model_name="paraphrase-MiniLM-L6-v2"):
        device = "cuda" if torch.cuda.is_available() else "cpu"
        self.device = device
        DiversityReward._load_shared_model(model_name, device)
        self.model = DiversityReward._shared_model
        self._history_cache: list[str] = []
        self._embedding_cache: list = []

    def calculate(self, new_content: str, history_contents: list, threshold=0.85) -> float:
        new_embedding = self.model.encode(new_content, convert_to_tensor=True)

        if not history_contents:
            return 0.5

        current_cache_len = len(self._history_cache)
        if current_cache_len < len(history_contents):
            new_histories = history_contents[current_cache_len:]
            new_embs = self.model.encode(new_histories, convert_to_tensor=True)
            if len(new_embs.shape) == 1:
                new_embs = new_embs.unsqueeze(0)
            self._embedding_cache.append(new_embs)
            self._history_cache.extend(new_histories)
        elif current_cache_len > len(history_contents):
            self._history_cache.clear()
            self._embedding_cache.clear()
            if history_contents:
                new_embs = self.model.encode(history_contents, convert_to_tensor=True)
                if len(new_embs.shape) == 1:
                    new_embs = new_embs.unsqueeze(0)
                self._embedding_cache.append(new_embs)
                self._history_cache.extend(history_contents)

        if not self._embedding_cache:
            return 0.5

        all_history_embeddings = torch.cat(self._embedding_cache, dim=0)
        similarities = cos_sim(new_embedding, all_history_embeddings)
        max_similarity = torch.max(similarities).item()

        if max_similarity > threshold:
            return -0.5
        return 0.5 * (1 - max_similarity)
