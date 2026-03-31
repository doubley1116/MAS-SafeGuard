from abc import ABC, abstractmethod
from typing import List

class BaseAttacker(ABC):
    """
    攻击者模型基类，定义攻击生成接口
    """
    
    @abstractmethod
    def generate_attack(self, context: str) -> str:
        """生成攻击内容，需子类实现
        Args:
            context: 当前对话上下文
        Returns:
            生成的攻击内容
        """
        pass
    
    @abstractmethod
    def update_policy(self, rewards: List[float]):
        """根据奖励更新策略
        Args:
            rewards: 每一步的奖励值列表
        """
        pass