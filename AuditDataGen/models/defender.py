from abc import ABC, abstractmethod
from typing import Tuple

class BaseDefender(ABC):
    """
    防御者模型基类，定义攻击检测接口
    """
    
    @abstractmethod
    def detect_attack(self, content: str) -> Tuple[float, str]:
        """检测攻击内容
        Args:
            content: 待检测的内容
        Returns:
            Tuple[风险评分, 原因说明]
            风险评分范围: 0.0(安全) ~ 1.0(高风险)
        """
        pass
    
    @abstractmethod
    def update_policy(self, rewards: List[float]):
        """根据奖励更新策略
        Args:
            rewards: 每一步的奖励值列表
        """
        pass