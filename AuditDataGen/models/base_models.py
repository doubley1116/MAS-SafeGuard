"""
base_models.py
──────────────
对抗性PPO训练的统一模型基类定义。
"""

from abc import ABC, abstractmethod
from typing import List, Dict, Tuple, Optional, Union
import torch


class BaseAttacker(ABC):
    """
    攻击者模型基类（与train/adversarial_ppo.py兼容）
    """
    
    @abstractmethod
    def generate_attack(self, context: str) -> str:
        """生成攻击内容"""
        pass
    
    @abstractmethod
    def update_policy(self, rewards: List[float]):
        """根据奖励更新策略（简化接口）"""
        pass
    
    def get_action_prob(self, states: List[str], actions: List[str]) -> torch.Tensor:
        """获取动作概率（PPO训练需要）"""
        # 默认实现返回随机概率
        return torch.rand(len(states))
    
    def parameters(self):
        """返回模型参数（用于优化器）"""
        return []


class BaseDefender(ABC):
    """
    防御者模型基类（与train/adversarial_ppo.py兼容）
    """
    
    @abstractmethod
    def detect_attack(self, content: str) -> Tuple[float, str]:
        """检测攻击内容
        Returns:
            Tuple[风险评分, 原因说明]
        """
        pass
    
    @abstractmethod
    def update_policy(self, rewards: List[float]):
        """根据奖励更新策略"""
        pass
    
    def get_action_prob(self, states: List[str], actions: List[str]) -> torch.Tensor:
        """获取动作概率（PPO训练需要）"""
        # 默认实现返回随机概率
        return torch.rand(len(states))
    
    def parameters(self):
        """返回模型参数（用于优化器）"""
        return []


# ============================================================================
# PPO训练专用基类（与src/adversarial_ppo.py兼容）
# ============================================================================

class RolloutSample:
    """GRPO训练样本"""
    def __init__(self, skeleton: 'Skeleton', response: str, reward: float, 
                 log_prob: float, advantage: float = 0.0, prompt: str = ""):
        self.skeleton = skeleton
        self.response = response
        self.reward = reward
        self.log_prob = log_prob
        self.advantage = advantage  # GRPO: 组内标准化的优势函数
        self.prompt = prompt  # GRPO: 保存prompt用于重新计算log_prob


class GRPOConfig:
    """GRPO训练配置（无Critic/Value模型）"""
    def __init__(self, 
                 batch_size: int = 8,
                 group_size: int = 4,
                 ppo_epochs: int = 4,
                 lr: float = 1e-5,
                 clip_epsilon: float = 0.2,
                 entropy_coef: float = 0.01):
        self.batch_size = batch_size
        self.group_size = group_size  # GRPO: 每个prompt生成的response数量
        self.ppo_epochs = ppo_epochs
        self.lr = lr
        self.clip_epsilon = clip_epsilon
        self.entropy_coef = entropy_coef

    @property
    def gamma(self):
        """保留gamma属性以保持向后兼容"""
        return 0.99
    
    @property
    def lam(self):
        """保留lam属性以保持向后兼容（GRPO不使用GAE）"""
        return 0.0
    
    @property
    def vf_coef(self):
        """保留vf_coef属性以保持向后兼容（GRPO无Value损失）"""
        return 0.0


# 向后兼容：PPOConfig 仍可用，内部自动映射到 GRPOConfig
class PPOConfig(GRPOConfig):
    """PPO训练配置（已迁移到GRPO，无Value模型）"""
    def __init__(self, 
                 batch_size: int = 8,
                 group_size: int = 4,
                 ppo_epochs: int = 4,
                 lr: float = 1e-5,
                 gamma: float = 0.99,
                 lam: float = 0.95,
                 clip_epsilon: float = 0.2,
                 vf_coef: float = 0.5,
                 entropy_coef: float = 0.01):
        super().__init__(
            batch_size=batch_size,
            group_size=group_size,
            ppo_epochs=ppo_epochs,
            lr=lr,
            clip_epsilon=clip_epsilon,
            entropy_coef=entropy_coef
        )


class BaseAttackerModel(ABC):
    """
    PPO攻击者模型基类（与src/adversarial_ppo.py兼容）
    """
    
    @abstractmethod
    def generate(self, prompt: str, scenario_type: str, **kwargs) -> str:
        """生成响应"""
        pass
    
    @abstractmethod
    def log_prob(self, prompt: str, response: str) -> float:
        """计算对数概率"""
        pass
    
    def ref_log_prob(self, prompt: str, response: str) -> float:
        """参考模型的对数概率（默认与主模型相同）"""
        return self.log_prob(prompt, response)
    
    @abstractmethod
    def update(self, samples: List[RolloutSample], config: PPOConfig):
        """PPO更新"""
        pass
    
    @abstractmethod
    def save(self, path: str):
        """保存模型"""
        pass
    
    @abstractmethod
    def load(self, path: str):
        """加载模型"""
        pass


class BaseDefenderModel(ABC):
    """
    PPO防御者模型基类（与src/adversarial_ppo.py兼容）
    """
    
    @abstractmethod
    def predict(self, text: str) -> Tuple[str, float]:
        """预测文本类别和置信度"""
        pass
    
    @abstractmethod
    def update(self, samples: List[str], labels: List[str], config: dict):
        """更新模型"""
        pass
    
    @abstractmethod
    def save(self, path: str):
        """保存模型"""
        pass
    
    @abstractmethod
    def load(self, path: str):
        """加载模型"""
        pass


# ============================================================================
# 适配器类：让PPO模型兼容训练器接口
# ============================================================================

class PPOAttackerAdapter(BaseAttacker):
    """将BaseAttackerModel适配为BaseAttacker接口"""
    
    def __init__(self, ppo_model: BaseAttackerModel):
        self.ppo_model = ppo_model
        self.history = []
    
    def generate_attack(self, context: str) -> str:
        # 简单提示构造
        prompt = f"生成攻击载荷: {context}"
        return self.ppo_model.generate(prompt, scenario_type="unknown")
    
    def update_policy(self, rewards: List[float]):
        # 简化的更新逻辑，实际PPO更新在PPO模型内部完成
        print(f"PPOAttackerAdapter收到奖励: {rewards}")
    
    def get_action_prob(self, states: List[str], actions: List[str]) -> torch.Tensor:
        # 计算平均对数概率
        probs = []
        for state, action in zip(states, actions):
            prob = self.ppo_model.log_prob(state, action)
            probs.append(prob)
        return torch.tensor(probs)
    
    def parameters(self):
        # 返回PPO模型的参数
        return []


class PPODefenderAdapter(BaseDefender):
    """将BaseDefenderModel适配为BaseDefender接口"""
    
    def __init__(self, ppo_model: BaseDefenderModel):
        self.ppo_model = ppo_model
    
    def detect_attack(self, content: str) -> Tuple[float, str]:
        label, confidence = self.ppo_model.predict(content)
        # 转换标签为风险评分
        risk_score = confidence if label == "MALICIOUS" else 1 - confidence
        reason = f"模型预测: {label} (置信度: {confidence:.2f})"
        return risk_score, reason
    
    def update_policy(self, rewards: List[float]):
        # 简化的更新逻辑
        print(f"PPODefenderAdapter收到奖励: {rewards}")
    
    def get_action_prob(self, states: List[str], actions: List[str]) -> torch.Tensor:
        # 对于防御者，动作概率较难定义，返回随机值
        return torch.rand(len(states))
    
    def parameters(self):
        return []


# 导出所有基类
__all__ = [
    'BaseAttacker', 'BaseDefender',
    'BaseAttackerModel', 'BaseDefenderModel',
    'RolloutSample', 'PPOConfig',
    'PPOAttackerAdapter', 'PPODefenderAdapter'
]