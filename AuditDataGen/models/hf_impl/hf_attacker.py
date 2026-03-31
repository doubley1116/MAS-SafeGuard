import torch
from typing import List
from transformers import AutoModelForCausalLM, AutoTokenizer

# 兼容直接运行和包导入两种场景
try:
    from ..base_models import BaseAttackerModel, RolloutSample, PPOConfig
except ImportError:
    import sys, os
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))
    from models.base_models import BaseAttackerModel, RolloutSample, PPOConfig

# 尝试导入 trl，如果失败则使用简化版本
try:
    from trl import PPOTrainer, PPOConfig as TRLPPOConfig
    HAS_TRl = True
except ImportError:
    HAS_TRl = False
    print("⚠ trl 库不可用，将使用简化训练")

class HFAttackerModel(BaseAttackerModel):
    def __init__(self, model_name: str, device: str = "cuda"):
        self.model_name = model_name
        self.device = device
        
        # 加载 tokenizer
        self.tokenizer = AutoTokenizer.from_pretrained(model_name)
        if self.tokenizer.pad_token is None:
            self.tokenizer.pad_token = self.tokenizer.eos_token
        
        # 加载模型
        self.model = AutoModelForCausalLM.from_pretrained(model_name).to(device)
        
        # 是否使用 TRL PPO
        self.use_trl = HAS_TRl
        if self.use_trl:
            # 加载参考模型
            self.ref_model = AutoModelForCausalLM.from_pretrained(model_name).to(device)
            self.ref_model.eval()
            
            # 初始化 TRL PPO Trainer
            self.ppo_config = TRLPPOConfig(
                batch_size=8,
                mini_batch_size=2,
                log_with=None,
                learning_rate=1e-5
            )
            self.ppo_trainer = PPOTrainer(
                config=self.ppo_config,
                model=self.model,
                ref_model=self.ref_model,
                tokenizer=self.tokenizer
            )
            print(f"✓ 使用 TRL PPO 训练器")
        else:
            # 简化模式：不使用 TRL
            self.ref_model = None
            self.ppo_trainer = None
            # 简单优化器用于梯度更新
            self.optimizer = torch.optim.AdamW(self.model.parameters(), lr=1e-5)
            print(f"✓ 使用简化训练（无 TRL）")
    
    def generate(self, prompt: str, scenario_type: str, **kwargs) -> str:
        input_ids = self.tokenizer.encode(prompt, return_tensors="pt").to(self.device)
        
        # 生成响应
        output = self.model.generate(
            input_ids,
            max_new_tokens=100,
            do_sample=True,
            top_p=0.9,
            temperature=0.8,
            pad_token_id=self.tokenizer.eos_token_id,
            **kwargs
        )
        
        response = self.tokenizer.decode(output[0], skip_special_tokens=True)
        return response[len(prompt):]  # 只返回新生成的文本
    
    def log_prob(self, prompt: str, response: str) -> float:
        full_text = prompt + response
        input_ids = self.tokenizer.encode(full_text, return_tensors="pt").to(self.device)
        
        # 获取响应部分的logits
        with torch.no_grad():
            outputs = self.model(input_ids, output_hidden_states=False)
            logits = outputs.logits
            
        # 计算对数概率
        log_probs = torch.log_softmax(logits, dim=-1)  # [1, seq_len, vocab_size]
        prompt_len = len(self.tokenizer.encode(prompt))
        response_ids = input_ids[:, prompt_len:]  # [1, response_len]
        
        # 确保维度正确
        if response_ids.size(1) == 0:
            return 0.0
        
        # 调整形状以便 gather
        response_log_probs = torch.gather(
            log_probs[:, prompt_len:-1, :],  # [1, response_len-1, vocab_size]
            dim=2,
            index=response_ids[:, :-1].unsqueeze(-1)  # [1, response_len-1, 1]
        ).squeeze(-1)  # [1, response_len-1]
        
        return response_log_probs.mean().item()
    
    def ref_log_prob(self, prompt: str, response: str) -> float:
        if not self.use_trl or self.ref_model is None:
            # 如果没有参考模型，返回主模型的对数概率
            return self.log_prob(prompt, response)
            
        full_text = prompt + response
        input_ids = self.tokenizer.encode(full_text, return_tensors="pt").to(self.device)
        
        # 获取参考模型的logits
        with torch.no_grad():
            outputs = self.ref_model(input_ids, output_hidden_states=False)
            logits = outputs.logits
            
        # 计算对数概率
        log_probs = torch.log_softmax(logits, dim=-1)
        response_ids = input_ids[:, len(prompt):]
        response_log_probs = torch.gather(
            log_probs[0, :-1], 
            dim=1, 
            index=response_ids.unsqueeze(-1)
        ).squeeze()
        
        return response_log_probs.mean().item()
    
    def update(self, samples: List[RolloutSample], config: PPOConfig):
        """
        GRPO 更新：纯策略梯度，无 Value/Critic 模型
        
        GRPO 损失函数（裁剪的代理目标函数）：
        L = -min(ratio * advantage, clamp(ratio, 1-eps, 1+eps) * advantage)
        
        其中：
        - ratio = exp(new_log_prob - old_log_prob)
        - advantage 已在 rollout 阶段通过组内标准化计算
        """
        if not samples:
            return {}

        self.model.train()
        
        # GRPO: 直接使用样本中预计算的 advantage（组内 Z-Score）
        # 不再使用 baseline 减法
        old_log_probs = torch.tensor([s.log_prob for s in samples]).to(self.device)
        advantages = torch.tensor([s.advantage for s in samples]).to(self.device)
        
        # 计算新的对数概率（需要重新前向传播）
        new_log_probs_list = []
        for sample in samples:
            prompt = sample.prompt if sample.prompt else sample.skeleton.description
            text = prompt + " " + sample.response
            inputs = self.tokenizer(
                text, return_tensors="pt",
                truncation=True, max_length=512
            )
            inputs = {k: v.to(self.device) for k, v in inputs.items()}
            
            with torch.no_grad():  # 先用old_log_prob的相同输入
                pass
            
            # 重新计算 new_log_prob（完整前向）
            outputs = self.model(**inputs)
            logits = outputs.logits
            
            # 计算 response 部分的对数概率
            prompt_len = len(self.tokenizer.encode(prompt))
            input_ids = inputs["input_ids"]
            response_ids = input_ids[:, prompt_len:]
            
            if response_ids.size(1) == 0:
                new_log_probs_list.append(torch.tensor(0.0).to(self.device))
                continue
            
            # 计算 log_prob
            log_probs = torch.log_softmax(logits, dim=-1)
            response_log_probs = torch.gather(
                log_probs[:, prompt_len:-1, :],
                dim=2,
                index=response_ids[:, :-1].unsqueeze(-1)
            ).squeeze(-1)
            new_log_probs_list.append(response_log_probs.mean())
        
        new_log_probs = torch.stack(new_log_probs_list)
        
        # 计算 GRPO ratio
        ratio = torch.exp(new_log_probs - old_log_probs)
        
        # 计算裁剪代理损失
        clip_epsilon = config.clip_epsilon
        surr1 = ratio * advantages
        surr2 = torch.clamp(ratio, 1.0 - clip_epsilon, 1.0 + clip_epsilon) * advantages
        policy_loss = -torch.min(surr1, surr2).mean()
        
        # 反向传播
        self.optimizer.zero_grad()
        policy_loss.backward()
        torch.nn.utils.clip_grad_norm_(self.model.parameters(), 1.0)
        self.optimizer.step()
        
        # 统计信息
        avg_reward = torch.tensor([s.reward for s in samples]).mean().item()
        avg_adv = advantages.mean().item()
        stats = {
            "policy_loss": policy_loss.item(),
            "avg_reward": avg_reward,
            "avg_advantage": avg_adv,
            "samples": len(samples),
            "mean_ratio": ratio.mean().item(),
        }
        
        print(f"  [HFAttacker] GRPO更新 | samples={len(samples)} "
              f"avg_reward={avg_reward:.3f} avg_adv={avg_adv:.3f} "
              f"policy_loss={policy_loss.item():.4f}")
        return stats
    
    def save(self, path: str):
        self.model.save_pretrained(path)
        self.tokenizer.save_pretrained(path)
        print(f"攻击者模型保存到: {path}")
    
    def load(self, path: str):
        self.model = AutoModelForCausalLM.from_pretrained(path).to(self.device)
        self.tokenizer = AutoTokenizer.from_pretrained(path)
        print(f"攻击者模型从{path}加载")