"""
hf_attacker.py
--------------
HuggingFace Attacker 模型实现
支持 Qwen2.5-7B-Instruct + Flash Attention 2 + LoRA (r=32)
"""
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

# 尝试导入 peft (LoRA)
try:
    from peft import get_peft_model, LoraConfig, TaskType
    HAS_PEFT = True
except ImportError:
    HAS_PEFT = False
    print("[WARN] peft 库不可用，将不使用 LoRA")

# 尝试导入 trl
try:
    from trl import PPOTrainer, PPOConfig as TRLPPOConfig
    HAS_TRL = True
except ImportError:
    HAS_TRL = False
    print("[WARN] trl 库不可用，将使用简化训练")


class HFAttackerModel(BaseAttackerModel):
    """
    Attacker 模型：支持 Qwen2.5-7B-Instruct
    
    H100 优化特性：
    - Flash Attention 2 加速
    - bfloat16 半精度
    - LoRA r=32, lora_alpha=64 (增强拟合能力)
    """
    
    def __init__(self, model_name: str = "Qwen/Qwen2.5-7B-Instruct", device: str = "cuda"):
        self.model_name = model_name
        self.device = device
        
        # 加载 tokenizer
        self.tokenizer = AutoTokenizer.from_pretrained(
            model_name,
            trust_remote_code=True
        )
        
        # H100 优化：注入 pad_token (大模型通常没有)
        if self.tokenizer.pad_token is None:
            self.tokenizer.pad_token = self.tokenizer.eos_token
        
        # ── H100 加速：Flash Attention 2 + bfloat16 ──────────────────────
        self.model = AutoModelForCausalLM.from_pretrained(
            model_name, 
            torch_dtype=torch.bfloat16,
            device_map=device,
            attn_implementation="flash_attention_2",  # H100 提速核心
            trust_remote_code=True
        )
        
        # H100 显存充足：增强 LoRA 配置
        if HAS_PEFT:
            peft_config = LoraConfig(
                task_type=TaskType.CAUSAL_LM,
                inference_mode=False,
                r=32,                          # 增强：16G->32
                lora_alpha=64,                 # 增强：32->64
                lora_dropout=0.05,
                target_modules=["q_proj", "k_proj", "v_proj", "o_proj", "gate_proj", "up_proj", "down_proj"]
            )
            self.model = get_peft_model(self.model, peft_config)
            self.model.print_trainable_parameters()
            print("[OK] 已启用 LoRA (r=32, alpha=64) - H100 优化")
        else:
            print("[WARN] 未启用 LoRA")
        
        # 是否使用 TRL PPO
        self.use_trl = HAS_TRL
        if self.use_trl:
            self.ref_model = AutoModelForCausalLM.from_pretrained(
                model_name, 
                torch_dtype=torch.bfloat16,
                device_map=device,
                attn_implementation="flash_attention_2",
                trust_remote_code=True
            )
            self.ref_model.eval()
            
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
            print("[OK] 使用 TRL PPO 训练器")
        else:
            self.ref_model = None
            self.ppo_trainer = None
            self.optimizer = torch.optim.AdamW(
                filter(lambda p: p.requires_grad, self.model.parameters()), 
                lr=1e-5
            )
            print("[OK] 使用简化训练（无 TRL）")
    
    def generate(self, prompt: str, scenario_type: str, **kwargs) -> str:
        """生成攻击内容"""
        inputs = self.tokenizer(prompt, return_tensors="pt").to(self.device)
        
        output = self.model.generate(
            input_ids=inputs["input_ids"],
            attention_mask=inputs["attention_mask"],
            max_new_tokens=150,              # 7B模型：增加生成长度
            do_sample=True,
            top_p=0.9,
            temperature=0.8,
            pad_token_id=self.tokenizer.pad_token_id,
            **kwargs
        )
        
        response = self.tokenizer.decode(output[0], skip_special_tokens=True)
        # 去掉 prompt 部分，只返回生成内容
        generated = response[len(prompt):]
        return generated.strip()
    
    def log_prob(self, prompt: str, response: str) -> float:
        """计算对数概率"""
        full_text = prompt + response
        input_ids = self.tokenizer.encode(full_text, return_tensors="pt").to(self.device)
        
        with torch.no_grad():
            outputs = self.model(input_ids, output_hidden_states=False)
            logits = outputs.logits
            
        log_probs = torch.log_softmax(logits, dim=-1)
        prompt_len = len(self.tokenizer.encode(prompt))
        response_ids = input_ids[:, prompt_len:]
        
        if response_ids.size(1) == 0:
            return 0.0
        
        response_log_probs = torch.gather(
            log_probs[:, prompt_len:-1, :],
            dim=2,
            index=response_ids[:, :-1].unsqueeze(-1)
        ).squeeze(-1)
        
        return response_log_probs.mean().item()
    
    def ref_log_prob(self, prompt: str, response: str) -> float:
        """参考模型的对数概率"""
        if not self.use_trl or self.ref_model is None:
            return self.log_prob(prompt, response)
            
        full_text = prompt + response
        input_ids = self.tokenizer.encode(full_text, return_tensors="pt").to(self.device)
        
        with torch.no_grad():
            outputs = self.ref_model(input_ids)
            logits = outputs.logits
            
        log_probs = torch.log_softmax(logits, dim=-1)
        response_ids = input_ids[:, len(prompt):]
        response_log_probs = torch.gather(
            log_probs[0, :-1], 
            dim=1, 
            index=response_ids.unsqueeze(-1)
        ).squeeze()
        
        return response_log_probs.mean().item()
    
    def update(self, samples: List[RolloutSample], config: PPOConfig):
        """GRPO 更新"""
        if not samples:
            return {}

        self.model.train()
        
        old_log_probs = torch.tensor([s.log_prob for s in samples]).to(self.device)
        advantages = torch.tensor([s.advantage for s in samples]).to(self.device)
        
        # 重新计算对数概率
        new_log_probs_list = []
        for sample in samples:
            prompt = sample.prompt if sample.prompt else sample.skeleton.description
            text = prompt + " " + sample.response
            inputs = self.tokenizer(
                text, return_tensors="pt",
                truncation=True, max_length=1024  # 7B模型：增加上下文长度
            )
            inputs = {k: v.to(self.device) for k, v in inputs.items()}
            
            outputs = self.model(**inputs)
            logits = outputs.logits
            
            prompt_len = len(self.tokenizer.encode(prompt))
            input_ids = inputs["input_ids"]
            response_ids = input_ids[:, prompt_len:]
            
            if response_ids.size(1) == 0:
                new_log_probs_list.append(torch.tensor(0.0).to(self.device))
                continue
            
            log_probs = torch.log_softmax(logits, dim=-1)
            response_log_probs = torch.gather(
                log_probs[:, prompt_len:-1, :],
                dim=2,
                index=response_ids[:, :-1].unsqueeze(-1)
            ).squeeze(-1)
            new_log_probs_list.append(response_log_probs.mean())
        
        new_log_probs = torch.stack(new_log_probs_list)
        
        # GRPO ratio
        ratio = torch.exp(new_log_probs - old_log_probs)
        clip_epsilon = config.clip_epsilon
        surr1 = ratio * advantages
        surr2 = torch.clamp(ratio, 1.0 - clip_epsilon, 1.0 + clip_epsilon) * advantages
        policy_loss = -torch.min(surr1, surr2).mean()
        
        # 反向传播
        self.optimizer.zero_grad()
        policy_loss.backward()
        torch.nn.utils.clip_grad_norm_(self.model.parameters(), 1.0)
        self.optimizer.step()
        
        avg_reward = torch.tensor([s.reward for s in samples]).mean().item()
        stats = {
            "policy_loss": policy_loss.item(),
            "avg_reward": avg_reward,
            "samples": len(samples),
        }
        
        print(f"  [HFAttacker] GRPO更新 | samples={len(samples)} "
              f"avg_reward={avg_reward:.3f} policy_loss={policy_loss.item():.4f}")
        return stats
    
    def save(self, path: str):
        self.model.save_pretrained(path)
        self.tokenizer.save_pretrained(path)
        print(f"[OK] 攻击者模型保存到: {path}")
    
    def load(self, path: str):
        self.model = AutoModelForCausalLM.from_pretrained(
            path,
            torch_dtype=torch.bfloat16,
            device_map=self.device,
            attn_implementation="flash_attention_2",
            trust_remote_code=True
        )
        self.tokenizer = AutoTokenizer.from_pretrained(path, trust_remote_code=True)
        if self.tokenizer.pad_token is None:
            self.tokenizer.pad_token = self.tokenizer.eos_token
        print(f"[OK] 攻击者模型从 {path} 加载")
