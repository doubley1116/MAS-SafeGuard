"""
run_adversarial_ppo.py
----------------------
对抗性PPO训练的统一运行脚本。
集成骨架数据、模型选择和训练循环。
"""

import os
import sys
import json
import random
import argparse
import yaml
from typing import List, Dict, Any
import numpy as np

# 添加项目根目录到Python路径
current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.dirname(current_dir)
sys.path.insert(0, project_root)

# 导入必要的模块（基础模块）
try:
    from src.skeletons import SKELETONS, FILLERS
    from src.adversarial_ppo import Skeleton, parse_skeleton, AdversarialPPOTrainer, PPOConfig
    from src.mock_models import MockAttackerModel, MockDefenderModel
    from models.base_models import BaseAttackerModel, BaseDefenderModel
    print("[OK] 基础模块导入成功")
except ImportError as e:
    print(f"[FAIL] 基础模块导入失败: {e}")
    print(f"Python路径: {sys.path}")
    print("请确保已安装所有依赖: pip install -r requirements.txt")
    sys.exit(1)

# HF相关模块延迟导入（只在需要时导入）
def import_hf_attacker():
    """延迟导入HFAttackerModel"""
    try:
        from models.hf_impl.hf_attacker import HFAttackerModel
        return HFAttackerModel
    except ImportError as e:
        print(f"[FAIL] HFAttackerModel导入失败: {e}")
        print("[WARN] 将回退到Mock模型")
        return None

def import_hf_defender():
    """延迟导入HFDefenderModel（7B分类器）"""
    try:
        from models.hf_impl.hf_defender import HFDefenderModel
        return HFDefenderModel
    except ImportError as e:
        print(f"[FAIL] HFDefenderModel导入失败: {e}")
        print("[WARN] 将回退到Mock模型")
        return None

def import_bert_defender():
    """延迟导入BERTDefenderModel（1.5B分类器）"""
    try:
        from models.hf_impl.bert_defender import BERTDefenderModel
        return BERTDefenderModel
    except ImportError as e:
        print(f"[FAIL] BERTDefenderModel导入失败: {e}")
        print("[WARN] 将回退到Mock模型")
        return None


def load_skeleton_pool(skeleton_type: str = "all") -> List[Skeleton]:
    """
    从骨架库加载训练数据
    
    Args:
        skeleton_type: "all" 或指定场景类型如 "DPI", "Impersonation"等
    """
    skeleton_pool = []
    
    for skeleton_def in SKELETONS:
        # 过滤场景类型
        if skeleton_type != "all" and skeleton_def["scenario_type"] != skeleton_type:
            continue
            
        # 填充占位符
        filled_flow = []
        for step in skeleton_def["flow"]:
            if len(step) < 4:
                continue
            sender, receiver, content, event_type = step
            if content is None:
                filled_flow.append((sender, receiver, content, event_type))
                continue
                
            # 替换占位符
            filled_content = content
            for placeholder, values in FILLERS.items():
                placeholder_str = f"{{{placeholder}}}"
                if placeholder_str in filled_content:
                    filled_content = filled_content.replace(
                        placeholder_str, 
                        str(random.choice(values))
                    )
            filled_flow.append((sender, receiver, filled_content, event_type))
        
        # 创建Skeleton对象
        skeleton = Skeleton(
            scenario_type=skeleton_def["scenario_type"],
            description=skeleton_def["description"],
            messages=[{"sender": s, "receiver": r, "content": c, "event_type": e} 
                     for s, r, c, e in filled_flow if c is not None]
        )
        skeleton_pool.append(skeleton)
    
    print(f"[OK] 加载了 {len(skeleton_pool)} 个骨架样本")
    return skeleton_pool


def create_attacker_model(model_type: str, model_name: str = None, device: str = "cpu") -> BaseAttackerModel:
    """
    创建攻击者模型
    
    Args:
        model_type: "mock", "gpt2", "wenozhong", "qwen"
        model_name: 可选，自定义模型名称
        device: "cpu" 或 "cuda"
    """
    # 如果请求mock模型，直接返回
    if model_type == "mock":
        return MockAttackerModel()
    
    # 设置默认模型名称
    if model_name is None:
        if model_type == "gpt2":
            model_name = "gpt2"
        elif model_type == "wenozhong":
            model_name = "IDEA-CCNL/Wenzhong-GPT2-110M"
        elif model_type == "qwen":
            model_name = "Qwen/Qwen2.5-1.5B-Instruct"
        else:
            model_name = "gpt2"
    
    # 检查设备可用性
    if device == "cuda":
        try:
            import torch
            if not torch.cuda.is_available():
                print("[WARN] CUDA不可用，回退到CPU")
                device = "cpu"
        except ImportError:
            device = "cpu"
    
    try:
        # 延迟导入HFAttackerModel
        HFAttackerModelClass = import_hf_attacker()
        if HFAttackerModelClass is None:
            print("[WARN] HFAttackerModel不可用，使用Mock模型作为后备")
            return MockAttackerModel()
        
        print(f"[OK] 创建攻击者模型: {model_name} on {device}")
        return HFAttackerModelClass(model_name=model_name, device=device)
    except Exception as e:
        print(f"[FAIL] 创建攻击者模型失败: {e}")
        print("[WARN] 使用Mock模型作为后备")
        return MockAttackerModel()


def create_defender_model(model_type: str, model_name: str = None, device: str = "cpu") -> BaseDefenderModel:
    """
    创建防御者模型
    
    Args:
        model_type: "mock", "bert", "roberta", "ernie"
        model_name: 可选，自定义模型名称
        device: "cpu" 或 "cuda"
    """
    # 如果请求mock模型，直接返回
    if model_type == "mock":
        return MockDefenderModel()
    
    # 设置默认模型名称
    if model_name is None:
        if model_type == "bert":
            model_name = "bert-base-chinese"
        elif model_type == "roberta":
            model_name = "hfl/chinese-roberta-wwm-ext"
        elif model_type == "ernie":
            model_name = "nghuyong/ernie-3.0-base-zh"
        elif model_type == "hf":
            model_name = "Qwen/Qwen2.5-7B-Instruct"  # H100双7B配置
        else:
            model_name = "bert-base-chinese"
    
    # 检查设备可用性
    if device == "cuda":
        try:
            import torch
            if not torch.cuda.is_available():
                print("[WARN] CUDA不可用，回退到CPU")
                device = "cpu"
        except ImportError:
            device = "cpu"
    
    try:
        # H100双7B：使用HFDefenderModel（7B分类器）
        if model_type == "hf":
            HFDefenderModelClass = import_hf_defender()
            if HFDefenderModelClass is None:
                print("[WARN] HFDefenderModel不可用，使用Mock模型作为后备")
                return MockDefenderModel()
            
            print(f"[OK] 创建防御者模型 (7B分类器): {model_name} on {device}")
            return HFDefenderModelClass(model_name=model_name, device=device)
        else:
            # 传统BERT类分类器
            BERTDefenderModelClass = import_bert_defender()
            if BERTDefenderModelClass is None:
                print("[WARN] BERTDefenderModel不可用，使用Mock模型作为后备")
                return MockDefenderModel()
            
            print(f"[OK] 创建防御者模型: {model_name} on {device}")
            return BERTDefenderModelClass(model_name=model_name, device=device)
    except Exception as e:
        print(f"[FAIL] 创建防御者模型失败: {e}")
        print("[WARN] 使用Mock模型作为后备")
        return MockDefenderModel()




def load_config(config_path: str = None) -> Dict[str, Any]:
    """
    从YAML配置文件加载训练配置
    
    Args:
        config_path: 配置文件路径，如果为None则使用默认路径
    
    Returns:
        配置字典
    """
    if config_path is None:
        # 默认配置文件路径
        config_path = os.path.join(project_root, "configs", "adversarial_ppo_config.yaml")
    
    if not os.path.exists(config_path):
        print(f"[FAIL] 配置文件不存在: {config_path}")
        print("请创建配置文件或指定有效的配置文件路径")
        sys.exit(1)
    
    try:
        with open(config_path, "r", encoding="utf-8") as f:
            config = yaml.safe_load(f)
        print(f"[OK] 从 {config_path} 加载配置")
        return config
    except Exception as e:
        print(f"[FAIL] 加载配置文件失败: {e}")
        sys.exit(1)


def train_from_config(config: Dict[str, Any]):
    """根据配置字典执行对抗性PPO训练"""
    print("=" * 60)
    print("对抗性PPO训练启动 (从配置文件)")
    print("=" * 60)

    # 1. 加载骨架数据
    print("\n[1/4] 加载训练数据...")
    skeleton_type = config.get("data", {}).get("skeleton_type", "all")
    skeleton_pool = load_skeleton_pool(skeleton_type=skeleton_type)

    if not skeleton_pool:
        print("[FAIL] 没有找到可用的骨架数据")
        return

    # 2. 创建模型
    device = config.get("device", "cpu")
    print(f"\n[2/4] 创建模型 (设备: {device})...")

    attacker_config = config.get("models", {}).get("attacker", {})
    defender_config = config.get("models", {}).get("defender", {})

    attacker = create_attacker_model(
        model_type=attacker_config.get("type", "mock"),
        model_name=attacker_config.get("name"),
        device=device
    )

    defender = create_defender_model(
        model_type=defender_config.get("type", "mock"),
        model_name=defender_config.get("name"),
        device=device
    )

    # 3. 创建训练器
    print(f"\n[3/4] 创建训练器...")
    train_config = config.get("train", {})
    config_ppo = PPOConfig(
        batch_size=train_config.get("batch_size", 8),
        ppo_epochs=train_config.get("ppo_epochs", 4),
        lr=train_config.get("learning_rate", 1e-5),
        gamma=train_config.get("gamma", 0.99),
        lam=train_config.get("lam", 0.95),
        clip_epsilon=train_config.get("clip_epsilon", 0.2),
        vf_coef=train_config.get("vf_coef", 0.5),
        entropy_coef=train_config.get("entropy_coef", 0.01)
    )

    # 从配置读取新参数
    curriculum_config = config.get("curriculum", {})
    diversity_config = config.get("diversity", {})
    output_config = config.get("output", {})

    phase_duration = curriculum_config.get("phase_duration", 5)
    max_history_size = diversity_config.get("history_size", 100)
    checkpoint_interval = output_config.get("checkpoint_interval", 20)
    output_dir = output_config.get("dir", "output_ppo")

    trainer = AdversarialPPOTrainer(
        attacker=attacker,
        defender=defender,
        config=config_ppo,
        skeleton_pool=skeleton_pool,
        max_history_size=max_history_size,
        phase_duration=phase_duration,
    )

    os.makedirs(output_dir, exist_ok=True)
    print(f"[OK] 输出目录: {output_dir}")

    # 5. 保存训练配置
    config_file = os.path.join(output_dir, "train_config.yaml")
    with open(config_file, "w", encoding="utf-8") as f:
        yaml.dump(config, f, default_flow_style=False, allow_unicode=True, indent=2)
    print(f"[OK] 训练配置保存到: {config_file}")

    # 6. 开始训练
    iterations = train_config.get("iterations", 50)
    print(f"\n[4/4] 开始训练 (迭代次数: {iterations})...")
    print("-" * 40)

    trainer.train(
        iterations,
        checkpoint_interval=checkpoint_interval,
        output_dir=output_dir,
    )
    
    # 7. 保存最终模型
    final_model_dir = os.path.join(output_dir, "final_model")
    os.makedirs(os.path.join(final_model_dir, "attacker"), exist_ok=True)
    os.makedirs(os.path.join(final_model_dir, "defender"), exist_ok=True)
    
    attacker.save(os.path.join(final_model_dir, "attacker"))
    defender.save(os.path.join(final_model_dir, "defender"))
    print(f"[OK] 最终模型保存到: {final_model_dir}")
    
    print("=" * 60)
    print("训练完成!")
    print("=" * 60)


def main():
    """主函数：从配置文件运行训练"""
    parser = argparse.ArgumentParser(
        description="对抗性PPO训练 - 从配置文件运行",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    
    # 只保留一个配置参数
    parser.add_argument("--config", type=str, default=None,
                       help="配置文件路径（默认: configs/adversarial_ppo_config.yaml）")
    
    args = parser.parse_args()
    
    # 加载配置
    config = load_config(args.config)
    
    # 运行训练
    train_from_config(config)


if __name__ == "__main__":
    main()
