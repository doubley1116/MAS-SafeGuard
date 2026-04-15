"""
run_adversarial_grpo.py
-----------------------
对抗性GRPO训练的统一运行脚本。
集成骨架数据、模型选择和训练循环。
"""

import os
import sys
import json
import copy
import random
import argparse
import yaml
import collections.abc
from typing import List, Dict, Any
import numpy as np

# 添加项目根目录到Python路径
current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.dirname(current_dir)
sys.path.insert(0, project_root)


def deep_update(d: dict, u: dict) -> dict:
    """
    递归深度合并两个字典。
    对于嵌套字典，会递归合并；对于普通值，用 u 覆盖 d。
    修复了 Python 中 dict.update() 只做浅拷贝导致嵌套字典被整体覆盖的问题。
    
    使用 deepcopy 确保原始字典不会被污染，适合多次调用或循环使用场景。
    
    Args:
        d: 基础字典（默认配置）
        u: 更新字典（用户配置）
    Returns:
        合并后的字典
    """
    d = copy.deepcopy(d)  # 保护原字典不被污染
    for k, v in u.items():
        if isinstance(v, collections.abc.Mapping):
            d[k] = deep_update(d.get(k, {}), v)
        else:
            d[k] = v
    return d


# 默认配置（用于深度合并）
DEFAULT_CONFIG = {
    "device": "cpu",
    "data": {
        "skeleton_type": "all"
    },
    "models": {
        "attacker": {
            "type": "mock",
            "name": None,
            "device": "cpu"
        },
        "defender": {
            "type": "mock",
            "name": None,
            "device": "cpu"
        }
    },
    "train": {
        "batch_size": 8,
        "group_size": 4,
        "grpo_epochs": 4,
        "learning_rate": 1e-5,
        "gamma": 0.99,
        "lam": 0.95,
        "clip_epsilon": 0.2,
        "vf_coef": 0.5,
        "entropy_coef": 0.01,
        "iterations": 50
    },
    "curriculum": {
        "phase_duration": 5
    },
    "diversity": {
        "history_size": 100
    },
    "output": {
        "checkpoint_interval": 20,
        "dir": "output_grpo"
    }
}

# 导入必要的模块（基础模块）
try:
    from src.skeletons import SKELETONS, FILLERS
    from src.adversarial_grpo import Skeleton, parse_skeleton, AdversarialGRPOTrainer, GRPOConfig
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


# 旧→新的 scenario_type 映射表（问题1修复）
SCENARIO_RENAME = {
    "DPI":           "SemanticInjection",
    "Impersonation": "CallerImpersonation",
    "MultiHop":      "SemanticInjection",
    "Colluding":     "PathBypass",
    "IPI":           "IPI",
    "Byzantine":     "PathBypass",
    "Contradicting": "PathBypass",
    "AiTM":          "AiTM",
    "benign":        "benign",
}


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
        
        # 映射旧名称到新名称（问题1修复）
        old_scenario = skeleton_def["scenario_type"]
        scenario_type = SCENARIO_RENAME.get(old_scenario, old_scenario)
        
        # 填充占位符
        filled_flow = []
        for step in skeleton_def["flow"]:
            if len(step) < 4:
                continue
            sender, receiver, content, event_type = step
            if content is None:
                filled_flow.append((sender, receiver, content, event_type))
                continue
                
            # 替换占位符（按键长度降序，避免短键破坏长键）
            filled_content = content
            # {ipi_file_content} 不直接存在于 FILLERS，需合并各场景池后采样
            if "{ipi_file_content}" in filled_content:
                all_ipi = [v for k, vs in FILLERS.items()
                           if k.startswith("ipi_file_content_") for v in vs]
                if all_ipi:
                    filled_content = filled_content.replace(
                        "{ipi_file_content}", str(random.choice(all_ipi))
                    )
            for placeholder, values in sorted(FILLERS.items(), key=lambda x: len(x[0]), reverse=True):
                placeholder_str = f"{{{placeholder}}}"
                if placeholder_str in filled_content:
                    filled_content = filled_content.replace(
                        placeholder_str,
                        str(random.choice(values))
                    )
            filled_flow.append((sender, receiver, filled_content, event_type))
        
        # 创建Skeleton对象（使用映射后的 scenario_type）
        skeleton = Skeleton(
            scenario_type=scenario_type,
            description=skeleton_def["description"],
            messages=[{"sender": s, "receiver": r, "content": c, "event_type": e} 
                     for s, r, c, e in filled_flow if c is not None]
        )
        skeleton_pool.append(skeleton)
    
    print(f"[OK] 加载了 {len(skeleton_pool)} 个骨架样本")
    return skeleton_pool


def create_attacker_model(
    model_type: str,
    model_name: str = None,
    device: str = "cpu",
    model_config: dict = None,
) -> BaseAttackerModel:
    """
    创建攻击者模型

    Args:
        model_type: "mock", "gpt2", "wenozhong", "qwen"
        model_name: 可选，自定义模型名称
        device: "cpu" 或 "cuda"
        model_config: YAML models.attacker 节完整字典，用于透传超参
    """
    if model_type == "mock":
        return MockAttackerModel()

    if model_name is None:
        if model_type == "gpt2":
            model_name = "gpt2"
        elif model_type == "wenozhong":
            model_name = "IDEA-CCNL/Wenzhong-GPT2-110M"
        elif model_type == "qwen":
            model_name = "Qwen/Qwen2.5-1.5B-Instruct"
        else:
            model_name = "gpt2"

    if device.startswith("cuda"):
        try:
            import torch
            if not torch.cuda.is_available():
                print("[WARN] CUDA不可用，回退到CPU")
                device = "cpu"
        except ImportError:
            device = "cpu"

    cfg = model_config or {}
    lora_cfg = cfg.get("lora", {})

    try:
        HFAttackerModelClass = import_hf_attacker()
        if HFAttackerModelClass is None:
            print("[WARN] HFAttackerModel不可用，使用Mock模型作为后备")
            return MockAttackerModel()

        print(f"[OK] 创建攻击者模型: {model_name} on {device}")
        return HFAttackerModelClass(
            model_name=model_name,
            device=device,
            dtype=cfg.get("dtype", "bfloat16"),
            attn_impl=cfg.get("attn_impl", "sdpa"),
            max_new_tokens=cfg.get("max_new_tokens", 150),
            top_p=cfg.get("top_p", 0.9),
            temperature=cfg.get("temperature", 0.8),
            lora_r=lora_cfg.get("r", 32),
            lora_alpha=lora_cfg.get("alpha", 64),
            lora_dropout=lora_cfg.get("dropout", 0.05),
        )
    except Exception as e:
        print(f"[FAIL] 创建攻击者模型失败: {e}")
        print("[WARN] 使用Mock模型作为后备")
        return MockAttackerModel()


def create_defender_model(
    model_type: str,
    model_name: str = None,
    device: str = "cpu",
    model_config: dict = None,
) -> BaseDefenderModel:
    """
    创建防御者模型

    Args:
        model_type: "mock", "bert", "roberta", "ernie", "hf"
        model_name: 可选，自定义模型名称
        device: "cpu" 或 "cuda"
        model_config: YAML models.defender 节完整字典，用于透传超参
    """
    if model_type == "mock":
        return MockDefenderModel()

    if model_name is None:
        if model_type == "bert":
            model_name = "bert-base-chinese"
        elif model_type == "roberta":
            model_name = "hfl/chinese-roberta-wwm-ext"
        elif model_type == "ernie":
            model_name = "nghuyong/ernie-3.0-base-zh"
        elif model_type == "hf":
            model_name = "Qwen/Qwen2.5-7B-Instruct"
        else:
            model_name = "bert-base-chinese"

    if device.startswith("cuda"):
        try:
            import torch
            if not torch.cuda.is_available():
                print("[WARN] CUDA不可用，回退到CPU")
                device = "cpu"
        except ImportError:
            device = "cpu"

    cfg = model_config or {}

    try:
        if model_type == "hf":
            HFDefenderModelClass = import_hf_defender()
            if HFDefenderModelClass is None:
                print("[WARN] HFDefenderModel不可用，使用Mock模型作为后备")
                return MockDefenderModel()

            print(f"[OK] 创建防御者模型: {model_name} on {device}")
            return HFDefenderModelClass(
                model_name=model_name,
                device=device,
                dtype=cfg.get("dtype", "bfloat16"),
                attn_impl=cfg.get("attn_impl", "sdpa"),
                max_length=cfg.get("max_length", 1024),
                num_labels=cfg.get("num_labels", 2),
            )
        else:
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
    从YAML配置文件加载训练配置，使用深度合并策略。
    
    配置会先使用默认配置（DEFAULT_CONFIG），然后用用户配置深度覆盖，
    确保用户配置中的任何嵌套字段都能正确覆盖默认值，而非整体替换。
    
    Args:
        config_path: 配置文件路径，如果为None则使用默认路径
    
    Returns:
        配置字典（已深度合并）
    """
    # 从默认配置开始（深拷贝，避免修改原字典）
    config = deep_update({}, DEFAULT_CONFIG)
    
    if config_path is None:
        # 默认配置文件路径
        config_path = os.path.join(project_root, "configs", "adversarial_grpo_config.yaml")
    
    if not os.path.exists(config_path):
        print(f"[FAIL] 配置文件不存在: {config_path}")
        print("请创建配置文件或指定有效的配置文件路径")
        sys.exit(1)
    
    try:
        with open(config_path, "r", encoding="utf-8") as f:
            user_config = yaml.safe_load(f)
        print(f"[OK] 从 {config_path} 加载配置")
        
        # 使用深度合并：用用户配置覆盖默认配置
        # 这样嵌套字典（如 models.attacker）只会部分覆盖，而非整体替换
        if user_config:
            config = deep_update(config, user_config)
        
        return config
    except Exception as e:
        print(f"[FAIL] 加载配置文件失败: {e}")
        sys.exit(1)


def train_from_config(config: Dict[str, Any]):
    """根据配置字典执行对抗性GRPO训练"""
    print("=" * 60)
    print("对抗性GRPO训练启动 (从配置文件)")
    print("=" * 60)

    # 1. 加载骨架数据
    print("\n[1/4] 加载训练数据...")
    skeleton_type = config.get("data", {}).get("skeleton_type", "all")
    skeleton_pool = load_skeleton_pool(skeleton_type=skeleton_type)

    if not skeleton_pool:
        print("[FAIL] 没有找到可用的骨架数据")
        return

    # 2. 创建模型
    attacker_config = config.get("models", {}).get("attacker", {})
    defender_config = config.get("models", {}).get("defender", {})
    
    # 从各自模型配置读取设备信息，支持独立双卡部署
    attacker_device = attacker_config.get("device", config.get("device", "cpu"))
    defender_device = defender_config.get("device", config.get("device", "cpu"))
    
    print(f"\n[2/4] 创建模型 (attacker: {attacker_device}, defender: {defender_device})...")

    attacker = create_attacker_model(
        model_type=attacker_config.get("type", "mock"),
        model_name=attacker_config.get("model_name", attacker_config.get("name")),
        device=attacker_device,
        model_config=attacker_config,
    )

    defender = create_defender_model(
        model_type=defender_config.get("type", "mock"),
        model_name=defender_config.get("model_name", defender_config.get("name")),
        device=defender_device,
        model_config=defender_config,
    )

    # 3. 创建训练器
    print(f"\n[3/4] 创建训练器...")
    train_config = config.get("train", {})
    config_grpo = GRPOConfig(
        batch_size=train_config.get("batch_size", 8),
        group_size=train_config.get("group_size", 4),
        grpo_epochs=train_config.get("grpo_epochs", 4),
        lr=train_config.get("learning_rate", 1e-5),
        clip_epsilon=train_config.get("clip_epsilon", 0.2),
        entropy_coef=train_config.get("entropy_coef", 0.01)
    )

    # 从配置读取新参数
    curriculum_config = config.get("curriculum", {})
    diversity_config = config.get("diversity", {})
    output_config = config.get("output", {})
    rl_config = config.get("rl", {})
    reward_weights = rl_config.get("reward_weights", {})

    phase_duration = curriculum_config.get("phase_duration", 5)
    # 读取 YAML 中的课程难度配置（如未配置则用代码默认值）
    # 注意：场景名必须与 SKELETONS 中 scenario_type 一致（新名称体系）
    yaml_difficulty = curriculum_config.get("difficulty_levels", None)
    max_history_size = diversity_config.get("history_size", 100)
    checkpoint_interval = output_config.get("checkpoint_interval", 20)
    output_dir = output_config.get("dir", "output_grpo")
    lambda_div = reward_weights.get("diversity", 0.3)
    defender_lr = train_config.get("defender_lr", rl_config.get("defender_lr", 1e-6))

    trainer = AdversarialGRPOTrainer(
        attacker=attacker,
        defender=defender,
        config=config_grpo,
        skeleton_pool=skeleton_pool,
        max_history_size=max_history_size,
        phase_duration=phase_duration,
        lambda_div=lambda_div,
        defender_lr=defender_lr,
        difficulty_levels=yaml_difficulty,
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
        description="对抗性GRPO训练 - 从配置文件运行",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    
    # 只保留一个配置参数
    parser.add_argument("--config", type=str, default=None,
                       help="配置文件路径（默认: configs/adversarial_grpo_config.yaml）")
    
    args = parser.parse_args()
    
    # 加载配置
    config = load_config(args.config)
    
    # 运行训练
    train_from_config(config)


if __name__ == "__main__":
    main()
