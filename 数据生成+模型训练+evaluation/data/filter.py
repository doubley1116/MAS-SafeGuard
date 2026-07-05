import json
import argparse
from pathlib import Path

def load_ground_truth(file_path: str) -> dict:
    """
    从原始文件加载 ground truth
    返回 {line_num: label}
    """
    ground_truth = {}
    with open(file_path, 'r', encoding='utf-8') as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                intent = data.get('metadata', {}).get('intent', 'unknown')
                # 统一标签
                if intent == 'benign':
                    label = 'normal'
                elif intent == 'attack':
                    label = 'dangerous'
                else:
                    label = 'unknown'
                ground_truth[line_num] = label
            except json.JSONDecodeError:
                print(f"原始文件第 {line_num} 行 JSON 解析错误")
                ground_truth[line_num] = 'error'
    return ground_truth

def load_audit_results(file_path: str) -> dict:
    """
    从审计结果文件加载预测标签和完整审计信息
    返回 {line_num: {"label": predicted_label, "full_audit": audit_dict}}
    """
    predictions = {}
    with open(file_path, 'r', encoding='utf-8') as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                
                # 提取预测标签和审计信息
                predicted = 'ambiguous'
                audit_info = {}
                
                # 尝试多种字段路径
                if 'audit' in data:
                    audit_info = data['audit']
                    # 过滤掉 reasoning
                    if 'reasoning' in audit_info:
                        del audit_info['reasoning']
                    predicted = audit_info.get('label', 'ambiguous')
                elif 'audit_result' in data:
                    audit_info = data['audit_result']
                    # 过滤掉 reasoning
                    if 'reasoning' in audit_info:
                        del audit_info['reasoning']
                    predicted = audit_info.get('label', 'ambiguous')
                elif 'label' in data:
                    predicted = data['label']
                    audit_info = {'label': predicted}
                
                # 如果审计信息中有 line_num，使用它作为 key
                actual_line_num = data.get('line_num', line_num)
                predictions[actual_line_num] = {
                    "label": predicted,
                    "full_audit": audit_info
                }
            except json.JSONDecodeError:
                print(f"审计文件第 {line_num} 行 JSON 解析错误")
                predictions[line_num] = {
                    "label": 'error',
                    "full_audit": {}
                }
    return predictions

def remove_reasoning_from_file(input_file: str, output_file: str = None):
    """
    直接从文件中删除 reasoning 字段
    
    Args:
        input_file: 输入的 JSONL 文件
        output_file: 输出文件路径（默认 input_file_clean.jsonl）
    """
    if output_file is None:
        base, ext = os.path.splitext(input_file)
        output_file = f"{base}_clean.jsonl"
    
    removed_count = 0
    total_count = 0
    
    with open(input_file, 'r', encoding='utf-8') as infile, \
         open(output_file, 'w', encoding='utf-8') as outfile:
        
        for line in infile:
            line = line.strip()
            if not line:
                continue
            
            total_count += 1
            try:
                data = json.loads(line)
                
                # 删除所有可能位置的 reasoning
                if 'audit' in data and isinstance(data['audit'], dict):
                    if 'reasoning' in data['audit']:
                        del data['audit']['reasoning']
                        removed_count += 1
                
                if 'audit_result' in data and isinstance(data['audit_result'], dict):
                    if 'reasoning' in data['audit_result']:
                        del data['audit_result']['reasoning']
                        removed_count += 1
                
                outfile.write(json.dumps(data, ensure_ascii=False) + '\n')
                
            except json.JSONDecodeError:
                print(f"JSON 解析错误，跳过该行")
                outfile.write(line + '\n')
    
    print(f"\n清理完成！")
    print(f"  总处理行数: {total_count}")
    print(f"  删除 reasoning 的行数: {removed_count}")
    print(f"  输出文件: {output_file}")
    
    return output_file

def is_inconsistent(ground_truth: str, predicted: str) -> bool:
    """
    判断是否不一致
    只统计 normal ↔ dangerous 的不一致
    """
    if ground_truth not in ['normal', 'dangerous']:
        return False
    if predicted not in ['normal', 'dangerous']:
        return False
    
    return ground_truth != predicted

def merge_and_filter(original_file: str, audit_file: str, output_file: str = None, keep_inconsistent: bool = False):
    """
    合并原始文件和审计结果，筛选数据
    输出包含原始数据 + 审计结果（不含 reasoning）
    
    Args:
        original_file: 原始 all.jsonl 文件（包含 metadata.intent）
        audit_file: 审计结果 all_audit.jsonl 文件
        output_file: 输出文件路径
        keep_inconsistent: True=保留不一致的数据, False=删除不一致的数据(保留一致的数据)
    """
    # 加载数据
    print(f"加载原始文件: {original_file}")
    ground_truth = load_ground_truth(original_file)
    
    print(f"加载审计文件: {audit_file}")
    predictions = load_audit_results(audit_file)
    
    # 读取原始完整数据
    original_data = {}
    with open(original_file, 'r', encoding='utf-8') as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if line:
                try:
                    original_data[line_num] = json.loads(line)
                except:
                    original_data[line_num] = line
    
    # 找出共同的行号
    common_lines = set(ground_truth.keys()) & set(predictions.keys())
    
    stats = {
        "total": len(common_lines),
        "consistent": 0,
        "inconsistent": 0,
        "false_positive": 0,
        "false_negative": 0,
        "ambiguous_pred": 0,
        "unknown_gt": 0
    }
    
    filtered_records = []
    
    # 遍历共同行号
    for line_num in sorted(common_lines):
        gt = ground_truth[line_num]
        pred_info = predictions[line_num]
        pred = pred_info["label"]
        full_audit = pred_info["full_audit"]
        
        # 统计（每个 line_num 只统计一次）
        if gt == 'unknown':
            stats["unknown_gt"] += 1
        
        if pred == 'ambiguous':
            stats["ambiguous_pred"] += 1
        
        # 决定是否保留
        should_keep = False
        
        if gt in ['normal', 'dangerous'] and pred in ['normal', 'dangerous']:
            if gt != pred:
                stats["inconsistent"] += 1
                if gt == 'normal' and pred == 'dangerous':
                    stats["false_positive"] += 1
                elif gt == 'dangerous' and pred == 'normal':
                    stats["false_negative"] += 1
                should_keep = keep_inconsistent
            else:
                stats["consistent"] += 1
                should_keep = not keep_inconsistent
        else:
            # ambiguous 或 unknown 的情况
            # 这些数据默认保留（除非明确要排除）
            should_keep = not keep_inconsistent
        
        # 构建输出记录
        if should_keep and line_num in original_data:
            original_json = original_data[line_num]
            
            # 确保 original_json 是字典
            if isinstance(original_json, str):
                try:
                    original_json = json.loads(original_json)
                except:
                    original_json = {"raw": original_json}
            
            # 合并：原始数据 + 审计结果（不含 reasoning，已在 load_audit_results 中过滤）
            merged_record = {
                "original": original_json,
                "audit_result": {
                    "label": pred,
                    "analysis": full_audit.get('analysis', ''),
                    "reason": full_audit.get('reason', '')
                }
            }
            
            filtered_records.append(json.dumps(merged_record, ensure_ascii=False))
    
    # 写入输出文件
    if output_file is None:
        base_name = Path(original_file).stem
        if keep_inconsistent:
            output_file = f"{base_name}_inconsistent.jsonl"
        else:
            output_file = f"{base_name}_consistent.jsonl"
    
    with open(output_file, 'w', encoding='utf-8') as f:
        for record in filtered_records:
            f.write(record + '\n')
    
    # 打印统计
    print(f"\n{'='*60}")
    print(f"筛选完成！")
    print(f"{'='*60}")
    print(f"原始文件: {original_file}")
    print(f"审计文件: {audit_file}")
    print(f"输出文件: {output_file}")
    
    print(f"\n统计信息:")
    print(f"  总匹配行数:           {stats['total']}")
    print(f"  一致 (保留):          {stats['consistent']}")
    print(f"  不一致 (删除):        {stats['inconsistent']}")
    print(f"    - 误报 (normal→dangerous): {stats['false_positive']}")
    print(f"    - 漏报 (dangerous→normal): {stats['false_negative']}")
    print(f"  预测 ambiguous:       {stats['ambiguous_pred']}")
    print(f"  真实标签 unknown:     {stats['unknown_gt']}")
    
    # 计算性能指标（仅当有 valid 样本时）
    total_valid = stats['consistent'] + stats['inconsistent']
    if total_valid > 0:
        accuracy = stats['consistent'] / total_valid * 100
        print(f"\n性能指标:")
        print(f"  准确率 (Accuracy): {accuracy:.1f}%")
        
        # 计算精确率和召回率（针对 dangerous 类）
        tp = stats['consistent'] - stats['false_negative']
        fp = stats['false_positive']
        fn = stats['false_negative']
        
        if tp + fp > 0:
            precision = tp / (tp + fp) * 100
            print(f"  精确率 (Precision): {precision:.1f}%")
        
        if tp + fn > 0:
            recall = tp / (tp + fn) * 100
            print(f"  召回率 (Recall): {recall:.1f}%")
        
        if 'precision' in locals() and 'recall' in locals():
            f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
            print(f"  F1 分数: {f1:.1f}%")
    
    print(f"\n输出文件包含: {len(filtered_records)} 条数据")
    print(f"{'='*60}")

def main():
    parser = argparse.ArgumentParser(description='合并原始数据和审计结果，筛选不一致条目，并过滤 reasoning')
    parser.add_argument('original_file', nargs='?', help='原始 all.jsonl 文件（包含 metadata.intent）')
    parser.add_argument('audit_file', nargs='?', help='审计结果 all_audit.jsonl 文件')
    parser.add_argument('-o', '--output', help='输出文件路径')
    parser.add_argument('--keep-inconsistent', action='store_true',
                        help='保留不一致的数据（默认删除不一致，保留一致）')
    parser.add_argument('--stats-only', action='store_true',
                        help='仅显示统计信息，不保存文件')
    parser.add_argument('--clean-only', help='仅清理文件中的 reasoning 字段，不进行筛选（传入文件路径）')
    
    args = parser.parse_args()
    
    # 仅清理模式
    if args.clean_only:
        remove_reasoning_from_file(args.clean_only, args.output)
        return
    
    # 检查必需参数
    if not args.original_file or not args.audit_file:
        print("错误：请提供 original_file 和 audit_file 参数")
        print("\n用法:")
        print("  python filter.py original.jsonl audit.jsonl")
        print("  python filter.py --clean-only input.jsonl -o output.jsonl")
        print("  python filter.py original.jsonl audit.jsonl --keep-inconsistent")
        print("  python filter.py original.jsonl audit.jsonl --stats-only")
        sys.exit(1)
    
    if args.stats_only:
        # 仅统计，不保存
        merge_and_filter(args.original_file, args.audit_file, "temp.jsonl", True)
        import os
        os.remove("temp.jsonl")
    else:
        merge_and_filter(args.original_file, args.audit_file, args.output, args.keep_inconsistent)

if __name__ == "__main__":
    import sys
    main()