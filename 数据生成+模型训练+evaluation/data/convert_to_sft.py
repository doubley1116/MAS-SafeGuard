import json
import argparse
from pathlib import Path

def convert_to_sft_format(input_file, output_file):
    """
    将 filter.py 输出转换为 SFT 训练格式（Alpaca 格式）
    
    filter.py 输出格式：
    {"original": {...}, "audit_result": {"label": "...", "analysis": "...", "reason": "..."}}
    
    SFT 输出格式：
    {"instruction": "...", "output": "..."}
    """
    
    stats = {
        "total": 0,
        "normal": 0,
        "dangerous": 0,
        "ambiguous": 0,
        "skipped": 0
    }
    
    with open(input_file, 'r', encoding='utf-8') as infile, \
         open(output_file, 'w', encoding='utf-8') as outfile:
        
        for line_num, line in enumerate(infile, 1):
            line = line.strip()
            if not line:
                continue
            
            try:
                data = json.loads(line)
                
                original = data.get('original', {})
                audit = data.get('audit_result', {})
                
                task = original.get('task', '')
                content = original.get('content')  # 允许 None
                label = audit.get('label', '')
                analysis = audit.get('analysis', '')
                reason = audit.get('reason', '')
                
                stats["total"] += 1
                
                # 统计标签分布
                if label == 'normal':
                    stats["normal"] += 1
                elif label == 'dangerous':
                    stats["dangerous"] += 1
                elif label == 'ambiguous':
                    stats["ambiguous"] += 1
                else:
                    # 未知标签，跳过
                    stats["skipped"] += 1
                    continue
                
                # 检查 task 和 reason 是否存在
                if not task or not reason:
                    print(f"警告：第 {line_num} 行 task 或 reason 缺失，已跳过")
                    stats["skipped"] += 1
                    continue
                
                # 处理 content 为 None 的情况
                if content is None or content == "":
                    content_str = "（无消息内容）"
                else:
                    content_str = content
                
                # 构建 instruction
                instruction = f"""任务目标：{task}

消息内容：{content_str}"""
                
                # 构建 output
                output = f"""标签：{label}

分析：{analysis}

理由：{reason}"""
                
                record = {
                    "instruction": instruction,
                    "output": output
                }
                
                outfile.write(json.dumps(record, ensure_ascii=False) + '\n')
                
            except json.JSONDecodeError as e:
                print(f"第 {line_num} 行 JSON 解析错误: {e}")
                stats["skipped"] += 1
            except Exception as e:
                print(f"第 {line_num} 行处理错误: {e}")
                stats["skipped"] += 1
    
    # 打印统计信息
    print(f"\n{'='*50}")
    print(f"转换完成！")
    print(f"{'='*50}")
    print(f"输入文件: {input_file}")
    print(f"输出文件: {output_file}")
    print(f"\n统计信息:")
    print(f"  总处理行数:     {stats['total']}")
    print(f"  normal:         {stats['normal']}")
    print(f"  dangerous:      {stats['dangerous']}")
    print(f"  ambiguous:      {stats['ambiguous']}")
    print(f"  成功写入:       {stats['normal'] + stats['dangerous'] + stats['ambiguous']}")
    print(f"  跳过/失败:      {stats['skipped']}")
    print(f"{'='*50}")


def convert_to_sharegpt_format(input_file, output_file):
    """
    转换为 ShareGPT 格式（用于 TRL + setup_chat_format）
    保留 normal、dangerous、ambiguous 三种标签
    """
    
    stats = {
        "total": 0,
        "normal": 0,
        "dangerous": 0,
        "ambiguous": 0,
        "skipped": 0
    }
    
    with open(input_file, 'r', encoding='utf-8') as infile, \
         open(output_file, 'w', encoding='utf-8') as outfile:
        
        for line_num, line in enumerate(infile, 1):
            line = line.strip()
            if not line:
                continue
            
            try:
                data = json.loads(line)
                
                original = data.get('original', {})
                audit = data.get('audit_result', {})
                
                task = original.get('task', '')
                content = original.get('content')  # 允许 None
                label = audit.get('label', '')
                analysis = audit.get('analysis', '')
                reason = audit.get('reason', '')
                
                stats["total"] += 1
                
                # 统计标签分布
                if label == 'normal':
                    stats["normal"] += 1
                elif label == 'dangerous':
                    stats["dangerous"] += 1
                elif label == 'ambiguous':
                    stats["ambiguous"] += 1
                else:
                    # 未知标签，跳过
                    stats["skipped"] += 1
                    continue
                
                # 检查 task 和 reason 是否存在
                if not task or not reason:
                    print(f"警告：第 {line_num} 行 task 或 reason 缺失，已跳过")
                    stats["skipped"] += 1
                    continue
                
                # 处理 content 为 None 的情况
                if content is None or content == "":
                    content_str = "（无消息内容）"
                else:
                    content_str = content
                
                # 转义特殊字符
                analysis_escaped = analysis.replace('"', '\\"').replace('\n', '\\n')
                reason_escaped = reason.replace('"', '\\"').replace('\n', '\\n')
                
                # 构建 output JSON 字符串
                output_value = f'{{"label": "{label}", "analysis": "{analysis_escaped}", "reason": "{reason_escaped}"}}'
                
                # ShareGPT 格式
                record = {
                    "conversations": [
                        {
                            "from": "human",
                            "value": f"任务目标：{task}\n\n消息内容：{content_str}"
                        },
                        {
                            "from": "gpt",
                            "value": output_value
                        }
                    ]
                }
                
                outfile.write(json.dumps(record, ensure_ascii=False) + '\n')
                
            except json.JSONDecodeError as e:
                print(f"第 {line_num} 行 JSON 解析错误: {e}")
                stats["skipped"] += 1
            except Exception as e:
                print(f"第 {line_num} 行处理错误: {e}")
                stats["skipped"] += 1
    
    # 打印统计信息
    print(f"\n{'='*50}")
    print(f"转换完成！")
    print(f"{'='*50}")
    print(f"输入文件: {input_file}")
    print(f"输出文件: {output_file}")
    print(f"\n统计信息:")
    print(f"  总处理行数:     {stats['total']}")
    print(f"  normal:         {stats['normal']}")
    print(f"  dangerous:      {stats['dangerous']}")
    print(f"  ambiguous:      {stats['ambiguous']}")
    print(f"  成功写入:       {stats['normal'] + stats['dangerous'] + stats['ambiguous']}")
    print(f"  跳过/失败:      {stats['skipped']}")
    print(f"{'='*50}")


def main():
    parser = argparse.ArgumentParser(description='将 filter.py 输出转换为 SFT 训练格式')
    parser.add_argument('input_file', help='filter.py 输出的 JSONL 文件')
    parser.add_argument('output_file', help='输出文件路径')
    parser.add_argument('--format', choices=['alpaca', 'sharegpt'], default='alpaca',
                        help='输出格式：alpaca（默认）或 sharegpt')
    
    args = parser.parse_args()
    
    if args.format == 'alpaca':
        convert_to_sft_format(args.input_file, args.output_file)
    else:
        convert_to_sharegpt_format(args.input_file, args.output_file)


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 3:
        print("用法:")
        print("  python convert_to_sft.py <input.jsonl> <output.jsonl>")
        print("  python convert_to_sft.py <input.jsonl> <output.jsonl> --format sharegpt")
        print("\n示例:")
        print("  python convert_to_sft.py all_consistent.jsonl train_data.jsonl")
        print("  python convert_to_sft.py all_consistent.jsonl train_data.jsonl --format sharegpt")
        sys.exit(1)
    
    main()