"""
fix_audit_tasks_v2.py
──────────────────────
修复 audit_fixed.jsonl 中 task 字段的冗余问题。

新增功能：
  1. 多线程并发：加快 API 调用速度。
  2. 断点保护：定期保存中间结果到临时文件。
  3. 参数化输出：支持 --output, --batch-save, --max-workers。

用法：
  python src/fix_audit_tasks_v2.py --input your_file.jsonl --max-workers 20 --batch-save 50
"""

from __future__ import annotations

import os
import sys
import json
import argparse
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock

# ── 提示词配置 ─────────────────────────────────────────────────────────────────
_TASK_PROMPT = """\
请用一句话（不超过80字）概括以下消息的核心操作意图。只描述用户声称要做什么。只输出意图描述，不要解释。
消息内容：
{content}"""

# ── 路径与环境变量 ─────────────────────────────────────────────────────────────
current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.dirname(current_dir)
for p in (current_dir, project_root):
    if p not in sys.path:
        sys.path.insert(0, p)

env_path = os.path.join(project_root, ".env")
if os.path.exists(env_path):
    try:
        from dotenv import load_dotenv
        load_dotenv(env_path, override=False)
    except ImportError:
        pass

# ─────────────────────────────────────────────────────────────────────────────
# API 客户端与工具函数
# ─────────────────────────────────────────────────────────────────────────────
def _make_api_client():
    try:
        from openai import OpenAI
    except ImportError:
        print("[ERROR] 缺少 openai 包")
        return None, None

    api_key = os.getenv("API_KEY")
    if not api_key:
        print("[ERROR] 环境变量 API_KEY 未设置")
        return None, None

    base_url = os.getenv("BASE_URL")
    model = os.getenv("MODEL", "qwen-plus")
    client = OpenAI(api_key=api_key, base_url=base_url if base_url else None)
    return client, model

def trace_needs_fix(trace_events: list[dict]) -> bool:
    """判断该 trace 的 task 是否需要修复"""
    user_event = next((e for e in trace_events if e.get("sender") == "User"), None)
    if not user_event: return False
    
    task, content = user_event.get("task", ""), user_event.get("content", "")
    if not task or task.endswith("...") or task == content:
        return True
    return False

def call_api_for_task(user_content: str, client, model: str) -> str:
    """单个 API 请求封装"""
    prompt = _TASK_PROMPT.format(content=user_content)
    try:
        resp = client.chat.completions.create(
            model=model,
            temperature=0.3,
            max_tokens=100,
            messages=[{"role": "user", "content": prompt}],
            timeout=30  # 防止死锁
        )
        return (resp.choices[0].message.content or "").strip().replace("\n", " ")
    except Exception:
        return ""

# ─────────────────────────────────────────────────────────────────────────────
# 主流程
# ─────────────────────────────────────────────────────────────────────────────
def main() -> int:
    parser = argparse.ArgumentParser(description="多线程修复 task 字段并具备断点保护")
    parser.add_argument("--input", required=True, help="输入 JSONL 路径")
    parser.add_argument("--output", default=None, help="输出路径（默认覆盖原文件）")
    parser.add_argument("--model", default=os.getenv("MODEL", "qwen-plus"))
    parser.add_argument("--max-workers", type=int, default=10, help="并发线程数")
    parser.add_argument("--batch-save", type=int, default=100, help="每修复多少条 Trace 保存一次中间进度")
    args = parser.parse_args()

    client, env_model = _make_api_client()
    if not client: return 1
    model = args.model or env_model

    in_path = Path(args.input)
    out_path = Path(args.output) if args.output else in_path
    tmp_path = out_path.with_suffix(".jsonl.tmp")

    # 1. 读取数据并分组
    print(f"[*] 正在读取文件: {in_path}")
    records = []
    with open(in_path, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip(): records.append(json.loads(line))

    traces = {}
    for r in records:
        traces.setdefault(r["trace_id"], []).append(r)

    fix_trace_ids = [tid for tid, events in traces.items() if trace_needs_fix(events)]
    total_to_fix = len(fix_trace_ids)
    print(f"[OK] 发现 {len(traces)} 个 Trace，其中 {total_to_fix} 个需要修复。")

    if total_to_fix == 0:
        print("所有 task 均已修复，无需处理。")
        return 0

    # 2. 多线程执行修复
    print(f"[*] 开始多线程修复 (线程数: {args.max_workers}, 保存间隔: {args.batch_save})...")
    
    fixed_count = 0
    save_lock = Lock() # 用于确保写文件时的线程安全（虽然这里是主线程写，但养成习惯）

    def save_checkpoint():
        """将当前内存状态写入临时文件"""
        with open(tmp_path, "w", encoding="utf-8") as tf:
            for r in records:
                tf.write(json.dumps(r, ensure_ascii=False) + "\n")
        print(f"  [Checkpoint] 进度已保存至: {tmp_path.name}")

    with ThreadPoolExecutor(max_workers=args.max_workers) as executor:
        # 创建任务映射
        future_to_tid = {}
        for tid in fix_trace_ids:
            user_content = next(e["content"] for e in traces[tid] if e["sender"] == "User")
            future = executor.submit(call_api_for_task, user_content, client, model)
            future_to_tid[future] = tid

        # 迭代处理完成的结果
        for future in as_completed(future_to_tid):
            tid = future_to_tid[future]
            new_task = future.result()
            
            if new_task:
                # 成功获取新 task，更新该 trace 下所有 record
                for e in traces[tid]:
                    e["task"] = new_task
                fixed_count += 1
            
            # 进度打印与断点保存逻辑
            if fixed_count % 10 == 0:
                print(f"进度: {fixed_count}/{total_to_fix} ...")
            
            if fixed_count % args.batch_save == 0:
                save_checkpoint()

    # 3. 最终写入
    print(f"[*] 修复完成，正在写入最终文件: {out_path}")
    with open(out_path, "w", encoding="utf-8") as f:
        for r in records:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")

    if tmp_path.exists():
        tmp_path.unlink() # 删除临时文件

    print(f"✅ 处理完毕！成功修复 {fixed_count} 个 Trace。")
    return 0

if __name__ == "__main__":
    sys.exit(main())