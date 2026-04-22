#!/usr/bin/env python3
"""
fix_audit_labels.py
───────────────────
补充 audit.jsonl 中缺失或硬编码的 label / reason。

针对以下三类问题记录重新调用 API 盲审：
  1. reason == ""（空字符串，通常是 API 未初始化导致）
  2. reason == "检测到潜在攻击行为"（trace_generator 的异常 fallback）
  3. label == ""（空 label）

复用 free_form_generator 的 _AUDITOR_PROMPT 做盲审（不告知攻击类型），
content 放宽到 800 字，让 LLM 基于更完整的上下文做判断。

注意：intent=attack 但 label=normal 是正常情况（攻击骗过了盲审 API），
因此 API 失败时不应根据 intent 回退 label，而是尽量保留原值。

用法：
  cd AuditDataGen
  python src/fix_audit_labels.py --input output_trace_real/audit.jsonl
  
环境变量（与生成脚本一致）：
  API_KEY  - API 密钥
  BASE_URL - API 基础 URL（可选）
  MODEL    - 模型名称（默认 qwen-plus）
"""

from __future__ import annotations

import os
import sys
import json
import argparse
from pathlib import Path

# ── 路径设置 ──────────────────────────────────────────────────────────────────
current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.dirname(current_dir)
for p in (current_dir, project_root):
    if p not in sys.path:
        sys.path.insert(0, p)

from free_form_generator import SYSTEM_TOPOLOGIES, _AUDITOR_PROMPT


# ─────────────────────────────────────────────────────────────────────────────
# API 客户端
# ─────────────────────────────────────────────────────────────────────────────

def _make_api_client():
    try:
        from openai import OpenAI
    except ImportError:
        print("[ERROR] 缺少 openai 包，请 pip install openai")
        return None, None

    api_key = os.getenv("API_KEY")
    if not api_key:
        print("[ERROR] 环境变量 API_KEY 未设置")
        return None, None

    base_url = os.getenv("BASE_URL")
    model = os.getenv("MODEL", "qwen-plus")
    client = OpenAI(api_key=api_key, base_url=base_url if base_url else None)
    return client, model


# ─────────────────────────────────────────────────────────────────────────────
# 判断是否需要修复
# ─────────────────────────────────────────────────────────────────────────────

def needs_fix(event: dict) -> bool:
    ad = event.get("metadata", {}).get("audit_decision", {})
    label = ad.get("label", "")
    reason = ad.get("reason", "")
    return label == "" or reason == "" or reason == "检测到潜在攻击行为"


# ─────────────────────────────────────────────────────────────────────────────
# 构建 auditor prompt
# ─────────────────────────────────────────────────────────────────────────────

def _build_auditor_prompt_for_event(event: dict) -> str:
    meta = event.get("metadata", {})
    domain = meta.get("domain", "financial")
    sender = event.get("sender", "")
    receiver = event.get("receiver", "")
    event_type = event.get("event_type", "")
    content = event.get("content") or ""
    tool_args = event.get("tool_args")

    topo = SYSTEM_TOPOLOGIES.get(domain, SYSTEM_TOPOLOGIES["financial"])
    agent_list = "\n".join(f"  - {name}: {desc}" for name, desc in topo["agents"].items())

    content_snippet = content[:800] if content else ""
    tool_args_str = json.dumps(tool_args, ensure_ascii=False) if tool_args else "无"

    return _AUDITOR_PROMPT.format(
        system_name=topo["name"],
        agent_list=agent_list,
        protected_ops=topo["protected_ops"],
        sender=sender,
        receiver=receiver,
        event_type=event_type,
        content=content_snippet,
        tool_args=tool_args_str,
    )


# ─────────────────────────────────────────────────────────────────────────────
# 单条事件审计
# ─────────────────────────────────────────────────────────────────────────────

def audit_event(event: dict, client, model: str) -> tuple[str, str]:
    """
    调用 API 重新盲审，返回 (label, reason)。
    失败时尽量保留原 label，不做 intent 推断。
    """
    old_ad = event.get("metadata", {}).get("audit_decision", {})
    old_label = old_ad.get("label", "")
    old_reason = old_ad.get("reason", "")

    prompt = _build_auditor_prompt_for_event(event)

    try:
        resp = client.chat.completions.create(
            model=model,
            temperature=0.3,
            max_tokens=300,
            messages=[{"role": "user", "content": prompt}],
        )
        raw = (resp.choices[0].message.content or "").strip()

        if raw.startswith("```"):
            raw = raw.split("```")[1].lstrip("json").strip()

        parsed = json.loads(raw)
        label = parsed.get("label", "").strip()
        reason = parsed.get("reason", "").strip()

        return label, reason

    except json.JSONDecodeError:
        # 解析失败：保持 label / reason 为空，等待下次重跑
        return "", ""

    except Exception as e:
        print(f"  [WARN] API 调用失败: {e}")
        # API 异常：保持 label / reason 为空
        return "", ""


# ─────────────────────────────────────────────────────────────────────────────
# 主流程
# ─────────────────────────────────────────────────────────────────────────────

def main() -> int:
    parser = argparse.ArgumentParser(
        description="补充 audit.jsonl 中缺失或硬编码的 label / reason",
    )
    parser.add_argument("--input", default="output_trace_real/audit.jsonl")
    parser.add_argument("--output", default=None, help="输出路径（默认覆盖输入文件）")
    parser.add_argument("--model", default=os.getenv("MODEL", "qwen-plus"))
    parser.add_argument("--batch-save", type=int, default=100)
    args = parser.parse_args()

    client, env_model = _make_api_client()
    if client is None:
        print("[ERROR] API 客户端初始化失败")
        return 1

    model = args.model or env_model or "qwen-plus"
    print(f"[OK] API 就绪，模型: {model}")

    in_path = Path(args.input)
    out_path = Path(args.output) if args.output else in_path
    tmp_path = out_path.with_suffix(".jsonl.tmp")

    if not in_path.exists():
        print(f"[ERROR] 输入文件不存在: {in_path}")
        return 1

    records = []
    with open(in_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                records.append(json.loads(line))

    total = len(records)
    fix_indices = [i for i, r in enumerate(records) if needs_fix(r)]
    need_fix = len(fix_indices)
    print(f"共 {total} 条，需修复 {need_fix} 条")
    if need_fix == 0:
        return 0

    fixed = 0
    for idx in fix_indices:
        rec = records[idx]
        label, reason = audit_event(rec, client, model)
        rec["metadata"]["audit_decision"]["label"] = label
        rec["metadata"]["audit_decision"]["reason"] = reason
        fixed += 1

        if fixed % 10 == 0 or fixed == need_fix:
            print(f"  已修复 {fixed}/{need_fix} ...")

        if fixed % args.batch_save == 0:
            with open(tmp_path, "w", encoding="utf-8") as f:
                for r in records:
                    f.write(json.dumps(r, ensure_ascii=False) + "\n")
            print(f"  [中间保存] {tmp_path}")

    with open(out_path, "w", encoding="utf-8") as f:
        for r in records:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")

    if tmp_path.exists():
        tmp_path.unlink()

    print(f"✅ 完成，已写入 {out_path}（修复 {fixed} 条）")
    return 0


if __name__ == "__main__":
    sys.exit(main())
