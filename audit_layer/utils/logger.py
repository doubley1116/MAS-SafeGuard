"""
utils/logger.py — AuditDecision 日志记录器

同时写三个目标：
  1. 控制台（带颜色，方便开发调试）
  2. JSON Lines 文件（每行一条记录，方便后续分析和 replay）
  3. 纯文本 .log 文件（人可直接阅读，方便排查问题）

使用方式：
    from utils.logger import AuditLogger

    logger = AuditLogger(log_dir="logs")   # 自动生成 audit.jsonl 和 audit.log
    logger.log(event, decision)
"""

from __future__ import annotations

import json
import logging
import os
import sys
from dataclasses import asdict
from datetime import datetime, timezone
from typing import Optional

from audit_models import AuditEvent, AuditDecision


# ══════════════════════════════════════════════════════════════
# 控制台颜色（Windows / Unix 兼容）
# ══════════════════════════════════════════════════════════════

class _Color:
    RED    = "\033[91m"
    YELLOW = "\033[93m"
    GREEN  = "\033[92m"
    CYAN   = "\033[96m"
    RESET  = "\033[0m"

    @classmethod
    def disable(cls):
        cls.RED = cls.YELLOW = cls.GREEN = cls.CYAN = cls.RESET = ""


# Windows 默认终端不支持 ANSI，尝试启用；失败则关闭颜色
if sys.platform == "win32":
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32
        kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
    except Exception:
        _Color.disable()


# ══════════════════════════════════════════════════════════════
# AuditLogger
# ══════════════════════════════════════════════════════════════

class AuditLogger:
    """
    AuditDecision 日志记录器。

    参数：
      log_dir    : 日志目录，默认 logs/
                   自动在该目录下生成 audit.jsonl 和 audit.log
                   传 None 则只输出控制台，不写文件
      console    : 是否输出到控制台，默认 True
      min_score  : 只记录 risk_score >= 此值的事件，默认 0.0（全部记录）
    """

    def __init__(
        self,
        log_dir: Optional[str] = "logs",
        console: bool = True,
        min_score: float = 0.0,
    ):
        self.min_score = min_score
        self.console   = console

        if log_dir:
            os.makedirs(log_dir, exist_ok=True)
            self._jsonl_file = open(os.path.join(log_dir, "audit.jsonl"), "a", encoding="utf-8")
            self._log_file   = open(os.path.join(log_dir, "audit.log"),   "a", encoding="utf-8")
        else:
            self._jsonl_file = None
            self._log_file   = None

        # 用标准 logging 模块处理控制台格式
        self._logger = logging.getLogger("audit")
        if not self._logger.handlers:
            handler = logging.StreamHandler(sys.stdout)
            handler.setFormatter(logging.Formatter("%(message)s"))
            self._logger.addHandler(handler)
        self._logger.setLevel(logging.DEBUG)
        self._logger.propagate = False

    # ── 主入口 ────────────────────────────────────────────────

    def log(self, event: AuditEvent, decision: AuditDecision) -> None:
        """记录一条审核决策，同时写控制台和文件。"""
        if decision.risk_score < self.min_score:
            return

        record = self._build_record(event, decision)

        if self.console:
            self._print_console(record, decision)

        if self._jsonl_file:
            self._jsonl_file.write(json.dumps(record, ensure_ascii=False) + "\n")
            self._jsonl_file.flush()

        if self._log_file:
            self._log_file.write(self._format_log(record, decision) + "\n")
            self._log_file.flush()

    # ── 构建日志记录 ──────────────────────────────────────────

    def _build_record(self, event: AuditEvent, decision: AuditDecision) -> dict:
        return {
            "timestamp"           : datetime.now(timezone.utc).isoformat(),
            "trace_id"            : event.trace_id,
            "event_id"            : event.event_id,
            # 事件信息
            "event_type"          : event.event_type,
            "sender"              : event.sender,
            "receiver"            : event.receiver,
            "tool_name"           : event.tool_name,
            "tool_args"           : event.tool_args,
            "call_path"           : event.call_path,
            # 决策结果
            "allow"               : decision.allow,
            "risk_score"          : round(decision.risk_score, 4),
            "reason"              : decision.reason,
            "blocking_risk_types" : decision.blocking_risk_types,
            "suggested_alternative": decision.suggested_alternative,
        }

    # ── .log 文本格式化 ──────────────────────────────────────

    def _format_log(self, record: dict, decision: AuditDecision) -> str:
        if not decision.allow and decision.risk_score >= 0.90:
            tag = "BLOCK "
        elif not decision.allow:
            tag = "REVIEW"
        elif decision.risk_score >= 0.40:
            tag = "LLM   "
        else:
            tag = "PASS  "

        ts     = record["timestamp"][:19].replace("T", " ")
        sender = record["sender"]
        tool   = record["tool_name"] or record["event_type"]
        score  = record["risk_score"]
        reason = record["reason"]

        lines = [
            f"[{tag}] {ts} | {sender:<18} | {tool:<22} | score={score:.2f}",
            f"        reason : {reason}",
        ]
        if decision.blocking_risk_types:
            lines.append(f"        risks  : {decision.blocking_risk_types}")
        if decision.suggested_alternative:
            lines.append(f"        suggest: {decision.suggested_alternative}")
        lines.append("")   # 每条记录后空一行，方便阅读

        return "\n".join(lines)

    # ── 控制台格式化输出 ──────────────────────────────────────

    def _print_console(self, record: dict, decision: AuditDecision) -> None:
        c = _Color

        # 根据决策结果选颜色和标签
        if not decision.allow and decision.risk_score >= 0.90:
            color, tag = c.RED,    "BLOCK "
        elif not decision.allow:
            color, tag = c.YELLOW, "REVIEW"
        elif decision.risk_score >= 0.40:
            color, tag = c.CYAN,   "LLM   "
        else:
            color, tag = c.GREEN,  "PASS  "

        ts        = record["timestamp"][11:19]          # HH:MM:SS
        sender    = record["sender"]
        tool      = record["tool_name"] or record["event_type"]
        score     = record["risk_score"]
        reason    = record["reason"][:80]

        self._logger.info(
            f"{color}[{tag}]{c.RESET} "
            f"{ts} | {sender:<18} | {tool:<22} | score={score:.2f} | {reason}"
        )

        if decision.blocking_risk_types:
            self._logger.info(
                f"         risks : {decision.blocking_risk_types}"
            )
        if decision.suggested_alternative:
            self._logger.info(
                f"         {c.YELLOW}suggest: {decision.suggested_alternative}{c.RESET}"
            )

    # ── 关闭文件 ──────────────────────────────────────────────

    def close(self) -> None:
        if self._jsonl_file:
            self._jsonl_file.close()
        if self._log_file:
            self._log_file.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()