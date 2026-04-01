# audit_sink.py
from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path
from typing import Protocol, Any

import os
import sys
REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from audit_layer.audit_models import AuditEvent, AuditDecision


class WorkflowBlocked(Exception):
    """SecurityCore 判定拦截时抛出，用于短路整个工作流"""
    def __init__(self, reason: str = "", decision: Any = None):
        super().__init__(reason)
        self.decision = decision


class AuditSink(Protocol):
    """审计事件输出接口"""
    def emit(self, event: AuditEvent) -> None:
        ...


class PrintAuditSink:
    """直接打印到控制台"""
    def emit(self, event: AuditEvent) -> None:
        print("[AUDIT]", json.dumps(asdict(event), ensure_ascii=False))


class JsonlAuditSink:
    """以 JSONL 形式写入文件"""
    def __init__(self, file_path: str = "database/audit_log.jsonl") -> None:
        self.file_path = Path(file_path)
        self.file_path.parent.mkdir(parents=True, exist_ok=True)

    def emit(self, event: AuditEvent) -> None:
        with self.file_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(asdict(event), ensure_ascii=False) + "\n")


class CompositeAuditSink:
    """同时输出到多个 sink。即使其中一个 sink 触发阻断，也会先把事件写到其余 sink。"""
    def __init__(self, *sinks: AuditSink) -> None:
        self.sinks = sinks

    def emit(self, event: AuditEvent) -> None:
        blocked_exc: WorkflowBlocked | None = None
        for sink in self.sinks:
            try:
                sink.emit(event)
            except WorkflowBlocked as exc:
                blocked_exc = exc
        if blocked_exc is not None:
            raise blocked_exc


class SecurityCoreSink:
    """
    对接 SecurityCore，审核每个事件。
    若 SecurityCore 判定拦截（allow=False），设置 blocked 标志并抛出 WorkflowBlocked。
    """
    def __init__(self, security_core) -> None:
        self.security_core = security_core
        self.blocked: bool = False
        self.blocked_reason: str = ""
        self.blocked_event: AuditEvent | None = None
        self.blocked_decision: AuditDecision | None = None

    def emit(self, event: AuditEvent) -> None:
        decision = self.security_core.handle_event(event)

        # 将 security_decision 写入 event.metadata
        if decision is not None:
            event.metadata = event.metadata or {}
            event.metadata["security_decision"] = {
                "allow": getattr(decision, "allow", None),
                "risk_score": getattr(decision, "risk_score", None),
                "reason": getattr(decision, "reason", None),
                "blocking_risk_types": getattr(decision, "blocking_risk_types", None),
            }

        if decision is not None and not getattr(decision, "allow", True):
            self.blocked = True
            self.blocked_reason = getattr(decision, "reason", "SecurityCore 拦截")
            self.blocked_event = event
            self.blocked_decision = decision
            raise WorkflowBlocked(self.blocked_reason, decision)

    def reset(self) -> None:
        self.blocked = False
        self.blocked_reason = ""
        self.blocked_event = None
        self.blocked_decision = None

    def is_blocked(self) -> bool:
        return self.blocked
