from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path
from typing import Protocol

from audit_models import AuditEvent


class WorkflowBlocked(Exception):
    """
    当 SecurityCore 判定不允许时，抛出此异常以中断工作流
    """
    def __init__(self, message: str, decision=None, event: AuditEvent = None) -> None:
        super().__init__(message)
        self.decision = decision
        self.event = event


class AuditSink(Protocol):
    """
    审计事件输出接口
    Adapter 只负责构造 AuditEvent，输出去哪里由 Sink 决定
    """
    def emit(self, event: AuditEvent) -> None:
        ...


class PrintAuditSink:
    """
    直接打印到控制台
    """
    def emit(self, event: AuditEvent) -> None:
        print("[AUDIT]", json.dumps(asdict(event), ensure_ascii=False, default=str))


class JsonlAuditSink:
    """
    以 JSONL 形式写入文件，一行一个 AuditEvent
    """
    def __init__(self, file_path: str = "database/audit_log.jsonl") -> None:
        self.file_path = Path(file_path)
        self.file_path.parent.mkdir(parents=True, exist_ok=True)

    def emit(self, event: AuditEvent) -> None:
        with self.file_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(asdict(event), ensure_ascii=False, default=str) + "\n")


class CompositeAuditSink:
    """
    同时输出到多个 sink
    例如：控制台 + JSONL 文件 + SecurityCore
    """
    def __init__(self, *sinks: AuditSink) -> None:
        self.sinks = sinks

    def emit(self, event: AuditEvent) -> None:
        for sink in self.sinks:
            try:
                sink.emit(event)
            except WorkflowBlocked:
                # 安全阻断异常必须继续向上抛，不能吞掉
                raise
            except Exception as e:
                print(f"[AUDIT_SINK_ERROR] sink={sink.__class__.__name__} error={e}")


class SecurityCoreSink:
    """
    对接 SecurityCore
    调用 security_core.handle_event(event) 获取决策
    若 allow=False，则直接抛出 WorkflowBlocked 中断工作流
    """
    def __init__(self, security_core) -> None:
        self.security_core = security_core

    def emit(self, event: AuditEvent) -> None:
        decision = self.security_core.handle_event(event)

        if event.metadata is None:
            event.metadata = {}

        event.metadata["security_decision"] = {
            "allow": decision.allow,
            "risk_score": decision.risk_score,
            "reason": decision.reason,
            "blocking_risk_types": decision.blocking_risk_types,
            "suggested_alternative": decision.suggested_alternative
        }

        if not decision.allow:
            raise WorkflowBlocked(
                message=f"SecurityCore 阻断工作流: {decision.reason}",
                decision=decision,
                event=event
            )
