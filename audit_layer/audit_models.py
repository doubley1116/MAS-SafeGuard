"""
audit_models.py — AuditEvent / AuditDecision 数据模型

与框架无关，SecurityCore、适配器、测试代码统一从这里 import。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, Literal, Dict, Any, List
import uuid


@dataclass
class AuditEvent:
    """
    审核事件数据模型
    统一表示多智能体系统中的通信、工具调用、状态变更等事件
    """
    # ══ 规则引擎直接读取的核心字段 ══════════════════════════════════════════
    event_type: Literal[
        "message",          # Agent 间消息传递
        "tool_call",        # 工具调用
        "tool_result",      # 工具执行结果
        "task_delegation",  # 任务委派（如 CrewAI 任务分配）
    ]
    sender: str                      # 发送方 Agent 名称，权限验证的主体
    receiver: Optional[str]          # 接收方 Agent 名称，工具调用时为 None

    tool_name: Optional[str]         # 工具名称，仅在 event_type="tool_call" 时有效
    tool_args: Optional[Dict[str, Any]] = None  # 工具参数，用于参数级风险检查

    call_path: List[str] = field(default_factory=list)
    # 本次会话的完整调用路径，用于检测路径绕过攻击
    # 示例：["Account_Manager", "Research_Agent", "Risk_Agent", "Trade_Agent"]
    # 规则引擎通过检查 "Risk_Agent" in call_path 来确保风控节点未被绕过

    # ══ LLM 引擎语义分析所需字段（规则引擎 0.4 < score < 0.9 时触发）══════════
    content: Optional[str] = None   # 消息正文，用于语义判断的主要输入

    history_summary: str = ""
    # 本次对话最近 n 条消息的摘要，帮助 LLM 理解上下文
    # 无此字段：LLM 看到"买入NVDA"可能误判为正常操作
    # 有此字段：LLM 能看到上下文中"风控默认通过"等暗示性内容

    task: str = ""
    # 用户原始任务的核心意图（一句话，≤80字符）
    # 由 adapter 的 set_user_task() 在工作流启动时提取
    # 每条 AuditEvent 都携带，作为意图一致性检测的锚点
    # 审核模型通过对比 task 与 content/tool_args 检测意图偏移和参数篡改
    # 示例："将SKU-002价格改为5元" / "分析客户C001的TSLA持仓"

    # ══ 事件追踪字段（用于审计日志系统）════════════════════════════════════════
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    # 单个事件的唯一标识符，用于日志去重、关联等操作

    trace_id: str = ""
    # 调用链追踪 ID，将同一次对话的所有事件串联起来
    # 便于完整回溯一次会话的全过程

    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    # 事件发生时间戳，用于时序分析、SLA 监控等

    # ══ 框架特定元数据（SecurityCore 不读取，仅供调试和适配器使用）══════════════
    metadata: Dict[str, Any] = field(default_factory=dict)
    # 存储框架特定的原始上下文信息
    # 如：AutoGen 的 message 对象、LangGraph 的 state 对象、CrewAI 的 task 对象等
    # 用于调试、适配器兼容性等，不影响安全决策


@dataclass
class AuditDecision:
    """
    审核决策结果模型
    由审核系统返回，决定是否允许事件继续执行
    """
    allow: bool          # 是否允许事件执行
    risk_score: float    # 风险评分 0.0 ~ 1.0，用于分级处理
    reason: str          # 决策原因，用于审计和调试

    rewrite: Optional[str] = None
    # 改写后的内容，用于脱敏或规范化（预留）

    blocking_risk_types: List[str] = field(default_factory=list)
    # 导致阻断的风险类型列表
    # 示例：["unauthorized_tool_caller", "missing_required_path_node"]

    suggested_alternative: Optional[str] = None
    # 建议的替代操作，供上层系统或用户参考
    trajectory_score: Optional[float] = None
    # 轨迹检测模型给出的风险分
    # None 表示轨迹检测未触发（trace 长度不足 3 条）
    # 最终 risk_score = α × llm_score + (1-α) × trajectory_score