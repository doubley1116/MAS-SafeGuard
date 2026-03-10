"""
autogen_adapter.py - AutoGen框架的审计适配器

负责监控AutoGen框架中的消息传递和工具调用，转换为标准AuditEvent格式
"""

from __future__ import annotations

import functools
import json
from typing import Optional, Dict, Any, List, Callable
from audit_models import AuditEvent


class AutoGenAuditAdapter:
    """
    AutoGen框架的审计适配器
    
    负责：
    - 监控Agent间的消息传递
    - 监控工具调用和执行
    - 转换为标准AuditEvent格式
    
    不负责：
    - 权限决策
    - 策略判断
    - 拦截执行
    """
    
    def __init__(self, trace_id: str = ""):
        self.trace_id = trace_id
        self.call_path: List[str] = []
        self.message_history: List[str] = []
        
    def sanitize_payload(self, payload: Any) -> Any:
        """递归净化数据，防止复杂对象导致JSON序列化崩溃"""
        if isinstance(payload, (str, int, float, bool, type(None))):
            return payload
        elif isinstance(payload, dict):
            return {str(k): self.sanitize_payload(v) for k, v in payload.items()}
        elif isinstance(payload, list):
            return [self.sanitize_payload(item) for item in payload]
        else:
            return f"<Object: {type(payload).__name__}>"
    
    def get_history_summary(self, max_messages: int = 5) -> str:
        """获取最近消息的摘要"""
        recent_messages = self.message_history[-max_messages:]
        return " | ".join(recent_messages) if recent_messages else ""
    
    def emit_message(self, 
                     sender: str, 
                     receiver: str, 
                     content: str,
                     metadata: Optional[Dict[str, Any]] = None) -> AuditEvent:
        """发送消息事件"""
        
        # 更新调用路径
        if sender not in self.call_path:
            self.call_path.append(sender)
        
        # 更新消息历史
        self.message_history.append(f"{sender}->{receiver}: {content[:50]}...")
        
        event = AuditEvent(
            event_type="message",
            sender=sender,
            receiver=receiver,
            tool_name=None,
            tool_args=None,
            call_path=self.call_path.copy(),
            content=content,
            history_summary=self.get_history_summary(),
            trace_id=self.trace_id,
            metadata=metadata or {}
        )
        
        self.print_audit(event, f"消息监控 ({sender} -> {receiver})")
        return event
    
    def emit_tool_call(self,
                       sender: str,
                       tool_name: str,
                       tool_args: Optional[Dict[str, Any]] = None,
                       content: Optional[str] = None,
                       metadata: Optional[Dict[str, Any]] = None) -> AuditEvent:
        """发送工具调用事件"""
        
        # 净化工具参数
        clean_args = self.sanitize_payload(tool_args or {})
        
        event = AuditEvent(
            event_type="tool_call",
            sender=sender,
            receiver=None,
            tool_name=tool_name,
            tool_args=clean_args,
            call_path=self.call_path.copy(),
            content=content,
            history_summary=self.get_history_summary(),
            trace_id=self.trace_id,
            metadata=metadata or {}
        )
        
        self.print_audit(event, f"工具调用监控 ({sender} -> {tool_name})")
        return event
    
    def emit_tool_result(self,
                         sender: str,
                         tool_name: str,
                         result: Any,
                         metadata: Optional[Dict[str, Any]] = None) -> AuditEvent:
        """发送工具执行结果事件"""
        
        event = AuditEvent(
            event_type="tool_result",
            sender=sender,
            receiver=None,
            tool_name=tool_name,
            tool_args=None,
            call_path=self.call_path.copy(),
            content=str(result),
            history_summary=self.get_history_summary(),
            trace_id=self.trace_id,
            metadata=metadata or {}
        )
        
        self.print_audit(event, f"工具结果监控 ({sender} -> {tool_name})")
        return event
    
    def print_audit(self, event: AuditEvent, prefix: str):
        """将标准化事件输出到终端"""
        print(f"\n[ 审计系统 | {prefix} ] ->")
        print(f"事件类型: {event.event_type}")
        print(f"发送方: {event.sender}")
        if event.receiver:
            print(f"接收方: {event.receiver}")
        if event.tool_name:
            print(f"工具名称: {event.tool_name}")
        if event.tool_args:
            print(f"工具参数: {json.dumps(event.tool_args, indent=2, ensure_ascii=False)}")
        if event.content:
            print(f"内容: {event.content[:200]}...")
        if event.call_path:
            print(f"调用路径: {' -> '.join(event.call_path)}")
        print("-" * 50)


def audit_tool_execution(func: Callable) -> Callable:
    """用于拦截工具调用的装饰器"""
    
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        # 获取工具名称和参数
        tool_name = func.__name__
        
        # 创建适配器实例
        adapter = AutoGenAuditAdapter(trace_id="tool_call_audit")
        
        # 发送工具调用事件
        adapter.emit_tool_call(
            sender="Agent",
            tool_name=tool_name,
            tool_args=kwargs
        )
        
        # 执行原始函数
        result = func(*args, **kwargs)
        
        # 发送工具结果事件
        adapter.emit_tool_result(
            sender="Agent",
            tool_name=tool_name,
            result=result
        )
        
        return result
    
    return wrapper


def create_audited_agent_wrapper(agent, adapter: AutoGenAuditAdapter):
    """创建带审计功能的Agent包装器"""
    
    def audited_reply_function(messages, sender, config):
        # 获取最后一条消息
        if messages:
            last_message = messages[-1]
            content = getattr(last_message, 'content', str(last_message))
            
            # 发送消息事件
            adapter.emit_message(
                sender=sender.name if hasattr(sender, 'name') else str(sender),
                receiver=agent.name if hasattr(agent, 'name') else str(agent),
                content=content
            )
        
        # 调用原始回复函数
        result = agent._reply_func(messages, sender, config)
        
        return result
    
    return audited_reply_function