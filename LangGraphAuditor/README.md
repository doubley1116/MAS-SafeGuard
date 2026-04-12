# LangGraphAuditor

Zero-trust auditing framework for LangGraph multi-agent workflows.

LangGraphAuditor provides seamless policy-based access control for LangGraph state graphs, enabling automatic audit trails, security review gates, and compliance logging for agent-to-agent communication and tool invocation.

## Comparison with AutoGenAuditor

| Component | AutoGenAuditor | LangGraphAuditor |
|-----------|----------------|------------------|
| Adapter Class | AutoGenAuditAdapter | LangGraphAuditAdapter |
| Graph Wrapper | AuditedGroupChatManager | AuditedGraph |
| Tool Decorator | @audited_tool (same) | @audited_tool (same) |
| Policy Key | agents: | nodes: |

## Quick Start

### 1. Install Dependencies

```bash
cd LangGraphAuditor
pip install -r requirements.txt
```

### 2. Configure Environment

```bash
cp .env.template .env
# Edit .env and add your API credentials:
# API_KEY=your_key
# BASE_URL=your_base_url
# MODEL=your_model
```

### 3. Write Security Policy

```bash
cp policy.yaml.template policy.yaml
# Edit policy.yaml with your nodes, tools, and access paths
```

### 4. Run Example

```bash
python example.py
```

## Core Usage

### Step 1: Create Audit Adapter

```python
from langgraph_adapter import LangGraphAuditAdapter

adapter = LangGraphAuditAdapter(
    yaml_path="policy.yaml",
    jsonl_path="audit_logs/audit_log.jsonl",
    workflow_dir="audit_logs/workflows",
)
```

### Step 2: Decorate Tools with Audit

```python
from audit_tool import audited_tool

@audited_tool(adapter=adapter, sender="Stats_Node", tool_name="stats_query_tool")
def stats_query_tool(merchant_id: str) -> str:
    return f"Stats for merchant {merchant_id}"
```

### Step 3: Build LangGraph

```python
from langgraph.graph import StateGraph, START, END
from langgraph.prebuilt import ToolNode
from typing import TypedDict, Annotated
from langgraph.graph.message import add_messages

class State(TypedDict):
    messages: Annotated[list, add_messages]

builder = StateGraph(State)
builder.add_node("Stats_Node", stats_node)
builder.add_node("tools", ToolNode([stats_query_tool]))
builder.add_edge(START, "Stats_Node")
builder.add_edge("tools", END)

graph = builder.compile()
```

### Step 4: Wrap with AuditedGraph

```python
from audited_graph import AuditedGraph

audited_graph = AuditedGraph(graph=graph, audit_adapter=adapter)
```

### Step 5: Execute with Audit Tracking

```python
import uuid

trace_id = str(uuid.uuid4())
audited_graph.set_scene_info(scene_name="query_stats", trace_id=trace_id)

result = audited_graph.invoke({
    "messages": [HumanMessage(content="Query merchant M001")]
})

adapter.finalize_workflow()
```

## policy.yaml Format

The policy file defines security rules using a `nodes:` key (equivalent to `agents:` in AutoGenAuditor):

```yaml
version: "2.0"
description: "E-commerce Zero-Trust Policy"

nodes:
  UserNode:
    role: user_node
    can_initiate: true
    allowed_tools: []
    blocked_tools: []

  Stats_Node:
    role: stats_node
    can_initiate: false
    allowed_tools:
      - stats_query_tool
    blocked_tools:
      - config_update_tool

tools:
  stats_query_tool:
    allowed_callers:
      - Stats_Node
    required_path_contains: []
    path_rule: valid_stats_path

paths:
  valid_stats_path:
    sequence:
      - UserNode
      - Stats_Node
    strict: false

thresholds:
  rule_block: 0.90
  human_review: 0.75
```

## Audit Log Location

Audit events are saved to:

- **Event Log**: `audit_logs/audit_log.jsonl` — line-delimited JSON events
- **Workflow Traces**: `audit_logs/workflows/` — per-workflow decision traces and call sequences

## Security Review Flow

```
User Request
    ↓
[AuditedGraph.invoke()]
    ↓
Tool Call → [LangGraphAuditAdapter.emit_tool_call()]
    ↓
    ├─→ Check: workflow blocked?
    │       └─→ YES: Return BLOCKED_WORKFLOW_MESSAGE
    │
    ├─→ Check: caller allowed for this tool?
    │
    ├─→ Run SecurityCore policy engine
    │       ├─→ Rule score ≥ 0.90: BLOCK
    │       └─→ Rule score < 0.90: Send to LLM review
    │           ├─→ LLM score ≥ 0.75: HUMAN_REVIEW
    │           └─→ LLM score < 0.75: ALLOW
    │
    ├─→ If blocked: raise WorkflowBlocked
    └─→ If allowed: continue execution
        ↓
    Execute Tool Function
        ↓
    Tool Result → [LangGraphAuditAdapter.emit_tool_result()]
        ↓
    Return to Caller
```

## Error Handling

If SecurityCore blocks a workflow:

```python
from langgraph_adapter import WorkflowBlocked

try:
    result = audited_graph.invoke(input_state)
except WorkflowBlocked as e:
    print(f"Workflow blocked: {e}")
    # Check audit logs for decision details
```

Tools wrapped with `@audited_tool` will return a string message starting with `[阻断]` instead of raising an exception, allowing the workflow to continue recording the block event.

## Policy Loader Compatibility

PolicyLoader accepts both `agents:` and `nodes:` as top-level keys for backward compatibility. LangGraphAuditor uses `nodes:` but you can substitute `agents:` if migrating from AutoGenAuditor policy files.
