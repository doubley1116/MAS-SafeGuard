const RISK_LABELS = {
  unauthorized_tool_caller: "未授权调用",
  missing_required_path_node: "缺少必经节点",
  blocked_tool: "命中禁用工具",
  intent_confidence_missing: "缺少意图置信度",
  intent_confidence_too_low: "意图置信度不足",
  route_hijack_check: "路由劫持检查",
  path_rule_violation: "路径规则冲突",
  strict_path_violation: "严格路径违规",
  arg_constraint_violation: "参数越界",
};

const STATUS_META = {
  blocked: { label: "Blocked", tone: "blocked" },
  allowed: { label: "Passed", tone: "allowed" },
  review: { label: "Review", tone: "review" },
};

const GLASS_REACTIVE_SELECTOR = [
  ".site-header",
  ".hero",
  ".panel",
  ".subpanel",
  ".metric-card",
  ".workflow-card",
  ".log-entry",
  ".source-card",
  ".entity-card",
  ".history-row",
  ".timeline-card",
  ".telemetry-card",
  ".hero-panel",
  ".security-summary-card",
  ".history-dialog",
].join(", ");

const DEFAULT_SERVER_ORIGIN = "http://127.0.0.1:48317";
const STORAGE_KEY = "zero-trust-frontend-showcase-state";
let activeGlassElement = null;

function createDefaultState() {
  return {
    filters: {
      workflowFramework: "all",
      workflowStatus: "all",
      logLevel: "all",
      logFramework: "all",
      logQuery: "",
    },
    source: {
      mode: "demo",
      apiBase: "",
      serverAvailable: false,
      loading: false,
      repoRoot: "",
      policyFiles: [],
      workflowDirs: [],
      selectedPolicyPath: "",
      selectedWorkflowDir: "",
      lastSync: "",
      lastMessage: "当前使用内置演示数据。",
      lastError: "",
      rawPolicyText: "",
      autoRefreshEnabled: true,
      autoRefreshIntervalMs: 3000,
      watchFingerprint: "",
      watchStatus: "Auto refresh ready.",
      watchLastChecked: "",
      watchLastChange: "",
      watchWorkflowCount: 0,
      watchExists: false,
    },
    activeWorkflowId: "wf-autogen-blocked",
    config: {
      version: "2.1",
      description: "Zero Trust 多智能体安全审计前端展示配置",
      frameworks: {
        autogen: true,
        langgraph: true,
        mas: true,
      },
      security_core: {
        enabled: true,
        entry_mode: "local_model",
        provider: "ZeroTrust-Guard",
        model_name: "zt-defender-v2",
        endpoint: "https://api.zerotrust.local/v1",
        local_model_path: "./models/defender",
        api_protocol: "openai_compatible",
        api_key_env: "ZERO_TRUST_API_KEY",
        api_route: "/chat/completions",
        api_timeout_ms: 30000,
        prompt_status: "pending",
        audit_scope: "hybrid",
        history_window: 30,
        log_level: "verbose",
      },
      thresholds: {
        rule_block: 0.9,
        human_review: 0.75,
      },
      ui: {
        aesthetic: "apple-nasa-hybrid",
        show_history_panel: true,
        show_log_stream: true,
        block_badge_mode: "risk_types",
      },
      agents: [
        {
          name: "UserProxy",
          role: "user_proxy",
          can_initiate: true,
          allowed_tools: [],
          blocked_tools: [],
          allowed_message_targets: ["Agent_A", "Stats_Node", "Risk_Agent"],
          notes: "用户入口代理，只负责发起任务和透传结果",
        },
        {
          name: "Agent_A",
          role: "worker_agent",
          can_initiate: false,
          allowed_tools: ["tool_a"],
          blocked_tools: ["tool_b"],
          allowed_message_targets: ["UserProxy", "Agent_B"],
          notes: "AutoGen 中的前置审批 Agent",
        },
        {
          name: "Agent_B",
          role: "sensitive_agent",
          can_initiate: false,
          allowed_tools: ["tool_b"],
          blocked_tools: ["tool_a"],
          allowed_message_targets: ["UserProxy", "Agent_A"],
          notes: "执行敏感工具前必须通过 Agent_A",
        },
        {
          name: "Stats_Node",
          role: "stats_node",
          can_initiate: false,
          allowed_tools: ["stats_query_tool"],
          blocked_tools: ["config_update_tool"],
          allowed_message_targets: ["UserProxy", "Config_Node"],
          notes: "LangGraph 查询节点",
        },
        {
          name: "Risk_Agent",
          role: "risk_agent",
          can_initiate: false,
          allowed_tools: ["trade_risk_assess_tool"],
          blocked_tools: ["execute_trade_tool"],
          allowed_message_targets: ["Trader_Agent", "Compliance_Agent"],
          notes: "MAS 场景中的风控审查节点",
        },
      ],
      tools: [
        {
          name: "tool_a",
          allowed_callers: ["Agent_A"],
          required_path_contains: [],
          path_rule: "valid_a_path",
          approval_required: false,
          approver: "",
          route_hijack_check: false,
          notes: "普通查询工具",
        },
        {
          name: "tool_b",
          allowed_callers: ["Agent_B"],
          required_path_contains: ["Agent_A"],
          path_rule: "valid_sensitive_path",
          approval_required: true,
          approver: "Agent_A",
          route_hijack_check: false,
          notes: "敏感工具，需要前置审批",
        },
        {
          name: "stats_query_tool",
          allowed_callers: ["Stats_Node"],
          required_path_contains: ["UserProxy"],
          path_rule: "valid_stats_path",
          approval_required: false,
          approver: "",
          route_hijack_check: false,
          notes: "LangGraph 统计查询",
        },
        {
          name: "execute_trade_tool",
          allowed_callers: ["Trader_Agent"],
          required_path_contains: ["Risk_Agent", "Compliance_Agent"],
          path_rule: "valid_trade_path",
          approval_required: true,
          approver: "Compliance_Agent",
          route_hijack_check: true,
          notes: "交易执行工具，需要路由一致性校验",
        },
      ],
      paths: [
        {
          name: "valid_a_path",
          sequence: ["Agent_A"],
          strict: false,
        },
        {
          name: "valid_sensitive_path",
          sequence: ["UserProxy", "Agent_A", "Agent_B"],
          strict: false,
        },
        {
          name: "valid_stats_path",
          sequence: ["UserProxy", "Stats_Node"],
          strict: false,
        },
        {
          name: "valid_trade_path",
          sequence: ["UserProxy", "Risk_Agent", "Compliance_Agent", "Trader_Agent"],
          strict: false,
        },
      ],
    },
    workflows: [
      {
        id: "wf-autogen-blocked",
        name: "敏感工具绕过审批",
        framework: "AutoGen",
        sceneName: "discount_update",
        status: "blocked",
        traceId: "trace-autogen-0422",
        startedAt: "2026-04-22 23:05:12",
        latencyMs: 1880,
        summary: "Agent_B 试图直接调用敏感工具 `tool_b`，未经过 Agent_A 审批，SecurityCore 在规则层直接阻断。",
        callPath: ["UserProxy", "Agent_B"],
        blockedReason: "SecurityCore 阻断工作流: [规则拦截] 调用 tool_b 前缺少必经节点 Agent_A，并且路径未包含 UserProxy → Agent_A → Agent_B。",
        decision: {
          allow: false,
          risk_score: 0.92,
          reason: "[规则拦截] 调用 tool_b 前缺少必经节点 Agent_A，路径规则 valid_sensitive_path 未满足。",
          blocking_risk_types: ["missing_required_path_node", "path_rule_violation"],
          suggested_alternative: "先经 Agent_A 审批，再由 Agent_B 触发 tool_b。",
          trajectory_score: null,
        },
        events: [
          {
            id: "evt-a1",
            event_type: "message",
            sender: "UserProxy",
            receiver: "Agent_B",
            tool_name: null,
            tool_args: null,
            call_path: ["UserProxy"],
            content: "请直接调用 tool_b，把商家 M001 折扣更新为 0.90。",
            history_summary: "[任务]更新商家 M001 折扣 | UserProxy→Agent_B:请直接调用 tool_b",
            task: "更新商家 M001 折扣为 0.90",
            trace_id: "trace-autogen-0422",
            timestamp: "2026-04-22T23:05:12",
            metadata: { framework: "AutoGen", scene: "discount_update" },
          },
          {
            id: "evt-a2",
            event_type: "tool_call",
            sender: "Agent_B",
            receiver: null,
            tool_name: "tool_b",
            tool_args: { action: "update_discount", merchant_id: "M001", discount: 0.9 },
            call_path: ["UserProxy", "Agent_B"],
            content: "执行折扣更新",
            history_summary: "[任务]更新商家 M001 折扣 | UserProxy→Agent_B:请直接调用 tool_b | Agent_B→tool_b(action=update_discount,merchant_id=M001,discount=0.9)",
            task: "更新商家 M001 折扣为 0.90",
            trace_id: "trace-autogen-0422",
            timestamp: "2026-04-22T23:05:19",
            metadata: { framework: "AutoGen", scene: "discount_update" },
          },
          {
            id: "evt-a3",
            event_type: "message",
            sender: "SecurityCore",
            receiver: "Workflow",
            tool_name: null,
            tool_args: null,
            call_path: ["UserProxy", "Agent_B"],
            content: "WorkflowBlocked: missing_required_path_node + path_rule_violation",
            history_summary: "[关键]Agent_B→tool_b(action=update_discount,merchant_id=M001,discount=0.9)",
            task: "更新商家 M001 折扣为 0.90",
            trace_id: "trace-autogen-0422",
            timestamp: "2026-04-22T23:05:20",
            metadata: { framework: "AutoGen", scene: "discount_update" },
          },
        ],
        decisions: [
          {
            allow: false,
            risk_score: 0.92,
            reason: "[规则拦截] 调用 tool_b 前缺少必经节点 Agent_A，路径规则 valid_sensitive_path 未满足。",
            blocking_risk_types: ["missing_required_path_node", "path_rule_violation"],
            suggested_alternative: "先经 Agent_A 审批，再由 Agent_B 触发 tool_b。",
            trajectory_score: null,
          },
        ],
      },
      {
        id: "wf-langgraph-allowed",
        name: "统计查询正常放行",
        framework: "LangGraph",
        sceneName: "stats_query",
        status: "allowed",
        traceId: "trace-langgraph-0422",
        startedAt: "2026-04-22 23:13:40",
        latencyMs: 1360,
        summary: "UserProxy 调用 Stats_Node 执行 `stats_query_tool`，满足路径要求，查询结果被正常记录并展示到日志。",
        callPath: ["UserProxy", "Stats_Node"],
        blockedReason: "",
        decision: {
          allow: true,
          risk_score: 0.18,
          reason: "规则分 0.00，未命中结构性风险；语义审核通过。",
          blocking_risk_types: [],
          suggested_alternative: null,
          trajectory_score: 0.12,
        },
        events: [
          {
            id: "evt-l1",
            event_type: "message",
            sender: "UserProxy",
            receiver: "Stats_Node",
            tool_name: null,
            tool_args: null,
            call_path: ["UserProxy"],
            content: "请查询商家 M001 最近 7 天销售统计。",
            history_summary: "[任务]查询商家 M001 最近 7 天销售统计",
            task: "查询商家 M001 最近 7 天销售统计",
            trace_id: "trace-langgraph-0422",
            timestamp: "2026-04-22T23:13:40",
            metadata: { framework: "LangGraph", scene: "stats_query" },
          },
          {
            id: "evt-l2",
            event_type: "tool_call",
            sender: "Stats_Node",
            receiver: null,
            tool_name: "stats_query_tool",
            tool_args: { merchant_id: "M001", range: "7d" },
            call_path: ["UserProxy", "Stats_Node"],
            content: "查询销售统计",
            history_summary: "[任务]查询商家 M001 最近 7 天销售统计 | Stats_Node→stats_query_tool(merchant_id=M001,range=7d)",
            task: "查询商家 M001 最近 7 天销售统计",
            trace_id: "trace-langgraph-0422",
            timestamp: "2026-04-22T23:13:43",
            metadata: { framework: "LangGraph", scene: "stats_query" },
          },
          {
            id: "evt-l3",
            event_type: "tool_result",
            sender: "stats_query_tool",
            receiver: "Stats_Node",
            tool_name: "stats_query_tool",
            tool_args: null,
            call_path: ["UserProxy", "Stats_Node"],
            content: "销售额 12000，订单量 58，退款率 0.6%。",
            history_summary: "[任务]查询商家 M001 最近 7 天销售统计 | [近期]stats_query_tool→Stats_Node(数值:金额12000,数量58)",
            task: "查询商家 M001 最近 7 天销售统计",
            trace_id: "trace-langgraph-0422",
            timestamp: "2026-04-22T23:13:44",
            metadata: { framework: "LangGraph", scene: "stats_query" },
          },
        ],
        decisions: [
          {
            allow: true,
            risk_score: 0.18,
            reason: "规则分 0.00，未命中结构性风险；语义审核通过。",
            blocking_risk_types: [],
            suggested_alternative: null,
            trajectory_score: 0.12,
          },
        ],
      },
      {
        id: "wf-mas-review",
        name: "交易执行待人工复核",
        framework: "MAS",
        sceneName: "trade_route_check",
        status: "review",
        traceId: "trace-mas-0422",
        startedAt: "2026-04-22 23:22:08",
        latencyMs: 2440,
        summary: "交易请求经过 Risk_Agent 与 Compliance_Agent，但路由存在语义偏移迹象，命中 route_hijack_check，建议人工审核。",
        callPath: ["UserProxy", "Risk_Agent", "Compliance_Agent", "Trader_Agent"],
        blockedReason: "",
        decision: {
          allow: true,
          risk_score: 0.74,
          reason: "规则分 0.45 命中 route_hijack_check，语义层发现指令由研究摘要偏移到交易执行，建议人工复核。",
          blocking_risk_types: ["route_hijack_check"],
          suggested_alternative: "将交易执行拆为二次确认流程，并要求 Trader_Agent 复述订单意图。",
          trajectory_score: 0.79,
        },
        events: [
          {
            id: "evt-m1",
            event_type: "message",
            sender: "UserProxy",
            receiver: "Risk_Agent",
            tool_name: null,
            tool_args: null,
            call_path: ["UserProxy"],
            content: "先评估 TSLA，再根据研究结果决定是否执行 100 股卖出。",
            history_summary: "[任务]评估 TSLA 并判断是否执行 100 股卖出",
            task: "评估 TSLA 并判断是否执行 100 股卖出",
            trace_id: "trace-mas-0422",
            timestamp: "2026-04-22T23:22:08",
            metadata: { framework: "MAS", scene: "trade_route_check" },
          },
          {
            id: "evt-m2",
            event_type: "message",
            sender: "Risk_Agent",
            receiver: "Compliance_Agent",
            tool_name: null,
            tool_args: null,
            call_path: ["UserProxy", "Risk_Agent"],
            content: "风险评估通过，但消息里出现了直接执行语句，请协助审查。",
            history_summary: "[关键]Risk_Agent→Compliance_Agent:风险评估通过，但出现直接执行语句",
            task: "评估 TSLA 并判断是否执行 100 股卖出",
            trace_id: "trace-mas-0422",
            timestamp: "2026-04-22T23:22:13",
            metadata: { framework: "MAS", scene: "trade_route_check" },
          },
          {
            id: "evt-m3",
            event_type: "tool_call",
            sender: "Trader_Agent",
            receiver: null,
            tool_name: "execute_trade_tool",
            tool_args: { symbol: "TSLA", side: "sell", quantity: 100 },
            call_path: ["UserProxy", "Risk_Agent", "Compliance_Agent", "Trader_Agent"],
            content: "执行交易",
            history_summary: "[任务]评估 TSLA 并判断是否执行 100 股卖出 | [关键]Trader_Agent→execute_trade_tool(symbol=TSLA,side=sell,quantity=100)",
            task: "评估 TSLA 并判断是否执行 100 股卖出",
            trace_id: "trace-mas-0422",
            timestamp: "2026-04-22T23:22:19",
            metadata: { framework: "MAS", scene: "trade_route_check", intent_confidence: 0.58 },
          },
        ],
        decisions: [
          {
            allow: true,
            risk_score: 0.74,
            reason: "规则分 0.45 命中 route_hijack_check，语义层发现指令由研究摘要偏移到交易执行，建议人工复核。",
            blocking_risk_types: ["route_hijack_check"],
            suggested_alternative: "将交易执行拆为二次确认流程，并要求 Trader_Agent 复述订单意图。",
            trajectory_score: 0.79,
          },
        ],
      },
    ],
  };
}

let state = hydrateState(loadState());
let workflowWatchTimer = null;
let workflowWatchPending = false;
normalizeState();

window.addEventListener("DOMContentLoaded", init);
window.addEventListener("beforeunload", () => {
  clearWorkflowWatcher();
});

async function init() {
  syncFilterControls();
  renderAll();
  setupGlassPointerEffects();
  document.addEventListener("click", handleClick);
  document.addEventListener("input", handleInput);
  document.addEventListener("change", handleInput);
  revealSections();
  await bootstrapServerDiscovery();
  if (state.source.mode === "filesystem" && state.source.serverAvailable) {
    await loadFilesystemData({ silent: true });
  }
}

function revealSections() {
  document.querySelectorAll(".reveal").forEach((element, index) => {
    window.setTimeout(() => element.classList.add("is-visible"), 40 * index);
  });
}

async function handleClick(event) {
  const target = event.target.closest("button, .workflow-card");
  if (!target) {
    return;
  }

  if (target.classList.contains("workflow-card")) {
    state.activeWorkflowId = target.dataset.workflowId;
    renderAll();
    persistState();
    return;
  }

  switch (target.id) {
    case "useDemoBtn":
      switchToDemoMode();
      break;
    case "refreshSourceBtn":
      await bootstrapServerDiscovery();
      if (state.source.mode === "filesystem" && state.source.serverAvailable) {
        await loadFilesystemData({ silent: true });
      }
      break;
    case "loadFilesystemBtn":
      await loadFilesystemData();
      break;
    case "focusBlockedBtn":
      focusFirstBlockedWorkflow();
      break;
    case "downloadYamlBtn":
    case "downloadYamlBtnTop":
      downloadYaml();
      break;
    case "copyYamlBtn":
      copyYaml();
      break;
    case "resetConfigBtn":
      resetConfig();
      break;
    case "addAgentBtn":
      state.config.agents.push(createEmptyAgent());
      renderAll();
      persistState();
      break;
    case "addToolBtn":
      state.config.tools.push(createEmptyTool());
      renderAll();
      persistState();
      break;
    case "addPathBtn":
      state.config.paths.push(createEmptyPath());
      renderAll();
      persistState();
      break;
    default:
      if (target.dataset.removeAgent !== undefined) {
        removeAt(state.config.agents, Number(target.dataset.removeAgent));
      } else if (target.dataset.removeTool !== undefined) {
        removeAt(state.config.tools, Number(target.dataset.removeTool));
      } else if (target.dataset.removePath !== undefined) {
        removeAt(state.config.paths, Number(target.dataset.removePath));
      } else if (target.dataset.openHistory) {
        openHistoryDialog(target.dataset.openHistory, target.dataset.eventId || "");
        return;
      } else {
        return;
      }
      normalizeState();
      renderAll();
      persistState();
      break;
  }
}

async function handleInput(event) {
  const target = event.target;
  if (target.id === "workflowFrameworkFilter") {
    state.filters.workflowFramework = target.value;
  } else if (target.id === "workflowStatusFilter") {
    state.filters.workflowStatus = target.value;
  } else if (target.id === "logLevelFilter") {
    state.filters.logLevel = target.value;
  } else if (target.id === "logFrameworkFilter") {
    state.filters.logFramework = target.value;
  } else if (target.id === "logSearchInput") {
    state.filters.logQuery = target.value;
  } else if (target.id === "sourceModeSelect") {
    if (target.value === "filesystem") {
      await loadFilesystemData();
      return;
    }
    switchToDemoMode();
    return;
  } else if (target.id === "policyPathSelect") {
    state.source.selectedPolicyPath = target.value;
    if (state.source.mode === "filesystem") {
      await loadFilesystemData({ silent: true, preserveActiveWorkflowId: true });
      return;
    }
  } else if (target.id === "workflowDirSelect") {
    state.source.selectedWorkflowDir = target.value;
    if (state.source.mode === "filesystem") {
      await loadFilesystemData({ silent: true, preserveActiveWorkflowId: true });
      return;
    }
  } else if (target.id === "autoRefreshToggle") {
    state.source.autoRefreshEnabled = Boolean(target.checked);
    if (!state.source.autoRefreshEnabled) {
      stopWorkflowWatcher("Auto refresh paused.");
      renderAll();
      persistState();
      return;
    }
    await configureWorkflowWatcher({ immediate: true });
    return;
  } else if (target.id === "autoRefreshIntervalSelect") {
    state.source.autoRefreshIntervalMs = Number(target.value) || 3000;
    await configureWorkflowWatcher({ immediate: state.source.mode === "filesystem" && state.source.autoRefreshEnabled });
    return;
  } else if (target.dataset.bind) {
    applyBinding(target);
  } else {
    return;
  }

  normalizeState();
  renderAll();
  persistState();
}

function applyBinding(target) {
  let value;
  if (target.type === "checkbox") {
    value = target.checked;
  } else {
    value = target.value;
  }

  if (target.dataset.format === "array") {
    value = parseList(value);
  } else if (target.dataset.cast === "number") {
    value = Number(value);
  }

  setByPath(state, target.dataset.bind, value);
}

function renderAll() {
  applyVisualTheme();
  renderMetrics();
  renderSourcePanel();
  renderWorkflowList();
  renderWorkflowDetail();
  renderSecurityControl();
  renderConfigEditors();
  renderYamlPreview();
  renderLogs();
  syncFilterControls();
}

function applyVisualTheme() {
  document.body.dataset.theme = state.config.ui.aesthetic || "apple-nasa-hybrid";
}

function setupGlassPointerEffects() {
  document.addEventListener("pointermove", handleGlassPointerMove, { passive: true });
  document.addEventListener("pointerdown", handleGlassPointerMove, { passive: true });
  document.addEventListener("pointerleave", clearActiveGlassEffect);
}

function handleGlassPointerMove(event) {
  if (!(event.target instanceof Element)) {
    clearActiveGlassEffect();
    return;
  }

  const pointerX = (event.clientX / Math.max(window.innerWidth, 1)) * 100;
  const pointerY = (event.clientY / Math.max(window.innerHeight, 1)) * 100;
  document.body.style.setProperty("--scene-pointer-x", `${pointerX.toFixed(2)}%`);
  document.body.style.setProperty("--scene-pointer-y", `${pointerY.toFixed(2)}%`);

  const target = event.target.closest(GLASS_REACTIVE_SELECTOR);
  if (!target) {
    clearActiveGlassEffect();
    return;
  }

  if (activeGlassElement && activeGlassElement !== target) {
    deactivateGlassElement(activeGlassElement);
  }

  activeGlassElement = target;

  const rect = target.getBoundingClientRect();
  const relativeX = Math.max(0, Math.min(rect.width, event.clientX - rect.left));
  const relativeY = Math.max(0, Math.min(rect.height, event.clientY - rect.top));
  const tiltX = ((relativeY / Math.max(rect.height, 1)) - 0.5) * -5;
  const tiltY = ((relativeX / Math.max(rect.width, 1)) - 0.5) * 6;

  target.style.setProperty("--glass-x", `${relativeX.toFixed(1)}px`);
  target.style.setProperty("--glass-y", `${relativeY.toFixed(1)}px`);
  target.style.setProperty("--glass-opacity", "1");
  target.style.setProperty("--glass-tilt-x", `${tiltX.toFixed(2)}deg`);
  target.style.setProperty("--glass-tilt-y", `${tiltY.toFixed(2)}deg`);
  target.classList.add("is-glass-active");
}

function deactivateGlassElement(element) {
  element.style.setProperty("--glass-opacity", "0");
  element.style.setProperty("--glass-tilt-x", "0deg");
  element.style.setProperty("--glass-tilt-y", "0deg");
  element.classList.remove("is-glass-active");
}

function clearActiveGlassEffect() {
  if (!activeGlassElement) {
    return;
  }

  deactivateGlassElement(activeGlassElement);
  activeGlassElement = null;
}

function renderSourcePanel() {
  const container = document.getElementById("sourceRuntimePanel");
  const source = state.source;
  const sourceTone = source.serverAvailable ? "allowed" : "review";
  const sourceLabel = source.serverAvailable ? "Server Ready" : "Demo Only";
  const workflowDirOptions = source.workflowDirs.length
    ? source.workflowDirs
    : [{ label: "未发现 audit_logs/workflows 目录", value: "" }];
  const policyOptions = source.policyFiles.length
    ? source.policyFiles
    : [{ label: "未发现 policy.yaml", value: "" }];

  container.innerHTML = `
    <div class="runtime-grid">
      <div class="runtime-stack">
        <div class="status-line">
          <span class="status-pill ${sourceTone}">${sourceLabel}</span>
          <span class="meta-pill">${escapeHtml(source.mode === "filesystem" ? "文件系统模式" : "内置演示模式")}</span>
          ${source.lastSync ? `<span class="meta-pill">Last Sync: ${escapeHtml(source.lastSync)}</span>` : ""}
          <span class="meta-pill">${escapeHtml(source.autoRefreshEnabled ? `Auto refresh ${getPollingIntervalLabel(source.autoRefreshIntervalMs)}` : "Auto refresh off")}</span>
          ${source.watchWorkflowCount ? `<span class="meta-pill">${escapeHtml(`Watching ${source.watchWorkflowCount} JSON`)}</span>` : ""}
        </div>

        <div class="toolbar">
          <label class="field">
            <span>数据源模式</span>
            <select id="sourceModeSelect">
              <option value="demo" ${source.mode === "demo" ? "selected" : ""}>内置演示</option>
              <option value="filesystem" ${source.mode === "filesystem" ? "selected" : ""}>真实文件系统</option>
            </select>
          </label>
          <label class="field grow">
            <span>策略文件</span>
            <select id="policyPathSelect" ${!source.serverAvailable ? "disabled" : ""}>
              ${policyOptions
                .map((item) => {
                  const value = item.value || item;
                  const label = item.label || item;
                  return `<option value="${escapeAttribute(value)}" ${value === source.selectedPolicyPath ? "selected" : ""}>${escapeHtml(label)}</option>`;
                })
                .join("")}
            </select>
          </label>
          <label class="field grow">
            <span>Workflow 目录</span>
            <select id="workflowDirSelect" ${!source.serverAvailable ? "disabled" : ""}>
              ${workflowDirOptions
                .map((item) => {
                  const value = item.value || item;
                  const label = item.label || item;
                  return `<option value="${escapeAttribute(value)}" ${value === source.selectedWorkflowDir ? "selected" : ""}>${escapeHtml(label)}</option>`;
                })
                .join("")}
            </select>
          </label>
        </div>

        <div class="panel-actions">
          <button class="button tertiary" id="useDemoBtn" type="button">使用演示数据</button>
          <button class="button tertiary" id="refreshSourceBtn" type="button">${source.loading ? "扫描中..." : "重新扫描仓库"}</button>
          <button class="button primary" id="loadFilesystemBtn" type="button" ${!source.serverAvailable || source.loading ? "disabled" : ""}>读取真实文件</button>
        </div>

        <div class="detail-callout">
          <p class="panel-kicker">Workflow Watch</p>
          <h3>Auto Refresh</h3>
          <div class="form-grid two-col">
            <label class="toggle-row" for="autoRefreshToggle">
              <span>Watch new workflow.json</span>
              <input id="autoRefreshToggle" type="checkbox" ${source.autoRefreshEnabled ? "checked" : ""}>
            </label>
            <label class="field">
              <span>Polling interval</span>
              <select id="autoRefreshIntervalSelect">
                <option value="3000" ${source.autoRefreshIntervalMs === 3000 ? "selected" : ""}>Every 3s</option>
                <option value="5000" ${source.autoRefreshIntervalMs === 5000 ? "selected" : ""}>Every 5s</option>
                <option value="10000" ${source.autoRefreshIntervalMs === 10000 ? "selected" : ""}>Every 10s</option>
              </select>
            </label>
          </div>
          <div class="detail-meta">
            <span class="meta-pill">${escapeHtml(source.watchExists ? "Watch target ready" : "Watch target pending")}</span>
            ${source.watchLastChecked ? `<span class="meta-pill">Last Check: ${escapeHtml(source.watchLastChecked)}</span>` : ""}
            ${source.watchLastChange ? `<span class="meta-pill">Last Change: ${escapeHtml(source.watchLastChange)}</span>` : ""}
          </div>
          <p class="runtime-note">${escapeHtml(source.watchStatus || "Auto refresh ready.")}</p>
        </div>

        <p class="runtime-note">${escapeHtml(source.lastMessage || "当前使用内置演示数据。")}</p>
        ${
          source.lastError
            ? `<p class="runtime-note"><strong>最近错误：</strong>${escapeHtml(source.lastError)}</p>`
            : ""
        }
      </div>

      <div class="runtime-stack">
        <div class="detail-callout">
          <p class="panel-kicker">Repository</p>
          <h3>路径映射</h3>
          <p class="detail-paragraph"><strong>API Base：</strong>${escapeHtml(getApiBase())}</p>
          <p class="detail-paragraph"><strong>Repo Root：</strong>${escapeHtml(source.repoRoot || "等待扫描")}</p>
          <p class="detail-paragraph"><strong>Policy：</strong>${escapeHtml(source.selectedPolicyPath || "未选择")}</p>
          <p class="detail-paragraph"><strong>Workflow Dir：</strong>${escapeHtml(source.selectedWorkflowDir || "未发现目录")}</p>
        </div>
      </div>
    </div>
  `;
}

function renderMetrics() {
  const workflows = state.workflows;
  const blockedCount = workflows.filter((item) => item.status === "blocked").length;
  const reviewCount = workflows.filter((item) => item.status === "review").length;
  const eventCount = workflows.reduce((total, workflow) => total + workflow.events.length, 0);
  const highestRisk = workflows.reduce((max, workflow) => {
    return Math.max(max, workflow.decision.risk_score || 0);
  }, 0);
  const metrics = [
    {
      label: "演示工作流",
      value: String(workflows.length),
      note: "覆盖 AutoGen、LangGraph、MAS",
    },
    {
      label: "阻断命中",
      value: `${blockedCount}/${workflows.length}`,
      note: `${reviewCount} 个流程进入人工复核`,
    },
    {
      label: "最高风险分",
      value: highestRisk.toFixed(2),
      note: `rule_block = ${state.config.thresholds.rule_block.toFixed(2)}`,
    },
    {
      label: "日志事件",
      value: String(eventCount),
      note: `${state.config.security_core.enabled ? "SecurityCore 已开启" : "SecurityCore 已关闭"}`,
    },
  ];

  document.getElementById("metricsGrid").innerHTML = metrics
    .map(
      (metric) => `
        <article class="metric-card">
          <p class="metric-label">${escapeHtml(metric.label)}</p>
          <p class="metric-value">${escapeHtml(metric.value)}</p>
          <p class="metric-note">${escapeHtml(metric.note)}</p>
        </article>
      `
    )
    .join("");
}

function renderWorkflowList() {
  const workflows = getVisibleWorkflows();
  const list = document.getElementById("workflowList");

  if (!workflows.length) {
    list.innerHTML = `<div class="empty-state">${
      state.source.mode === "filesystem"
        ? "当前真实目录下还没有 workflow.json。你可以先运行 AutoGenAuditor / LangGraphAuditor 示例生成 audit_logs/workflows/*.json，再点“读取真实文件”。"
        : "当前筛选条件下没有工作流。"
    }</div>`;
    return;
  }

  list.innerHTML = workflows
    .map((workflow) => {
      const status = STATUS_META[workflow.status];
      const isActive = workflow.id === state.activeWorkflowId;
      return `
        <article class="workflow-card ${isActive ? "is-active" : ""}" data-workflow-id="${workflow.id}">
          <div class="workflow-card-head">
            <h3 class="workflow-title">${escapeHtml(workflow.name)}</h3>
            <span class="status-pill ${status.tone}">${status.label}</span>
          </div>
          <p class="workflow-summary">${escapeHtml(workflow.summary)}</p>
          <div class="workflow-meta">
            <span class="meta-pill">${escapeHtml(workflow.framework)}</span>
            <span class="meta-pill">${escapeHtml(workflow.traceId)}</span>
            <span class="meta-pill">${workflow.latencyMs} ms</span>
          </div>
        </article>
      `;
    })
    .join("");
}

function renderWorkflowDetail() {
  const workflow = getActiveWorkflow();
  const container = document.getElementById("workflowDetail");

  if (!workflow) {
    container.innerHTML = `<div class="empty-state">请选择一个工作流查看详情。</div>`;
    return;
  }

  const status = STATUS_META[workflow.status];
  const decisionTags = (workflow.decision.blocking_risk_types || [])
    .map((tag) => `<span class="tag ${workflow.status === "blocked" ? "risk" : "warn"}">${escapeHtml(getRiskLabel(tag))}</span>`)
    .join("");

  const eventTimeline = workflow.events
    .map(
      (event) => `
        <article class="timeline-card">
          <div class="workflow-card-head">
            <h4>${escapeHtml(formatEventTitle(event))}</h4>
            <span class="meta-pill">${escapeHtml(event.event_type)}</span>
          </div>
          <div class="timeline-card-meta">
            <span>${escapeHtml(formatEventActors(event))}</span>
            <span>${escapeHtml(formatTimestamp(event.timestamp))}</span>
          </div>
          <p class="timeline-card-content">${escapeHtml(event.content || "无正文")}</p>
          <div class="timeline-card-meta">
            <span>call_path: ${escapeHtml((event.call_path || []).join(" → ") || "-")}</span>
            ${event.tool_name ? `<span>tool: ${escapeHtml(event.tool_name)}</span>` : ""}
          </div>
          <div class="timeline-card-actions">
            <button class="button tertiary" type="button" data-open-history="${workflow.id}" data-event-id="${event.id}">
              查看 history
            </button>
          </div>
        </article>
      `
    )
    .join("");

  container.innerHTML = `
    <div class="detail-stack">
      <section class="detail-callout">
        <div class="workflow-detail-head">
          <div>
            <p class="panel-kicker">${escapeHtml(workflow.framework)} / ${escapeHtml(workflow.sceneName)}</p>
            <h2>${escapeHtml(workflow.name)}</h2>
          </div>
          <span class="status-pill ${status.tone}">${status.label}</span>
        </div>
        <p class="detail-paragraph">${escapeHtml(workflow.summary)}</p>
        <div class="detail-meta">
          <span class="meta-pill">Trace: ${escapeHtml(workflow.traceId)}</span>
          <span class="meta-pill">Started: ${escapeHtml(workflow.startedAt)}</span>
          <span class="meta-pill">Latency: ${workflow.latencyMs} ms</span>
        </div>
        <div class="call-path">
          ${workflow.callPath.map((node) => `<span class="path-node">${escapeHtml(node)}</span>`).join("")}
        </div>
      </section>

      <section class="decision-card">
        <div class="decision-head">
          <div>
            <p class="panel-kicker">Decision</p>
            <h3>${workflow.status === "blocked" ? "阻断说明" : workflow.status === "review" ? "人工复核建议" : "放行结果"}</h3>
          </div>
          <div class="decision-score">${workflow.decision.risk_score.toFixed(2)}</div>
        </div>
        <p class="detail-paragraph">${escapeHtml(workflow.decision.reason)}</p>
        <div class="decision-strip">
          ${decisionTags || `<span class="tag ${workflow.status === "allowed" ? "safe" : "info"}">${workflow.status === "allowed" ? "未命中阻断标签" : "待补充人工标签"}</span>`}
        </div>
        ${
          workflow.decision.suggested_alternative
            ? `<p class="detail-paragraph"><strong>建议替代路径：</strong>${escapeHtml(workflow.decision.suggested_alternative)}</p>`
            : ""
        }
        ${
          workflow.blockedReason
            ? `<p class="detail-paragraph"><strong>WorkflowBlocked：</strong>${escapeHtml(workflow.blockedReason)}</p>`
            : ""
        }
        <div class="timeline-card-actions">
          <button class="button secondary" type="button" data-open-history="${workflow.id}">打开完整 history 窗口</button>
        </div>
      </section>

      <section class="detail-callout">
        <div class="subpanel-head">
          <h3>事件时间线</h3>
        </div>
        <div class="timeline">${eventTimeline}</div>
      </section>
    </div>
  `;
}

function renderSecurityControl() {
  const config = state.config.security_core;
  const workflow = getActiveWorkflow();
  const container = document.getElementById("securityControl");
  const activeModeLabel = config.entry_mode === "local_model" ? "Local Model" : "API Model";
  const modeDescription = config.entry_mode === "local_model"
    ? "Use your trained model locally for offline demo and policy review."
    : "Route the guard model through an API endpoint now, then add prompts later.";
  const protocolLabel = config.api_protocol === "custom_rest" ? "Custom REST" : "OpenAI Compatible";

  container.innerHTML = `
    <div class="security-card">
      <div class="security-header">
        <div>
          <p class="panel-kicker">Model Entry</p>
          <h3>${escapeHtml(activeModeLabel)}</h3>
        </div>
        <span class="status-pill ${config.enabled ? "allowed" : "review"}">${config.enabled ? "Armed" : "Standby"}</span>
      </div>

      <p class="security-note">${escapeHtml(modeDescription)}</p>

      <div class="mode-chip-row">
        <span class="mode-chip ${config.entry_mode === "local_model" ? "is-active" : ""}">Local Runtime</span>
        <span class="mode-chip ${config.entry_mode === "api_gateway" ? "is-active" : ""}">API Bridge</span>
        <span class="mode-chip">${escapeHtml(config.audit_scope)}</span>
        <span class="mode-chip">${escapeHtml(config.log_level)}</span>
      </div>

      <label class="toggle-row">
        <span>启用 SecurityCore 总开关</span>
        <input type="checkbox" data-bind="config.security_core.enabled" ${config.enabled ? "checked" : ""}>
      </label>

      <div class="security-grid">
        <label class="field">
          <span>入口模式</span>
          <select data-bind="config.security_core.entry_mode">
            <option value="local_model" ${config.entry_mode === "local_model" ? "selected" : ""}>本地训练模型</option>
            <option value="api_gateway" ${config.entry_mode === "api_gateway" ? "selected" : ""}>API 接模型</option>
          </select>
        </label>

        <label class="field">
          <span>Provider</span>
          <input type="text" data-bind="config.security_core.provider" value="${escapeAttribute(config.provider)}">
        </label>

        <label class="field">
          <span>模型名称</span>
          <input type="text" data-bind="config.security_core.model_name" value="${escapeAttribute(config.model_name)}">
        </label>

        ${
          config.entry_mode === "local_model"
            ? `
              <label class="field">
                <span>本地模型路径</span>
                <input type="text" data-bind="config.security_core.local_model_path" value="${escapeAttribute(config.local_model_path)}">
              </label>
            `
            : `
              <label class="field">
                <span>API 协议</span>
                <select data-bind="config.security_core.api_protocol">
                  <option value="openai_compatible" ${config.api_protocol === "openai_compatible" ? "selected" : ""}>OpenAI Compatible</option>
                  <option value="custom_rest" ${config.api_protocol === "custom_rest" ? "selected" : ""}>Custom REST</option>
                </select>
              </label>
              <label class="field">
                <span>API Base URL</span>
                <input type="text" data-bind="config.security_core.endpoint" value="${escapeAttribute(config.endpoint)}">
              </label>
              <label class="field">
                <span>API Route</span>
                <input type="text" data-bind="config.security_core.api_route" value="${escapeAttribute(config.api_route)}">
              </label>
              <label class="field">
                <span>API Key Env</span>
                <input type="text" data-bind="config.security_core.api_key_env" value="${escapeAttribute(config.api_key_env)}">
              </label>
              <label class="field">
                <span>Timeout (ms)</span>
                <input type="number" min="1000" max="120000" step="1000" data-bind="config.security_core.api_timeout_ms" data-cast="number" value="${config.api_timeout_ms}">
              </label>
            `
        }

        <label class="field">
          <span>审计范围</span>
          <select data-bind="config.security_core.audit_scope">
            <option value="rules_only" ${config.audit_scope === "rules_only" ? "selected" : ""}>仅规则</option>
            <option value="hybrid" ${config.audit_scope === "hybrid" ? "selected" : ""}>规则 + 语义</option>
            <option value="trajectory_first" ${config.audit_scope === "trajectory_first" ? "selected" : ""}>轨迹优先</option>
          </select>
        </label>

        <label class="field">
          <span>History 窗口大小</span>
          <input type="number" min="5" max="60" step="1" data-bind="config.security_core.history_window" data-cast="number" value="${config.history_window}">
        </label>

        <label class="field">
          <span>日志级别</span>
          <select data-bind="config.security_core.log_level">
            <option value="quiet" ${config.log_level === "quiet" ? "selected" : ""}>quiet</option>
            <option value="verbose" ${config.log_level === "verbose" ? "selected" : ""}>verbose</option>
            <option value="trace" ${config.log_level === "trace" ? "selected" : ""}>trace</option>
          </select>
        </label>
      </div>

      <div class="security-summary-card">
        <div class="decision-strip">
          <span class="meta-pill">Entry: ${escapeHtml(activeModeLabel)}</span>
          ${
            config.entry_mode === "api_gateway"
              ? `<span class="meta-pill">Protocol: ${escapeHtml(protocolLabel)}</span>`
              : `<span class="meta-pill">Runtime: local</span>`
          }
          <span class="meta-pill">Prompt: ${escapeHtml(config.prompt_status || "pending")}</span>
        </div>
        <p class="security-note">
          模型提示词位先保留为 <strong>${escapeHtml(config.prompt_status || "pending")}</strong>，你后面可以直接补到 API 请求层或本地模型推理层。
        </p>
      </div>

      ${
        workflow
          ? `
            <div class="detail-callout">
              <p class="panel-kicker">Current Workflow Snapshot</p>
              <h3>${escapeHtml(workflow.name)}</h3>
              <p class="detail-paragraph">${escapeHtml(workflow.decision.reason)}</p>
              <div class="decision-strip">
                <span class="status-pill ${STATUS_META[workflow.status].tone}">${STATUS_META[workflow.status].label}</span>
                <span class="meta-pill">risk ${workflow.decision.risk_score.toFixed(2)}</span>
                <span class="meta-pill">${escapeHtml(activeModeLabel)}</span>
              </div>
            </div>
          `
          : ""
      }
    </div>
  `;
}

function renderConfigEditors() {
  renderBaseConfigEditor();
  renderAgentEditor();
  renderToolEditor();
  renderPathEditor();
}

function renderBaseConfigEditor() {
  const config = state.config;
  const container = document.getElementById("baseConfigEditor");
  container.innerHTML = `
    <label class="field">
      <span>配置版本</span>
      <input type="text" data-bind="config.version" value="${escapeAttribute(config.version)}">
    </label>

    <label class="field">
      <span>配置描述</span>
      <input type="text" data-bind="config.description" value="${escapeAttribute(config.description)}">
    </label>

    <label class="toggle-row">
      <span>接入 AutoGen</span>
      <input type="checkbox" data-bind="config.frameworks.autogen" ${config.frameworks.autogen ? "checked" : ""}>
    </label>

    <label class="toggle-row">
      <span>接入 LangGraph</span>
      <input type="checkbox" data-bind="config.frameworks.langgraph" ${config.frameworks.langgraph ? "checked" : ""}>
    </label>

    <label class="toggle-row">
      <span>接入 MAS</span>
      <input type="checkbox" data-bind="config.frameworks.mas" ${config.frameworks.mas ? "checked" : ""}>
    </label>

    <label class="field">
      <span>Rule Block 阈值</span>
      <input type="number" min="0" max="1" step="0.01" data-bind="config.thresholds.rule_block" data-cast="number" value="${config.thresholds.rule_block}">
    </label>

    <label class="field">
      <span>Human Review 阈值</span>
      <input type="number" min="0" max="1" step="0.01" data-bind="config.thresholds.human_review" data-cast="number" value="${config.thresholds.human_review}">
    </label>

    <label class="field">
      <span>Block 标签模式</span>
      <select data-bind="config.ui.block_badge_mode">
        <option value="risk_types" ${config.ui.block_badge_mode === "risk_types" ? "selected" : ""}>risk_types</option>
        <option value="severity" ${config.ui.block_badge_mode === "severity" ? "selected" : ""}>severity</option>
        <option value="mixed" ${config.ui.block_badge_mode === "mixed" ? "selected" : ""}>mixed</option>
      </select>
    </label>

    <label class="field">
      <span>视觉主题</span>
      <select data-bind="config.ui.aesthetic">
        <option value="apple-nasa-hybrid" ${config.ui.aesthetic === "apple-nasa-hybrid" ? "selected" : ""}>Apple x NASA</option>
        <option value="apple-glass" ${config.ui.aesthetic === "apple-glass" ? "selected" : ""}>Apple Glass</option>
        <option value="mission-control" ${config.ui.aesthetic === "mission-control" ? "selected" : ""}>Mission Control</option>
      </select>
    </label>

    <label class="toggle-row">
      <span>显示 History 面板</span>
      <input type="checkbox" data-bind="config.ui.show_history_panel" ${config.ui.show_history_panel ? "checked" : ""}>
    </label>

    <label class="toggle-row">
      <span>显示日志流</span>
      <input type="checkbox" data-bind="config.ui.show_log_stream" ${config.ui.show_log_stream ? "checked" : ""}>
    </label>
  `;
}

function renderAgentEditor() {
  const container = document.getElementById("agentEditor");
  container.innerHTML = state.config.agents
    .map(
      (agent, index) => `
        <article class="entity-card">
          <div class="entity-head">
            <h4>${escapeHtml(agent.name || `Agent ${index + 1}`)}</h4>
            <button class="button tertiary" type="button" data-remove-agent="${index}">删除</button>
          </div>
          <label class="field">
            <span>名称</span>
            <input type="text" data-bind="config.agents.${index}.name" value="${escapeAttribute(agent.name)}">
          </label>
          <label class="field">
            <span>Role</span>
            <input type="text" data-bind="config.agents.${index}.role" value="${escapeAttribute(agent.role)}">
          </label>
          <label class="toggle-row">
            <span>允许发起流程</span>
            <input type="checkbox" data-bind="config.agents.${index}.can_initiate" ${agent.can_initiate ? "checked" : ""}>
          </label>
          <label class="field">
            <span>allowed_tools</span>
            <textarea data-bind="config.agents.${index}.allowed_tools" data-format="array">${escapeHtml(agent.allowed_tools.join(", "))}</textarea>
          </label>
          <label class="field">
            <span>blocked_tools</span>
            <textarea data-bind="config.agents.${index}.blocked_tools" data-format="array">${escapeHtml(agent.blocked_tools.join(", "))}</textarea>
          </label>
          <label class="field">
            <span>allowed_message_targets</span>
            <textarea data-bind="config.agents.${index}.allowed_message_targets" data-format="array">${escapeHtml(agent.allowed_message_targets.join(", "))}</textarea>
          </label>
          <label class="field">
            <span>说明</span>
            <textarea data-bind="config.agents.${index}.notes">${escapeHtml(agent.notes)}</textarea>
          </label>
        </article>
      `
    )
    .join("");
}

function renderToolEditor() {
  const container = document.getElementById("toolEditor");
  container.innerHTML = state.config.tools
    .map(
      (tool, index) => `
        <article class="entity-card">
          <div class="entity-head">
            <h4>${escapeHtml(tool.name || `Tool ${index + 1}`)}</h4>
            <button class="button tertiary" type="button" data-remove-tool="${index}">删除</button>
          </div>
          <label class="field">
            <span>名称</span>
            <input type="text" data-bind="config.tools.${index}.name" value="${escapeAttribute(tool.name)}">
          </label>
          <label class="field">
            <span>allowed_callers</span>
            <textarea data-bind="config.tools.${index}.allowed_callers" data-format="array">${escapeHtml(tool.allowed_callers.join(", "))}</textarea>
          </label>
          <label class="field">
            <span>required_path_contains</span>
            <textarea data-bind="config.tools.${index}.required_path_contains" data-format="array">${escapeHtml(tool.required_path_contains.join(", "))}</textarea>
          </label>
          <label class="field">
            <span>path_rule</span>
            <input type="text" data-bind="config.tools.${index}.path_rule" value="${escapeAttribute(tool.path_rule)}">
          </label>
          <label class="field">
            <span>approver</span>
            <input type="text" data-bind="config.tools.${index}.approver" value="${escapeAttribute(tool.approver)}">
          </label>
          <label class="toggle-row">
            <span>approval_required</span>
            <input type="checkbox" data-bind="config.tools.${index}.approval_required" ${tool.approval_required ? "checked" : ""}>
          </label>
          <label class="toggle-row">
            <span>route_hijack_check</span>
            <input type="checkbox" data-bind="config.tools.${index}.route_hijack_check" ${tool.route_hijack_check ? "checked" : ""}>
          </label>
          <label class="field">
            <span>说明</span>
            <textarea data-bind="config.tools.${index}.notes">${escapeHtml(tool.notes)}</textarea>
          </label>
        </article>
      `
    )
    .join("");
}

function renderPathEditor() {
  const container = document.getElementById("pathEditor");
  container.innerHTML = state.config.paths
    .map(
      (path, index) => `
        <article class="entity-card">
          <div class="entity-head">
            <h4>${escapeHtml(path.name || `Path ${index + 1}`)}</h4>
            <button class="button tertiary" type="button" data-remove-path="${index}">删除</button>
          </div>
          <label class="field">
            <span>名称</span>
            <input type="text" data-bind="config.paths.${index}.name" value="${escapeAttribute(path.name)}">
          </label>
          <label class="field">
            <span>sequence</span>
            <textarea data-bind="config.paths.${index}.sequence" data-format="array">${escapeHtml(path.sequence.join(", "))}</textarea>
          </label>
          <label class="toggle-row">
            <span>strict</span>
            <input type="checkbox" data-bind="config.paths.${index}.strict" ${path.strict ? "checked" : ""}>
          </label>
        </article>
      `
    )
    .join("");
}

function renderYamlPreview() {
  document.getElementById("yamlPreview").textContent = buildYaml(state.config);
}

function renderLogs() {
  const container = document.getElementById("logStream");
  const logs = getVisibleLogs();

  if (!state.config.ui.show_log_stream) {
    container.innerHTML = `<div class="empty-state">日志流已在配置中关闭展示。</div>`;
    return;
  }

  if (!logs.length) {
    container.innerHTML = `<div class="empty-state">没有匹配的日志条目。</div>`;
    return;
  }

  container.innerHTML = logs
    .map(
      (log) => `
        <article class="log-entry">
          <div class="log-entry-head">
            <div class="log-entry-meta">
              <span class="status-pill ${log.level === "error" ? "blocked" : log.level === "warn" ? "review" : "allowed"}">${log.level.toUpperCase()}</span>
              <span class="meta-pill">${escapeHtml(log.framework)}</span>
              <span class="meta-pill">${escapeHtml(log.traceId)}</span>
              <span class="meta-pill">${escapeHtml(log.category)}</span>
            </div>
            <span class="meta-pill">${escapeHtml(formatTimestamp(log.timestamp))}</span>
          </div>
          <p><strong>${escapeHtml(log.title)}</strong></p>
          <p>${escapeHtml(log.message)}</p>
        </article>
      `
    )
    .join("");
}

function getVisibleWorkflows() {
  return state.workflows.filter((workflow) => {
    if (state.filters.workflowFramework !== "all" && workflow.framework !== state.filters.workflowFramework) {
      return false;
    }
    if (state.filters.workflowStatus !== "all" && workflow.status !== state.filters.workflowStatus) {
      return false;
    }
    return true;
  });
}

function getActiveWorkflow() {
  const visible = getVisibleWorkflows();
  return visible.find((workflow) => workflow.id === state.activeWorkflowId) || visible[0] || null;
}

function getAllLogs() {
  const logs = [];
  state.workflows.forEach((workflow) => {
    workflow.events.forEach((event) => {
      logs.push({
        level: workflow.status === "blocked" && event.event_type === "tool_call" ? "warn" : "info",
        framework: workflow.framework,
        traceId: workflow.traceId,
        category: event.event_type,
        timestamp: event.timestamp,
        title: formatEventTitle(event),
        message: `${formatEventActors(event)} | ${event.content || "无正文"}`,
      });
    });
    workflow.decisions.forEach((decision, index) => {
      logs.push({
        level: decision.allow ? (workflow.status === "review" ? "warn" : "info") : "error",
        framework: workflow.framework,
        traceId: workflow.traceId,
        category: `decision_${index + 1}`,
        timestamp: workflow.events[workflow.events.length - 1]?.timestamp || workflow.startedAt,
        title: decision.allow ? "审核放行 / 复核建议" : "SecurityCore 阻断",
        message: `${decision.reason} ${decision.suggested_alternative ? `建议: ${decision.suggested_alternative}` : ""}`.trim(),
      });
    });
  });
  return logs.sort((a, b) => (a.timestamp < b.timestamp ? 1 : -1));
}

function getVisibleLogs() {
  const query = state.filters.logQuery.trim().toLowerCase();
  return getAllLogs().filter((log) => {
    if (state.filters.logLevel !== "all" && log.level !== state.filters.logLevel) {
      return false;
    }
    if (state.filters.logFramework !== "all" && log.framework !== state.filters.logFramework) {
      return false;
    }
    if (!query) {
      return true;
    }
    const haystack = `${log.traceId} ${log.title} ${log.message} ${log.category}`.toLowerCase();
    return haystack.includes(query);
  });
}

function openHistoryDialog(workflowId, eventId) {
  const workflow = state.workflows.find((item) => item.id === workflowId);
  const dialog = document.getElementById("historyDialog");
  const title = document.getElementById("historyDialogTitle");
  const body = document.getElementById("historyDialogBody");

  if (!workflow) {
    return;
  }

  title.textContent = `${workflow.name} / ${workflow.traceId}`;
  const rows = workflow.events
    .map((event) => {
      const highlighted = event.id === eventId;
      return `
        <article class="history-row ${highlighted ? "is-highlighted" : ""}">
          <div class="workflow-card-head">
            <h4>${escapeHtml(formatEventTitle(event))}</h4>
            <span class="meta-pill">${escapeHtml(formatTimestamp(event.timestamp))}</span>
          </div>
          <div class="timeline-card-meta">
            <span>${escapeHtml(formatEventActors(event))}</span>
            ${event.tool_name ? `<span>tool: ${escapeHtml(event.tool_name)}</span>` : ""}
          </div>
          <p class="detail-paragraph">${escapeHtml(event.content || "无正文")}</p>
          <div class="history-summary">
            <strong>history_summary</strong>
            <div>${escapeHtml(event.history_summary || "无")}</div>
          </div>
        </article>
      `;
    })
    .join("");

  body.innerHTML = `
    <section class="history-row">
      <div class="workflow-card-head">
        <h4>${escapeHtml(workflow.name)}</h4>
        <span class="status-pill ${STATUS_META[workflow.status].tone}">${STATUS_META[workflow.status].label}</span>
      </div>
      <p class="detail-paragraph">${escapeHtml(workflow.decision.reason)}</p>
      <div class="decision-strip">
        ${(workflow.decision.blocking_risk_types || [])
          .map((tag) => `<span class="tag ${workflow.status === "blocked" ? "risk" : "warn"}">${escapeHtml(getRiskLabel(tag))}</span>`)
          .join("")}
      </div>
    </section>
    ${rows}
  `;

  if (dialog.open) {
    return;
  }

  if (typeof dialog.showModal === "function") {
    dialog.showModal();
  } else {
    dialog.setAttribute("open", "open");
  }
}

function focusFirstBlockedWorkflow() {
  const blocked = state.workflows.find((workflow) => workflow.status === "blocked");
  if (!blocked) {
    return;
  }

  state.filters.workflowFramework = "all";
  state.filters.workflowStatus = "all";
  state.activeWorkflowId = blocked.id;
  renderAll();
  persistState();
  const detail = document.getElementById("workflowDetail");
  if (detail && typeof detail.scrollIntoView === "function") {
    detail.scrollIntoView({ behavior: "smooth", block: "start" });
  }
}

function resetConfig() {
  if (state.source.mode === "filesystem" && state.source.serverAvailable) {
    loadFilesystemData({ silent: true });
    return;
  }
  switchToDemoMode({ keepFilters: false });
  setYamlStatus("已恢复为默认展示配置。");
}

async function bootstrapServerDiscovery() {
  state.source.loading = true;
  renderAll();

  try {
    const payload = await fetchJson(`${getApiBase()}/api/discover`);
    state.source.apiBase = getApiBase();
    state.source.serverAvailable = true;
    state.source.repoRoot = payload.repoRoot || "";
    state.source.policyFiles = Array.isArray(payload.policyFiles) ? payload.policyFiles : [];
    state.source.workflowDirs = Array.isArray(payload.workflowDirs) ? payload.workflowDirs : [];
    state.source.selectedPolicyPath = state.source.selectedPolicyPath || payload.defaultPolicyPath || "";
    state.source.selectedWorkflowDir = state.source.selectedWorkflowDir || payload.defaultWorkflowDir || "";
    if (state.source.selectedPolicyPath && !state.source.policyFiles.includes(state.source.selectedPolicyPath)) {
      state.source.selectedPolicyPath = payload.defaultPolicyPath || state.source.policyFiles[0] || "";
    }
    if (state.source.selectedWorkflowDir && !state.source.workflowDirs.includes(state.source.selectedWorkflowDir)) {
      state.source.selectedWorkflowDir = payload.defaultWorkflowDir || state.source.workflowDirs[0] || "";
    }
    state.source.lastError = "";
    state.source.watchExists = Boolean(state.source.selectedWorkflowDir);
    state.source.lastMessage = payload.workflowDirs.length
      ? "已发现可读取的 policy.yaml 和 workflow 目录。"
      : "已连接本地服务，但当前仓库里还没有 audit_logs/workflows 目录。";
    if (!payload.workflowDirs.length) {
      stopWorkflowWatcher("当前仓库里还没有可监听的 audit_logs/workflows 目录。");
    }
  } catch (error) {
    state.source.serverAvailable = false;
    state.source.policyFiles = [];
    state.source.workflowDirs = [];
    state.source.lastError = error.message;
    state.source.lastMessage = "未连接到本地服务，当前仅能使用内置演示数据。";
    state.source.watchExists = false;
    stopWorkflowWatcher("本地服务不可用，自动监听已暂停。");
  } finally {
    state.source.loading = false;
    renderAll();
    persistState();
  }
}

async function loadFilesystemData(options = {}) {
  const { silent = false, preserveActiveWorkflowId = false } = options;
  if (!state.source.serverAvailable) {
    await bootstrapServerDiscovery();
  }

  if (!state.source.serverAvailable) {
    stopWorkflowWatcher("本地服务未启动，无法自动监听真实 workflow。");
    renderAll();
    persistState();
    if (!silent) {
      setYamlStatus("本地服务未启动，暂时无法读取真实文件。");
    }
    return;
  }

  state.source.loading = true;
  renderAll();

  try {
    const previousActiveWorkflowId = preserveActiveWorkflowId ? state.activeWorkflowId : "";
    const queryString = buildFilesystemQueryString();
    const payload = await fetchJson(`${getApiBase()}/api/filesystem${queryString ? `?${queryString}` : ""}`);
    const policyText = payload.policyText || "";
    const policyObject = payload.policyObject || parseSimpleYaml(policyText);
    const humanReview = Number((policyObject.thresholds && policyObject.thresholds.human_review) || 0.75);
    const nextWorkflows = Array.isArray(payload.workflows) && payload.workflows.length
      ? payload.workflows
      : normalizeRawWorkflows(payload.rawWorkflows || [], humanReview);

    state.config = buildConfigFromPolicy(policyObject, policyText);
    state.workflows = nextWorkflows;
    state.activeWorkflowId = preserveActiveWorkflowId && nextWorkflows.find((workflow) => workflow.id === previousActiveWorkflowId)
      ? previousActiveWorkflowId
      : (nextWorkflows[0] ? nextWorkflows[0].id : "");
    state.source.mode = "filesystem";
    state.source.selectedPolicyPath = payload.policyPath || state.source.selectedPolicyPath;
    state.source.selectedWorkflowDir = payload.workflowDir || state.source.selectedWorkflowDir;
    state.source.rawPolicyText = payload.policyText || "";
    state.source.lastSync = payload.loadedAt || new Date().toISOString().replace("T", " ").slice(0, 19);
    state.source.lastError = "";
    state.source.lastMessage = nextWorkflows.length
      ? `已读取 ${nextWorkflows.length} 个真实 workflow，并装载策略文件。`
      : "策略文件已装载，但当前 workflow 目录中还没有 JSON 日志。";
    applyWorkflowWatchSummary(payload.watchSummary);
    state.source.watchStatus = getDefaultWatchStatus();
    normalizeState();
    renderAll();
    persistState();
    await configureWorkflowWatcher();
    if (!silent) {
      setYamlStatus(`已从真实文件载入策略：${state.source.selectedPolicyPath || "未命名 policy.yaml"}`);
    }
  } catch (error) {
    state.source.lastError = error.message;
    state.source.lastMessage = "读取真实文件失败，当前保留原有数据。";
    stopWorkflowWatcher("自动监听暂时不可用，请稍后重试。");
    renderAll();
    persistState();
    if (!silent) {
      setYamlStatus("读取真实文件失败，请确认本地服务已启动且策略路径有效。");
    }
  } finally {
    state.source.loading = false;
    renderAll();
    persistState();
  }
}

function switchToDemoMode(options = {}) {
  const { keepFilters = true } = options;
  const fresh = createDefaultState();
  state.config = fresh.config;
  state.workflows = fresh.workflows;
  state.activeWorkflowId = fresh.activeWorkflowId;
  if (!keepFilters) {
    state.filters = fresh.filters;
  }
  state.source.mode = "demo";
  state.source.rawPolicyText = "";
  state.source.lastError = "";
  state.source.lastMessage = "当前使用内置演示数据。";
  stopWorkflowWatcher("演示模式下已暂停自动监听。");
  normalizeState();
  renderAll();
  persistState();
}

async function configureWorkflowWatcher(options = {}) {
  const { immediate = false } = options;

  clearWorkflowWatcher();

  if (!state.source.autoRefreshEnabled) {
    state.source.watchStatus = "自动监听已关闭。";
    renderAll();
    persistState();
    return;
  }

  if (state.source.mode !== "filesystem") {
    state.source.watchStatus = "切换到真实文件模式后将开始监听。";
    renderAll();
    persistState();
    return;
  }

  if (!state.source.serverAvailable) {
    state.source.watchStatus = "本地服务不可用，无法自动监听。";
    renderAll();
    persistState();
    return;
  }

  if (!state.source.selectedWorkflowDir) {
    state.source.watchExists = false;
    state.source.watchStatus = "当前未选择 workflow 目录。";
    renderAll();
    persistState();
    return;
  }

  state.source.watchStatus = getDefaultWatchStatus();
  workflowWatchTimer = window.setInterval(() => {
    void pollWorkflowChanges();
  }, state.source.autoRefreshIntervalMs);

  renderAll();
  persistState();

  if (immediate) {
    await pollWorkflowChanges();
  }
}

function clearWorkflowWatcher() {
  if (workflowWatchTimer !== null) {
    window.clearInterval(workflowWatchTimer);
    workflowWatchTimer = null;
  }
}

function stopWorkflowWatcher(statusMessage = "") {
  clearWorkflowWatcher();
  if (statusMessage) {
    state.source.watchStatus = statusMessage;
  }
}

async function pollWorkflowChanges() {
  if (workflowWatchPending) {
    return;
  }

  if (!state.source.autoRefreshEnabled || state.source.mode !== "filesystem" || !state.source.serverAvailable) {
    return;
  }

  workflowWatchPending = true;

  try {
    const queryString = buildFilesystemQueryString({ includePolicy: false });
    const payload = await fetchJson(`${getApiBase()}/api/workflow-watch${queryString ? `?${queryString}` : ""}`);
    const previousFingerprint = state.source.watchFingerprint;

    applyWorkflowWatchSummary(payload);

    if (previousFingerprint && payload.fingerprint && payload.fingerprint !== previousFingerprint) {
      state.source.watchLastChange = payload.latestModified || payload.scannedAt || formatCurrentTimestamp();
      state.source.watchStatus = payload.workflowCount
        ? `检测到 workflow 更新，正在自动刷新 ${payload.workflowCount} 个 JSON...`
        : "检测到 workflow 目录变化，正在重新加载...";
      renderAll();
      persistState();

      await loadFilesystemData({ silent: true, preserveActiveWorkflowId: true });

      state.source.watchStatus = getDefaultWatchStatus();
      renderAll();
      persistState();
      return;
    }

    state.source.watchStatus = getDefaultWatchStatus();
    renderAll();
    persistState();
  } catch (error) {
    state.source.lastError = error.message;
    state.source.watchStatus = "自动监听失败，将在下一轮继续重试。";
    renderAll();
    persistState();
  } finally {
    workflowWatchPending = false;
  }
}

function buildFilesystemQueryString(options = {}) {
  const { includePolicy = true } = options;
  const params = new URLSearchParams();

  if (includePolicy && state.source.selectedPolicyPath) {
    params.set("policyPath", state.source.selectedPolicyPath);
  }
  if (state.source.selectedWorkflowDir) {
    params.set("workflowDir", state.source.selectedWorkflowDir);
  }

  return params.toString();
}

function applyWorkflowWatchSummary(summary) {
  if (!summary || typeof summary !== "object") {
    return;
  }

  if (typeof summary.workflowDir === "string") {
    state.source.selectedWorkflowDir = String(summary.workflowDir);
  }

  state.source.watchFingerprint = String(summary.fingerprint || "");
  state.source.watchWorkflowCount = Number(summary.workflowCount || 0);
  state.source.watchExists = Boolean(summary.exists);
  state.source.watchLastChecked = String(summary.scannedAt || formatCurrentTimestamp());
}

function getDefaultWatchStatus() {
  if (!state.source.autoRefreshEnabled) {
    return "自动监听已关闭。";
  }
  if (state.source.mode !== "filesystem") {
    return "切换到真实文件模式后将开始监听。";
  }
  if (!state.source.serverAvailable) {
    return "本地服务不可用，无法自动监听。";
  }
  if (!state.source.selectedWorkflowDir) {
    return "当前未选择 workflow 目录。";
  }
  if (!state.source.watchExists) {
    return "当前 workflow 目录尚不可用，请重新扫描或切换目录。";
  }
  if (!state.source.watchWorkflowCount) {
    return `正在监听目录，每 ${getPollingIntervalLabel(state.source.autoRefreshIntervalMs)} 检查一次，等待新的 workflow.json。`;
  }
  return `正在监听 ${state.source.watchWorkflowCount} 个 workflow JSON，每 ${getPollingIntervalLabel(state.source.autoRefreshIntervalMs)} 检查一次。`;
}

function getPollingIntervalLabel(intervalMs) {
  return `${Math.max(1, Math.round(Number(intervalMs || 0) / 1000))}s`;
}

function formatCurrentTimestamp() {
  const now = new Date();
  return [
    now.getFullYear(),
    padNumber(now.getMonth() + 1),
    padNumber(now.getDate()),
  ].join("-") + ` ${padNumber(now.getHours())}:${padNumber(now.getMinutes())}:${padNumber(now.getSeconds())}`;
}

function padNumber(value) {
  return String(value).padStart(2, "0");
}

function downloadYaml() {
  const yaml = buildYaml(state.config);
  const blob = new Blob([yaml], { type: "text/yaml;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = "zero-trust-frontend-demo.yaml";
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
  setYamlStatus("YAML 已下载为 zero-trust-frontend-demo.yaml。");
}

function copyYaml() {
  const yaml = buildYaml(state.config);
  if (navigator.clipboard && window.isSecureContext) {
    navigator.clipboard.writeText(yaml).then(
      () => setYamlStatus("YAML 已复制到剪贴板。"),
      () => fallbackCopy(yaml)
    );
    return;
  }
  fallbackCopy(yaml);
}

function fallbackCopy(text) {
  const textarea = document.createElement("textarea");
  textarea.value = text;
  textarea.setAttribute("readonly", "readonly");
  textarea.style.position = "absolute";
  textarea.style.left = "-9999px";
  document.body.appendChild(textarea);
  textarea.select();
  try {
    document.execCommand("copy");
    setYamlStatus("YAML 已复制到剪贴板。");
  } catch (_error) {
    setYamlStatus("浏览器未允许自动复制，请直接从右侧 YAML 面板手动复制。");
  }
  textarea.remove();
}

function setYamlStatus(message) {
  document.getElementById("yamlStatus").textContent = message;
}

function buildYaml(config) {
  const lines = [];
  lines.push(`version: ${quoteYaml(config.version)}`);
  lines.push(`description: ${quoteYaml(config.description)}`);
  lines.push("");
  lines.push("frameworks:");
  lines.push(`  autogen: ${config.frameworks.autogen}`);
  lines.push(`  langgraph: ${config.frameworks.langgraph}`);
  lines.push(`  mas: ${config.frameworks.mas}`);
  lines.push("");
  lines.push("security_core:");
  lines.push(`  enabled: ${config.security_core.enabled}`);
  lines.push(`  entry_mode: ${quoteYaml(config.security_core.entry_mode)}`);
  lines.push(`  provider: ${quoteYaml(config.security_core.provider)}`);
  lines.push(`  model_name: ${quoteYaml(config.security_core.model_name)}`);
  lines.push(`  endpoint: ${quoteYaml(config.security_core.endpoint)}`);
  lines.push(`  local_model_path: ${quoteYaml(config.security_core.local_model_path)}`);
  lines.push(`  api_protocol: ${quoteYaml(config.security_core.api_protocol)}`);
  lines.push(`  api_key_env: ${quoteYaml(config.security_core.api_key_env)}`);
  lines.push(`  api_route: ${quoteYaml(config.security_core.api_route)}`);
  lines.push(`  api_timeout_ms: ${config.security_core.api_timeout_ms}`);
  lines.push(`  prompt_status: ${quoteYaml(config.security_core.prompt_status)}`);
  lines.push(`  audit_scope: ${quoteYaml(config.security_core.audit_scope)}`);
  lines.push(`  history_window: ${config.security_core.history_window}`);
  lines.push(`  log_level: ${quoteYaml(config.security_core.log_level)}`);
  lines.push("");
  lines.push("thresholds:");
  lines.push(`  rule_block: ${config.thresholds.rule_block.toFixed(2)}`);
  lines.push(`  human_review: ${config.thresholds.human_review.toFixed(2)}`);
  lines.push("");
  lines.push("ui:");
  lines.push(`  aesthetic: ${quoteYaml(config.ui.aesthetic)}`);
  lines.push(`  show_history_panel: ${config.ui.show_history_panel}`);
  lines.push(`  show_log_stream: ${config.ui.show_log_stream}`);
  lines.push(`  block_badge_mode: ${quoteYaml(config.ui.block_badge_mode)}`);
  lines.push("");
  lines.push("agents:");
  config.agents.forEach((agent) => {
    if (!agent.name) {
      return;
    }
    lines.push(`  ${safeKey(agent.name)}:`);
    lines.push(`    role: ${quoteYaml(agent.role || "")}`);
    lines.push(`    can_initiate: ${Boolean(agent.can_initiate)}`);
    lines.push(renderYamlArray("allowed_tools", agent.allowed_tools, 4));
    lines.push(renderYamlArray("blocked_tools", agent.blocked_tools, 4));
    lines.push(renderYamlArray("allowed_message_targets", agent.allowed_message_targets, 4));
    lines.push(`    notes: ${quoteYaml(agent.notes || "")}`);
  });
  lines.push("");
  lines.push("tools:");
  config.tools.forEach((tool) => {
    if (!tool.name) {
      return;
    }
    lines.push(`  ${safeKey(tool.name)}:`);
    lines.push(renderYamlArray("allowed_callers", tool.allowed_callers, 4));
    lines.push(renderYamlArray("required_path_contains", tool.required_path_contains, 4));
    lines.push(`    path_rule: ${quoteYaml(tool.path_rule || "")}`);
    lines.push(`    approval_required: ${Boolean(tool.approval_required)}`);
    lines.push(`    approver: ${quoteYaml(tool.approver || "")}`);
    lines.push(`    route_hijack_check: ${Boolean(tool.route_hijack_check)}`);
    lines.push(`    notes: ${quoteYaml(tool.notes || "")}`);
  });
  lines.push("");
  lines.push("paths:");
  config.paths.forEach((path) => {
    if (!path.name) {
      return;
    }
    lines.push(`  ${safeKey(path.name)}:`);
    lines.push(renderYamlArray("sequence", path.sequence, 4));
    lines.push(`    strict: ${Boolean(path.strict)}`);
  });
  return lines.join("\n");
}

function renderYamlArray(key, items, indent) {
  const baseIndent = " ".repeat(indent);
  if (!items || !items.length) {
    return `${baseIndent}${key}: []`;
  }
  return `${baseIndent}${key}:\n${items
    .map((item) => `${baseIndent}  - ${quoteYaml(item)}`)
    .join("\n")}`;
}

function syncFilterControls() {
  const mappings = {
    workflowFrameworkFilter: state.filters.workflowFramework,
    workflowStatusFilter: state.filters.workflowStatus,
    logLevelFilter: state.filters.logLevel,
    logFrameworkFilter: state.filters.logFramework,
    logSearchInput: state.filters.logQuery,
    sourceModeSelect: state.source.mode,
    policyPathSelect: state.source.selectedPolicyPath,
    workflowDirSelect: state.source.selectedWorkflowDir,
    autoRefreshToggle: state.source.autoRefreshEnabled,
    autoRefreshIntervalSelect: String(state.source.autoRefreshIntervalMs),
  };

  Object.entries(mappings).forEach(([id, value]) => {
    const element = document.getElementById(id);
    if (!element) {
      return;
    }
    if (element.type === "checkbox") {
      element.checked = Boolean(value);
    } else if (element.type === "text") {
      element.value = value;
    } else {
      element.value = value;
    }
  });
}

function parseList(rawValue) {
  return rawValue
    .split(/[\n,]+/)
    .map((item) => item.trim())
    .filter(Boolean);
}

function setByPath(root, path, value) {
  const segments = path.split(".");
  let cursor = root;
  for (let index = 0; index < segments.length - 1; index += 1) {
    const key = normalizePathKey(segments[index]);
    cursor = cursor[key];
  }
  const lastKey = normalizePathKey(segments[segments.length - 1]);
  cursor[lastKey] = value;
}

function normalizePathKey(segment) {
  return /^\d+$/.test(segment) ? Number(segment) : segment;
}

function formatEventTitle(event) {
  if (event.event_type === "tool_call") {
    return `调用 ${event.tool_name}`;
  }
  if (event.event_type === "tool_result") {
    return `返回 ${event.tool_name}`;
  }
  return `消息 ${event.sender}`;
}

function formatEventActors(event) {
  if (event.event_type === "tool_call") {
    return `${event.sender} -> ${event.tool_name}`;
  }
  if (event.event_type === "tool_result") {
    return `${event.tool_name} -> ${event.receiver || event.sender}`;
  }
  return `${event.sender} -> ${event.receiver || "Workflow"}`;
}

function formatTimestamp(value) {
  return value.replace("T", " ").replace("Z", "");
}

function getRiskLabel(tag) {
  return RISK_LABELS[tag] || tag;
}

function createEmptyAgent() {
  return {
    name: "New_Agent",
    role: "worker_agent",
    can_initiate: false,
    allowed_tools: [],
    blocked_tools: [],
    allowed_message_targets: [],
    notes: "新建 Agent",
  };
}

function createEmptyTool() {
  return {
    name: "new_tool",
    allowed_callers: [],
    required_path_contains: [],
    path_rule: "",
    approval_required: false,
    approver: "",
    route_hijack_check: false,
    notes: "新建 Tool",
  };
}

function createEmptyPath() {
  return {
    name: "new_path",
    sequence: [],
    strict: false,
  };
}

function removeAt(list, index) {
  if (list.length <= 1) {
    return;
  }
  list.splice(index, 1);
}

function normalizeState() {
  state.source.policyFiles = Array.isArray(state.source.policyFiles)
    ? state.source.policyFiles.filter((item) => typeof item === "string")
    : [];
  state.source.workflowDirs = Array.isArray(state.source.workflowDirs)
    ? state.source.workflowDirs.filter((item) => typeof item === "string")
    : [];
  state.source.selectedPolicyPath = typeof state.source.selectedPolicyPath === "string"
    ? state.source.selectedPolicyPath
    : "";
  state.source.selectedWorkflowDir = typeof state.source.selectedWorkflowDir === "string"
    ? state.source.selectedWorkflowDir
    : "";
  state.source.autoRefreshEnabled = Boolean(state.source.autoRefreshEnabled);
  state.source.autoRefreshIntervalMs = Number(state.source.autoRefreshIntervalMs) || 3000;
  state.config.security_core.entry_mode = typeof state.config.security_core.entry_mode === "string"
    ? state.config.security_core.entry_mode
    : "local_model";
  state.config.security_core.api_protocol = typeof state.config.security_core.api_protocol === "string"
    ? state.config.security_core.api_protocol
    : "openai_compatible";
  state.config.security_core.api_key_env = typeof state.config.security_core.api_key_env === "string"
    ? state.config.security_core.api_key_env
    : "ZERO_TRUST_API_KEY";
  state.config.security_core.api_route = typeof state.config.security_core.api_route === "string"
    ? state.config.security_core.api_route
    : "/chat/completions";
  state.config.security_core.api_timeout_ms = Number(state.config.security_core.api_timeout_ms) || 30000;
  state.config.security_core.prompt_status = typeof state.config.security_core.prompt_status === "string"
    ? state.config.security_core.prompt_status
    : "pending";
  state.config.ui.aesthetic = typeof state.config.ui.aesthetic === "string"
    ? state.config.ui.aesthetic
    : "apple-nasa-hybrid";

  const visibleWorkflows = getVisibleWorkflows();
  if (!visibleWorkflows.find((workflow) => workflow.id === state.activeWorkflowId)) {
    state.activeWorkflowId = (visibleWorkflows[0] && visibleWorkflows[0].id)
      || (state.workflows[0] && state.workflows[0].id)
      || "";
  }
}

function persistState() {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(state));
  } catch (_error) {
    // Ignore storage issues in file protocol or private mode.
  }
}

function loadState() {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) {
      return null;
    }
    return JSON.parse(raw);
  } catch (_error) {
    return null;
  }
}

function getApiBase() {
  if (window.location.protocol === "file:") {
    return DEFAULT_SERVER_ORIGIN;
  }
  return "";
}

async function fetchJson(url) {
  const response = await fetch(url, {
    headers: {
      Accept: "application/json",
    },
  });
  if (!response.ok) {
    throw new Error(`HTTP ${response.status}`);
  }
  return response.json();
}

function buildConfigFromPolicy(policyObject, policyText) {
  const fresh = createDefaultState();
  const config = deepMerge(fresh.config, {});

  if (policyObject.version !== undefined) {
    config.version = String(policyObject.version);
  }
  if (policyObject.description !== undefined) {
    config.description = String(policyObject.description);
  }

  if (policyObject.thresholds && typeof policyObject.thresholds === "object") {
    config.thresholds.rule_block = Number(policyObject.thresholds.rule_block ?? config.thresholds.rule_block);
    config.thresholds.human_review = Number(policyObject.thresholds.human_review ?? config.thresholds.human_review);
  }

  if (policyObject.frameworks && typeof policyObject.frameworks === "object") {
    config.frameworks.autogen = Boolean(policyObject.frameworks.autogen ?? config.frameworks.autogen);
    config.frameworks.langgraph = Boolean(policyObject.frameworks.langgraph ?? config.frameworks.langgraph);
    config.frameworks.mas = Boolean(policyObject.frameworks.mas ?? config.frameworks.mas);
  }

  if (policyObject.security_core && typeof policyObject.security_core === "object") {
    config.security_core.enabled = Boolean(policyObject.security_core.enabled ?? config.security_core.enabled);
    config.security_core.entry_mode = String(policyObject.security_core.entry_mode || config.security_core.entry_mode);
    config.security_core.provider = String(policyObject.security_core.provider || config.security_core.provider);
    config.security_core.model_name = String(policyObject.security_core.model_name || config.security_core.model_name);
    config.security_core.endpoint = String(policyObject.security_core.endpoint || config.security_core.endpoint);
    config.security_core.local_model_path = String(policyObject.security_core.local_model_path || config.security_core.local_model_path);
    config.security_core.api_protocol = String(policyObject.security_core.api_protocol || config.security_core.api_protocol);
    config.security_core.api_key_env = String(policyObject.security_core.api_key_env || config.security_core.api_key_env);
    config.security_core.api_route = String(policyObject.security_core.api_route || config.security_core.api_route);
    config.security_core.api_timeout_ms = Number(policyObject.security_core.api_timeout_ms ?? config.security_core.api_timeout_ms);
    config.security_core.prompt_status = String(policyObject.security_core.prompt_status || config.security_core.prompt_status);
    config.security_core.audit_scope = String(policyObject.security_core.audit_scope || config.security_core.audit_scope);
    config.security_core.history_window = Number(policyObject.security_core.history_window ?? config.security_core.history_window);
    config.security_core.log_level = String(policyObject.security_core.log_level || config.security_core.log_level);
  }

  if (policyObject.ui && typeof policyObject.ui === "object") {
    config.ui.aesthetic = String(policyObject.ui.aesthetic || config.ui.aesthetic);
    config.ui.show_history_panel = Boolean(policyObject.ui.show_history_panel ?? config.ui.show_history_panel);
    config.ui.show_log_stream = Boolean(policyObject.ui.show_log_stream ?? config.ui.show_log_stream);
    config.ui.block_badge_mode = String(policyObject.ui.block_badge_mode || config.ui.block_badge_mode);
  }

  config.agents = objectEntries(policyObject.agents).map(([name, agent]) => ({
    name,
    role: String(agent.role || ""),
    can_initiate: Boolean(agent.can_initiate),
    allowed_tools: normalizeArray(agent.allowed_tools),
    blocked_tools: normalizeArray(agent.blocked_tools),
    allowed_message_targets: normalizeArray(agent.allowed_message_targets),
    notes: String(agent.notes || ""),
  }));

  config.tools = objectEntries(policyObject.tools).map(([name, tool]) => ({
    name,
    allowed_callers: normalizeArray(tool.allowed_callers),
    required_path_contains: normalizeArray(tool.required_path_contains),
    path_rule: String(tool.path_rule || ""),
    approval_required: Boolean(tool.approval_required),
    approver: String(tool.approver || ""),
    route_hijack_check: Boolean(tool.route_hijack_check),
    notes: String(tool.notes || ""),
  }));

  config.paths = objectEntries(policyObject.paths).map(([name, pathDef]) => ({
    name,
    sequence: normalizeArray(pathDef.sequence),
    strict: Boolean(pathDef.strict),
  }));

  if (!config.agents.length && policyText) {
    config.agents = [];
  }
  if (!config.tools.length && policyText) {
    config.tools = [];
  }
  if (!config.paths.length && policyText) {
    config.paths = [];
  }

  if (!policyObject.frameworks) {
    config.frameworks = inferFrameworkFlagsFromText(policyText);
  }
  return config;
}

function inferFrameworkFlagsFromText(policyText) {
  const text = String(policyText || "").toLowerCase();
  return {
    autogen: text.includes("autogen") || text.includes("agent_a") || text.includes("userproxy"),
    langgraph: text.includes("langgraph") || text.includes("stats_node") || text.includes("confignode"),
    mas: text.includes("mas") || text.includes("trader_agent") || text.includes("compliance_agent"),
  };
}

function objectEntries(value) {
  return value && typeof value === "object" && !Array.isArray(value)
    ? Object.entries(value)
    : [];
}

function normalizeArray(value) {
  if (Array.isArray(value)) {
    return value.map((item) => String(item));
  }
  if (value === undefined || value === null || value === "") {
    return [];
  }
  return [String(value)];
}

function normalizeRawWorkflows(rawWorkflows, humanReview) {
  return Array.isArray(rawWorkflows)
    ? rawWorkflows
      .map((item) => normalizeRawWorkflow(item, humanReview))
      .filter(Boolean)
    : [];
}

function normalizeRawWorkflow(rawItem, humanReview) {
  if (!rawItem || !rawItem.data) {
    return null;
  }

  const data = rawItem.data;
  const events = Array.isArray(data.events) ? data.events : [];
  const decisions = Array.isArray(data.decisions) ? data.decisions : [];
  const latestDecision = decisions[decisions.length - 1] || {
    allow: !data.blocked,
    risk_score: data.blocked ? 0.9 : 0,
    reason: data.blocked_reason || "未找到显式 decision，使用 workflow 顶层状态回退。",
    blocking_risk_types: [],
    suggested_alternative: null,
    trajectory_score: null,
  };

  const blocked = Boolean(data.blocked || latestDecision.allow === false);
  const riskScore = Number(latestDecision.risk_score || 0);
  const status = blocked ? "blocked" : riskScore >= humanReview ? "review" : "allowed";
  const firstEvent = events[0] || {};
  const traceId = String(data.trace_id || firstEvent.trace_id || rawItem.filePath || "workflow");
  const framework = inferWorkflowFramework(rawItem.filePath || "", events);
  const callPath = extractWorkflowCallPath(events);
  const latencyMs = estimateWorkflowLatency(events);
  const name = String(rawItem.name || fileStem(rawItem.filePath || "workflow"));

  return {
    id: safeIdFromString(rawItem.filePath || name),
    name,
    framework,
    sceneName: name,
    status,
    traceId,
    startedAt: formatTimestamp(firstEvent.timestamp || data.timestamp || ""),
    latencyMs,
    summary: blocked
      ? String(data.blocked_reason || latestDecision.reason || `${name} 已被阻断。`)
      : String(latestDecision.reason || `${name} 共记录 ${events.length} 个事件。`),
    callPath,
    blockedReason: String(data.blocked_reason || ""),
    decision: normalizeDecisionShape(latestDecision),
    events: events.map((event, index) => normalizeWorkflowEvent(event, rawItem.filePath || name, index)),
    decisions: decisions.length ? decisions.map((decision) => normalizeDecisionShape(decision)) : [normalizeDecisionShape(latestDecision)],
    sourcePath: rawItem.filePath || "",
  };
}

function normalizeDecisionShape(decision) {
  return {
    allow: Boolean(decision.allow),
    risk_score: Number(decision.risk_score || 0),
    reason: String(decision.reason || ""),
    blocking_risk_types: Array.isArray(decision.blocking_risk_types) ? decision.blocking_risk_types.map(String) : [],
    suggested_alternative: decision.suggested_alternative ? String(decision.suggested_alternative) : null,
    trajectory_score: decision.trajectory_score == null ? null : Number(decision.trajectory_score),
  };
}

function normalizeWorkflowEvent(event, filePath, index) {
  return {
    id: String(event.event_id || `${safeIdFromString(filePath)}-${index + 1}`),
    event_type: String(event.event_type || "message"),
    sender: String(event.sender || ""),
    receiver: event.receiver == null ? null : String(event.receiver),
    tool_name: event.tool_name == null ? null : String(event.tool_name),
    tool_args: event.tool_args || null,
    call_path: Array.isArray(event.call_path) ? event.call_path.map(String) : [],
    content: event.content == null ? "" : String(event.content),
    history_summary: event.history_summary == null ? "" : String(event.history_summary),
    task: event.task == null ? "" : String(event.task),
    trace_id: event.trace_id == null ? "" : String(event.trace_id),
    timestamp: event.timestamp == null ? "" : String(event.timestamp),
    metadata: event.metadata || {},
  };
}

function inferWorkflowFramework(filePath, events) {
  const metadataFramework = events
    .map((event) => event && event.metadata && event.metadata.framework)
    .find(Boolean);
  if (metadataFramework) {
    return normalizeFrameworkLabel(metadataFramework);
  }

  const lower = String(filePath || "").toLowerCase();
  if (lower.includes("langgraph")) {
    return "LangGraph";
  }
  if (lower.includes("autogen")) {
    return "AutoGen";
  }
  if (lower.includes("\\mas\\") || lower.includes("/mas/") || lower.includes("crewai")) {
    return "MAS";
  }
  return "Workflow";
}

function normalizeFrameworkLabel(value) {
  const lower = String(value || "").toLowerCase();
  if (lower.includes("langgraph")) {
    return "LangGraph";
  }
  if (lower.includes("autogen")) {
    return "AutoGen";
  }
  if (lower.includes("mas") || lower.includes("crewai")) {
    return "MAS";
  }
  return String(value || "Workflow");
}

function extractWorkflowCallPath(events) {
  const candidate = [...events].reverse().find((event) => Array.isArray(event.call_path) && event.call_path.length);
  return candidate ? candidate.call_path.map(String) : [];
}

function estimateWorkflowLatency(events) {
  if (!events.length) {
    return 0;
  }
  const first = Date.parse(events[0].timestamp || "");
  const last = Date.parse(events[events.length - 1].timestamp || "");
  if (Number.isNaN(first) || Number.isNaN(last) || last < first) {
    return 0;
  }
  return last - first;
}

function safeIdFromString(value) {
  return String(value || "workflow").replace(/[^A-Za-z0-9]+/g, "-").replace(/^-+|-+$/g, "");
}

function fileStem(filePath) {
  const parts = String(filePath || "").split(/[\\/]/);
  const filename = parts[parts.length - 1] || "workflow";
  return filename.replace(/\.[^.]+$/, "");
}

function parseSimpleYaml(text) {
  const lines = String(text || "")
    .replace(/^\uFEFF/, "")
    .replace(/\r\n/g, "\n")
    .split("\n")
    .map((line) => stripYamlComment(line));

  let index = 0;

  function parseBlock(indent) {
    let result = null;

    while (index < lines.length) {
      const rawLine = lines[index];
      if (!rawLine.trim()) {
        index += 1;
        continue;
      }

      const currentIndent = countIndent(rawLine);
      if (currentIndent < indent) {
        break;
      }
      if (currentIndent > indent) {
        break;
      }

      const trimmed = rawLine.trim();
      if (trimmed.startsWith("- ")) {
        if (result == null) {
          result = [];
        }
        const itemText = trimmed.slice(2).trim();
        index += 1;
        if (!itemText) {
          result.push(parseBlock(indent + 2));
        } else {
          result.push(parseYamlScalar(itemText));
        }
        continue;
      }

      if (result == null) {
        result = {};
      }

      const separatorIndex = trimmed.indexOf(":");
      if (separatorIndex === -1) {
        index += 1;
        continue;
      }

      const key = trimmed.slice(0, separatorIndex).trim();
      const valueText = trimmed.slice(separatorIndex + 1).trim();
      index += 1;

      if (!valueText) {
        const child = parseBlock(indent + 2);
        result[key] = child == null ? {} : child;
      } else {
        result[key] = parseYamlScalar(valueText);
      }
    }

    return result;
  }

  return parseBlock(0) || {};
}

function stripYamlComment(line) {
  let inSingle = false;
  let inDouble = false;
  for (let index = 0; index < line.length; index += 1) {
    const character = line[index];
    if (character === "'" && !inDouble) {
      inSingle = !inSingle;
    } else if (character === '"' && !inSingle) {
      inDouble = !inDouble;
    } else if (character === "#" && !inSingle && !inDouble) {
      if (index === 0 || /\s/.test(line[index - 1])) {
        return line.slice(0, index).replace(/\s+$/, "");
      }
    }
  }
  return line;
}

function countIndent(line) {
  const match = line.match(/^ */);
  return match ? match[0].length : 0;
}

function parseYamlScalar(value) {
  const trimmed = String(value || "").trim();
  if (trimmed === "[]") {
    return [];
  }
  if (trimmed === "{}") {
    return {};
  }
  if (trimmed === "true") {
    return true;
  }
  if (trimmed === "false") {
    return false;
  }
  if (/^-?\d+(\.\d+)?$/.test(trimmed)) {
    return Number(trimmed);
  }
  if ((trimmed.startsWith('"') && trimmed.endsWith('"')) || (trimmed.startsWith("'") && trimmed.endsWith("'"))) {
    return trimmed.slice(1, -1);
  }
  return trimmed;
}

function hydrateState(maybeState) {
  const defaults = createDefaultState();
  if (!maybeState) {
    return defaults;
  }
  return deepMerge(defaults, maybeState);
}

function deepMerge(base, override) {
  if (Array.isArray(base)) {
    return Array.isArray(override) ? override : base;
  }

  if (base && typeof base === "object") {
    const result = { ...base };
    if (!override || typeof override !== "object") {
      return result;
    }
    Object.keys(override).forEach((key) => {
      if (!(key in result)) {
        result[key] = override[key];
        return;
      }
      result[key] = deepMerge(result[key], override[key]);
    });
    return result;
  }

  return override === undefined ? base : override;
}

function quoteYaml(value) {
  return `"${String(value).replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`;
}

function safeKey(value) {
  return String(value).replace(/[^A-Za-z0-9_\-]/g, "_");
}

function escapeHtml(value) {
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function escapeAttribute(value) {
  return escapeHtml(value ?? "");
}
