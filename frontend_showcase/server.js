const fs = require("fs");
const http = require("http");
const path = require("path");
const { URL } = require("url");

const FRONTEND_ROOT = __dirname;
const REPO_ROOT = path.resolve(__dirname, "..");
const PORT = Number(process.env.ZERO_TRUST_SHOWCASE_PORT || 48317);

const MIME_TYPES = {
  ".html": "text/html; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".js": "application/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".txt": "text/plain; charset=utf-8",
};

const server = http.createServer((request, response) => {
  const requestUrl = new URL(request.url, `http://${request.headers.host || "127.0.0.1"}`);

  if (requestUrl.pathname.startsWith("/api/")) {
    handleApi(requestUrl, response);
    return;
  }

  serveStatic(requestUrl.pathname, response);
});

server.listen(PORT, "127.0.0.1", () => {
  console.log(`Zero Trust Showcase listening on http://127.0.0.1:${PORT}`);
});

function handleApi(requestUrl, response) {
  try {
    if (requestUrl.pathname === "/api/discover") {
      writeJson(response, 200, discoverRepo());
      return;
    }

    if (requestUrl.pathname === "/api/filesystem") {
      const discovery = discoverRepo();
      const policyPath = requestUrl.searchParams.get("policyPath") || discovery.defaultPolicyPath || "";
      const workflowDir = requestUrl.searchParams.get("workflowDir") || discovery.defaultWorkflowDir || "";
      const policyText = policyPath && fs.existsSync(policyPath) ? fs.readFileSync(policyPath, "utf8") : "";
      const policyObject = policyText ? parseSimpleYaml(policyText) : {};
      const humanReview = Number((policyObject.thresholds && policyObject.thresholds.human_review) || 0.75);
      const workflowFiles = workflowDir && fs.existsSync(workflowDir)
        ? fs.readdirSync(workflowDir)
          .filter((fileName) => fileName.toLowerCase().endsWith(".json"))
          .map((fileName) => path.join(workflowDir, fileName))
        : [];
      const workflows = workflowFiles
        .map((filePath) => normalizeWorkflowFile(filePath, humanReview))
        .filter(Boolean);

      writeJson(response, 200, {
        repoRoot: REPO_ROOT,
        policyPath,
        workflowDir,
        workflowFiles,
        policyText,
        policyObject,
        workflows,
        loadedAt: new Date().toISOString().replace("T", " ").slice(0, 19),
      });
      return;
    }

    writeJson(response, 404, { error: "Not found" });
  } catch (error) {
    writeJson(response, 500, { error: error.message });
  }
}

function serveStatic(requestPath, response) {
  const normalized = requestPath === "/" ? "/index.html" : requestPath;
  const safePath = path.normalize(normalized).replace(/^(\.\.[/\\])+/, "");
  const filePath = path.join(FRONTEND_ROOT, safePath);

  if (!filePath.startsWith(FRONTEND_ROOT) || !fs.existsSync(filePath) || fs.statSync(filePath).isDirectory()) {
    response.writeHead(404, { "Content-Type": "text/plain; charset=utf-8" });
    response.end("Not found");
    return;
  }

  const extension = path.extname(filePath).toLowerCase();
  response.writeHead(200, {
    "Content-Type": MIME_TYPES[extension] || "application/octet-stream",
  });
  fs.createReadStream(filePath).pipe(response);
}

function writeJson(response, statusCode, payload) {
  response.writeHead(statusCode, {
    "Content-Type": "application/json; charset=utf-8",
    "Access-Control-Allow-Origin": "*",
    "Cache-Control": "no-store",
  });
  response.end(JSON.stringify(payload, null, 2));
}

function discoverRepo() {
  const policyFiles = [];
  const workflowDirs = [];

  walkDirectory(REPO_ROOT, (entryPath, stats) => {
    const lower = entryPath.toLowerCase();
    if (stats.isDirectory()) {
      if (path.basename(entryPath).toLowerCase() === "workflows" && lower.includes(`${path.sep}audit_logs${path.sep}`)) {
        workflowDirs.push(entryPath);
      }
      return;
    }

    if (stats.isFile() && path.basename(entryPath).toLowerCase() === "policy.yaml") {
      policyFiles.push(entryPath);
    }
  });

  policyFiles.sort();
  workflowDirs.sort();

  const defaultPolicyPath = policyFiles.find((item) => item.includes(`${path.sep}AutoGenAuditor${path.sep}`))
    || policyFiles[0]
    || "";
  const defaultWorkflowDir = workflowDirs[0] || "";

  return {
    repoRoot: REPO_ROOT,
    policyFiles,
    workflowDirs,
    defaultPolicyPath,
    defaultWorkflowDir,
  };
}

function walkDirectory(root, visitor) {
  const stack = [root];
  const skipNames = new Set([".git", "node_modules", "__pycache__"]);

  while (stack.length) {
    const current = stack.pop();
    let entries = [];
    try {
      entries = fs.readdirSync(current, { withFileTypes: true });
    } catch (_error) {
      continue;
    }

    entries.forEach((entry) => {
      const entryPath = path.join(current, entry.name);
      if (entry.isDirectory() && skipNames.has(entry.name)) {
        return;
      }

      let stats;
      try {
        stats = fs.statSync(entryPath);
      } catch (_error) {
        return;
      }

      visitor(entryPath, stats);

      if (stats.isDirectory()) {
        stack.push(entryPath);
      }
    });
  }
}

function normalizeWorkflowFile(filePath, humanReview) {
  let raw;
  try {
    raw = JSON.parse(fs.readFileSync(filePath, "utf8"));
  } catch (_error) {
    return null;
  }

  const events = Array.isArray(raw.events) ? raw.events : [];
  const decisions = Array.isArray(raw.decisions) ? raw.decisions : [];
  const latestDecision = decisions[decisions.length - 1] || buildFallbackDecision(raw);
  const blocked = Boolean(raw.blocked || latestDecision.allow === false);
  const riskScore = Number(latestDecision.risk_score || 0);
  const status = blocked ? "blocked" : riskScore >= humanReview ? "review" : "allowed";
  const traceId = String(raw.trace_id || events[0]?.trace_id || path.basename(filePath, ".json"));
  const framework = inferFramework(filePath, events);
  const callPath = extractCallPath(events);
  const latencyMs = estimateLatency(events);
  const startedAt = formatTimestamp(events[0]?.timestamp || raw.timestamp || "");
  const name = path.basename(filePath, ".json");

  return {
    id: safeIdFromPath(filePath),
    name,
    framework,
    sceneName: name,
    status,
    traceId,
    startedAt,
    latencyMs,
    summary: blocked
      ? String(raw.blocked_reason || latestDecision.reason || `工作流 ${name} 已被阻断。`)
      : String(latestDecision.reason || `工作流 ${name} 共记录 ${events.length} 个事件。`),
    callPath,
    blockedReason: String(raw.blocked_reason || ""),
    decision: normalizeDecision(latestDecision),
    events: events.map((event, index) => normalizeEvent(event, filePath, index)),
    decisions: decisions.length ? decisions.map((decision) => normalizeDecision(decision)) : [normalizeDecision(latestDecision)],
    sourcePath: filePath,
  };
}

function buildFallbackDecision(raw) {
  return {
    allow: !raw.blocked,
    risk_score: raw.blocked ? 0.9 : 0,
    reason: raw.blocked_reason || "未找到显式 decision，使用 workflow 顶层状态回退。",
    blocking_risk_types: [],
    suggested_alternative: null,
    trajectory_score: null,
  };
}

function normalizeDecision(decision) {
  return {
    allow: Boolean(decision.allow),
    risk_score: Number(decision.risk_score || 0),
    reason: String(decision.reason || ""),
    blocking_risk_types: Array.isArray(decision.blocking_risk_types) ? decision.blocking_risk_types.map(String) : [],
    suggested_alternative: decision.suggested_alternative ? String(decision.suggested_alternative) : null,
    trajectory_score: decision.trajectory_score == null ? null : Number(decision.trajectory_score),
  };
}

function normalizeEvent(event, filePath, index) {
  return {
    id: String(event.event_id || `${safeIdFromPath(filePath)}-${index + 1}`),
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

function inferFramework(filePath, events) {
  const metadataFramework = events
    .map((event) => event && event.metadata && event.metadata.framework)
    .find(Boolean);
  if (metadataFramework) {
    return normalizeFrameworkLabel(String(metadataFramework));
  }

  const lower = filePath.toLowerCase();
  if (lower.includes("langgraph")) {
    return "LangGraph";
  }
  if (lower.includes("autogen")) {
    return "AutoGen";
  }
  if (lower.includes(`${path.sep}mas${path.sep}`) || lower.includes("crewai")) {
    return "MAS";
  }
  return "Workflow";
}

function normalizeFrameworkLabel(value) {
  const lower = value.toLowerCase();
  if (lower.includes("langgraph")) {
    return "LangGraph";
  }
  if (lower.includes("autogen")) {
    return "AutoGen";
  }
  if (lower.includes("mas") || lower.includes("crewai")) {
    return "MAS";
  }
  return value;
}

function extractCallPath(events) {
  const candidate = [...events]
    .reverse()
    .find((event) => Array.isArray(event.call_path) && event.call_path.length);
  return candidate ? candidate.call_path.map(String) : [];
}

function estimateLatency(events) {
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

function formatTimestamp(value) {
  return String(value || "").replace("T", " ").replace("Z", "");
}

function safeIdFromPath(filePath) {
  return path.relative(REPO_ROOT, filePath).replace(/[^A-Za-z0-9]+/g, "-").replace(/^-+|-+$/g, "");
}

function parseSimpleYaml(text) {
  const lines = String(text || "")
    .replace(/^\uFEFF/, "")
    .replace(/\r\n/g, "\n")
    .split("\n")
    .map((line) => stripInlineComment(line));

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
          result.push(parseScalar(itemText));
        }
        continue;
      }

      if (result == null) {
        result = {};
      }

      const separator = trimmed.indexOf(":");
      if (separator === -1) {
        index += 1;
        continue;
      }

      const key = trimmed.slice(0, separator).trim();
      const valueText = trimmed.slice(separator + 1).trim();
      index += 1;

      if (!valueText) {
        const child = parseBlock(indent + 2);
        result[key] = child == null ? {} : child;
      } else {
        result[key] = parseScalar(valueText);
      }
    }

    return result;
  }

  return parseBlock(0) || {};
}

function stripInlineComment(line) {
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

function parseScalar(valueText) {
  const value = valueText.trim();
  if (value === "[]") {
    return [];
  }
  if (value === "{}") {
    return {};
  }
  if (value === "true") {
    return true;
  }
  if (value === "false") {
    return false;
  }
  if (/^-?\d+(\.\d+)?$/.test(value)) {
    return Number(value);
  }
  if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) {
    return value.slice(1, -1);
  }
  return value;
}
