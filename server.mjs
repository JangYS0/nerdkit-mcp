#!/usr/bin/env node
/**
 * nerdkit-mcp — Zero-dependency local Model Context Protocol (MCP) stdio server.
 * Tools:
 *   1. redact_har_secrets       — Scrub cookies, custom auth headers, URL tokens, JWTs & JSON postData secrets from HAR 1.2
 *   2. analyze_postgres_explain — Compute exclusive node time, filter drop ratio & disk spills from EXPLAIN FORMAT JSON
 *   3. calculate_llm_vram       — Estimate GPU weights + KV-cache memory (Standard GQA vs DeepSeek MLA)
 *   4. lint_mcp_config          — Catch Windows spawn npx ENOENT, hardcoded env secrets, duplicate keys & relative paths
 *
 * Interactive zero-upload browser versions: https://global-utils.com/en/mcp-inspector
 */
import fs from "node:fs";
import readline from "node:readline";

const PROTOCOL_VERSION = "2024-11-05";
const SERVER_INFO = { name: "nerdkit-mcp", version: "1.0.0" };

// ---------------------------------------------------------------------------
// 1. HAR 1.2 Secret Scrubber
// ---------------------------------------------------------------------------
const SENSITIVE_HEADER_RE = /^(cookie|set-cookie|authorization|proxy-authorization|x-api-key|x-auth-token|x-csrf-token|x-xsrf-token|x-amz-security-token|api-key)$/i;
const SENSITIVE_QUERY_RE = /^(token|access_token|refresh_token|id_token|api_key|apikey|key|secret|password|sig|signature|x-amz-signature|code|session|sid)$/i;
const SENSITIVE_JSON_KEY_RE = /(password|passwd|secret|client_secret|access_token|refresh_token|id_token|api_key|apikey|private_key|authorization|session_id|credit_card|cvv)/i;
const BEARER_VALUE_RE = /^(Bearer|Basic|Digest|Token)\s+[A-Za-z0-9._~+/=-]+/i;
const JWT_RE = /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g;

function scrubJsonValue(val) {
  if (Array.isArray(val)) return val.map(scrubJsonValue);
  if (val && typeof val === "object") {
    const out = {};
    for (const [k, v] of Object.entries(val)) {
      out[k] = SENSITIVE_JSON_KEY_RE.test(k) ? "[REDACTED]" : scrubJsonValue(v);
    }
    return out;
  }
  if (typeof val === "string") return val.replace(JWT_RE, "[REDACTED_JWT]");
  return val;
}

export function redactHarSecrets(harInput, dropResponseBodies = false) {
  const har = typeof harInput === "string" ? JSON.parse(harInput) : structuredClone(harInput);
  const entries = har?.log?.entries;
  if (!Array.isArray(entries)) {
    throw new Error("Invalid HAR 1.2 payload: missing log.entries array");
  }
  let redactedHeaders = 0;
  let redactedCookies = 0;
  let redactedParams = 0;
  let redactedBodies = 0;

  for (const entry of entries) {
    for (const side of [entry.request, entry.response]) {
      if (!side) continue;
      if (Array.isArray(side.cookies) && side.cookies.length > 0) {
        redactedCookies += side.cookies.length;
        side.cookies = side.cookies.map((c) => ({ ...c, value: "[REDACTED]" }));
      }
      if (Array.isArray(side.headers)) {
        side.headers = side.headers.map((h) => {
          if (SENSITIVE_HEADER_RE.test(h.name) || BEARER_VALUE_RE.test(h.value || "")) {
            redactedHeaders++;
            return { ...h, value: "[REDACTED]" };
          }
          if (typeof h.value === "string" && JWT_RE.test(h.value)) {
            JWT_RE.lastIndex = 0;
            redactedHeaders++;
            return { ...h, value: h.value.replace(JWT_RE, "[REDACTED_JWT]") };
          }
          return h;
        });
      }
    }

    if (entry.request) {
      if (typeof entry.request.url === "string") {
        try {
          const u = new URL(entry.request.url);
          let touched = false;
          for (const [k] of u.searchParams.entries()) {
            if (SENSITIVE_QUERY_RE.test(k)) {
              u.searchParams.set(k, "REDACTED");
              redactedParams++;
              touched = true;
            }
          }
          if (touched) entry.request.url = u.toString();
        } catch {}
      }
      if (Array.isArray(entry.request.queryString)) {
        entry.request.queryString = entry.request.queryString.map((q) =>
          SENSITIVE_QUERY_RE.test(q.name) ? { ...q, value: "[REDACTED]" } : q
        );
      }
      if (entry.request.postData?.text) {
        const raw = entry.request.postData.text;
        try {
          const scrubbed = JSON.stringify(scrubJsonValue(JSON.parse(raw)));
          if (scrubbed !== raw) {
            entry.request.postData.text = scrubbed;
            redactedBodies++;
          }
        } catch {
          const replaced = raw.replace(JWT_RE, "[REDACTED_JWT]");
          if (replaced !== raw) {
            entry.request.postData.text = replaced;
            redactedBodies++;
          }
        }
      }
    }

    if (entry.response?.content?.text) {
      if (dropResponseBodies) {
        entry.response.content.text = "[OMITTED_BODY]";
        redactedBodies++;
      } else {
        try {
          const scrubbed = JSON.stringify(scrubJsonValue(JSON.parse(entry.response.content.text)));
          if (scrubbed !== entry.response.content.text) {
            entry.response.content.text = scrubbed;
            redactedBodies++;
          }
        } catch {}
      }
    }
  }

  return {
    stats: { entries: entries.length, redactedHeaders, redactedCookies, redactedParams, redactedBodies },
    har,
  };
}

// ---------------------------------------------------------------------------
// 2. PostgreSQL EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) Hotspot Analyzer
// ---------------------------------------------------------------------------
export function analyzePostgresExplain(explainInput) {
  const parsed = typeof explainInput === "string" ? JSON.parse(explainInput) : explainInput;
  const rootObj = Array.isArray(parsed) ? parsed[0] : parsed;
  const rootPlan = rootObj?.Plan || rootObj;
  if (!rootPlan || typeof rootPlan !== "object" || !rootPlan["Node Type"]) {
    throw new Error("Invalid PostgreSQL EXPLAIN JSON: missing Plan[\"Node Type\"]");
  }

  const nodes = [];
  let executionTotalMs = Number(rootObj["Execution Time"] || 0);

  function walk(node, depth = 0) {
    const loops = Number(node["Actual Loops"] ?? 1);
    const totalMs = Number(node["Actual Total Time"] ?? 0) * loops;
    let childrenMs = 0;
    const subplans = Array.isArray(node.Plans) ? node.Plans : [];
    for (const child of subplans) {
      childrenMs += Number(child["Actual Total Time"] ?? 0) * Number(child["Actual Loops"] ?? 1);
      walk(child, depth + 1);
    }
    const exclusiveMs = Math.max(0, totalMs - childrenMs);
    const actualRowsTotal = Number(node["Actual Rows"] ?? 0) * loops;
    const removedFilter = Number(node["Rows Removed by Filter"] ?? 0) * loops;
    const removedJoin = Number(node["Rows Removed by Join Filter"] ?? 0) * loops;
    const sortDisk = node["Sort Space Type"] === "Disk";
    const hashBatches = Number(node["Hash Batches"] ?? 1);

    const flags = [];
    if (sortDisk) flags.push(`DISK_SORT(${node["Sort Space Used"] || 0}kB)`);
    if (hashBatches > 1) flags.push(`HASH_SPILL(${hashBatches}_batches)`);
    if (removedFilter + removedJoin > Math.max(1000, actualRowsTotal * 10)) {
      flags.push(`HIGH_FILTER_DROP(${removedFilter + removedJoin}_rows_discarded)`);
    }

    nodes.push({
      depth,
      nodeType: node["Node Type"],
      relation: node["Relation Name"] || node["Index Name"] || node["CTE Name"] || null,
      loops,
      exclusiveMs: Number(exclusiveMs.toFixed(3)),
      totalMs: Number(totalMs.toFixed(3)),
      actualRowsTotal,
      sharedReadBlocks: Number(node["Shared Read Blocks"] ?? 0),
      flags,
    });
  }

  walk(rootPlan, 0);
  if (!executionTotalMs) {
    executionTotalMs = Number(rootPlan["Actual Total Time"] ?? 0) * Number(rootPlan["Actual Loops"] ?? 1);
  }
  const hotspots = [...nodes].sort((a, b) => b.exclusiveMs - a.exclusiveMs);
  return {
    executionTimeMs: Number(executionTotalMs.toFixed(3)),
    planningTimeMs: rootObj["Planning Time"] ?? null,
    nodeCount: nodes.length,
    hotspots: hotspots.slice(0, 10),
  };
}

// ---------------------------------------------------------------------------
// 3. Local LLM GPU VRAM & KV-Cache Calculator (Standard GQA vs DeepSeek MLA)
// ---------------------------------------------------------------------------
const QUANT_BPW = {
  FP16: 16.0,
  Q8_0: 8.5,
  Q6_K: 6.56,
  Q4_K_M: 4.85,
  IQ4_XS: 4.25,
};

export function calculateLlmVram({
  paramsBillions,
  quantization = "Q4_K_M",
  contextTokens = 8192,
  architecture = "gqa",
  layers = 64,
  kvHeads = 8,
  headDim = 128,
  mlaCompressedDim = 576,
}) {
  if (!(paramsBillions > 0)) throw new Error("paramsBillions must be > 0");
  const bpw = QUANT_BPW[quantization] ?? QUANT_BPW.Q4_K_M;
  const weightsGb = (paramsBillions * 1e9 * (bpw / 8)) / (1024 ** 3);
  // FP16 KV cache (2 bytes per element)
  const kvBytesPerToken =
    architecture === "mla"
      ? layers * mlaCompressedDim * 2
      : 2 * layers * kvHeads * headDim * 2;
  const kvCacheGb = (kvBytesPerToken * contextTokens) / (1024 ** 3);
  const overheadGb = Math.max(0.6, weightsGb * 0.04 + 0.5);
  const totalGb = weightsGb + kvCacheGb + overheadGb;
  return {
    quantization,
    bitsPerWeight: bpw,
    architecture,
    contextTokens,
    weightsGb: Number(weightsGb.toFixed(2)),
    kvCacheGb: Number(kvCacheGb.toFixed(2)),
    overheadGb: Number(overheadGb.toFixed(2)),
    totalGb: Number(totalGb.toFixed(2)),
  };
}

// ---------------------------------------------------------------------------
// 4. mcp.json Config Linter
// ---------------------------------------------------------------------------
const SECRET_VALUE_RE = /^(sk-[A-Za-z0-9_-]{12,}|sk-ant-[A-Za-z0-9_-]{12,}|gh[pousr]_[A-Za-z0-9]{16,}|AIza[0-9A-Za-z_-]{20,}|AKIA[0-9A-Z]{16}|xox[baprs]-[A-Za-z0-9-]{12,})$/;

export function lintMcpConfig(rawJson) {
  if (typeof rawJson !== "string") throw new Error("rawJson must be a string");
  const issues = [];

  // Detect duplicate server keys inside raw JSON before JSON.parse silently overwrites
  const keyMatch = rawJson.match(/"mcpServers"\s*:\s*\{([\s\S]*)\}/m);
  if (keyMatch?.[1]) {
    const serverNames = [];
    for (const m of keyMatch[1].matchAll(/^\s*"([^"]+)"\s*:\s*\{/gm)) {
      if (serverNames.includes(m[1])) {
        issues.push({ severity: "error", server: m[1], code: "DUPLICATE_SERVER_KEY", message: `Duplicate server entry "${m[1]}"; later block silently overwrites earlier config.` });
      }
      serverNames.push(m[1]);
    }
  }

  let parsed;
  try {
    parsed = JSON.parse(rawJson);
  } catch (err) {
    return {
      validJson: false,
      issues: [{ severity: "error", server: null, code: "INVALID_JSON", message: err.message }],
    };
  }

  const servers = parsed?.mcpServers && typeof parsed.mcpServers === "object" ? parsed.mcpServers : {};
  for (const [name, cfg] of Object.entries(servers)) {
    if (!cfg || typeof cfg !== "object") continue;
    const cmd = String(cfg.command || "");
    const args = Array.isArray(cfg.args) ? cfg.args.map(String) : [];

    if (/^(npx|npm|pnpm|yarn)$/i.test(cmd)) {
      issues.push({
        severity: "warning",
        server: name,
        code: "WINDOWS_SPAWN_NPX_ENOENT",
        message: `Direct command "${cmd}" throws spawn ENOENT on Windows GUI hosts (Claude Desktop / Cursor). Wrap with command "cmd" and args ["/c", "${cmd}", ...].`,
      });
    }

    for (const a of args) {
      if (a.startsWith("./") || a.startsWith("../")) {
        issues.push({
          severity: "warning",
          server: name,
          code: "RELATIVE_SCRIPT_PATH",
          message: `Relative arg "${a}" depends on IDE working directory; use an absolute path.`,
        });
      }
    }

    if (cfg.env && typeof cfg.env === "object") {
      for (const [envKey, envVal] of Object.entries(cfg.env)) {
        const val = String(envVal || "");
        if (SECRET_VALUE_RE.test(val) || (/(TOKEN|SECRET|KEY|PASSWORD)/i.test(envKey) && val.length >= 16 && !val.startsWith("${") && !val.includes("YOUR_"))) {
          issues.push({
            severity: "error",
            server: name,
            code: "EXPOSED_ENV_SECRET",
            message: `Plaintext secret in env.${envKey} (${val.slice(0, 6)}...). Load via OS keychain or environment reference before committing mcp.json.`,
          });
        }
      }
    }
  }

  return {
    validJson: true,
    serverCount: Object.keys(servers).length,
    issues,
  };
}

// ---------------------------------------------------------------------------
// 5. MCP JSON-RPC 2.0 Stdio Server + CLI Entrypoint
// ---------------------------------------------------------------------------
const TOOLS = [
  {
    name: "redact_har_secrets",
    description: "Scrub sensitive headers, cookies, query tokens, JWTs, and nested JSON postData/response secrets from a Chrome HAR 1.2 JSON file while keeping HTTP timings.",
    inputSchema: {
      type: "object",
      properties: {
        harJson: { type: "string", description: "Raw HAR 1.2 JSON string" },
        dropResponseBodies: { type: "boolean", description: "Replace all response.content.text payloads with [OMITTED_BODY]" },
      },
      required: ["harJson"],
    },
  },
  {
    name: "analyze_postgres_explain",
    description: "Parse PostgreSQL EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) to find exclusive-time bottlenecks, filter drops, and disk sort/hash spills.",
    inputSchema: {
      type: "object",
      properties: {
        explainJson: { type: "string", description: "JSON output from EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON)" },
      },
      required: ["explainJson"],
    },
  },
  {
    name: "calculate_llm_vram",
    description: "Calculate local LLM GPU VRAM requirements (model weights + KV cache for Standard GQA or DeepSeek MLA + runtime buffer).",
    inputSchema: {
      type: "object",
      properties: {
        paramsBillions: { type: "number", description: "Total model parameters in billions (e.g. 7, 14, 32, 70)" },
        quantization: { type: "string", enum: Object.keys(QUANT_BPW), description: "Weight quantization preset" },
        contextTokens: { type: "number", description: "Context window length in tokens (default 8192)" },
        architecture: { type: "string", enum: ["gqa", "mla"], description: "KV cache architecture: gqa or mla" },
        layers: { type: "number", description: "Transformer layer count (default 64)" },
        kvHeads: { type: "number", description: "Number of KV heads for GQA (default 8)" },
        headDim: { type: "number", description: "Attention head dimension for GQA (default 128)" },
        mlaCompressedDim: { type: "number", description: "Compressed KV + RoPE dims per token for MLA (default 576)" },
      },
      required: ["paramsBillions"],
    },
  },
  {
    name: "lint_mcp_config",
    description: "Audit Claude Desktop / Cursor mcp.json config for Windows spawn npx ENOENT, leaked API tokens in env, duplicate server keys, and relative paths.",
    inputSchema: {
      type: "object",
      properties: {
        rawJson: { type: "string", description: "Raw contents of mcp.json or claude_desktop_config.json" },
      },
      required: ["rawJson"],
    },
  },
];

function sendJsonRpc(obj) {
  process.stdout.write(`${JSON.stringify(obj)}\n`);
}

function handleRpcMessage(msg) {
  if (!msg || typeof msg !== "object" || msg.jsonrpc !== "2.0") return;
  const { id, method, params } = msg;

  // Notifications without id do not receive a response in JSON-RPC 2.0
  if (id === undefined || id === null) return;

  try {
    if (method === "initialize") {
      return sendJsonRpc({
        jsonrpc: "2.0",
        id,
        result: {
          protocolVersion: PROTOCOL_VERSION,
          capabilities: { tools: {} },
          serverInfo: SERVER_INFO,
        },
      });
    }
    if (method === "ping") {
      return sendJsonRpc({ jsonrpc: "2.0", id, result: {} });
    }
    if (method === "tools/list") {
      return sendJsonRpc({ jsonrpc: "2.0", id, result: { tools: TOOLS } });
    }
    if (method === "tools/call") {
      const toolName = params?.name;
      const args = params?.arguments || {};
      let resultObj;
      if (toolName === "redact_har_secrets") {
        resultObj = redactHarSecrets(args.harJson, Boolean(args.dropResponseBodies));
      } else if (toolName === "analyze_postgres_explain") {
        resultObj = analyzePostgresExplain(args.explainJson);
      } else if (toolName === "calculate_llm_vram") {
        resultObj = calculateLlmVram(args);
      } else if (toolName === "lint_mcp_config") {
        resultObj = lintMcpConfig(args.rawJson);
      } else {
        return sendJsonRpc({
          jsonrpc: "2.0",
          id,
          error: { code: -32601, message: `Unknown tool: ${toolName}` },
        });
      }
      return sendJsonRpc({
        jsonrpc: "2.0",
        id,
        result: { content: [{ type: "text", text: JSON.stringify(resultObj, null, 2) }] },
      });
    }
    return sendJsonRpc({
      jsonrpc: "2.0",
      id,
      error: { code: -32601, message: `Method not found: ${method}` },
    });
  } catch (err) {
    return sendJsonRpc({
      jsonrpc: "2.0",
      id,
      result: {
        isError: true,
        content: [{ type: "text", text: `Tool execution failed: ${err.message}` }],
      },
    });
  }
}

const isEntrypoint =
  import.meta.url === `file://${process.argv[1]?.replace(/\\/g, "/")}` ||
  process.argv[1]?.endsWith("server.mjs");

if (isEntrypoint) {
  const args = process.argv.slice(2);
  if (args.includes("--help") || args.includes("-h")) {
    console.log("nerdkit-mcp — Zero-dependency MCP stdio server");
    console.log("Usage:");
    console.log("  node server.mjs                  Start MCP JSON-RPC 2.0 stdio server");
    console.log("  node server.mjs --lint-mcp PATH  Lint an mcp.json / claude_desktop_config.json file");
    console.log("Web UI: https://global-utils.com/en/mcp-inspector");
    process.exit(0);
  }
  const lintIdx = args.indexOf("--lint-mcp");
  if (lintIdx !== -1) {
    const filePath = args[lintIdx + 1];
    if (!filePath) {
      console.error("Missing path after --lint-mcp");
      process.exit(2);
    }
    const report = lintMcpConfig(fs.readFileSync(filePath, "utf8"));
    console.log(JSON.stringify(report, null, 2));
    process.exit(report.validJson ? 0 : 1);
  }

  const rl = readline.createInterface({ input: process.stdin, crlfDelay: Infinity });
  rl.on("line", (line) => {
    const trimmed = line.trim();
    if (!trimmed) return;
    try {
      handleRpcMessage(JSON.parse(trimmed));
    } catch (err) {
      sendJsonRpc({
        jsonrpc: "2.0",
        id: null,
        error: { code: -32700, message: `Parse error: ${err.message}` },
      });
    }
  });
}
