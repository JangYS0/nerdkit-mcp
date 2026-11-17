import test from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";

const SERVER_PATH = path.join(path.dirname(fileURLToPath(import.meta.url)), "server.mjs");

function runMcpSession(requests) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [SERVER_PATH], { stdio: ["pipe", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (d) => { stdout += d.toString("utf8"); });
    child.stderr.on("data", (d) => { stderr += d.toString("utf8"); });
    child.on("error", reject);
    child.on("close", (code) => {
      if (code !== 0) return reject(new Error(`Server exited ${code}: ${stderr}`));
      const responses = stdout
        .trim()
        .split(/\r?\n/)
        .filter(Boolean)
        .map((line) => JSON.parse(line));
      resolve(responses);
    });

    for (const req of requests) {
      child.stdin.write(`${JSON.stringify(req)}\n`);
    }
    child.stdin.end();
  });
}

test("MCP stdio session handles initialize, tools/list, and all 4 tool calls", async () => {
  const sampleHar = JSON.stringify({
    log: {
      version: "1.2",
      entries: [
        {
          startedDateTime: "2026-11-17T00:00:00Z",
          time: 120,
          request: {
            method: "POST",
            url: "https://api.example.com/graphql?api_key=secret123",
            headers: [{ name: "X-API-Key", value: "live_key_999" }],
            cookies: [{ name: "sid", value: "cookie_secret" }],
            postData: { text: JSON.stringify({ refresh_token: "rt_secret" }) },
          },
          response: {
            status: 200,
            headers: [{ name: "Set-Cookie", value: "sid=new" }],
            cookies: [],
            content: { text: JSON.stringify({ access_token: "at_secret" }) },
          },
        },
      ],
    },
  });

  const sampleExplain = JSON.stringify([
    {
      "Planning Time": 0.4,
      "Execution Time": 48.2,
      Plan: {
        "Node Type": "Sort",
        "Sort Space Type": "Disk",
        "Sort Space Used": 2048,
        "Actual Total Time": 48.0,
        "Actual Loops": 1,
        "Actual Rows": 500,
        Plans: [
          {
            "Node Type": "Seq Scan",
            "Relation Name": "orders",
            "Actual Total Time": 30.0,
            "Actual Loops": 1,
            "Actual Rows": 500,
            "Rows Removed by Filter": 95000,
          },
        ],
      },
    },
  ]);

  const sampleMcpJson = JSON.stringify({
    mcpServers: {
      filesystem: {
        command: "npx",
        args: ["-y", "@modelcontextprotocol/server-filesystem", "./data"],
        env: { API_TOKEN: "sk-proj-1234567890abcdef" },
      },
    },
  });

  const responses = await runMcpSession([
    { jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2024-11-05", capabilities: {} } },
    { jsonrpc: "2.0", method: "notifications/initialized" },
    { jsonrpc: "2.0", id: 2, method: "tools/list", params: {} },
    { jsonrpc: "2.0", id: 3, method: "tools/call", params: { name: "redact_har_secrets", arguments: { harJson: sampleHar } } },
    { jsonrpc: "2.0", id: 4, method: "tools/call", params: { name: "analyze_postgres_explain", arguments: { explainJson: sampleExplain } } },
    { jsonrpc: "2.0", id: 5, method: "tools/call", params: { name: "calculate_llm_vram", arguments: { paramsBillions: 32, quantization: "Q4_K_M", contextTokens: 16384, architecture: "gqa" } } },
    { jsonrpc: "2.0", id: 6, method: "tools/call", params: { name: "lint_mcp_config", arguments: { rawJson: sampleMcpJson } } },
  ]);

  assert.equal(responses.length, 6);

  const init = responses.find((r) => r.id === 1);
  assert.equal(init.result.protocolVersion, "2024-11-05");
  assert.equal(init.result.serverInfo.name, "nerdkit-mcp");

  const list = responses.find((r) => r.id === 2);
  assert.equal(list.result.tools.length, 4);

  const harRes = JSON.parse(responses.find((r) => r.id === 3).result.content[0].text);
  assert.equal(harRes.stats.redactedHeaders, 2);
  assert.equal(harRes.stats.redactedParams, 1);
  assert.equal(harRes.stats.redactedBodies, 2);
  assert.equal(harRes.har.log.entries[0].request.headers[0].value, "[REDACTED]");

  const pgRes = JSON.parse(responses.find((r) => r.id === 4).result.content[0].text);
  assert.equal(pgRes.hotspots[0].nodeType, "Seq Scan");
  assert.equal(pgRes.hotspots[0].exclusiveMs, 30);
  assert.ok(pgRes.hotspots[1].flags.some((f) => f.startsWith("DISK_SORT")));

  const vramRes = JSON.parse(responses.find((r) => r.id === 5).result.content[0].text);
  assert.ok(vramRes.totalGb > 18 && vramRes.totalGb < 30);

  const lintRes = JSON.parse(responses.find((r) => r.id === 6).result.content[0].text);
  const codes = lintRes.issues.map((i) => i.code);
  assert.ok(codes.includes("WINDOWS_SPAWN_NPX_ENOENT"));
  assert.ok(codes.includes("RELATIVE_SCRIPT_PATH"));
  assert.ok(codes.includes("EXPOSED_ENV_SECRET"));
});
