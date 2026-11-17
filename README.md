# nerdkit-mcp

Zero-dependency local **Model Context Protocol (MCP)** server (`stdio`, Node.js >= 18) providing four diagnostic and security utilities that run completely offline on local inputs:

1. **`redact_har_secrets`** — Scrubs `Cookie`, `Set-Cookie`, `Authorization`, `X-API-Key`, `X-Auth-Token`, `X-CSRF-Token`, URL query tokens, embedded JWTs, and nested JSON secrets inside `postData.text` and `response.content.text` from Chrome `.har` captures while keeping latency `timings` and byte counts intact.
2. **`analyze_postgres_explain`** — Parses PostgreSQL `EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON)` plans, fixes cumulative parent/child loop double-counting (`Actual Total Time * Actual Loops - child sums`), and flags filter-drop hotspots and disk sort/hash spills.
3. **`calculate_llm_vram`** — Estimates GPU VRAM (`weights + KV cache + runtime overhead`) across `FP16`, `Q8_0`, `Q6_K`, `Q4_K_M`, and `IQ4_XS` quantizations, distinguishing Standard GQA from DeepSeek MLA KV-cache scaling.
4. **`lint_mcp_config`** — Audits `mcp.json` / `claude_desktop_config.json` configs for Windows `spawn npx ENOENT` bugs (unwrapped `npx` without `cmd /c`), hardcoded API secrets inside `env`, duplicate server names, and relative paths.

Need an interactive browser UI without installing anything? The same zero-upload logic runs locally in browser RAM on NerdKit:
- [MCP `mcp.json` Inspector](https://global-utils.com/en/mcp-inspector)
- [HAR Waterfall & Secret Sanitizer](https://global-utils.com/en/har-analyzer)
- [PostgreSQL EXPLAIN Flamegraph Visualizer](https://global-utils.com/en/sql-explain-visualizer)
- [Local LLM GPU VRAM Calculator](https://global-utils.com/en/gpu-vram-calculator)

## Quick Start

No build step or external npm dependencies required:

```bash
git clone https://github.com/JangYS0/nerdkit-mcp.git
cd nerdkit-mcp
npm test
```

### Claude Desktop / Cursor Configuration (`mcpServers`)

macOS / Linux:

```json
{
  "mcpServers": {
    "nerdkit-mcp": {
      "command": "node",
      "args": ["/absolute/path/to/nerdkit-mcp/server.mjs"]
    }
  }
}
```

Windows (wrapping via `cmd /c` if launching via `npx`, or direct `node` executable):

```json
{
  "mcpServers": {
    "nerdkit-mcp": {
      "command": "node",
      "args": ["C:/path/to/nerdkit-mcp/server.mjs"]
    }
  }
}
```

### CLI Mode (`--lint-mcp`)

You can also lint a local `mcp.json` directly from the terminal without running an MCP client:

```bash
node server.mjs --lint-mcp ~/.cursor/mcp.json
```

## License

MIT
