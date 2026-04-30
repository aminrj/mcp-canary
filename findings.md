# findings.md

## FastMCP decorator behavior (assumed, to verify)

`@mcp.tool()` introspects the wrapped function's `__doc__` and signature at
*decoration time* to register the tool's description with the MCP server. So
any docstring mutation must happen before `@mcp.tool()` runs. In Python
decorator stacking, the bottom-most decorator runs first:

```python
@mcp.tool()       # runs second — sees mutated __doc__
@canary.file_path("/etc/secrets/api.key", alerter=a)  # runs first
def add(...): ...
```

This is the order shown in the spec §3 quickstart, so the spec already endorses it. Good.

## Bait string shapes

Researched fake-key formats (well known shapes used by Canarytokens, AWS docs):

- AWS access key: `AKIA` + 16 uppercase alphanumerics. Bait will be
  `AKIA` + 16 random uppercase chars; we never use a real prefix Amazon issues
  to a real account (AWS publishes ranges). For honeytokens we just need
  shape-believable strings.
- GitHub PAT (classic): `ghp_` + 36 alphanumerics.
- OpenAI API key: `sk-` + 48 alphanumerics.
- Generic: hex-32 with `canary_` prefix.

## Detection model

Two complementary signals:

1. **Bait-string hit**: any string from the active bait registry appears as a
   substring in any tool's input arguments. Scan all string args and recursively
   into dict/list values.
2. **Decoy invocation**: a tool registered as a decoy is ever called.

Both fire the alerter with structured event metadata: `{type, tool_name, bait,
matched_field, ts}`.

## MCP package import path

`from mcp.server.fastmcp import FastMCP` per the spec §3 example. We do not
import this in core library — only in `examples/`. The library is FastMCP-
agnostic at the runtime level (just decorates plain Python functions and
mutates `__doc__`); the FastMCP integration is "use this decorator in your
FastMCP server."

## Webhook payload shape

```json
{
  "version": 1,
  "event": "canary.fired",
  "type": "file_path|api_key|decoy",
  "tool": "add",
  "bait": "/etc/secrets/api.key",
  "matched_field": "args.note",
  "ts": "2026-04-30T15:00:00Z",
  "server": "<optional server name>"
}
```
