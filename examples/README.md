# Examples

## `basic_server.py`

A FastMCP server with all three v1 canary types.

```bash
pip install "mcp-canary[mcp]"
python examples/basic_server.py
```

Connect any MCP client (Claude Desktop, the MCP Inspector, etc.) and call the tools. The decoy will fire on the first invocation; the file-path and api-key canaries fire when an LLM has been induced to echo their bait back into another tool's input.

## `simulate_attack.py`

Imports `basic_server` and calls the tools with attacker-shaped inputs so you can see canaries fire without an LLM in the loop:

```bash
python examples/simulate_attack.py
```

You should see `[mcp-canary]` JSON lines on stderr for each tripped canary.
