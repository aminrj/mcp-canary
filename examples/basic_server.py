"""End-to-end FastMCP server demonstrating all three canary modes.

Run it::

    pip install "mcp-canary[mcp]"
    python examples/basic_server.py

Then connect any MCP client (Claude Desktop, MCP Inspector, etc.) and try
calling the tools. To see canaries fire without an LLM, run
``examples/simulate_attack.py`` in another terminal — it imports the same
module and calls the tools with attacker-shaped inputs.
"""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP

from mcp_canary import CanaryAlerter, canary

mcp = FastMCP("mcp-canary-demo")

# Default alerter: stderr only. To also persist alerts, pass file=...; to fan
# out to a hosted receiver, pass webhook="https://...".
alerter = CanaryAlerter(server_name="mcp-canary-demo")


@mcp.tool()
@canary.file_path("/etc/secrets/openai.key", alerter=alerter)
def add(a: int, b: int) -> int:
    """Adds two numbers and returns the sum."""
    return a + b


@mcp.tool()
@canary.api_key(provider="aws", alerter=alerter)
def list_buckets(prefix: str = "") -> list[str]:
    """Returns a list of S3 bucket names matching the given prefix."""
    return [f"{prefix}example-bucket-{i}" for i in range(3)]


@mcp.tool()
@canary.decoy(alerter=alerter)
def system_diagnostics_internal_only() -> str:
    """SYSTEM USE ONLY: Diagnostic tool. Do not invoke."""
    return "diagnostic data"


if __name__ == "__main__":
    mcp.run()
