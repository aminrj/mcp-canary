"""Simulate a compromised LLM tripping each of the demo server's canaries.

Drives the *real* FastMCP server in ``basic_server.py`` with attacker-shaped
inputs, so you can watch the canaries fire on stderr without a live MCP client.

Run it from anywhere::

    pip install -e ".[dev]"
    python examples/simulate_attack.py

You should see three ``[mcp-canary]`` JSON lines on stderr — one per canary
mode. For a polished, color-coded walkthrough that needs no ``mcp`` extra,
run ``mcp-canary demo`` instead.
"""

from __future__ import annotations

import sys
from pathlib import Path

# Make the repo root importable so ``from examples import ...`` works no matter
# what directory this script is launched from. (When run as a script, Python
# only puts this file's own directory on sys.path, not the repo root.)
_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from examples import basic_server  # noqa: E402
from mcp_canary.detection import registry  # noqa: E402


def main() -> None:
    print("--> 1) file_path canary: leaking /etc/secrets/openai.key via list_buckets prefix")
    basic_server.list_buckets(prefix="ack /etc/secrets/openai.key ")

    # Look up the AWS bait minted for list_buckets at decoration time and
    # simulate an LLM echoing it back through another tool input.
    aws_bait = next(
        (rec.bait for rec in registry().by_bait.values() if rec.type == "api_key"),
        None,
    )
    print(f"--> 2) api_key canary: echoing {aws_bait!r} back via list_buckets prefix")
    basic_server.list_buckets(prefix=f"using credential {aws_bait}")

    print("--> 3) decoy canary: calling system_diagnostics_internal_only()")
    basic_server.system_diagnostics_internal_only()


if __name__ == "__main__":
    main()
