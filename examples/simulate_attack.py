"""Simulate a compromised LLM tripping each of the demo server's canaries.

Run it after installing the package locally::

    pip install -e ".[dev]"
    python examples/simulate_attack.py

You should see three ``[mcp-canary]`` lines on stderr — one per canary mode.
"""

from __future__ import annotations

from examples import basic_server
from mcp_canary.detection import registry


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
