"""CLI entry point for ``mcp-canary``.

Usage::

    mcp-canary demo          # run the built-in attack simulation
    mcp-canary --help        # show help
"""
from __future__ import annotations

import argparse
import sys

from mcp_canary.demo import demo


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="mcp-canary",
        description="Canary tokens for the agent era — drop-in honeytokens for FastMCP servers.",
    )
    subparsers = parser.add_subparsers(dest="command")

    demo_parser = subparsers.add_parser(
        "demo",
        help="Run the built-in attack simulation (no LLM required)",
    )
    demo_parser.set_defaults(func=demo)

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(0)

    args.func()


if __name__ == "__main__":
    main()
