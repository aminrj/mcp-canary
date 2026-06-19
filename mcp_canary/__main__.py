"""``mcp-canary`` command-line entry point.

Subcommands::

    mcp-canary demo       # run the zero-setup three-canary demo
    mcp-canary version    # print the installed version

Also reachable as ``python -m mcp_canary <subcommand>``.
"""

from __future__ import annotations

import argparse
import sys

from mcp_canary import __version__


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="mcp-canary",
        description="Honeytoken tripwires for FastMCP tool descriptions.",
    )
    sub = parser.add_subparsers(dest="command")
    sub.add_parser("demo", help="run the zero-setup three-canary demo")
    sub.add_parser("version", help="print the installed version")

    args = parser.parse_args(argv)

    if args.command == "demo":
        from mcp_canary.demo import main as demo_main

        return demo_main()
    if args.command == "version":
        print(f"mcp-canary {__version__}")
        return 0

    parser.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
