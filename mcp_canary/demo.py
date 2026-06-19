"""Built-in demo for ``mcp-canary demo``.

Defines three ordinary Python functions wrapped with the real ``@canary.*``
decorators, then simulates attacker-shaped inputs so you can watch the
canaries fire — no live LLM, no MCP client, and not even the optional ``mcp``
extra required. This is what makes ``pip install mcp-canary && mcp-canary
demo`` work with zero setup.

The canary decorators work on any callable, so the demo needs no FastMCP
server. For the real FastMCP integration, see ``examples/basic_server.py``.

Usage::

    pip install mcp-canary
    mcp-canary demo
"""

from __future__ import annotations

import os
import sys

from mcp_canary import CanaryAlerter, bait_strings, canary
from mcp_canary.alerter import CanaryEvent, Sink
from mcp_canary.detection import registry

# A fake, never-real sensitive path used as file_path bait.
SECRET_PATH = "/etc/secrets/openai.key"
# Minted up front so the demo can both plant it and display it.
AWS_BAIT = bait_strings.make_bait("aws")


# --------------------------------------------------------------------------- #
# Colour helpers (respect NO_COLOR / non-tty)
# --------------------------------------------------------------------------- #
def _use_color() -> bool:
    if os.environ.get("NO_COLOR") is not None:
        return False
    if os.environ.get("FORCE_COLOR") is not None:
        return True
    return sys.stdout.isatty()


_COLOR = _use_color()


def _c(text: str, code: str) -> str:
    return f"\033[{code}m{text}\033[0m" if _COLOR else text


# --------------------------------------------------------------------------- #
# Capture sink — collects events so the demo renders evidence on its own terms
# --------------------------------------------------------------------------- #
class _CaptureSink(Sink):
    def __init__(self) -> None:
        self.events: list[CanaryEvent] = []

    def emit(self, event: CanaryEvent) -> None:
        self.events.append(event)


_capture = _CaptureSink()
# stdout=False: the demo prints its own structured evidence instead of raw JSON.
alerter = CanaryAlerter(sinks=[_capture], server_name="mcp-canary-demo")


# --------------------------------------------------------------------------- #
# Demo tools — ordinary functions wrapped with the real decorators.
# No @mcp.tool() needed: the canary decorators work on any callable.
# --------------------------------------------------------------------------- #
@canary.file_path(SECRET_PATH, alerter=alerter)
def fetch_user_profile(user_id: str) -> dict:
    """Fetch a user's profile record by id."""
    return {"user_id": user_id, "name": "Ada Lovelace", "role": "admin"}


@canary.api_key(provider="aws", alerter=alerter, bait=AWS_BAIT)
def list_buckets(prefix: str = "") -> list[str]:
    """Return S3 bucket names matching the given prefix."""
    return [f"{prefix}example-bucket-{i}" for i in range(3)]


@canary.decoy(alerter=alerter)
def system_diagnostics_internal_only() -> str:
    """SYSTEM USE ONLY: Diagnostic tool. Do not invoke."""
    return "diagnostic data"


# --------------------------------------------------------------------------- #
# Demo driver
# --------------------------------------------------------------------------- #
def _show_evidence(event: CanaryEvent) -> None:
    print(f"    {_c('⚠ CANARY FIRED', '31;1')}  type={_c(event.type, '1')}  tool={event.tool}")
    print(f"      bait          : {_c(event.bait, '33')}")
    if event.matched_field is not None:
        print(f"      matched_field : {_c(event.matched_field, '36')}")
    print(f"      detected_at   : {event.ts}")


def demo() -> None:
    """Run the canary-firing demo. The decorators above planted bait at import."""
    sep = "=" * 64
    print()
    print(sep)
    print("  mcp-canary — Canary Tokens for the Agent Era")
    print("  Attack Simulation Demo  (no server, no LLM, zero setup)")
    print(sep)
    print(f"  {len(registry().by_bait)} bait string(s) planted in the registry.")
    print()

    # ── 1. File-path canary ──────────────────────────────────────────
    print("[1] file_path canary: poisoned description tells the LLM to read a file")
    print(f"    Bait planted : {_c(SECRET_PATH, '33')}")
    print("    Baseline     : fetch_user_profile(user_id='u-1001')")
    before = len(_capture.events)
    fetch_user_profile(user_id="u-1001")
    print(f"      -> {_c('no alert', '32')}")
    print("    Attack       : LLM echoes the planted path back via user_id")
    fetch_user_profile(user_id=f"u-1001 notes={SECRET_PATH}")
    _show_evidence(_capture.events[before])
    print()

    # ── 2. API-key canary ────────────────────────────────────────────
    print("[2] api_key canary: poisoned description leaks a fake AWS credential")
    print(f"    Bait planted : {_c(AWS_BAIT, '33')}")
    print("    Baseline     : list_buckets(prefix='prod-')")
    before = len(_capture.events)
    list_buckets(prefix="prod-")
    print(f"      -> {_c('no alert', '32')}")
    print("    Attack       : LLM echoes the fake key into a later tool call")
    list_buckets(prefix=f"retry-with-cred-{AWS_BAIT}-")
    _show_evidence(_capture.events[before])
    print()

    # ── 3. Decoy tool ────────────────────────────────────────────────
    print("[3] decoy canary: poisoned prompt tells the LLM to call a privileged tool")
    print("    Bait planted : system_diagnostics_internal_only (SYSTEM USE ONLY)")
    print("    Attack       : LLM invokes the decoy tool")
    before = len(_capture.events)
    system_diagnostics_internal_only()
    _show_evidence(_capture.events[before])
    print()

    # ── Summary ──────────────────────────────────────────────────────
    fired = len(_capture.events)
    print(sep)
    print(f"  All {fired} canaries fired. Attack detected and logged.")
    print(sep)
    print()
    print("  Add it to your own FastMCP server in three lines:")
    print("    from mcp_canary import canary, CanaryAlerter")
    print("    @mcp.tool()")
    print("    @canary.file_path('/etc/secrets/api.key', alerter=alerter)")
    print("    def my_tool(...): ...")
    print()


if __name__ == "__main__":
    demo()
