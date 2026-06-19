"""Self-contained, zero-setup demo of all three canary modes.

Run it via the CLI::

    mcp-canary demo

or directly::

    python -m mcp_canary demo

The demo needs **no** MCP server, no client, and not even the optional ``mcp``
extra. It defines three ordinary Python functions wrapped with the real
``@canary.*`` decorators, then drives them with two kinds of input:

* a *baseline* legitimate call (no bait, no alert), and
* an *attacker-shaped* call (the LLM has followed the poisoned tool
  description and surfaced the bait) — which trips the canary.

For each mode it prints the planted bait, the baseline result, the attack
input, and the captured alert evidence so an audience can see exactly what
fired and why.
"""

from __future__ import annotations

import json
import os
import sys

from mcp_canary import bait_strings, canary
from mcp_canary.alerter import CanaryAlerter, CanaryEvent, Sink
from mcp_canary.detection import registry

# A fake, never-real sensitive path used as file_path bait.
SECRET_PATH = "/etc/secrets/openai.key"
# Minted up front so the demo can both plant it and display it.
AWS_BAIT = bait_strings.make_bait("aws")


# --------------------------------------------------------------------------- #
# Output helpers
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


def _bold(t: str) -> str:
    return _c(t, "1")


def _dim(t: str) -> str:
    return _c(t, "2")


def _green(t: str) -> str:
    return _c(t, "32")


def _red(t: str) -> str:
    return _c(t, "31;1")


def _yellow(t: str) -> str:
    return _c(t, "33")


def _cyan(t: str) -> str:
    return _c(t, "36")


def _rule() -> None:
    print(_dim("─" * 68))


# --------------------------------------------------------------------------- #
# Capture sink — collects events so the demo can render them itself
# --------------------------------------------------------------------------- #
class _CaptureSink(Sink):
    """In-memory sink so the demo can pretty-print evidence on its own terms."""

    def __init__(self) -> None:
        self.events: list[CanaryEvent] = []

    def emit(self, event: CanaryEvent) -> None:
        self.events.append(event)


_capture = _CaptureSink()
# stdout=False: the demo renders alerts itself instead of raw stderr JSON.
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
# Scenario rendering
# --------------------------------------------------------------------------- #
def _fired_since(start: int) -> CanaryEvent | None:
    return _capture.events[start] if len(_capture.events) > start else None


def _show_evidence(event: CanaryEvent) -> None:
    print(f"  {_red('⚠ CANARY FIRED')}  {_bold(event.type)}")
    print(f"    tool        : {event.tool}")
    print(f"    bait        : {_yellow(event.bait)}")
    if event.matched_field is not None:
        print(f"    matched_field: {_cyan(event.matched_field)}")
    origin = event.extra.get("bait_origin_tool")
    if origin and origin != event.tool:
        print(f"    bait planted on: {origin}  (cross-tool exfiltration)")
    print(_dim("    payload:"))
    payload = json.dumps(event.as_payload(), default=str, indent=2)
    for line in payload.splitlines():
        print(_dim(f"      {line}"))


def _scenario(
    n: int,
    title: str,
    planted: str,
    baseline_desc: str,
    baseline_call,
    attack_desc: str,
    attack_call,
    *,
    decoy: bool = False,
) -> bool:
    _rule()
    print(_bold(f"[{n}/3] {title}"))
    print(f"  planted bait : {_yellow(planted)}")
    print()

    if not decoy:
        # Baseline — a legitimate call. No bait in the input, no alert.
        before = len(_capture.events)
        print(f"  {_dim('baseline')}    : {baseline_desc}")
        result = baseline_call()
        ok = _fired_since(before) is None
        status = _green("no alert ✓") if ok else _red("UNEXPECTED ALERT ✗")
        print(f"               -> result={result!r}   {status}")
        print()

    # Attack — attacker-shaped input that surfaces the bait.
    before = len(_capture.events)
    print(f"  {_red('attack')}      : {attack_desc}")
    attack_call()
    event = _fired_since(before)
    print()
    if event is None:
        print(f"  {_red('NO CANARY FIRED — demo bug ✗')}")
        return False
    _show_evidence(event)
    print()
    return True


def main() -> int:
    """Run the three-canary demo. Returns a process exit code."""
    # The decorators above already planted bait in the process-global registry
    # at import time; nothing else to set up.
    print()
    print(_bold("mcp-canary — live canary demo"))
    print(_dim("Honeytoken tripwires for FastMCP tool descriptions."))
    print(_dim(f"{len(registry().by_bait)} bait string(s) planted in the registry. No server, no LLM."))
    print()

    results = [
        _scenario(
            1,
            "file_path canary",
            SECRET_PATH,
            "fetch_user_profile(user_id='u-1001')",
            lambda: fetch_user_profile(user_id="u-1001"),
            "LLM read the planted path and echoed it back in user_id",
            lambda: fetch_user_profile(user_id=f"u-1001 notes={SECRET_PATH}"),
        ),
        _scenario(
            2,
            "api_key canary",
            AWS_BAIT,
            "list_buckets(prefix='prod-')",
            lambda: list_buckets(prefix="prod-"),
            "LLM echoed the fake AWS credential into a later tool call",
            lambda: list_buckets(prefix=f"retry-with-cred-{AWS_BAIT}-"),
        ),
        _scenario(
            3,
            "decoy tool",
            "system_diagnostics_internal_only()",
            "",
            lambda: None,
            "LLM invoked the 'do not call' diagnostic tool",
            lambda: system_diagnostics_internal_only(),
            decoy=True,
        ),
    ]

    _rule()
    fired = sum(results)
    if fired == 3:
        print(_green(_bold(f"  All {fired}/3 canaries fired. ")) + _dim("Add 3 lines to your own server to get this."))
        print(_dim("  Configure sinks: CanaryAlerter(file='alerts.jsonl', webhook='https://...')"))
        print()
        return 0
    print(_red(_bold(f"  Only {fired}/3 canaries fired.")))
    print()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
