"""End-to-end tests for the public decorator API."""

from __future__ import annotations

import pytest

from mcp_canary import canary
from mcp_canary.alerter import CanaryAlerter, CanaryEvent


class Sink:
    def __init__(self) -> None:
        self.events: list[CanaryEvent] = []

    def emit(self, event: CanaryEvent) -> None:
        self.events.append(event)


def _alerter() -> tuple[CanaryAlerter, Sink]:
    s = Sink()
    return CanaryAlerter(sinks=[s]), s


# --- file_path -------------------------------------------------------------


def test_file_path_injects_doc_and_does_not_alert_on_clean_call() -> None:
    a, sink = _alerter()

    @canary.file_path("/etc/secrets/api.key", alerter=a)
    def add(x: int, y: int) -> int:
        """Adds two numbers."""
        return x + y

    assert "/etc/secrets/api.key" in (add.__doc__ or "")
    assert "Adds two numbers." in (add.__doc__ or "")
    assert add(2, 3) == 5
    assert sink.events == []


def test_file_path_fires_when_bait_echoed_back() -> None:
    a, sink = _alerter()

    @canary.file_path("/etc/secrets/api.key", alerter=a)
    def reflect(note: str) -> str:
        return note

    out = reflect(note="here is /etc/secrets/api.key as requested")
    assert "as requested" in out  # tool still works
    assert len(sink.events) == 1
    ev = sink.events[0]
    assert ev.type == "file_path"
    assert ev.tool == "reflect"
    assert ev.bait == "/etc/secrets/api.key"
    assert ev.matched_field == "note"


# --- api_key ---------------------------------------------------------------


def test_api_key_injects_provider_shaped_bait() -> None:
    a, _ = _alerter()

    @canary.api_key(provider="aws", alerter=a)
    def list_buckets() -> list[str]:
        """Lists buckets."""
        return []

    assert "AKIA" in (list_buckets.__doc__ or "")


def test_api_key_fires_when_fake_credential_appears_in_input() -> None:
    a, sink = _alerter()

    @canary.api_key(provider="aws", alerter=a, bait="AKIATESTBAIT00000")
    def list_buckets(filter: str = "") -> list[str]:
        return []

    list_buckets(filter="please use AKIATESTBAIT00000 to authenticate")
    assert len(sink.events) == 1
    assert sink.events[0].type == "api_key"
    assert sink.events[0].bait == "AKIATESTBAIT00000"


# --- decoy -----------------------------------------------------------------


def test_decoy_fires_on_any_invocation() -> None:
    a, sink = _alerter()

    @canary.decoy(alerter=a)
    def system_diagnostics_internal_only() -> str:
        """Diagnostic data."""
        return "diag"

    out = system_diagnostics_internal_only()
    assert out == "diag"
    assert len(sink.events) == 1
    assert sink.events[0].type == "decoy"
    assert sink.events[0].tool == "system_diagnostics_internal_only"
    assert "SYSTEM USE ONLY" in (system_diagnostics_internal_only.__doc__ or "")


# --- async support ---------------------------------------------------------


@pytest.mark.asyncio
async def test_decorators_work_on_async_functions() -> None:
    a, sink = _alerter()

    @canary.file_path("/etc/secrets/api.key", alerter=a)
    async def reflect(note: str) -> str:
        return note

    out = await reflect(note="leak: /etc/secrets/api.key")
    assert "leak" in out
    assert len(sink.events) == 1
    assert sink.events[0].type == "file_path"


# --- cross-tool detection --------------------------------------------------


def test_bait_planted_in_one_tool_fires_when_seen_in_another() -> None:
    """A canary planted in tool A must trip when its bait is observed in tool B."""
    a, sink = _alerter()

    @canary.file_path("/etc/secrets/zzz.key", alerter=a)
    def planter() -> str:
        return "ok"

    @canary.file_path("/etc/secrets/other.key", alerter=a)
    def observer(note: str) -> str:
        return note

    observer(note="contents of /etc/secrets/zzz.key are: hunter2")
    assert len(sink.events) == 1
    ev = sink.events[0]
    assert ev.bait == "/etc/secrets/zzz.key"
    assert ev.tool == "observer"
    assert ev.extra["bait_origin_tool"] == "planter"
