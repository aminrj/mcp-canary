"""Tests for the bait-input scanner."""

from __future__ import annotations

from mcp_canary.alerter import CanaryAlerter
from mcp_canary.detection import BaitRecord, registry, scan_inputs


def _seed(bait: str = "/etc/secrets/api.key") -> CanaryAlerter:
    a = CanaryAlerter(stdout=False)
    registry().register_bait(BaitRecord(bait=bait, tool="t", type="file_path", alerter=a))
    return a


def test_scan_returns_none_when_empty_registry() -> None:
    assert scan_inputs((), {}) is None


def test_scan_finds_bait_in_kwarg_string() -> None:
    _seed()
    m = scan_inputs((), {"note": "I read /etc/secrets/api.key for you"})
    assert m is not None
    assert m.bait == "/etc/secrets/api.key"
    assert m.field_path == "note"


def test_scan_finds_bait_in_positional_arg() -> None:
    _seed()
    m = scan_inputs(("contains /etc/secrets/api.key here",), {})
    assert m is not None
    assert m.field_path == "args[0]"


def test_scan_recurses_into_nested_dicts_and_lists() -> None:
    _seed("AKIATESTBAIT0000")
    m = scan_inputs(
        (),
        {"payload": {"creds": [{"key": "AKIATESTBAIT0000"}]}},
    )
    assert m is not None
    assert m.bait == "AKIATESTBAIT0000"
    assert "payload" in m.field_path
    assert "creds" in m.field_path
    assert "key" in m.field_path


def test_scan_no_match_when_substring_absent() -> None:
    _seed("AKIATESTBAIT0000")
    m = scan_inputs((), {"x": "nothing interesting"})
    assert m is None


def test_scan_ignores_non_string_types() -> None:
    _seed("AKIATESTBAIT0000")
    m = scan_inputs((1, 2.5, None, b"AKIATESTBAIT0000"), {"n": 7})
    # bytes are not scanned in v1; integer/float/None must not trip.
    assert m is None
