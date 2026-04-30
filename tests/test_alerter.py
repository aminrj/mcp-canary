"""Tests for the alerter and built-in sinks."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from mcp_canary.alerter import (
    CanaryAlerter,
    CanaryEvent,
    FileSink,
    HttpWebhookSink,
    StdoutSink,
)


def test_event_payload_shape() -> None:
    ev = CanaryEvent(type="file_path", tool="add", bait="/etc/x", matched_field="kwargs.note")
    payload = ev.as_payload()
    assert payload["version"] == 1
    assert payload["event"] == "canary.fired"
    assert payload["type"] == "file_path"
    assert payload["tool"] == "add"
    assert payload["bait"] == "/etc/x"
    assert "ts" in payload


def test_stdout_sink_writes_line(capsys: pytest.CaptureFixture[str]) -> None:
    sink = StdoutSink()
    ev = CanaryEvent(type="decoy", tool="t", bait="decoy:t")
    sink.emit(ev)
    captured = capsys.readouterr()
    assert "[mcp-canary]" in captured.err
    payload_text = captured.err.split("[mcp-canary]", 1)[1].strip()
    decoded = json.loads(payload_text)
    assert decoded["tool"] == "t"


def test_file_sink_appends_jsonl(tmp_path: Path) -> None:
    target = tmp_path / "nested" / "alerts.log"
    sink = FileSink(target)
    sink.emit(CanaryEvent(type="api_key", tool="a", bait="AKIA1"))
    sink.emit(CanaryEvent(type="api_key", tool="b", bait="AKIA2"))
    lines = target.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2
    assert json.loads(lines[0])["tool"] == "a"
    assert json.loads(lines[1])["tool"] == "b"


def test_alerter_default_uses_stdout(capsys: pytest.CaptureFixture[str]) -> None:
    alerter = CanaryAlerter()
    alerter.fire(type="file_path", tool="x", bait="/p")
    captured = capsys.readouterr()
    assert "[mcp-canary]" in captured.err


def test_alerter_explicit_sinks_only(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    log = tmp_path / "a.log"
    alerter = CanaryAlerter(sinks=[FileSink(log)])
    alerter.fire(type="decoy", tool="x", bait="decoy:x")
    assert "[mcp-canary]" not in capsys.readouterr().err
    assert log.exists()


def test_alerter_swallows_sink_errors() -> None:
    class Boom:
        def emit(self, event: CanaryEvent) -> None:
            raise RuntimeError("nope")

    alerter = CanaryAlerter(sinks=[Boom()])
    # Must not raise.
    alerter.fire(type="decoy", tool="x", bait="decoy:x")


def test_webhook_sink_swallows_network_failure() -> None:
    sink = HttpWebhookSink("http://127.0.0.1:1/never", timeout=0.1)
    # Must not raise even though the connection will fail.
    sink.emit(CanaryEvent(type="decoy", tool="x", bait="decoy:x"))


def test_alerter_server_name_propagates() -> None:
    captured: list[CanaryEvent] = []

    class S:
        def emit(self, event: CanaryEvent) -> None:
            captured.append(event)

    alerter = CanaryAlerter(sinks=[S()], server_name="my-server")
    alerter.fire(type="decoy", tool="x", bait="decoy:x")
    assert captured[0].server == "my-server"
