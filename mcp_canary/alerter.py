"""Alerter and pluggable sinks.

A ``CanaryAlerter`` accepts one or more ``Sink`` implementations and dispatches
``CanaryEvent`` instances to all of them. Sinks must never raise — failures
are swallowed so a misconfigured webhook never breaks a user's tool call.
"""

from __future__ import annotations

import contextlib
import json
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal, Protocol, runtime_checkable

import httpx
from pydantic import BaseModel, ConfigDict, Field

EventType = Literal["file_path", "api_key", "decoy"]

_PAYLOAD_VERSION = 1


class CanaryEvent(BaseModel):
    """Structured record of a tripped canary."""

    model_config = ConfigDict(frozen=True)

    type: EventType
    tool: str
    bait: str
    matched_field: str | None = None
    server: str | None = None
    extra: dict[str, Any] = Field(default_factory=dict)
    ts: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())

    def as_payload(self) -> dict[str, Any]:
        """Serialize to the documented webhook payload shape."""
        data = self.model_dump()
        data["version"] = _PAYLOAD_VERSION
        data["event"] = "canary.fired"
        return data


@runtime_checkable
class Sink(Protocol):
    """Anything that knows how to deliver a ``CanaryEvent`` somewhere."""

    def emit(self, event: CanaryEvent) -> None: ...


class StdoutSink:
    """Default sink — prints a single-line JSON record to stderr."""

    def __init__(self, stream: Any = None) -> None:
        self._stream = stream if stream is not None else sys.stderr

    def emit(self, event: CanaryEvent) -> None:
        try:
            line = json.dumps(event.as_payload(), default=str)
            print(f"[mcp-canary] {line}", file=self._stream, flush=True)
        except Exception:
            # Best-effort: never break the host process from a sink.
            pass


class FileSink:
    """Append-only JSONL file sink. Creates parent dirs on demand."""

    def __init__(self, path: str | Path) -> None:
        self._path = Path(path)
        with contextlib.suppress(OSError):
            self._path.parent.mkdir(parents=True, exist_ok=True)

    def emit(self, event: CanaryEvent) -> None:
        try:
            with self._path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(event.as_payload(), default=str) + "\n")
        except OSError:
            pass


class HttpWebhookSink:
    """POSTs the event payload as JSON to a webhook URL.

    Fire-and-forget, short timeout. Network failures are silently swallowed —
    a canary that fails to phone home is logged-but-not-fatal by design; for
    durable delivery, combine with a ``FileSink``.
    """

    def __init__(self, url: str, *, timeout: float = 2.0, headers: dict[str, str] | None = None) -> None:
        self._url = url
        self._timeout = timeout
        self._headers = {"content-type": "application/json", **(headers or {})}

    def emit(self, event: CanaryEvent) -> None:
        with contextlib.suppress(Exception):
            httpx.post(
                self._url,
                json=event.as_payload(),
                timeout=self._timeout,
                headers=self._headers,
            )


class CanaryAlerter:
    """Fan-out dispatcher over one or more sinks.

    Convenience constructor arguments build common sinks inline:

        CanaryAlerter()                      # stdout only
        CanaryAlerter(file="alerts.log")     # stdout + file
        CanaryAlerter(webhook="https://...") # stdout + webhook
        CanaryAlerter(sinks=[my_sink])       # explicit list, no defaults
    """

    def __init__(
        self,
        *,
        sinks: list[Sink] | None = None,
        webhook: str | None = None,
        file: str | Path | None = None,
        stdout: bool = True,
        server_name: str | None = None,
    ) -> None:
        if sinks is not None:
            self._sinks: list[Sink] = list(sinks)
        else:
            self._sinks = []
            if stdout:
                self._sinks.append(StdoutSink())
            if file is not None:
                self._sinks.append(FileSink(file))
            if webhook is not None:
                self._sinks.append(HttpWebhookSink(webhook))
        self.server_name = server_name

    def add_sink(self, sink: Sink) -> None:
        self._sinks.append(sink)

    def fire(
        self,
        *,
        type: EventType,
        tool: str,
        bait: str,
        matched_field: str | None = None,
        extra: dict[str, Any] | None = None,
    ) -> CanaryEvent:
        """Build a ``CanaryEvent`` and dispatch it to every configured sink."""
        event = CanaryEvent(
            type=type,
            tool=tool,
            bait=bait,
            matched_field=matched_field,
            server=self.server_name,
            extra=extra or {},
        )
        for sink in self._sinks:
            # Defensive: a buggy custom sink must not break the host.
            with contextlib.suppress(Exception):
                sink.emit(event)
        return event
