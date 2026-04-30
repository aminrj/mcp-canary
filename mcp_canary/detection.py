"""Detection layer.

A process-global registry tracks every active bait string registered by the
``@canary.*`` decorators. ``scan_inputs`` walks tool-call arguments looking
for any registered bait substring and returns the first match (if any).

Decoys are handled separately: their decorator fires unconditionally on
invocation rather than going through this scanner.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from mcp_canary.alerter import CanaryAlerter, EventType


@dataclass
class BaitRecord:
    """Bookkeeping for one piece of bait planted by a decorator.

    ``bait`` is the literal string we scan for. ``tool`` is the name of the
    function the bait was planted on (so reports can show *which* tool's
    description leaked the bait). ``alerter`` is fired on a match.
    """

    bait: str
    tool: str
    type: EventType
    alerter: CanaryAlerter


@dataclass
class _Registry:
    # bait string -> record. A given bait string might in principle be reused
    # across tools; we keep the first registration. Callers should rely on
    # ``make_bait`` to mint unique strings per call site.
    by_bait: dict[str, BaitRecord] = field(default_factory=dict)

    def register_bait(self, record: BaitRecord) -> None:
        self.by_bait.setdefault(record.bait, record)

    def clear(self) -> None:
        self.by_bait.clear()


_REGISTRY = _Registry()


def registry() -> _Registry:
    """Return the process-global registry (test seam)."""
    return _REGISTRY


@dataclass
class Match:
    """A registered bait substring observed inside a tool call's arguments."""

    bait: str
    record: BaitRecord
    field_path: str


def _walk(value: Any, path: str) -> list[tuple[str, str]]:
    """Yield ``(field_path, string_value)`` pairs over a nested structure.

    Recurses into dicts and lists/tuples so bait hidden inside structured
    payloads (a common LLM exfiltration shape) is still surfaced. Non-string
    leaves (int, float, None, bytes) are skipped: they cannot carry a string
    bait substring.
    """
    out: list[tuple[str, str]] = []
    if isinstance(value, str):
        out.append((path, value))
    elif isinstance(value, dict):
        for k, v in value.items():
            out.extend(_walk(v, f"{path}.{k}" if path else str(k)))
    elif isinstance(value, (list, tuple)):
        for i, v in enumerate(value):
            out.extend(_walk(v, f"{path}[{i}]"))
    return out


def scan_inputs(args: tuple[Any, ...], kwargs: dict[str, Any]) -> Match | None:
    """Return the first bait match found in ``args``/``kwargs``, or ``None``.

    Field paths use dot/bracket notation so an alert can pinpoint *where* in
    a structured payload the bait surfaced (e.g. ``payload.creds[0].key``).
    """
    if not _REGISTRY.by_bait:
        return None

    fields: list[tuple[str, str]] = []
    for i, a in enumerate(args):
        fields.extend(_walk(a, f"args[{i}]"))
    for k, v in kwargs.items():
        fields.extend(_walk(v, k))

    for path, text in fields:
        for bait, record in _REGISTRY.by_bait.items():
            if bait in text:
                return Match(bait=bait, record=record, field_path=path)
    return None
