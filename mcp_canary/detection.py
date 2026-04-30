"""Detection layer.

A process-global registry tracks every active bait string and decoy tool
registered by the decorators. ``scan_inputs`` walks tool call arguments
looking for any registered bait substring and returns the first match (if any).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from mcp_canary.alerter import CanaryAlerter, EventType


@dataclass
class BaitRecord:
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
    decoys: dict[str, BaitRecord] = field(default_factory=dict)

    def register_bait(self, record: BaitRecord) -> None:
        self.by_bait.setdefault(record.bait, record)

    def register_decoy(self, tool_name: str, record: BaitRecord) -> None:
        self.decoys[tool_name] = record

    def clear(self) -> None:
        self.by_bait.clear()
        self.decoys.clear()


_REGISTRY = _Registry()


def registry() -> _Registry:
    """Return the process-global registry (test seam)."""
    return _REGISTRY


@dataclass
class Match:
    bait: str
    record: BaitRecord
    field_path: str


def _walk(value: Any, path: str) -> list[tuple[str, str]]:
    """Yield ``(field_path, string_value)`` pairs over a nested structure."""
    out: list[tuple[str, str]] = []
    if isinstance(value, str):
        out.append((path, value))
    elif isinstance(value, dict):
        for k, v in value.items():
            out.extend(_walk(v, f"{path}.{k}" if path else str(k)))
    elif isinstance(value, (list, tuple)):
        for i, v in enumerate(value):
            out.extend(_walk(v, f"{path}[{i}]"))
    # Other types (int, float, None, bytes) cannot carry a string bait substring.
    return out


def scan_inputs(args: tuple[Any, ...], kwargs: dict[str, Any]) -> Match | None:
    """Return the first bait match found in ``args``/``kwargs``, or None."""
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
