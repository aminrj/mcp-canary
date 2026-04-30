"""Shared pytest fixtures."""

from __future__ import annotations

from typing import Any

import pytest

from mcp_canary.alerter import CanaryAlerter, CanaryEvent, Sink
from mcp_canary.detection import registry


class RecordingSink:
    """Test sink that captures emitted events in memory."""

    def __init__(self) -> None:
        self.events: list[CanaryEvent] = []

    def emit(self, event: CanaryEvent) -> None:
        self.events.append(event)


@pytest.fixture(autouse=True)
def _clean_registry() -> Any:
    """Ensure each test starts with an empty bait registry."""
    registry().clear()
    yield
    registry().clear()


@pytest.fixture
def recording_sink() -> RecordingSink:
    return RecordingSink()


@pytest.fixture
def alerter(recording_sink: RecordingSink) -> CanaryAlerter:
    # Explicit sinks list disables stdout-default and webhook-default.
    sink: Sink = recording_sink
    return CanaryAlerter(sinks=[sink])
