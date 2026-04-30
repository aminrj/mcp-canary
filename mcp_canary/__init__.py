"""mcp-canary — drop-in honeytokens for FastMCP servers.

Public API:

    from mcp_canary import canary, CanaryAlerter

The ``canary`` namespace exposes three decorators:

* ``canary.file_path(path, alerter=...)`` — fake sensitive file path bait
* ``canary.api_key(provider=..., alerter=...)`` — fake API-key bait
* ``canary.decoy(alerter=...)`` — decoy tool that should never be called

See README.md for usage.
"""

from mcp_canary import canary
from mcp_canary.alerter import (
    CanaryAlerter,
    CanaryEvent,
    FileSink,
    HttpWebhookSink,
    Sink,
    StdoutSink,
)

__all__ = [
    "CanaryAlerter",
    "CanaryEvent",
    "FileSink",
    "HttpWebhookSink",
    "Sink",
    "StdoutSink",
    "canary",
]

__version__ = "0.1.0"
