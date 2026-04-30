"""``canary`` namespace — re-exports the three v1 decorators.

Usage::

    from mcp_canary import canary

    @canary.file_path("/etc/secrets/api.key", alerter=alerter)
    @canary.api_key(provider="aws", alerter=alerter)
    @canary.decoy(alerter=alerter)
"""

from mcp_canary.decorators import api_key, decoy, file_path

__all__ = ["api_key", "decoy", "file_path"]
