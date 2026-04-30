"""Public decorator API.

Usage (FastMCP)::

    from mcp.server.fastmcp import FastMCP
    from mcp_canary import canary, CanaryAlerter

    mcp = FastMCP("my-server")
    alerter = CanaryAlerter()  # stdout by default

    @mcp.tool()
    @canary.file_path("/etc/secrets/api.key", alerter=alerter)
    def add(a: int, b: int) -> int:
        '''Adds two numbers.'''
        return a + b

Decorator-order rule
--------------------
Python applies decorators bottom-up. ``@canary.*`` mutates the wrapped
function's ``__doc__`` *at decoration time* (so FastMCP picks up the bait
when it later introspects the description). For that to work, ``@canary.*``
must run **before** ``@mcp.tool()`` \u2014 i.e. it must appear *below* it in
source order, closer to the ``def``. The shipped examples demonstrate this.
"""

from __future__ import annotations

import asyncio
import contextlib
import functools
from collections.abc import Callable
from typing import Any

from mcp_canary import bait_strings, descriptions
from mcp_canary.alerter import CanaryAlerter
from mcp_canary.bait_strings import Provider
from mcp_canary.detection import BaitRecord, registry, scan_inputs


def _wrap(
    func: Callable[..., Any],
    *,
    on_call: Callable[[tuple[Any, ...], dict[str, Any]], None],
) -> Callable[..., Any]:
    """Wrap ``func`` (sync or async) so ``on_call`` runs before the call.

    Any exception raised by ``on_call`` is swallowed: a buggy detector must
    never break the host tool. The legitimate return value of ``func`` is
    always passed through unchanged \u2014 canaries are observe-only.
    """
    if asyncio.iscoroutinefunction(func):

        @functools.wraps(func)
        async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
            with contextlib.suppress(Exception):
                on_call(args, kwargs)
            return await func(*args, **kwargs)

        return async_wrapper

    @functools.wraps(func)
    def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
        with contextlib.suppress(Exception):
            on_call(args, kwargs)
        return func(*args, **kwargs)

    return sync_wrapper


def _scan_and_fire(tool_name: str) -> Callable[[tuple[Any, ...], dict[str, Any]], None]:
    """Build a pre-call hook that scans inputs and fires on the first match.

    The hook is closed over ``tool_name`` (the tool *currently being called*).
    A match's ``record.tool`` is the tool whose decorator originally registered
    the bait \u2014 these can differ when bait planted on tool A surfaces in a
    call to tool B, which is the common cross-tool exfiltration pattern.
    """

    def hook(args: tuple[Any, ...], kwargs: dict[str, Any]) -> None:
        match = scan_inputs(args, kwargs)
        if match is None:
            return
        match.record.alerter.fire(
            type=match.record.type,
            tool=tool_name,
            bait=match.bait,
            matched_field=match.field_path,
            extra={"observed_in_tool": tool_name, "bait_origin_tool": match.record.tool},
        )

    return hook


def file_path(path: str, *, alerter: CanaryAlerter) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Inject a fake-file-path bait instruction into the tool's description.

    Fires when the bait path appears as a substring of any tool input across
    the server (i.e. an LLM tried to pass back what it read).
    """

    def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
        tool_name = func.__name__
        func.__doc__ = descriptions.inject(func.__doc__, descriptions.file_path_instruction(path))
        registry().register_bait(
            BaitRecord(bait=path, tool=tool_name, type="file_path", alerter=alerter)
        )
        return _wrap(func, on_call=_scan_and_fire(tool_name))

    return decorator


def api_key(
    *,
    provider: Provider = "generic",
    alerter: CanaryAlerter,
    bait: str | None = None,
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Inject a provider-shaped fake credential into the tool's description.

    A unique bait string is minted per decoration unless ``bait`` is supplied
    explicitly (useful for tests). Fires when the bait string appears in any
    subsequent tool input across the server.
    """
    bait_value = bait if bait is not None else bait_strings.make_bait(provider)

    def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
        tool_name = func.__name__
        func.__doc__ = descriptions.inject(
            func.__doc__, descriptions.api_key_instruction(bait_value, provider)
        )
        registry().register_bait(
            BaitRecord(bait=bait_value, tool=tool_name, type="api_key", alerter=alerter)
        )
        return _wrap(func, on_call=_scan_and_fire(tool_name))

    return decorator


def decoy(*, alerter: CanaryAlerter) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Mark a tool as a decoy. Any invocation fires the alerter.

    Combine with a ``@mcp.tool()`` decorator above this one so the decoy is
    actually published to the MCP server.
    """

    def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
        tool_name = func.__name__
        func.__doc__ = descriptions.inject(func.__doc__, descriptions.decoy_instruction())
        # The decoy fires unconditionally on call, so it doesn't need to live in
        # the bait-substring registry. We synthesize a stable identifier purely
        # so alert payloads can correlate "which decoy was hit".
        decoy_marker = f"decoy:{tool_name}"

        def hook(args: tuple[Any, ...], kwargs: dict[str, Any]) -> None:
            alerter.fire(
                type="decoy",
                tool=tool_name,
                bait=decoy_marker,
                matched_field=None,
                extra={"args_count": len(args), "kwargs_keys": sorted(kwargs.keys())},
            )

        return _wrap(func, on_call=hook)

    return decorator
