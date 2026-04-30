"""Tests for description injection."""

from __future__ import annotations

from mcp_canary import descriptions


def test_inject_appends_block_with_markers() -> None:
    out = descriptions.inject("Adds two numbers.", descriptions.file_path_instruction("/etc/x"))
    assert out.startswith("Adds two numbers.")
    assert descriptions.CANARY_BEGIN in out
    assert descriptions.CANARY_END in out
    assert "/etc/x" in out


def test_inject_handles_none() -> None:
    out = descriptions.inject(None, descriptions.decoy_instruction())
    assert descriptions.CANARY_BEGIN in out
    assert "SYSTEM USE ONLY" in out


def test_inject_idempotent() -> None:
    once = descriptions.inject("Doc.", descriptions.file_path_instruction("/etc/x"))
    twice = descriptions.inject(once, descriptions.file_path_instruction("/etc/y"))
    assert once == twice  # second injection is suppressed
    assert "/etc/y" not in twice


def test_api_key_instruction_contains_bait() -> None:
    block = descriptions.api_key_instruction("AKIATESTBAIT", "aws")
    assert "AKIATESTBAIT" in block
    assert "aws" in block
