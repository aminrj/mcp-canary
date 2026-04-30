"""Tests for bait_strings.py."""

from __future__ import annotations

import re
import string

import pytest

from mcp_canary import bait_strings


def test_aws_access_key_shape() -> None:
    key = bait_strings.aws_access_key()
    assert re.fullmatch(r"AKIA[A-Z0-9]{16}", key), key


def test_github_token_shape() -> None:
    tok = bait_strings.github_token()
    assert tok.startswith("ghp_")
    body = tok[4:]
    assert len(body) == 36
    assert all(c in string.ascii_letters + string.digits for c in body)


def test_openai_key_shape() -> None:
    key = bait_strings.openai_key()
    assert key.startswith("sk-")
    assert len(key) == 3 + 48


def test_generic_token_shape() -> None:
    tok = bait_strings.generic_token()
    assert re.fullmatch(r"canary_[0-9a-f]{32}", tok), tok


def test_make_bait_dispatch() -> None:
    assert bait_strings.make_bait("aws").startswith("AKIA")
    assert bait_strings.make_bait("github").startswith("ghp_")
    assert bait_strings.make_bait("openai").startswith("sk-")
    assert bait_strings.make_bait("generic").startswith("canary_")


def test_make_bait_unique() -> None:
    a = bait_strings.make_bait("aws")
    b = bait_strings.make_bait("aws")
    assert a != b


def test_make_bait_unknown_provider() -> None:
    with pytest.raises(ValueError, match="unknown provider"):
        bait_strings.make_bait("nope")  # type: ignore[arg-type]
