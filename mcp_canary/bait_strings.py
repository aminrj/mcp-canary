"""Generators for shape-believable fake credentials used as bait.

These strings are intentionally never valid against any real provider — they
are uniformly random within each provider's well-known shape so that:

* an LLM that has been instructed to harvest credentials will treat them as
  real and try to exfiltrate them, and
* an operator can scan logs/traffic for the literal string and know with
  certainty that a canary was tripped.
"""

from __future__ import annotations

import secrets
import string
from typing import Literal

Provider = Literal["aws", "github", "openai", "generic"]

_UPPER_ALNUM = string.ascii_uppercase + string.digits
_ALNUM = string.ascii_letters + string.digits


def _rand(alphabet: str, n: int) -> str:
    return "".join(secrets.choice(alphabet) for _ in range(n))


def aws_access_key() -> str:
    """Return an AWS-shaped fake access key id (``AKIA`` + 16 upper-alnum)."""
    return "AKIA" + _rand(_UPPER_ALNUM, 16)


def github_token() -> str:
    """Return a GitHub-PAT-shaped fake token (``ghp_`` + 36 alnum)."""
    return "ghp_" + _rand(_ALNUM, 36)


def openai_key() -> str:
    """Return an OpenAI-shaped fake key (``sk-`` + 48 alnum)."""
    return "sk-" + _rand(_ALNUM, 48)


def generic_token() -> str:
    """Return a generic identifiable canary token (``canary_`` + 32 hex)."""
    return "canary_" + secrets.token_hex(16)


_GENERATORS = {
    "aws": aws_access_key,
    "github": github_token,
    "openai": openai_key,
    "generic": generic_token,
}


def make_bait(provider: Provider = "generic") -> str:
    """Generate a fresh bait string for the given provider shape.

    Raises ``ValueError`` for unknown providers.
    """
    try:
        return _GENERATORS[provider]()
    except KeyError as exc:
        valid = ", ".join(sorted(_GENERATORS))
        raise ValueError(f"unknown provider {provider!r}; expected one of: {valid}") from exc
