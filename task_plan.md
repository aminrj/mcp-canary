# task_plan.md — mcp-canary v1

## Goal

Ship a pip-installable Python package `mcp-canary` that lets a FastMCP server
author add tripwire honeytokens to tool descriptions with one decorator. When a
compromised LLM follows the bait — reads a fake file path, exfiltrates a fake
key, or calls a decoy tool — an `Alerter` fires.

Success = README quickstart works end-to-end in <60s, three canary modes have
unit tests, CI green, ready to publish to PyPI.

## Tech stack (locked)

- Python 3.11+ (target 3.11 and 3.12 in CI)
- Build/packaging: `pyproject.toml` with `hatchling` backend
- Runtime deps cap (per spec §9): `mcp>=1.2`, `httpx`, `pydantic>=2`. That's it.
- Dev deps: `pytest`, `pytest-asyncio`, `ruff`
- CI: GitHub Actions (test.yml + publish.yml using PyPI Trusted Publishers / OIDC)
- License: MIT

## Architecture (locked from spec §5)

Three layers, no more:

1. **Bait layer** (`bait_strings.py`, `descriptions.py`)
   - Generate provider-shaped fake credentials (AWS, GitHub, OpenAI, generic).
   - Inject hidden `<IMPORTANT>` instruction blocks into tool descriptions.
2. **Detection layer** (`detection.py`)
   - Maintain a process-wide registry of active bait strings + decoy tool names.
   - Scan tool inputs for bait substrings. Track decoy tool invocations.
3. **Alert layer** (`alerter.py`)
   - `CanaryAlerter` with pluggable sinks: stdout (default), file, HTTP webhook.
   - Sinks called via `httpx` (sync) for webhook; non-blocking best-effort.

Public API surface:

```python
from mcp_canary import canary, CanaryAlerter
```

`canary` is a namespace exposing `.file_path(...)`, `.api_key(...)`, `.decoy(...)`
decorators. Each decorator:
- Wraps the FastMCP-decorated function (must work whether `@canary.*` is above
  or below `@mcp.tool()`).
- Mutates the wrapped function's `__doc__` to embed the bait instruction.
- Registers the bait with the global detector.
- Wraps the call to scan inputs and fire alerts pre-execution.

## Phases

| # | Phase | Status |
|---|-------|--------|
| 1 | Planning files + scaffold (pyproject, pkg dirs, MIT, .gitignore) | in_progress |
| 2 | `bait_strings.py` — fake key generators + tests | not_started |
| 3 | `descriptions.py` — hidden-instruction injection + tests | not_started |
| 4 | `alerter.py` — base + stdout/file/webhook sinks + tests | not_started |
| 5 | `detection.py` — registry + input scanner + decoy tracker + tests | not_started |
| 6 | `decorators.py` — `canary.file_path/api_key/decoy` + tests | not_started |
| 7 | `examples/basic_server.py` — FastMCP server with all 3 canary types | not_started |
| 8 | README.md + docs/why-mcp-canary.md + docs/threat-model.md | not_started |
| 9 | GitHub Actions: test.yml, publish.yml | not_started |
| 10 | Final polish, run full test suite, version 0.1.0 | not_started |

Each phase ends with a git commit (no claude attribution).

## Key design decisions

- **Decorator ordering**: `@mcp.tool()` first (closer to def), then `@canary.*`
  above it. Doc string mutation must happen before FastMCP introspects, so
  `@canary.*` actually mutates `__doc__` *and re-applies* via wrapping.
  Simpler: require `@canary.*` to be applied *first* (below `@mcp.tool()` in
  source), so it runs first and mutates `__doc__` before FastMCP reads it.
  Document this clearly in README.
- **Bait registry**: process-global singleton `_REGISTRY` in `detection.py`. Not
  thread-safe perfection — best-effort scanning is acceptable for v1.
- **Webhook sink**: fire-and-forget via `httpx.post(..., timeout=2)`. Swallow
  errors, never break the user's tool call.
- **Privacy**: zero telemetry. Webhook only fires to user-configured URL.

## Errors Encountered

| Error | Attempt | Resolution |
|-------|---------|------------|

## Out of scope (resist)

Per spec §2: no SaaS dashboard, no DNS canaries, no Slack/PagerDuty, no signing,
no behavioral baselines, no mcp-scan integration. Three canary types only.
