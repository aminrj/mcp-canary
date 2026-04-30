# progress.md

## Session 1 — 2026-04-30

### Phase 1: scaffold (DONE)
- Read spec `02-mcp-canary.md`.
- Created planning files (`task_plan.md`, `findings.md`, `progress.md`).
- Locked tech stack: Python 3.11+, hatchling, mcp/httpx/pydantic, ruff/pytest.
- Created `pyproject.toml`, `LICENSE` (MIT), `.gitignore`.

### Phases 2-6: core implementation (DONE)
- `bait_strings.py`: AWS / GitHub / OpenAI / generic generators + `make_bait()`.
- `descriptions.py`: `<IMPORTANT>` block injection wrapped in canary markers, idempotent.
- `alerter.py`: `CanaryEvent` (pydantic), `Sink` protocol, `StdoutSink`, `FileSink` (JSONL), `HttpWebhookSink` (httpx, fire-and-forget), `CanaryAlerter` fan-out.
- `detection.py`: process-global `_REGISTRY`, recursive `scan_inputs` walking dicts/lists.
- `decorators.py`: `file_path`, `api_key`, `decoy`. Sync + async wrappers via `asyncio.iscoroutinefunction`.
- `canary.py` namespace re-export.

### Phases 7-8: tests & polish (DONE)
- 32 unit tests, all green.
- Ruff configured (E/F/I/B/UP/SIM), all checks pass.

### Phase 9: example + docs (DONE)
- `examples/basic_server.py` — FastMCP demo with all 3 canary types.
- `examples/simulate_attack.py` — verified output: 3 `[mcp-canary]` JSON lines on stderr.
- `docs/why-mcp-canary.md`, `docs/threat-model.md`, `docs/deployment.md`.
- `README.md` with 60-second quickstart.

### Phase 10: CI (DONE)
- `.github/workflows/test.yml` — matrix on Python 3.11/3.12/3.13, ruff + pytest.
- `.github/workflows/publish.yml` — trusted publisher OIDC on `v*` tags.

### Status
v1 scope from spec §9 satisfied. Ready for git tag + PyPI publish (operator action).
