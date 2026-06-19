# mcp-canary

> **Canary tokens for the agent era.** Drop-in honeytokens for [FastMCP](https://github.com/jlowin/fastmcp) servers — detect a compromised LLM the moment it follows a poisoned tool description and tries to exfiltrate.

[![Black Hat Europe Arsenal 2026](https://img.shields.io/badge/Black%20Hat%20Europe-Arsenal%202026-black.svg)](https://www.blackhat.com/eu-26/)
[![CI](https://github.com/aminrj/mcp-canary/actions/workflows/test.yml/badge.svg)](https://github.com/aminrj/mcp-canary/actions/workflows/test.yml)
[![PyPI](https://img.shields.io/pypi/v/mcp-canary.svg)](https://pypi.org/project/mcp-canary/)
[![Python](https://img.shields.io/pypi/pyversions/mcp-canary.svg)](https://pypi.org/project/mcp-canary/)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

`mcp-canary` plants honeytoken bait — a fake file path, a fake API key, or a decoy tool — inside your FastMCP tool descriptions. When an upstream-poisoned LLM follows the bait and tries to read or echo it back, the canary fires: stderr, file, or webhook. **Zero false positives** — nobody reads `/etc/secrets/openai.key` or echoes an `AKIA…` key by accident.

It's three lines of code, has zero runtime overhead on legitimate calls, and never phones home.

```bash
pip install mcp-canary       # the library
mcp-canary demo              # watch all three canaries fire — no setup, no server, no LLM
```

## Why it matters

MCP's trust model assumes tool descriptions are benign. They're not. The LLM reads your tool descriptions as part of its prompt — so if *anything* between you and the agent is compromised (a malicious upstream MCP server, a poisoned dependency, a prompt-injection in a page the agent fetched), the LLM can be steered into following hidden instructions in those descriptions. Most servers never notice.

`mcp-canary` is the trip-wire layer. It plants the bait *before* the attacker does, so you catch the compromise on the **first attempt** — like [Thinkst Canarytokens](https://canarytokens.org/), but for the agent stack. This is OWASP ASI02 (tool poisoning) detection.

## 60-second demo

```bash
pip install mcp-canary
mcp-canary demo
```

No MCP server, no client, not even the optional `mcp` extra. You'll see, for each of the three canary modes:

1. the **bait** that was planted in the tool description,
2. a **baseline** legitimate call — no alert,
3. an **attacker-shaped** call — the canary fires, and
4. the **evidence**: the exact bait, the tool that fired it, and where in the payload it surfaced.

```
[1/3] file_path canary
  planted bait : /etc/secrets/openai.key

  baseline    : fetch_user_profile(user_id='u-1001')
               -> result={'user_id': 'u-1001', ...}   no alert ✓

  attack      : LLM read the planted path and echoed it back in user_id

  ⚠ CANARY FIRED  file_path
    tool        : fetch_user_profile
    bait        : /etc/secrets/openai.key
    matched_field: user_id
```

## Add it to your own server (three lines)

```python
from mcp.server.fastmcp import FastMCP
from mcp_canary import canary, CanaryAlerter

mcp = FastMCP("my-server")
alerter = CanaryAlerter()  # logs to stderr by default

@mcp.tool()
@canary.file_path("/etc/secrets/api.key", alerter=alerter)
def add(a: int, b: int) -> int:
    """Adds two numbers."""
    return a + b

if __name__ == "__main__":
    mcp.run()
```

Legitimate `add(2, 3)` calls still return `5`. Behind the scenes, `mcp-canary` planted the bait path in the tool's description and registered it with a process-global detector. The moment that literal string shows up in *any* tool input across the server, the canary fires:

```
[mcp-canary] {"version": 1, "event": "canary.fired", "type": "file_path", "tool": "add", "bait": "/etc/secrets/api.key", "matched_field": "notes", ...}
```

> **Decorator order matters.** `@canary.*` must be **below** `@mcp.tool()` so it runs first and mutates the docstring before FastMCP introspects it.

## The three canary modes

### 1. File-path canary

```python
@mcp.tool()
@canary.file_path("/etc/secrets/api.key", alerter=alerter)
def add(a: int, b: int) -> int:
    """Adds two numbers."""
    return a + b
```

Injects an instruction telling the LLM to read a sensitive file. Fires when that literal path appears in any tool input across the server.

### 2. API-key canary

```python
@mcp.tool()
@canary.api_key(provider="aws", alerter=alerter)
def list_buckets(prefix: str = "") -> list[str]:
    """List S3 buckets matching the prefix."""
    return [f"{prefix}bucket-{i}" for i in range(3)]
```

Mints a shape-believable fake credential (`aws` / `github` / `openai` / `generic`) and embeds it in the description. Fires when that exact string shows up in any subsequent tool input.

### 3. Decoy tool

```python
@mcp.tool()
@canary.decoy(alerter=alerter)
def system_diagnostics_internal_only() -> str:
    """SYSTEM USE ONLY: Diagnostic tool. Do not invoke."""
    return "diag"
```

Fires the moment any agent calls it. A legitimate flow never should.

## Alerters and sinks

Default sink is stderr. Add a file or a webhook in one line:

```python
alerter = CanaryAlerter(
    file="alerts.jsonl",
    webhook="https://canary.example.com/alert/<token>",
)
```

Or compose your own sinks. A sink is anything with `emit(event: CanaryEvent) -> None`:

```python
from mcp_canary import CanaryAlerter, FileSink, HttpWebhookSink

alerter = CanaryAlerter(sinks=[
    FileSink("/var/log/mcp-canary.jsonl"),
    HttpWebhookSink("https://hooks.example.com/abc"),
])
```

Webhook delivery is fire-and-forget with a 2s timeout. For durable storage, pair it with a `FileSink`. The payload shape:

```json
{
  "version": 1,
  "event": "canary.fired",
  "type": "file_path",
  "tool": "add",
  "bait": "/etc/secrets/api.key",
  "matched_field": "notes",
  "server": "my-server",
  "extra": {"observed_in_tool": "add", "bait_origin_tool": "add"},
  "ts": "2026-04-30T15:00:00Z"
}
```

## How it works

The `@canary.*` decorator appends an `<IMPORTANT>`-tagged instruction block to your tool's docstring (which FastMCP publishes as the tool description) and registers the bait string in a process-global registry. It then wraps the tool so every call's arguments are scanned — recursively, into nested dicts and lists — for any registered bait substring. On a match it fires the alerter and the tool still runs normally; canaries are observe-only and never alter behavior. Decoys are simpler: they fire unconditionally on first invocation. There are no network calls on the legitimate path and no telemetry, ever.

## Does it work against a real LLM?

The `demo` and `simulate_attack.py` flows prove the *wiring*. To test the *premise* — that a real model, handed the poisoned tool descriptions, follows the bait on its own — run [`examples/llm_efficacy.py`](examples/llm_efficacy.py): it wires the canary-protected tools to a live Claude model through the Messages API tool-use loop and records which canaries the model trips. See [docs/efficacy.md](docs/efficacy.md) for how to run it and how to read the results.

## What this catches / doesn't catch

**Catches:**
- An LLM induced to follow tool-description instructions and read a sensitive path, exfiltrate a fake credential, or call a decoy tool.
- Cross-tool exfiltration — bait planted on tool A that surfaces in a call to tool B (the alert records both `observed_in_tool` and `bait_origin_tool`).

**Doesn't catch:**
- Attackers operating outside the agent's tool-call surface (network MitM, host compromise, side-channels).
- An LLM sophisticated enough to strip `<IMPORTANT>` blocks before acting on them.
- Exfiltration through channels that never become a tool-call argument (e.g. the model narrates the bait in chat but never passes it to a tool).

**Pairs well with:** [`mcp-scan`](https://github.com/invariantlabs-ai/mcp-scan) for static description analysis, plus standard observability on your MCP traffic.

## Examples

- [`examples/basic_server.py`](examples/basic_server.py) — a real FastMCP server with all three canary types.
- [`examples/simulate_attack.py`](examples/simulate_attack.py) — drives that server with attacker-shaped inputs so you can see the raw stderr alerts without a live MCP client. Run it from anywhere: `python examples/simulate_attack.py`.

## Development

```bash
git clone https://github.com/aminrj/mcp-canary
cd mcp-canary
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest          # 32 tests
ruff check .
```

## License

MIT — see [LICENSE](LICENSE).

## Credits & inspiration

- [Thinkst Canarytokens](https://canarytokens.org/) — the gold standard for honeytoken UX.
- [Invariant Labs `mcp-scan`](https://github.com/invariantlabs-ai/mcp-scan) — complementary static analysis.
- [OWASP Agentic Security Initiative](https://genai.owasp.org/) — ASI02 (tool poisoning) is the attack class this defends against.
