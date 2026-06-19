# mcp-canary — Canary Tokens for the Agent Era

## What it does
mcp-canary is a Python library that drops honeytoken tripwires into FastMCP server tool descriptions. When a compromised LLM follows poisoned instructions and tries to exfiltrate bait (fake file paths, fake API keys, or calls to decoy tools), mcp-canary alerts instantly — stderr, file, or webhook.

## Why it matters
MCP's trust model assumes tool descriptions are benign. They're not. An upstream poisoning attack can inject instructions into tool descriptions that cause the LLM to read sensitive paths or echo fake credentials. mcp-canary plants the bait before the attacker does, so you detect the compromise on the first attempt. Zero false positives — if someone reads `/etc/secrets/api.key` or echoes `AKIA...`, it didn't happen by accident.

## What attendees get
- A pip-installable tool: `pip install mcp-canary`
- Three lines to add to any FastMCP server
- A live demo showing all three canary modes firing against simulated attacks
- Clear output showing the attack, the detection, and the evidence

## The demo
Attendees will see:
1. A FastMCP server with three tools, each protected by a different canary type
2. Baseline: legitimate tool calls produce normal output, no alerts
3. Attack simulation: attacker-shaped inputs trigger each canary
4. Real-time alerts showing the exact bait, the tool that fired it, and where the bait was found in the payload
5. How to configure alert sinks (stdout, file, webhook)

The demo runs with a single command and needs no setup:

```bash
pip install mcp-canary
mcp-canary demo
```

## Technical details
- Python 3.11+, pip-installable
- Works as a decorator on any FastMCP tool
- Process-global bait registry with recursive input scanning
- Three sink types: stdout (JSON), file (JSONL), HTTP webhook
- Zero network calls on the happy path
- <500 lines of Python, MIT licensed
- Source: github.com/aminrj/mcp-canary

---

## Black Hat Arsenal submission form — field by field

The CFP portal asks for the fields below. Project-derivable answers are filled
in; anything marked `<FILL: ...>` needs the presenter's own details. Copy/paste
into the form when submitting.

**Tool name:** mcp-canary

**One-line description:** Canary-token tripwires for FastMCP servers — detect a
compromised LLM the instant it follows poisoned tool descriptions.

**Track / category:** AI, ML & Data Science Security (defensive / blue-team).
Secondary fit: Red Teaming & Offensive (it operationalizes the tool-poisoning
attack class). *Pick the single closest the portal offers; lead with AI/LLM
Security.*

**Is this a new tool or an update to a previously released tool?** New tool
(first public release, v0.1.0, June 2026).

**Has this tool been presented at any other conference?** `<FILL: e.g. "No — Black Hat Europe Arsenal is the debut" or list prior venues>`

**Open source?** Yes. **License:** MIT.

**Tool URL / source code:** https://github.com/aminrj/mcp-canary —
**PyPI:** https://pypi.org/project/mcp-canary/ (`pip install mcp-canary`)

**Demo video URL:** `<FILL: link to a 2–3 min screen recording of `mcp-canary demo` + the README docs/demo.svg; record before submitting if required>`

**Abstract (website copy, ~100 words):**
> MCP's trust model assumes tool descriptions are benign. They're not. A poisoned
> upstream server or a prompt-injected context can hide instructions in a tool's
> description that make a connected LLM read sensitive files or echo credentials.
> mcp-canary plants honeytoken bait — a fake file path, a fake API key, or a decoy
> tool — inside FastMCP tool descriptions, and alerts the instant an agent surfaces
> the bait. Zero false positives, zero overhead on the happy path, three lines to
> deploy. Attendees get a pip-installable tool, a live demo of all three canary
> modes firing against simulated attacks, and a reproducible harness that tests
> whether real LLMs take the bait.

**Audience takeaways:**
- How MCP tool-description poisoning (OWASP ASI02) actually works, concretely.
- A drop-in, runtime detection layer they can add to any FastMCP server in three lines.
- How honeytoken tripwires complement static scanners like mcp-scan.
- A reproducible way to measure whether their own agent stack follows injected bait.

**Audience level:** Intermediate. Useful to anyone building or securing MCP/agent
systems; no prior MCP internals required.

**What attendees should bring:** A laptop with Python 3.11+ to follow along
(`pip install mcp-canary && mcp-canary demo`). Not required — the booth demo is
self-contained and needs no network.

**Tooling / AV needs at the booth:** Laptop + power; a monitor if provided. The
demo runs fully offline (no network, no server, no API keys), so booth Wi-Fi is
not a dependency. `<FILL: confirm any AV specifics the portal asks for>`

**Presenter(s):**
- Name: `<FILL: Amine Raji>`
- Title / company: `<FILL>`
- Bio (~75 words): `<FILL: background, relevant work, why you built this>`
- Prior speaking experience: `<FILL>`
- Contact email: `<FILL>` · Social/handle: `<FILL>`

**Source/registry availability confirmation:** Tool is publicly installable
(`pip install mcp-canary`) and source is MIT on GitHub today — satisfies the
Arsenal "attendees can take it home" requirement.
