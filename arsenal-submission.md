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
