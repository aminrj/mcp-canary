# Threat model

## Assumptions

- You operate a FastMCP server and trust your own server code.
- The agent connecting to your server is *intended* to be benign but may be compromised by upstream prompt injection or a malicious peer MCP server.
- Tool descriptions you publish are read by the agent's LLM as part of its prompt. The LLM may follow instructions embedded in them.
- You can read the alerter sink (stderr, file, or webhook).

## What `mcp-canary` catches

| Signal | Catches |
|---|---|
| File-path canary | An LLM that read a fake sensitive path because a poisoned tool description told it to, then passed the path or its "contents" back through any tool argument. |
| API-key canary | An LLM that took a shape-believable fake credential from a tool description and echoed it into a subsequent tool call (a common exfiltration pattern). |
| Decoy tool | Any agent that calls a tool clearly marked SYSTEM USE ONLY — typically because a prompt injection added it to the agent's plan. |

## What it does *not* catch

- **Out-of-band exfiltration.** If the agent reads the bait and exfiltrates it via a non-tool channel (DNS lookup, network call from an unrelated process, screenshot upload), the canary cannot see it. v2 plans DNS-based canaries to close part of this gap.
- **Smart attackers who strip canaries.** A sophisticated injector may scan tool descriptions for `<IMPORTANT>` blocks before deciding what to follow. The marker is intentionally visible so operators can audit; this is a tradeoff.
- **Server compromise.** If your host is owned, all bets are off — the attacker can disable the alerter.
- **False negatives from LLMs that ignore tool descriptions entirely.** A well-aligned agent might read the bait and refuse to follow it. That's a *good* outcome, but it means no signal — pair with static scanning (`mcp-scan`) to catch the poisoning attempt itself.

## Privacy

`mcp-canary` performs zero network calls unless you configure an `HttpWebhookSink`, and even then only fires to the URL you provided. There is no telemetry, no anonymous usage reporting, and no phone-home behavior. Auditable: it's <500 lines of Python.

## Operational guidance

- **Choose distinctive bait paths.** `/etc/secrets/<service>.key` is more believable than `/foo/bar`.
- **Never reuse a real credential as bait.** Always use the generators or pass an obviously-fake string. If a real key ends up in the registry, a buggy alerter could leak it.
- **Combine sinks for durability.** Webhooks fail; logs persist. `CanaryAlerter(file="alerts.log", webhook=...)` is a sensible default.
- **Review your alerter's logs.** A canary that fires into stderr and is never read is no canary at all.
