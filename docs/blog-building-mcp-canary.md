# Building mcp-canary in a weekend: notes from the build

I shipped the first version of [mcp-canary](https://github.com/aminrj/mcp-canary) in one sitting. The library is small on purpose. Under 500 lines of Python, two runtime deps, an opt-in third for FastMCP itself. This post is the writeup for people about to build something similar who want to skip a few of my wrong turns.

If you want the pitch, the README has it. This is the appendix.

## What the library actually does

You decorate a FastMCP tool. The decorator silently appends an `<IMPORTANT>` block to the tool's docstring, telling any reader to leak a fake credential, read a fake file path, or call a decoy tool. A process-global registry remembers the bait. Every tool call gets its arguments scanned for any registered bait substring. On a hit, an alerter fires.

Three lines of user-facing code:

```python
from mcp_canary import canary, CanaryAlerter
alerter = CanaryAlerter()

@mcp.tool()
@canary.file_path("/etc/secrets/api.key", alerter=alerter)
def add(a: int, b: int) -> int:
    """Adds two numbers."""
    return a + b
```

The legitimate `add(2, 3)` still returns `5`. A poisoned LLM that follows the bait will surface the path *somewhere* in the server's tool calls, and you find out within milliseconds.

## The cross-tool detection thing

My first instinct was to scope each decorator's bait to its own tool. Bait planted on `add` would only fire when echoed into `add`'s own arguments. That's wrong, and it took me about ten minutes to convince myself.

The whole point of poisoning is to make the LLM act *across* tools. Read this fake file via tool A, then quietly pass it as a "context" string to tool B, where the operator wasn't looking. So the registry is one flat map, and every tool's pre-call hook scans against everything.

The first time I ran the simulator the alert came back with `bait_origin_tool: "add"` but `observed_in_tool: "list_buckets"`. Exactly the pattern I wanted to catch.

## Decorator order is a real constraint

`@mcp.tool()` reads the function's docstring at decoration time. If `@canary.*` runs *after* it, the bait never reaches the published description. So the user has to write:

```python
@mcp.tool()             # runs second, sees the mutated doc
@canary.file_path(...)  # runs first
```

That's just how Python decorators work, bottom-up. I considered writing a wrapper that auto-inserts itself in the right slot, decided the magic wasn't worth it, and put the constraint in three places instead: the README, the module docstring, and the example file. If users mis-order it, the canary silently does nothing. That's the worst possible failure mode for a security tool, so I'd rather be loud about it up front.

## Bytes don't trip the scanner

The recursive walker only inspects `str`, `dict`, `list`, and `tuple`. I wrote a test for it pretty late and it almost surprised me into a bug:

```python
def test_scan_ignores_non_string_types() -> None:
    _seed("AKIATESTBAIT0000")
    m = scan_inputs((1, 2.5, None, b"AKIATESTBAIT0000"), {"n": 7})
    assert m is None
```

The `bytes` case bothers me a little. An LLM exfiltrating via base64 would defeat substring matching anyway, so I left bytes out for v1. If it becomes a common evasion pattern, I'll revisit.

## I shipped a docs bug to my own README

The first README claimed alerts would show `"matched_field": "kwargs.notes"`. The scanner actually emits the bare kwarg name, just `"notes"`. I caught it in the post-build verification pass, not during the build itself.

Lesson, written down in case I forget: build the smoke test that runs the README's exact example, not just the unit tests. The unit tests verify the implementation. The smoke test verifies the *story*.

## I had dead code in my registry

The `_Registry` dataclass had two maps, `by_bait` and `decoys`. The `decoys` map was written by a `register_decoy()` method and read by exactly nothing. The decoy decorator fires unconditionally on call — it doesn't need the registry at all. I noticed it on the audit pass, deleted both, and the test suite stayed green. Eight lines gone for free.

This is the kind of bug that survives test-driven workflows. Tests verify outputs, not whether your internal state is actually being used.

## Numbers

| Metric | Value |
|---|---|
| Python files in `mcp_canary/` | 7 |
| Total runtime LOC | ~280 |
| Tests | 32 |
| Test suite wall time | 0.25s |
| Wheel size | 28 KB |
| Runtime deps | 2 (`httpx`, `pydantic`); `mcp` as an extra |
| CI matrix | Python 3.11, 3.12, 3.13 |
| Time from `git init` to PyPI-ready | one session |

The dependency budget came from the spec, which capped me at three packages. It was easy to hold to. `httpx` does the webhook sink, `pydantic` gets me a frozen `CanaryEvent` model with one line, and `mcp` is opt-in because users who already have FastMCP installed shouldn't have to download a second copy.

## Things I'd do differently

Write the smoke-test script before the README. I had the wrong `matched_field` in the README for two commits because the README was authored before I ever ran a real end-to-end alert. Order matters: example, then README, then publish.

Don't bother with a `decoys` map. I assumed the decoy detector might want to look up records later, for richer reporting maybe. It never did. Defer the data structure until something actually reads it.

If possible, encode the decorator-order rule in the runtime. I can't really do this in the type system — Python decorators don't carry that kind of metadata. But a runtime check could verify it: if a tool's published description doesn't contain the canary marker by the time someone calls it, log a loud warning. Small v1.1 thing.

## What's not in v1

Resisting feature creep was honestly the hardest part of the build. The spec was explicit about what to leave out, and I held the line:

- No hosted dashboard.
- No DNS-based canaries.
- No Slack or PagerDuty plugins. The webhook sink is enough; point it at your own infra.
- No more than three canary types.
- No telemetry. None.

The whole thing is auditable in an afternoon, which is part of the point.

## What's next

PyPI Trusted Publisher setup is the next step. Once that's wired up, tagging `v0.1.0` will publish automatically. Then it's launch posts and seeing whether anyone cares.

If you're running an MCP server in production right now and you can't tell me what would happen if a tool description got rewritten under you, you should probably install this.

Source: [github.com/aminrj/mcp-canary](https://github.com/aminrj/mcp-canary).
