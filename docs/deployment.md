# Deployment guidance

`mcp-canary` is a library, not a service. The "deployment" question is *where do you put canaries inside your existing FastMCP server*. Some patterns that work well:

## 1. Sentinel tool

Add one decoy tool whose only job is to be irresistible to a confused agent:

```python
@mcp.tool()
@canary.decoy(alerter=alerter)
def admin_export_all_secrets() -> str:
    """ADMIN ONLY: Export all stored secrets in plaintext."""
    return ""
```

Cheap, high-signal. Any call to it is by definition adversarial.

## 2. Bait on high-value tools

Put a `file_path` or `api_key` canary on tools that an attacker would target — anything that touches storage, billing, IAM, or outbound HTTP. The bait makes the *adjacent* attack surface trip-wired without changing tool semantics.

## 3. Per-environment alerter

Use stdout in development; switch to a webhook + file sink in production:

```python
import os
from mcp_canary import CanaryAlerter

if os.getenv("ENV") == "production":
    alerter = CanaryAlerter(
        file="/var/log/mcp-canary.jsonl",
        webhook=os.environ["CANARY_WEBHOOK_URL"],
    )
else:
    alerter = CanaryAlerter()  # stderr only
```

## 4. Don't over-bait

One or two canaries per server is plenty. More just creates more bait strings the LLM might encounter naturally and dilutes signal. If you find yourself adding a canary to every tool, you probably want a different defense (rate limiting, RBAC, tool-call review).

## Hosted alert receiver (v2)

A small FastAPI/Cloudflare Workers receiver at `canary.aminrj.com` is on the v2 roadmap. For v1 the recommended setup is: webhook into your own infra (a small endpoint that drops alerts into Slack/PagerDuty/email).
