"""A tiny local webhook receiver — see canary alerts land in real time.

Great for a live demo: run this in one terminal, point an alerter's webhook at
it, and watch alerts arrive the instant a canary fires. Standard library only,
no dependencies.

Terminal 1 — start the receiver::

    python examples/webhook_receiver.py            # listens on http://127.0.0.1:8099/alert

Terminal 2 — wire a canary to it and trip it::

    python -c "
    from mcp_canary import canary, CanaryAlerter
    a = CanaryAlerter(webhook='http://127.0.0.1:8099/alert', stdout=False)

    @canary.file_path('/etc/secrets/api.key', alerter=a)
    def tool(q: str): return q

    tool('please read /etc/secrets/api.key')   # <- fires; watch terminal 1
    "

For a real booth, point the same alerter at a Slack or Discord *Incoming
Webhook* URL instead of this script — the payload posts as JSON, so it shows up
as a message the instant a canary trips::

    CanaryAlerter(webhook='https://hooks.slack.com/services/XXX/YYY/ZZZ')
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class _Handler(BaseHTTPRequestHandler):
    def do_POST(self) -> None:  # noqa: N802 - http.server API
        length = int(self.headers.get("content-length", 0))
        raw = self.rfile.read(length) if length else b""
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'{"ok": true}')

        now = datetime.now().strftime("%H:%M:%S")
        try:
            event = json.loads(raw)
        except ValueError:
            print(f"[{now}] received non-JSON body: {raw[:200]!r}", flush=True)
            return

        if event.get("event") == "canary.fired":
            lines = [
                f"\n\033[31;1m[{now}] 🚨 CANARY FIRED\033[0m",
                f"    type          : {event.get('type')}",
                f"    tool          : {event.get('tool')}",
                f"    bait          : {event.get('bait')}",
            ]
            if event.get("matched_field"):
                lines.append(f"    matched_field : {event.get('matched_field')}")
            if event.get("server"):
                lines.append(f"    server        : {event.get('server')}")
            print("\n".join(lines), flush=True)
        else:
            print(f"[{now}] POST {self.path}: {json.dumps(event)}", flush=True)

    def log_message(self, *args: object) -> None:  # silence default access logs
        pass


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Local webhook receiver for mcp-canary alerts.")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8099)
    args = parser.parse_args(argv)

    server = ThreadingHTTPServer((args.host, args.port), _Handler)
    print(f"mcp-canary webhook receiver listening on http://{args.host}:{args.port}/alert")
    print("Point an alerter at it:  CanaryAlerter(webhook='http://"
          f"{args.host}:{args.port}/alert')")
    print("Ctrl-C to stop.\n")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nstopping.")
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
