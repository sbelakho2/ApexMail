#!/usr/bin/env python3
"""Small Prometheus exporter for ApexMail synthetic HTTP transactions."""

from __future__ import annotations

import os
import sys
import threading
import time
import traceback
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

LISTEN_ADDRESS = os.environ.get("SYNTHETIC_LISTEN_ADDRESS", "0.0.0.0:9128")
TARGETS = [
    target.strip()
    for target in os.environ.get(
        "SYNTHETIC_TARGETS",
        "https://api.apexmail.ee/health,https://track.apexmail.ee/",
    ).split(",")
    if target.strip()
]
INTERVAL_SECONDS = int(os.environ.get("SYNTHETIC_INTERVAL_SECONDS", "60"))
TIMEOUT_SECONDS = int(os.environ.get("SYNTHETIC_TIMEOUT_SECONDS", "10"))
USER_AGENT = os.environ.get("SYNTHETIC_USER_AGENT", "apexmail-synthetic-monitor/1.0")

_lock = threading.Lock()
_results: dict[str, dict[str, float | int | str]] = {}


def _escape_label(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def _probe_target(target: str) -> dict[str, float | int | str]:
    started = time.monotonic()
    status_code = 0
    error = ""
    success = 0

    request = urllib.request.Request(target, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as response:
            status_code = response.status
            response.read(1024)
            success = 1 if 200 <= status_code < 400 else 0
    except urllib.error.HTTPError as exc:
        status_code = exc.code
        error = exc.reason or str(exc)
    except Exception as exc:  # noqa: BLE001 - metrics should preserve probe failures.
        error = exc.__class__.__name__
        print(
            f"synthetic probe failed for {target}: {exc!r}\n{traceback.format_exc()}",
            file=sys.stderr,
            flush=True,
        )

    return {
        "success": success,
        "status_code": status_code,
        "duration_seconds": time.monotonic() - started,
        "last_probe_timestamp": time.time(),
        "error": error,
    }


def _probe_loop() -> None:
    while True:
        snapshot = {target: _probe_target(target) for target in TARGETS}
        with _lock:
            _results.clear()
            _results.update(snapshot)
        time.sleep(max(INTERVAL_SECONDS, 5))


def _metrics() -> str:
    with _lock:
        snapshot = dict(_results)

    lines = [
        "# HELP apexmail_synthetic_transaction_success Synthetic transaction success status.",
        "# TYPE apexmail_synthetic_transaction_success gauge",
        "# HELP apexmail_synthetic_transaction_duration_seconds Synthetic transaction duration.",
        "# TYPE apexmail_synthetic_transaction_duration_seconds gauge",
        "# HELP apexmail_synthetic_transaction_status_code Synthetic transaction HTTP status code.",
        "# TYPE apexmail_synthetic_transaction_status_code gauge",
        "# HELP apexmail_synthetic_transaction_last_probe_timestamp_seconds Last synthetic probe Unix timestamp.",
        "# TYPE apexmail_synthetic_transaction_last_probe_timestamp_seconds gauge",
    ]
    for target, result in snapshot.items():
        labels = f'target="{_escape_label(target)}",error="{_escape_label(str(result["error"]))}"'
        lines.append(f"apexmail_synthetic_transaction_success{{{labels}}} {result['success']}")
        lines.append(f"apexmail_synthetic_transaction_duration_seconds{{{labels}}} {result['duration_seconds']:.6f}")
        lines.append(f"apexmail_synthetic_transaction_status_code{{{labels}}} {result['status_code']}")
        lines.append(f"apexmail_synthetic_transaction_last_probe_timestamp_seconds{{{labels}}} {result['last_probe_timestamp']:.0f}")
    return "\n".join(lines) + "\n"


class Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API.
        if self.path == "/healthz":
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok\n")
            return
        if self.path != "/metrics":
            self.send_response(404)
            self.end_headers()
            return

        body = _metrics().encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        return


def main() -> None:
    if not TARGETS:
        raise SystemExit("SYNTHETIC_TARGETS must include at least one URL")
    host, port = LISTEN_ADDRESS.rsplit(":", 1)
    threading.Thread(target=_probe_loop, daemon=True).start()
    ThreadingHTTPServer((host, int(port)), Handler).serve_forever()


if __name__ == "__main__":
    main()
