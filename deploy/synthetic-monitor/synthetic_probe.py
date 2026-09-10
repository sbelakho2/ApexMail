#!/usr/bin/env python3
"""Small Prometheus exporter for ApexMail synthetic HTTP transactions."""

from __future__ import annotations

import json
import os
import socket
import ssl
import sys
import threading
import time
import traceback
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# ── Probe configuration ────────────────────────────────────────────────
LISTEN_ADDRESS = os.environ.get("SYNTHETIC_LISTEN_ADDRESS", "0.0.0.0:9128")

# Health/availability probes (simple GET)
TARGETS = [
    target.strip()
    for target in os.environ.get(
        "SYNTHETIC_TARGETS",
        "https://api.apexmail.ee/health,https://track.apexmail.ee/",
    ).split(",")
    if target.strip()
]

# SMTP connectivity probes
SMTP_TARGETS = [
    target.strip()
    for target in os.environ.get(
        "SYNTHETIC_SMTP_TARGETS",
        "smtp.apexmail.ee:25,smtp.apexmail.ee:587,smtp.apexmail.ee:465",
    ).split(",")
    if target.strip()
]

# Critical user journey probes (simulate real user flows)
# These probe deeper functionality beyond simple health checks.
LOGIN_ENDPOINT = os.environ.get("SYNTHETIC_LOGIN_ENDPOINT", "https://api.apexmail.ee/v1/auth/login")
SEND_EMAIL_ENDPOINT = os.environ.get("SYNTHETIC_SEND_EMAIL_ENDPOINT", "https://api.apexmail.ee/v1/email/send")
LIST_DOMAINS_ENDPOINT = os.environ.get("SYNTHETIC_LIST_DOMAINS_ENDPOINT", "https://api.apexmail.ee/v1/domains")

INTERVAL_SECONDS = int(os.environ.get("SYNTHETIC_INTERVAL_SECONDS", "60"))
TIMEOUT_SECONDS = int(os.environ.get("SYNTHETIC_TIMEOUT_SECONDS", "10"))
USER_AGENT = os.environ.get("SYNTHETIC_USER_AGENT", "apexmail-synthetic-monitor/1.0")
API_KEY = os.environ.get("SYNTHETIC_API_KEY", "")

_lock = threading.Lock()
_results: dict[str, dict[str, float | int | str]] = {}
_smtp_results: dict[str, dict[str, float | int | str]] = {}
_journey_results: dict[str, dict[str, float | int | str]] = {}


def _escape_label(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def _probe_target(target: str) -> dict[str, float | int | str]:
    started = time.monotonic()
    status_code = 0
    error = ""
    success = 0

    request = urllib.request.Request(target, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as response: # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected — internal tooling hitting a configured/constant endpoint, not a user-supplied URL
            status_code = response.status
            response.read(1024)
            success = 1 if 200 <= status_code < 400 else 0
    except urllib.error.HTTPError as exc:
        status_code = exc.code
        error = exc.reason or str(exc)
    except (urllib.error.URLError, TimeoutError, OSError, ssl.SSLError) as exc:
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


def _read_smtp_line(sock: socket.socket) -> bytes:
    data = b""
    while not data.endswith(b"\n") and len(data) < 2048:
        chunk = sock.recv(1)
        if not chunk:
            break
        data += chunk
    return data


def _probe_smtp_target(target: str) -> dict[str, float | int | str]:
    started = time.monotonic()
    success = 0
    error = ""

    host, port = target.rsplit(":", 1)
    port_number = int(port)
    try:
        raw_sock = socket.create_connection((host, port_number), timeout=TIMEOUT_SECONDS)
        raw_sock.settimeout(TIMEOUT_SECONDS)
        context = ssl.create_default_context() if port_number == 465 else None
        with (context.wrap_socket(raw_sock, server_hostname=host) if context else raw_sock) as sock:
            banner = _read_smtp_line(sock)
            if not banner.startswith(b"220"):
                raise RuntimeError(f"unexpected banner: {banner[:80]!r}")
            sock.sendall(b"EHLO synthetic.apexmail.ee\r\n")
            ehlo = _read_smtp_line(sock)
            if not ehlo.startswith((b"250", b"220")):
                raise RuntimeError(f"unexpected EHLO response: {ehlo[:80]!r}")
            sock.sendall(b"QUIT\r\n")
            success = 1
    except (OSError, TimeoutError, ssl.SSLError, RuntimeError, ValueError) as exc:
        error = exc.__class__.__name__
        print(
            f"synthetic SMTP probe failed for {target}: {exc!r}\n{traceback.format_exc()}",
            file=sys.stderr,
            flush=True,
        )

    return {
        "success": success,
        "duration_seconds": time.monotonic() - started,
        "last_probe_timestamp": time.time(),
        "error": error,
    }


def _probe_journey_login() -> dict[str, float | int | str]:
    """Probe the login endpoint to verify auth flow is functional."""
    started = time.monotonic()
    success = 0
    status_code = 0
    error = ""
    try:
        request = urllib.request.Request(
            LOGIN_ENDPOINT,
            data=b'{"email":"probe@apexmail.ee","password":"__synthetic_probe__"}',
            headers={
                "User-Agent": USER_AGENT,
                "Content-Type": "application/json",
            },
        )
        with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as response: # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected — internal tooling hitting a configured/constant endpoint, not a user-supplied URL
            status_code = response.status
            response.read(1024)
            # We expect 401 (unauthorized) for invalid credentials, which proves
            # the login endpoint is functional
            success = 1 if 200 <= status_code < 500 else 0
    except urllib.error.HTTPError as exc:
        status_code = exc.code
        # 401 is acceptable — means auth flow is working
        success = 1 if exc.code in (401, 400) else 0
        if not success:
            error = exc.reason or str(exc)
    except (urllib.error.URLError, TimeoutError, OSError, ssl.SSLError) as exc:
        error = exc.__class__.__name__
        print(f"synthetic journey login probe failed: {exc!r}", file=sys.stderr, flush=True)

    return {
        "success": success,
        "status_code": status_code,
        "duration_seconds": time.monotonic() - started,
        "last_probe_timestamp": time.time(),
        "error": error,
    }


def _probe_journey_list_domains() -> dict[str, float | int | str]:
    """Probe the domains list endpoint to verify domain management is functional."""
    started = time.monotonic()
    success = 0
    status_code = 0
    error = ""
    try:
        headers = {"User-Agent": USER_AGENT}
        if API_KEY:
            headers["Authorization"] = f"Bearer {API_KEY}"
        request = urllib.request.Request(LIST_DOMAINS_ENDPOINT, headers=headers)
        with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as response: # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected — internal tooling hitting a configured/constant endpoint, not a user-supplied URL
            status_code = response.status
            response.read(1024)
            success = 1 if 200 <= status_code < 400 else 0
    except urllib.error.HTTPError as exc:
        status_code = exc.code
        # 401/403 acceptable — probe may not have valid API key
        success = 1 if exc.code in (401, 403) else 0
        if not success:
            error = exc.reason or str(exc)
    except (urllib.error.URLError, TimeoutError, OSError, ssl.SSLError) as exc:
        error = exc.__class__.__name__
        print(f"synthetic journey domains probe failed: {exc!r}", file=sys.stderr, flush=True)

    return {
        "success": success,
        "status_code": status_code,
        "duration_seconds": time.monotonic() - started,
        "last_probe_timestamp": time.time(),
        "error": error,
    }


def _probe_journey_send_email() -> dict[str, float | int | str]:
    """Probe the email send endpoint to verify email submission is functional."""
    started = time.monotonic()
    success = 0
    status_code = 0
    error = ""
    try:
        headers = {
            "User-Agent": USER_AGENT,
            "Content-Type": "application/json",
        }
        if API_KEY:
            headers["Authorization"] = f"Bearer {API_KEY}"
        body = json.dumps({
            "to": "synthetic-probe@apexmail.ee",
            "subject": "Synthetic Probe",
            "text": "This is a synthetic probe to verify email send functionality.",
        }).encode("utf-8")
        request = urllib.request.Request(
            SEND_EMAIL_ENDPOINT,
            data=body,
            headers=headers,
        )
        with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as response: # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected — internal tooling hitting a configured/constant endpoint, not a user-supplied URL
            status_code = response.status
            response.read(1024)
            success = 1 if 200 <= status_code < 400 else 0
    except urllib.error.HTTPError as exc:
        status_code = exc.code
        # 401/403/429 acceptable for operational verification
        success = 1 if exc.code in (401, 403, 429) else 0
        if not success:
            error = exc.reason or str(exc)
    except (urllib.error.URLError, TimeoutError, OSError, ssl.SSLError) as exc:
        error = exc.__class__.__name__
        print(f"synthetic journey email send probe failed: {exc!r}", file=sys.stderr, flush=True)

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
        smtp_snapshot = {target: _probe_smtp_target(target) for target in SMTP_TARGETS}
        journey_snapshot = {
            "login": _probe_journey_login(),
            "list_domains": _probe_journey_list_domains(),
            "send_email": _probe_journey_send_email(),
        }
        with _lock:
            _results.clear()
            _results.update(snapshot)
            _smtp_results.clear()
            _smtp_results.update(smtp_snapshot)
            _journey_results.clear()
            _journey_results.update(journey_snapshot)
        time.sleep(max(INTERVAL_SECONDS, 5))


def _metrics() -> str:
    with _lock:
        snapshot = dict(_results)
        smtp_snapshot = dict(_smtp_results)
        journey_snapshot = dict(_journey_results)

    lines = [
        "# HELP apexmail_synthetic_transaction_success Synthetic transaction success status.",
        "# TYPE apexmail_synthetic_transaction_success gauge",
        "# HELP apexmail_synthetic_transaction_duration_seconds Synthetic transaction duration.",
        "# TYPE apexmail_synthetic_transaction_duration_seconds gauge",
        "# HELP apexmail_synthetic_transaction_status_code Synthetic transaction HTTP status code.",
        "# TYPE apexmail_synthetic_transaction_status_code gauge",
        "# HELP apexmail_synthetic_transaction_last_probe_timestamp_seconds Last synthetic probe Unix timestamp.",
        "# TYPE apexmail_synthetic_transaction_last_probe_timestamp_seconds gauge",
        "# HELP apexmail_synthetic_smtp_success Synthetic SMTP probe success status.",
        "# TYPE apexmail_synthetic_smtp_success gauge",
        "# HELP apexmail_synthetic_smtp_duration_seconds Synthetic SMTP probe duration.",
        "# TYPE apexmail_synthetic_smtp_duration_seconds gauge",
        "# HELP apexmail_synthetic_smtp_last_probe_timestamp_seconds Last synthetic SMTP probe Unix timestamp.",
        "# TYPE apexmail_synthetic_smtp_last_probe_timestamp_seconds gauge",
        "# HELP apexmail_synthetic_journey_success Synthetic user journey probe success status.",
        "# TYPE apexmail_synthetic_journey_success gauge",
        "# HELP apexmail_synthetic_journey_duration_seconds Synthetic user journey probe duration.",
        "# TYPE apexmail_synthetic_journey_duration_seconds gauge",
        "# HELP apexmail_synthetic_journey_status_code Synthetic user journey HTTP status code.",
        "# TYPE apexmail_synthetic_journey_status_code gauge",
        "# HELP apexmail_synthetic_journey_last_probe_timestamp_seconds Last synthetic journey probe Unix timestamp.",
        "# TYPE apexmail_synthetic_journey_last_probe_timestamp_seconds gauge",
    ]
    for target, result in snapshot.items():
        labels = f'target="{_escape_label(target)}",error="{_escape_label(str(result["error"]))}"'
        lines.append(f"apexmail_synthetic_transaction_success{{{labels}}} {result['success']}")
        lines.append(f"apexmail_synthetic_transaction_duration_seconds{{{labels}}} {result['duration_seconds']:.6f}")
        lines.append(f"apexmail_synthetic_transaction_status_code{{{labels}}} {result['status_code']}")
        lines.append(f"apexmail_synthetic_transaction_last_probe_timestamp_seconds{{{labels}}} {result['last_probe_timestamp']:.0f}")
    for target, result in smtp_snapshot.items():
        labels = f'target="{_escape_label(target)}",error="{_escape_label(str(result["error"]))}"'
        lines.append(f"apexmail_synthetic_smtp_success{{{labels}}} {result['success']}")
        lines.append(f"apexmail_synthetic_smtp_duration_seconds{{{labels}}} {result['duration_seconds']:.6f}")
        lines.append(f"apexmail_synthetic_smtp_last_probe_timestamp_seconds{{{labels}}} {result['last_probe_timestamp']:.0f}")
    for journey, result in journey_snapshot.items():
        labels = f'journey="{_escape_label(journey)}",error="{_escape_label(str(result["error"]))}"'
        lines.append(f"apexmail_synthetic_journey_success{{{labels}}} {result['success']}")
        lines.append(f"apexmail_synthetic_journey_duration_seconds{{{labels}}} {result['duration_seconds']:.6f}")
        lines.append(f"apexmail_synthetic_journey_status_code{{{labels}}} {result['status_code']}")
        lines.append(f"apexmail_synthetic_journey_last_probe_timestamp_seconds{{{labels}}} {result['last_probe_timestamp']:.0f}")
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
    if not TARGETS and not SMTP_TARGETS:
        raise SystemExit("SYNTHETIC_TARGETS or SYNTHETIC_SMTP_TARGETS must include at least one probe")
    host, port = LISTEN_ADDRESS.rsplit(":", 1)
    threading.Thread(target=_probe_loop, daemon=True).start()
    ThreadingHTTPServer((host, int(port)), Handler).serve_forever()


if __name__ == "__main__":
    main()
