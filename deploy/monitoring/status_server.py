#!/usr/bin/env python3
"""ApexMail Status Server — serves live health-check JSON on port 9090.

Reads from check_services.sh for real component-level health data.
When the script fails, returns cached data with a stale flag.

Endpoints:
  GET /health       — status server self-check
  GET /api/status   — full component-level status JSON
  GET /api/history  — last 90 check records
"""

import json
import os
import subprocess
import sys
import time
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path

PORT = int(os.environ.get("STATUS_PORT", "9090"))
SCRIPT_DIR = Path(__file__).resolve().parent
CHECK_SCRIPT = SCRIPT_DIR / "check_services.sh"
BASE_URL = os.environ.get("BASE_URL", "https://api.apexmail.com")
DASHBOARD_URL = os.environ.get("DASHBOARD_URL", "https://app.apexmail.com")
STATUS_URL = os.environ.get("STATUS_URL", "https://status.apexmail.ee")
CACHE_TTL = int(os.environ.get("CACHE_TTL", "60"))
HISTORY_LIMIT = int(os.environ.get("HISTORY_LIMIT", "90"))

cache = {"data": None, "ts": 0, "stale": False}
cache_lock = threading.Lock()


def run_check() -> dict:
    env = os.environ.copy()
    env["BASE_URL"] = BASE_URL
    env["DASHBOARD_URL"] = DASHBOARD_URL
    env["STATUS_URL"] = STATUS_URL

    try:
        result = subprocess.run(
            ["bash", str(CHECK_SCRIPT)],
            capture_output=True,
            text=True,
            timeout=120,
            env=env,
        )
        if result.returncode == 0 and result.stdout.strip():
            return json.loads(result.stdout)
    except (subprocess.TimeoutExpired, json.JSONDecodeError, Exception):
        pass
    return None


def refresh_cache():
    global cache
    while True:
        data = run_check()
        with cache_lock:
            if data:
                cache["data"] = data
                cache["ts"] = time.time()
                cache["stale"] = False
            else:
                cache["stale"] = True
        time.sleep(CACHE_TTL)


def build_status_response():
    with cache_lock:
        if cache["data"]:
            resp = dict(cache["data"])
            resp["cached_at"] = time.strftime(
                "%Y-%m-%dT%H:%M:%SZ", time.gmtime(cache["ts"])
            )
            resp["stale"] = cache["stale"]
        else:
            resp = {
                "overall_status": "unknown",
                "checked_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "total_probes": 0,
                "failures": 0,
                "probes": [],
                "cached_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "stale": True,
            }
    return resp


def load_history(limit: int = HISTORY_LIMIT):
    history_file = SCRIPT_DIR / ".check_history.json"
    if not history_file.exists():
        return {"checks": []}
    try:
        with open(history_file) as f:
            data = json.load(f)
        checks = data.get("checks", [])[:limit]
        return {"checks": checks, "total": len(checks)}
    except (json.JSONDecodeError, OSError):
        return {"checks": []}


class StatusHandler(BaseHTTPRequestHandler):
    def _cors(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Accept, Content-Type")
        self.send_header("Cache-Control", "public, max-age=60")
        self.send_header("X-Content-Type-Options", "nosniff")

    def _json(self, code: int, body: dict):
        payload = json.dumps(body, indent=2).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self._cors()
        self.end_headers()
        self.wfile.write(payload)

    def do_OPTIONS(self):
        self.send_response(204)
        self._cors()
        self.end_headers()

    def do_GET(self):
        path = self.path.split("?")[0]

        if path == "/health":
            resp = build_status_response()
            healthy = resp.get("overall_status") == "ok" or (
                resp.get("overall_status") == "degraded"
                and resp.get("failures", 0) < resp.get("total_probes", 1)
            )
            code = 200 if (healthy or resp.get("stale")) else 503
            self._json(code, {"status": "ok", "server": "apexmail-status"})

        elif path == "/api/status":
            resp = build_status_response()
            self._json(200, resp)

        elif path == "/api/history":
            history = load_history()
            self._json(200, history)

        elif path == "/":
            resp = build_status_response()
            probes_html = ""
            for p in resp.get("probes", []):
                svc = p.get("service", "?")
                st = p.get("status", "?")
                ms = p.get("response_ms", 0)
                up = p.get("uptime_90d_pct", "0")
                color = "green" if st == "ok" else "red"
                badges = f'<span style="color:{color};font-weight:bold">{st.upper()}</span>'
                probes_html += f"<tr><td>{svc}</td><td>{badges}</td><td>{ms}ms</td><td>{up}%</td></tr>\n"

            html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>ApexMail Status</title>
<style>
  body {{ font-family: system-ui, sans-serif; max-width: 800px; margin: 2rem auto; padding: 0 1rem; }}
  h1 {{ margin-bottom: 0.25rem; }}
  .summary {{ color: #666; font-size: 0.9rem; margin-bottom: 1.5rem; }}
  table {{ width: 100%; border-collapse: collapse; }}
  th, td {{ padding: 0.75rem; text-align: left; border-bottom: 1px solid #eee; }}
  th {{ font-size: 0.8rem; text-transform: uppercase; color: #999; }}
  .stale {{ background: #fff3cd; padding: 0.75rem; border-radius: 4px; margin-bottom: 1rem; font-size: 0.9rem; }}
  .footer {{ margin-top: 2rem; font-size: 0.8rem; color: #999; }}
  .footer a {{ color: #666; }}
</style>
</head>
<body>
<h1>ApexMail Service Status</h1>
<p class="summary">Overall: <strong>{resp.get("overall_status","?").upper()}</strong> &middot;
Last check: {resp.get("checked_at","?")} &middot;
Cached: {resp.get("cached_at","?")}</p>
{"<div class='stale'>Data may be stale — last successful check was " + resp.get("cached_at","?") + "</div>" if resp.get("stale") else ""}
<table>
<tr><th>Service</th><th>Status</th><th>Latency</th><th>90d Uptime</th></tr>
{probes_html}
</table>
<p class="footer">
  <a href="/api/status">JSON API</a> &middot;
  <a href="/api/history">History</a> &middot;
  <a href="https://apexmail.ee/">apexmail.ee</a> &middot;
  <a href="https://apexmail.ee/performance-methodology/">Methodology</a>
</p>
</body>
</html>"""
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(html.encode())))
            self._cors()
            self.end_headers()
            self.wfile.write(html.encode())

        else:
            self._json(404, {"error": "not found"})


def main():
    print(f"[status-server] Starting on port {PORT}")
    print(f"[status-server] Check script: {CHECK_SCRIPT}")
    print(f"[status-server] Cache TTL: {CACHE_TTL}s")

    if not CHECK_SCRIPT.exists():
        print(f"[status-server] WARNING: check_services.sh not found at {CHECK_SCRIPT}", file=sys.stderr)

    t = threading.Thread(target=refresh_cache, daemon=True)
    t.start()

    server = HTTPServer(("0.0.0.0", PORT), StatusHandler)
    print(f"[status-server] Listening on 0.0.0.0:{PORT}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[status-server] Shutting down")
        server.shutdown()


if __name__ == "__main__":
    main()
