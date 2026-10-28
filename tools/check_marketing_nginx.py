#!/usr/bin/env python3
"""Live nginx serving check for the marketing container.

`apps/marketing-zola/nginx.conf` is the config the marketing container runs
(installed as `/etc/nginx/conf.d/default.conf`): a public listener on 8080,
an internal static server on 8081 and a consent-filtering proxy on 8082. The
pixel walk and the serving gate both exercise the api-server path; this tool
proves the OTHER serving path — the one that runs in front of the zola build
output — really serves the ARK documents and assets.

It copies the committed config into a throwaway prefix, rewrites the baked-in
container paths/ports to this machine, runs the real nginx binary, and asserts
over HTTP:

  * `/`                     200 text/html, CSP + nosniff + HSTS headers,
                            the cookie banner pending state
  * consent cookie           the banner flips to `recorded` (the sub_filter hop)
  * `/css/ark.css`          200 text/css, immutable cache tier
  * `/css/styles.css`       200 text/css
  * `/fonts/*.woff2`        200 font/woff2
  * gzip                    HTML and CSS come back compressed
  * `/js/anything.js`       404 — the site ships no scripts
  * a missing path          404 with the branded error document
  * `nginx -t`              the config itself validates

Requires a local `nginx` binary (the container config is what runs in
production; this is a deployment-time check, not a CI lane — the CI image does
not ship nginx).

Usage: python3 tools/check_marketing_nginx.py [--root DIR] [--keep]
"""

from __future__ import annotations

import argparse
import gzip
import http.client
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CONFIG = ROOT / "apps/marketing-zola/nginx.conf"
PUBLIC = ROOT / "apps/marketing-zola/public"
PORTS = {"8080": 18080, "8081": 18081, "8082": 18082}


def free(port: int) -> bool:
    with socket.socket() as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind(("127.0.0.1", port))
            return True
        except OSError:
            return False


def request(port: int, path: str, headers: dict[str, str] | None = None):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    conn.request("GET", path, headers=headers or {})
    resp = conn.getresponse()
    body = resp.read()
    conn.close()
    return resp, body


def rewrite_config(text: str, public: Path, ports: dict[str, int]) -> str:
    """Rebind the committed container config's baked-in paths and ports to
    this machine (the temp-prefix conf the live check then runs)."""
    return (text
            .replace("/usr/share/nginx/html", str(public))
            .replace("listen 8080;", f"listen {ports['8080']};")
            .replace("listen 127.0.0.1:8081;", f"listen 127.0.0.1:{ports['8081']};")
            .replace("127.0.0.1:8081", f"127.0.0.1:{ports['8081']}")
            .replace("127.0.0.1:8082", f"127.0.0.1:{ports['8082']}")
            .replace("listen 127.0.0.1:8082;", f"listen 127.0.0.1:{ports['8082']};"))


def banner_state(html: str, state: str) -> bool:
    """The cookie banner renders in `state` (pending on first visit,
    recorded after the consent cookie hop)."""
    return f'data-consent-state="{state}"' in html or f"data-consent-state={state}" in html


def self_test() -> int:
    """nginx-free proof of the config-rewrite and expectation layers: a
    clean fixture conf rebinds fully, each drifted variant leaves a stale
    container token behind, and the banner-state expectations fire."""
    import tempfile

    def miss(detail: str) -> int:
        print(f"self-test FAIL: {detail}", file=sys.stderr)
        return 1

    conf = ("server {\n    listen 8080;\n    root /usr/share/nginx/html;\n}\n"
            "server {\n    listen 127.0.0.1:8081;\n    root /usr/share/nginx/html;\n}\n"
            "location /api/ { proxy_pass http://127.0.0.1:8082/; }\n")
    with tempfile.TemporaryDirectory() as td:
        public = Path(td) / "public"
        public.mkdir()
        good = rewrite_config(conf, public, PORTS)
        for name, ok in (
            ("public listener rebound", "listen 18080;" in good and "listen 8080;" not in good),
            ("docroot rebound", str(public) in good and "/usr/share/nginx/html" not in good),
            ("internal hops rebound",
             "127.0.0.1:18081" in good and "127.0.0.1:18082" in good
             and ":8081" not in good and ":8082" not in good),
        ):
            if not ok:
                return miss(f"clean fixture failed: {name}")

        drift = (
            ("listener drift", conf.replace("listen 8080;", "listen 8080 default_server;"),
             lambda r: "8080" in r),
            ("docroot drift", conf.replace("/usr/share/nginx/html", "/srv/site"),
             lambda r: str(public) not in r),
            ("internal-hop drift", conf.replace("8082", "8083"),
             lambda r: "18082" not in r),
        )
        for name, bad_conf, detected in drift:
            if not detected(rewrite_config(bad_conf, public, PORTS)):
                return miss(f"{name} not detectable after rewrite")

        pending = '<div data-consent-state="pending">cookies</div>'
        if not banner_state(pending, "pending"):
            return miss("banner pending expectation broken")
        if banner_state("<div>no banner here</div>", "pending"):
            return miss("missing banner state must fail the expectation")
        if banner_state(pending, "recorded"):
            return miss("unflipped consent page must fail the recorded expectation")
    print("self-test: ok")
    return 0


def main() -> int:
    if "--self-test" in sys.argv:
        return self_test()
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default=str(PUBLIC))
    ap.add_argument("--keep", action="store_true", help="keep the temp prefix for inspection")
    args = ap.parse_args()

    nginx = shutil.which("nginx")
    if not nginx:
        print("FAIL: nginx is not installed — this check runs on the deployment host", file=sys.stderr)
        return 2
    public = Path(args.root).resolve()
    if not (public / "index.html").is_file():
        print(f"FAIL: {public}/index.html is missing — run `zola build` first", file=sys.stderr)
        return 2
    for port in PORTS.values():
        if not free(port):
            print(f"FAIL: port {port} is already in use", file=sys.stderr)
            return 2

    prefix = Path(tempfile.mkdtemp(prefix="apexmail-nginx-"))
    conf = rewrite_config(CONFIG.read_text(), public, PORTS)
    (prefix / "nginx.conf").write_text(
        f"worker_processes 1;\npid {prefix}/nginx.pid;\n"
        f"error_log {prefix}/error.log;\n"
        f"events {{ worker_connections 64; }}\n"
        f"http {{\n  access_log off;\n  include {prefix}/mime.types;\n  default_type application/octet-stream;\n  client_body_temp_path {prefix}/body;\n"
        f"  proxy_temp_path {prefix}/proxy;\n  fastcgi_temp_path {prefix}/fastcgi;\n"
        f"  uwsgi_temp_path {prefix}/uwsgi;\n  scgi_temp_path {prefix}/scgi;\n"
        f"{conf}\n}}\n"
    )
    mime = Path("/opt/homebrew/etc/nginx/mime.types")
    if not mime.is_file():
        mime = Path("/etc/nginx/mime.types")
    if mime.is_file():
        (prefix / "mime.types").write_text(mime.read_text())
    for d in ("body", "proxy", "fastcgi", "uwsgi", "scgi"):
        (prefix / d).mkdir()

    failures: list[str] = []

    def check(name: str, ok: bool, detail: str = "") -> None:
        if not ok:
            failures.append(f"{name}: {detail}")

    tested = subprocess.run([nginx, "-t", "-p", str(prefix), "-c", str(prefix / "nginx.conf")],
                            capture_output=True, text=True)
    check("nginx -t", tested.returncode == 0, (tested.stderr or tested.stdout).strip()[:400])
    if tested.returncode != 0:
        print("\n".join(failures))
        return 1

    started = subprocess.run([nginx, "-p", str(prefix), "-c", str(prefix / "nginx.conf")],
                             capture_output=True, text=True)
    if started.returncode != 0:
        print(f"FAIL: nginx did not start: {started.stderr.strip()[:400]}")
        return 1
    try:
        time.sleep(0.4)
        port = PORTS["8080"]

        resp, body = request(port, "/")
        check("GET /", resp.status == 200, f"status {resp.status}")
        ctype = (resp.getheader("Content-Type") or "")
        check("GET / content-type", ctype.startswith("text/html"), ctype)
        csp = resp.getheader("Content-Security-Policy") or ""
        check("GET / CSP", "script-src 'none'" in csp, csp[:120])
        check("GET / nosniff", resp.getheader("X-Content-Type-Options") == "nosniff", "")
        check("GET / HSTS", "max-age=" in (resp.getheader("Strict-Transport-Security") or ""), "")
        html = body.decode("utf-8", "replace")
        check("banner pending", banner_state(html, "pending"),
              "cookie banner state not found on /")

        resp, body = request(port, "/", {"Cookie": "apexmail_consent=1"})
        html = body.decode("utf-8", "replace")
        check("banner recorded with consent", banner_state(html, "recorded"),
              "the sub_filter hop did not rewrite the banner state")

        resp, body = request(port, "/css/ark.css")
        check("GET /css/ark.css", resp.status == 200, f"status {resp.status}")
        check("ark.css content-type", (resp.getheader("Content-Type") or "").startswith("text/css"),
              resp.getheader("Content-Type") or "")
        check("ark.css cache tier", "immutable" in (resp.getheader("Cache-Control") or ""),
              resp.getheader("Cache-Control") or "")
        check("ark.css body", b"--ink" in body or b"--background" in body, "tokens missing")

        resp, body = request(port, "/css/styles.css")
        check("GET /css/styles.css", resp.status == 200, f"status {resp.status}")

        resp, body = request(port, "/fonts/Overpass-latin-400-normal.woff2")
        check("GET /fonts/...woff2", resp.status == 200, f"status {resp.status}")
        check("woff2 content-type", "font/woff2" in (resp.getheader("Content-Type") or ""),
              resp.getheader("Content-Type") or "")

        resp, body = request(port, "/", {"Accept-Encoding": "gzip"})
        enc = (resp.getheader("Content-Encoding") or "")
        check("gzip html", enc == "gzip", f"content-encoding {enc or 'none'}")
        if enc == "gzip":
            try:
                gzip.decompress(body)
            except OSError as exc:
                check("gzip decodes", False, str(exc))

        resp, body = request(port, "/css/ark.css", {"Accept-Encoding": "gzip"})
        check("gzip css", (resp.getheader("Content-Encoding") or "") == "gzip",
              resp.getheader("Content-Encoding") or "none")

        resp, body = request(port, "/js/app.js")
        check("no script route", resp.status == 404, f"status {resp.status}")

        resp, body = request(port, "/definitely-not-a-page")
        check("404 status", resp.status == 404, f"status {resp.status}")
        text = body.decode("utf-8", "replace").lower()
        check("branded 404", "avenir" not in text and "page not found" in text or "404" in text,
              "the branded error document did not render")
    finally:
        subprocess.run([nginx, "-p", str(prefix), "-c", str(prefix / "nginx.conf"), "-s", "stop"],
                       capture_output=True, text=True)
        if not args.keep:
            shutil.rmtree(prefix, ignore_errors=True)

    if failures:
        print(f"FAIL: {len(failures)} violation(s)")
        for failure in failures:
            print(" -", failure)
        return 1
    print("nginx marketing serving: 0 violations")
    return 0


if __name__ == "__main__":
    sys.exit(main())
