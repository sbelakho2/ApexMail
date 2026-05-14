#!/usr/bin/env python3
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


DEFAULT_SCRAPE_URI = "https://clickhouse:8443/"
DEFAULT_PORT = 9116
METRIC_NAME_PATTERN = re.compile(r"[^a-zA-Z0-9_]")


def parse_args(arguments):
    scrape_uri = os.environ.get("CLICKHOUSE_SCRAPE_URI", DEFAULT_SCRAPE_URI)
    port = int(os.environ.get("CLICKHOUSE_EXPORTER_PORT", DEFAULT_PORT))

    for argument in arguments:
        if argument.startswith("-scrape_uri="):
            scrape_uri = argument.split("=", 1)[1]
        elif argument.startswith("-web.listen-address="):
            listen_address = argument.split("=", 1)[1]
            if ":" in listen_address:
                port = int(listen_address.rsplit(":", 1)[1])

    return scrape_uri, port


def normalize_metric_name(raw_name):
    normalized = METRIC_NAME_PATTERN.sub("_", raw_name.strip())
    normalized = re.sub(r"_+", "_", normalized).strip("_").lower()
    return f"clickhouse_{normalized}" if normalized else "clickhouse_unknown_metric"


def clickhouse_request(scrape_uri, query):
    user = os.environ.get("CLICKHOUSE_USER", "default")
    password = os.environ.get("CLICKHOUSE_PASSWORD", "")
    parsed_uri = urllib.parse.urlparse(scrape_uri)
    allow_insecure = os.environ.get("CLICKHOUSE_ALLOW_INSECURE_HTTP", "").lower() in {"1", "true", "yes"}
    if password and parsed_uri.scheme != "https" and not allow_insecure:
        raise RuntimeError("refusing to send ClickHouse password over non-TLS HTTP")
    request = urllib.request.Request(scrape_uri, data=query.encode("utf-8"), method="POST")
    request.add_header("Content-Type", "text/plain; charset=utf-8")
    request.add_header("X-ClickHouse-User", user)
    if password:
        request.add_header("X-ClickHouse-Key", password)

    with urllib.request.urlopen(request, timeout=5) as response:
        return response.read().decode("utf-8")


def parse_tab_separated_metrics(body):
    metrics = []
    for line in body.splitlines():
        fields = line.split("\t")
        if len(fields) != 2:
            continue
        metric_name, metric_value = fields
        try:
            value = float(metric_value)
        except ValueError:
            continue
        metrics.append((normalize_metric_name(metric_name), value))
    return metrics


def scrape_clickhouse(scrape_uri):
    queries = [
        "SELECT metric, value FROM system.metrics FORMAT TabSeparated",
        "SELECT metric, value FROM system.asynchronous_metrics FORMAT TabSeparated",
    ]
    collected_metrics = []
    for query in queries:
        body = clickhouse_request(scrape_uri, query)
        collected_metrics.extend(parse_tab_separated_metrics(body))
    return collected_metrics


def render_prometheus(metrics, scrape_duration, scrape_error=None):
    lines = [
        "# HELP clickhouse_up Whether the exporter could scrape ClickHouse.",
        "# TYPE clickhouse_up gauge",
        f"clickhouse_up {0 if scrape_error else 1}",
        "# HELP clickhouse_exporter_scrape_duration_seconds Duration of the last ClickHouse scrape.",
        "# TYPE clickhouse_exporter_scrape_duration_seconds gauge",
        f"clickhouse_exporter_scrape_duration_seconds {scrape_duration:.6f}",
    ]

    if scrape_error:
        escaped_error = str(scrape_error).replace("\\", "\\\\").replace('"', '\\"')[:240]
        lines.extend([
            "# HELP clickhouse_exporter_last_scrape_error Last scrape error, exposed as a labelled gauge.",
            "# TYPE clickhouse_exporter_last_scrape_error gauge",
            f'clickhouse_exporter_last_scrape_error{{message="{escaped_error}"}} 1',
        ])
    else:
        seen = set()
        for metric_name, metric_value in metrics:
            if metric_name not in seen:
                lines.extend([f"# TYPE {metric_name} gauge"])
                seen.add(metric_name)
            lines.append(f"{metric_name} {metric_value:g}")

    lines.append("")
    return "\n".join(lines).encode("utf-8")


class MetricsHandler(BaseHTTPRequestHandler):
    scrape_uri = DEFAULT_SCRAPE_URI

    def do_GET(self):
        parsed_path = urllib.parse.urlparse(self.path)
        if parsed_path.path == "/healthz":
            self.send_response(HTTPStatus.OK)
            self.end_headers()
            self.wfile.write(b"OK\n")
            return
        if parsed_path.path != "/metrics":
            self.send_response(HTTPStatus.NOT_FOUND)
            self.end_headers()
            return

        started_at = time.monotonic()
        try:
            metrics = scrape_clickhouse(self.scrape_uri)
            payload = render_prometheus(metrics, time.monotonic() - started_at)
        except (OSError, urllib.error.URLError, urllib.error.HTTPError) as error:
            payload = render_prometheus([], time.monotonic() - started_at, error)

        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, format_string, *args):
        sys.stderr.write("clickhouse-exporter: " + format_string % args + "\n")


def main():
    scrape_uri, port = parse_args(sys.argv[1:])
    MetricsHandler.scrape_uri = scrape_uri
    server = ThreadingHTTPServer(("0.0.0.0", port), MetricsHandler)
    print(f"clickhouse exporter listening on :{port}, scraping {scrape_uri}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()