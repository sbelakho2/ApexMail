#!/usr/bin/env python3
"""Homepage public metrics — every hero number sourced from an artifact.

The hero band used to hardcode three literals (99.9%, 1.8s, 5.2m) with a link
to the methodology page but NO production source behind them. Plan A4/B5
forbid that: a published number must come from an artifact that records WHERE
it was measured, WHEN, and over WHICH window — or the page must not present it
as measured.

This tool writes `apps/marketing-zola/data/public_metrics.json`:

  * `deliveries_30d`  — MEASURED from the ClickHouse event store (count of
    `sent` events over the window; the same `CLICKHOUSE_*` conventions as
    tools/generate_deliverability_report.py). `unavailable` when the store
    cannot be read; `insufficient_data` when it holds no events.
  * `uptime_12mo`     — no production uptime series exists in this repository
    (the status host records INCIDENTS, not availability samples), so its
    status is `illustrative`: the hero MUST NOT render it as a measured value
    until a real availability source is wired (see the artifact's
    `upgrade_path`).
  * `recipient_mx_acceptance_seconds` — likewise `illustrative`: the metric is
    defined on the methodology page but no production series is exposed to
    this tool yet.

`--check` is hermetic: the committed artifact must be internally consistent
(status vs value/source), and it FAILS when a metric is marked `measured`
without a source stamp. `--self-test` proves both directions.

Usage:
  python3 tools/generate_public_metrics.py            # query + write
  python3 tools/generate_public_metrics.py --check    # hermetic artifact check
  python3 tools/generate_public_metrics.py --self-test
"""
from __future__ import annotations

import argparse
import contextlib
import datetime as dt
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ARTIFACT = ROOT / "apps/marketing-zola/data/public_metrics.json"

WINDOW_DAYS = 30
QUERY_VERSION = "public-metrics-v1"

# Which metric ids the homepage hero consumes, and how the template must treat
# each status:
#   measured          → render the value (with its unit) and the meter
#   illustrative      → render the label only, linked to the methodology page
#                       ("not measured" is the honest presentation)
#   insufficient_data → same as illustrative, with the reason recorded here
HERO_METRICS = ("uptime_12mo", "recipient_mx_acceptance_seconds", "deliveries_30d")

DELIVERIES_QUERY = """
SELECT countIf(event_type = 'sent') AS sent
FROM __DATABASE__.events
WHERE timestamp >= toDateTime64('__START__', 3)
  AND timestamp < toDateTime64('__END__', 3)
"""


def clickhouse_config() -> dict[str, str]:
    return {
        "url": os.environ.get("CLICKHOUSE_URL", "http://127.0.0.1:8123").rstrip("/"),
        "database": os.environ.get("CLICKHOUSE_DATABASE", "apexmail"),
        "user": os.environ.get("CLICKHOUSE_USER", "apexmail"),
        "password": os.environ.get("CLICKHOUSE_PASSWORD", ""),
    }


def query_clickhouse(config: dict[str, str], query: str, timeout: float = 20.0) -> list[dict]:
    params = urllib.parse.urlencode(
        {
            "database": config["database"],
            "default_format": "JSON",
            "user": config["user"],
            "password": config["password"],
        }
    )
    request = urllib.request.Request(  # noqa: S310 — operator-configured endpoint (env convention)
        f"{config['url']}/?{params}",
        data=query.encode("utf-8"),
        method="POST",
        headers={"Content-Type": "text/plain; charset=utf-8"},
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310
            payload = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as error:
        detail = ""
        try:
            detail = error.read().decode("utf-8", "replace").strip()[:300]
        except Exception:  # noqa: BLE001
            pass
        raise RuntimeError(f"clickhouse_http_{error.code}: {detail or error.reason}") from error
    except (urllib.error.URLError, TimeoutError, OSError) as error:
        raise RuntimeError(f"clickhouse_unreachable: {error}") from error
    except json.JSONDecodeError as error:
        raise RuntimeError(f"clickhouse_invalid_response: {error}") from error
    rows = payload.get("data")
    if rows is None:
        raise RuntimeError("clickhouse_response_missing_data")
    return rows


def human_count(value: int) -> str:
    """Render a count the way the hero band displays it: `5.2m` for 5 200 000."""
    if value >= 1_000_000:
        return f"{value / 1_000_000:.1f}m"
    if value >= 1_000:
        return f"{value / 1_000:.1f}k"
    return str(value)


def build_metrics(
    *,
    window_start: dt.datetime,
    window_end: dt.datetime,
    deliveries: int | None,
    unavailable_reason: str | None,
    source_host: str,
) -> dict[str, object]:
    """Build the artifact. `deliveries` is `None` when the store could not be
    read (unavailable) — never coerced to 0, which would claim a measurement."""
    deliveries_status = (
        "unavailable"
        if deliveries is None
        else ("measured" if deliveries > 0 else "insufficient_data")
    )
    metrics = [
        {
            "id": "uptime_12mo",
            "label": "uptime · 12mo",
            "status": "illustrative",
            "value": None,
            "unit": "%",
            "display": None,
            "source": None,
            "note": "No production availability series exists in this repository yet: the "
            "status host records INCIDENTS, not availability samples. The hero therefore "
            "does not present an uptime number as measured; the live status page is "
            "authoritative.",
            "upgrade_path": "wire a real availability series (probe samples) and point this "
            "metric at it in tools/generate_public_metrics.py",
        },
        {
            "id": "recipient_mx_acceptance_seconds",
            "label": "recipient-MX acceptance",
            "status": "illustrative",
            "value": None,
            "unit": "s",
            "display": None,
            "source": None,
            "note": "The metric is defined on the methodology page (1.3) but no production "
            "series is exposed to this tool yet; the hero does not present it as measured.",
            "upgrade_path": "expose the SMTP handoff latency series (Prometheus) and query it "
            "here",
        },
        {
            "id": "deliveries_30d",
            "label": f"deliveries · {window_end.strftime('%b %Y')}",
            "status": deliveries_status,
            "value": deliveries,
            "unit": None,
            "display": human_count(deliveries) if deliveries is not None else None,
            "source": {
                "kind": "clickhouse-http",
                "host": source_host,
                "table": "events",
                "query_version": QUERY_VERSION,
                "window_days": WINDOW_DAYS,
            },
            "note": "Count of `sent` events in the delivery event store over the window; "
            "rendered as a scaled count (5.2m) and never as a rate.",
            "unavailable_reason": unavailable_reason,
        },
    ]
    return {
        "generated_by": "tools/generate_public_metrics.py",
        "generated_at": window_end.astimezone(dt.timezone.utc).isoformat(),
        "window": {
            "start": window_start.astimezone(dt.timezone.utc).isoformat(),
            "end": window_end.astimezone(dt.timezone.utc).isoformat(),
            "days": WINDOW_DAYS,
        },
        "hero_metrics": list(HERO_METRICS),
        "metrics": metrics,
        "note": "Every hero number must appear here with its status and source; the template "
        "renders a value ONLY for status=measured, so a number can never be presented as "
        "measured without a backing artifact.",
    }


def consistency_problems(metrics: dict[str, object]) -> list[str]:
    """The hermetic invariant: a `measured` metric carries a value AND a source
    stamp; a non-measured metric carries no value (nothing to render as if it
    were measured)."""
    problems: list[str] = []
    identifiers = [metric.get("id") for metric in metrics.get("metrics", [])]  # type: ignore[union-attr]
    for hero_id in HERO_METRICS:
        if hero_id not in identifiers:
            problems.append(f"hero metric `{hero_id}` is missing from the artifact")
    for metric in metrics.get("metrics", []):  # type: ignore[union-attr]
        status = metric.get("status")
        if status == "measured":
            if metric.get("value") is None or metric.get("display") is None:
                problems.append(f"{metric.get('id')}: measured without a value/display")
            if not metric.get("source"):
                problems.append(f"{metric.get('id')}: measured without a source stamp")
        else:
            if metric.get("value") is not None:
                problems.append(
                    f"{metric.get('id')}: status={status} must not carry a value "
                    "(the template would render an unmeasured number)"
                )
            if not metric.get("note"):
                problems.append(f"{metric.get('id')}: non-measured metric must say why")
        if status not in ("measured", "illustrative", "insufficient_data", "unavailable"):
            problems.append(f"{metric.get('id')}: unknown status `{status}`")
    if not metrics.get("window"):
        problems.append("artifact must stamp its measurement window")
    return problems


def write(metrics: dict[str, object]) -> None:
    ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
    previous = ARTIFACT.read_text(encoding="utf-8") if ARTIFACT.is_file() else None
    stamp_only = json.dumps(metrics, indent=2, ensure_ascii=False) + "\n"
    if previous is not None and previous == stamp_only:
        print(f"  unchanged: {ARTIFACT.relative_to(ROOT)}")
        return
    ARTIFACT.write_text(stamp_only, encoding="utf-8")
    print(f"  wrote: {ARTIFACT.relative_to(ROOT)}")


def check() -> int:
    if not ARTIFACT.is_file():
        print(f"  FAIL: {ARTIFACT.relative_to(ROOT)} is missing", file=sys.stderr)
        return 1
    try:
        metrics = json.loads(ARTIFACT.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        print(f"  FAIL: {ARTIFACT.relative_to(ROOT)} is not valid JSON: {error}", file=sys.stderr)
        return 1
    problems = consistency_problems(metrics)
    if problems:
        for problem in problems:
            print(f"  INVALID: {problem}", file=sys.stderr)
        return 1
    measured = [
        metric["id"] for metric in metrics["metrics"] if metric["status"] == "measured"
    ]
    print(
        f"  PASS: public metrics artifact is consistent "
        f"({len(metrics['metrics'])} metric(s), measured: {measured or 'none'})"
    )
    return 0


def generate(args: argparse.Namespace) -> int:
    config = clickhouse_config()
    if args.url:
        config["url"] = args.url.rstrip("/")
    if args.database:
        config["database"] = args.database
    if args.user:
        config["user"] = args.user
    window_end = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
    window_start = window_end - dt.timedelta(days=WINDOW_DAYS)

    deliveries: int | None = None
    unavailable: str | None = None
    query = (
        DELIVERIES_QUERY.replace("__DATABASE__", config["database"])
        .replace("__START__", window_start.strftime("%Y-%m-%d %H:%M:%S"))
        .replace("__END__", window_end.strftime("%Y-%m-%d %H:%M:%S"))
    )
    try:
        rows = query_clickhouse(config, query)
        deliveries = int(rows[0]["sent"]) if rows else 0
        print(f"  clickhouse: {deliveries} sent event(s) in the {WINDOW_DAYS}-day window")
    except (RuntimeError, KeyError, ValueError) as error:
        unavailable = str(error)
        print(f"  clickhouse unavailable: {unavailable}", file=sys.stderr)
        print("  writing the artifact with an explicit unavailable status (never a fake count)")

    host = urllib.parse.urlsplit(config["url"]).netloc or config["url"]
    metrics = build_metrics(
        window_start=window_start,
        window_end=window_end,
        deliveries=deliveries,
        unavailable_reason=unavailable,
        source_host=host,
    )
    write(metrics)
    for metric in metrics["metrics"]:
        print(f"  {metric['id']}: status={metric['status']} display={metric['display']}")
    return 0


def self_test() -> int:
    """Prove both directions hermetically."""
    failures: list[str] = []

    print("  self-test 1/3: the committed artifact is consistent")
    if check() != 0:
        failures.append("the committed public-metrics artifact is inconsistent")

    print("  self-test 2/3: a fabricated `measured` number without a source FAILS")
    fabricated = build_metrics(
        window_start=dt.datetime(2026, 9, 15, tzinfo=dt.timezone.utc),
        window_end=dt.datetime(2026, 10, 15, tzinfo=dt.timezone.utc),
        deliveries=5_200_000,
        unavailable_reason=None,
        source_host="clickhouse",
    )
    fabricated["metrics"][2]["source"] = None
    if consistency_problems(fabricated):
        print("    PASS: measured-without-source rejected")
    else:
        failures.append("a measured metric without a source stamp was accepted")

    print("  self-test 3/3: an unmeasured metric carrying a renderable value FAILS")
    sneaky = build_metrics(
        window_start=dt.datetime(2026, 9, 15, tzinfo=dt.timezone.utc),
        window_end=dt.datetime(2026, 10, 15, tzinfo=dt.timezone.utc),
        deliveries=None,
        unavailable_reason="clickhouse_unreachable",
        source_host="clickhouse",
    )
    sneaky["metrics"][0]["value"] = 99.9  # the removal of exactly this literal
    sneaky["metrics"][0]["display"] = "99.9"
    if consistency_problems(sneaky):
        print("    PASS: illustrative-number rejected")
    else:
        failures.append("an illustrative metric carrying a value was accepted")

    # The measured path is also exercised hermetically (no network): the
    # display is derived from the count.
    measured = build_metrics(
        window_start=dt.datetime(2026, 9, 15, tzinfo=dt.timezone.utc),
        window_end=dt.datetime(2026, 10, 15, tzinfo=dt.timezone.utc),
        deliveries=5_200_000,
        unavailable_reason=None,
        source_host="clickhouse",
    )
    if consistency_problems(measured) == [] and measured["metrics"][2]["display"] == "5.2m":
        print("    PASS: measured path derives `5.2m` from 5,200,000 events")
    else:
        failures.append("the measured path did not derive the display from the count")

    if failures:
        for failure in failures:
            print(f"  FAIL: {failure}", file=sys.stderr)
        return 1
    print("  PASS: public metrics self-test (both directions)")
    return 0


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--check", action="store_true", help="hermetic artifact check (no network)")
    mode.add_argument("--self-test", action="store_true", help="prove the check has teeth")
    parser.add_argument("--url", help="override CLICKHOUSE_URL")
    parser.add_argument("--database", help="override CLICKHOUSE_DATABASE")
    parser.add_argument("--user", help="override CLICKHOUSE_USER")
    args = parser.parse_args(argv[1:])
    if args.self_test:
        return self_test()
    if args.check:
        return check()
    return generate(args)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
