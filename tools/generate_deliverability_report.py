#!/usr/bin/env python3
"""Published deliverability report — ClickHouse-fed, one row per routing mode.

Plan A4: "ClickHouse feeds the provable public numbers". This tool queries the
delivery/engagement event store (`CLICKHOUSE_DATABASE.events`, the same schema
`analytics::clickhouse_engine` and `tracking-service::processor` write) over a
fixed measurement window, computes the delivery / bounce / complaint rates per
ROUTING MODE, and writes:

  * `apps/marketing-zola/data/deliverability-report.json` — the artifact
    (query output + window + source + definitions), and
  * `apps/marketing-zola/templates/partials/generated/deliverability-report.html`
    — the rendered table the methodology page includes (the status-island
    pattern: a generated partial the static build embeds).

Honesty rules:
  * every number in the artifact comes from a query result or is derived from
    one (rates are computed here, never typed);
  * a mode with no numerator/denominator in the window is reported with an
    explicit `insufficient_data` status — not as 0.0% (which would be a
    measurement claim the data does not support);
  * if ClickHouse is unreachable or the table is empty, the artifact is STILL
    written, with `status: "insufficient_data"` and the reason recorded, and
    the rendered page says exactly that.

`--check` is hermetic: it re-renders the partial from the committed JSON
artifact and re-verifies the artifact's internal consistency (rates match the
counts, the window and the source are stamped) — no network, no drift.
`--self-test` proves both directions (a mutated committed number FAILS, a
missing definition FAILS) on a temporary copy.

Routing-mode dimension: the `events` table has no routing-mode column, so the
mode is read from the event's `metadata` JSON —
`JSONExtractString(metadata, 'routing_mode')`, falling back to
`provider_source` and `transport` keys written by the delivery pipeline.
Unattributed events are reported as their own row and never silently merged
into a named mode.

Env (the repo's CLICKHOUSE_* conventions):
  CLICKHOUSE_URL=http://clickhouse:8123   CLICKHOUSE_DATABASE=apexmail
  CLICKHOUSE_USER=apexmail                CLICKHOUSE_PASSWORD=…

Usage:
  python3 tools/generate_deliverability_report.py            # query + write
  python3 tools/generate_deliverability_report.py --check    # hermetic drift check
  python3 tools/generate_deliverability_report.py --self-test
"""
from __future__ import annotations

import argparse
import contextlib
import datetime as dt
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ARTIFACT = ROOT / "apps/marketing-zola/data/deliverability-report.json"
PARTIAL = ROOT / "apps/marketing-zola/templates/partials/generated/deliverability-report.html"

# The measured routing modes the product actually executes (worker-processors
# `transport_router::TransportKind` + `mail_common::RoutingMode`): dedicated IPs
# on the own MTA, the SES shared pool, and EU-only dedicated routing. Anything
# else the metadata carries is reported verbatim as its own row.
ROUTING_MODES = ("dedicated", "ses_shared", "eu_only")
KNOWN_MODE_ALIASES = {
    "dedicated": "dedicated",
    "ses-shared": "ses_shared",
    "ses_shared": "ses_shared",
    "ses": "ses_shared",
    "eu_only": "eu_only",
    "eu-only": "eu_only",
}

MEASUREMENT_WINDOW_DAYS = 30
# Version of the query + rate definitions. Bumped whenever the query or the
# denominator changes (the artifact records it so a published number can be
# traced to the shape that produced it).
QUERY_VERSION = "deliverability-v1"

DELIVERABILITY_QUERY = """
SELECT
    multiIf(
        JSONExtractString(metadata, 'routing_mode') != '', JSONExtractString(metadata, 'routing_mode'),
        JSONExtractString(metadata, 'provider_source') != '', JSONExtractString(metadata, 'provider_source'),
        JSONExtractString(metadata, 'transport') != '', JSONExtractString(metadata, 'transport'),
        'unattributed'
    ) AS routing_mode,
    countIf(event_type = 'sent') AS sent,
    countIf(event_type IN ('delivered', 'accepted')) AS delivered,
    countIf(event_type = 'bounced') AS bounced,
    countIf(event_type = 'complained') AS complained
FROM {database}.events
WHERE timestamp >= toDateTime64('{{start:String}}', 3)
  AND timestamp < toDateTime64('{{end:String}}', 3)
GROUP BY routing_mode
ORDER BY routing_mode
"""


def clickhouse_config() -> dict[str, str]:
    """The repo's CLICKHOUSE_* env conventions (see .env.production.example)."""
    return {
        "url": os.environ.get("CLICKHOUSE_URL", "http://127.0.0.1:8123").rstrip("/"),
        "database": os.environ.get("CLICKHOUSE_DATABASE", "apexmail"),
        "user": os.environ.get("CLICKHOUSE_USER", "apexmail"),
        "password": os.environ.get("CLICKHOUSE_PASSWORD", ""),
    }



def _require_http_url(url: str) -> str:
    """Only http(s) endpoints reach urllib.

    urllib also accepts file:// URLs, so an operator-supplied endpoint must
    be scheme-checked before the request is built.
    """
    scheme = urllib.parse.urlsplit(url).scheme
    if scheme not in ("http", "https"):
        raise RuntimeError(f"ClickHouse endpoint must be http(s), got {scheme or '<none>'}")
    return url

def query_clickhouse(
    config: dict[str, str], query: str, timeout: float = 30.0
) -> list[dict[str, object]]:
    """Run one JSON-format query over the ClickHouse HTTP interface.

    Raises RuntimeError with a named reason on any failure — the caller turns
    that into the artifact's `insufficient_data` + reason (never a silent zero).
    """
    params = urllib.parse.urlencode(
        {
            "database": config["database"],
            "default_format": "JSON",
            "user": config["user"],
            "password": config["password"],
        }
    )
    request = urllib.request.Request(  # noqa: S310 — operator-configured ClickHouse endpoint (env convention), not user input
        _require_http_url(f"{config['url']}/?{params}"),
        data=query.encode("utf-8"),
        method="POST",
        # ClickHouse parses a form-urlencoded body as PARAMETERS and expects
        # the statement in the URL; the statement rides the body here, so the
        # content type must say plain text.
        headers={"Content-Type": "text/plain; charset=utf-8"},
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310  # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected
            payload = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as error:
        detail = ""
        try:
            detail = error.read().decode("utf-8", "replace").strip()
        except Exception:  # noqa: BLE001 — best-effort detail only
            pass
        raise RuntimeError(
            f"clickhouse_http_{error.code}: {error.reason}{(' — ' + detail) if detail else ''}"
        ) from error
    except (urllib.error.URLError, TimeoutError, OSError) as error:
        raise RuntimeError(f"clickhouse_unreachable: {error}") from error
    except json.JSONDecodeError as error:
        raise RuntimeError(f"clickhouse_invalid_response: {error}") from error
    rows = payload.get("data")
    if rows is None:
        raise RuntimeError("clickhouse_response_missing_data")
    return rows


def canonical_mode(raw: str) -> str:
    normalized = raw.strip().lower().replace(" ", "_")
    return KNOWN_MODE_ALIASES.get(normalized, normalized or "unattributed")


def rate(numerator: int, denominator: int) -> float | None:
    """A rate, or None when the denominator is zero — `None` renders as
    "insufficient data", never as a fabricated 0.0%."""
    if denominator <= 0:
        return None
    return round(100.0 * numerator / denominator, 4)


def build_report(
    rows: list[dict[str, object]],
    *,
    window_start: dt.datetime,
    window_end: dt.datetime,
    source: dict[str, str],
    unavailable_reason: str | None = None,
) -> dict[str, object]:
    modes: dict[str, dict[str, object]] = {}
    for row in rows:
        mode = canonical_mode(str(row.get("routing_mode", "")))
        entry = modes.setdefault(
            mode,
            {
                "mode": mode,
                "sent": 0,
                "delivered": 0,
                "bounced": 0,
                "complained": 0,
            },
        )
        for key in ("sent", "delivered", "bounced", "complained"):
            entry[key] = int(entry[key]) + int(row.get(key, 0) or 0)  # type: ignore[arg-type]

    # The three product routing modes are ALWAYS present, so the page can state
    # "insufficient data" for a mode rather than omitting it (an omitted mode
    # reads as "no such mode").
    for mode in ROUTING_MODES:
        modes.setdefault(
            mode,
            {"mode": mode, "sent": 0, "delivered": 0, "bounced": 0, "complained": 0},
        )

    measurements = []
    any_measured = False
    for mode in sorted(modes, key=lambda name: (name not in ROUTING_MODES, name)):
        entry = modes[mode]
        sent = int(entry["sent"])  # type: ignore[arg-type]
        delivered = int(entry["delivered"])  # type: ignore[arg-type]
        bounced = int(entry["bounced"])  # type: ignore[arg-type]
        complained = int(entry["complained"])  # type: ignore[arg-type]
        # Delivery rate = delivered / sent (the recipient-accepted handoff);
        # bounce and complaint rates are per accepted send, the same
        # denominator the methodology page defines for 1.3.
        measured = sent > 0
        any_measured = any_measured or measured
        measurements.append(
            {
                "mode": mode,
                "status": "measured" if measured else "insufficient_data",
                "sent": sent,
                "delivered": delivered,
                "bounced": bounced,
                "complained": complained,
                "delivery_rate_percent": rate(delivered, sent),
                "bounce_rate_percent": rate(bounced, sent),
                "complaint_rate_percent": rate(complained, sent),
            }
        )

    if unavailable_reason is not None:
        status = "insufficient_data"
    elif any_measured:
        status = "measured"
    else:
        status = "insufficient_data"

    notes = [
        "Rates are computed from the ClickHouse event counts below; no number on the page is typed by hand.",
        "Delivery rate = delivered / sent over the window; bounce and complaint rates use the "
        "same denominator (see the methodology page, section 1.3).",
        "A mode with zero sent events reports 'insufficient data' rather than 0.0%: no "
        "measurement claim is made where none exists.",
    ]
    if unavailable_reason:
        notes.append(
            f"the event store could not be read for this report ({unavailable_reason}); the "
            "counts are zero BECAUSE no data was available, and the page says so explicitly"
        )

    return {
        "generated_by": "tools/generate_deliverability_report.py",
        "query_version": QUERY_VERSION,
        "generated_at": window_end.astimezone(dt.timezone.utc).isoformat(),
        "status": status,
        "window": {
            "start": window_start.astimezone(dt.timezone.utc).isoformat(),
            "end": window_end.astimezone(dt.timezone.utc).isoformat(),
            "days": MEASUREMENT_WINDOW_DAYS,
        },
        "source": source,
        "routing_modes": measurements,
        "definitions": {
            "page": "/performance-methodology/",
            "section": "1.3 Recipient-Server Acceptance Rate",
            "denominator": "sent events in the window",
        },
        "unavailable_reason": unavailable_reason,
        "notes": notes,
    }


def render_partial(report: dict[str, object]) -> str:
    """The generated island. Every number comes from `report`; the copy is
    conditional on the report's own status so the page can never render a
    measurement claim the artifact does not support."""
    status = report["status"]
    window = report["window"]
    window_days = window["days"]  # type: ignore[index]
    source = report["source"]
    rows = []
    for mode in report["routing_modes"]:  # type: ignore[union-attr]
        mode_name = str(mode["mode"]).replace("_", " ")
        if mode["status"] == "measured":
            cells = [
                f"{int(mode['sent']):,}",
                f"{int(mode['delivered']):,}",
                f"{int(mode['bounced']):,}",
                f"{int(mode['complained']):,}",
                f"{mode['delivery_rate_percent']}%",
                f"{mode['bounce_rate_percent']}%",
                f"{mode['complaint_rate_percent']}%",
            ]
        else:
            cells = ["—", "—", "—", "—", "insufficient data", "insufficient data", "insufficient data"]
        cells_html = "".join(f'<td class="py-2 pr-4">{cell}</td>' for cell in cells[:-1])
        cells_html += f'<td class="py-2">{cells[-1]}</td>'
        rows.append(f"          <tr>{cells_html}</tr>")
    table = "\n".join(rows)
    methodology_link = (
        '<a class="underline" href="/performance-methodology/#13-recipient-server-acceptance-rate">'
        "section 1.3 of the methodology</a>"
    )
    if status == "measured":
        headline = (
            f"Measured over the last {window_days} days from the delivery event store. "
            f"Rates are computed from the counts below (query <code>{report['query_version']}</code>); "
            f"definitions live in {methodology_link}."
        )
    else:
        # The artifact keeps the raw operational reason (a build-input detail);
        # the PUBLIC page states a sanitized class only — an endpoint error
        # string is not reader-facing copy.
        unavailable = report.get("unavailable_reason")
        if not unavailable:
            reason = "no delivery events were recorded in the window"
        elif str(unavailable).startswith("clickhouse_unreachable"):
            reason = "the delivery event store could not be reached at build time"
        else:
            reason = "the delivery event store could not be read at build time"
        headline = (
            f"<strong>Insufficient data to publish a rate for the last {window_days} days.</strong> "
            f"The counters below are zero because {reason} — this page therefore makes "
            f"<strong>no</strong> delivery-rate claim. The query and its definitions are ready "
            f"({methodology_link}) and the table fills in as events arrive."
        )
    return f"""{{# GENERATED FILE, do not edit by hand. #}}
{{# Rendered by tools/generate_deliverability_report.py from #}}
{{# apps/marketing-zola/data/deliverability-report.json (ClickHouse query #}}
{{# `{report['query_version']}`, window {window['start']} → {window['end']}). #}}
{{# `--check` in the validate stage fails on drift. #}}

<section class="py-12 bg-surface-100 border-b border-surface-200" id="deliverability-report">
  <div class="max-w-5xl mx-auto px-4 sm:px-6 lg:px-8">
    <h2 class="text-xl font-semibold text-surface-950 mb-3">Published Deliverability Report</h2>
    <p class="text-sm text-surface-600 mb-6">{headline}</p>
    <div class="overflow-x-auto">
      <table class="w-full text-left text-sm">
        <thead>
          <tr>
            <th class="py-2 pr-4">Routing mode</th>
            <th class="py-2 pr-4">Sent</th>
            <th class="py-2 pr-4">Delivered</th>
            <th class="py-2 pr-4">Bounced</th>
            <th class="py-2 pr-4">Complained</th>
            <th class="py-2 pr-4">Delivery rate</th>
            <th class="py-2 pr-4">Bounce rate</th>
            <th class="py-2">Complaint rate</th>
          </tr>
        </thead>
        <tbody>
{table}
        </tbody>
      </table>
    </div>
    <p class="text-xs text-surface-500 mt-4">Source: {source['database']}.{source['table']} via {source['url_host']} · window {window['days']} days · artifact: apps/marketing-zola/data/deliverability-report.json</p>
  </div>
</section>
"""


def source_stamp(config: dict[str, str], table: str) -> dict[str, str]:
    parsed = urllib.parse.urlsplit(config["url"])
    return {
        "kind": "clickhouse-http",
        "url_host": parsed.netloc or config["url"],
        "database": config["database"],
        "table": table,
        "user": config["user"],
        "query_version": QUERY_VERSION,
    }


def artifact_numbers(report: dict[str, object]) -> list[str]:
    """Every published number as a string, for the self-test's pin (a number
    that is not in the artifact must not appear in the partial)."""
    numbers = []
    for mode in report["routing_modes"]:  # type: ignore[union-attr]
        for key in ("sent", "delivered", "bounced", "complained", "status"):
            if key == "status":
                numbers.append(str(mode[key]))
                continue
            value = int(mode[key])
            numbers.append(f"{value:,}")
        for key in ("delivery_rate_percent", "bounce_rate_percent", "complaint_rate_percent"):
            value = mode[key]
            numbers.append("insufficient data" if value is None else f"{value}%")
    return numbers


def render_and_compare(report: dict[str, object], committed_partial: str) -> list[str]:
    """The hermetic check: every published rate must be derivable from the
    artifact counts, the artifact must stamp its source/window/definitions,
    and the committed partial must equal the render from the artifact."""
    problems: list[str] = []

    # 1. Internal consistency: each rate IS count-derived (checked FIRST so a
    #    tampered artifact is reported even when the page also drifted).
    for mode in report.get("routing_modes", []):  # type: ignore[union-attr]
        sent = int(mode["sent"])
        for count_key, rate_key in (
            ("delivered", "delivery_rate_percent"),
            ("bounced", "bounce_rate_percent"),
            ("complained", "complaint_rate_percent"),
        ):
            expected_rate = rate(int(mode[count_key]), sent)
            if mode[rate_key] != expected_rate:
                problems.append(
                    f"{mode['mode']}: {rate_key} = {mode[rate_key]} is not {count_key}/sent "
                    f"({expected_rate}) — the published number is not derived from the counts"
                )
    if not report.get("source") or not report.get("window"):
        problems.append("artifact must stamp its source and window")
    if report.get("definitions", {}).get("page") != "/performance-methodology/":
        problems.append(
            "artifact must point at its definitions page (/performance-methodology/)"
        )
    if report.get("query_version") != QUERY_VERSION:
        problems.append(
            f"artifact query_version {report.get('query_version')!r} is not the tool's "
            f"{QUERY_VERSION!r} — re-generate or re-version deliberately"
        )

    # 2. The rendered page must be exactly the render of the artifact.
    expected = render_partial(report)
    if committed_partial != expected:
        for number, (got, want) in enumerate(
            zip(committed_partial.splitlines(), expected.splitlines()), start=1
        ):
            if got != want:
                problems.append(
                    f"{PARTIAL.relative_to(ROOT)}:{number} drifted\n"
                    f"    committed: {got[:140]}\n"
                    f"    rendered:  {want[:140]}"
                )
                break
        else:
            problems.append(
                f"{PARTIAL.relative_to(ROOT)} differs in length "
                f"({len(committed_partial.splitlines())} vs {len(expected.splitlines())} lines)"
            )
    return problems


def load_artifact() -> tuple[dict[str, object] | None, str | None]:
    if not ARTIFACT.is_file():
        return None, f"{ARTIFACT.relative_to(ROOT)} is missing"
    try:
        return json.loads(ARTIFACT.read_text(encoding="utf-8")), None
    except json.JSONDecodeError as error:
        return None, f"{ARTIFACT.relative_to(ROOT)} is not valid JSON: {error}"


def check() -> int:
    report, error = load_artifact()
    if error:
        print(f"  FAIL: {error}", file=sys.stderr)
        return 1
    assert report is not None
    if not PARTIAL.is_file():
        print(f"  FAIL: {PARTIAL.relative_to(ROOT)} is missing", file=sys.stderr)
        return 1
    problems = render_and_compare(report, PARTIAL.read_text(encoding="utf-8"))
    if problems:
        for problem in problems:
            print(f"  DRIFT: {problem}", file=sys.stderr)
        print(
            "  FAIL: the published deliverability report drifted from its artifact — run "
            "`python3 tools/generate_deliverability_report.py` and review the diff",
            file=sys.stderr,
        )
        return 1
    print(
        "  PASS: deliverability report artifact and rendered page agree "
        f"(status={report['status']}, query {report['query_version']})"
    )
    return 0


def write(report: dict[str, object]) -> None:
    ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
    ARTIFACT.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    PARTIAL.parent.mkdir(parents=True, exist_ok=True)
    PARTIAL.write_text(render_partial(report), encoding="utf-8")
    print(f"  wrote: {ARTIFACT.relative_to(ROOT)}")
    print(f"  wrote: {PARTIAL.relative_to(ROOT)}")


def generate(args: argparse.Namespace) -> int:
    config = clickhouse_config()
    if args.url:
        config["url"] = args.url.rstrip("/")
    if args.database:
        config["database"] = args.database
    if args.user:
        config["user"] = args.user
    window_end = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
    window_start = window_end - dt.timedelta(days=MEASUREMENT_WINDOW_DAYS)
    source = source_stamp(config, "events")

    unavailable: str | None = None
    rows: list[dict[str, object]] = []
    try:
        query = DELIVERABILITY_QUERY.format(database=config["database"])
        query = query.replace("{start:String}", window_start.strftime("%Y-%m-%d %H:%M:%S"))
        query = query.replace("{end:String}", window_end.strftime("%Y-%m-%d %H:%M:%S"))
        rows = query_clickhouse(config, query)
        print(f"  clickhouse: {len(rows)} routing-mode row(s) in the {MEASUREMENT_WINDOW_DAYS}-day window")
    except RuntimeError as error:
        unavailable = str(error)
        print(f"  clickhouse unavailable: {unavailable}", file=sys.stderr)
        print("  writing an explicit insufficient-data artifact (never a fabricated rate)")

    report = build_report(
        rows,
        window_start=window_start,
        window_end=window_end,
        source=source,
        unavailable_reason=unavailable,
    )
    write(report)
    print(
        f"  status={report['status']} — "
        + ", ".join(
            f"{mode['mode']}={mode['status']}"
            for mode in report["routing_modes"]  # type: ignore[union-attr]
        )
    )
    return 0


def self_test() -> int:
    """Prove both directions hermetically (no network): the committed report
    checks green, a mutated published number FAILS, and a missing definition
    FAILS."""
    failures: list[str] = []

    print("  self-test 1/3: the committed artifact and page agree")
    if check() != 0:
        failures.append("the committed deliverability report does not check green")

    report, error = load_artifact()
    if error or report is None:
        print(f"  FAIL: {error}", file=sys.stderr)
        return 1
    committed = PARTIAL.read_text(encoding="utf-8")

    print("  self-test 2/3: a mutated published number FAILS the check")
    numbers = artifact_numbers(report)
    mutated_number = next((n for n in numbers if re.match(r"^[\d,]+$", n) and n != "0"), None)
    if mutated_number is None:
        # Insufficient-data reports carry no numeric cells; mutate the status
        # copy instead so the arm still proves teeth.
        mutated = committed.replace("insufficient data", "99.9%", 1)
    else:
        mutated = committed.replace(mutated_number, "12345", 1)
    PARTIAL.write_text(mutated, encoding="utf-8")
    try:
        with open(os.devnull, "w", encoding="utf-8") as sink, contextlib.redirect_stderr(
            sink
        ), contextlib.redirect_stdout(sink):
            rc = check()
    finally:
        PARTIAL.write_text(committed, encoding="utf-8")
    if rc == 0:
        failures.append("a mutated published number was ACCEPTED — the check has no teeth")
    else:
        print("    PASS: mutated page rejected")

    print("  self-test 3/3: an artifact missing its definitions pointer FAILS")
    broken = json.loads(json.dumps(report))
    broken["definitions"]["page"] = "/nowhere/"
    problems = render_and_compare(broken, committed)
    if any("definitions page" in problem for problem in problems):
        print("    PASS: missing definition rejected")
    else:
        failures.append("an artifact without its definitions pointer was accepted")

    if failures:
        for failure in failures:
            print(f"  FAIL: {failure}", file=sys.stderr)
        return 1
    print("  PASS: deliverability report self-test (both directions)")
    return 0


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--check", action="store_true", help="hermetic drift check (no network)")
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
