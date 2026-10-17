#!/usr/bin/env python3
"""Provider-export importer CLI — the switching customer's one command.

Uploads a SendGrid / Mailgun / Postmark / Resend export to the ApexMail
importer endpoint (`POST /v1/import/{provider}/{kind}`) and prints the report.
The endpoint defaults to a DRY RUN; pass `--commit` explicitly to write.

    # preview a SendGrid bounce export (writes nothing)
    tools/provider-import.py --provider sendgrid --kind suppressions \
        --file bounces.csv --source-type bounces

    # commit it
    tools/provider-import.py --provider sendgrid --kind suppressions \
        --file bounces.csv --source-type bounces --commit

    # a Mailgun mailing-list JSON export into contacts
    tools/provider-import.py --provider mailgun --kind contacts \
        --file list-members.json --commit

    # the read-only DNS report for a domain already added in ApexMail
    tools/provider-import.py --provider sendgrid --kind domains \
        --domain example.com

Credential: `APEXMAIL_API_KEY` (or `--api-key`). The key needs the scope the
canonical surface for the kind requires — suppressions:write, contacts:write,
templates:write (+ the custom_templates entitlement), domains:read.

Exit codes: 0 the request succeeded (including a report full of conflicts);
1 a refusal or transport failure (the named error is printed); 2 usage.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

KINDS = ("suppressions", "contacts", "templates", "domains")
PROVIDERS = ("sendgrid", "mailgun", "postmark", "resend")


def content_type_for(path: Path, explicit: str | None) -> str:
    if explicit:
        return "application/json" if explicit == "json" else "text/csv"
    suffix = path.suffix.lower()
    if suffix == ".json":
        return "application/json"
    if suffix in (".csv", ".txt", ""):
        return "text/csv"
    # Unknown extension: let the server sniff the first byte.
    return "application/octet-stream"


def build_url(args: argparse.Namespace) -> str:
    base = args.url.rstrip("/")
    url = f"{base}/v1/import/{args.provider}/{args.kind}"
    params = [f"mode={'commit' if args.commit else 'dry_run'}"]
    if args.source_type:
        params.append(f"source_type={args.source_type}")
    if args.format:
        params.append(f"format={args.format}")
    if args.domain:
        params.append(f"domain={urllib.parse.quote(args.domain)}")
    return url + "?" + "&".join(params)


def print_summary(report: dict) -> None:
    counts = report.get("counts", {})
    mode = report.get("mode", "dry_run")
    print(
        f"{report.get('provider')}/{report.get('kind')} [{mode}] "
        f"format={report.get('format')} bytes={report.get('file_bytes')} "
        f"sha256={report.get('file_sha256', '')[:16]}…"
    )
    print(
        "rows={rows} imported={imported} duplicates={duplicates} invalid={invalid} "
        "needs_review={needs_review} failed={failed}".format(
            rows=counts.get("rows", 0),
            imported=counts.get("imported", 0),
            duplicates=counts.get("duplicates", 0),
            invalid=counts.get("invalid", 0),
            needs_review=counts.get("needs_review", 0),
            failed=counts.get("failed", 0),
        )
    )
    suppressions = report.get("suppressions") or {}
    if suppressions:
        by_reason = ", ".join(
            f"{row.get('reason')}={row.get('count')}"
            for row in suppressions.get("by_reason", [])
        )
        print(f"source_type={suppressions.get('source_type')} reasons: {by_reason}")
    templates = report.get("templates") or []
    if templates:
        for row in templates:
            flags = []
            if row.get("needs_review"):
                flags.append("NEEDS_REVIEW")
            if row.get("error"):
                flags.append(f"error: {row['error']}")
            suffix = f" [{' | '.join(flags)}]" if flags else ""
            print(f"  template {row.get('row')}: {row.get('name')} — {row.get('status')}{suffix}")
            for note in row.get("conversions", []):
                print(f"      converted {note.get('construct')}: {note.get('action')}")
            for unconverted in row.get("unconverted", []):
                print(f"      unconverted (kept verbatim): {unconverted}")
    domain = report.get("domain")
    if domain:
        print(f"domain report for {domain.get('domain')} (from {domain.get('from_provider')}):")
        for record in domain.get("keep", []):
            print(f"  KEEP   {record.get('record_type'):5} {record.get('hostname')}")
        for record in domain.get("delete_candidates", []):
            print(
                f"  DELETE {record.get('record_type'):5} {record.get('hostname')} "
                f"→ {record.get('value')}"
            )
        for record in domain.get("edits", []):
            print(f"  EDIT   {record.get('record_type'):5} {record.get('hostname')}: {record.get('value')}")
    for warning in report.get("warnings", []):
        print(f"warning: {warning}")
    for note in report.get("conflicts", [])[:10]:
        print(f"conflict row {note.get('row')}: {note.get('note')}")
    for note in report.get("invalid", [])[:10]:
        print(f"invalid row {note.get('row')}: {note.get('note')}")
    for note in report.get("failed", [])[:10]:
        print(f"failed row {note.get('row')}: {note.get('note')}")
    if report.get("report_id"):
        print(f"stored report: GET /v1/import/reports/{report['report_id']}")


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        description="Import a SendGrid/Mailgun/Postmark/Resend export into ApexMail.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--provider", required=True, choices=PROVIDERS)
    parser.add_argument("--kind", required=True, choices=KINDS)
    parser.add_argument("--file", help="the export file (not needed for kind=domains)")
    parser.add_argument("--domain", help="domain name or id (kind=domains)")
    parser.add_argument(
        "--commit",
        action="store_true",
        help="perform the writes and store the report (default: dry run)",
    )
    parser.add_argument("--source-type", help="suppressions sub-type (bounces, blocks, …)")
    parser.add_argument("--format", choices=("csv", "json"), help="force the file format")
    parser.add_argument("--url", default=os.environ.get("APEXMAIL_URL", "http://127.0.0.1:8080"))
    parser.add_argument("--api-key", default=os.environ.get("APEXMAIL_API_KEY"))
    parser.add_argument("--json", action="store_true", help="print the raw report JSON")
    args = parser.parse_args(argv[1:])

    if not args.api_key:
        print("error: provide --api-key or set APEXMAIL_API_KEY", file=sys.stderr)
        return 2
    if args.kind == "domains" and not args.domain:
        print("error: kind=domains needs --domain", file=sys.stderr)
        return 2
    if args.kind != "domains" and not args.file:
        print("error: provide --file with the provider export", file=sys.stderr)
        return 2

    body = b""
    content_type = "application/json"
    if args.file:
        path = Path(args.file)
        if not path.is_file():
            print(f"error: no such file: {path}", file=sys.stderr)
            return 2
        body = path.read_bytes()
        content_type = content_type_for(path, args.format)

    url = build_url(args)
    # urllib would accept file://; an operator-supplied endpoint must be http(s).
    _scheme = urllib.parse.urlsplit(url).scheme
    if _scheme not in ("http", "https"):
        print(f"error: --url must be http(s), got {_scheme or '<none>'}", file=sys.stderr)
        return 2
    request = urllib.request.Request(
        url,
        data=body,
        method="POST",
        headers={"X-API-Key": args.api_key, "Content-Type": content_type},
    )
    try:
        with urllib.request.urlopen(request, timeout=300) as response:  # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected
            report = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as error:
        detail = error.read().decode("utf-8", "replace")
        message, code = detail, error.code
        try:
            parsed = json.loads(detail)
            envelope = parsed.get("error")
            if isinstance(envelope, dict):
                message = envelope.get("message", detail)
                code = envelope.get("code", error.code)
                details = envelope.get("details") or envelope.get("errors")
                if details:
                    message = f"{message} ({details})"
        except json.JSONDecodeError:
            pass
        print(f"error: refused ({code}): {message}", file=sys.stderr)
        return 1
    except (urllib.error.URLError, TimeoutError) as error:
        print(f"error: could not reach {url}: {error}", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print_summary(report)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
