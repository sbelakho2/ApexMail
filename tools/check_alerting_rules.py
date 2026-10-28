#!/usr/bin/env python3
"""Alerting-rules gate (the observability quality lane, landed 2026-10-28).

`deploy/alerting-rules.yml` is the file Prometheus loads in production, and
before this gate NOTHING in CI read it for quality — only the topology
contract checked that alerts the topology manifest names exist. The classes
this gate catches:

  1. structure — groups/rules parse, every rule is an alert, names unique;
  2. severity — every alert carries labels.severity in {critical, warning, info};
  3. annotations — every alert carries non-empty summary + description and a
     runbook_url anchored at the documented base (an alert nobody can act on
     is not an alert);
  4. pacing — every alert carries a `for:` duration (an instant-firing alert
     on a flapping metric is noise);
  5. expression sanity — non-empty expr with balanced braces/parens and at
     least one metric selector (a constant expression alerts on nothing or
     everything);
  6. promtool — `promtool check rules` over the file when the binary exists
     (the authoritative parser). Absent promtool the structural checks still
     run; the CI stage tool-gates promtool separately, so this branch is a
     fallback, not a skip.

`--self-test` proves every class with a seeded defect and a clean fixture.

Usage: check_alerting_rules.py [FILE] [--self-test]
Exit codes: 0 = clean, 1 = violations, 2 = usage/IO error.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_FILE = ROOT / "deploy" / "alerting-rules.yml"
RUNBOOK_BASE = "https://apexmail.ee/docs/alerts#"
SEVERITIES = {"critical", "warning", "info"}
DURATION_RE = re.compile(r"^\d+[smhd]$")
SELECTOR_RE = re.compile(r"[A-Za-z_:][A-Za-z0-9_:]*\s*(\{|\[|$|\s)")


# --- minimal YAML subset parser (this file's shape only: nested mappings,
# sequences of mappings, quoted/plain scalars, comments; no anchors/flow) ---
def _scalar(token: str):
    if len(token) >= 2 and token[0] == token[-1] and token[0] in "\"'":
        return token[1:-1]
    return token


def _entry(line: str) -> tuple[str, str] | None:
    """`key: value` (value possibly empty) or None."""
    if line.startswith("- ") or ":" not in line:
        return None
    key, _, val = line.partition(":")
    if key.startswith(('"', "'")):
        return None
    return key.strip(), val.strip()


def _parse_block(lines: list[tuple[int, str]], i: int, indent: int):
    """Parse a mapping or sequence whose entries start at lines[i] (>= indent).
    Returns (value, next_index)."""
    if i >= len(lines) or lines[i][0] != indent:
        return None, i
    if lines[i][1].startswith("- "):
        seq: list = []
        while i < len(lines) and lines[i][0] == indent and lines[i][1].startswith("- "):
            body = lines[i][1][2:].strip()
            i += 1
            entry = _entry(body)
            if entry is None:
                seq.append(_scalar(body))
                continue
            key, val = entry
            item: dict = {}
            child_indent = indent + 2
            if val in ("|", "|-", "|+", ">", ">-", ">+"):
                _block = []
                while i < len(lines) and lines[i][0] > indent + 2:
                    _block.append(lines[i][1])
                    i += 1
                item[key] = "\n".join(_block)
            elif val:
                item[key] = _scalar(val)
            elif i < len(lines) and lines[i][0] >= child_indent:
                item[key], i = _parse_block(lines, i, lines[i][0])
            # remaining keys of this item mapping sit at indent+2
            while i < len(lines) and lines[i][0] == child_indent \
                    and not lines[i][1].startswith("- "):
                nxt = _entry(lines[i][1])
                if nxt is None:
                    break
                k2, v2 = nxt
                i += 1
                if v2 in ("|", "|-", "|+", ">", ">-", ">+"):
                    _block = []
                    while i < len(lines) and lines[i][0] > child_indent:
                        _block.append(lines[i][1])
                        i += 1
                    item[k2] = "\n".join(_block)
                elif v2:
                    item[k2] = _scalar(v2)
                elif i < len(lines) and lines[i][0] > child_indent:
                    item[k2], i = _parse_block(lines, i, lines[i][0])
                else:
                    item[k2] = None
            seq.append(item)
        return seq, i
    mapping: dict = {}
    while i < len(lines) and lines[i][0] == indent \
            and not lines[i][1].startswith("- "):
        entry = _entry(lines[i][1])
        if entry is None:
            i += 1
            continue
        key, val = entry
        i += 1
        if val in ("|", "|-", "|+", ">", ">-", ">+"):
            _block = []
            while i < len(lines) and lines[i][0] > indent:
                _block.append(lines[i][1])
                i += 1
            mapping[key] = "\n".join(_block)
        elif val:
            mapping[key] = _scalar(val)
        elif i < len(lines) and lines[i][0] > indent:
            mapping[key], i = _parse_block(lines, i, lines[i][0])
        else:
            mapping[key] = None
    return mapping, i


def parse_yaml_subset(text: str):
    lines = [
        (len(raw) - len(raw.lstrip(" ")), raw.strip())
        for raw in text.splitlines()
        if raw.strip() and not raw.lstrip().startswith("#")
    ]
    if not lines:
        return None
    value, _ = _parse_block(lines, 0, lines[0][0])
    return value


def check_rules(file: Path, *, promtool: str | None = None) -> list[str]:
    problems: list[str] = []
    try:
        text = file.read_text()
    except OSError as exc:
        return [f"unreadable rules file {file}: {exc}"]
    doc = parse_yaml_subset(text)
    if not isinstance(doc, dict) or not isinstance(doc.get("groups"), list):
        return ["no groups parsed — the rules file is empty or malformed"]
    seen: set[str] = set()
    count = 0
    for group in doc["groups"]:
        if not isinstance(group, dict) or not group.get("name"):
            problems.append("a group without a name")
            continue
        rules = group.get("rules")
        if not isinstance(rules, list) or not rules:
            problems.append(f"group {group.get('name')!r}: no rules list")
            continue
        for rule in rules:
            if not isinstance(rule, dict):
                problems.append(f"group {group.get('name')!r}: rule is not a mapping")
                continue
            count += 1
            # Recording rules: name + expression only — no alert semantics.
            rec = rule.get("record")
            if rec:
                expr = str(rule.get("expr", "")).strip()
                if not expr:
                    problems.append(f"record {rec}: empty expr")
                elif expr.count("{") != expr.count("}") or expr.count("(") != expr.count(")"):
                    problems.append(f"record {rec}: expr braces/parens are unbalanced")
                continue
            name = rule.get("alert")
            if not name:
                problems.append(f"group {group.get('name')!r}: rule without an alert name")
                continue
            if name in seen:
                problems.append(f"{name}: duplicate alert name")
            seen.add(name)
            labels = rule.get("labels") if isinstance(rule.get("labels"), dict) else {}
            severity = labels.get("severity")
            if severity not in SEVERITIES:
                problems.append(
                    f"{name}: labels.severity must be one of {sorted(SEVERITIES)}, got {severity!r}")
            annotations = rule.get("annotations") if isinstance(rule.get("annotations"), dict) else {}
            for field in ("summary", "description"):
                if not str(annotations.get(field, "")).strip():
                    problems.append(f"{name}: annotations.{field} is missing or empty")
            expr = str(rule.get("expr", "")).strip()
            # The Watchdog convention: an always-firing dead-man's switch
            # (vector(1)) that MUST fire continuously — no `for:`, no metric
            # selector, no runbook. It is exempt from exactly those three;
            # severity and annotations still apply.
            watchdog = name == "Watchdog" and expr == "vector(1)"
            if not watchdog:
                runbook = str(annotations.get("runbook_url", ""))
                if not runbook.startswith(RUNBOOK_BASE) or len(runbook) <= len(RUNBOOK_BASE):
                    problems.append(f"{name}: runbook_url must anchor at {RUNBOOK_BASE}<alert-id>")
                duration = str(rule.get("for", "")).strip()
                if not DURATION_RE.match(duration):
                    problems.append(f"{name}: missing or malformed `for:` duration (got {duration!r})")
            if not expr:
                problems.append(f"{name}: empty expr")
                continue
            if expr.count("{") != expr.count("}") or expr.count("(") != expr.count(")"):
                problems.append(f"{name}: expr braces/parens are unbalanced")
            if not watchdog and not SELECTOR_RE.search(expr):
                problems.append(f"{name}: expr carries no metric selector")
    if count == 0:
        problems.append("no alert rules found at all")
    if promtool:
        try:
            proc = subprocess.run([promtool, "check", "rules", str(file)],
                                  capture_output=True, text=True, timeout=120)
        except (OSError, subprocess.TimeoutExpired) as exc:
            problems.append(f"promtool invocation failed: {exc}")
        else:
            if proc.returncode != 0:
                detail = (proc.stdout + proc.stderr).strip().splitlines()
                problems.append("promtool: " + (detail[-1] if detail else "check failed"))
    return problems


def self_test() -> int:
    clean = """groups:
  - name: g
    rules:
      - alert: GoodAlert
        expr: up{job="x"} == 0
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "s"
          description: "d"
          runbook_url: "https://apexmail.ee/docs/alerts#good-alert"
"""
    seeds = {
        "duplicate alert name": (
            # two groups under one `groups:` carrying the same alert name
            "groups:\n"
            + "".join(l + "\n" for l in clean.splitlines()[1:])
            + "  - name: g2\n    rules:\n"
            + "".join(l + "\n" for l in clean.splitlines()[3:])
        ),
        "missing severity": clean.replace("severity: critical", "other: x"),
        "bad severity": clean.replace("severity: critical", "severity: urgent"),
        "empty summary": clean.replace('summary: "s"', 'summary: ""'),
        "missing description": clean.replace('          description: "d"\n', ""),
        "unanchored runbook": clean.replace(
            "https://apexmail.ee/docs/alerts#good-alert", "https://example.com/x"),
        "missing for": clean.replace("        for: 1m\n", ""),
        "malformed for": clean.replace("for: 1m", "for: immediately"),
        "empty expr": clean.replace('up{job="x"} == 0', '""'),
        "unbalanced expr": clean.replace('up{job="x"} == 0', 'up{job="x" == 0'),
        "selector-free expr": clean.replace('up{job="x"} == 0', "1 == 1"),
        "no groups": "not_rules: []",
    }
    failures = 0
    with tempfile.TemporaryDirectory() as tmp:
        base = Path(tmp)
        clean_file = base / "clean.yml"
        clean_file.write_text(clean)
        if check_rules(clean_file):
            print(f"self-test FAIL: the clean fixture was rejected: {check_rules(clean_file)}",
                  file=sys.stderr)
            return 1
        for label, text in seeds.items():
            fixture = base / "seed.yml"
            fixture.write_text(text)
            problems = check_rules(fixture)
            if not problems:
                print(f"self-test FAIL: seeded defect not caught: {label}", file=sys.stderr)
                failures += 1
    if failures:
        print(f"self-test FAIL: {failures} seeded defect(s) escaped", file=sys.stderr)
        return 1
    print("check_alerting_rules self-test: ok (clean accepted; duplicate, severity, "
          "annotation, runbook, pacing and expression defects all caught)")
    return 0


def main(argv: list[str]) -> int:
    if "--self-test" in argv:
        return self_test()
    args = [a for a in argv if not a.startswith("--")]
    path = Path(args[0]) if args else DEFAULT_FILE
    if not path.exists():
        print(f"alerting rules gate: {path} not found", file=sys.stderr)
        return 2
    promtool = shutil.which("promtool")
    problems = check_rules(path, promtool=promtool)
    if problems:
        print("alerting rules gate FAILED:", file=sys.stderr)
        for p in problems:
            print(f"  - {p}", file=sys.stderr)
        return 1
    print(f"alerting rules gate: clean ({path.name}"
          + (" + promtool" if promtool else ", structural only (install promtool)") + ")")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
