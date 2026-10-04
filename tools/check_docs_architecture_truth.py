#!/usr/bin/env python3
"""Architecture-truth gate for the documentation tree (audit EXT-E #11).

The authoritative architecture is a SINGLE HETZNER HOST with DOCKER COMPOSE
(ARCHITECTURE.md: "no Kubernetes"). Operational documentation must not teach
commands that cannot work on that deployment. This gate fails any production
runbook / operational doc under docs/ that contains Kubernetes-operations
commands:

  kubectl ...        (any kubectl invocation, incl. `kubectl rollout`)
  helm ...           (the Helm chart is retired; deploy/legacy-k8s is archive)
  k9s ...            (Kubernetes TUI — no cluster to point it at)
  istioctl / argocd  (service-mesh / GitOps operators of the retired topology)
  "namespace apexmail" (a Kubernetes namespace this deployment never had)

UNLESS the document carries the historical/roadmap marker within its first
MARKER_SCAN_LINES lines:

  ARCHITECTURE-TRUTH: HISTORICAL | ROADMAP | ALTERNATIVE

(case-insensitive keywords; the marker line is what operators grep for).
Marked documents are reported, not failed — the marker kills the ambiguity
while preserving the design value of e.g. roadmap topologies.

Non-operational RECORD trees are excluded outright (point-in-time records
where retired-topology mentions are historical by construction):
  docs/audit/  docs/adr/  docs/design/  docs/evaluation/  docs/marketing/
  docs/ddos_analysis_report.md  docs/recovered-files-analysis.md

Word boundaries are used ("overwhelm" must not match `helm`). Prose that
merely SAYS "no Kubernetes" (ARCHITECTURE.md) is out of scope by design —
this gate scans docs/ only, and only operational-command patterns.

Usage:
  python3 tools/check_docs_architecture_truth.py [docs-root]
  python3 tools/check_docs_architecture_truth.py --selftest

Exit 0 clean / 1 violations (or selftest failure).
"""
from __future__ import annotations

import re
import shutil
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_DOCS = ROOT / "docs"
MARKER_SCAN_LINES = 15

# Non-operational record trees: historical by construction, never a runbook.
NON_OPERATIONAL_DIRS = ("audit", "adr", "design", "evaluation", "marketing")
NON_OPERATIONAL_FILES = (
    "ddos_analysis_report.md",
    "recovered-files-analysis.md",
)

# Kubernetes-operations command patterns (word-boundary anchored).
PATTERNS = [
    (re.compile(r"\bkubectl\b"), "kubectl (Kubernetes CLI — no cluster exists)"),
    (re.compile(r"\bhelm\b"), "helm (retired Helm chart — deploy/legacy-k8s archive)"),
    (re.compile(r"\bk9s\b"), "k9s (Kubernetes TUI — no cluster exists)"),
    (re.compile(r"\bistioctl\b"), "istioctl (service mesh of the retired topology)"),
    (re.compile(r"\bargocd\b"), "argocd (GitOps operator of the retired topology)"),
    (re.compile(r"namespace apexmail"), "Kubernetes namespace (never existed here)"),
]

MARKER_RE = re.compile(
    r"ARCHITECTURE-TRUTH:\s*(HISTORICAL|ROADMAP|ALTERNATIVE)", re.IGNORECASE
)

failures: list[str] = []


def is_exempt_path(rel: Path) -> bool:
    parts = rel.parts
    if any(p in NON_OPERATIONAL_DIRS for p in parts[:-1]):
        return True
    return rel.name in NON_OPERATIONAL_FILES


def carries_marker(text_lines: list[str]) -> str | None:
    for line in text_lines[:MARKER_SCAN_LINES]:
        m = MARKER_RE.search(line)
        if m:
            return m.group(1).upper()
    return None


def check_docs(docs_dir: Path) -> int:
    global failures
    failures = []
    exempted: list[str] = []
    files = sorted(docs_dir.rglob("*.md"))
    if not files:
        print(f"FAIL no markdown files under {docs_dir}")
        return 1
    for path in files:
        rel = path.relative_to(docs_dir)
        if is_exempt_path(rel):
            continue
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError as e:
            failures.append(f"{rel}: unreadable ({e})")
            continue
        marker = carries_marker(lines)
        if marker:
            exempted.append(f"{rel} ({marker})")
            continue
        for lineno, line in enumerate(lines, start=1):
            for pattern, why in PATTERNS:
                if pattern.search(line):
                    excerpt = line.strip()
                    if len(excerpt) > 100:
                        excerpt = excerpt[:97] + "..."
                    failures.append(f"{rel}:{lineno}: {why}\n    {excerpt}")
    print(f"docs architecture truth: scanned {len(files)} files under {docs_dir}")
    if exempted:
        print(f"exempt via ARCHITECTURE-TRUTH marker ({len(exempted)}):")
        for e in exempted:
            print(f"  - {e}")
    if failures:
        print()
        print(f"ARCHITECTURE-TRUTH FAILURES: {len(failures)}")
        for f in failures[:50]:
            print(f"  - {f}")
        if len(failures) > 50:
            print(f"  … and {len(failures) - 50} more")
        print()
        print("Fix: replace with the real Docker Compose command (single Hetzner")
        print("host — ARCHITECTURE.md, docker-compose.prod.yml, deploy/rollback-plan.md),")
        print(f"or mark a genuinely historical/roadmap doc with a top-of-file")
        print(f"'ARCHITECTURE-TRUTH: HISTORICAL|ROADMAP|ALTERNATIVE' line (first {MARKER_SCAN_LINES}).")
        return 1
    print("docs architecture truth: all green (no Kubernetes operations in production docs)")
    return 0


def selftest() -> int:
    """Drift-injection proof on a throwaway docs tree."""
    ok = True
    tmp = Path(tempfile.mkdtemp(prefix="archtruth-selftest-"))
    try:
        runbooks = tmp / "operations" / "runbooks"
        runbooks.mkdir(parents=True)
        (tmp / "audit").mkdir()

        clean = runbooks / "clean.md"
        clean.write_text(
            "# Clean Runbook\n\n```bash\ndocker compose exec postgres psql -U apexmail\n```\n",
            encoding="utf-8",
        )
        historical = runbooks / "historical.md"
        historical.write_text(
            "# Old Design\n\n> ARCHITECTURE-TRUTH: HISTORICAL — retired-topology record.\n\n"
            "```bash\nhelm rollback apexmail 5 -n apexmail\n```\n",
            encoding="utf-8",
        )
        record = tmp / "audit" / "record.md"
        record.write_text("audit record mentioning kubectl get pods\n", encoding="utf-8")
        overwhelm = runbooks / "overwhelm.md"
        overwhelm.write_text(
            "# Word boundary check\n\nThe system cannot be overwhelmed by traffic.\n",
            encoding="utf-8",
        )

        print("selftest 1: clean tree passes (marker file exempt, audit record excluded)")
        rc = check_docs(tmp)
        ok &= rc == 0

        print("selftest 2: injected `kubectl` drift FAILS")
        drift = runbooks / "drift.md"
        drift.write_text(
            "# Drifted Runbook\n\n```bash\nkubectl rollout restart deployment/api-server -n apexmail\n```\n",
            encoding="utf-8",
        )
        rc = check_docs(tmp)
        ok &= rc == 1

        print("selftest 4: removing the drift makes it pass again")
        drift.unlink()
        rc = check_docs(tmp)
        ok &= rc == 0

        print("selftest 5: word boundaries — 'overwhelm' never matched helm")
        # (implicit: selftest 1/4 passed with overwhelm.md present)

        print("selftest 6: marker below the scan horizon is NOT accepted")
        late = runbooks / "late-marker.md"
        late.write_text(
            "# Late marker\n\n" * MARKER_SCAN_LINES + "<!-- ARCHITECTURE-TRUTH: HISTORICAL -->\n\n```bash\nkubectl get pods\n```\n",
            encoding="utf-8",
        )
        rc = check_docs(tmp)
        ok &= rc == 1
        late.unlink()

        print("selftest 7: ROADMAP/ALTERNATIVE keyword variants accepted")
        roadmap = runbooks / "roadmap.md"
        roadmap.write_text(
            "# Roadmap\n\n> architecture-truth: roadmap — future topology.\n\n```bash\nhelm upgrade --install redis ./chart\n```\n",
            encoding="utf-8",
        )
        rc = check_docs(tmp)
        ok &= rc == 0
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    print()
    print("SELFTEST:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


def main(argv: list[str]) -> int:
    if "--selftest" in argv:
        return selftest()
    args = [a for a in argv[1:] if not a.startswith("-")]
    docs = Path(args[0]) if args else DEFAULT_DOCS
    if not docs.is_dir():
        print(f"FAIL docs directory missing: {docs}")
        return 1
    return check_docs(docs)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
