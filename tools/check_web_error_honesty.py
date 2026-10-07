#!/usr/bin/env python3
"""Web error-honesty gate (outage-honesty audit #16).

The audited console swallowed request-path database failures with
`.ok().flatten()`, `.unwrap_or(0)` and `.unwrap_or_default()`, which made a
Postgres outage semantically IDENTICAL to the handler's negative answers:
"invalid credentials", "contact not found", "zero recipients", "tenant not
found". The conversion contract (see `WebActionError` /
`temporary_storage_failure` in routes/web.rs) is:

    Ok(Some(_)) -> proceed        Ok(None) -> genuine not-found copy
    Err(_)      -> temporary_storage_failure (error-logged, outage-counted)

This gate keeps the swallow patterns OUT of the web console's production
regions forever. It scans `routes/web.rs` and `routes/web/*.rs`:

  1. `.ok().flatten()` anywhere in production code (a Result<Option<_>>
     collapsed into a bare Option<_> is ALWAYS a swallowed error);
  2. `.unwrap_or(...)` / `.unwrap_or_default()` / `.unwrap_or_else(...)` /
     `.ok()` in the tail of a database statement (after the final `.await`
     of a fetch_optional/fetch_one/fetch_all/execute chain) — unless a `?`
     already propagated the error and the unwrap only defaults the INNER
     option (e.g. `fetch_optional(..).await?.unwrap_or(0)` on an aggregate);
  3. `if let Ok(...)` / `let Ok(...)` scrutinees riding a database statement
     (the "degrade to empty on error" shape);
  4. the honest surface itself is PRESENT: `WebActionError`,
     `temporary_storage_failure`, the neutral flash copy, the outage
     counter, and the two documented anti-enumeration exception sites
     (forgot-password, resend-verification) still log AND count internally.

Test regions (`#[cfg(test)]` items and modules) are excluded — the outage
matrix tests legitimately drive dead pools there.

Any FAIL exits 1. Allowlist entries must still match (a stale entry is a
failure) and each carries a justification.

Self-test: `check_web_error_honesty.py --self-test` runs the gate against a
sandboxed copy of the real web sources and proves it FAILS when a
`.ok().flatten()` swallow or a database-result `.unwrap_or` default is
injected into production code (the real files are never touched).
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
WEB_DIR = ROOT / "services/mail-server/crates/api-server/src/routes/web"
SOURCES = [ROOT / "services/mail-server/crates/api-server/src/routes/web.rs"]
if WEB_DIR.is_dir():
    SOURCES.extend(sorted(WEB_DIR.glob("*.rs")))

failures: list[str] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    status = "PASS" if ok else "FAIL"
    suffix = f" — {detail}" if detail and not ok else ""
    print(f"{status} {name}{suffix}")
    if not ok:
        failures.append(name)


# ── Source masking ────────────────────────────────────────────────────
#
# Comments and string/char/raw-string contents are blanked (offsets and
# newlines preserved) so brace matching and statement splitting only ever
# see structural Rust. The web console embeds HTML with `{}` braces, so a
# naive brace count would desynchronize instantly without this.

def mask(text: str) -> str:
    out = list(text)
    n = len(text)
    i = 0
    state = "code"
    raw_hashes = 0
    while i < n:
        ch = text[i]
        nxt = text[i + 1] if i + 1 < n else ""
        if state == "code":
            if ch == "/" and nxt == "/":
                state = "line_comment"
                out[i] = out[i + 1] = " "
                i += 2
                continue
            if ch == "/" and nxt == "*":
                state = "block_comment"
                out[i] = out[i + 1] = " "
                i += 2
                continue
            if ch == '"':
                # Raw string? r#"..."#, r##"..."##, ...
                if i > 0 and text[i - 1] == "r":
                    hashes = 0
                    j = i + 1
                    while j < n and text[j] == "#":
                        hashes += 1
                        j += 1
                    if hashes:
                        state = "raw_string"
                        raw_hashes = hashes
                        out[i] = " "
                        i += 1
                        continue
                state = "string"
                out[i] = " "
                i += 1
                continue
            if ch == "'":
                # Lifetime ('a, 'static) — NOT a char literal. A char literal
                # is 'X' or '\X' (closing quote within two chars).
                if nxt == "\\":
                    state = "char"
                    out[i] = " "
                    i += 1
                    continue
                if nxt and i + 2 < n and text[i + 2] == "'":
                    state = "char"
                    out[i] = " "
                    i += 1
                    continue
                # Lifetime: leave as code.
                i += 1
                continue
            i += 1
            continue
        if state == "line_comment":
            if ch == "\n":
                state = "code"
            else:
                out[i] = " "
            i += 1
            continue
        if state == "block_comment":
            if ch == "*" and nxt == "/":
                out[i] = out[i + 1] = " "
                state = "code"
                i += 2
                continue
            if ch != "\n":
                out[i] = " "
            i += 1
            continue
        if state == "string":
            if ch == "\\":
                # Blank the escape target too — unless it is a newline (an
                # escaped line continuation), which must survive so offsets
                # keep mapping to real line numbers.
                if nxt and nxt != "\n":
                    out[i] = out[i + 1] = " "
                else:
                    out[i] = " "
                i += 2
                continue
            if ch == '"':
                state = "code"
                out[i] = " "
                i += 1
                continue
            # Rust string literals may span lines (multi-line SQL is common
            # here); ONLY the closing quote ends the string. Treating a
            # newline as a terminator desynchronized the whole mask on every
            # multi-line literal (found by the 2026-10-07 gates review: the
            # `#[cfg(test)] mod` brace match then ran to EOF).
            if ch != "\n":
                out[i] = " "
            i += 1
            continue
        if state == "raw_string":
            if ch == '"':
                j = i + 1
                hashes = 0
                while j < n and text[j] == "#":
                    hashes += 1
                    j += 1
                if hashes == raw_hashes:
                    for k in range(i, j):
                        out[k] = " "
                    i = j
                    state = "code"
                    continue
            if ch != "\n":
                out[i] = " "
            i += 1
            continue
        if state == "char":
            if ch == "'":
                state = "code"
                out[i] = " "
                i += 1
                continue
            # Same rule as strings: a bare newline inside a char literal is
            # impossible in valid Rust, but if the masker is ever desynced the
            # newline must survive (line numbers) rather than silently close.
            if ch != "\n":
                out[i] = " "
            i += 1
            continue
    return "".join(out)


def blank_test_regions(masked: str) -> str:
    """Blank `#[cfg(test)]`-annotated items and modules (offsets preserved).

    A `#[cfg(test)] mod X { ... }` is wholesale test code; a bare
    `#[cfg(test)] fn/item` excludes only that item — production code RESUMES
    after it (web.rs carries such an item mid-file).
    """
    out = list(masked)
    attr_re = re.compile(r"^#\[(cfg\([^)]*test[^)]*\))\]", re.M)
    for match in attr_re.finditer(masked):
        # Find the annotated item: skip further attribute lines.
        pos = match.end()
        while True:
            while pos < len(masked) and masked[pos] in " \t\r\n":
                pos += 1
            if masked.startswith("#[", pos):
                end = masked.find("]", pos)
                pos = end + 1 if end != -1 else pos + 2
                continue
            break
        # Skip `pub(...)`, `pub`, qualifiers to the item keyword.
        window = masked[pos : pos + 200]
        kw = re.search(
            r"^(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?(mod|fn|struct|enum|trait|impl|const|static|union|use)\b",
            window,
        )
        if not kw:
            continue
        brace = masked.find("{", pos)
        if kw.group(1) == "use" or brace == -1:
            end = masked.find(";", pos)
            stop = (end + 1) if end != -1 else len(masked)
        else:
            depth = 0
            j = brace
            while j < len(masked):
                if masked[j] == "{":
                    depth += 1
                elif masked[j] == "}":
                    depth -= 1
                    if depth == 0:
                        break
                j += 1
            stop = j + 1
        # A construct that runs to EOF yields stop == len(masked) + 1; clamp so
        # the masking loop cannot index past the buffer (a gate must REPORT,
        # not crash — this fired on the last item of a file, 2026-10-06).
        for k in range(pos, min(stop, len(out))):
            if out[k] != "\n":
                out[k] = " "
    return "".join(out)


def statements(masked: str):
    """Yield (start, end, text) for brace/paren-depth-0 logical statements."""
    depth = 0
    start = 0
    for i, ch in enumerate(masked):
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth = max(0, depth - 1)
        elif depth == 0 and ch in ";{}":
            if masked[start:i].strip():
                yield start, i + 1, masked[start : i + 1]
            start = i + 1
    if masked[start:].strip():
        yield start, len(masked), masked[start:]


def line_of(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


# ── Patterns ──────────────────────────────────────────────────────────

DB_MARKER_RE = re.compile(r"fetch_optional\(|fetch_one\(|fetch_all\(|\.execute\(")
OK_FLATTEN_RE = re.compile(r"\.ok\(\)\s*\.flatten\(\)")
SWALLOW_RE = re.compile(r"\.unwrap_or\(|\.unwrap_or_default\(|\.unwrap_or_else\(|\.ok\(")
IF_LET_OK_RE = re.compile(r"\bif\s+let\s+Ok\b|\blet\s+Ok\b")
AWAIT_RE = re.compile(r"\.await\b")

# Allowlist: (file substring, statement substring, justification).
# Entries are fail-closed: an entry that no longer matches anything is a
# STALE ALLOWLIST failure, so justifications cannot outlive their site.
ALLOWLIST: list[tuple[str, str, str]] = [
    # Example shape:
    # ("web.rs", ".unwrap_or(0)", "audit #16 exception: <why this swallow is honest>"),
]

def _self_test() -> int:
    """Meta-test: prove this gate FAILS when its evidence disappears.

    Copies the real web-console sources and THIS checker into a temp
    sandbox and runs the copied gate there. Control: the unmutated sandbox
    stays green. Then swallows are injected into the SANDBOX copy of web.rs
    (a production region — appended after the trailing test module):

      1. an `.ok().flatten()` collapse (Result<Option<_>> -> bare Option);
      2. an `.unwrap_or(0)` defaulting a fetched database row's tail.

    The real sources are never touched.
    """
    import shutil
    import subprocess
    import tempfile

    checker = Path(__file__).resolve()
    routes_dir = WEB_DIR.parent  # .../api-server/src/routes
    ok = True

    with tempfile.TemporaryDirectory(prefix="web-honesty-selftest-") as tmp:
        root = Path(tmp)
        sandbox_routes = root / "services/mail-server/crates/api-server/src/routes"
        (sandbox_routes / "web").mkdir(parents=True)
        (root / "tools").mkdir()
        shutil.copyfile(checker, root / "tools" / "check_web_error_honesty.py")
        shutil.copyfile(routes_dir / "web.rs", sandbox_routes / "web.rs")
        for path in sorted(WEB_DIR.glob("*.rs")):
            shutil.copyfile(path, sandbox_routes / "web" / path.name)

        def run_gate() -> tuple[int, str]:
            proc = subprocess.run(
                [sys.executable, str(root / "tools" / "check_web_error_honesty.py")],
                capture_output=True,
                text=True,
            )
            return proc.returncode, proc.stdout + proc.stderr

        def injected_case(label: str, injection: str, needle: str) -> None:
            nonlocal ok
            web_rs = sandbox_routes / "web.rs"
            web_rs.write_text(web_rs.read_text() + injection)
            code, output = run_gate()
            if code == 1 and needle in output:
                print(f"SELF-TEST PASS {label}")
            else:
                ok = False
                print(f"SELF-TEST FAIL {label}: exit={code}, needle={needle!r}")
                print("\n".join(output.strip().splitlines()[-10:]))
            web_rs.write_text(SANDBOX_BASELINE[0])

        # Baseline for restoring between mutations.
        SANDBOX_BASELINE.clear()
        SANDBOX_BASELINE.append((sandbox_routes / "web.rs").read_text())

        code, output = run_gate()
        if code == 0:
            print("SELF-TEST PASS unmutated sandbox copy stays green")
        else:
            ok = False
            print("SELF-TEST FAIL unmutated sandbox copy must stay green:")
            print("\n".join(output.strip().splitlines()[-10:]))

        injected_case(
            "injected .ok().flatten() swallow fails the gate",
            "\n\n// self-test injection: production swallow\n"
            "fn __selftest_injected_ok_flatten(\n"
            "    result: Result<Option<String>, sqlx::Error>,\n"
            ") -> Option<String> {\n"
            "    result.ok().flatten()\n"
            "}\n",
            "ok-flatten swallow",
        )
        injected_case(
            "injected db-result .unwrap_or default fails the gate",
            "\n\n// self-test injection: production swallow\n"
            "async fn __selftest_injected_db_default(row_id: i64) -> i64 {\n"
            '    sqlx::query_scalar::<_, i64>("select 1")\n'
            "        .fetch_one(&pool)\n"
            "        .await\n"
            "        .unwrap_or(0)\n"
            "}\n",
            "db-swallow",
        )

    print(f"web-error-honesty self-test: {'PASS' if ok else 'FAIL'}")
    return 0 if ok else 1


SANDBOX_BASELINE: list[str] = []

if "--self-test" in sys.argv[1:]:
    sys.exit(_self_test())

# ── Scan ──────────────────────────────────────────────────────────────

production: dict[str, str] = {}
raw_source: dict[str, str] = {}
for path in SOURCES:
    raw_source[path.name] = path.read_text()
    masked = blank_test_regions(mask(path.read_text()))
    production[path.name] = masked

# Structural rules 1-3.
prev_db = False
for name, masked in production.items():
    prev_db = False
    for start, end, stmt in statements(masked):
        rel = stmt
        line = line_of(masked, start)
        allowlisted = any(
            file_part in name and needle in stmt for file_part, needle, _ in ALLOWLIST
        )
        if not allowlisted:
            if OK_FLATTEN_RE.search(rel):
                failures.append(
                    f"{name}:{line} ok-flatten swallow: `.ok().flatten()` collapses a "
                    "storage failure into a bare absence (audit #16)"
                )
            tail = ""
            awaits = list(AWAIT_RE.finditer(rel))
            if awaits:
                tail = rel[awaits[-1].end() :]
            if (
                DB_MARKER_RE.search(rel)
                and awaits
                and "?" not in tail
                and SWALLOW_RE.search(tail)
            ):
                failures.append(
                    f"{name}:{line} db-swallow: `.unwrap_or*`/`.ok()` defaults a database "
                    "result's tail — an outage becomes a fabricated value "
                    "(audit #16); return the error (or temporary_storage_failure)"
                )
            if IF_LET_OK_RE.search(rel) and prev_db:
                failures.append(
                    f"{name}:{line} if-let-ok swallow: an `if let Ok` on a database "
                    "result degrades the failure to a no-op (audit #16)"
                )
        prev_db = DB_MARKER_RE.search(rel) is not None

# Stale allowlist detection: every entry must still match its file.
for file_part, needle, justification in ALLOWLIST:
    owner = next((n for n in production if file_part in n), None)
    matches = bool(owner) and any(
        needle in stmt for _, _, stmt in statements(production[owner])
    )
    check(
        f"allowlist-fresh:{file_part}:{needle.strip()[:40]}",
        matches,
        f"allowlist entry no longer matches any statement — remove it "
        f"(justification was: {justification})",
    )

# ── Positive contract: the honest surface must exist ──────────────────
#
# Presence checks run on the RAW source: they must find string literals,
# counters inside macros, and the (test-region) outage matrix module, none
# of which survive the structural mask.
WEB = raw_source.get("web.rs", "")
for needle, label in [
    ("enum WebActionError", "WebActionError (Database/Validation) honest error type"),
    ("fn temporary_storage_failure", "temporary_storage_failure PRG exit"),
    ("TEMPORARY_STORAGE_FLASH", "shared neutral flash copy constant"),
    ("The service is temporarily unavailable. Please try again.", "the neutral outage copy"),
    ("apexmail_web_storage_failures", "outage counter"),
    ("mod outage_matrix_tests", "the outage matrix test module"),
]:
    check(f"honest-surface:{label.split(' ')[0].lower()}", needle in WEB, f"{label} missing from web.rs production+tests")

# Anti-enumeration exceptions (documented sites): the public response stays
# neutral for EVERY outcome, but the lookup failure is logged AND counted —
# the gate proves the counters (and their audit comments) did not rot away.
for needle, label in [
    (
        "apexmail_web_forgot_password_storage_failures",
        "forgot-password anti-enumeration exception still logged+counted",
    ),
    (
        "apexmail_web_resend_verification_storage_failures",
        "resend-verification anti-enumeration exception still logged+counted",
    ),
]:
    check(
        f"anti-enumeration-exception:{label.split('-')[0]}",
        needle in WEB and "ANTI-ENUMERATION EXCEPTION" in WEB,
        f"{label} — the neutral-response site lost its internal error accounting",
    )

# The converted helpers must keep Result-returning signatures (no silent
# re-widening back to Option/bool). Matched with whitespace collapsed so
# rustfmt's line-wrapping cannot false-fail the pin (external audit
# 2026-10-02 follow-up: the campaign's cargo fmt pass reflowed these
# signatures and the exact single-line needles went red).
def _ws_normalized(text: str) -> str:
    # Compare signatures as whitespace-free token streams (rustfmt reflows
    # argument lists — line breaks, the space after '(' and the trailing
    # comma must not false-fail the pin), folding rustfmt's multi-line
    # trailing comma (`&str,\n)` -> `&str)`) first.
    folded = "".join(text.split()).replace(",)", ")")
    return folded


for needle, label in [
    ("async fn find_user_by_email(state: &AppState, email: &str) -> Result<Option<WebUserRow>, sqlx::Error>", "find_user_by_email"),
    ("pub(crate) async fn is_system_tenant(state: &AppState, tenant_id: &str) -> Result<bool, sqlx::Error>", "is_system_tenant"),
]:
    check(
        f"result-signature:{label}",
        _ws_normalized(needle) in _ws_normalized(WEB),
        f"{label} must keep its Result-returning signature",
    )

DATA = raw_source.get("data.rs", "")
for needle, label in [
    ("pub(crate) async fn load_campaign_detail(", "load_campaign_detail"),
    ("pub(crate) async fn load_domain_detail(", "load_domain_detail"),
    ("pub(crate) async fn load_list_detail(", "load_list_detail"),
    ("pub(crate) async fn count_list_recipients_filtered(", "count_list_recipients_filtered"),
    ("pub(crate) async fn tenant_plan_names(", "tenant_plan_names"),
    ("pub(crate) async fn tenant_lists_for_select(", "tenant_lists_for_select"),
]:
    check(f"loader-present:{label}", needle in DATA, f"{label} missing from web/data.rs production")

check(
    "loaders-fail-closed",
    "Result<Option<CampaignDetailData>, sqlx::Error>" in DATA
    and "Result<Option<ListPageData>, sqlx::Error>" in DATA
    and "Result<Option<ui_foundation::view_data::ListDetailData>, sqlx::Error>" in DATA
    and "Result<i64, sqlx::Error>" in DATA,
    "the detail loaders / recipient counter must keep failing closed via Result",
)

print()
if failures:
    print(f"WEB ERROR-HONESTY FAILURES: {len(failures)}")
    for name in failures:
        print(f"  - {name}")
    sys.exit(1)
print("web error honesty: all green")
