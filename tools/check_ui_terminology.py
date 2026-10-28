#!/usr/bin/env python3
"""Gate J — UI terminology gate.

Executable language contract over the app surfaces (ADVISORY by design —
see ci/pipeline.conf CI_UI_TERMINOLOGY_CHECK):

  1. REQUIRED TERMS from deploy/tests/product-names-register.md — the
     "Locked Names" table is parsed into official spellings; every
     case-insensitive occurrence in app-surface copy that does NOT match the
     official spelling exactly is a violation (Apexmail → ApexMail).
     Domain/email contexts are excluded (the register explicitly allows
     lowercase brand tokens there). If the register itself cannot be parsed
     (no Locked Names section / zero rows) the gate FAILS STRUCTURALLY —
     a canon the gate cannot read gates nothing (the topology-gate lesson).
  2. BANNED SUBJECTIVE PHRASES (curated, mirrors the marketing voice bans):
     "enterprise-grade", "lightning-fast", "seamless" must not appear in
     app-surface strings / flash literals.
  3. "tenant" must not appear in web-surface flash strings — the customer
     word is "workspace" (operator surfaces may still say tenant).

Scanned surfaces: flash literals across all crates (production regions via
tools/ui_flash_extract.py) + the visible text of the web / control-plane
fixture documents when the fixture export is available.

Usage: python3 tools/check_ui_terminology.py [fixtures-dir]
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from ui_flash_extract import all_flash_sites  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
REGISTER = ROOT / "deploy/tests/product-names-register.md"
DEFAULT_FIXTURES = ROOT / "services/mail-server/crates/ui-foundation/baselines/rust-ui"
WEB_RS = ROOT / "services/mail-server/crates/api-server/src/routes/web.rs"

failures: list[str] = []
structural_failure = False

APP_SURFACES = {"web", "control-plane"}

# ── Marketing copy surfaces (owner directive 2026-10-25: the copy lint
#    applies everywhere). Template text nodes are scanned with Tera tags and
#    HTML markup stripped; i18n.json values are scanned per locale. ──
MARKETING_TEMPLATES = ROOT / "apps/marketing-zola/templates"
I18N_CATALOG = ROOT / "apps/marketing-zola/data/i18n.json"
_TERA_TAG = re.compile(r"\{%.*?%\}|\{\{.*?\}\}|\{#.*?#\}", re.S)
_HTML_TAG = re.compile(r"<[^>]+>", re.S)


def template_text_nodes(text: str) -> str:
    """The visible fallback copy of a Tera template: Tera directives and
    HTML tags removed."""
    return _HTML_TAG.sub(" ", _TERA_TAG.sub(" ", text))


def marketing_copy_sites():
    """(path, line, phrase) for banned phrases on marketing surfaces."""
    sites = []
    if MARKETING_TEMPLATES.is_dir():
        for path in sorted(MARKETING_TEMPLATES.rglob("*.html")):
            text = template_text_nodes(path.read_text(errors="ignore"))
            for phrase in BANNED_PHRASES:
                if phrase in text.lower():
                    sites.append((str(path), 0, phrase))
    if I18N_CATALOG.is_file():
        import json as _json

        catalog = _json.loads(I18N_CATALOG.read_text())
        def walk(node, where):
            if isinstance(node, dict):
                for k, v in node.items():
                    walk(v, f"{where}.{k}")
            elif isinstance(node, list):
                for i, v in enumerate(node):
                    walk(v, f"{where}[{i}]")
            elif isinstance(node, str):
                low = node.lower()
                for phrase in BANNED_PHRASES:
                    if re.search(
                        r"(?<![A-Za-z0-9_-])" + re.escape(phrase) + r"(?![A-Za-z0-9_-])",
                        low,
                    ):
                        sites.append((str(I18N_CATALOG), where, phrase))
        walk(catalog, "i18n")
    return sites

BANNED_PHRASES = {
    # The content-standards table (docs/marketing/content-standards.md) plus
    # the docs-lint filler vocabulary, enforced on every copy surface:
    # marketing templates and i18n values join the flash strings.
    "enterprise-grade": "say what is actually true about the deployment instead",
    "lightning-fast": "drop the speed superlative — state the mechanism or number",
    "seamless": "describe the actual flow; nothing is seamless",
    "seamlessly": "describe the actual flow; nothing is seamless",
    "world-class": "name the measurable achievement",
    "best-in-class": "state the objective comparison",
    "effortless": "state the number of steps",
    "powerful": "name the capability",
    "robust": "state the reliability data",
    "cutting-edge": "name the technology",
    "state-of-the-art": "name the technology",
    "revolutionary": "remove the claim",
    "unmatched": "substantiate with an independent comparison or remove",
    "built for scale": "state the scale numbers",
    "secure by design": "name the security controls",
    "developer-first": "name the developer features (API, SDKs, docs)",
    "premium": "remove the tier adjective",
    "comprehensive": "state what is actually covered",
    "battle-tested": "state the production evidence",
    "production-ready": "state the conformance evidence",
    "game-changing": "remove the claim",
    "next-generation": "name the generation's actual mechanism",
    "future-proof": "state what is guaranteed",
    "turnkey": "state the setup steps",
    "single pane of glass": "name the surfaces it unifies",
    "supercharge": "state the measured change",
    "unlock": "state what the reader can do",
    "empower": "state what the reader can do",
    "elevate": "state the change",
    "foster": "state the effect",
    "delve": "use 'read' or 'review'",
    "leverage": "use 'use'",
    "in today's": "start with the fact",
    "not merely": "drop the contrast construction",
    "the property you can rely on": "state the property",
}

# "tenant" is operator vocabulary — customer-facing (web-surface) flash
# strings must say "workspace". The rule is scoped to customer-console
# regions of web.rs (batch-2 triage): `form_admin_*` handlers are the
# system-tenant-gated operator surface where "tenant" IS the correct word,
# and the `delete-tenant` arm of the shared destructive-confirm handler
# acts on the operator `/tenants` console. Both regions are exempt below;
# every other web.rs flash site is treated as customer-facing.
TENANT_RE = re.compile(r"\btenants?\b", re.I)


def web_rs_operator_spans() -> list[tuple[int, int]]:
    """(start_line, end_line) spans of web.rs's operator flash regions,
    in PRODUCTION-text coordinates (the same coordinate system
    ui_flash_extract reports site lines in)."""
    from pathlib import Path as _Path

    import ui_flash_extract as _ufe

    path = _Path(__file__).resolve().parent.parent / (
        "services/mail-server/crates/api-server/src/routes/web.rs"
    )
    if not path.is_file():
        return []
    _, production = _ufe.production_text(path)
    lines = production.splitlines()
    spans: list[tuple[int, int]] = []

    def line_of(offset: int) -> int:
        return production.count("\n", 0, offset) + 1

    # 1. Every `async fn form_admin_*` body (the admin form router twins).
    for m in re.finditer(r"async fn (form_admin_\w+)", production):
        brace = production.find("{", m.end())
        if brace == -1:
            continue
        close = _ufe._matching_brace(production, brace)
        if close == -1:
            continue
        spans.append((line_of(m.start()), line_of(close)))

    # 2. The `delete-tenant` arm of the shared destructive-confirm handler:
    #    it acts on the operator /tenants console (system-tenant gated).
    marker = production.find('"delete-tenant" =>')
    if marker != -1:
        brace = production.find("{", marker)
        close = _ufe._matching_brace(production, brace)
        if brace != -1 and close != -1:
            spans.append((line_of(marker), line_of(close)))
    return spans


def parse_register(text: str) -> list[str]:
    """Official names from the Locked Names table; [] if unparsable."""
    section = re.search(r"##\s*Locked Names(.*?)(?=\n##\s|\Z)", text, re.S)
    if section is None:
        return []
    names: list[str] = []
    for line in section.group(1).splitlines():
        line = line.strip()
        if not line.startswith("|"):
            continue
        cells = [c.strip() for c in line.strip("|").split("|")]
        if len(cells) < 2:
            continue
        name = cells[0]
        if not name or name.lower() == "official name":
            continue
        if set(name) <= set("-: "):  # markdown table separator row
            continue
        names.append(name)
    return names


def scrub_domains_emails(text: str) -> str:
    """Remove domain/email contexts (register allows lowercase brand there)."""
    text = re.sub(r"[\w.+-]*@[\w.-]+", " ", text)           # emails
    text = re.sub(r"\b[\w-]*apexmail[\w-]*\.[\w.-]*", " ", text, flags=re.I)  # domains
    return text


def main(argv: list[str]) -> int:
    if "--self-test" in argv[1:]:
        return self_test()
    global structural_failure
    fixtures = Path(argv[1]) if len(argv) > 1 else DEFAULT_FIXTURES

    # ── 1. the canon must parse ────────────────────────────────────────────
    register_text = REGISTER.read_text() if REGISTER.is_file() else ""
    official_names = parse_register(register_text)
    print(f"required terms parsed from {REGISTER.relative_to(ROOT)}: "
          f"{len(official_names)}")
    if not official_names:
        print(f"FAIL terminology register unparsable: {REGISTER} — "
              f"a canon the gate cannot read gates nothing (topology-gate lesson)")
        return 1

    patterns: list[tuple[str, re.Pattern]] = [
        (name, re.compile(re.escape(name), re.I)) for name in official_names
    ]
    patterns.sort(key=lambda p: -len(p[0]))  # longest first, overlap-aware

    def check_brand(text: str, where: str) -> None:
        text = scrub_domains_emails(text)
        consumed: list[tuple[int, int]] = []

        def overlapped(start: int, end: int) -> bool:
            return any(s < end and start < e for s, e in consumed)

        for name, pattern in patterns:
            for m in pattern.finditer(text):
                if overlapped(m.start(), m.end()):
                    continue
                if m.group(0) != name:
                    print(f"FAIL wrong-case-brand {where} — "
                          f"{m.group(0)!r} must be {name!r}")
                    failures.append(f"wrong-case-brand {where}")
                consumed.append((m.start(), m.end()))

    def check_phrases(text: str, where: str) -> None:
        for phrase, advice in BANNED_PHRASES.items():
            for m in re.finditer(re.escape(phrase), text, re.I):
                print(f"FAIL banned-phrase {where} — {phrase!r} ({advice})")
                failures.append(f"banned-phrase {where}")

    # ── 2. flash literals (all crates, production regions) ────────────────
    sites, _leaked = all_flash_sites()
    print(f"flash literals scanned: {len(sites)}")
    operator_spans = web_rs_operator_spans()
    exempted = 0
    for site in sites:
        where = f"{site.path}:{site.line}"
        check_brand(scrub_domains_emails(site.text), where)
        check_phrases(site.text, where)
        if site.path.endswith("api-server/src/routes/web.rs"):
            # Batch-2 triage: the operator regions (form_admin_* handlers and
            # the shared confirm handler's delete-tenant arm) are exempt —
            # "tenant" is the correct operator word there.
            if any(start <= site.line <= end for start, end in operator_spans):
                if TENANT_RE.search(site.text):
                    exempted += 1
                continue
            for m in TENANT_RE.finditer(site.text):
                print(f"FAIL customer-word-tenant {where} — "
                      f"{m.group(0)!r} in a customer-facing flash string "
                      f"(the customer word is \"workspace\")")
                failures.append(f"customer-word-tenant {where}")
    if exempted:
        print(f"operator-region 'tenant' flashes exempt (admin surface): {exempted}")

    # ── 3. marketing copy (templates' visible text + i18n values) ─────────
    marketing_sites = marketing_copy_sites()
    checked = 0
    for path, where, phrase in marketing_sites:
        print(f"FAIL banned-phrase {path}:{where} — {phrase!r} "
              f"({BANNED_PHRASES[phrase]})")
        failures.append(f"banned-phrase {path}:{where}")
        checked += 1
    print(f"marketing copy surfaces: {checked} finding(s)")

    # ── 4. app-surface fixture text (when the export is available) ────────
    if fixtures.is_dir():
        from ui_html_rules import iter_documents
        docs = 0
        for entry, doc in iter_documents(fixtures):
            if entry["surface"] not in APP_SURFACES:
                continue
            docs += 1
            where = f"{entry['surface']}{entry['route']}"
            visible = visible_text(doc.text)
            check_brand(visible, where)
            check_phrases(visible, where)
        print(f"app-surface documents scanned: {docs}")
    else:
        print(f"note: fixtures dir absent ({fixtures}) — fixture scan skipped")

    print()
    if failures:
        print(f"TERMINOLOGY FINDINGS: {len(failures)} (advisory gate)")
        for name in failures[:50]:
            print(f"  - {name}")
        if len(failures) > 50:
            print(f"  … and {len(failures) - 50} more")
        return 1
    print("terminology: all green")
    return 0


_TAG_RE = re.compile(r"<[^>]+>")
_STYLE_RE = re.compile(r"<style[^>]*>.*?</style>", re.S | re.I)
_SCRIPT_RE = re.compile(r"<script[^>]*>.*?</script>", re.S | re.I)


def visible_text(html: str) -> str:
    """Approximate visible text: drop style/script, strip tags, unescape."""
    import html as _html

    html = _STYLE_RE.sub(" ", html)
    html = _SCRIPT_RE.sub(" ", html)
    html = _TAG_RE.sub(" ", html)
    return _html.unescape(html)


# ── self-test (drift injection over a throwaway fixture set) ────────────────
#
# The app-surface fixture scan runs against the REAL register and the REAL
# flash/marketing sources (a green committed tree — the CI precondition):
# clean copy passes, and one known-bad variant per contract clause makes the
# REAL detection path print its FAIL line. The register class is proven by
# pointing REGISTER at an absent file (a canon the gate cannot read).

_TERM_SELFTEST_DOCS = {
    "clean": "<p>Sign in to ApexMail to manage the workspace.</p>",
    "wrong-case-brand": "<p>Sign in to Apexmail to manage the workspace.</p>",
    "banned-phrase": "<p>Sign in to ApexMail for a seamless experience.</p>",
}


def self_test() -> int:
    import io
    import json
    import tempfile
    from contextlib import redirect_stdout

    ok = True

    def run_case(body: str, *, register: Path | None = None) -> tuple[int, str]:
        failures.clear()
        saved = REGISTER
        if register is not None:
            globals()["REGISTER"] = register
        try:
            with tempfile.TemporaryDirectory() as tmp:
                fixtures = Path(tmp)
                (fixtures / "manifest.json").write_text(json.dumps(
                    {"fixtures": [{"surface": "web", "route": "/selftest",
                                   "htmlFile": "selftest.html"}]}))
                (fixtures / "selftest.html").write_text(
                    f"<!DOCTYPE html><html lang=\"en\"><body>{body}</body></html>")
                buffer = io.StringIO()
                with redirect_stdout(buffer):
                    code = main(["check_ui_terminology.py", str(fixtures)])
            return code, buffer.getvalue()
        finally:
            globals()["REGISTER"] = saved

    def case(label: str, expect: str | None, body: str,
             register: Path | None = None) -> None:
        nonlocal ok
        code, out = run_case(body, register=register)
        if expect is None:
            good = code == 0 and "all green" in out
        else:
            good = code == 1 and f"FAIL {expect}" in out
        if good:
            print(f"self-test PASS [{label}]")
        else:
            print(f"self-test FAIL: {label} — exit {code}, expected {expect!r}, "
                  f"findings: {out.splitlines()[-4:]}", file=sys.stderr)
            ok = False

    case("clean app-surface copy passes", None, _TERM_SELFTEST_DOCS["clean"])
    case("brand spelled against the register fails", "wrong-case-brand",
         _TERM_SELFTEST_DOCS["wrong-case-brand"])
    case("banned subjective phrase fails", "banned-phrase",
         _TERM_SELFTEST_DOCS["banned-phrase"])
    case("register the gate cannot parse fails structurally", "terminology register unparsable",
         _TERM_SELFTEST_DOCS["clean"],
         register=ROOT / "deploy/tests/product-names-register.selftest-absent.md")

    if not ok:
        return 1
    print("ui terminology self-test: ok")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
