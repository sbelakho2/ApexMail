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

BANNED_PHRASES = {
    "enterprise-grade": "say what is actually true about the deployment instead",
    "lightning-fast": "drop the speed superlative — state the mechanism or number",
    "seamless": "describe the actual flow; nothing is seamless",
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

    # ── 3. app-surface fixture text (when the export is available) ────────
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


if __name__ == "__main__":
    sys.exit(main(sys.argv))
