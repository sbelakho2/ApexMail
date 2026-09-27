#!/usr/bin/env python3
"""Gate K — UI strings catalog extractor.

Single source of truth for WHAT user-visible copy exists and WHERE: emits
docs/development/ui-strings-catalog.json,

    {"generated_by": "…",
     "namespaces": {"web": […], "control-plane": […], "flash": […],
                    "tracking": […], "email": […]}}

with entries {"id": "path:line", "text": "…"} (ids are repo-relative
file:line of the containing string literal; entries are deduplicated and
sorted, so the output is deterministic).

Extraction (stdlib regex, same extractors as the gates):
  flash          — gate-C extractor over crates/*/src (redirect_* /
                   FlashMessage::*, production regions)
  web /
  control-plane  — ui-foundation's leptos_views.rs, attributed by the
                   enclosing top-level function prefix (web_* vs
                   control_plane*/cp_*/sales_*); shared helpers without a
                   surface prefix are skipped, as are the marketing_* fns
                   (the marketing site has its own voice gates)
  tracking       — tracking-service templates.rs render_* format! templates
  email          — the known system-email builder fns:
                   auth.rs::enqueue_verification_email,
                   web.rs::form_signup, web.rs::form_forgot_password and
                   forgot_password.rs::forgot_password (the verification and
                   reset templates and their web PRG twins)

Modes:
  default        — (re)write the catalog
  --check        — re-extract and exit 1 when the result differs from the
                   committed catalog (drift gate)
  --output PATH  — write somewhere else (default: the committed catalog)

Usage: python3 tools/extract_ui_strings.py [--check] [--output PATH]
"""
from __future__ import annotations

import json
import re
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from ui_flash_extract import (  # noqa: E402
    _matching_brace,
    decode_rust_literal,
    production_split,
    rust_string_literals,
    visible_text_fragments,
)

ROOT = Path(__file__).resolve().parent.parent
CATALOG = ROOT / "docs/development/ui-strings-catalog.json"
VIEWS = ROOT / "services/mail-server/crates/ui-foundation/src/leptos_views.rs"
TRACKING_TEMPLATES = ROOT / "services/mail-server/crates/tracking-service/src/templates.rs"

GENERATED_BY = ("tools/extract_ui_strings.py (stdlib extraction; regenerate, "
                "do not edit by hand)")

EMAIL_BUILDER_FNS = [
    ("services/mail-server/crates/api-server/src/routes/auth.rs",
     "enqueue_verification_email"),
    ("services/mail-server/crates/api-server/src/routes/web.rs",
     "form_signup"),
    ("services/mail-server/crates/api-server/src/routes/web.rs",
     "form_forgot_password"),
    ("services/mail-server/crates/api-server/src/routes/forgot_password.rs",
     "forgot_password"),
]

_WEB_FN_RE = re.compile(r"^pub(?:\(crate\))?\s+fn\s+([a-z0-9_]+)", re.M)


def _catalog_worthy_fragment(fragment: str) -> bool:
    if len(fragment) < 4:
        return False
    if sum(ch.isalpha() for ch in fragment) < 3:
        return False
    if " " not in fragment and not fragment.endswith((".", "!", "?", ":")):
        return False
    if set(fragment) <= set("-—•|/ "):
        return False
    return True


def _plain_catalog_worthy(text: str) -> bool:
    text = text.strip()
    if len(text) < 4 or "{" in text or "}" in text or ";" in text:
        return False
    if sum(ch.isalpha() for ch in text) < 3 or " " not in text:
        return False
    if re.fullmatch(r"[\w\-./%]+", text):
        return False  # css class / path / identifier shaped
    return True


def _entries_from_markup(literal_text: str, rel: str, line: int, entries: list) -> None:
    for fragment in visible_text_fragments(literal_text):
        if _catalog_worthy_fragment(fragment):
            entries.append({"id": f"{rel}:{line}", "text": fragment})


def flash_namespace_entries() -> list[dict]:
    from ui_flash_extract import all_flash_sites

    entries: list[dict] = []
    for site in all_flash_sites()[0]:
        text = re.sub(r"\s+", " ", site.text).strip()
        if text:
            entries.append({"id": f"{site.path}:{site.line}", "text": text})
    return entries


def _literal_inner(raw: str) -> str:
    """Content of a Rust string literal (quotes / r#"…"# wrapper removed)."""
    if raw.startswith('r"'):
        return raw[2:-1]
    if raw.startswith("r"):
        hashes = raw[1:raw.index('"')]
        return raw[2 + len(hashes):-(1 + len(hashes))]
    return decode_rust_literal(raw[1:-1])


def tracking_namespace_entries() -> list[dict]:
    production = production_split(TRACKING_TEMPLATES.read_text(errors="replace"))
    rel = TRACKING_TEMPLATES.resolve().relative_to(ROOT).as_posix()
    entries: list[dict] = []
    for start, _end, raw in rust_string_literals(production):
        literal = _literal_inner(raw)
        if "<" not in literal:
            continue
        line = production.count("\n", 0, start) + 1
        _entries_from_markup(literal, rel, line, entries)
    return entries


def _fn_body(path: Path, fn_name: str) -> tuple[str, int] | None:
    production = production_split(path.read_text(errors="replace"))
    m = re.search(rf"\bfn\s+{re.escape(fn_name)}\s*\(", production)
    if m is None:
        return None
    brace = production.find("{", m.end())
    if brace < 0:
        return None
    close = _matching_brace(production, brace)
    end = close + 1 if close >= 0 else len(production)
    base_line = production.count("\n", 0, m.start())
    return production[brace:end], base_line + production[:brace].count("\n")


def email_namespace_entries() -> list[dict]:
    entries: list[dict] = []
    for rel_path, fn_name in EMAIL_BUILDER_FNS:
        path = ROOT / rel_path
        found = _fn_body(path, fn_name)
        if found is None:
            print(f"note: email builder {fn_name} not found in {rel_path}")
            continue
        body, base_line = found
        for start, _end, raw in rust_string_literals(body):
            literal = _literal_inner(raw)
            line = base_line + body.count("\n", 0, start) + 1
            if "<" in literal and ">" in literal:
                _entries_from_markup(literal, rel_path, line, entries)
            else:
                text = re.sub(r"\s+", " ", literal).strip()
                # interpolated text bodies are copy too: judge them with the
                # placeholders blanked, but catalog the real text
                blanked = re.sub(r"\{[^}]*\}", " ", text)
                if _catalog_worthy_fragment(blanked) or _plain_catalog_worthy(blanked):
                    entries.append({"id": f"{rel_path}:{line}", "text": text})
    return entries


def build_catalog() -> dict:
    # view entries carry no namespace tag — the single views file is split by
    # the enclosing top-level function prefix (web_* vs control_plane*/…).
    web, cp = [], []
    production = production_split(VIEWS.read_text(errors="replace"))
    rel = VIEWS.resolve().relative_to(ROOT).as_posix()
    matches = list(_WEB_FN_RE.finditer(production))
    for i, m in enumerate(matches):
        fn = m.group(1)
        if fn.startswith("web_"):
            sink = web
        elif fn.startswith(("control_plane", "cp_", "sales_")):
            sink = cp
        else:
            continue
        body_start = production.find("{", m.end())
        body_end = matches[i + 1].start() if i + 1 < len(matches) else len(production)
        body = production[body_start:body_end]
        base_line = production.count("\n", 0, m.start())
        for start, _end, raw in rust_string_literals(body):
            line = base_line + body.count("\n", 0, start) + 1
            literal = _literal_inner(raw)
            if "<" in literal and ">" in literal:
                _entries_from_markup(literal, rel, line, sink)
            elif _plain_catalog_worthy(literal):
                sink.append(
                    {"id": f"{rel}:{line}", "text": re.sub(r"\s+", " ", literal).strip()}
                )

    def finalize(entries: list[dict]) -> list[dict]:
        seen = set()
        out = []
        for entry in sorted(entries, key=lambda e: (e["id"], e["text"])):
            key = (entry["id"], entry["text"])
            if key in seen:
                continue
            seen.add(key)
            out.append(entry)
        return out

    return {
        "generated_by": GENERATED_BY,
        "namespaces": {
            "web": finalize(web),
            "control-plane": finalize(cp),
            "flash": finalize(flash_namespace_entries()),
            "tracking": finalize(tracking_namespace_entries()),
            "email": finalize(email_namespace_entries()),
        },
    }


def canonical(catalog: dict) -> str:
    return json.dumps(catalog, indent=2, ensure_ascii=False, sort_keys=False) + "\n"


def main(argv: list[str]) -> int:
    check = "--check" in argv
    output = CATALOG
    if "--output" in argv:
        output = Path(argv[argv.index("--output") + 1])

    catalog = build_catalog()
    counts = {ns: len(entries) for ns, entries in catalog["namespaces"].items()}
    print("extracted strings per namespace: " +
          ", ".join(f"{ns}={n}" for ns, n in counts.items()) +
          f" (total {sum(counts.values())})")

    rendered = canonical(catalog)
    if check:
        if not output.is_file():
            print(f"FAIL catalog missing: {output} — run without --check to write it")
            return 1
        committed = output.read_text()
        if committed == rendered:
            print(f"PASS catalog in sync: {output}")
            return 0
        try:
            committed_catalog = json.loads(committed)
            committed_counts = {
                ns: len(entries)
                for ns, entries in committed_catalog.get("namespaces", {}).items()
            }
            print(f"FAIL catalog drift: {output}")
            for ns in sorted(set(counts) | set(committed_counts)):
                if committed_counts.get(ns) != counts.get(ns):
                    print(f"  - namespace {ns}: committed "
                          f"{committed_counts.get(ns)} vs extracted {counts.get(ns)}")
        except json.JSONDecodeError:
            print(f"FAIL catalog at {output} is not valid JSON")
        return 1

    output.parent.mkdir(parents=True, exist_ok=True)
    tmp = tempfile.NamedTemporaryFile(
        "w", delete=False, dir=str(output.parent), suffix=".tmp", encoding="utf-8"
    )
    tmp.write(rendered)
    tmp.close()
    Path(tmp.name).replace(output)
    print(f"wrote {output}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
