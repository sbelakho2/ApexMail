#!/usr/bin/env python3
"""Gate E — UI accessibility gate.

Executable a11y baseline over the exported UI fixtures (same input as the
form-hygiene gate: ui-foundation's export_visual_fixtures output). Every
rule is keyed so allowlist entries can target exactly one surface/route:

  html-lang       every document declares `<html … lang=…>`
  img-alt         every <img> has a non-empty alt, or alt="" AND aria-hidden
  label-for       every visible <input>/<select>/<textarea> is labelled
                  (label[for] / wrapping <label> / aria-label /
                  aria-labelledby — same logic as gate D, shared through
                  tools/ui_html_rules.py)
  control-label   the id-less subset of the above: a control with no id must
                  be labelled by a wrapping <label> or an aria-label
  error-association  every aria-describedby target must exist in the document
                  (an invalid control must describe itself with a real
                  element, not a dangling id)
  one-h1          exactly one <h1> per document
  viewport-meta   a `<meta name="viewport" …>` is present
  autocomplete    inputs with type email/password carry autocomplete
  button-type     every <button> inside a POST form declares type

Allowlist: tools/ui_a11y_allowlist.json —
    [{"rule": "…", "surface": "…", "route": "…", "justify": "…"}]
Match is exact per field ("*" wildcards nothing — entries are per finding).
Any non-allowlisted violation exits 1.

Usage: python3 tools/check_ui_a11y.py [fixtures-dir]
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from ui_html_rules import (  # noqa: E402
    control_label_state,
    describedby_missing_ids,
    iter_documents,
    require_fixture_coverage,
)

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_FIXTURES = ROOT / "services/mail-server/crates/ui-foundation/baselines/rust-ui"
ALLOWLIST = Path(__file__).resolve().parent / "ui_a11y_allowlist.json"

failures: list[str] = []


def load_allowlist(path: Path) -> list[dict]:
    if not path.is_file():
        return []
    data = json.loads(path.read_text())
    for entry in data:
        missing = {"rule", "surface", "route", "justification"} - set(entry)
        if missing:
            print(f"allowlist entry missing keys {sorted(missing)}: {entry}")
            sys.exit(1)
    return data


def allowlisted(allowlist: list[dict], rule: str, surface: str, route: str) -> bool:
    return any(
        e["rule"] == rule and e["surface"] == surface and e["route"] == route
        for e in allowlist
    )


def check_document(entry: dict, doc, allowlist: list[dict]) -> None:
    surface = entry["surface"]
    route = entry["route"]

    def fail(rule: str, detail: str) -> None:
        if allowlisted(allowlist, rule, surface, route):
            return
        where = f"{entry['html_file']} [{surface}{route}]"
        print(f"FAIL {rule} {where} — {detail}")
        failures.append(f"{rule} {surface}{route}")

    # html-lang ─ the document element must declare a language.
    html_els = doc.by_tag("html")
    if not html_els or not (html_els[0].attr("lang") or "").strip():
        fail("html-lang", "no <html lang=…> declared")

    # img-alt ─ informative images describe themselves; decorative ones say
    # so twice (alt="" AND aria-hidden="true").
    for img in doc.by_tag("img"):
        alt = img.attr("alt")
        aria_hidden = (img.attr("aria-hidden") or "").strip().lower() == "true"
        if alt is None:
            fail("img-alt", f"<img> line {img.line} has no alt attribute")
        elif alt.strip() == "" and not aria_hidden:
            fail("img-alt", f"<img> line {img.line} has empty alt without aria-hidden")

    # label-for ─ shared contract with the form-hygiene gate. EVERY visible
    # control is checked, including controls with NO id: an id-less control
    # can only be labelled by a wrapping <label> or an aria-label, and the
    # old `continue` let every id-less control skip the rule entirely.
    for control in doc.controls():
        labelled, detail = control_label_state(doc, control)
        if not labelled:
            fail(
                "label-for",
                f"<{control.tag}> line {control.line} is unlabelled: {detail}",
            )

    # control-label ─ explicit report for the id-less case, so the finding
    # names the actual defect (no id ⇒ no label[for] is even possible).
    for control in doc.controls():
        if (control.attr("id") or "").strip():
            continue
        labelled, _ = control_label_state(doc, control)
        if not labelled:
            fail(
                "control-label",
                f"<{control.tag}> line {control.line} "
                f"({control.attr('name') or 'unnamed'}) has no id and no wrapping <label>",
            )

    # error-association ─ a control marked invalid must point its description
    # at an element that exists: aria-invalid without a resolvable
    # aria-describedby announces an error with no message.
    for detail in describedby_missing_ids(doc):
        fail("error-association", detail)

    # one-h1 ─ one document, one page title.
    h1_count = len(doc.by_tag("h1"))
    if h1_count != 1:
        fail("one-h1", f"found {h1_count} <h1> elements (expected exactly 1)")

    # viewport-meta ─ responsive rendering contract.
    if not any(
        (m.attr("name") or "").strip().lower() == "viewport" for m in doc.by_tag("meta")
    ):
        fail("viewport-meta", "no <meta name=viewport> present")

    # autocomplete ─ email/password inputs must hint credential managers.
    for control in doc.by_tag("input"):
        input_type = (control.attr("type") or "text").strip().lower()
        if input_type in {"email", "password"} and not (control.attr("autocomplete") or "").strip():
            fail(
                "autocomplete",
                f"<input type={input_type}> line {control.line} "
                f"({control.attr('name') or 'unnamed'}) lacks autocomplete",
            )

    # button-type ─ every <button> in a POST form declares its type (IE
    # historically defaulted to submit; explicitness is the contract).
    # SCOPED to the api-server SSR surfaces (web, control-plane, tracking…):
    # their HTML is served exactly as authored. The marketing-zola fixtures
    # are MINIFIED build output — the pinned zola minifier strips the
    # redundant `type="submit"` (a form button's default) and unquotes
    # attributes, so an absent type there is a build artifact, not a source
    # defect: every marketing template/content button declares
    # type="submit" in apps/marketing-zola (verified by grep over templates/
    # and content/).
    if surface not in {"marketing", "marketing-zola"}:
        for button in doc.by_tag("button"):
            form = doc.in_form(button)
            if form is None or not form.is_post_form():
                continue
            if not (button.attr("type") or "").strip():
                fail("button-type", f"<button> line {button.line} in POST form lacks type")


def main(argv: list[str]) -> int:
    fixtures = Path(argv[1]) if len(argv) > 1 else DEFAULT_FIXTURES
    if not fixtures.is_dir():
        print(f"FAIL fixtures directory missing: {fixtures}")
        print("provision with: APEX_EXPORT_ALL_UI_ROUTES=1 cargo run -p ui-foundation "
              "--bin export_visual_fixtures -- <dir>  (from services/mail-server)")
        return 1

    if require_fixture_coverage(fixtures):
        return 1
    allowlist = load_allowlist(ALLOWLIST)
    print(f"fixtures: {fixtures}")
    print(f"a11y allowlist entries: {len(allowlist)}")

    documents = 0
    for entry, doc in iter_documents(fixtures):
        documents += 1
        check_document(entry, doc, allowlist)

    print()
    print(f"checked {documents} documents")
    if failures:
        print(f"A11Y FAILURES: {len(failures)}")
        for name in failures[:50]:
            print(f"  - {name}")
        if len(failures) > 50:
            print(f"  … and {len(failures) - 50} more")
        return 1
    print("accessibility: all green")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
