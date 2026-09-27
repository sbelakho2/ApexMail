#!/usr/bin/env python3
"""Gate D — UI form hygiene gate.

Executable form contract: every `method="post"` form in the exported UI
fixtures (ui-foundation's export_visual_fixtures, APEX_EXPORT_ALL_UI_ROUTES=1)
must satisfy the zero-JavaScript PRG contract:

  1. its `action` resolves to a POST route actually registered by
     api-server's web.rs router blocks (`public_router`, `consent_router`,
     `authenticated_router`, `detail_router`, `admin_router`) — or sits on
     FORM_ACTION_ALLOWLIST (first-party consent route + the marketing API
     console's own explorer endpoints, which never hit api-server);
  2. it carries a `name="_csrf"` hidden input (allowlisted/external actions
     are exempt — api-server's CSRF token does not apply off-party);
  3. every visible <input>/<select>/<textarea> with an `id` is labelled:
     a matching `<label for=…>`, `aria-label` or `aria-labelledby`.

Violations print file:input-name; any violation exits 1. Route extraction
lives in tools/ui_routes.py (shared with the link gate), HTML rules in
tools/ui_html_rules.py (shared with the a11y gate).

Usage: python3 tools/check_ui_form_hygiene.py [fixtures-dir]
       (default: the exporter's in-repo baseline output)
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import ui_routes  # noqa: E402
from ui_html_rules import iter_documents, control_label_state  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_FIXTURES = ROOT / "services/mail-server/crates/ui-foundation/baselines/rust-ui"
WEB_RS = ROOT / "services/mail-server/crates/api-server/src/routes/web.rs"

failures: list[str] = []

# Actions that are legitimate POST targets but are NOT api-server web.rs
# routes: the cookie-consent twin (kept here as belt-and-braces — the
# extractor already sees consent_router) and the marketing API console /
# pricing calculator, which POST to the public explorer API host and are
# gated by deploy/tests, not by api-server's form stack.
FORM_ACTION_ALLOWLIST = {
    "/consent",
    "https://api.apexmail.ee/explorer/exec",
    "https://api.apexmail.ee/explorer/grade",
    "https://api.apexmail.ee/explorer/calculate",
    # real api-server POST route (app.rs nests /v1/contact →
    # routes::contact::router() → .route("/sales", post(contact_sales)));
    # rendered as an absolute production URL from the marketing surface.
    "https://api.apexmail.ee/v1/contact/sales",
}


def main(argv: list[str]) -> int:
    fixtures = Path(argv[1]) if len(argv) > 1 else DEFAULT_FIXTURES
    if not fixtures.is_dir():
        print(f"FAIL fixtures directory missing: {fixtures}")
        print("provision with: APEX_EXPORT_ALL_UI_ROUTES=1 cargo run -p ui-foundation "
              "--bin export_visual_fixtures -- <dir>  (from services/mail-server)")
        return 1

    post_routes = ui_routes.post_routes(WEB_RS.read_text())
    print(f"fixtures: {fixtures}")
    print(f"registered POST routes (web.rs): {len(post_routes)}")

    forms_seen = 0
    controls_seen = 0
    for entry, doc in iter_documents(fixtures):
        surface = entry["surface"]
        route = entry["route"]
        where = f"{entry['html_file']} [{surface}{route}]"
        for form in doc.post_forms():
            forms_seen += 1
            action = (form.attr("action") or "").strip()
            allowed = action in FORM_ACTION_ALLOWLIST or ui_routes.action_matches_any(
                action, post_routes
            )
            if not action:
                print(f"FAIL missing-action {where} form line {form.line}")
                failures.append(f"missing-action {entry['html_file']}:{form.line}")
            elif not allowed:
                print(f"FAIL unregistered-action {where} form line {form.line} — action={action!r}")
                failures.append(f"unregistered-action {action} {entry['html_file']}:{form.line}")
            if action not in FORM_ACTION_ALLOWLIST:
                if not any(
                    c.attr("name") == "_csrf" and c.form_seq == form.form_seq
                    for c in doc.by_tag("input")
                ):
                    print(f"FAIL missing-csrf {where} form line {form.line} — no name=_csrf input")
                    failures.append(f"missing-csrf {entry['html_file']}:{form.line}")
        for control in doc.controls():
            # The labelling contract is scoped to controls that carry an id
            # (a `<label for=…>` can only associate through one). Un-id'd
            # group controls (checkbox families) are gate E's aria concern.
            if not (control.attr("id") or "").strip():
                continue
            controls_seen += 1
            labelled, detail = control_label_state(doc, control)
            if labelled:
                continue
            name = control.attr("name") or control.attr("id") or detail
            print(f"FAIL unlabelled-control {where} "
                  f"<{control.tag} name={name!r}> line {control.line}")
            failures.append(
                f"unlabelled-control {name} {entry['html_file']}:{control.line}"
            )

    print()
    print(f"checked {forms_seen} POST forms / {controls_seen} visible controls")
    if failures:
        print(f"FORM HYGIENE FAILURES: {len(failures)}")
        for name in failures[:50]:
            print(f"  - {name}")
        if len(failures) > 50:
            print(f"  … and {len(failures) - 50} more")
        return 1
    print("form hygiene: all green")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
