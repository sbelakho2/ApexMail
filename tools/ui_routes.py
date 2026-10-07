#!/usr/bin/env python3
"""Shared route-table extraction for the UI gates (form hygiene, links).

House style: stdlib only, mirrors tools/check_topology_contracts.py.

Sources:
  * services/mail-server/crates/api-server/src/routes/web.rs — the zero-JS
    PRG form routes. Every `.route("path", post(handler))` (and the
    `.route("path", get(h).post(h2))` twin form) in the PRODUCTION region
    contributes to the POST route table. The production region is computed
    by `ui_flash_extract.production_split()`: top-level `#[cfg(test)]` ITEMS
    are removed individually (brace/comment/string aware) instead of cutting
    the file at the first `#[cfg(test)]` attribute — web.rs carries a
    test-visible alias at line 474 followed by thousands of lines of real
    routes, so the naive split scanned only 473 of 26,265 lines (coverage
    audit U-5). `python3 tools/ui_routes.py --self-test` pins this.
  * docs/development/ui-baseline-manifest.json — every declared route of
    every surface (web / control-plane / marketing / marketing-zola).
  * services/mail-server/crates/tracking-service/src/config.rs — the
    TRACKING_*_PATH env defaults (`/o`, `/c`, `/u`, `/p`), parsed so the
    link gate can never drift from the real configuration.

Consumed by tools/check_ui_form_hygiene.py and tools/check_ui_links.py
(import this module — do not copy the regexes).
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

sys.path.insert(0, str(Path(__file__).resolve().parent))
import ui_flash_extract  # noqa: E402  (same-directory module)

WEB_RS = ROOT / "services/mail-server/crates/api-server/src/routes/web.rs"
UI_MANIFEST = ROOT / "docs/development/ui-baseline-manifest.json"
TRACKING_CONFIG = ROOT / "services/mail-server/crates/tracking-service/src/config.rs"


def _masked_source(text: str) -> str:
    """`text` with comments and string/raw-string literals blanked to spaces.

    Uses ui_flash_extract's masking helpers (comment_spans is string-aware,
    rust_string_literals skips comments) so an attribute-looking token inside
    a comment or literal can never be mistaken for code. Newlines are kept so
    offsets match the original.
    """
    masked = list(text)
    spans = ui_flash_extract.comment_spans(text)
    spans += [(start, end) for start, end, _ in ui_flash_extract.rust_string_literals(text)]
    for start, end in spans:
        for index in range(start, min(end, len(masked))):
            if masked[index] != "\n":
                masked[index] = " "
    return "".join(masked)


def _item_end(masked: str, start: int) -> int:
    """End offset of the item whose `#[cfg(test)]` attribute starts at `start`."""
    n = len(masked)
    i = masked.find("]", start) + 1
    while i < n and masked[i] in " \t\r\n":
        i += 1
    while masked.startswith("#[", i) or masked.startswith("#![", i):
        close = masked.find("]", i)
        if close < 0:
            return n
        i = close + 1
        while i < n and masked[i] in " \t\r\n":
            i += 1
    brace = masked.find("{", i)
    semi = masked.find(";", i)
    if brace != -1 and (semi == -1 or brace < semi):
        depth = 0
        j = brace
        while j < n:
            if masked[j] == "{":
                depth += 1
            elif masked[j] == "}":
                depth -= 1
                if depth == 0:
                    return j + 1
            j += 1
        return n
    return semi + 1 if semi != -1 else n


def production_source(text: str) -> str:
    """Blank every top-level `#[cfg(test)]` item; keep all production code.

    A naive `split("#[cfg(test)]")[0]` cuts at ANY attribute — including a
    top-level test-only alias in the middle of a production file (the U-5
    bug: 473 of 26,265 lines of web.rs scanned) and, symmetrically, an
    attribute-shaped token inside a comment or string literal. This masks
    comments/strings first (ui_flash_extract's helpers), then blanks each
    real top-level cfg(test) item by brace matching. Nested cfg(test)
    attributes stay untouched (they disappear with their enclosing test
    module, which is itself a top-level item).
    """
    masked = _masked_source(text)
    out = list(text)
    # Comment text never registers a route; blank comments in the returned
    # source so a commented-out `.route(...)` cannot pollute the route table.
    # String literals are NOT blanked — the route path itself is a literal.
    for start, end in ui_flash_extract.comment_spans(text):
        for index in range(start, min(end, len(out))):
            if out[index] != "\n":
                out[index] = " "
    depth = 0
    i = 0
    n = len(masked)
    while i < n:
        char = masked[i]
        if char == "{":
            depth += 1
        elif char == "}":
            depth = max(0, depth - 1)
        elif depth == 0 and masked.startswith("#[cfg(test)]", i):
            end = _item_end(masked, i)
            for index in range(i, min(end, n)):
                if out[index] != "\n":
                    out[index] = " "
            i = end
            continue
        i += 1
    return "".join(out)


def _balanced_paren(text: str, open_idx: int) -> int:
    """Index of the paren closing the one at `open_idx`, or -1."""
    depth = 0
    in_str = False
    i = open_idx
    while i < len(text):
        ch = text[i]
        if in_str:
            if ch == "\\":
                i += 2
                continue
            if ch == '"':
                in_str = False
        elif ch == '"':
            in_str = True
        elif ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return -1


_STRING_LIT_RE = re.compile(r'"((?:[^"\\]|\\.)*)"')


def _first_string(inner: str) -> str | None:
    m = _STRING_LIT_RE.search(inner)
    if m is None:
        return None
    return m.group(1)


def extract_routes(web_rs_text: str) -> list[dict]:
    """Every `.route("path", …)` in the production region of web.rs.

    Returns entries {path, post} where `post` is True when a `post(…)`
    handler is registered on the route (the PRG form twins).
    """
    production = production_source(web_rs_text)
    routes: list[dict] = []
    seen: set[str] = set()
    for m in re.finditer(r"\.route\s*\(", production):
        close = _balanced_paren(production, m.end() - 1)
        if close < 0:
            continue
        inner = production[m.end():close]
        path = _first_string(inner)
        if path is None:
            continue
        has_post = re.search(r"\bpost\s*\(", inner) is not None
        if path not in seen:
            seen.add(path)
            routes.append({"path": path, "post": has_post})
        elif has_post:
            for entry in routes:
                if entry["path"] == path:
                    entry["post"] = True
    return routes


def post_routes(web_rs_text: str) -> list[str]:
    """The POST route patterns (`/web/…`, axum `:param` segments intact)."""
    return [r["path"] for r in extract_routes(web_rs_text) if r["post"]]


def action_matches_route(action: str, route: str) -> bool:
    """Does a concrete form action match an axum route pattern?

    `:param` segments match any single non-empty segment, `*rest` matches
    the remainder. Query strings on the action are ignored.
    """
    action_path = action.split("?", 1)[0].split("#", 1)[0]
    a_segs = [s for s in action_path.split("/") if s != ""]
    r_segs = [s for s in route.split("/") if s != ""]
    i = 0
    for i, (a, r) in enumerate(zip(a_segs, r_segs)):
        if r.startswith("*"):
            return True
        if r.startswith(":"):
            continue
        if a != r:
            return False
    if len(a_segs) != len(r_segs):
        # only a trailing wildcard may absorb the difference
        return len(r_segs) > 0 and r_segs[-1].startswith("*") and len(a_segs) > len(r_segs) - 1
    return True


def action_matches_any(action: str, routes: list[str]) -> bool:
    return any(action_matches_route(action, route) for route in routes)


def manifest_route_paths() -> list[str]:
    """Every declared route path across ALL surfaces of the baseline manifest."""
    data = json.loads(UI_MANIFEST.read_text())
    paths: set[str] = set()
    for surface in data.get("surfaces", []):
        for route in surface.get("routes", []):
            path = route.get("path")
            if path:
                paths.add(path)
                pattern = route.get("canonicalPattern")
                if pattern:
                    paths.add(pattern)
    return sorted(paths)


_TRACKING_PATH_RE = re.compile(
    r'var_or\(\s*"TRACKING_(?:PIXEL|CLICK|UNSUBSCRIBE|PREFERENCES)_PATH",\s*&?"([^"]+)"'
)


def tracking_paths(config_text: str | None = None) -> list[str]:
    """tracking-service path config defaults (pixel/click/unsubscribe/prefs)."""
    if config_text is None:
        config_text = TRACKING_CONFIG.read_text()
    production = production_source(config_text)
    return sorted(set(_TRACKING_PATH_RE.findall(production)))


# ── self-test (coverage audit U-5) ───────────────────────────────────────────
# Fixture shape that broke the old implementation: a top-level `#[cfg(test)]`
# alias BEFORE production routes, then the real `#[cfg(test)] mod tests`.
# `#[cfg(test)]` inside comments and string literals must not cut anything.
_SELF_TEST_FIXTURE = r'''
//! Doc comment mentioning #[cfg(test)] and even a `.route("/comment-only", ...)`.
use axum::routing::{get, post};
const S: &str = "#[cfg(test)] .route(\"/string-only\", post(nope))";

#[cfg(test)]
pub(crate) use middleware::guard as web_form_rejection_middleware_for_tests;

pub fn router() -> Router {
    Router::new()
        .route("/web/first", post(first))
        .route("/web/second", post(second))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registers_test_only_route() {
        let _ = Router::new().route("/web/test-only", post(test_only));
    }
}
'''


def self_test() -> int:
    """Can-fail probe for the production-region split.

    Fails on the pre-U-5 implementation: the naive split at the first
    `#[cfg(test)]` drops `/web/second` (and everything after the alias).
    """
    errors: list[str] = []
    production = production_source(_SELF_TEST_FIXTURE)
    routes = [route["path"] for route in extract_routes(_SELF_TEST_FIXTURE)]
    for expected in ("/web/first", "/web/second"):
        if expected not in routes:
            errors.append(f"production route {expected!r} is invisible to the extractor")
    for forbidden in ("/web/test-only", "/comment-only", "/string-only"):
        if forbidden in routes:
            errors.append(f"non-production route {forbidden!r} leaked into the route table")

    # The fixture's post-alias region must actually be scanned: a floor on
    # the production text size, not just route membership.
    if len(production) < len(_SELF_TEST_FIXTURE) // 2:
        errors.append("production region looks truncated (post-alias code removed)")

    # Real file invariant: the precise region is far larger than the naive
    # 473-line prefix, and every naive-region route is still found.
    text = WEB_RS.read_text()
    naive_routes = {
        route["path"]
        for route in extract_routes(text)
        if route["path"] in set(re.findall(r'"([^"]+)"', text.split("#[cfg(test)]")[0]))
    }
    precise_routes = {route["path"] for route in extract_routes(text)}
    missing = sorted(naive_routes - precise_routes)
    if missing:
        errors.append(f"precise extraction lost routes the old prefix found: {missing}")

    if errors:
        for error in errors:
            print(f"SELFTEST FAIL: {error}", file=sys.stderr)
        return 1
    print(
        f"ui_routes self-test passed: fixture routes found "
        f"({len(routes)}), production region {len(production)} chars, "
        f"real web.rs routes {len(precise_routes)}"
    )
    return 0


if __name__ == "__main__":
    if "--self-test" in sys.argv[1:]:
        raise SystemExit(self_test())
    print("ui_routes: import-only module; run with --self-test", file=sys.stderr)
    raise SystemExit(2)
