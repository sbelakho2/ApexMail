#!/usr/bin/env python3
"""Shared route-table extraction for the UI gates (form hygiene, links).

House style: stdlib only, mirrors tools/check_topology_contracts.py.

Sources:
  * services/mail-server/crates/api-server/src/routes/web.rs — the zero-JS
    PRG form routes. Every `.route("path", post(handler))` (and the
    `.route("path", get(h).post(h2))` twin form) in the PRODUCTION region
    (the file is split at the first `#[cfg(test)]`, exactly like
    check_topology_contracts.py) contributes to the POST route table.
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
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

WEB_RS = ROOT / "services/mail-server/crates/api-server/src/routes/web.rs"
UI_MANIFEST = ROOT / "docs/development/ui-baseline-manifest.json"
TRACKING_CONFIG = ROOT / "services/mail-server/crates/tracking-service/src/config.rs"


def production_source(text: str) -> str:
    """Drop everything from the first `#[cfg(test)]` marker onwards.

    Same contract as check_topology_contracts.py's `APP.split(...)[0]`: test
    fixtures carry deliberately malformed copy and must not gate.
    """
    return text.split("#[cfg(test)]")[0]


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
