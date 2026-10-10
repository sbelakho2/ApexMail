"""Mechanical surface enumeration — the "wider" core of dogfood-v2.

Sources of truth (parsed, never a hand list):
  * SSR pages: `docs/development/ui-baseline-manifest.json` (web /
    control-plane / marketing / marketing-zola + the /cp aliases it carries);
  * JSON API routes: the api-server router tables — `src/app.rs` mounts
    (nest/merge) joined to each route module's `.route("...", method...)`
    registrations through a local call graph;
  * static asset routes: `.route_service` / `.nest_service` registrations;
  * daemons/workers: `docker-compose.yml` (+ override/prod) services;
  * tables: `services/mail-server/migrations/*.sql` CREATE TABLE / DROP TABLE
    (net), cross-checked against the live DB for schema orphans;
  * env surface: compose environment keys, documented keys
    (docs/deployment/configuration.md) and code `env::var` reads.

Every enumerated surface yields a stable id; the coverage module asserts that
some probe covers each of them (or an allowlist entry justifies it).
"""
from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path

from .config import REPO_ROOT

API_SRC = REPO_ROOT / "services/mail-server/crates/api-server/src"
ROUTES_DIR = API_SRC / "routes"
MIGRATIONS_DIR = REPO_ROOT / "services/mail-server/migrations"
UI_MANIFEST = REPO_ROOT / "docs/development/ui-baseline-manifest.json"
COMPOSE_FILES = [
    REPO_ROOT / "docker-compose.yml",
    REPO_ROOT / "docker-compose.override.yml",
    REPO_ROOT / "docker-compose.prod.yml",
]
CONFIG_DOC = REPO_ROOT / "docs/deployment/configuration.md"


@dataclass
class Surface:
    id: str
    kind: str                    # ssr | api | static | service | table | env
    method: str = ""
    path: str = ""
    host_kind: str = ""          # web | control-plane | marketing
    mount_class: str = ""        # public | authenticated | admin | ssr
    auth_required: bool | None = None
    source: str = ""             # file:line
    meta: dict = field(default_factory=dict)

    def as_dict(self) -> dict:
        return {
            "id": self.id, "kind": self.kind, "method": self.method,
            "path": self.path, "host": self.host_kind, "mount": self.mount_class,
            "auth_required": self.auth_required, "source": self.source,
            "meta": self.meta,
        }


@dataclass
class Ledger:
    surfaces: list[Surface] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def by_kind(self, kind: str) -> list[Surface]:
        return [s for s in self.surfaces if s.kind == kind]

    def counts(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for surface in self.surfaces:
            out[surface.kind] = out.get(surface.kind, 0) + 1
        return out


# ── source stripping (the U-5 trap: never split at the FIRST cfg(test)) ─────

_ITEM_KEYWORDS = (
    "pub(crate) async fn", "pub async fn", "pub(crate) fn", "pub fn",
    "async fn", "fn", "pub mod", "mod", "pub struct", "struct",
    "pub enum", "enum", "pub const", "const", "pub static", "static",
    "pub use", "use", "pub type", "type", "impl",
)

_RAW_STRING = re.compile(r"r(#*)\"")


def mask_rust_literals(source: str) -> str:
    """Return a same-length copy of `source` with the CONTENT of string
    literals, char literals, raw strings and comments blanked to spaces.

    Brace counting over the raw text is wrong (a `{` inside a format string
    or a comment ends the scan early; an unbalanced brace inside a literal
    makes the scan run past the item). Masking in place keeps every byte
    offset identical, so callers can locate structure on the mask and slice
    the ORIGINAL text with the same boundaries.
    """
    out = list(source)
    index = 0
    length = len(source)

    def blank(start: int, end: int) -> None:
        for position in range(start, min(end, length)):
            if out[position] != "\n":
                out[position] = " "

    while index < length:
        char = source[index]
        if char == "/" and index + 1 < length and source[index + 1] == "/":
            end = source.find("\n", index)
            end = length if end == -1 else end
            blank(index, end)
            index = end
            continue
        if char == "/" and index + 1 < length and source[index + 1] == "*":
            depth = 1
            cursor = index + 2
            while cursor < length and depth:
                if source.startswith("/*", cursor):
                    depth += 1
                    cursor += 2
                elif source.startswith("*/", cursor):
                    depth -= 1
                    cursor += 2
                else:
                    cursor += 1
            blank(index, cursor)
            index = cursor
            continue
        if char == '"':
            cursor = index + 1
            while cursor < length:
                if source[cursor] == "\\":
                    cursor += 2
                    continue
                if source[cursor] == '"':
                    cursor += 1
                    break
                cursor += 1
            blank(index, cursor)
            index = cursor
            continue
        if char == "r" and index + 1 < length and source[index + 1] in ('"', "#"):
            raw = _RAW_STRING.match(source, index)
            if raw:
                closing = '"' + raw.group(1)
                end = source.find(closing, raw.end())
                end = length if end == -1 else end + len(closing)
                blank(index, end)
                index = end
                continue
        if char == "'":
            literal = re.match(r"'(?:\\.|[^'\\\n])'", source[index:])
            if literal:
                end = index + literal.end()
                blank(index, end)
                index = end
                continue
        index += 1
    return "".join(out)


def _item_start_after_attributes(masked: str, position: int) -> int | None:
    """The index where the item/statement following a `#[...]` attribute
    begins: skip whitespace and further outer attributes, then read the item
    token at that exact position. Never scans to a later keyword (that
    deleted everything between a mid-function `#[cfg(test)]` statement and
    the next `fn`, corrupting the remaining source)."""
    cursor = position
    while True:
        cursor += re.match(r"\s*", masked[cursor:]).end()
        if cursor < len(masked) and masked.startswith("#[", cursor):
            depth = 0
            probe = cursor
            while probe < len(masked):
                char = masked[probe]
                if char == "[":
                    depth += 1
                elif char == "]":
                    depth -= 1
                    if depth == 0:
                        probe += 1
                        break
                probe += 1
            cursor = probe
            continue
        break
    if cursor >= len(masked):
        return None
    for keyword in _ITEM_KEYWORDS:
        if masked.startswith(keyword, cursor):
            after = masked[cursor + len(keyword):cursor + len(keyword) + 1]
            if not (after.isalnum() or after == "_"):
                return cursor
    # not a keyworded item: an expression statement / macro call (`#[cfg(test)]
    # SNAPSHOT.fetch_add(...);`) — the token itself is the item start.
    if re.match(r"[A-Za-z_]", masked[cursor:]):
        return cursor
    return None


def _item_end(masked: str, start: int) -> int:
    """End index (inclusive) of the item beginning at `start`: the matching
    `}` of its braced body, or the `;` terminating a declaration/statement.
    Semiconductors/braces nested in (), [] or strings (masked) are ignored."""
    depth = 0
    cursor = start
    while cursor < len(masked):
        char = masked[cursor]
        if char in "([":
            depth += 1
        elif char in ")]":
            depth -= 1
        elif char == "{" and depth == 0:
            return _brace_end(masked, cursor)
        elif char == ";" and depth == 0:
            return cursor
        cursor += 1
    return len(masked) - 1


def strip_test_items(source: str) -> str:
    """Remove top-level `#[cfg(test)]` items individually (never a naive
    split-at-first-attribute — the U-5 defect in tools/ui_routes.py).

    Boundaries are located on the literal-masked copy, so braces inside
    strings/comments can neither end a scan early nor run it past the item.
    """
    masked = mask_rust_literals(source)
    spans: list[tuple[int, int]] = []
    cursor = 0
    while True:
        match = re.search(r"#\[cfg\(test\)\]", masked[cursor:])
        if not match:
            break
        start = cursor + match.start()
        attribute_end = cursor + match.end()
        item_start = _item_start_after_attributes(masked, attribute_end)
        if item_start is None:
            cursor = attribute_end
            continue
        end = _item_end(masked, item_start)
        cursor = end + 1
        spans.append((start, cursor))
    if not spans:
        return source
    # Nested spans (a cfg(test) item inside a removed cfg(test) module) must
    # not be applied independently — drop any span contained in an earlier one,
    # otherwise the shifting indices corrupt the text after the outer span.
    spans.sort()
    normalized: list[tuple[int, int]] = []
    for span_start, span_end in spans:
        if normalized and span_start <= normalized[-1][1]:
            normalized[-1] = (normalized[-1][0], max(normalized[-1][1], span_end))
        else:
            normalized.append((span_start, span_end))
    out = source
    for span_start, span_end in reversed(normalized):
        out = out[:span_start] + out[span_end:]
    return out


def _brace_end(text: str, open_index: int) -> int:
    depth = 0
    for index in range(open_index, len(text)):
        char = text[index]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return index
    return len(text) - 1


def _paren_end(text: str, open_index: int) -> int:
    depth = 0
    in_string = False
    escape = False
    for index in range(open_index, len(text)):
        char = text[index]
        if in_string:
            if escape:
                escape = False
            elif char == "\\":
                escape = True
            elif char == '"':
                in_string = False
            continue
        if char == '"':
            in_string = True
        elif char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                return index
    return len(text) - 1


# ── API route parsing ───────────────────────────────────────────────────────

ROUTE_CALL = re.compile(r"\.(route|route_service)\(\s*(\"[^\"]*\"|[A-Z_][A-Z0-9_]*)\s*,")
FUNC_DEF = re.compile(r"\bfn\s+([a-z_0-9]+)\s*(?:<[^>]*>)?\s*\(")
_MOD = r"(?:(?:crate|self)::)?(?:routes|super)::([a-z0-9_:]+)::([a-z0-9_]+)"
NEST_CALL = re.compile(rf"nest\(\s*\"([^\"]+)\"\s*,\s*{_MOD}\s*\(")
MERGE_CALL = re.compile(rf"merge\(\s*{_MOD}\s*\(")
METHOD_RE = re.compile(r"\b(get|post|put|patch|delete|head|options)\s*\(")
ROUTER_LET = re.compile(r"let\s+([a-z_0-9]+)\s*(?::\s*Router\s*<[^>]*>)?\s*=\s*Router::(?:new|default)\s*\(")


def _module_file(modpath: str, base_dir: Path | None = None) -> Path | None:
    """Resolve `a::b` to routes/a/b.rs or routes/a/b/mod.rs.

    When `base_dir` is given the path is resolved relative to it (for
    `super::x` references inside a route module)."""
    segments = modpath.split("::")
    base = (base_dir or ROUTES_DIR).joinpath(*segments)
    for candidate in (base.with_suffix(".rs"), base / "mod.rs"):
        if candidate.exists():
            return candidate
    return None


def _router_spans(source: str) -> list[tuple[str, int, int]]:
    """[(name, start, end)] for every `let <name> = Router::new()…;` chain.

    The chain ends at the first `;` at bracket depth 0 after the constructor,
    so every `.nest`/`.merge` inside it can be attributed to the router it
    configures (admin / authenticated / rate_limited_public)."""
    spans = []
    for match in ROUTER_LET.finditer(source):
        cursor = match.end() - 1          # the '(' of Router::new(
        depth = 0
        end = len(source) - 1
        for index in range(cursor, len(source)):
            char = source[index]
            if char in "([{":
                depth += 1
            elif char in ")]}":
                depth -= 1
            elif char == ";" and depth <= 0:
                end = index
                break
        spans.append((match.group(1), match.start(), end))
    return spans


def _mount_class(spans, position: int) -> str:
    for name, start, end in spans:
        if start <= position <= end:
            if name == "admin":
                return "admin"
            if name == "authenticated":
                return "authenticated"
            return "public"
    return "public"


def parse_app_mounts(app_source: str) -> tuple[dict[str, dict[str, list[tuple[str, str]]]], list[str]]:
    """-> (modpath -> func -> [(prefix, mount_class)]), warnings.

    Each mount occurrence is recorded with its real prefix and the mount class
    of the router chain that performs it; the caller applies a function's OWN
    prefixes to that function's routes only (a module's auxiliary routers are
    never handed another router's prefix)."""
    warnings: list[str] = []
    spans = _router_spans(app_source)
    mounts: dict[str, dict[str, list[tuple[str, str]]]] = {}
    for match in NEST_CALL.finditer(app_source):
        prefix, modpath, func = match.group(1), match.group(2), match.group(3)
        mounts.setdefault(modpath, {}).setdefault(func, []).append(
            (prefix, _mount_class(spans, match.start()))
        )
    for match in MERGE_CALL.finditer(app_source):
        modpath, func = match.group(1), match.group(2)
        mounts.setdefault(modpath, {}).setdefault(func, []).append(
            ("", _mount_class(spans, match.start()))
        )
    return mounts, warnings


def _function_ranges(source: str) -> list[tuple[str, int, int]]:
    """[(fn_name, body_start, body_end)] for every fn in the source."""
    out = []
    for match in FUNC_DEF.finditer(source):
        name = match.group(1)
        brace = source.find("{", match.end())
        if brace == -1:
            continue
        end = _brace_end(source, brace)
        out.append((name, brace, end))
    return out


def _local_calls(body: str, known: set[str]) -> set[str]:
    calls = set()
    for match in re.finditer(r"\b([a-z_0-9]+)\s*\(", body):
        if match.group(1) in known:
            calls.add(match.group(1))
    return calls


def _submodule_mounts(source: str, module_dir: Path) -> list[tuple[str, Path, str, str, str]]:
    """Module-local mounts of OTHER route modules.

    A router file may `.nest("/x", super::y::router())` or
    `.merge(super::y::router())`; the referenced module is part of the same
    mounted surface and must be enumerated with the parent's prefix.
    Returns [(inner_prefix, resolved_path, func, kind, owner_fn)] where kind
    is `nest` (prefix composes) or `merge` (parent prefix only)."""
    out = []
    functions = _function_ranges(source)

    def owner_of(position: int) -> str:
        for name, start, end in functions:
            if start <= position <= end:
                return name
        return ""

    for match in NEST_CALL.finditer(source):
        prefix, modpath, func = match.group(1), match.group(2), match.group(3)
        resolved = _module_file(modpath, base_dir=module_dir)
        if resolved is not None:
            out.append((prefix, resolved, func, "nest", owner_of(match.start())))
    for match in MERGE_CALL.finditer(source):
        modpath, func = match.group(1), match.group(2)
        resolved = _module_file(modpath, base_dir=module_dir)
        if resolved is not None:
            out.append(("", resolved, func, "merge", owner_of(match.start())))
    return out


def parse_route_file(path: Path, mount_map: dict[str, list[tuple[str, str]]]) -> tuple[list[Surface], list[str]]:
    """Parse one route module and emit each route with the prefixes of the
    function that actually owns it (directly mounted, or reachable from a
    mounted builder through the file-local call graph).

    `mount_map`: fn name -> [(prefix, mount_class)] for every mount of this
    module recorded in a parent router (app.rs or another route module).
    """
    warnings: list[str] = []
    try:
        raw = path.read_text()
    except OSError as error:
        return [], [f"unreadable route file {path}: {error}"]
    source = strip_test_items(raw)
    masked = mask_rust_literals(source)
    relative = path.relative_to(REPO_ROOT)
    # function ranges from the MASKED text: braces in strings/comments cannot
    # stretch a body over the next function (which mis-attributed routes).
    functions = _function_ranges(masked)
    known = {name for name, _, _ in functions}
    mounted = {name for name in mount_map if name in known}

    # attribute each `.route` to its enclosing fn, then expand across the
    # file-local call graph so helper routers merged into `router()` count.
    route_positions = []
    for match in ROUTE_CALL.finditer(source):
        route_positions.append((match.start(), match))
    attribution: dict[str, list[tuple[str, str, str]]] = {}
    for position, match in route_positions:
        owner = None
        for name, start, end in functions:
            if start <= position <= end:
                owner = name
                break
        literal = match.group(2)
        if not literal.startswith('"'):
            warnings.append(f"{relative}:{source[:position].count(chr(10)) + 1}: non-literal route path")
            continue
        route_path = literal[1:-1]
        open_paren = match.start() + 1 + len(match.group(1))
        expr = source[match.end():_paren_end(source, open_paren)]
        methods = {m.upper() for m in METHOD_RE.findall(expr)}
        if match.group(1) == "route_service":
            methods |= {"GET", "HEAD"}
        if not methods:
            methods = {"GET"}
        attribution.setdefault(owner or "?", []).append((route_path, ",".join(sorted(methods)), expr))

    # forward call closure from MOUNTED builders only: which mounted fn can
    # reach each fn. (The previous reverse pass started from every fn, so the
    # `owner in owners` test was always true and each function received every
    # prefix in the module — the path-doubling defect.)
    call_graph: dict[str, set[str]] = {}
    for name, start, end in functions:
        call_graph[name] = _local_calls(source[start:end], known)
    roots_for: dict[str, set[str]] = {}
    if mounted:
        stack = list(mounted)
        seen_roots: dict[str, set[str]] = {}
        while stack:
            root = stack.pop()
            reachable = set()
            frontier = [root]
            while frontier:
                current = frontier.pop()
                if current in reachable:
                    continue
                reachable.add(current)
                frontier.extend(call_graph.get(current, ()))
            for fn in reachable:
                seen_roots.setdefault(fn, set()).add(root)
        roots_for = seen_roots

    surfaces: list[Surface] = []
    for owner, routes in attribution.items():
        if not routes:
            continue
        if owner in mount_map:
            pairs = mount_map[owner]
        else:
            roots = roots_for.get(owner, set())
            pairs = [pair for root in sorted(roots) for pair in mount_map.get(root, [])]
        if not pairs:
            if owner != "?" and mounted:
                warnings.append(
                    f"{relative}: fn {owner} declares {len(routes)} route(s) but is not "
                    f"reachable from any mounted router ({sorted(mounted)}) — not enumerated"
                )
            continue
        seen_ids: set[str] = set()
        for route_path, methods_csv, _expr in routes:
            for method in methods_csv.split(","):
                for prefix, mount_class in pairs:
                    full = _join(prefix, route_path)
                    surface_id = f"api:{method} {full}"
                    if surface_id in seen_ids:
                        continue
                    seen_ids.add(surface_id)
                    surfaces.append(
                        Surface(
                            id=surface_id, kind="api", method=method, path=full,
                            host_kind="web", mount_class=mount_class,
                            source=str(relative),
                            meta={"owner": owner, "prefix": prefix},
                        )
                    )
    return surfaces, warnings


def _join(prefix: str, route_path: str) -> str:
    if not prefix:
        return route_path
    if route_path == "/":
        return prefix
    return prefix.rstrip("/") + "/" + route_path.lstrip("/")


def enumerate_api_surfaces() -> tuple[list[Surface], list[str]]:
    app_source = strip_test_items((API_SRC / "app.rs").read_text())
    mounts, warnings = parse_app_mounts(app_source)
    surfaces: list[Surface] = []

    # Expand module-local mounts (`super::x::router()` inside a route module)
    # so sub-routers like routes/admin/audit_search.rs are enumerated with
    # the parent's prefix instead of being silently missed.
    pending: list[tuple[Path, dict[str, list[tuple[str, str]]]]] = []
    for modpath, func_map in sorted(mounts.items()):
        path = _module_file(modpath)
        if path is None:
            warnings.append(f"unresolved module for mount routes::{modpath}")
            continue
        pending.append((path, func_map))
    visited: set[tuple[str, tuple]] = set()
    while pending:
        path, func_map = pending.pop(0)
        key = (str(path), tuple(sorted((f, tuple(sorted(p))) for f, p in func_map.items())))
        if key in visited:
            continue
        visited.add(key)
        module_surfaces, module_warnings = parse_route_file(path, func_map)
        surfaces.extend(module_surfaces)
        warnings.extend(module_warnings)
        try:
            module_source = strip_test_items(path.read_text())
        except OSError:
            continue
        for inner_prefix, inner_path, inner_func, kind, owner in _submodule_mounts(module_source, path.parent):
            # the sub-router inherits the prefixes of the fn that mounts it
            owner_pairs = func_map.get(owner)
            if not owner_pairs:
                owner_pairs = [pair for pairs in func_map.values() for pair in pairs]
            inner_map: dict[str, list[tuple[str, str]]] = {}
            for prefix, mount_class in owner_pairs:
                composed = _join(prefix, inner_prefix) if kind == "nest" else prefix
                inner_map.setdefault(inner_func, []).append((composed, mount_class))
            if inner_map:
                pending.append((inner_path, inner_map))
    warnings.extend(_dedupe(list(warnings)))

    # app.rs-inline routers (absolute paths; assets, grader, placement, stripe)
    app_surfaces: list[Surface] = []
    for match in ROUTE_CALL.finditer(app_source):
        literal = match.group(2)
        if not literal.startswith('"'):
            warnings.append(f"src/app.rs:{app_source[:match.start()].count(chr(10)) + 1}: non-literal route path")
            continue
        route_path = literal[1:-1]
        open_paren = match.start() + 1 + len(match.group(1))
        expr = app_source[match.end():_paren_end(app_source, open_paren)]
        methods = {m.upper() for m in METHOD_RE.findall(expr)}
        is_service = match.group(1) == "route_service"
        if is_service:
            methods |= {"GET", "HEAD"}
        if not methods:
            methods = {"GET"}
        for method in methods:
            app_surfaces.append(
                Surface(
                    id=f"api:{method} {route_path}", kind="api", method=method, path=route_path,
                    host_kind="web", mount_class="public", source="src/app.rs",
                    meta={"owner": "build_app", "prefix": "", "service": is_service},
                )
            )
    surfaces.extend(app_surfaces)

    # mount classes: public router vs authenticated vs admin (from app.rs)
    admin_prefixes = set()
    authenticated_prefixes = set()
    public_prefixes = set()
    spans = _router_spans(app_source)
    for match in NEST_CALL.finditer(app_source):
        prefix = match.group(1)
        mount_class = _mount_class(spans, match.start())
        if mount_class == "admin":
            admin_prefixes.add(prefix)
        elif mount_class == "authenticated":
            authenticated_prefixes.add(prefix)
        else:
            public_prefixes.add(prefix)
    for surface in surfaces:
        for prefix in sorted(admin_prefixes, key=len, reverse=True):
            if surface.path == prefix or surface.path.startswith(prefix.rstrip("/") + "/"):
                surface.mount_class = "admin"
                break
        else:
            for prefix in sorted(authenticated_prefixes, key=len, reverse=True):
                if surface.path == prefix or surface.path.startswith(prefix.rstrip("/") + "/"):
                    surface.mount_class = "authenticated"
                    break
    return surfaces, warnings


# ── SSR surfaces ────────────────────────────────────────────────────────────

def enumerate_ssr_surfaces() -> list[Surface]:
    manifest = json.loads(UI_MANIFEST.read_text())
    surfaces: list[Surface] = []
    for group in manifest["surfaces"]:
        group_id = group["id"]
        for route in group["routes"]:
            path = route["path"]
            surface = Surface(
                id=f"ssr:{group_id}:GET {path}",
                kind="ssr", method="GET", path=path,
                host_kind="web" if group_id == "web" else ("control-plane" if group_id == "control-plane" else "marketing"),
                mount_class="ssr", auth_required=bool(route.get("authRequired")),
                source="docs/development/ui-baseline-manifest.json",
                meta={
                    "surface": group_id, "name": route.get("name"),
                    "category": route.get("category"),
                    "canonical_pattern": route.get("canonicalPattern"),
                },
            )
            surfaces.append(surface)
    return surfaces


# ── compose services ────────────────────────────────────────────────────────

def enumerate_services() -> list[Surface]:
    services: dict[str, dict] = {}
    for compose in COMPOSE_FILES:
        if not compose.exists():
            continue
        text = compose.read_text()
        current = None
        in_services = False
        for line in text.splitlines():
            if re.match(r"^services:\s*$", line):
                in_services = True
                continue
            if in_services and re.match(r"^[a-z]", line):
                in_services = False
                current = None
                continue
            if not in_services:
                continue
            match = re.match(r"^  ([a-z0-9_-]+):\s*$", line)
            if match:
                current = match.group(1)
                services.setdefault(current, {
                    "files": [], "profiles": [], "has_healthcheck": False,
                    "build": False, "image": "",
                })
                services[current]["files"].append(compose.name)
                continue
            if current:
                profile = re.match(r"^    profiles:\s*$", line)
                if profile:
                    services[current]["profiles"] = services[current].get("profiles", [])
                    services[current]["_in_profiles"] = True
                elif services[current].get("_in_profiles") and re.match(r"^      - ", line):
                    services[current]["profiles"].append(line.split("-", 1)[1].strip())
                else:
                    services[current]["_in_profiles"] = False
                if "healthcheck:" in line:
                    services[current]["has_healthcheck"] = True
                if re.match(r"^    build:\s*$", line) or re.match(r"^    build:\s+\S", line):
                    services[current]["build"] = True
                image = re.match(r"^    image:\s*(\S+)", line)
                if image:
                    services[current]["image"] = image.group(1)
        for name in services:
            services[name].pop("_in_profiles", None)
    out = []
    for name, info in sorted(services.items()):
        # topology: prod-only services have no container by design in the dev
        # stack; profile-gated services run only when their profile is active.
        info["topology"] = (
            "prod" if info["files"] and set(info["files"]) == {"docker-compose.prod.yml"}
            else "dev"
        )
        info["image_only"] = bool(info.get("image")) and not info.get("build")
        out.append(
            Surface(
                id=f"svc:{name}", kind="service", source="docker-compose", meta=info,
            )
        )
    return out


# ── tables (schema-orphan detection) ────────────────────────────────────────

CREATE_TABLE_RE = re.compile(
    r"CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?(?:public\.)?\"?([a-z0-9_]+)\"?",
    re.IGNORECASE,
)
DROP_TABLE_RE = re.compile(
    r"DROP\s+TABLE\s+(?:IF\s+EXISTS\s+)?(?:public\.)?\"?([a-z0-9_]+)\"?",
    re.IGNORECASE,
)
PARTITION_OF_RE = re.compile(r"PARTITION\s+OF\s+(?:public\.)?\"?([a-z0-9_]+)\"?", re.IGNORECASE)


def mask_sql_literals(text: str) -> str:
    """Blank SQL comments AND single-quoted strings in ONE positional pass.

    Stripping them in two sequential regex passes corrupts the pairing: a
    comment marker inside a string (`'-- Initial schema: …'`, migration 060's
    down_sql) makes the comment pass delete the string's closing quote, after
    which real DDL text pairs with the wrong quotes and phantom tables appear
    (or real ones vanish). One left-to-right scan handles both correctly.
    Dollar-quoted bodies (`DO $$ … $$`) stay intact: the DDL inside them is
    real (a static CREATE TABLE in a DO block runs).
    """
    out = []
    index = 0
    length = len(text)
    while index < length:
        char = text[index]
        if char == "-" and text.startswith("--", index):
            end = text.find("\n", index)
            end = length if end == -1 else end
            out.append(" " * (end - index))
            index = end
            continue
        if char == "/" and text.startswith("/*", index):
            depth = 1
            cursor = index + 2
            while cursor < length and depth:
                if text.startswith("/*", cursor):
                    depth += 1
                    cursor += 2
                elif text.startswith("*/", cursor):
                    depth -= 1
                    cursor += 2
                else:
                    cursor += 1
            out.append(" " * (cursor - index))
            index = cursor
            continue
        if char == "'":
            cursor = index + 1
            while cursor < length:
                if text[cursor] == "\\":
                    cursor += 2
                    continue
                if text[cursor] == "'":
                    if cursor + 1 < length and text[cursor + 1] == "'":
                        cursor += 2
                        continue
                    cursor += 1
                    break
                cursor += 1
            out.append(" " * (cursor - index))
            index = cursor
            continue
        out.append(char)
        index += 1
    return "".join(out)


def _strip_sql_comments(text: str) -> str:
    return mask_sql_literals(text)


def _strip_sql_strings(text: str) -> str:
    return text


def migration_tables() -> dict[str, list[str]]:
    """Net CREATE/DROP table names across the migration chain, applied in
    migration order (066 drops and recreates `metering_events` as partitioned;
    a global set-difference wrongly reported it missing).

    String literals are blanked first (dynamic `format('CREATE TABLE x_%s')`
    partition builders and NOTICE strings are not static declarations), and a
    name immediately followed by `%` is a format placeholder: skipped.
    """
    created: dict[str, list[str]] = {}
    present: dict[str, list[str]] = {}
    for path in sorted(MIGRATIONS_DIR.glob("*.sql")):
        text = mask_sql_literals(path.read_text(errors="replace"))
        events: list[tuple[int, str, str]] = []
        for pattern in (CREATE_TABLE_RE, PARTITION_OF_RE):
            for match in pattern.finditer(text):
                name = match.group(1)
                if text[match.end():match.end() + 1] == "%":
                    continue                     # dynamic format placeholder
                events.append((match.start(), "create", name))
        for match in DROP_TABLE_RE.finditer(text):
            events.append((match.start(), "drop", match.group(1)))
        # statements execute top-to-bottom: a DROP followed by a CREATE in the
        # same migration (066 recreates metering_events as partitioned) nets a
        # live table, never a phantom removal.
        for _position, kind, name in sorted(events):
            if kind == "create":
                created.setdefault(name, []).append(path.name)
                present[name] = sorted(set(created[name]))
            else:
                present.pop(name, None)
    net = {name: files for name, files in present.items() if name != "_sqlx_migrations"}
    return dict(sorted(net.items()))


def enumerate_tables(planned_tables: dict[str, list[str]]) -> list[Surface]:
    return [
        Surface(
            id=f"table:{name}", kind="table", source=",".join(sorted(set(files))),
            meta={"migrations": sorted(set(files))},
        )
        for name, files in planned_tables.items()
    ]


# ── env surface ─────────────────────────────────────────────────────────────

ENV_KEY_RE = re.compile(r"^\s{4,}([A-Z][A-Z0-9_]{2,}):")
DOC_ENV_RE = re.compile(r"^\|\s*`([A-Z][A-Z0-9_]{2,})`")


def enumerate_env() -> list[Surface]:
    compose_keys: dict[str, set[str]] = {}
    for compose in COMPOSE_FILES:
        if not compose.exists():
            continue
        in_services = False
        service = None
        for line in compose.read_text().splitlines():
            if re.match(r"^services:\s*$", line):
                in_services = True
                continue
            if in_services and re.match(r"^[a-z]", line):
                in_services = False
            if not in_services:
                continue
            smatch = re.match(r"^  ([a-z0-9_-]+):\s*$", line)
            if smatch:
                service = smatch.group(1)
                continue
            kmatch = ENV_KEY_RE.match(line)
            if kmatch and service:
                compose_keys.setdefault(kmatch.group(1), set()).add(service)
    documented: set[str] = set()
    if CONFIG_DOC.exists():
        for line in CONFIG_DOC.read_text(errors="replace").splitlines():
            match = DOC_ENV_RE.match(line)
            if match:
                documented.add(match.group(1))
    code_reads: set[str] = set()
    for root, _dirs, files in os.walk(REPO_ROOT / "services/mail-server/crates"):
        for name in files:
            if not name.endswith(".rs"):
                continue
            try:
                text = (Path(root) / name).read_text(errors="replace")
            except OSError:
                continue
            for match in re.finditer(r'env::var\(\s*"([A-Z][A-Z0-9_]{2,})"', text):
                code_reads.add(match.group(1))

    surfaces: list[Surface] = []
    names = sorted(set(compose_keys) | documented | code_reads)
    for name in names:
        surfaces.append(
            Surface(
                id=f"env:{name}", kind="env", source="compose/docs/code",
                meta={
                    "set_on": sorted(compose_keys.get(name, set())),
                    "documented": name in documented,
                    "code_read": name in code_reads,
                },
            )
        )
    return surfaces


# ── tracking-service surfaces ──────────────────────────────────────────────

TRACKING_CONFIG = REPO_ROOT / "services/mail-server/crates/tracking-service/src/config.rs"


def enumerate_tracking_surfaces() -> list[Surface]:
    """Tracking-service routes from its own router table + config defaults."""
    text = TRACKING_CONFIG.read_text() if TRACKING_CONFIG.exists() else ""
    defaults = {}
    for match in re.finditer(r'var_or\("(TRACKING_[A-Z_]+)",\s*"([^"]+)"\)', text):
        defaults[match.group(1)] = match.group(2)
    pixel = defaults.get("TRACKING_PIXEL_PATH", "/o")
    click = defaults.get("TRACKING_CLICK_PATH", "/c")
    unsub = defaults.get("TRACKING_UNSUBSCRIBE_PATH", "/u")
    prefs = defaults.get("TRACKING_PREFERENCES_PATH", "/p")
    routes = [
        ("GET", f"{pixel}/:tracking_id"), ("GET", "/o.gif"), ("GET", f"{click}/:tracking_id"),
        ("POST", f"{unsub}/:token"), ("GET", f"{unsub}/:token"), ("POST", f"{unsub}/:token/confirm"),
        ("GET", f"{prefs}/:token"), ("POST", f"{prefs}/:token"), ("GET", "/v1/stream"),
        ("GET", "/health"), ("GET", "/ready"),
    ]
    return [
        Surface(
            id=f"trk:{method} {path}", kind="tracking", method=method, path=path,
            host_kind="tracking", mount_class="public",
            source="tracking-service/src/routes/mod.rs + config.rs",
        )
        for method, path in routes
    ]


# ── top level ───────────────────────────────────────────────────────────────

def enumerate() -> Ledger:
    ledger = Ledger()
    api_surfaces, warnings = enumerate_api_surfaces()
    ledger.warnings.extend(warnings)
    ledger.surfaces.extend(api_surfaces)
    ledger.surfaces.extend(enumerate_ssr_surfaces())
    ledger.surfaces.extend(enumerate_services())
    ledger.surfaces.extend(enumerate_tables(migration_tables()))
    ledger.surfaces.extend(enumerate_env())
    ledger.surfaces.extend(enumerate_tracking_surfaces())

    # de-duplicate (same id can arise from multi-mount attribution)
    seen: dict[str, Surface] = {}
    for surface in ledger.surfaces:
        if surface.id not in seen:
            seen[surface.id] = surface
        else:
            existing = seen[surface.id]
            if surface.mount_class == "admin":
                existing.mount_class = "admin"
            elif surface.mount_class == "authenticated" and existing.mount_class != "admin":
                existing.mount_class = "authenticated"
    ledger.surfaces = sorted(seen.values(), key=lambda s: (s.kind, s.id))
    return ledger


def _dedupe(items: list[str]) -> list[str]:
    out = []
    for item in items:
        if item not in out:
            out.append(item)
    return out


if __name__ == "__main__":  # pragma: no cover - manual inspection helper
    ledger = enumerate()
    print(json.dumps(ledger.counts(), indent=2))
    for warning in ledger.warnings[:40]:
        print("WARN", warning)
