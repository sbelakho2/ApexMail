#!/usr/bin/env python3
"""Gate I — UI dead-link gate.

Executable navigation contract: every `href=` / `action=` in the exported
UI fixtures must resolve against ONE of

  (a) the manifest routes of ALL surfaces
      (docs/development/ui-baseline-manifest.json);
  (b) the route table of api-server's web.rs (GET + POST — shared extractor
      with the form-hygiene gate, tools/ui_routes.py);
  (c) tracking-service's path config defaults (/o /c /u /p — parsed from
      crates/tracking-service/src/config.rs);
  (d) the built-in static allowlist: `mailto:`, `#`, `https://` absolutes,
      /assets/, /v1/, /api/, /css, /js, /fonts, /images, /legal/, and the
      exporter's own top-level assets (giallo.css, icon.svg, manifest.json,
      robots.txt, sitemap.xml);
  (e) the built marketing site (apps/marketing-zola/public): a target is
      alive when <path>/, <path>/index.html or <path>.html exists there —
      this is what keeps locale (/de, /fr, /es) and compare pages alive
      without enumerating them. When the built site is absent (fresh
      checkout) existence is assumed and a note is printed; with
      --require-marketing (CI: passed when the marketing build is unavailable)
      an absent site is a failure instead — a green run must not be able to
      mean "the site was never built".
  (f) tools/ui_links_allowlist.txt — reviewed false positives only
      (`path # justification`), one per line.

Dead links print surface:route:target; any dead link exits 1.

Usage: python3 tools/check_ui_links.py [--require-marketing] [fixtures-dir]
"""
from __future__ import annotations

import html
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import ui_routes  # noqa: E402
from ui_html_rules import iter_documents, require_fixture_coverage  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_FIXTURES = ROOT / "services/mail-server/crates/ui-foundation/baselines/rust-ui"
WEB_RS = ROOT / "services/mail-server/crates/api-server/src/routes/web.rs"
MARKETING_PUBLIC = ROOT / "apps/marketing-zola/public"
LINK_ALLOWLIST = Path(__file__).resolve().parent / "ui_links_allowlist.txt"

failures: list[str] = []

STATIC_PREFIXES = (
    "assets/", "v1/", "api/", "css", "js", "fonts", "images", "legal/",
)
EXPORTER_ASSETS = {
    "giallo.css", "icon.svg", "manifest.json", "robots.txt", "sitemap.xml",
}

_HREF_RE = re.compile(
    r'(?:href|action)=("([^"]*)"|\'([^\']*)\'|([^\s">]+))', re.I
)
_ID_SHAPE_RE = re.compile(r"^[a-z]{1,4}_[A-Za-z0-9_-]+$")
_PARAM_RE = re.compile(r":[A-Za-z_][A-Za-z0-9_]*")
_FRAGMENT_RE = re.compile(r'(?:id|name)=("([^"]+)"|\'([^\']+)\'|([^\s">]+))', re.I)


def load_link_allowlist(path: Path) -> dict[str, str]:
    entries: dict[str, str] = {}
    if not path.is_file():
        return entries
    for raw in path.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        target, _, justification = line.partition("#")
        entries[target.strip()] = justification.strip() or "(no justification)"
    return entries


def normalize(target: str) -> str:
    target = html.unescape(target)  # fixtures carry &amp;-escaped hrefs
    path = re.split(r"[?#]", target, maxsplit=1)[0]
    path = path.rstrip("/")
    return path or "/"


def de_id(segment: str) -> str:
    """Collapse concrete resource ids (c_spring, l_vip, t_1) to `<id>`.

    The baseline manifest spells param-shaped routes with a canonical
    concrete id (/campaigns/c_1); fixtures use other instances of the same
    shape (/campaigns/c_spring). Both sides are collapsed before compare.
    """
    return "<id>" if _ID_SHAPE_RE.match(segment) else segment


def shape(path: str) -> str:
    return "/".join(de_id(s) for s in normalize(path).split("/") if s != "")


def pattern_matches(route_pattern: str, path: str) -> bool:
    """Does a concrete path match a parametrized route pattern?

    `/web/admin/ai/drafts/:id/approve` must resolve
    `/web/admin/ai/drafts/draft_dogfood_ui_visual_0001/approve`: the fixture
    carries a REAL id where the route table carries `:id`, and a gate that
    only compares literal strings declares every detail/action form dead.
    """
    pattern = _PARAM_RE.sub("[^/]+", route_pattern.rstrip("/") or "/")
    return re.fullmatch(pattern, path.rstrip("/") or "/") is not None


def document_ids(text: str) -> set[str]:
    ids = set()
    for m in _FRAGMENT_RE.finditer(text):
        value = m.group(2) or m.group(3) or m.group(4) or ""
        if value:
            ids.add(value)
    return ids


class LinkResolver:
    def __init__(self) -> None:
        self.routes = ui_routes.extract_routes(WEB_RS.read_text())
        self.route_paths = {r["path"].rstrip("/") or "/" for r in self.routes}
        self.param_patterns = sorted(p for p in self.route_paths if ":" in p)
        self.manifest = {p.rstrip("/") or "/" for p in ui_routes.manifest_route_paths()}
        self.manifest_shapes = {shape(p) for p in self.manifest}
        self.manifest_patterns = sorted(p for p in self.manifest if ":" in p)
        self.tracking = set(ui_routes.tracking_paths())
        self.marketing_public = MARKETING_PUBLIC if MARKETING_PUBLIC.is_dir() else None

    def marketing_page_exists(self, path: str) -> bool:
        if self.marketing_public is None:
            return True  # no built site: assume alive (exporter used fallbacks)
        base = self.marketing_public
        rel = normalize(path).lstrip("/")
        if not rel:
            return (base / "index.html").is_file()
        return (
            (base / rel / "index.html").is_file()
            or (base / rel).is_file()
            or (base / (rel + ".html")).is_file()
            or (base / rel).is_dir()
        )

    def resolves(self, target: str) -> bool:
        if target.startswith(("mailto:", "#", "https://", "http://", "tel:")):
            return True
        path = normalize(target)
        stripped = path.lstrip("/")
        if any(stripped == p or stripped.startswith(p) for p in STATIC_PREFIXES):
            return True
        if Path(stripped).name in EXPORTER_ASSETS and "/" not in stripped:
            return True
        if path in self.tracking:
            return True
        if path in self.route_paths or path in self.manifest:
            return True
        if shape(path) in self.manifest_shapes:
            return True
        # Parametrized routes: a fixture's concrete id must match the
        # route table's `:param` pattern (both the web.rs table and the
        # manifest spell detail/action routes that way).
        if any(pattern_matches(p, path) for p in self.param_patterns):
            return True
        if any(pattern_matches(p, path) for p in self.manifest_patterns):
            return True
        return self.marketing_page_exists(path)


def main(argv: list[str]) -> int:
    require_marketing = "--require-marketing" in argv
    positional = [a for a in argv[1:] if not a.startswith("--")]
    fixtures = Path(positional[0]) if positional else DEFAULT_FIXTURES
    if not fixtures.is_dir():
        print(f"FAIL fixtures directory missing: {fixtures}")
        print("provision with: APEX_EXPORT_ALL_UI_ROUTES=1 cargo run -p ui-foundation "
              "--bin export_visual_fixtures -- <dir>  (from services/mail-server)")
        return 1

    if require_fixture_coverage(fixtures):
        return 1
    resolver = LinkResolver()
    allowlist = load_link_allowlist(LINK_ALLOWLIST)
    print(f"fixtures: {fixtures}")
    print(f"route sources: {len(resolver.route_paths)} web.rs routes, "
          f"{len(resolver.manifest)} manifest routes, "
          f"tracking paths {sorted(resolver.tracking)}")
    print(f"marketing public: {resolver.marketing_public or 'ABSENT (existence assumed)'}")
    print(f"link allowlist entries: {len(allowlist)}")
    if resolver.marketing_public is None and require_marketing:
        print("FAIL marketing public/ is absent and --require-marketing is set — "
              "the marketing half of the dead-link gate cannot be verified "
              "(build apps/marketing-zola: the zola_gates build produces public/)")
        return 1

    links_seen = 0
    fragments_seen = 0
    for entry, doc in iter_documents(fixtures):
        surface = entry["surface"]
        route = entry["route"]
        ids_in_document = document_ids(doc.text)
        for m in _HREF_RE.finditer(doc.text):
            target = m.group(2) or m.group(3) or m.group(4) or ""
            if not target or target.startswith("data:"):
                continue
            # Escaped example markup (`placeholder="&lt;a href=&quot;…"`) and
            # unresolved template placeholders are documentation, not links.
            if any(token in target for token in ("&quot;", "&lt;", "&gt;", "{{", "}}")):
                continue
            links_seen += 1
            # Fragment validation: a same-document `#frag` must land on an
            # element that actually carries that id/name.
            _, _, fragment = target.partition("#")
            if fragment and not target.startswith(("http://", "https://", "//")):
                fragments_seen += 1
                path_part = target.split("#", 1)[0]
                if not path_part and fragment not in ids_in_document:
                    line = doc.text.count("\n", 0, m.start()) + 1
                    print(f"FAIL dead-fragment {surface}{route} → {target} "
                          f"({entry['html_file']}:{line})")
                    failures.append(f"dead-fragment {surface}{route} → {target}")
                    continue
            if resolver.resolves(target):
                continue
            if target in allowlist or normalize(target) in allowlist:
                continue
            line = doc.text.count("\n", 0, m.start()) + 1
            print(f"FAIL dead-link {surface}{route} → {target} "
                  f"({entry['html_file']}:{line})")
            failures.append(f"dead-link {surface}{route} → {target}")

    print()
    print(f"checked {links_seen} href/action targets, {fragments_seen} fragment targets")
    if failures:
        print(f"DEAD LINK FAILURES: {len(failures)}")
        for name in failures[:50]:
            print(f"  - {name}")
        if len(failures) > 50:
            print(f"  … and {len(failures) - 50} more")
        return 1
    print("ui links: all green")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
