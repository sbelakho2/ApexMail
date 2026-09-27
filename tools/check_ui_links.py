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
      checkout) existence is assumed and a note is printed.
  (f) tools/ui_links_allowlist.txt — reviewed false positives only
      (`path # justification`), one per line.

Dead links print surface:route:target; any dead link exits 1.

Usage: python3 tools/check_ui_links.py [fixtures-dir]
"""
from __future__ import annotations

import html
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import ui_routes  # noqa: E402
from ui_html_rules import iter_documents  # noqa: E402

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

_HREF_RE = re.compile(r'(?:href|action)=("([^"]*)"|([^\s">]+))', re.I)
_ID_SHAPE_RE = re.compile(r"^[a-z]{1,4}_[A-Za-z0-9_-]+$")


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


class LinkResolver:
    def __init__(self) -> None:
        self.routes = ui_routes.extract_routes(WEB_RS.read_text())
        self.route_paths = {r["path"].rstrip("/") or "/" for r in self.routes}
        self.manifest = {p.rstrip("/") or "/" for p in ui_routes.manifest_route_paths()}
        self.manifest_shapes = {shape(p) for p in self.manifest}
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
        return self.marketing_page_exists(path)


def main(argv: list[str]) -> int:
    fixtures = Path(argv[1]) if len(argv) > 1 else DEFAULT_FIXTURES
    if not fixtures.is_dir():
        print(f"FAIL fixtures directory missing: {fixtures}")
        print("provision with: APEX_EXPORT_ALL_UI_ROUTES=1 cargo run -p ui-foundation "
              "--bin export_visual_fixtures -- <dir>  (from services/mail-server)")
        return 1

    resolver = LinkResolver()
    allowlist = load_link_allowlist(LINK_ALLOWLIST)
    print(f"fixtures: {fixtures}")
    print(f"route sources: {len(resolver.route_paths)} web.rs routes, "
          f"{len(resolver.manifest)} manifest routes, "
          f"tracking paths {sorted(resolver.tracking)}")
    print(f"marketing public: {resolver.marketing_public or 'ABSENT (existence assumed)'}")
    print(f"link allowlist entries: {len(allowlist)}")

    links_seen = 0
    for entry, doc in iter_documents(fixtures):
        surface = entry["surface"]
        route = entry["route"]
        for m in _HREF_RE.finditer(doc.text):
            target = m.group(2) if m.group(2) is not None else m.group(3)
            if not target or target.startswith("data:"):
                continue
            links_seen += 1
            if resolver.resolves(target):
                continue
            if target in allowlist or normalize(target) in allowlist:
                continue
            line = doc.text.count("\n", 0, m.start()) + 1
            print(f"FAIL dead-link {surface}{route} → {target} "
                  f"({entry['html_file']}:{line})")
            failures.append(f"dead-link {surface}{route} → {target}")

    print()
    print(f"checked {links_seen} href/action targets")
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
