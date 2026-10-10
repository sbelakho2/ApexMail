"""Marketing surface probes (partition: marketing).

Rendered content markers, internal link integrity (no dead links), SEO/legal
assets, and the price/plan claims on the public pages.
"""
from __future__ import annotations

import re
import xml.etree.ElementTree as ET

from ..assertions import Checks
from ..registry import probe

MAX_LINK_PROBES = 60


@probe("p.marketing.content", "marketing", severity="P2",
       description="Key marketing pages render with their expected content markers")
def content(ctx):
    checks = Checks("p.marketing.content", "marketing-ssr")
    pages = {
        "/": ("ApexMail",),
        "/pricing": ("pricing",),
        "/features": ("feature",),
        "/compare/postmark": ("Postmark",),
        "/terms": ("terms",),
        "/privacy": ("privacy",),
        "/dpa": ("data processing",),
        "/sla": ("sla",),
        "/acceptable-use": ("acceptable",),
        "/data-locations": ("data",),
        "/docs/api": ("api",),
    }
    for path, markers in pages.items():
        resp = ctx.http.get(path, host=ctx.cfg.marketing_host)
        body = (resp.text or "").lower()
        ok = resp.status == 200 and all(marker.lower() in body for marker in markers)
        checks.add(
            f"marketing {path} renders with its content markers",
            ok, observed=f"status={resp.status} len={len(resp.text or '')} markers={markers}",
            expected="200 with the page's subject matter",
            severity="P2", surface=f"ssr:marketing:GET {path}",
        )
    return checks.obs


@probe("p.marketing.dead_links", "marketing", severity="P2",
       description="Internal links on the homepage/pricing/features resolve (no 404s)")
def dead_links(ctx):
    checks = Checks("p.marketing.dead_links", "marketing-links")
    seen: dict[str, int] = {}
    checked = 0
    for start in ("/", "/pricing", "/features"):
        resp = ctx.http.get(start, host=ctx.cfg.marketing_host)
        hrefs = re.findall(r'href="(/[^"#?]*)"', resp.text or "")
        for href in hrefs:
            if href in seen or href.startswith("//"):
                continue
            seen[href] = checked
            if checked >= MAX_LINK_PROBES:
                break
            checked += 1
            target = ctx.http.get(href, host=ctx.cfg.marketing_host)
            if target.status not in (200, 301, 302, 303, 304, 307, 308):
                checks.add(
                    f"internal link {href} (from {start}) resolves",
                    False, observed=f"status={target.status}",
                    expected="200/3xx — a 404 is a dead link",
                    severity="P2", surface=f"ssr:marketing:GET {href}",
                )
        if checked >= MAX_LINK_PROBES:
            break
    checks.add(f"checked {checked} distinct internal links", True,
               observed=f"links={checked}", expected="sampled link integrity sweep",
               surface="marketing-links")
    return checks.obs


@probe("p.marketing.assets_and_legal", "marketing", severity="P2",
       description="robots.txt/sitemap.xml/security.txt/webmanifest are valid and complete")
def assets_and_legal(ctx):
    from ..assertions import env_block_detail, is_env_blocked

    checks = Checks("p.marketing.assets_and_legal", "marketing-assets")
    robots = ctx.http.get("/robots.txt", host=ctx.cfg.marketing_host)
    if is_env_blocked(robots):
        checks.unreachable("robots.txt", env_block_detail(robots), surface="api:GET /robots.txt")
    else:
        checks.add("robots.txt is served and mentions the sitemap",
                   robots.status == 200 and "sitemap" in (robots.text or "").lower(),
                   observed=f"status={robots.status} body={robots.text[:120]!r}",
                   expected="200 with a Sitemap line", severity="P2",
                   surface="api:GET /robots.txt")
    sitemap = ctx.http.get("/sitemap.xml", host=ctx.cfg.marketing_host)
    if is_env_blocked(sitemap):
        checks.unreachable("sitemap.xml", env_block_detail(sitemap), surface="api:GET /sitemap.xml")
    else:
        valid_xml, url_count = False, 0
        try:
            root = ET.fromstring(sitemap.text or "")
            url_count = len(list(root.iter()))
            valid_xml = url_count >= 5
        except Exception:  # noqa: BLE001
            pass
        checks.add("sitemap.xml parses as XML with URL entries",
                   sitemap.status == 200 and valid_xml,
                   observed=f"status={sitemap.status} elements={url_count}",
                   expected="valid sitemap XML", severity="P2", surface="api:GET /sitemap.xml")
    sec = ctx.http.get("/.well-known/security.txt", host=ctx.cfg.marketing_host)
    if is_env_blocked(sec):
        checks.unreachable("security.txt", env_block_detail(sec), surface="api:GET /.well-known/security.txt")
    else:
        body = sec.text or ""
        checks.add("security.txt carries a Contact field",
                   sec.status == 200 and "contact:" in body.lower(),
                   observed=f"status={sec.status} body={body[:160]!r}",
                   expected="RFC 9116 Contact", severity="P2",
                   surface="api:GET /.well-known/security.txt")
    manifest = ctx.http.get("/manifest.json", host=ctx.cfg.marketing_host)
    if is_env_blocked(manifest):
        checks.unreachable("manifest.json", env_block_detail(manifest), surface="api:GET /manifest.json")
    else:
        checks.add("web manifest is served", manifest.status == 200,
                   observed=f"status={manifest.status}", expected="200",
                   surface="api:GET /manifest.json", severity="P3")
    return checks.obs
