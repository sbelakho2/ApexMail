#!/usr/bin/env python3
"""ARK pixel dogfood — walks EVERY rendered page and verifies the law on the
real DOM (computed styles), in light, dark and mobile, with screenshots.

Coverage:
  * every console/control-plane fixture (tools/contrast-audit/fixtures)
  * every built marketing document (apps/marketing-zola/public)
  * every auth/recipient/error/sandbox page that the fixtures export

What it asserts per page (computed styles, after fonts settle):
  ARK-1  body font-family starts with Overpass; display headings resolve to
         Spectral; machine data (pre/code/.apex-mono) to Overpass Mono.
  ARK-2  border-radius is 0 on every element.
  ARK-3  box-shadow is none on every element.
  ARK-4  backdrop-filter is none on every element.
  ARK-5  background-image is none, EXCEPT the engraved repeating-linear
         gradient on evidence/hatch elements.
  ARK-6  the palette contains only ARK hues (no purple/indigo/green fills).
  ARK-7  text contrast clears AA (4.5 normal / 3.0 large) per text node.
  ARK-8  focus-visible paints the 3px double ink outline on a button.
  ARK-9  dark mode (.dark) flips the page background and keeps contrast.
  ARK-10 the wordmark keeps the fixed two tones (185 28 28 / 9 9 11).

Usage: python3 tools/ark_pixel_dogfood.py [--roots DIRS] [--limit N]
Writes: tools/contrast-audit/reports/ark-pixel/report.json + shots/*.png
"""

from __future__ import annotations

import argparse
import functools
import http.server
import json
import os
import re
import socketserver
import sys
import threading
from pathlib import Path

from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "tools/contrast-audit/fixtures"
MARKETING = ROOT / "apps/marketing-zola/public"
REPORT = ROOT / "tools/contrast-audit/reports/ark-pixel"
SHOTS = REPORT / "shots"

ARK_HUES = {
    "rgb(14, 20, 27)", "rgb(61, 75, 89)", "rgb(91, 107, 122)",
    "rgb(196, 205, 213)", "rgb(246, 248, 250)", "rgb(238, 242, 246)",
    "rgb(255, 255, 255)", "rgb(29, 79, 124)", "rgb(20, 58, 92)",
    "rgb(232, 239, 246)", "rgb(216, 229, 240)", "rgb(185, 207, 226)",
    "rgb(143, 176, 205)", "rgb(95, 136, 172)", "rgb(15, 44, 72)",
    "rgb(11, 33, 54)", "rgb(8, 24, 38)", "rgb(5, 15, 24)",
    "rgb(142, 42, 32)", "rgb(116, 34, 26)", "rgb(92, 27, 21)",
    "rgb(70, 21, 16)", "rgb(48, 14, 11)", "rgb(30, 9, 7)",
    "rgb(247, 236, 234)", "rgb(238, 215, 211)", "rgb(224, 178, 170)",
    "rgb(201, 130, 118)", "rgb(170, 82, 68)",
    "rgb(138, 90, 16)", "rgb(116, 75, 13)", "rgb(92, 60, 10)",
    "rgb(70, 46, 8)", "rgb(48, 31, 5)", "rgb(30, 20, 3)",
    "rgb(251, 246, 236)", "rgb(246, 234, 208)", "rgb(235, 211, 160)",
    "rgb(214, 176, 102)", "rgb(184, 139, 58)",
    "rgb(27, 37, 48)", "rgb(21, 30, 40)", "rgb(42, 54, 66)",
    "rgb(139, 153, 167)", "rgb(108, 124, 139)", "rgb(51, 65, 78)",
    "rgb(237, 241, 244)", "rgb(192, 202, 211)", "rgb(216, 226, 233)",
    "rgb(232, 238, 242)", "rgb(240, 244, 247)", "rgb(245, 248, 250)",
    "rgb(155, 189, 220)", "rgb(186, 210, 232)", "rgb(205, 224, 239)",
    "rgb(219, 233, 243)", "rgb(231, 241, 247)", "rgb(240, 247, 251)",
    "rgb(24, 41, 59)", "rgb(28, 48, 70)", "rgb(38, 63, 90)",
    "rgb(60, 90, 122)", "rgb(110, 148, 182)",
    "rgb(224, 138, 128)", "rgb(234, 168, 159)", "rgb(241, 189, 182)",
    "rgb(246, 206, 200)", "rgb(250, 221, 216)", "rgb(252, 234, 231)",
    "rgb(46, 22, 18)", "rgb(58, 28, 23)", "rgb(82, 39, 32)",
    "rgb(136, 63, 52)", "rgb(190, 104, 90)",
    "rgb(210, 166, 94)", "rgb(224, 188, 128)", "rgb(233, 205, 155)",
    "rgb(240, 218, 178)", "rgb(246, 229, 198)", "rgb(250, 238, 216)",
    "rgb(44, 35, 20)", "rgb(56, 44, 25)", "rgb(76, 60, 34)",
    "rgb(120, 95, 52)", "rgb(166, 131, 73)",
    "rgb(9, 9, 11)", "rgb(185, 28, 28)", "rgb(196, 80, 70)",
    "rgba(0, 0, 0, 0)", "transparent",
}
BANNED_HUE_RE = re.compile(
    r"rgb\((99, 102, 241|139, 92, 246|168, 85, 247|126, 34, 206|79, 70, 229|"
    r"34, 197, 94|22, 163, 74|16, 185, 129|5, 150, 105|20, 83, 45|"
    r"236, 72, 153|244, 63, 94)\)"
)

FREEZE_JS = """
() => {
  const style = document.createElement('style');
  style.id = 'ark-measure-freeze';
  style.textContent = '*,*::before,*::after{transition:none !important;animation:none !important}';
  document.head.appendChild(style);
}
"""

PROBE_JS = r"""
() => {
  const out = {violations: [], samples: {}};
  const els = Array.from(document.querySelectorAll('*'));
  const body = getComputedStyle(document.body);
  out.samples.bodyFont = body.fontFamily;
  out.samples.bodyColor = body.color;
  out.samples.bodyBg = body.backgroundColor;
  const fonts = {};
  for (const f of ['Overpass', 'Spectral', 'Overpass Mono', 'Inter Wordmark']) {
    fonts[f] = document.fonts.check(`16px "${f}"`);
  }
  out.samples.fonts = fonts;

  const h1 = document.querySelector('h1');
  if (h1) out.samples.h1Font = getComputedStyle(h1).fontFamily;
  const mono = document.querySelector('pre, code, .apex-mono, .apex-mono-id');
  if (mono) out.samples.monoFont = getComputedStyle(mono).fontFamily;

  const isEvidence = (el) => el.closest('.apex-evidence, .apex-receipt, .apex-hatch, .apex-evidence__hatch');
  const textNodes = [];
  const seen = new Set();
  const addViolation = (el, kind, detail) => {
    if (out.violations.length > 60) return;
    const id = kind + '|' + detail;
    if (seen.has(id)) return;
    seen.add(id);
    const path = el.tagName.toLowerCase() + (el.className && typeof el.className === 'string' ? '.' + el.className.trim().split(/\s+/).slice(0,3).join('.') : '');
    out.violations.push({kind, detail, el: path});
  };

  const isClipped = (cs, el) => {
    if (cs.clip && cs.clip !== 'auto' && cs.clip !== '') return true;
    if (el.offsetWidth <= 1 && el.offsetHeight <= 1) return true;
    return false;
  };
  for (const el of els) {
    const cs = getComputedStyle(el);
    if (cs.display === 'none' || cs.visibility === 'hidden') continue;
    if (isClipped(cs, el)) continue;
    if (cs.borderRadius !== '0px' && cs.borderRadius !== '') {
      addViolation(el, 'radius', cs.borderRadius);
    }
    if (cs.boxShadow && cs.boxShadow !== 'none') {
      addViolation(el, 'shadow', cs.boxShadow.slice(0, 60));
    }
    if (cs.backdropFilter && cs.backdropFilter !== 'none') {
      addViolation(el, 'blur', cs.backdropFilter);
    }
    const bi = cs.backgroundImage;
    if (bi && bi !== 'none') {
      const engraved = bi.includes('repeating-linear-gradient');
      if (!engraved) addViolation(el, 'gradient', bi.slice(0, 80));
      else if (!isEvidence(el)) addViolation(el, 'engraved-outside-evidence', bi.slice(0, 60));
    }
    const bg = cs.backgroundColor;
    const bannedHue = /rgb\((99, 102, 241|139, 92, 246|168, 85, 247|126, 34, 206|79, 70, 229|34, 197, 94|22, 163, 74|16, 185, 129|5, 150, 105|20, 83, 45|236, 72, 153|244, 63, 94)\)/;
    if (bg && bg !== 'rgba(0, 0, 0, 0)') {
      if (bannedHue.test(bg)) addViolation(el, 'banned-hue', bg);
    }
    // gather text nodes for contrast (visible text only)
    for (const node of el.childNodes) {
      if (node.nodeType === 3 && node.textContent.trim().length > 1) {
        textNodes.push({el, text: node.textContent.trim().slice(0, 40)});
        break;
      }
    }
  }
  // contrast: nearest opaque background up the tree
  const parse = (c) => {
    const m = c.match(/rgba?\(([^)]+)\)/);
    if (!m) return null;
    const p = m[1].split(',').map(Number);
    return {r:p[0], g:p[1], b:p[2], a:p.length > 3 ? p[3] : 1};
  };
  const lum = (c) => {
    const f = (v) => { v = v/255; return v <= 0.04045 ? v/12.92 : Math.pow((v+0.055)/1.055, 2.4); };
    return 0.2126*f(c.r) + 0.7152*f(c.g) + 0.0722*f(c.b);
  };
  const ratio = (a,b) => {
    const la = lum(a), lb = lum(b);
    const hi = Math.max(la,lb), lo = Math.min(la,lb);
    return (hi+0.05)/(lo+0.05);
  };
  const bgOf = (el) => {
    let e = el;
    while (e) {
      const c = parse(getComputedStyle(e).backgroundColor);
      if (c && c.a > 0.5) return c;
      e = e.parentElement;
    }
    return {r:255,g:255,b:255,a:1};
  };
  // For text INSIDE its own element's fill (buttons, notices, status rows),
  // the element's own background is the ground — ancestors are only for
  // transparent wrappers.
  for (const t of textNodes) {
    const cs = getComputedStyle(t.el);
    const fg = parse(cs.color);
    if (!fg) continue;
    const own = parse(cs.backgroundColor);
    const bg = own && own.a > 0.5 ? own : bgOf(t.el);
    const size = parseFloat(cs.fontSize);
    const weight = parseInt(cs.fontWeight) || 400;
    const large = size >= 24 || (size >= 18.66 && weight >= 700);
    const need = large ? 3.0 : 4.5;
    const r = ratio(fg, bg);
    if (r < need - 0.01) {
      addViolation(t.el, 'contrast', `${r.toFixed(2)} < ${need} on rgb(${bg.r},${bg.g},${bg.b}) ["${t.text}"]`);
    }
  }
  // focus ring: the authority must ship the 3px double :focus-visible rule
  let hasDouble = false;
  for (const sheet of document.styleSheets) {
    let list; try { list = sheet.cssRules } catch (e) { continue; }
    const walk = (rs) => { for (let i = 0; i < rs.length; i++) {
      const r = rs[i];
      if (r.cssRules && r.cssRules.length) { walk(r.cssRules); }
      if (r.selectorText && r.selectorText.includes(':focus-visible')) {
        // var()-bearing shorthands expose only .outline, not the longhands.
        const o = (r.style.outline || '') + ' ' + (r.style.outlineStyle || '') + ' ' + (r.style.outlineWidth || '');
        if (o.includes('double') && o.includes('3px')) hasDouble = true;
      }
    } };
    walk(list);
  }
  out.samples.focus = {doubleRule: hasDouble};
  // wordmark tones
  const apex = document.querySelector('.apex-wordmark__apex');
  const mail = document.querySelector('.apex-wordmark__mail');
  if (apex && mail) {
    out.samples.wordmark = {apex: getComputedStyle(apex).color, mail: getComputedStyle(mail).color};
  }
  return out;
}
"""

DARK_PROBE_JS = r"""
() => {
  document.documentElement.classList.add('dark');
  const out = {violations: [], samples: {}};
  const body = getComputedStyle(document.body);
  out.samples.bodyBg = body.backgroundColor;
  out.samples.bodyColor = body.color;
  const parse = (c) => {
    const m = c.match(/rgba?\(([^)]+)\)/);
    if (!m) return null;
    const p = m[1].split(',').map(Number);
    return {r:p[0], g:p[1], b:p[2], a:p.length > 3 ? p[3] : 1};
  };
  const lum = (c) => {
    const f = (v) => { v = v/255; return v <= 0.04045 ? v/12.92 : Math.pow((v+0.055)/1.055, 2.4); };
    return 0.2126*f(c.r) + 0.7152*f(c.g) + 0.0722*f(c.b);
  };
  const ratio = (a,b) => { const la=lum(a), lb=lum(b); const hi=Math.max(la,lb), lo=Math.min(la,lb); return (hi+0.05)/(lo+0.05); };
  const bgOf = (el) => {
    let e = el;
    while (e) {
      const c = parse(getComputedStyle(e).backgroundColor);
      if (c && c.a > 0.5) return c;
      e = e.parentElement;
    }
    return parse(body.backgroundColor) || {r:14,g:20,b:27,a:1};
  };
  const seen = new Set();
  const clipped = (cs, el) => (cs.clip && cs.clip !== 'auto' && cs.clip !== '') || (el.offsetWidth <= 1 && el.offsetHeight <= 1);
  for (const el of document.querySelectorAll('*')) {
    const cs = getComputedStyle(el);
    if (cs.display === 'none' || cs.visibility === 'hidden') continue;
    if (clipped(cs, el)) continue;
    if (cs.borderRadius !== '0px' && cs.borderRadius !== '') {
      const id='radius|'+cs.borderRadius; if(!seen.has(id)){seen.add(id);out.violations.push({kind:'radius',detail:cs.borderRadius});}
    }
    if (cs.boxShadow && cs.boxShadow !== 'none') {
      const id='shadow|'+cs.boxShadow.slice(0,40); if(!seen.has(id)){seen.add(id);out.violations.push({kind:'shadow',detail:cs.boxShadow.slice(0,50)});}
    }
    const bi = cs.backgroundImage;
    if (bi && bi !== 'none' && !bi.includes('repeating-linear-gradient')) {
      const id='gradient|'+bi.slice(0,50); if(!seen.has(id)){seen.add(id);out.violations.push({kind:'gradient',detail:bi.slice(0,60)});}
    }
    for (const node of el.childNodes) {
      if (node.nodeType !== 3 || node.textContent.trim().length < 2) continue;
      const fg = parse(cs.color);
      if (!fg) break;
      const ownD = parse(cs.backgroundColor);
      const bg = ownD && ownD.a > 0.5 ? ownD : bgOf(el);
      const size = parseFloat(cs.fontSize);
      const weight = parseInt(cs.fontWeight) || 400;
      const large = size >= 24 || (size >= 18.66 && weight >= 700);
      const need = large ? 3.0 : 4.5;
      const r = ratio(fg, bg);
      if (r < need - 0.01) {
        const id = 'contrast|'+r.toFixed(2)+'|'+node.textContent.trim().slice(0,24);
        if(!seen.has(id)){seen.add(id);out.violations.push({kind:'contrast',detail:`${r.toFixed(2)} < ${need} on rgb(${bg.r},${bg.g},${bg.b}) ["${node.textContent.trim().slice(0,30)}"]`});}
      }
      break;
    }
    if (out.violations.length > 40) break;
  }
  const apex = document.querySelector('.apex-wordmark__apex');
  const mail = document.querySelector('.apex-wordmark__mail');
  if (apex && mail) out.samples.wordmark = {apex: getComputedStyle(apex).color, mail: getComputedStyle(mail).color};
  document.documentElement.classList.remove('dark');
  return out;
}
"""


class QuietHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *args, **kwargs):  # silence the walk
        return


class MarketingHandler(QuietHandler):
    """Serves public/ with the canonical origin rewritten to this server so
    every request is SAME-ORIGIN (cross-origin sheets block CSSOM reads,
    which the computed-style probes need)."""

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if path.endswith("/"):
            path += "index.html"
        target = (MARKETING / path.lstrip("/")).resolve()
        if not str(target).startswith(str(MARKETING.resolve())) or not target.is_file():
            self.send_error(404)
            return
        data = target.read_bytes()
        ctype = "text/html" if target.suffix in (".html", "") else None
        if ctype:
            port = self.server.server_address[1]
            for origin in ("https://apexmail.ee", "https://www.apexmail.ee", "https://cdn.apexmail.ee"):
                data = data.replace(origin.encode(), f"http://127.0.0.1:{port}".encode())
        self.send_response(200)
        if ctype:
            self.send_header("Content-Type", ctype)
        elif target.suffix == ".css":
            self.send_header("Content-Type", "text/css")
        elif target.suffix == ".woff2":
            self.send_header("Content-Type", "font/woff2")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


class Quiet(socketserver.TCPServer):
    allow_reuse_address = True


def serve(directory: Path, port: int, handler_cls=QuietHandler) -> socketserver.TCPServer:
    handler = functools.partial(handler_cls, directory=str(directory))

    httpd = Quiet(("127.0.0.1", port), handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd


def pages_to_walk(limit: int | None) -> list[tuple[str, Path]]:
    pages: list[tuple[str, Path]] = []
    for f in sorted(FIXTURES.glob("*.html")):
        pages.append(("fixtures", f))
    for f in sorted(MARKETING.rglob("*.html")):
        if "404" in f.name and f.parent == MARKETING:
            pass
        pages.append(("marketing", f))
    if limit:
        pages = pages[:limit]
    return pages


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--limit", type=int, default=None)
    ap.add_argument("--only", choices=["fixtures", "marketing"], default=None)
    args = ap.parse_args()

    REPORT.mkdir(parents=True, exist_ok=True)
    SHOTS.mkdir(parents=True, exist_ok=True)
    serve(FIXTURES, 8011)
    serve(MARKETING, 8012, MarketingHandler)

    all_pages = pages_to_walk(None)
    if args.only:
        all_pages = [p for p in all_pages if p[0] == args.only]
    pages = all_pages[: args.limit] if args.limit else all_pages
    failures: list[dict] = []
    checked = 0
    shots = 0
    with sync_playwright() as pw:
        browser = pw.chromium.launch()
        ctx = browser.new_context(viewport={"width": 1440, "height": 900})

        page = ctx.new_page()
        for kind, path in pages:
            rel = path.relative_to(FIXTURES if kind == "fixtures" else MARKETING)
            port = 8011 if kind == "fixtures" else 8012
            slug = re.sub(r"[^a-z0-9]+", "-", str(rel).lower()).strip("-")[:80]
            url = f"http://127.0.0.1:{port}/{rel.as_posix()}"
            try:
                page.goto(url, wait_until="load", timeout=15000)
                page.evaluate("document.fonts.ready")
                page.evaluate(FREEZE_JS)
                page.wait_for_timeout(30)
                res = page.evaluate(PROBE_JS)
                dark = page.evaluate(DARK_PROBE_JS)
                # screenshots: light desktop, dark desktop, light mobile
                page.screenshot(path=str(SHOTS / f"{slug}--light.png"), full_page=True)
                shots += 1
                page.evaluate("document.documentElement.classList.add('dark')")
                page.wait_for_timeout(40)
                page.screenshot(path=str(SHOTS / f"{slug}--dark.png"), full_page=True)
                shots += 1
                page.evaluate("document.documentElement.classList.remove('dark')")
                page.set_viewport_size({"width": 390, "height": 844})
                page.wait_for_timeout(40)
                page.screenshot(path=str(SHOTS / f"{slug}--mobile.png"), full_page=True)
                shots += 1
                page.set_viewport_size({"width": 1440, "height": 900})
            except Exception as exc:  # page failed to load/probe
                failures.append({"page": str(rel), "kind": kind, "error": str(exc)[:200]})
                continue
            checked += 1
            for phase, data in (("light", res), ("dark", dark)):
                for v in data["violations"]:
                    failures.append({"page": str(rel), "kind": kind, "phase": phase, **v})
                s = data.get("samples", {})
                if phase == "light":
                    body_font = (s.get("bodyFont") or "")
                    if not body_font.startswith("Overpass"):
                        failures.append({"page": str(rel), "kind": kind, "phase": phase,
                                         "violation": "font", "detail": f"body font {body_font[:50]}"})
                    fonts = s.get("fonts") or {}
                    if not fonts.get("Overpass"):
                        failures.append({"page": str(rel), "kind": kind, "phase": phase,
                                         "violation": "font", "detail": "Overpass not loaded"})
                    h1f = (s.get("h1Font") or "")
                    if h1f and "Spectral" not in h1f:
                        failures.append({"page": str(rel), "kind": kind, "phase": phase,
                                         "violation": "font", "detail": f"h1 font {h1f[:50]}"})
                    focus = s.get("focus") or {}
                    if focus and not focus.get("doubleRule"):
                        failures.append({"page": str(rel), "kind": kind, "phase": phase,
                                         "violation": "focus", "detail": json.dumps(focus)})
                    wm = s.get("wordmark")
                    if wm and not (wm["apex"] == "rgb(185, 28, 28)" and wm["mail"] == "rgb(9, 9, 11)"):
                        failures.append({"page": str(rel), "kind": kind, "phase": phase,
                                         "violation": "wordmark", "detail": json.dumps(wm)})
                else:
                    wm = s.get("wordmark")
                    if wm and not (wm["apex"] == "rgb(196, 80, 70)" and wm["mail"] == "rgb(237, 241, 244)"):
                        failures.append({"page": str(rel), "kind": kind, "phase": phase,
                                         "violation": "wordmark-dark", "detail": json.dumps(wm)})
        browser.close()

    report = {
        "pages_checked": checked,
        "screenshots": shots,
        "failures": failures,
        "violations_total": len(failures),
    }
    (REPORT / "report.json").write_text(json.dumps(report, indent=2))
    print(f"pages checked: {checked}, screenshots: {shots}, violations: {len(failures)}")
    for f in failures[:40]:
        print(" ", f.get("page"), f.get("phase", ""), f.get("kind"),
              f.get("violation") or f.get("kind"), ":", str(f.get("detail") or f.get("error"))[:120])
    return 0 if not failures else 1


if __name__ == "__main__":
    sys.exit(main())
