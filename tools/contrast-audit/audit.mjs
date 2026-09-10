#!/usr/bin/env node
// ApexMail dark-mode + WCAG 2.1 contrast audit.
//
// Surfaces audited (all read-only, loaded from static fixtures/pages):
//   - web (console)          : full-route fixtures exported by ui-foundation export_visual_fixtures
//   - control-plane          : same fixture export
//   - marketing (zola public): every built HTML page under apps/marketing-zola/public
//
// For every page x theme:
//   (a) DOM walk: effective fg/bg via ancestor background resolution (rgb(var(--token))
//       resolved by getComputedStyle), WCAG ratio, AA normal/large classification,
//       placeholder text, borders (non-text contrast), focus indicators (real Tab presses).
//   (b) Full-page screenshot.
//   (c) Pixel pass: decode the PNG in Node and sample every text finding's bbox to
//       confirm the computed ratio matches rendered reality (catches opacity, blending,
//       gradients, text-over-image that DOM math misses).
//
// Output: reports/violations.json, reports/summary.md, reports/screenshots/
import fs from 'node:fs';
import path from 'node:path';
import http from 'node:http';
import { chromium } from 'playwright';
import { decodePng } from './lib/png.mjs';

const ROOT = path.dirname(new URL(import.meta.url).pathname);
const REPO = path.resolve(ROOT, '../..');
const FIXTURES = path.join(ROOT, 'fixtures');
const MARKETING = path.resolve(REPO, 'apps/marketing-zola/public');
const REPORTS = path.join(ROOT, 'reports');
const SHOTS = path.join(REPORTS, 'screenshots');
const MAX_SHOT_HEIGHT = 16000;
const WORKERS = Number(process.env.AUDIT_WORKERS || 6);
const ONLY = process.env.AUDIT_ONLY || null; // optional "surface:page" substring filter

fs.mkdirSync(SHOTS, { recursive: true });

// ---------------------------------------------------------------- inventory
function buildInventory() {
  const pages = [];
  const manifest = JSON.parse(fs.readFileSync(path.join(FIXTURES, 'manifest.json'), 'utf8'));
  const seen = new Set();
  for (const fx of manifest.fixtures) {
    if (fx.surface !== 'web' && fx.surface !== 'control-plane') continue;
    if (seen.has(fx.htmlFile)) continue;
    seen.add(fx.htmlFile);
    pages.push({
      surface: fx.surface,
      route: fx.route,
      url: `/f/${fx.htmlFile}`,
      stem: fx.htmlFile.replace(/\.html$/, ''),
    });
  }
  const walk = (dir, base = dir) => {
    const out = [];
    for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
      const p = path.join(dir, e.name);
      if (e.isDirectory()) out.push(...walk(p, base));
      else if (e.name.endsWith('.html')) out.push(path.relative(base, p));
    }
    return out;
  };
  for (const rel of walk(MARKETING)) {
    const urlPath = rel.endsWith('index.html')
      ? '/' + rel.slice(0, -'index.html'.length)
      : '/' + rel;
    pages.push({
      surface: 'marketing',
      route: urlPath,
      url: urlPath,
      stem: rel.replace(/(index)?\.html$/, '').replace(/[/\\]/g, '-'),
    });
  }
  return pages;
}

// ---------------------------------------------------------------- server
const MIME = {
  '.html': 'text/html', '.css': 'text/css', '.js': 'text/javascript',
  '.svg': 'image/svg+xml', '.png': 'image/png', '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg',
  '.webp': 'image/webp', '.ico': 'image/x-icon', '.woff2': 'font/woff2',
  '.ttf': 'font/ttf', '.json': 'application/json', '.txt': 'text/plain', '.xml': 'application/xml',
  '.webmanifest': 'application/manifest+json', '.asc': 'text/plain',
};
function startServer() {
  const server = http.createServer((req, res) => {
    try {
      const u = decodeURIComponent(new URL(req.url, 'http://x').pathname);
      let file = null;
      if (u.startsWith('/f/')) {
        const rel = u.slice(3).replace(/\.\./g, '');
        file = path.join(FIXTURES, rel);
        if (!file.startsWith(FIXTURES)) file = null;
      } else {
        const rel = u.slice(1).replace(/\.\./g, '');
        file = path.join(MARKETING, rel);
        if (!file.startsWith(MARKETING)) file = null;
      }
      if (!file || !fs.existsSync(file)) { res.writeHead(404); res.end('nf'); return; }
      if (fs.statSync(file).isDirectory()) file = path.join(file, 'index.html');
      if (!fs.existsSync(file) || !fs.statSync(file).isFile()) { res.writeHead(404); res.end('nf'); return; }
      res.writeHead(200, { 'content-type': MIME[path.extname(file)] || 'application/octet-stream' });
      fs.createReadStream(file).pipe(res);
    } catch {
      res.writeHead(500); res.end('err');
    }
  });
  return new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve({ server, port: server.address().port })));
}

// ---------------------------------------------------------------- in-page collector
const COLLECTOR = `(() => {
  const SKIP = new Set(['script','style','noscript','template','meta','link','title','head','br','iframe','object','area','map','source','track','param']);
  const parseColor = (str) => {
    if (str == null) return null;
    str = String(str).trim();
    if (str === 'transparent') return { r: 0, g: 0, b: 0, a: 0 };
    const m = str.match(/^rgba?\\(([^)]+)\\)$/);
    if (!m) return undefined;
    const parts = m[1].split(/[\\s,\\/]+/).filter(s => s.length).map(Number);
    if (parts.length < 3 || parts.slice(0, 4).some(n => Number.isNaN(n))) return undefined;
    return { r: parts[0], g: parts[1], b: parts[2], a: parts.length > 3 ? parts[3] : 1 };
  };
  const blendOver = (fg, bg) => {
    const a = Math.max(0, Math.min(1, fg.a));
    return { r: Math.round(a * fg.r + (1 - a) * bg.r), g: Math.round(a * fg.g + (1 - a) * bg.g), b: Math.round(a * fg.b + (1 - a) * bg.b) };
  };
  const bgInfo = (el) => {
    const layers = [];
    let node = el, opaque = false, chainOpacity = 1;
    while (node && node.nodeType === 1) {
      const cs = getComputedStyle(node);
      const bg = parseColor(cs.backgroundColor);
      const gradient = cs.backgroundImage && cs.backgroundImage !== 'none';
      const image = /url\\(/.test(cs.backgroundImage || '');
      const op = Number(cs.opacity);
      layers.push({ bg, gradient, image, op });
      if (bg && bg.a >= 0.999 && !gradient && !image) { opaque = true; break; }
      node = node.parentElement;
    }
    // composite bottom-up over the default canvas (white)
    let base = { r: 255, g: 255, b: 255 };
    for (let i = layers.length - 1; i >= 0; i--) {
      const l = layers[i];
      if (l.bg && l.bg.a > 0) base = blendOver({ ...l.bg, a: l.bg.a * (l.op < 1 ? l.op : 1) }, base);
    }
    // opacity chain for fg (up to the opaque bg stop)
    node = el;
    for (const l of layers) { if (l.op < 1) chainOpacity *= l.op; }
    const source = layers.some(l => l.gradient) ? 'gradient' : layers.some(l => l.image) ? 'bg-image' : 'solid';
    return { bg: base, source, chainOpacity, opaqueFound: opaque };
  };
  const cssPath = (el) => {
    const parts = [];
    let n = el;
    while (n && n.nodeType === 1 && n !== document.body && parts.length < 4) {
      let sel = n.tagName.toLowerCase();
      if (n.id) { parts.unshift(sel + '#' + n.id); break; }
      const parent = n.parentElement;
      if (parent) {
        let idx = 1, sib = n, same = 0;
        while ((sib = sib.previousElementSibling)) { if (sib.tagName === n.tagName) idx++; }
        for (const c of parent.children) if (c.tagName === n.tagName) same++;
        if (same > 1) sel += ':nth-of-type(' + idx + ')';
      }
      const cls = Array.from(n.classList).filter(c => !/^__/.test(c)).slice(0, 3).map(c => c.replace(/([^a-zA-Z0-9_-])/g, '\\\\$1')).join('.');
      if (cls) sel += '.' + cls;
      parts.unshift(sel);
      n = n.parentElement;
    }
    return parts.join(' > ');
  };
  const visible = (el, cs) => {
    if (cs.display === 'none' || cs.visibility === 'hidden' || Number(cs.opacity) === 0) return false;
    const r = el.getBoundingClientRect();
    return r.width >= 2 && r.height >= 2;
  };
  // F52: sticky/fixed elements are mis-sampled in full-page captures (the
  // stitched image does not place them at their captured-scroll bbox), so the
  // classifier measures them from dedicated element screenshots instead.
  const isSticky = (el) => {
    let n = el;
    while (n && n.nodeType === 1) {
      const pos = getComputedStyle(n).position;
      if (pos === 'sticky' || pos === 'fixed') return true;
      n = n.parentElement;
    }
    return false;
  };
  const findings = [];
  let nextAuditId = 0;
  const docW = document.documentElement.scrollWidth, docH = document.documentElement.scrollHeight;
  const sx = window.scrollX, sy = window.scrollY;
  const all = document.body.querySelectorAll('*');
  let unparsed = 0, textChecked = 0;
  for (const el of all) {
    const tag = el.tagName.toLowerCase();
    if (SKIP.has(tag)) continue;
    const cs = getComputedStyle(el);
    if (!visible(el, cs)) continue;
    const rect = el.getBoundingClientRect();
    const bbox = [Math.round(rect.left + sx), Math.round(rect.top + sy), Math.round(rect.width), Math.round(rect.height)];
    const info = bgInfo(el);
    const disabled = el.disabled === true || el.getAttribute('aria-disabled') === 'true'
      || !!(el.closest && el.closest('button:disabled, input:disabled, select:disabled, textarea:disabled, [aria-disabled="true"]'));
    const svg = !!el.closest('svg');
    // ---- direct text
    let text = '';
    for (const n of el.childNodes) if (n.nodeType === 3) text += n.nodeValue;
    text = text.replace(/\\s+/g, ' ').trim();
    const colRaw = cs.color;
    const col = parseColor(colRaw);
    if (text.length > 0) {
      if (col === undefined) { unparsed++; }
      else {
        const fgEff = blendOver({ ...col, a: col.a * info.chainOpacity }, info.bg);
        const fontSize = parseFloat(cs.fontSize) || 16;
        const weight = parseInt(cs.fontWeight, 10) || 400;
        const large = fontSize >= 24 || (fontSize >= 18.66 && weight >= 700);
        // F52: a unique data attribute lets the Node side re-locate THIS
        // element for a dedicated element.screenshot() measurement.
        const auditId = nextAuditId++;
        el.setAttribute('data-contrast-audit-id', String(auditId));
        findings.push({
          kind: disabled ? 'text-disabled' : 'text', tag, selector: cssPath(el),
          auditId, sticky: isSticky(el),
          text: text.slice(0, 60), fg: [fgEff.r, fgEff.g, fgEff.b], rawFg: colRaw,
          skipLink: tag === 'a' && (el.getAttribute('href') || '').startsWith('#') && rect.top < 0,
          bg: [info.bg.r, info.bg.g, info.bg.b], bgSource: info.source,
          fontSize: Math.round(fontSize * 10) / 10, fontWeight: weight, large,
          bbox, svg, mono: cs.fontFamily.includes('mono'),
        });
        if (!disabled) textChecked++;
      }
    }
    // ---- placeholder
    const ph = el.getAttribute && el.getAttribute('placeholder');
    if (ph && (tag === 'input' || tag === 'textarea') && !['submit', 'button', 'hidden', 'reset', 'image'].includes(el.type)) {
      const pcs = getComputedStyle(el, '::placeholder');
      const pcol = parseColor(pcs.color);
      if (pcol === undefined) unparsed++;
      else if (!disabled) {
        const fgEff = blendOver({ ...pcol, a: pcol.a * info.chainOpacity }, info.bg);
        const fontSize = parseFloat(pcs.fontSize) || 16;
        const auditId = nextAuditId++;
        el.setAttribute('data-contrast-audit-id', String(auditId));
        findings.push({
          kind: 'placeholder', tag, selector: cssPath(el), text: ph.slice(0, 60),
          auditId, sticky: isSticky(el),
          fg: [fgEff.r, fgEff.g, fgEff.b], rawFg: pcs.color,
          bg: [info.bg.r, info.bg.g, info.bg.b], bgSource: info.source,
          fontSize: Math.round(fontSize * 10) / 10, fontWeight: parseInt(pcs.fontWeight, 10) || 400,
          large: fontSize >= 24 || (fontSize >= 18.66 && (parseInt(pcs.fontWeight, 10) || 400) >= 700),
          bbox, svg: false, mono: false,
        });
      }
    }
    // ---- borders (non-text contrast, WCAG 1.4.11)
    if (tag !== 'svg') {
      for (const side of ['Top', 'Right', 'Bottom', 'Left']) {
        const w = parseFloat(cs['border' + side + 'Width']) || 0;
        if (w < 1) continue;
        const st = cs['border' + side + 'Style'];
        if (!st || st === 'none' || st === 'hidden') continue;
        const bc = parseColor(cs['border' + side + 'Color']);
        if (bc === undefined || bc.a < 0.35) continue;
        const borderEff = blendOver(bc, info.bg);
        findings.push({
          kind: 'border', tag, selector: cssPath(el), text: '',
          fg: [borderEff.r, borderEff.g, borderEff.b], rawFg: cs['border' + side + 'Color'],
          bg: [info.bg.r, info.bg.g, info.bg.b], bgSource: info.source,
          width: w, bbox, svg: false,
        });
        break; // one record per element is enough (colors usually uniform)
      }
    }
  }
  return { findings, unparsed, textChecked, docW, docH };
})()`;

const FOCUS_SNAPSHOT = `(() => {
  const el = document.activeElement;
  if (!el || el === document.body) return null;
  const cs = getComputedStyle(el);
  const path = (() => {
    const parts = []; let n = el;
    while (n && n.nodeType === 1 && n !== document.body && parts.length < 4) {
      let sel = n.tagName.toLowerCase();
      if (n.id) { parts.unshift(sel + '#' + n.id); break; }
      const cls = Array.from(n.classList).filter(c => !/^__/.test(c)).slice(0, 3).join('.');
      if (cls) sel += '.' + cls;
      parts.unshift(sel); n = n.parentElement;
    }
    return parts.join(' > ');
  })();
  const outlineVisible = cs.outlineStyle !== 'none' && parseFloat(cs.outlineWidth) > 0 && parseOutlineAlpha(cs.outlineColor) > 0.3;
  function parseOutlineAlpha(c) {
    const m = /(?:rgba?\\(([^)]+)\\))/.exec(c || '');
    if (!m) return 0;
    const parts = m[1].split(/[\\s,\\/]+/).filter(s => s.length).map(Number);
    return parts.length > 3 ? parts[3] : 1;
  }
  return {
    selector: path,
    tag: el.tagName.toLowerCase(),
    text: (el.textContent || el.value || el.getAttribute('aria-label') || '').replace(/\\s+/g, ' ').trim().slice(0, 40),
    focusVisible: el.matches(':focus-visible'),
    outline: cs.outlineStyle + ' ' + cs.outlineWidth + ' ' + cs.outlineColor,
    outlineVisible,
    boxShadow: (cs.boxShadow && cs.boxShadow !== 'none') ? cs.boxShadow.slice(0, 140) : 'none',
  };
})()`;

// ---------------------------------------------------------------- color math (node)
const lum = (r, g, b) => {
  const f = (v) => { v /= 255; return v <= 0.03928 ? v / 12.92 : Math.pow((v + 0.055) / 1.055, 2.4); };
  return 0.2126 * f(r) + 0.7152 * f(g) + 0.0722 * f(b);
};
const ratio = (a, b) => {
  const l1 = lum(a[0], a[1], a[2]), l2 = lum(b[0], b[1], b[2]);
  const hi = Math.max(l1, l2), lo = Math.min(l1, l2);
  return (hi + 0.05) / (lo + 0.05);
};

// Pixel sampling: recover fg/bg clusters from a bbox of the rendered screenshot.
// `scale` accounts for Chromium downscaling very tall full-page captures.
function pixelRatioOf(img, bbox, scale = 1) {
  const bx = Math.round(bbox[0] * scale), by = Math.round(bbox[1] * scale);
  const bw = Math.round(bbox[2] * scale), bh = Math.round(bbox[3] * scale);
  if (bx < 0 || by < 0 || bx + bw > img.width || by + bh > img.height) return null;
  const stepX = Math.max(1, Math.floor(bw / 48));
  const stepY = Math.max(1, Math.floor(bh / 24));
  const lums = [];
  for (let y = by + Math.floor(stepY / 2); y < by + bh; y += stepY) {
    for (let x = bx + Math.floor(stepX / 2); x < bx + bw; x += stepX) {
      const i = (y * img.width + x) * 4;
      if (img.data[i + 3] < 200) continue;
      lums.push(lum(img.data[i], img.data[i + 1], img.data[i + 2]));
    }
  }
  if (lums.length < 24) return null;
  lums.sort((a, b) => a - b);
  // bg = histogram mode; text = the (minority) pixel cluster on the far side of the mode
  const NB = 64;
  const hist = new Array(NB).fill(0);
  for (const l of lums) hist[Math.min(NB - 1, Math.floor(l * NB))]++;
  let modeIdx = 0;
  for (let i = 1; i < NB; i++) if (hist[i] > hist[modeIdx]) modeIdx = i;
  const bgEst = (modeIdx + 0.5) / NB;
  const half = 1 / (NB * 2);
  const bgCluster = lums.filter((l) => Math.abs(l - bgEst) <= half);
  // text pixels = minority cluster CLEARLY away from the bg (>0.1 luminance).
  // fg = 92nd/8th percentile WITHIN that cluster (near glyph core, above the
  // antialiasing fringe); bg = median of the mode (background) cluster.
  const farDark = lums.filter((l) => l < bgEst - 0.1);
  const farLight = lums.filter((l) => l > bgEst + 0.1);
  let fgSide;
  if (farDark.length && farLight.length) fgSide = farDark.length <= farLight.length ? farDark : farLight;
  else fgSide = farDark.length ? farDark : farLight;
  if (!fgSide || !bgCluster.length) return null; // uniform region — no readable text pixels
  if (fgSide.length < Math.max(4, lums.length * 0.004)) return null;
  const fgLum = fgSide === farLight
    ? fgSide[Math.min(fgSide.length - 1, Math.floor(fgSide.length * 0.92))]
    : fgSide[Math.floor(fgSide.length * 0.08)];
  const bgLum = bgCluster[Math.floor(bgCluster.length / 2)];
  const hi = Math.max(fgLum, bgLum), lo = Math.min(fgLum, bgLum);
  const r = (hi + 0.05) / (lo + 0.05);
  return Math.round(r * 100) / 100;
}

// For gradient/image backgrounds: measure only the BACKGROUND from pixel edge
// strips (top/bottom 12% rows of the bbox, glyph-free in practice) and use the
// exact DOM fg color. Returns the worst (lowest) contrast among edge patches.
function pixelRatioBgOnly(img, bbox, scale, domFg) {
  const bx = Math.round(bbox[0] * scale), by = Math.round(bbox[1] * scale);
  const bw = Math.round(bbox[2] * scale), bh = Math.round(bbox[3] * scale);
  if (bx < 0 || by < 0 || bx + bw > img.width || by + bh > img.height) return null;
  const stripH = Math.max(2, Math.round(bh * 0.12));
  const fgLum = lum(domFg[0], domFg[1], domFg[2]);
  const patches = [];
  const collect = (y0, y1) => {
    const lums = [];
    for (let y = y0; y < y1; y++) for (let x = bx; x < bx + bw; x += Math.max(1, Math.floor(bw / 40))) {
      const i = (y * img.width + x) * 4;
      if (img.data[i + 3] < 200) continue;
      lums.push(lum(img.data[i], img.data[i + 1], img.data[i + 2]));
    }
    if (lums.length >= 6) lums.sort((a, b) => a - b), patches.push(lums[Math.floor(lums.length / 2)]);
  };
  collect(by, by + stripH);
  collect(by + bh - stripH, by + bh);
  if (!patches.length) return null;
  let worst = Infinity;
  for (const bgLum of patches) {
    const hi = Math.max(fgLum, bgLum), lo = Math.min(fgLum, bgLum);
    worst = Math.min(worst, (hi + 0.05) / (lo + 0.05));
  }
  return Math.round(worst * 100) / 100;
}

// ---------------------------------------------------------------- F52: element measurement + shared classifier

// F52: measure one finding from a dedicated ELEMENT-region screenshot. The
// in-page collector tags every text/placeholder element with a unique
// data-contrast-audit-id; the element is scrolled into view and exactly its
// box is captured at deviceScaleFactor 1 — no fullPage stitching, no
// downscale, and correct coordinates for sticky/fixed headers (the
// fullPage-crop bbox for a sticky element points at the wrong rows of the
// stitched image).
//
// Capture protocol (scroll-race hardened): Chromium's scroll anchoring can
// shift the page AFTER scrollIntoViewIfNeeded resolves (observed ±25px while
// measuring many elements back-to-back), which decouples a previously read
// boundingBox from the pixels actually captured. The audit context therefore
// disables overflow-anchor, the element rect is read in-page after a
// two-frame settle (one JS task — no round-trip between settle and read),
// and the capture is dimension-checked against that rect: a capture whose
// size disagrees with the element box is a failed measurement (null), never
// a false contrast verdict.
async function measureFromElement(pg, finding) {
  try {
    const selector = `[data-contrast-audit-id="${finding.auditId}"]`;
    const locator = pg.locator(selector);
    await locator.scrollIntoViewIfNeeded();
    // F52: center the element in the viewport before measuring. A minimal
    // scrollIntoView can park the element at the very bottom/top of the
    // viewport, UNDER a fixed overlay (cookie-consent banner, sticky footer
    // CTA) — the captured pixels would then be the overlay's, producing a
    // false contrast verdict for content that renders correctly. Centering
    // measures the element clear of the fixed chrome.
    await pg.evaluate((sel) => {
      const el = document.querySelector(sel);
      if (!el) return;
      const b = el.getBoundingClientRect();
      const centered = window.scrollY + b.top + b.height / 2 - window.innerHeight / 2;
      window.scrollTo(0, Math.max(0, centered));
    }, selector);
    const rect = await pg.evaluate(async (sel) => {
      const el = document.querySelector(sel);
      if (!el) return null;
      // Let any pending scroll adjustment / layout shift land before the
      // rect is read; the read itself runs in this one JS task.
      await new Promise((r) => requestAnimationFrame(r));
      await new Promise((r) => requestAnimationFrame(r));
      const b = el.getBoundingClientRect();
      if (b.width < 2 || b.height < 2) return null;
      return { left: b.left, top: b.top, width: b.width, height: b.height };
    }, selector);
    if (!rect) return null;
    const shot = await pg.screenshot({
      clip: { x: rect.left, y: rect.top, width: rect.width, height: rect.height },
    });
    const img = decodePng(shot);
    // Dimension check: the capture must be exactly the element box (±2px of
    // rounding). A different size means the clip was taken against a
    // different scroll/layout state — a failed measurement, never a verdict.
    if (Math.abs(img.width - rect.width) > 2 || Math.abs(img.height - rect.height) > 2) {
      return null;
    }
    const bbox = [0, 0, img.width, img.height];
    const pixel = finding.bgSource === 'solid'
      ? pixelRatioOf(img, bbox, 1)
      : pixelRatioBgOnly(img, bbox, 1, finding.fg);
    return { pixel, shot };
  } catch {
    return null;
  }
}

// F52: the ONE classifier used by the real audit AND the self-test fixtures
// (node audit.mjs --self-test) — the gate proves its own classifier each
// run instead of trusting a prior committed report.
//
// Verdict rules (F52 hardening):
//   * gradient/image backgrounds: the RENDERED pixel ratio is authoritative.
//     There is NO fallback-color exemption — a failing measured gradient
//     ratio is a failure even when the DOM ratio against the solid fallback
//     clears AA (an opaque light gradient over a dark fallback is the exact
//     counterexample that used to be downgraded to pixel-suspect).
//   * a gradient that cannot be measured is flagged pixel-suspect with
//     failSource pixel-unmeasured (review), never silently certified by the
//     fallback-color DOM math.
//   * solid backgrounds: DOM computed-style math is authoritative; the
//     pixel sample is an independent confirmation (large shortfalls are
//     flagged pixel-suspect).
async function classifyCollected(pg, collected, opts = {}) {
  const { fullImg = null, scale = 1 } = opts;
  const violations = [];
  const stats = { textAaFail: 0, textAaaOnlyFail: 0, borderFail: 0, pixelSuspect: 0 };
  const borderAgg = new Map();
  const elementCache = new Map();
  const measureElement = async (finding) => {
    if (!elementCache.has(finding.auditId)) {
      elementCache.set(finding.auditId, await measureFromElement(pg, finding));
    }
    return elementCache.get(finding.auditId);
  };

  for (const f of collected.findings) {
    if (f.kind === 'text-disabled') continue;
    const domRatio = Math.round(ratio(f.fg, f.bg) * 100) / 100;
    const aaTh = f.kind === 'border' ? 3 : f.large ? 3 : 4.5;
    const aaaTh = f.kind === 'border' ? 3 : f.large ? 4.5 : 7;
    if (f.kind === 'border') {
      const key = `${f.fg.join(',')}|${f.bg.join(',')}`;
      const agg = borderAgg.get(key) || { ...f, occurrences: 0 };
      agg.occurrences++;
      borderAgg.set(key, agg);
      if (domRatio < 3) stats.borderFail++;
      continue;
    }
    const gradientBg = f.bgSource !== 'solid';
    // F52 sampling strategy: gradient/image backgrounds AND sticky/fixed
    // elements are measured from element screenshots; plain solid in-flow
    // elements keep the fullPage-crop confirmation sample.
    const needsElementShot = gradientBg || f.sticky;
    let effPixel = null;
    let measuredVia = null;
    let elementShot = null;
    if (needsElementShot) {
      const measured = await measureElement(f);
      if (measured) { effPixel = measured.pixel; measuredVia = 'element'; elementShot = measured.shot; }
    } else if (fullImg) {
      effPixel = pixelRatioOf(fullImg, f.bbox, scale);
      measuredVia = 'fullpage';
    }
    f.ratio = domRatio;
    f.pixelRatio = effPixel;
    f.measuredVia = measuredVia;
    const effRatio = gradientBg && effPixel != null ? effPixel : domRatio;
    const domFail = effRatio < aaTh;
    const pixelFail = effPixel != null && effPixel < aaTh;
    let verdict = null, failSource = null;
    if (gradientBg && effPixel == null) {
      verdict = 'pixel-suspect'; failSource = 'pixel-unmeasured'; stats.pixelSuspect++;
    } else if (domFail) {
      verdict = 'fail-aa'; failSource = gradientBg ? 'pixel' : 'dom'; stats.textAaFail++;
    } else if (!gradientBg && pixelFail && effPixel < aaTh - 0.75) {
      verdict = 'pixel-suspect'; failSource = 'pixel'; stats.pixelSuspect++;
    } else if (effRatio < aaaTh) {
      verdict = 'fail-aaa'; stats.textAaaOnlyFail++;
    }
    if (verdict) {
      violations.push({
        ...f,
        threshold: aaTh, aaaThreshold: aaaTh,
        verdict, failSource: failSource || 'aaa',
        pixelConfirmed: effPixel != null && effPixel < aaTh,
        pixelSkipped: effPixel == null,
        elementShot: elementShot || null,
      });
    }
  }
  return { violations, stats, borders: [...borderAgg.values()] };
}

// ---------------------------------------------------------------- audit task
async function auditTask(browser, port, task, results) {
  const { url: pageUrl, theme, surface, route } = task;
  const isMarketing = surface === 'marketing';
  const ctx = await browser.newContext({
    viewport: { width: isMarketing ? 1440 : 1280, height: 900 },
    deviceScaleFactor: 1,
    colorScheme: theme === 'dark' ? 'dark' : 'light',
    reducedMotion: 'reduce',
  });
  // Kill entrance animations (tailwindcss-animate .animate-in fades start at
  // opacity 0 — measuring mid-animation yields phantom fg==bg results).
  await ctx.addInitScript(() => {
    const nuke = () => {
      const s = document.createElement('style');
      s.textContent = '*,*::before,*::after{animation:none!important;transition:none!important;}html,body{overflow-anchor:none!important;}';
      (document.head || document.documentElement).appendChild(s);
    };
    nuke();
    document.addEventListener('DOMContentLoaded', nuke);
  });
  // Serve absolute https://apexmail.ee/... asset URLs from the local marketing dir; abort other externals.
  await ctx.route((u) => { const h = new URL(u).hostname; return h !== '127.0.0.1' && h !== 'localhost' && h !== 'apexmail.ee'; }, (r) => r.abort());
  await ctx.route((u) => new URL(u).hostname === 'apexmail.ee', async (route2) => {
    const p = decodeURIComponent(new URL(route2.request().url()).pathname);
    try {
      const body = fs.readFileSync(path.join(MARKETING, p.slice(1).replace(/\.\./g, '')));
      await route2.fulfill({ body, contentType: MIME[path.extname(p)] || 'application/octet-stream' });
    } catch { await route2.fulfill({ status: 404, body: 'nf' }); }
  });
  const pg = await ctx.newPage();
  const entry = { surface, page: route, theme, error: null, textChecked: 0, unparsed: 0 };
  try {
    await pg.goto(`http://127.0.0.1:${port}${pageUrl}`, { waitUntil: 'load', timeout: 30000 });
    await pg.evaluate(() => document.fonts.ready).catch(() => {});
    if (theme === 'dark-class') {
      await pg.evaluate(() => document.documentElement.classList.add('dark'));
    }
    await pg.waitForTimeout(120);
    const collected = await pg.evaluate(COLLECTOR);
    entry.textChecked = collected.textChecked;
    entry.unparsed = collected.unparsed;

    // focus indicator check: real Tab presses exercise :focus-visible
    const focusFindings = [];
    for (let i = 0; i < 10; i++) {
      await pg.keyboard.press('Tab');
      const snap = await pg.evaluate(FOCUS_SNAPSHOT).catch(() => null);
      if (snap && !focusFindings.some(f => f.selector === snap.selector)) focusFindings.push(snap);
    }

    // screenshot (full page; Chromium may downscale very tall captures)
    const stem = `${surface}--${task.stem}--${theme}`.replace(/[^a-zA-Z0-9._-]+/g, '_');
    const shotPath = path.join(SHOTS, `${stem}.png`);
    await pg.screenshot({ path: shotPath, fullPage: true });
    const img = decodePng(fs.readFileSync(shotPath));
    const vpW = isMarketing ? 1440 : 1280;
    const scale = img.width / vpW;

    // classify + pixel-confirm (F52: the same shared classifier the
    // self-test fixtures exercise; gradient/sticky findings are measured
    // from dedicated element screenshots, and a failing measured gradient
    // ratio is a failure — no fallback-color exemption).
    const classified = await classifyCollected(pg, collected, { fullImg: img, scale });
    const violations = classified.violations.map((v) => {
      if (v.elementShot) {
        const elPath = path.join(SHOTS, `${stem}--el${v.auditId}.png`);
        try { fs.writeFileSync(elPath, v.elementShot); } catch { /* best effort */ }
        return { ...v, elementShot: path.relative(REPORTS, elPath) };
      }
      const { elementShot, ...rest } = v;
      return rest;
    });
    const stats = classified.stats;
    const borderAgg = new Map(classified.borders.map((b) => [`${b.fg.join(',')}|${b.bg.join(',')}`, b]));
    entry.stats = stats;
    entry.violations = violations;
    entry.borders = [...borderAgg.values()];
    entry.focus = focusFindings;
    entry.docH = collected.docH;
    entry.shot = path.relative(REPORTS, shotPath);
    results.push(entry);
    process.stderr.write(`  ok ${surface} ${route} [${theme}] text=${collected.textChecked} aaFail=${stats.textAaFail} pixelSuspect=${stats.pixelSuspect}\\n`);
  } catch (e) {
    entry.error = String(e).slice(0, 300);
    results.push(entry);
    process.stderr.write(`  ERR ${surface} ${route} [${theme}]: ${entry.error}\\n`);
  } finally {
    await ctx.close().catch(() => {});
  }
}

// ---------------------------------------------------------------- self-test (F52)
// `node audit.mjs --self-test` (and automatically before every gate/full
// audit run): the classifier proves ITSELF against known-negative and
// known-positive fixtures each run, instead of trusting a prior committed
// report. Fixtures:
//   (a) NEGATIVE — white text on an OPAQUE WHITE gradient with a BLACK
//       background-color fallback MUST fail. The DOM ratio against the
//       solid fallback is ~21:1 (≥ AA + 1 — the exact input the removed
//       floorGuard downgraded to nonblocking pixel-suspect), while the
//       rendered gradient measures 1:1. A pass here certifies the
//       fallback-color exemption is really gone.
//   (b) POSITIVE — dark text on a light gradient (≥ 4.5 rendered) must
//       produce NO AA failure.
//   (c) STICKY — the same pair inside position:sticky headers in the
//       middle of a tall (~8k px) document: the bad header must still fail
//       AND be measured via the scroll-aware element screenshot (not the
//       fullPage crop whose bbox points at the wrong rows for sticky
//       elements), with the measured ratio reflecting the rendered
//       gradient (≈1:1), never the fallback.
const SELF_TEST_ONLY = process.argv.includes('--self-test');
const SELFTEST_REPORT = path.join(REPORTS, 'self-test.json');

async function runSelfTest(browser) {
  const results = [];
  const check = (name, ok, detail = '') => {
    results.push({ name, ok: !!ok, detail });
    process.stderr.write(`  [self-test] ${ok ? 'ok  ' : 'FAIL'} ${name}${detail ? ' — ' + detail : ''}\n`);
    return !!ok;
  };
  const ctx = await browser.newContext({
    viewport: { width: 1280, height: 900 },
    deviceScaleFactor: 1,
    reducedMotion: 'reduce',
  });
  const pg = await ctx.newPage();
  // Same measurement-environment nuke as auditTask (animations/transitions
  // off, scroll anchoring off) so the self-test exercises the identical
  // capture protocol the real pages get.
  await pg.addInitScript(() => {
    const s = document.createElement('style');
    s.textContent = '*,*::before,*::after{animation:none!important;transition:none!important;}html,body{overflow-anchor:none!important;}';
    (document.head || document.documentElement).appendChild(s);
  });
  try {
    // ---- (a) negative gradient: MUST fail-aa, pixel-confirmed
    await pg.setContent(`<!doctype html><html><head><style>body{margin:0}</style></head><body>
      <div id="neg" style="background-image:linear-gradient(#ffffff,#ffffff);background-color:#000000;color:#ffffff;padding:10px 16px;font-size:16px;">Deliberately unreadable white on white</div>
    </body></html>`, { waitUntil: 'load' });
    let collected = await pg.evaluate(COLLECTOR);
    let cls = await classifyCollected(pg, collected);
    const negFail = cls.violations.filter((v) => v.verdict === 'fail-aa');
    const negFinding = collected.findings.find((f) => f.text && f.text.includes('Deliberately'));
    check('negative fixture produces a fail-aa violation', negFail.length > 0,
      `${negFail.length} fail-aa of ${cls.violations.length} violations`);
    if (negFail.length > 0) {
      const v = negFail[0];
      check('negative fixture is pixel-confirmed', v.pixelConfirmed === true,
        `pixelRatio=${v.pixelRatio} via ${v.measuredVia}`);
      check('negative fixture measured the rendered gradient (≈1:1), not the fallback',
        typeof v.pixelRatio === 'number' && v.pixelRatio < 2, `pixelRatio=${v.pixelRatio}`);
      check('negative fixture is the floorGuard counterexample (DOM fallback ratio ≥ AA+1)',
        v.ratio >= 4.5 + 1, `domRatio=${v.ratio}`);
    }
    check('collector found the negative fixture text', !!negFinding);

    // ---- (b) positive gradient: NO AA failure
    await pg.setContent(`<!doctype html><html><head><style>body{margin:0}</style></head><body>
      <div id="pos" style="background-image:linear-gradient(#ffffff,#e8e8e8);color:#123257;padding:10px 16px;font-size:16px;">Comfortably readable on a gradient</div>
    </body></html>`, { waitUntil: 'load' });
    collected = await pg.evaluate(COLLECTOR);
    cls = await classifyCollected(pg, collected);
    const posFail = cls.violations.filter((v) => v.verdict === 'fail-aa');
    check('positive gradient fixture has zero fail-aa violations', posFail.length === 0,
      `${posFail.length} fail-aa; stats=${JSON.stringify(cls.stats)}`);
    const posFinding = cls.violations.find((v) => v.text && v.text.includes('Comfortably'));
    check('positive gradient was measured at all', !posFinding || typeof posFinding.pixelRatio === 'number',
      posFinding ? `pixelRatio=${posFinding.pixelRatio} via ${posFinding.measuredVia}` : 'no violation recorded (passes clean)');

    // ---- (c) sticky-header sampling correctness on a tall page
    await pg.setContent(`<!doctype html><html><head><style>body{margin:0}</style></head><body>
      <div style="height:6000px"></div>
      <div style="height:600px;background:#f6f6f6">
        <div id="sticky-bad" style="position:sticky;top:0;background-image:linear-gradient(#ffffff,#ffffff);background-color:#000000;color:#ffffff;padding:10px 16px;font-size:16px;">Sticky unreadable</div>
        <div style="height:200px"></div>
        <div id="sticky-good" style="position:sticky;top:48px;background-image:linear-gradient(#ffffff,#e8e8e8);color:#123257;padding:10px 16px;font-size:16px;">Sticky readable</div>
      </div>
      <div style="height:2000px"></div>
    </body></html>`, { waitUntil: 'load' });
    collected = await pg.evaluate(COLLECTOR);
    cls = await classifyCollected(pg, collected);
    const stickyBad = cls.violations.find((v) => v.text && v.text.includes('Sticky unreadable'));
    const stickyGoodFail = cls.violations.find((v) => v.text && v.text.includes('Sticky readable') && v.verdict === 'fail-aa');
    check('sticky bad header fails', !!stickyBad, stickyBad ? `verdict=${stickyBad.verdict} pixelRatio=${stickyBad.pixelRatio}` : 'no violation for the bad sticky header');
    if (stickyBad) {
      check('sticky bad header measured via the element screenshot (scroll-aware sampling)',
        stickyBad.measuredVia === 'element', `measuredVia=${stickyBad.measuredVia}`);
      check('sticky bad header measurement reflects the rendered gradient (≈1:1)',
        typeof stickyBad.pixelRatio === 'number' && stickyBad.pixelRatio < 2, `pixelRatio=${stickyBad.pixelRatio}`);
    }
    check('sticky good header does not fail', !stickyGoodFail, stickyGoodFail ? `verdict=${stickyGoodFail.verdict}` : 'clean');
    const stickyCollected = collected.findings.filter((f) => f.text && f.text.includes('Sticky'));
    check('sticky fixtures are tagged sticky in the collector', stickyCollected.length === 2 && stickyCollected.every((f) => f.sticky === true));

    const ok = results.every((r) => r.ok);
    fs.mkdirSync(REPORTS, { recursive: true });
    fs.writeFileSync(SELFTEST_REPORT, JSON.stringify({
      generated: new Date().toISOString(),
      ok,
      fixtures: ['negative-white-on-white-gradient-must-fail', 'positive-gradient-passes', 'sticky-header-element-sampling'],
      results,
    }, null, 1));
    process.stderr.write(`[self-test] ${ok ? 'PASS' : 'FAIL'} — ${results.filter((r) => r.ok).length}/${results.length} checks (${SELFTEST_REPORT})\n`);
    return { ok, results };
  } finally {
    await ctx.close().catch(() => {});
  }
}

// ---------------------------------------------------------------- gate mode
// `node audit.mjs --gate` (or AUDIT_GATE=1): CI gate over a representative
// subset — every console + control-plane fixture route (all three themes)
// plus a curated top-20 of the marketing pages (both themes). ZERO AA text
// failures allowed; any page load error also fails the gate. Writes
// reports/gate-report.json and exits nonzero on failure.
const GATE = process.argv.includes('--gate') || process.env.AUDIT_GATE === '1';
// Marketing pages chosen to cover every systemic contrast pattern: code
// blocks (zola/giallo), prose tables (th), footer address, skip link, dark
// panels, brand-tinted chips, status notices, compare tables, locales.
const GATE_MARKETING = new Set([
  '/', '/pricing/', '/features/', '/docs/webhooks/', '/docs/sdks/', '/docs/api/',
  '/quickstart/', '/api-explorer/', '/forensic/', '/inbox-placement/',
  '/private-cloud/', '/status/', '/about/', '/architecture/', '/security/',
  '/compare/', '/compare/postmark/', '/secure-email-for-regulated-saas/',
  '/de/', '/404.html',
]);
if (GATE) {
  const REPORTS_DIR = path.join(ROOT, 'reports');
  fs.mkdirSync(REPORTS_DIR, { recursive: true });
  const reportPath = path.join(REPORTS_DIR, 'gate-report.json');
  const failed = [];
  let aaTotal = 0;
  try {
    const pages = buildInventory()
      .filter(p => p.surface !== 'marketing' || GATE_MARKETING.has(p.route));
    const themesFor = (s) => (s === 'marketing' ? ['light', 'dark'] : ['light', 'dark', 'dark-class']);
    const tasks = [];
    for (const p of pages) for (const t of themesFor(p.surface)) tasks.push({ ...p, theme: t });
    process.stderr.write(`[gate] auditing ${pages.length} pages, ${tasks.length} page-theme runs\n`);
    const t0 = Date.now();
    const { server, port } = await startServer();
    const browser = await chromium.launch({ channel: 'chromium' });
    // F52: the gate FIRST proves its own classifier against the negative
    // fixtures (white-on-opaque-white-gradient MUST fail; a good gradient
    // must pass; sticky headers must be measured via element screenshots).
    // A self-test failure fails the gate outright — a gate that cannot
    // classify known inputs cannot certify real pages.
    process.stderr.write('[gate] running the classifier self-test fixtures first\n');
    const selfTest = await runSelfTest(browser);
    if (!selfTest.ok) {
      await browser.close();
      server.close();
      fs.writeFileSync(reportPath, JSON.stringify({ generated: new Date().toISOString(), ok: false, selfTestFailed: true, selfTest: selfTest.results.filter(r => !r.ok) }, null, 1));
      process.stderr.write(`[gate] FAIL — classifier self-test failed (${SELFTEST_REPORT}); real pages were not certified\n`);
      process.exit(1);
    }
    const results = [];
    let idx = 0;
    async function worker() {
      while (idx < tasks.length) {
        const t = tasks[idx++];
        await auditTask(browser, port, t, results, { gate: true });
      }
    }
    await Promise.all(Array.from({ length: WORKERS }, worker));
    await browser.close();
    server.close();
    for (const run of results) {
      if (run.error) { failed.push({ surface: run.surface, page: run.page, theme: run.theme, error: run.error }); continue; }
      const aa = (run.violations || []).filter(v => v.verdict === 'fail-aa');
      aaTotal += aa.reduce((a, v) => a + (v.occurrences || 1), 0);
      if (aa.length) {
        failed.push({
          surface: run.surface, page: run.page, theme: run.theme,
          groups: aa.length,
          occurrences: aa.reduce((a, v) => a + (v.occurrences || 1), 0),
          worst: Math.min(...aa.map(v => v.ratio)),
          examples: aa.slice(0, 3).map(v => `${v.selector} "${(v.text || '').slice(0, 40)}" ${v.fg.join(',')} on ${v.bg.join(',')} @${v.ratio}${v.measuredVia === 'element' ? ` (element-measured ${v.pixelRatio})` : ''}`),
        });
      }
    }
    const seconds = ((Date.now() - t0) / 1000).toFixed(1);
    const ok = failed.length === 0 && aaTotal === 0;
    fs.writeFileSync(reportPath, JSON.stringify({ generated: new Date().toISOString(), ok, selfTestPassed: true, aaFailures: aaTotal, failedRuns: failed.length, seconds: Number(seconds), failed }, null, 1));
    process.stderr.write(`[gate] ${ok ? 'PASS' : 'FAIL'} — AA failures: ${aaTotal} across ${failed.length} runs (${pages.length} pages, ${tasks.length} runs, ${seconds}s)\n`);
    if (!ok) for (const f of failed.slice(0, 20)) process.stderr.write(`[gate]   ${f.surface} ${f.page} [${f.theme}] ${f.groups} groups / ${f.occurrences} occurrences${f.examples && f.examples.length ? ' — e.g. ' + f.examples[0] : ' — ' + (f.error || '')}\n`);
    process.stderr.write(`[gate] report: ${reportPath}\n`);
    process.exit(ok ? 0 : 1);
  } catch (e) {
    console.error('[gate] audit crashed:', e);
    process.exit(1);
  }
}

// ---------------------------------------------------------------- self-test-only mode
if (SELF_TEST_ONLY) {
  try {
    const browser = await chromium.launch({ channel: 'chromium' });
    const selfTest = await runSelfTest(browser);
    await browser.close();
    process.exit(selfTest.ok ? 0 : 1);
  } catch (e) {
    console.error('[self-test] crashed:', e);
    process.exit(1);
  }
}

// ---------------------------------------------------------------- main
(async () => {
  const pages = buildInventory().filter(p => !ONLY || `${p.surface}:${p.route}`.includes(ONLY));
  const themesFor = (s) => (s === 'marketing' ? ['light', 'dark'] : ['light', 'dark', 'dark-class']);
  const tasks = [];
  for (const p of pages) for (const t of themesFor(p.surface)) tasks.push({ ...p, theme: t });
  process.stderr.write(`Auditing ${pages.length} pages, ${tasks.length} page-theme runs\\n`);

  const { server, port } = await startServer();
  const browser = await chromium.launch({ channel: 'chromium' }); // full chromium: supports fullPage capture
  // F52: prove the classifier against the negative fixtures BEFORE
  // auditing real pages — the report is only meaningful if the tool can
  // classify known-bad and known-good inputs correctly.
  const selfTest = await runSelfTest(browser);
  if (!selfTest.ok) {
    await browser.close();
    server.close();
    process.exit(1);
  }
  const results = [];
  let idx = 0;
  async function worker() {
    while (idx < tasks.length) {
      const t = tasks[idx++];
      await auditTask(browser, port, t, results);
    }
  }
  await Promise.all(Array.from({ length: WORKERS }, worker));
  await browser.close();
  server.close();

  // ---- global dedup of text violations across identical (fg,bg,large,kind,tag) per page+theme
  const violations = [];
  for (const run of results) {
    if (!run.violations) continue;
    const map = new Map();
    for (const v of run.violations) {
      const key = [v.kind, v.tag, v.fg.join(','), v.bg.join(','), v.large, v.verdict].join('|');
      const ex = map.get(key);
      if (ex) { ex.occurrences++; if (v.text && ex.text === '') ex.text = v.text; }
      else map.set(key, { ...v, occurrences: 1 });
    }
    for (const v of map.values()) {
      violations.push({
        surface: run.surface, page: run.page, theme: run.theme, kind: v.kind, tag: v.tag,
        selector: v.selector, text: v.text, fg: v.fg, bg: v.bg, bgSource: v.bgSource,
        fontSize: v.fontSize, fontWeight: v.fontWeight, largeText: v.large,
        ratio: v.ratio, pixelRatio: v.pixelRatio, threshold: v.threshold,
        verdict: v.verdict, failSource: v.failSource, pixelConfirmed: v.pixelConfirmed,
        pixelSkipped: v.pixelSkipped, occurrences: v.occurrences, inSvg: v.svg, mono: !!v.mono,
        skipLink: !!v.skipLink,
      });
    }
  }
  // border findings (deduped per run by color pair)
  const borderFindings = [];
  for (const run of results) {
    for (const b of run.borders || []) {
      if (b.ratio >= 3) continue;
      borderFindings.push({
        surface: run.surface, page: run.page, theme: run.theme, selector: b.selector,
        borderColor: b.fg, bg: b.bg, ratio: b.ratio, threshold: 3, occurrences: b.occurrences,
      });
    }
  }
  const focusFindings = [];
  for (const run of results) {
    for (const f of run.focus || []) {
      focusFindings.push({ surface: run.surface, page: run.page, theme: run.theme, ...f });
    }
  }

  const stats = {};
  for (const run of results) {
    const k = `${run.surface}|${run.theme}`;
    stats[k] = stats[k] || { runs: 0, errors: 0, textChecked: 0, textAaFail: 0, textAaaOnlyFail: 0, pixelSuspect: 0 };
    const s = stats[k];
    s.runs++; if (run.error) s.errors++;
    s.textChecked += run.textChecked || 0;
    if (run.stats) { s.textAaFail += run.stats.textAaFail; s.textAaaOnlyFail += run.stats.textAaaOnlyFail; s.pixelSuspect += run.stats.pixelSuspect; }
  }

  const out = {
    meta: {
      generated: new Date().toISOString(),
      tool: 'tools/contrast-audit/audit.mjs',
      method: 'DOM walk (effective fg/bg via computed styles + ancestor alpha compositing) + full-page screenshot + PNG pixel sampling confirmation',
      thresholds: { textAA: 4.5, textLargeAA: 3, textAAA: 7, textLargeAAA: 4.5, nonText: 3 },
      largeText: '>=24px, or >=18.66px at font-weight>=700',
      themes: { web: ['light', 'dark (prefers-color-scheme)', 'dark-class (html.dark explicit-toggle variant)'], marketing: ['light', 'dark (prefers-color-scheme)'] },
      viewport: { web: '1280x900', controlPlane: '1280x900', marketing: '1440x900' },
      screenshotHeightCap: MAX_SHOT_HEIGHT,
      notes: [
        'dark-class exercises the .dark class override layer in ui-foundation globals.css (production console is zero-JS; dark comes from prefers-color-scheme, the .dark layer is the explicit-toggle path).',
        'verdict fail-aa = WCAG 2.1 AA failure (fix required); fail-aaa = passes AA but fails AAA (enhancement); pixel-suspect = DOM math passes but rendered pixels fall >0.75 short of the threshold (possible occlusion/blend — review screenshots).',
        'failSource=pixel on gradient/image backgrounds means the rendered pixels are authoritative; on solid backgrounds DOM computed-style math is authoritative and pixelConfirmed records independent pixel agreement.',
        'Marketing surface fixtures under baselines/rust-ui are byte-identical include_str! copies of apps/marketing-zola/public pages, so the public dir is the single audited source of truth.',
      ],
    },
    stats,
    violations,
    borderFindings,
    focusFindings,
    runs: results.map(r => ({ surface: r.surface, page: r.page, theme: r.theme, error: r.error, textChecked: r.textChecked, docH: r.docH, shot: r.shot })),
  };
  fs.writeFileSync(path.join(REPORTS, 'violations.json'), JSON.stringify(out, null, 1));
  process.stderr.write(`\\nDone: ${violations.length} violation groups, ${borderFindings.length} border findings across ${results.length} runs.\\n`);
  process.stderr.write(`Reports: ${REPORTS}/violations.json\\n`);
})().catch((e) => { console.error(e); process.exit(1); });
