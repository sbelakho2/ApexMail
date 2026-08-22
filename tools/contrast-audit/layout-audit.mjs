#!/usr/bin/env node
// ApexMail layout-spill audit.
//
// Surfaces audited (read-only, from the same static fixtures as the contrast
// audit plus the built marketing site):
//   - web (console)          : fixtures exported by ui-foundation export_visual_fixtures
//   - control-plane          : same fixture export
//   - marketing (zola public): every built HTML page under apps/marketing-zola/public
//
// For every page x theme x viewport:
//   1. document horizontal overflow (content wider than the viewport)
//   2. elements extending past the viewport edges (clipped or scroll-forcing)
//   3. in-flow content escaping its visual container card (text spilling out)
//   4. text boxes whose content overflows horizontally with overflow:visible
//      (glyphs render beyond the box and collide with neighbours)
//   5. in-flow solid siblings overlapping each other (stacked/broken grid)
//   6. text-bearing elements rendered at zero size (invisible content)
//   7. broken images (naturalWidth === 0)
//
// Viewports: desktop (1280 / 1440 marketing) and mobile 375.
// Themes: light, dark (prefers-color-scheme), dark-class (html.dark) — the
// dark-class layer only at desktop (it is the explicit-toggle variant).
//
// Output: reports/layout/violations.json, per-flag screenshots under
// reports/layout/screenshots/, and a PASS/FAIL summary (exit 1 on findings
// unless AUDIT_LAYOUT_REPORT_ONLY=1).
import fs from 'node:fs';
import path from 'node:path';
import http from 'node:http';
import { chromium } from 'playwright';

const ROOT = path.dirname(new URL(import.meta.url).pathname);
const REPO = path.resolve(ROOT, '../..');
const FIXTURES = path.join(ROOT, 'fixtures');
const MARKETING = path.resolve(REPO, 'apps/marketing-zola/public');
const OUT = path.join(ROOT, 'reports/layout');
const SHOTS = path.join(OUT, 'screenshots');
const WORKERS = Number(process.env.AUDIT_WORKERS || 6);
const ONLY = process.env.AUDIT_ONLY || null;
const REPORT_ONLY = process.env.AUDIT_LAYOUT_REPORT_ONLY === '1';

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

// ---------------------------------------------------------------- collector
// Runs inside the page. Everything is tolerance-guarded to keep false
// positives near zero; the driver still triages interactively.
const COLLECTOR = `(() => {
  const vw = window.innerWidth;
  const out = [];
  const TEXTUAL = new Set(['script','style','noscript','template','meta','link','title','head','br']);
  const pathOf = (el) => {
    const parts = [];
    let n = el;
    while (n && n.nodeType === 1 && n !== document.body && n !== document.documentElement && parts.length < 5) {
      let sel = n.tagName.toLowerCase();
      if (n.id) { parts.unshift(sel + '#' + n.id); break; }
      const p = n.parentElement;
      if (p) {
        const same = [...p.children].filter(c => c.tagName === n.tagName);
        if (same.length > 1) sel += ':nth-of-type(' + (same.indexOf(n) + 1) + ')';
      }
      parts.unshift(sel);
      n = n.parentElement;
    }
    return 'body>' + parts.join('>');
  };
  const describe = (el, cs, r) => ({
    path: pathOf(el),
    tag: el.tagName.toLowerCase(),
    cls: (el.className && el.className.baseVal !== undefined ? el.className.baseVal : el.className || '').toString().slice(0, 120),
    text: (el.textContent || '').trim().replace(/\\s+/g, ' ').slice(0, 90),
    rect: { x: Math.round(r.x), y: Math.round(r.y), w: Math.round(r.width), h: Math.round(r.height) },
    overflowX: cs.overflowX, overflowY: cs.overflowY,
    position: cs.position,
  });
  const push = (kind, el, cs, r, extra) => out.push({ kind, ...describe(el, cs, r), ...extra });

  // -- broken images
  for (const img of document.images) {
    if (img.complete && img.naturalWidth === 0) {
      const cs = getComputedStyle(img);
      push('broken-image', img, cs, img.getBoundingClientRect(), { src: (img.getAttribute('src') || '').slice(0, 120) });
    }
  }

  const all = [...document.querySelectorAll('*')];
  const info = new Map();
  for (const el of all) {
    if (TEXTUAL.has(el.tagName.toLowerCase())) continue;
    const cs = getComputedStyle(el);
    if (cs.display === 'none' || cs.visibility === 'hidden') continue;
    if ((el.getAttribute('class') || '').includes('sr-only')) continue;
    // closed <details> content is unrendered by definition
    if (el.closest('details:not([open])')) continue;
    const r = el.getBoundingClientRect();
    if (r.width === 0 && r.height === 0) continue;
    const ownText = [...el.childNodes].some(n => n.nodeType === 3 && n.textContent.trim().length > 0);
    info.set(el, { cs, r, ownText, inFlow: cs.position === 'static' || cs.position === 'relative' });
  }

  // -- zero-size text (invisible content)
  for (const [el, { cs, r, ownText }] of info) {
    if (!ownText) continue;
    if ((el.getAttribute('aria-hidden') || '') === 'true') continue;
    if (r.width < 2 || r.height < 2) push('invisible-text', el, cs, r, {});
  }

  // -- document horizontal overflow
  const doc = document.documentElement;
  const docSpill = doc.scrollWidth - doc.clientWidth;

  // scroll-container lookup: content that overflows inside overflow:auto/scroll
  // ancestors is contained by design (scrollable tables, code blocks)
  const insideScrollContainer = (el) => {
    let n = el.parentElement;
    while (n && n.nodeType === 1 && n !== document.body) {
      const s = info.get(n) ? info.get(n).cs : getComputedStyle(n);
      if (s.overflowX === 'auto' || s.overflowX === 'scroll' || s.overflowY === 'auto' || s.overflowY === 'scroll') return true;
      n = n.parentElement;
    }
    return false;
  };

  // -- per-element checks
  for (const [el, { cs, r, ownText, inFlow }] of info) {
    const textual = ownText || el.tagName === 'IMG' || el.tagName === 'SVG';
    // elements past the viewport edges — only real content, never the
    // overflow a scroll container is designed to absorb
    if (textual && inFlow && !insideScrollContainer(el) && (r.right > vw + 1.5 || r.left < -1.5)) {
      push('past-viewport', el, cs, r, { byRight: Math.round(r.right - vw), byLeft: Math.round(-r.left) });
    }
    // horizontal text spill with overflow visible (glyphs escape the box)
    if (ownText && cs.overflowX === 'visible' && el.scrollWidth > el.clientWidth + 2 && el.clientWidth > 0) {
      push('text-spills-box', el, cs, r, { spill: el.scrollWidth - el.clientWidth });
    }
    // cut-off text: clipped without ellipsis (lossy truncation)
    if (ownText && !insideScrollContainer(el)) {
      if (cs.overflowX === 'hidden' && cs.textOverflow !== 'ellipsis' && el.scrollWidth > el.clientWidth + 6 && el.clientWidth > 0) {
        push('cut-off-text-x', el, cs, r, { spill: el.scrollWidth - el.clientWidth });
      }
      if (cs.overflowY === 'hidden' && el.scrollHeight > el.clientHeight + 6 && el.clientHeight > 0) {
        push('cut-off-text-y', el, cs, r, { spill: el.scrollHeight - el.clientHeight });
      }
    }
  }

  // -- content escaping its nearest tight visual card (text spilling out of a box)
  // card = nearest ancestor with a border, corner radius, or overflow clipping
  // that is not a page-level wrapper; a scroll container between card and
  // content means the overflow is scrollable by design and is skipped.
  const tightCard = (cs, el) => {
    if (el.tagName === 'BODY' || el.tagName === 'HTML' || el.tagName === 'MAIN') return false;
    if (el.scrollWidth > vw * 1.05) return false; // page-wide band, not a card
    return parseFloat(cs.borderTopWidth) > 0 || parseFloat(cs.borderLeftWidth) > 0
      || parseFloat(cs.borderRadius) > 2
      || cs.overflowX === 'hidden' || cs.overflowY === 'hidden';
  };
  for (const [el, di] of info) {
    if (!di.ownText && el.tagName !== 'IMG' && el.tagName !== 'SVG') continue;
    if (!di.inFlow) continue; // absolutely positioned overhangs are intentional patterns
    let card = null, n = el.parentElement;
    while (n && n.nodeType === 1 && n !== document.body) {
      const ni = info.get(n) || { cs: getComputedStyle(n) };
      if (ni.cs.overflowX === 'auto' || ni.cs.overflowX === 'scroll' || ni.cs.overflowY === 'auto' || ni.cs.overflowY === 'scroll') { card = null; break; }
      if (tightCard(ni.cs, n)) { card = n; break; }
      n = n.parentElement;
    }
    if (!card) continue;
    // collapsed disclosure containers (grid-rows 0fr / height 0 menus) keep
    // child layout boxes while hiding them — that containment is intentional
    if (card.clientHeight < 2 || card.clientWidth < 2) continue;
    // overhang ribbons/badges: absolutely positioned wrappers between the
    // content and the card place content outside the card on purpose
    let posAncestor = false, pn = el.parentElement;
    while (pn && pn !== card && pn.nodeType === 1) {
      const pcs = info.get(pn) ? info.get(pn).cs : getComputedStyle(pn);
      if (pcs.position === 'absolute' || pcs.position === 'fixed') { posAncestor = true; break; }
      pn = pn.parentElement;
    }
    if (posAncestor) continue;
    const cr = card.getBoundingClientRect();
    const ccs = info.get(card).cs;
    const dr = di.r;
    const clipped = ccs.overflowX === 'hidden' || ccs.overflowX === 'clip' || ccs.overflowY === 'hidden' || ccs.overflowY === 'clip';
    const outR = Math.max(0, dr.right - cr.right), outL = Math.max(0, cr.left - dr.left);
    const outB = Math.max(0, dr.bottom - cr.bottom), outT = Math.max(0, cr.top - dr.top);
    const worst = Math.max(outR, outL, outB, outT);
    if (worst > 8) {
      push(clipped ? 'clipped-by-card' : 'escapes-card', el, di.cs, dr, {
        card: pathOf(card), cardCls: (card.getAttribute('class') || '').slice(0, 90),
        out: { right: Math.round(outR), left: Math.round(outL), bottom: Math.round(outB), top: Math.round(outT) },
      });
    }
  }

  // -- overlapping in-flow solid siblings (broken stacking like the header-tag bug)
  // Only block-level boxes are compared: wrapped inline elements (code chips,
  // links) have bounding rects spanning every line box they occupy, which
  // flow-layout places correctly and would otherwise false-positive.
  const solidBox = (cs) =>
    (cs.backgroundColor !== 'rgba(0, 0, 0, 0)' && cs.backgroundColor !== 'transparent')
    || parseFloat(cs.borderTopWidth) > 0 || parseFloat(cs.borderLeftWidth) > 0;
  const isBlockLevel = (cs) => /^(block|flex|grid|inline-flex|inline-grid|inline-block|table|table-row|table-cell|flow-root|list-item)/.test(cs.display);
  for (const [parent] of info) {
    const kids = [...parent.children].map(c => ({ el: c, i: info.get(c) })).filter(k => k.i);
    for (let i = 0; i < kids.length; i++) {
      for (let j = i + 1; j < kids.length; j++) {
        const { el: el1, i: a } = kids[i];
        const { el: el2, i: b } = kids[j];
        if (!a.inFlow || !b.inFlow) continue;
        if (!isBlockLevel(a.cs) || !isBlockLevel(b.cs)) continue;
        const aSolid = a.ownText || solidBox(a.cs), bSolid = b.ownText || solidBox(b.cs);
        if (!aSolid || !bSolid) continue;
        // intentional overlap via negative margins (section pull-ups) is excluded
        if (parseFloat(a.cs.marginTop) < 0 || parseFloat(a.cs.marginBottom) < 0) continue;
        if (parseFloat(b.cs.marginTop) < 0 || parseFloat(b.cs.marginBottom) < 0) continue;
        const ox = Math.min(a.r.right, b.r.right) - Math.max(a.r.left, b.r.left);
        const oy = Math.min(a.r.bottom, b.r.bottom) - Math.max(a.r.top, b.r.top);
        if (ox > 6 && oy > 6) {
          push('sibling-overlap', el1, a.cs, a.r, { other: pathOf(el2), otherCls: (el2.getAttribute('class') || '').slice(0, 90), ix: Math.round(ox), iy: Math.round(oy) });
        }
      }
    }
  }

  return { docSpill, vw, findings: out };
})()`;

// ---------------------------------------------------------------- audit task
async function auditTask(browser, port, task, results) {
  const { url: pageUrl, theme, surface, route, viewport } = task;
  const isMarketing = surface === 'marketing';
  const width = viewport === 'mobile' ? 375 : (isMarketing ? 1440 : 1280);
  const ctx = await browser.newContext({
    viewport: { width, height: 800 },
    deviceScaleFactor: 1,
    colorScheme: theme === 'dark' ? 'dark' : 'light',
    reducedMotion: 'reduce',
    isMobile: viewport === 'mobile',
    hasTouch: viewport === 'mobile',
  });
  await ctx.addInitScript(() => {
    const nuke = () => {
      const s = document.createElement('style');
      // kill entrance animations (translate/opacity would measure as spills)
      // and neutralise classic scrollbars so 100vw elements match overlay-scrollbar reality
      s.textContent = '*,*::before,*::after{animation:none!important;transition:none!important;}::-webkit-scrollbar{width:0;height:0;display:none;}html{scrollbar-width:none;}';
      (document.head || document.documentElement).appendChild(s);
    };
    nuke();
    document.addEventListener('DOMContentLoaded', nuke);
  });
  await ctx.route((u) => { const h = new URL(u).hostname; return h !== '127.0.0.1' && h !== 'localhost' && h !== 'apexmail.ee'; }, (r) => r.abort());
  await ctx.route((u) => new URL(u).hostname === 'apexmail.ee', async (route2) => {
    const p = decodeURIComponent(new URL(route2.request().url()).pathname);
    try {
      const body = fs.readFileSync(path.join(MARKETING, p.slice(1).replace(/\.\./g, '')));
      await route2.fulfill({ body, contentType: MIME[path.extname(p)] || 'application/octet-stream' });
    } catch { await route2.fulfill({ status: 404, body: 'nf' }); }
  });
  const pg = await ctx.newPage();
  const entry = { surface, page: route, theme, viewport, error: null, docSpill: 0, findings: [] };
  try {
    await pg.goto(`http://127.0.0.1:${port}${pageUrl}`, { waitUntil: 'load', timeout: 30000 });
    await pg.evaluate(() => document.fonts.ready).catch(() => {});
    if (theme === 'dark-class') {
      await pg.evaluate(() => document.documentElement.classList.add('dark'));
    }
    await pg.waitForTimeout(100);
    const collected = await pg.evaluate(COLLECTOR);
    entry.docSpill = collected.docSpill;
    entry.findings = collected.findings;
    if (collected.docSpill > 2) {
      entry.findings.unshift({ kind: 'doc-horizontal-overflow', spill: collected.docSpill, vw: collected.vw, path: 'document', tag: 'html', cls: '', text: '', rect: { x: 0, y: 0, w: collected.vw, h: 0 }, overflowX: '', overflowY: '', position: '' });
    }
  } catch (e) {
    entry.error = String(e).slice(0, 200);
  } finally {
    await ctx.close();
  }
  results.push(entry);
}

// ---------------------------------------------------------------- main
async function main() {
  const pages = buildInventory().filter(p => !ONLY || `${p.surface}:${p.route}`.includes(ONLY) || p.stem.includes(ONLY));
  const tasks = [];
  for (const p of pages) {
    const themes = p.surface === 'marketing' ? ['light', 'dark'] : ['light', 'dark', 'dark-class'];
    for (const theme of themes) {
      tasks.push({ ...p, theme, viewport: 'desktop' });
      if (theme !== 'dark-class') tasks.push({ ...p, theme, viewport: 'mobile' });
    }
  }
  console.log(`Layout-auditing ${pages.length} pages, ${tasks.length} page-theme-viewport runs`);
  const { server, port } = await startServer();
  const browser = await chromium.launch();
  const results = [];
  let idx = 0;
  const workers = Array.from({ length: WORKERS }, async () => {
    while (idx < tasks.length) {
      const t = tasks[idx++];
      await auditTask(browser, port, t, results);
      const e = results[results.length - 1];
      const n = e.findings.length;
      console.log(`  ${n === 0 && !e.error ? 'ok ' : 'FLAG'} ${e.surface} ${e.page} [${e.theme}/${e.viewport}] findings=${n}${e.error ? ' error=' + e.error : ''}`);
    }
  });
  await Promise.all(workers);
  await browser.close();
  server.close();

  // screenshots for flagged runs (triage evidence)
  const flagged = results.filter(r => r.findings.length > 0);
  if (flagged.length) {
    const b2 = await chromium.launch();
    let i2 = 0;
    const shot = async (entry) => {
      const page = pages.find(p => p.surface === entry.surface && p.route === entry.page);
      if (!page) return;
      const width = entry.viewport === 'mobile' ? 375 : (entry.surface === 'marketing' ? 1440 : 1280);
      const ctx = await b2.newContext({ viewport: { width, height: 800 }, colorScheme: entry.theme === 'dark' ? 'dark' : 'light', reducedMotion: 'reduce', isMobile: entry.viewport === 'mobile', hasTouch: entry.viewport === 'mobile' });
      await ctx.addInitScript(() => {
        const s = document.createElement('style');
        s.textContent = '*,*::before,*::after{animation:none!important;transition:none!important;}::-webkit-scrollbar{width:0;height:0;display:none;}html{scrollbar-width:none;}';
        (document.head || document.documentElement).appendChild(s);
      });
      await ctx.route((u) => { const h = new URL(u).hostname; return h !== '127.0.0.1' && h !== 'localhost' && h !== 'apexmail.ee'; }, (r) => r.abort());
      await ctx.route((u) => new URL(u).hostname === 'apexmail.ee', async (route2) => {
        const p = decodeURIComponent(new URL(route2.request().url()).pathname);
        try {
          const body = fs.readFileSync(path.join(MARKETING, p.slice(1).replace(/\.\./g, '')));
          await route2.fulfill({ body, contentType: MIME[path.extname(p)] || 'application/octet-stream' });
        } catch { await route2.fulfill({ status: 404, body: 'nf' }); }
      });
      const pg = await ctx.newPage();
      try {
        await pg.goto(`http://127.0.0.1:${port2}${page.url}`, { waitUntil: 'load', timeout: 30000 });
        if (entry.theme === 'dark-class') await pg.evaluate(() => document.documentElement.classList.add('dark'));
        await pg.waitForTimeout(80);
        const stem = `${entry.surface}--${page.stem}--${entry.theme}--${entry.viewport}`.replace(/[^a-zA-Z0-9._-]+/g, '_');
        await pg.screenshot({ path: path.join(SHOTS, `${stem}.png`), fullPage: true });
      } catch { /* triage screenshot is best-effort */ }
      await ctx.close();
    };
    // second server (first closed)
    const s2 = await startServer();
    var port2 = s2.port; // eslint-disable-line no-var
    await Promise.all(Array.from({ length: WORKERS }, async () => {
      while (i2 < flagged.length) { const e = flagged[i2++]; await shot(e); }
    }));
    await b2.close();
    s2.server.close();
  }

  const byKind = {};
  let total = 0;
  for (const r of results) for (const f of r.findings) { byKind[f.kind] = (byKind[f.kind] || 0) + 1; total++; }
  fs.mkdirSync(OUT, { recursive: true });
  fs.writeFileSync(path.join(OUT, 'violations.json'), JSON.stringify({ generatedAt: new Date().toISOString(), runs: results.length, totalFindings: total, byKind, results }, null, 2));
  console.log(`\nDone: ${total} layout findings across ${results.length} runs.`);
  console.log('By kind:', JSON.stringify(byKind));
  console.log(`Report: ${path.join(OUT, 'violations.json')}`);
  if (total > 0 && !REPORT_ONLY) {
    console.log('FLAGGED pages:');
    for (const r of results.filter(x => x.findings.length)) {
      console.log(`  ${r.surface} ${r.page} [${r.theme}/${r.viewport}]: ${r.findings.map(f => f.kind).join(', ')}`);
    }
    process.exit(1);
  }
}

main().catch(e => { console.error(e); process.exit(2); });
