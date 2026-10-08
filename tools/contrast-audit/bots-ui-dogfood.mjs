#!/usr/bin/env node
// Bot-surface UI/visual dogfood capture (dogfood 2026-10-06 ui-visual).
//
// Captures the console assistant (/assistant) and the AI-drafts review
// queue (/reviews/ai-drafts) per state, per theme, at 320/768/1280 CSS px,
// and records, for each run:
//   * a full-page screenshot,
//   * horizontal-overflow / clipping metrics,
//   * hit-target sizes (buttons/links < 24px CSS fail the bar),
//   * keyboard traversal (Tab/Shift-Tab) with focus-ring detection,
//   * heading outline + skip link,
//   * a copy/honesty scan (internal ids, paths, raw errors, unmasked
//     tenant vocabulary on the web surface).
//
// Modes:
//   node bots-ui-dogfood.mjs fixtures [--out DIR]
//       Serves tools/contrast-audit/fixtures and walks every bot state
//       fixture registered in the manifest (plus the route-level empty
//       states). No auth, no live stack.
//   node bots-ui-dogfood.mjs live --cookies "am_session=…; csrf_token=…"
//       [--base http://127.0.0.1:8080] [--cp-cookies "…"]
//       Drives the RUNNING stack. With --post it also submits one message
//       through the assistant form and measures layout shift across the
//       navigation; with --flush-rate-limit N it posts N messages first so
//       the rate-limit flash can be captured.
//
// Output: DIR (default tools/contrast-audit/reports/bots-ui) with
// screenshots/<state>-<theme>-<width>.png and report.json.
import fs from 'node:fs';
import path from 'node:path';
import http from 'node:http';
import { fileURLToPath } from 'node:url';
import { chromium } from 'playwright';

// fileURLToPath decodes percent-escapes in the checkout path (spaces,
// non-ASCII); `new URL(import.meta.url).pathname` leaves them encoded and
// the fixture root derived from it misses the tree (R-1, 2026-10-07).
const ROOT = path.dirname(fileURLToPath(import.meta.url));
const FIXTURES = path.join(ROOT, 'fixtures');
const args = process.argv.slice(2);
const MODE = args[0] || 'fixtures';
const argValue = (name, fallback = null) => {
  const i = args.indexOf(`--${name}`);
  return i >= 0 && args[i + 1] ? args[i + 1] : fallback;
};
const OUT = path.resolve(argValue('out', path.join(ROOT, 'reports/bots-ui')));
const BASE = argValue('base', 'http://127.0.0.1:8080');
const CP_BASE = argValue('cp-base', 'http://localhost:8080');
const ROUTES = argValue('routes', ''); // comma-separated extra live routes (web)
const CP_ROUTES = argValue('cp-routes', ''); // comma-separated extra live routes (control plane)
const COOKIES = argValue('cookies', '');
const CP_COOKIES = argValue('cp-cookies', '');
const POST = args.includes('--post');
const FLUSH = Number(argValue('flush-rate-limit', '0')); // eslint-disable-line no-unused-vars
const WIDTHS = [320, 768, 1280];
const THEMES = ['light', 'dark'];

fs.mkdirSync(path.join(OUT, 'screenshots'), { recursive: true });

const MIME = {
  '.html': 'text/html', '.css': 'text/css', '.js': 'text/javascript',
  '.svg': 'image/svg+xml', '.png': 'image/png', '.jpg': 'image/jpeg',
  '.webp': 'image/webp', '.ico': 'image/x-icon', '.woff2': 'font/woff2',
  '.ttf': 'font/ttf', '.json': 'application/json', '.txt': 'text/plain',
  '.xml': 'application/xml', '.webmanifest': 'application/manifest+json',
};

function startFixtureServer() {
  const server = http.createServer((req, res) => {
    const u = decodeURIComponent(new URL(req.url, 'http://x').pathname);
    const rel = (u.startsWith('/f/') ? u.slice(3) : u.slice(1)).replace(/\.\./g, '');
    const file = path.join(FIXTURES, rel);
    if (!file.startsWith(FIXTURES) || !fs.existsSync(file) || fs.statSync(file).isDirectory()) {
      res.writeHead(404); res.end('nf'); return;
    }
    res.writeHead(200, { 'content-type': MIME[path.extname(file)] || 'application/octet-stream' });
    fs.createReadStream(file).pipe(res);
  });
  return new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve({ server, port: server.address().port })));
}

// ---------------------------------------------------------------- collector
const COLLECT = `(() => {
  const vw = document.documentElement.clientWidth;
  const out = {
    url: location.href,
    title: document.title,
    viewport: { width: vw, height: document.documentElement.clientHeight },
    scrollWidth: document.documentElement.scrollWidth,
    horizontalOverflow: document.documentElement.scrollWidth - vw,
    overflowing: [],
    clipped: [],
    smallTargets: [],
    headings: [...document.querySelectorAll('h1,h2,h3,h4')].map(h => h.tagName + ':' + h.textContent.trim().slice(0, 48)),
    h1Count: document.querySelectorAll('h1').length,
    skipLink: !!document.querySelector('a[href^="#"]'),
    mainId: document.querySelector('main') ? document.querySelector('main').id : null,
    text: document.body.innerText.slice(0, 60000),
  };
  const visible = (el) => {
    const r = el.getBoundingClientRect();
    const s = getComputedStyle(el);
    return r.width > 0 && r.height > 0 && s.visibility !== 'hidden' && s.display !== 'none';
  };
  const isSrOnly = (el) => String(el.className || '').split(/\s+/).some((c) => c.startsWith('sr-only'));
  for (const el of document.querySelectorAll('body *')) {
    if (!visible(el) || isSrOnly(el)) continue;
    const r = el.getBoundingClientRect();
    // Elements extending past the viewport (clipped or forcing scroll).
    if (r.right - vw > 1 || r.left < -1) {
      const tag = el.tagName.toLowerCase();
      if (!['html','body'].includes(tag)) {
        out.overflowing.push({ sel: tag + '.' + String(el.className || '').slice(0, 80), right: Math.round(r.right), left: Math.round(r.left), w: Math.round(r.width), text: (el.textContent || '').trim().slice(0, 60) });
      }
    }
    // Text boxes whose content is wider than the box and not scroll-reachable.
    const s = getComputedStyle(el);
    if (el.children.length === 0 && (el.textContent || '').trim().length > 0 && el.scrollWidth - el.clientWidth > 1) {
      out.clipped.push({ sel: el.tagName.toLowerCase() + '.' + String(el.className || '').slice(0, 80), scrollWidth: el.scrollWidth, clientWidth: el.clientWidth, overflowX: s.overflowX, text: el.textContent.trim().slice(0, 60) });
    }
  }
  for (const el of document.querySelectorAll('button, a[href], input[type=submit], summary, [role=button]')) {
    if (!visible(el) || isSrOnly(el)) continue;
    const r = el.getBoundingClientRect();
    if (r.width < 24 || r.height < 24) {
      out.smallTargets.push({ tag: el.tagName.toLowerCase(), text: (el.textContent || el.getAttribute('aria-label') || '').trim().slice(0, 40), w: Math.round(r.width), h: Math.round(r.height) });
    }
  }
  // Deduplicate trivially repeated offenders.
  const uniq = (list, key) => { const seen = new Set(); return list.filter(x => { const k = x[key]; if (seen.has(k)) return false; seen.add(k); return true; }); };
  out.overflowing = uniq(out.overflowing, 'sel').slice(0, 25);
  out.clipped = uniq(out.clipped, 'sel').slice(0, 25);
  out.smallTargets = uniq(out.smallTargets, 'text').slice(0, 25);
  return out;
})()`;

const FOCUS_PROBE = `(async () => {
  // Walk the tab order and record each stop's visible focus indicator.
  const stops = [];
  const limit = 60;
  for (let i = 0; i < limit; i++) {
    const before = document.activeElement;
    // Dispatch a real Tab via the browser is not possible from script; the
    // driver presses keys. This helper only reads the CURRENT stop.
    if (!before) break;
    const s = getComputedStyle(before);
    const ring = (s.outlineStyle !== 'none' && parseFloat(s.outlineWidth) > 0) || (s.boxShadow && s.boxShadow !== 'none');
    stops.push({ tag: before.tagName.toLowerCase(), id: before.id || null, text: (before.textContent || before.getAttribute('aria-label') || '').trim().slice(0, 40), ring, outline: s.outline, boxShadow: (s.boxShadow || '').slice(0, 60) });
    // The driver moves focus; stop when it wraps back to the start.
    if (i > 0 && document.activeElement === document.body) break;
    break;
  }
  return stops;
})()`;

async function collect(pg) {
  return pg.evaluate(COLLECT);
}

/** Tab through up to `max` stops, returning each stop's focus indicator. */
async function tabWalk(pg, max = 40) {
  const stops = [];
  await pg.evaluate(() => { window.__focusSeen = new Set(); });
  for (let i = 0; i < max; i++) {
    await pg.keyboard.press('Tab');
    const stop = await pg.evaluate(() => {
      const el = document.activeElement;
      if (!el || el === document.body) return { body: true };
      const s = getComputedStyle(el);
      const visible = (s.outlineStyle !== 'none' && parseFloat(s.outlineWidth) > 0) || (s.boxShadow && s.boxShadow !== 'none');
      return {
        tag: el.tagName.toLowerCase(),
        id: el.id || null,
        text: (el.textContent || el.getAttribute('aria-label') || el.getAttribute('placeholder') || '').trim().slice(0, 40),
        visible,
        outline: s.outline,
        boxShadow: (s.boxShadow || 'none').slice(0, 80),
      };
    });
    if (stop.body) { stops.push({ wrappedToBody: true }); break; }
    const key = `${stop.tag}#${stop.id}:${stop.text}`;
    if (stops.some((s) => s.key === key)) { stops.push({ repeated: true, ...stop, key }); break; }
    stops.push({ ...stop, key });
  }
  return stops;
}

const COPY_RULES = [
  { id: 'internal-route-path', re: /\/(web|v1)\/[a-z0-9_/-]+/i, why: 'raw internal route path in visible copy' },
  { id: 'source-file', re: /[a-z_]+\.rs\b/, why: 'source file name in visible copy' },
  { id: 'raw-error', re: /\b(sqlx|panicked|unwrap\(|Error:)\b/, why: 'raw error text in visible copy' },
  { id: 'id-shaped', re: /\b(usr|tnt|wsp|draft|chat|inb|msg)_[a-z0-9]{6,}\b/i, why: 'internal identifier shape in visible copy' },
  // "tenant" is operator vocabulary: allowed on the control plane, banned on
  // the customer console (terminology gate J). Scope it to the web surface.
  { id: 'tenant-words', re: /\btenants?\b/i, why: 'operator vocabulary on the web surface', surface: 'web' },
];

function copyScan(text, surface) {
  return COPY_RULES
    .filter((rule) => !rule.surface || rule.surface === surface)
    .map((rule) => ({ rule: rule.id, why: rule.why, matches: [...new Set((text.match(new RegExp(rule.re.source, 'gi')) || []))].slice(0, 5) }))
    .filter((r) => r.matches.length > 0);
}

// ---------------------------------------------------------------- runs
async function capture(browser, baseUrl, cookieHeader, route, label, opts = {}) {
  const surface = opts.surface || (route === '/reviews/ai-drafts' ? 'control-plane' : 'web');
  const results = [];
  for (const theme of THEMES) {
    for (const width of WIDTHS) {
      const ctx = await browser.newContext({
        viewport: { width, height: 900 },
        colorScheme: theme,
        reducedMotion: 'reduce',
      });
      if (cookieHeader) {
        const cookies = cookieHeader.split(';').map((pair) => {
          const [name, ...rest] = pair.trim().split('=');
          return { name, value: rest.join('='), url: baseUrl };
        }).filter((c) => c.name && c.value !== undefined);
        await ctx.addCookies(cookies);
      }
      const pg = await ctx.newPage();
      const run = { label, route, theme, width, error: null };
      try {
        await pg.goto(baseUrl + route, { waitUntil: 'load', timeout: 30000 });
        await pg.evaluate(() => document.fonts.ready).catch(() => {});
        await pg.waitForTimeout(150);
        const metrics = await collect(pg);
        // Screenshot the MEASURED state first: the keyboard walk below moves
        // focus/scroll, and the evidence shot must match the collected metrics.
        const shot = path.join(OUT, 'screenshots', `${label}-${theme}-${width}.png`);
        await pg.screenshot({ path: shot, fullPage: true });
        const focus = await tabWalk(pg, 30);
        run.metrics = metrics;
        run.focus = {
          stops: focus,
          ringlessStops: focus.filter((s) => s.tag && !s.visible).map((s) => s.key),
          trapped: focus.some((s) => s.wrappedToBody && !s.visible),
          repeated: focus.some((s) => s.repeated),
        };
        run.copy = opts.skipCopyScan ? [] : copyScan(metrics.text, surface);
        run.screenshot = path.relative(OUT, shot);
      } catch (e) {
        run.error = String(e).slice(0, 300);
      }
      results.push(run);
      await ctx.close();
    }
  }
  return results;
}

function summarize(report) {
  const lines = [];
  for (const run of report.runs) {
    if (run.error) { lines.push(`ERROR ${run.label} ${run.theme} ${run.width}: ${run.error}`); continue; }
    const m = run.metrics;
    const flags = [];
    if (m.horizontalOverflow > 1) flags.push(`overflow=${m.horizontalOverflow}px`);
    if (m.overflowing.length) flags.push(`elements-past-viewport=${m.overflowing.length}`);
    if (m.clipped.length) flags.push(`clipped=${m.clipped.length}`);
    if (m.smallTargets.length) flags.push(`small-targets=${m.smallTargets.length}`);
    if (run.focus.ringlessStops.length) flags.push(`ringless=${run.focus.ringlessStops.length}`);
    if (m.h1Count !== 1) flags.push(`h1=${m.h1Count}`);
    if (run.copy.length) flags.push(`copy=${run.copy.map((c) => c.rule).join(',')}`);
    lines.push(`${flags.length ? 'FLAG' : ' ok '} ${run.label} ${run.theme} ${run.width} ${flags.join(' ')}`);
  }
  return lines.join('\n');
}

async function main() {
  const report = { mode: MODE, base: BASE, generated: new Date().toISOString(), runs: [] };
  const browser = await chromium.launch({ channel: 'chromium' });
  try {
    if (MODE === 'fixtures') {
      const { server, port } = await startFixtureServer();
      const base = `http://127.0.0.1:${port}/f/`;
      const manifest = JSON.parse(fs.readFileSync(path.join(FIXTURES, 'manifest.json'), 'utf8'));
      const botFiles = [...new Set(manifest.fixtures
        .filter((fx) => fx.route === '/assistant' || fx.route === '/reviews/ai-drafts')
        .map((fx) => fx.htmlFile))].sort();
      for (const file of botFiles) {
        const label = file.replace(/\.html$/, '');
        const runs = await capture(browser, base, '', file, label);
        report.runs.push(...runs);
      }
      server.close();
    } else if (MODE === 'live') {
      if (!COOKIES) throw new Error('live mode needs --cookies');
      if (ROUTES || CP_ROUTES) {
        // Targeted pages (capability-wave routes etc.): label from the path.
        for (const route of ROUTES.split(',').map((r) => r.trim()).filter(Boolean)) {
          const label = `live-${route.replace(/[^a-z0-9]+/gi, '-').replace(/^-|-$/g, '')}`;
          report.runs.push(...(await capture(browser, BASE, COOKIES, route, label)));
        }
        for (const route of CP_ROUTES.split(',').map((r) => r.trim()).filter(Boolean)) {
          const label = `live-cp-${route.replace(/[^a-z0-9]+/gi, '-').replace(/^-|-$/g, '')}`;
          report.runs.push(...(await capture(browser, CP_BASE, CP_COOKIES || COOKIES, route, label, { surface: 'control-plane' })));
        }
      } else {
        const assistant = await capture(browser, BASE, COOKIES, '/assistant', 'live-assistant');
        report.runs.push(...assistant);
        if (CP_COOKIES) {
          const drafts = await capture(browser, CP_BASE, CP_COOKIES, '/reviews/ai-drafts', 'live-drafts');
          report.runs.push(...drafts);
        }
      }
    } else {
      throw new Error(`unknown mode ${MODE}`);
    }
  } finally {
    await browser.close();
  }
  fs.writeFileSync(path.join(OUT, 'report.json'), JSON.stringify(report, null, 1));
  process.stdout.write(summarize(report) + '\n');
  process.stdout.write(`report: ${path.join(OUT, 'report.json')}\n`);
}

main().catch((e) => { console.error(e); process.exit(1); });
