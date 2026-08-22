#!/usr/bin/env node
// Spot-check helper: re-render a page in a theme and save a cropped screenshot
// around a violation's selector/bbox for manual verification.
// Usage: node crop.mjs <surface> <page> <theme> <selector|bbox> [out.png]
import fs from 'node:fs';
import path from 'node:path';
import http from 'node:http';
import { chromium } from 'playwright';

const ROOT = path.dirname(new URL(import.meta.url).pathname);
const REPO = path.resolve(ROOT, '../..');
const FIXTURES = path.join(ROOT, 'fixtures');
const MARKETING = path.resolve(REPO, 'apps/marketing-zola/public');
const [surface, page, theme, target, outArg] = process.argv.slice(2);

const MIME = { '.html': 'text/html', '.css': 'text/css', '.js': 'text/javascript', '.svg': 'image/svg+xml', '.png': 'image/png', '.woff2': 'font/woff2', '.ttf': 'font/ttf', '.json': 'application/json' };
const server = http.createServer((req, res) => {
  const u = decodeURIComponent(new URL(req.url, 'http://x').pathname);
  let file = u.startsWith('/f/') ? path.join(FIXTURES, u.slice(3)) : path.join(MARKETING, u.slice(1));
  if (!fs.existsSync(file)) { res.writeHead(404); res.end(); return; }
  if (fs.statSync(file).isDirectory()) file = path.join(file, 'index.html');
  res.writeHead(200, { 'content-type': MIME[path.extname(file)] || 'application/octet-stream' });
  res.end(fs.readFileSync(file));
});
await new Promise((r) => server.listen(0, '127.0.0.1', r));
const port = server.address().port;

const url = surface === 'marketing' ? page : `/f/${surface}-${page === '/' ? 'home' : page.slice(1).replaceAll('/', '-')}.html`;
const b = await chromium.launch({ channel: 'chromium' });
const ctx = await b.newContext({
  viewport: { width: surface === 'marketing' ? 1440 : 1280, height: 900 },
  colorScheme: theme === 'dark' ? 'dark' : 'light',
  reducedMotion: 'reduce',
});
await ctx.addInitScript(() => {
  const nuke = () => {
    const s = document.createElement('style');
    s.textContent = '*,*::before,*::after{animation:none!important;transition:none!important;}';
    (document.head || document.documentElement).appendChild(s);
  };
  nuke();
  document.addEventListener('DOMContentLoaded', nuke);
});
await ctx.route((u) => new URL(u).hostname === 'apexmail.ee', async (r2) => {
  const p = decodeURIComponent(new URL(r2.request().url()).pathname);
  try {
    const body = fs.readFileSync(path.join(MARKETING, p.slice(1).replace(/\.\./g, '')));
    await r2.fulfill({ body, contentType: MIME[path.extname(p)] || 'application/octet-stream' });
  } catch { await r2.fulfill({ status: 404, body: 'nf' }); }
});
const p = await ctx.newPage();
await p.goto(`http://127.0.0.1:${port}${url}`, { waitUntil: 'load' });
await p.evaluate(() => document.fonts.ready);
if (theme === 'dark-class') await p.evaluate(() => document.documentElement.classList.add('dark'));
await p.waitForTimeout(150);

let clip = null;
if (target.startsWith('[')) {
  const [x, y, w, h] = JSON.parse(target);
  const pad = 24;
  await p.evaluate(([yy]) => window.scrollTo(0, Math.max(0, yy - 300)), [y]);
  await p.waitForTimeout(150);
  const sy = await p.evaluate(() => window.scrollY);
  clip = { x: Math.max(0, x - pad), y: Math.max(0, y - sy - pad), width: w + pad * 2, height: h + pad * 2 };
} else {
  const el = p.locator(target).first();
  await el.scrollIntoViewIfNeeded();
  const box = await el.boundingBox();
  const pad = 24;
  if (box) clip = { x: Math.max(0, box.x - pad), y: Math.max(0, box.y - pad), width: box.width + pad * 2, height: box.height + pad * 2 };
}
const out = outArg || path.join(ROOT, 'reports', 'crops', `${surface}-${(page || 'home').replaceAll('/', '_')}-${theme}-${Date.now()}.png`);
fs.mkdirSync(path.dirname(out), { recursive: true });
await p.screenshot({ path: out, clip: clip || undefined });
console.log('saved', out, clip ? JSON.stringify(clip) : '(no clip)');
await b.close(); server.close();
