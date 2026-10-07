// Focused live probes: flag-disabled 403 (cache-aware) + a well-formed draft approve.
import { chromium } from 'playwright';
import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';

const OUT = path.resolve('reports/bots-ui-live');
const session = JSON.parse(fs.readFileSync('/tmp/ui_session.json', 'utf8'));
const cp = JSON.parse(fs.readFileSync('/tmp/cp_session.json', 'utf8'));
const WEB = 'http://127.0.0.1:8080';
const CP = 'http://admin.localhost:8080';
const report = { generated: new Date().toISOString(), steps: [] };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function psql(q) {
  return execFileSync('docker', ['exec', 'apexmail-postgres', 'psql', '-U', 'apexmail', '-d', 'apexmail', '-t', '-A', '-c', q], { encoding: 'utf8' }).trim();
}
const cookiesFor = (base, header) => header.split(';').map((pair) => {
  const [name, ...rest] = pair.trim().split('=');
  return { name, value: rest.join('='), url: base };
}).filter((c) => c.name && c.value !== undefined);

const browser = await chromium.launch({ channel: 'chromium' });
const step = async (name, fn) => {
  const entry = { name };
  try { Object.assign(entry, await fn()); } catch (e) { entry.error = String(e).slice(0, 300); }
  report.steps.push(entry);
  console.log(`${entry.error ? 'ERROR' : 'ok'} ${name} ${entry.note || ''}`);
};

const tenant = psql(`SELECT tenant_id FROM users WHERE email='${session.email}'`);
console.log('tenant', tenant);

// ── flag-disabled (cache TTL is 30s) ────────────────────────────────────
const ctx = await browser.newContext({ viewport: { width: 1280, height: 900 } });
await ctx.addCookies(cookiesFor(WEB, session.cookie));
const pg = await ctx.newPage();

await step('wait-out-rate-limit', async () => { await sleep(65000); return { note: 'window cleared' }; });

await step('flag-disabled-page', async () => {
  psql(`INSERT INTO feature_flag_overrides (tenant_id, flag_key, value) VALUES ('${tenant}','ai_chat','false'::jsonb) ON CONFLICT (tenant_id, flag_key) DO UPDATE SET value='false'::jsonb`);
  await sleep(35000); // feature-flag cache TTL
  await pg.goto(`${WEB}/assistant`, { waitUntil: 'load' });
  const state = await pg.evaluate(() => {
    const t = document.body.innerText;
    return {
      disabledNotice: t.includes('not enabled for this workspace'),
      namesReason: t.includes('capability is disabled'),
      namesSwitchOff: t.includes('switched the AI assistant off'),
      hasForm: !!document.querySelector('form[action="/web/assistant/message"]'),
      emptyPrompt: t.includes('Ask about your workspace'),
    };
  });
  await pg.screenshot({ path: path.join(OUT, 'live-assistant-flag-disabled-page.png'), fullPage: true });
  return { state, note: JSON.stringify(state) };
});

await step('flag-disabled-post-refusal', async () => {
  // Direct POST (the honest refusal must exist even if a stale form was open).
  const html = await pg.content();
  const m = html.match(/name="_csrf"\s+value="([^"]+)"/);
  const result = await pg.evaluate(async ({ token }) => {
    const body = new URLSearchParams({ _csrf: token, message: 'flag-disabled probe' });
    const r = await fetch('/web/assistant/message', { method: 'POST', body, headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, redirect: 'follow' });
    const t = await r.text();
    const flash = t.match(/aria-label="Error"[^>]*>.*?<span[^>]*>([^<]*)</s);
    return { status: r.status, hasDisabledNotice: t.includes('not enabled for this workspace'), hasForm: t.includes('/web/assistant/message'), flash: flash ? flash[1].trim() : (t.includes('too many questions') ? 'rate-limited flash' : '') };
  }, { token: m ? m[1] : '' });
  await pg.screenshot({ path: path.join(OUT, 'live-assistant-flag-disabled-post.png'), fullPage: true });
  return { result, note: JSON.stringify(result) };
});

await step('flag-restored', async () => {
  psql(`DELETE FROM feature_flag_overrides WHERE tenant_id='${tenant}' AND flag_key='ai_chat'`);
  await sleep(35000);
  await pg.goto(`${WEB}/assistant`, { waitUntil: 'load' });
  const state = await pg.evaluate(() => ({
    hasForm: !!document.querySelector('form[action="/web/assistant/message"]'),
    disabledNotice: document.body.innerText.includes('not enabled for this workspace'),
    turns: document.querySelectorAll('article').length,
  }));
  return { state, note: JSON.stringify(state) };
});

// ── drafts: approve a well-formed row ───────────────────────────────────
const cpCtx = await browser.newContext({ viewport: { width: 1280, height: 900 } });
await cpCtx.addCookies(cookiesFor(CP, cp.cookie));
const cpPg = await cpCtx.newPage();

await step('drafts-approve-wellformed', async () => {
  const row = psql("SELECT id FROM inbound_messages WHERE pending_approval = true AND ai_response IS NOT NULL AND tenant_id IS NOT NULL AND from_email IS NOT NULL AND from_email <> '' ORDER BY received_at ASC LIMIT 1");
  if (!row) return { note: 'no well-formed row' };
  await cpPg.goto(`${CP}/reviews/ai-drafts`, { waitUntil: 'load' });
  const action = await cpPg.evaluate((id) => {
    const f = document.querySelector(`form[action="/web/admin/ai/drafts/${id}/approve"]`);
    return f ? f.getAttribute('action') : null;
  }, row);
  if (!action) return { note: `row ${row} not on the first page of the queue` };
  await cpPg.fill(`input[id="note-approve-${row}"]`, 'Approved by the UI visual dogfood');
  await Promise.all([cpPg.waitForNavigation({ waitUntil: 'load' }), cpPg.click(`form[action$="/${row}/approve"] button[type=submit]`)]); 
  const flash = await cpPg.evaluate(() => (document.querySelector('#flash') || {}).innerText || '');
  await cpPg.screenshot({ path: path.join(OUT, 'live-drafts-approved-wellformed.png'), fullPage: true });
  return { row, flash, note: flash.slice(0, 120) };
});

await browser.close();
fs.writeFileSync(path.join(OUT, 'flag-probe-report.json'), JSON.stringify(report, null, 1));
console.log('report:', path.join(OUT, 'flag-probe-report.json'));
