// Live bot-surface interaction probes (temporary; dogfood 2026-10-06 ui-visual).
import { chromium } from 'playwright';
import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';

const OUT = path.resolve('reports/bots-ui-live');
fs.mkdirSync(OUT, { recursive: true });
const session = JSON.parse(fs.readFileSync('/tmp/ui_session.json', 'utf8'));
const cp = JSON.parse(fs.readFileSync('/tmp/cp_session.json', 'utf8'));
const SYSTEM_TENANT = 'system_internal_tenant01';
const WEB = 'http://127.0.0.1:8080';
const CP = 'http://admin.localhost:8080';

const report = { generated: new Date().toISOString(), steps: [] };
const shot = async (pg, name) => {
  const file = path.join(OUT, `${name}.png`);
  await pg.screenshot({ path: file, fullPage: true });
  return path.relative(OUT, file);
};

const cookiesFor = (base, header) =>
  header.split(';').map((pair) => {
    const [name, ...rest] = pair.trim().split('=');
    return { name, value: rest.join('='), url: base };
  }).filter((c) => c.name && c.value !== undefined);

const addCookies = async (ctx, base, header) => ctx.addCookies(cookiesFor(base, header));

function psql(query) {
  return execFileSync('docker', ['exec', 'apexmail-postgres', 'psql', '-U', 'apexmail', '-d', 'apexmail', '-t', '-A', '-c', query], { encoding: 'utf8' }).trim();
}

const browser = await chromium.launch({ channel: 'chromium' });

async function step(name, fn) {
  const entry = { name };
  try {
    Object.assign(entry, await fn(entry));
  } catch (e) {
    entry.error = String(e).slice(0, 400);
  }
  report.steps.push(entry);
  console.log(`${entry.error ? 'ERROR' : 'ok'} ${name}${entry.error ? ' ' + entry.error : ''} ${entry.note || ''}`);
}

// ── web assistant (customer session) ────────────────────────────────────
const webCtx = await browser.newContext({ viewport: { width: 1280, height: 900 } });
await addCookies(webCtx, WEB, session.cookie);
const pg = await webCtx.newPage();

await step('assistant-empty-or-current', async () => {
  await pg.goto(`${WEB}/assistant`, { waitUntil: 'load' });
  const state = await pg.evaluate(() => {
    const t = document.body.innerText;
    return {
      empty: t.includes('Ask about your workspace'),
      disabled: t.includes('not enabled for this workspace'),
      unavailable: t.includes('Conversation unavailable'),
      turns: document.querySelectorAll('article').length,
      hasForm: !!document.querySelector('form[action="/web/assistant/message"]'),
    };
  });
  return { state, shot: await shot(pg, 'live-assistant-before'), note: JSON.stringify(state) };
});

await step('assistant-first-message', async () => {
  const before = await pg.evaluate(() => document.querySelectorAll('article').length);
  await pg.fill('#assistant-message', 'What does the Pro plan include, and is there an annual discount?');
  await Promise.all([pg.waitForNavigation({ waitUntil: 'load' }), pg.click('form[action="/web/assistant/message"] button[type=submit]')]);
  const after = await pg.evaluate(() => {
    const t = document.body.innerText;
    const articles = [...document.querySelectorAll('article')];
    return {
      turns: articles.length,
      flash: (document.querySelector('#flash') || {}).innerText || '',
      lastRole: articles.length ? articles[articles.length - 1].innerText.slice(0, 160) : '',
      hasYou: t.includes('You'),
      hasAssistant: t.includes('ApexMail Assistant'),
    };
  });
  return { before, after, shot: await shot(pg, 'live-assistant-first-message'), note: `turns ${before} -> ${after.turns}` };
});

await step('assistant-long-message', async () => {
  const long = ('We are migrating about forty thousand contacts next quarter and need the exact limits. ' +
    'Please cover custom-field mapping, deduplication, suppression handling and retry behaviour. ').repeat(24) +
    'The runbook points at https://apexmail.ee/docs/api/imports#bulk-contact-import-with-custom-field-mapping-and-idempotent-retries but it does not answer the retry question.';
  await pg.fill('#assistant-message', long.slice(0, 3900));
  await Promise.all([pg.waitForNavigation({ waitUntil: 'load' }), pg.click('form[action="/web/assistant/message"] button[type=submit]')]);
  const after = await pg.evaluate(() => {
    const articles = [...document.querySelectorAll('article')];
    const longTurn = articles.find((a) => a.innerText.length > 1200);
    const el = longTurn || articles[articles.length - 1];
    return {
      turns: articles.length,
      longestTurnChars: Math.max(...articles.map((a) => a.innerText.length), 0),
      overflow: document.documentElement.scrollWidth - document.documentElement.clientWidth,
      longTurnWrap: el ? getComputedStyle(el.querySelector('p')).whiteSpace + '/' + getComputedStyle(el.querySelector('p')).overflowWrap : '',
      flash: (document.querySelector('#flash') || {}).innerText || '',
    };
  });
  return { after, shot: await shot(pg, 'live-assistant-long-message'), note: `turns=${after.turns} overflow=${after.overflow}` };
});

await step('assistant-rate-limit-429', async () => {
  const flashes = [];
  for (let i = 0; i < 24; i++) {
    await pg.fill('#assistant-message', `rate-limit probe ${i}`);
    await Promise.all([pg.waitForNavigation({ waitUntil: 'load' }), pg.click('form[action="/web/assistant/message"] button[type=submit]')]);
    const flash = await pg.evaluate(() => (document.querySelector('#flash') || {}).innerText || '');
    flashes.push(flash);
    if (flash.includes('too many questions')) break;
  }
  const hit = flashes.find((f) => f.includes('too many questions')) || '';
  return {
    attempts: flashes.length,
    hit,
    shot: await shot(pg, 'live-assistant-rate-limit'),
    note: hit ? '429 flash observed' : 'rate limit not reached in 24 attempts',
  };
});

await step('assistant-flag-disabled-403', async () => {
  const tenant = psql(`SELECT tenant_id FROM users WHERE email='${session.email}'`);
  psql(`INSERT INTO feature_flag_overrides (tenant_id, flag_key, value) VALUES ('${tenant}','ai_chat','false'::jsonb) ON CONFLICT (tenant_id, flag_key) DO UPDATE SET value='false'::jsonb`);
  await pg.goto(`${WEB}/assistant`, { waitUntil: 'load' });
  const pageState = await pg.evaluate(() => {
    const t = document.body.innerText;
    return {
      disabledNotice: t.includes('not enabled for this workspace'),
      namesReason: t.includes('capability is disabled'),
      hasForm: !!document.querySelector('form[action="/web/assistant/message"]'),
    };
  });
  const pageShot = await shot(pg, 'live-assistant-disabled-page');
  // If the page still renders the form, post to see the refusal flash.
  let flash = '';
  if (pageState.hasForm) {
    await pg.fill('#assistant-message', 'flag-disabled probe');
    await Promise.all([pg.waitForNavigation({ waitUntil: 'load' }), pg.click('form[action="/web/assistant/message"] button[type=submit]')]);
    flash = await pg.evaluate(() => (document.querySelector('#flash') || {}).innerText || '');
  }
  const flashShot = await shot(pg, 'live-assistant-disabled-flash');
  psql(`DELETE FROM feature_flag_overrides WHERE tenant_id='${tenant}' AND flag_key='ai_chat'`);
  await pg.goto(`${WEB}/assistant`, { waitUntil: 'load' });
  const restored = await pg.evaluate(() => document.body.innerText.includes('Ask about your workspace') || !!document.querySelector('form[action="/web/assistant/message"]'));
  return { pageState, flash, restored, shot: flashShot, pageShot, note: JSON.stringify({ ...pageState, flash: flash.slice(0, 80) }) };
});

// ── drafts (operator session, localhost) ────────────────────────────────
const cpCtx = await browser.newContext({ viewport: { width: 1280, height: 900 } });
await addCookies(cpCtx, CP, cp.cookie);
const cpPg = await cpCtx.newPage();

await step('drafts-populated-live', async () => {
  await cpPg.goto(`${CP}/reviews/ai-drafts`, { waitUntil: 'load' });
  const state = await cpPg.evaluate(() => {
    const rows = document.querySelectorAll('article.apex-panel').length;
    const pills = document.querySelectorAll('.apex-pill--brand').length;
    const details = [...document.querySelectorAll('details')].length;
    return { rows, pills, details, hasEmpty: document.body.innerText.includes('No drafts need review') };
  });
  return { state, shot: await shot(cpPg, 'live-drafts-populated'), note: JSON.stringify(state) };
});

await step('drafts-expand-first-reply', async () => {
  const summary = cpPg.locator('article.apex-panel details summary').first();
  await summary.click();
  await cpPg.waitForTimeout(200);
  const state = await cpPg.evaluate(() => {
    const pre = document.querySelector('article.apex-panel details pre');
    return {
      open: !!document.querySelector('article.apex-panel details[open]'),
      preWhiteSpace: pre ? getComputedStyle(pre).whiteSpace : null,
      preOverflowWrap: pre ? getComputedStyle(pre).overflowWrap : null,
      preScrollWidth: pre ? pre.scrollWidth : null,
      preClientWidth: pre ? pre.clientWidth : null,
      docOverflow: document.documentElement.scrollWidth - document.documentElement.clientWidth,
    };
  });
  return { state, shot: await shot(cpPg, 'live-drafts-expanded'), note: JSON.stringify(state) };
});

await step('drafts-approve-feedback', async () => {
  const action = await cpPg.evaluate(() => {
    const form = document.querySelector('form[action*="/approve"]');
    return form ? form.getAttribute('action') : null;
  });
  if (!action) return { note: 'no approve form (empty queue)' };
  await cpPg.fill('input[id^=note-approve-]', 'Approved by the UI visual dogfood');
  await Promise.all([cpPg.waitForNavigation({ waitUntil: 'load' }), cpPg.click('form[action*="/approve"] button[type=submit]')]);
  const flash = await cpPg.evaluate(() => (document.querySelector('#flash') || {}).innerText || '');
  return { action, flash, shot: await shot(cpPg, 'live-drafts-approved'), note: flash.slice(0, 90) };
});

await step('drafts-reject-feedback', async () => {
  const action = await cpPg.evaluate(() => {
    const form = document.querySelector('form[action*="/reject"]');
    return form ? form.getAttribute('action') : null;
  });
  if (!action) return { note: 'no reject form (empty queue)' };
  await cpPg.fill('input[id^=note-reject-]', 'Rejected by the UI visual dogfood');
  await Promise.all([cpPg.waitForNavigation({ waitUntil: 'load' }), cpPg.click('form[action*="/reject"] button[type=submit]')]);
  const flash = await cpPg.evaluate(() => (document.querySelector('#flash') || {}).innerText || '');
  return { action, flash, shot: await shot(cpPg, 'live-drafts-rejected'), note: flash.slice(0, 90) };
});

await browser.close();
fs.writeFileSync(path.join(OUT, 'probe-report.json'), JSON.stringify(report, null, 1));
console.log(`report: ${path.join(OUT, 'probe-report.json')}`);
