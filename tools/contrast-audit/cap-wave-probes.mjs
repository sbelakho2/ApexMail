// Capability-wave live probes (2026-10-08): alert-rules CRUD, message
// timeline states, custom tracking-domain states. Drives the shipped forms
// and seeds the data the product needs for the deeper states.
import { chromium } from 'playwright';
import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';

const OUT = path.resolve('reports/cap-wave-live');
fs.mkdirSync(OUT, { recursive: true });
const session = JSON.parse(fs.readFileSync('/tmp/ui_session.json', 'utf8'));
const cp = JSON.parse(fs.readFileSync('/tmp/cp_session.json', 'utf8'));
const WEB = 'http://127.0.0.1:8080';
const CP = 'http://admin.localhost:8080';
const report = { generated: new Date().toISOString(), steps: [] };

const psql = (q) => execFileSync('docker', ['exec', 'apexmail-postgres', 'psql', '-U', 'apexmail', '-d', 'apexmail', '-t', '-A', '-c', q], { encoding: 'utf8' }).trim();
const cookiesFor = (base, header) => header.split(';').map((pair) => {
  const [name, ...rest] = pair.trim().split('=');
  return { name, value: rest.join('='), url: base };
}).filter((c) => c.name && c.value !== undefined);

const browser = await chromium.launch({ channel: 'chromium' });
const step = async (name, fn) => {
  const entry = { name };
  try { Object.assign(entry, await fn()); } catch (e) { entry.error = String(e).slice(0, 400); }
  report.steps.push(entry);
  console.log(`${entry.error ? 'ERROR' : 'ok'} ${name} ${entry.note || ''}`);
};
const shot = async (pg, name) => { await pg.screenshot({ path: path.join(OUT, `${name}.png`), fullPage: true }); return `${name}.png`; };

// ── 1. CP /alerts/rules CRUD ────────────────────────────────────────────
const cpCtx = await browser.newContext({ viewport: { width: 1280, height: 900 } });
await cpCtx.addCookies(cookiesFor(CP, cp.cookie));
let cpPg = await cpCtx.newPage();

await step('alerts-rules-list', async () => {
  await cpPg.goto(`${CP}/alerts/rules`, { waitUntil: 'load' });
  const state = await cpPg.evaluate(() => ({
    title: document.title,
    hasCreate: !!document.querySelector('form[data-form-id="alert-rule-create"]'),
    rows: document.querySelectorAll('form[action*="/toggle"]').length,
    unavailable: document.body.innerText.includes('unavailable right now'),
    empty: document.body.innerText.includes('No alert rules yet'),
  }));
  return { state, shot: await shot(cpPg, 'alerts-rules-01-list'), note: JSON.stringify(state) };
});

let createdRuleId = '';
await step('alerts-rules-create', async () => {
  const tenantOption = await cpPg.evaluate(() => {
    const sel = document.querySelector('#rule-tenant');
    const opt = [...sel.options].find((o) => o.value);
    return opt ? opt.value : '';
  });
  if (!tenantOption) return { note: 'no tenant option available' };
  await cpPg.selectOption('#rule-tenant', tenantOption);
  await cpPg.fill('#rule-name', 'UI visual dogfood rule');
  await cpPg.selectOption('#rule-metric', 'emails');
  await cpPg.fill('#rule-threshold', '87');
  await cpPg.selectOption('#rule-channel', 'email');
  await cpPg.selectOption('#rule-severity', 'warning');
  await Promise.all([
    cpPg.waitForNavigation({ waitUntil: 'load' }),
    cpPg.click('form[data-form-id="alert-rule-create"] button[type=submit]'),
  ]);
  const state = await cpPg.evaluate(() => ({
    flash: (document.querySelector('#flash') || {}).innerText || '',
    hasRule: document.body.innerText.includes('UI visual dogfood rule'),
    editHref: (document.querySelector('a[href*="?edit="]') || {}).getAttribute
      ? document.querySelector('a[href*="?edit="]').getAttribute('href')
      : null,
  }));
  createdRuleId = (state.editHref || '').split('edit=')[1] || '';
  return { state, shot: await shot(cpPg, 'alerts-rules-02-created'), note: `flash=${state.flash.replace(/\n/g, ' ')} id=${createdRuleId}` };
});

await step('alerts-rules-edit-form', async () => {
  if (!createdRuleId) return { note: 'no rule id' };
  await cpPg.goto(`${CP}/alerts/rules?edit=${createdRuleId}`, { waitUntil: 'load' });
  const state = await cpPg.evaluate(() => ({
    hasEditForm: !!document.querySelector('form[data-form-id="alert-rule-edit"]'),
    nameValue: (document.querySelector('#rule-edit-name') || {}).value || '',
    thresholdValue: (document.querySelector('#rule-edit-threshold') || {}).value || '',
    fixedNote: document.body.innerText.includes('fixed — delete and recreate'),
  }));
  return { state, shot: await shot(cpPg, 'alerts-rules-03-edit'), note: JSON.stringify(state) };
});

await step('alerts-rules-toggle', async () => {
  if (!createdRuleId) return { note: 'no rule id' };
  await cpPg.goto(`${CP}/alerts/rules`, { waitUntil: 'load' });
  await Promise.all([
    cpPg.waitForNavigation({ waitUntil: 'load' }),
    cpPg.click(`form[action="/web/admin/alert-rules/${createdRuleId}/toggle"] button[type=submit]`),
  ]);
  const state = await cpPg.evaluate(() => ({
    flash: (document.querySelector('#flash') || {}).innerText || '',
    disabledShown: document.body.innerText.includes('Disabled'),
    enableLabel: document.body.innerText.includes('Enable') && !document.body.innerText.includes('Disable'),
  }));
  const dbEnabled = psql(`SELECT enabled FROM usage_alert_configs WHERE id='${createdRuleId}'`);
  return { state, dbEnabled, shot: await shot(cpPg, 'alerts-rules-04-disabled'), note: `db=${dbEnabled} ${state.flash.replace(/\n/g, ' ')}` };
});

await step('alerts-rules-delete', async () => {
  if (!createdRuleId) return { note: 'no rule id' };
  await Promise.all([
    cpPg.waitForNavigation({ waitUntil: 'load' }),
    cpPg.click(`form[action="/web/admin/alert-rules/${createdRuleId}/delete"] button[type=submit]`),
  ]);
  const state = await cpPg.evaluate(() => ({
    flash: (document.querySelector('#flash') || {}).innerText || '',
    stillThere: document.body.innerText.includes('UI visual dogfood rule'),
  }));
  const dbCount = psql(`SELECT count(*) FROM usage_alert_configs WHERE id='${createdRuleId}'`);
  return { state, dbCount, shot: await shot(cpPg, 'alerts-rules-05-deleted'), note: `db=${dbCount} ${state.flash.replace(/\n/g, ' ')}` };
});
await cpCtx.close();

// ── 2. Timeline: populated (system tenant) + refusals ───────────────────
const sysMsg = psql("SELECT m.id FROM messages m WHERE m.tenant_id='system_internal_tenant01' AND EXISTS (SELECT 1 FROM events e WHERE e.message_id::text = m.id::text) ORDER BY m.created_at DESC LIMIT 1");
const sysTenant = 'system_internal_tenant01';
// The capability wave grants time_travel_debugging in builtin_plan_seed, but
// the seeded plans.features JSON rows predate it (every plan reports false),
// so the runtime escape hatch is the per-tenant override — the same one the
// docs describe. Grant it to the message's tenant for the populated capture.
psql(`INSERT INTO feature_flag_overrides (tenant_id, flag_key, value) VALUES ('${sysTenant}','time_travel_debugging','true'::jsonb) ON CONFLICT (tenant_id, flag_key) DO UPDATE SET value='true'::jsonb`);
console.log('system message', sysMsg);

const sysCtx = await browser.newContext({ viewport: { width: 1280, height: 900 } });
await sysCtx.addCookies(cookiesFor(WEB, cp.cookie)); // the CP jar carries the system am_session
const sysPg = await sysCtx.newPage();
await step('timeline-populated', async () => {
  await sysPg.goto(`${WEB}/messages/${sysMsg}/timeline`, { waitUntil: 'load' });
  const state = await sysPg.evaluate(() => ({
    url: location.pathname,
    title: document.title,
    h1: (document.querySelector('h1') || {}).innerText || '',
    kpis: [...document.querySelectorAll('[class*="apex-kpi"], dt, .apex-panel-title')].map((e) => e.innerText).slice(0, 6),
    tableRows: document.querySelectorAll('tbody tr').length,
    empty: document.body.innerText.includes('No state transitions at this timestamp'),
    insufficient: document.body.innerText.includes('insufficient'),
    flash: (document.querySelector('#flash') || {}).innerText || '',
  }));
  return { state, shot: await shot(sysPg, 'timeline-01-populated'), note: `rows=${state.tableRows} url=${state.url}` };
});
await sysCtx.close();

const freeCtx = await browser.newContext({ viewport: { width: 1280, height: 900 } });
await freeCtx.addCookies(cookiesFor(WEB, session.cookie));
const freePg = await freeCtx.newPage();
const freeTenant = psql(`SELECT tenant_id FROM users WHERE email='${session.email}'`);
const freeMsgId = '11111111-1111-4111-8111-111111111111';
await step('timeline-seed-free-message', async () => {
  psql(`DELETE FROM messages WHERE id='${freeMsgId}'`);
  psql(
  "INSERT INTO messages (id, tenant_id, from_email, to_addresses, to_emails, status, message_category) " +
    `VALUES ('${freeMsgId}', '${freeTenant}', 'ui-visual@apexmail.local', ARRAY['recipient@example.test'], '["recipient@example.test"]'::jsonb, 'delivered', 'marketing')`
  );
  return { note: `seeded ${freeMsgId} for ${freeTenant}` };
});
await step('timeline-entitlement-refusal', async () => {
  await freePg.goto(`${WEB}/messages/${freeMsgId}/timeline`, { waitUntil: 'load' });
  const state = await freePg.evaluate(() => ({
    url: location.pathname,
    flash: (document.querySelector('#flash') || {}).innerText || '',
  }));
  return { state, shot: await shot(freePg, 'timeline-02-entitlement'), note: `url=${state.url} ${state.flash.replace(/\n/g, ' ')}` };
});
await step('timeline-not-found', async () => {
  const bogus = '00000000-0000-4000-8000-000000000abc';
  await freePg.goto(`${WEB}/messages/${bogus}/timeline`, { waitUntil: 'load' });
  const state = await freePg.evaluate(() => ({
    url: location.pathname,
    flash: (document.querySelector('#flash') || {}).innerText || '',
  }));
  return { state, shot: await shot(freePg, 'timeline-03-not-found'), note: `url=${state.url} ${state.flash.replace(/\n/g, ' ')}` };
});

// ── 3. Tracking-domain states (customer tenant) ─────────────────────────
const customerTenant = psql(`SELECT tenant_id FROM users WHERE email='${session.email}'`);
const domainName = `ui-visual-${Date.now().toString(36)}.test`;
let domainId = '';
await step('tracking-create-domain', async () => {
  await freePg.goto(`${WEB}/domains/new`, { waitUntil: 'load' });
  await freePg.fill('#domain-name', domainName).catch(async () => {
    await freePg.fill('input[name="name"]', domainName);
  });
  await Promise.all([
    freePg.waitForNavigation({ waitUntil: 'load' }),
    freePg.click('form[action="/web/domains"] button[type=submit]'),
  ]);
  const url = new URL(freePg.url());
  domainId = url.pathname.split('/')[2] || '';
  const state = { url: url.pathname, domainId, hasTrackingLink: await freePg.evaluate(() => !!document.querySelector('a[href$="/tracking"]')) };
  return { state, shot: await shot(freePg, 'tracking-00-domain-detail'), note: JSON.stringify(state) };
});

await step('tracking-not-verified', async () => {
  if (!domainId) return { note: 'no domain id' };
  await freePg.goto(`${WEB}/domains/${domainId}/tracking`, { waitUntil: 'load' });
  const state = await freePg.evaluate(() => ({
    title: document.title,
    notVerified: document.body.innerText.includes('first. A tracking domain must be a subdomain of a verified domain'),
    notEntitled: document.body.innerText.includes('Pro and above'),
    hasForm: !!document.querySelector('form[data-form-id="tracking-domain-create"]'),
  }));
  return { state, shot: await shot(freePg, 'tracking-01-not-verified'), note: JSON.stringify(state) };
});

await step('tracking-not-entitled', async () => {
  psql(`UPDATE domains SET verified = true, status = 'verified' WHERE id = '${domainId}'`);
  await freePg.goto(`${WEB}/domains/${domainId}/tracking`, { waitUntil: 'load' });
  const state = await freePg.evaluate(() => ({
    notEntitled: document.body.innerText.includes('Pro and above'),
    hasForm: !!document.querySelector('form[data-form-id="tracking-domain-create"]'),
    text: document.body.innerText.replace(/\s+/g, ' ').slice(0, 220),
  }));
  return { state, shot: await shot(freePg, 'tracking-02-not-entitled'), note: JSON.stringify({ notEntitled: state.notEntitled, hasForm: state.hasForm }) };
});

await step('tracking-configure-form', async () => {
  // Same stale-plan-metadata story as the timeline: grant the capability via
  // the per-tenant override the runtime supports.
  psql(`INSERT INTO feature_flag_overrides (tenant_id, flag_key, value) VALUES ('${customerTenant}','custom_tracking_domain','true'::jsonb) ON CONFLICT (tenant_id, flag_key) DO UPDATE SET value='true'::jsonb`);
  await freePg.goto(`${WEB}/domains/${domainId}/tracking`, { waitUntil: 'load' });
  const state = await freePg.evaluate(() => ({
    hasForm: !!document.querySelector('form[data-form-id="tracking-domain-create"]'),
    intro: document.body.innerText.includes('Use your own subdomain'),
  }));
  return { state, shot: await shot(freePg, 'tracking-03-configure'), note: JSON.stringify(state) };
});

async function captureConfigured(status, reason) {
  const domain = `track-${Date.now().toString(36)}.${domainName}`;
  psql(`DELETE FROM tracking_domains WHERE tenant_id='${customerTenant}'`);
  psql(
    "INSERT INTO tracking_domains (tenant_id, domain, parent_domain, status, status_reason, cname_target, verified_at) " +
    `VALUES ('${customerTenant}', '${domain}', '${domainName}', '${status}', ${reason ? `'${reason}'` : 'NULL'}, 'trk.apexmail.ee', ${status === 'verified' ? 'now()' : 'NULL'})`
  );
  await freePg.goto(`${WEB}/domains/${domainId}/tracking`, { waitUntil: 'load' });
  const state = await freePg.evaluate(() => ({
    text: document.body.innerText.replace(/\s+/g, ' ').slice(0, 400),
    hasVerify: document.body.innerText.includes('Verify DNS now'),
    hasRemove: document.body.innerText.includes('Remove'),
    cnameShown: document.body.innerText.includes('trk.apexmail.ee'),
  }));
  return state;
}

for (const [status, reason] of [
  ['pending', null],
  ['verified', null],
  ['failed', 'CNAME points at trk.other.test, expected trk.apexmail.ee'],
]) {
  await step(`tracking-${status}`, async () => {
    const state = await captureConfigured(status, reason);
    return { state, shot: await shot(freePg, `tracking-04-${status}`), note: JSON.stringify({ hasVerify: state.hasVerify, cname: state.cnameShown }) };
  });
}

await step('tracking-cleanup', async () => {
  psql(`DELETE FROM tracking_domains WHERE tenant_id='${customerTenant}'`);
  psql(`DELETE FROM feature_flag_overrides WHERE tenant_id='${customerTenant}' AND flag_key='custom_tracking_domain'`);
  psql(`DELETE FROM domains WHERE id = '${domainId}'`);
  psql(`DELETE FROM messages WHERE id='${freeMsgId}'`);
  return { note: 'tracking row + domain + seeded message removed, override cleared' };
});

await browser.close();
fs.writeFileSync(path.join(OUT, 'probe-report.json'), JSON.stringify(report, null, 1));
console.log('report:', path.join(OUT, 'probe-report.json'));
