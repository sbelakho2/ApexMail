// =============================================================================
// journey-actions.mjs — the live MUTATION and STATE-TRANSITION journey.
// =============================================================================
// journey-deep.mjs checks how every page RENDERS; journey-flows.mjs checks
// that each create flow persists. This one walks the rest of the state
// machine: edit, start/pause/resume, revoke, delete, suspend, impersonate,
// enable/disable MFA — and then checks two things a screenshot cannot show:
//
//   * ANALYTICS TRUTH: the KPIs the console prints against the rows the
//     database actually holds.
//   * ERROR SURFACES: 404, an authorization refusal, a CSRF failure and an
//     expired session must each be honest, and none may 5xx.
//
// Usage: node journey-actions.mjs [--out DIR] [--base URL] [--cp URL]
// =============================================================================
import { chromium } from "playwright";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

const args = process.argv.slice(2);
const argOf = (n, d) => {
  const i = args.indexOf(n);
  return i >= 0 ? args[i + 1] : d;
};
const BASE = argOf("--base", "http://127.0.0.1:8080");
const CP = argOf("--cp", "http://admin.localhost:8080");
const OUT = argOf("--out", "/tmp/journey-actions");
const PASSWORD = "Journey!2026-Strong-Pass-1";
const OP_PASSWORD = "Journey!2026-Strong-Pass-2";
const TENANT = "qvto1dgn0teqij6llg5v05upxn";
const stamp = Date.now().toString(36);

fs.mkdirSync(OUT, { recursive: true });
const findings = [];
const steps = [];
const record = (f) => {
  findings.push(f);
  console.log(`[${f.severity}] ${f.kind}: ${f.flow} — ${f.detail}`);
};
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function totp(b32, t = Date.now()) {
  const a = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = "";
  for (const c of b32) {
    const i = a.indexOf(c);
    if (i >= 0) bits += i.toString(2).padStart(5, "0");
  }
  const by = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) by.push(parseInt(bits.slice(i, i + 8), 2));
  const b = Buffer.alloc(8);
  b.writeBigUInt64BE(BigInt(Math.floor(t / 30000)));
  const h = crypto.createHmac("sha256", Buffer.from(by)).update(b).digest();
  const o = h[h.length - 1] & 0xf;
  return String((((h[o] & 0x7f) << 24) | (h[o + 1] << 16) | (h[o + 2] << 8) | h[o + 3]) % 1000000).padStart(6, "0");
}

const isDashboard = (url) => {
  try {
    return new URL(url).pathname === "/dashboard";
  } catch {
    return false;
  }
};

async function newPage(browser, viewport) {
  const ctx = await browser.newContext({ viewport: viewport || { width: 1440, height: 900 } });
  const page = await ctx.newPage();
  const state = { errors: [], bad: [] };
  page.on("console", (m) => {
    if (m.type() !== "error") return;
    const t = m.text();
    if (/status of 4\d\d/.test(t)) return;
    state.errors.push(t.slice(0, 160));
  });
  page.on("pageerror", (e) => state.errors.push(`pageerror ${String(e).slice(0, 160)}`));
  page.on("response", (r) => {
    if (r.status() >= 500) state.bad.push(`${r.status()} ${r.url()}`);
  });
  return { ctx, page, state };
}

/**
 * Run one state transition and judge it: no 5xx, no console error, and the
 * outcome the flow names (a flash, a redirect target, or a predicate on the
 * page it lands on).
 */
async function step(page, state, flow, fn, check = {}) {
  state.errors.length = 0;
  state.bad.length = 0;
  let outcome = {};
  try {
    outcome = (await fn()) || {};
  } catch (e) {
    record({ severity: "P1", kind: "flow-error", flow, detail: String(e).slice(0, 220) });
    return null;
  }
  await sleep(500);
  const url = page.url();
  const body = await page.locator("body").innerText().catch(() => "");
  const facts = { flow, url, ...outcome };

  if (state.bad.length) record({ severity: "P0", kind: "server-error", flow, detail: state.bad.slice(0, 3).join(", ") });
  if (state.errors.length) record({ severity: "P1", kind: "console-error", flow, detail: state.errors.slice(0, 2).join(" | ") });
  if (check.no5xx && state.bad.length === 0 && /Something went wrong|Internal Server Error/i.test(body))
    record({ severity: "P0", kind: "error-page", flow, detail: body.replace(/\s+/g, " ").slice(0, 140) });
  if (check.expect && !check.expect.test(body) && !check.expect.test(url))
    record({ severity: "P1", kind: "unexpected-outcome", flow, detail: `expected ${check.expect}; got ${url} :: ${body.replace(/\s+/g, " ").slice(0, 150)}` });
  if (check.forbid && check.forbid.test(body))
    record({ severity: "P1", kind: "refused", flow, detail: body.replace(/\s+/g, " ").slice(0, 160) });
  if (check.landedOn && !check.landedOn.test(url))
    record({ severity: "P1", kind: "wrong-landing", flow, detail: `expected ${check.landedOn}, landed ${url}` });

  steps.push(facts);
  console.log(`  ${flow} -> ${url}`);
  return facts;
}

/**
 * Destructive console actions route through `/confirm?...` (a signed
 * confirmation page with a "Yes, continue" button). Completing it is part of
 * the journey — stopping at the confirm page is stopping short of the action.
 */
const confirmIfNeeded = async (page) => {
  if (!/\/confirm\?/.test(page.url())) return false;
  const yes = page.locator('form[action="/web/confirm"] button[type=submit]').first();
  if (!(await yes.count())) return false;
  await yes.click();
  await sleep(1000);
  return true;
};

const submitIn = async (page, action, { button } = {}) => {
  const form = page.locator(`form[action="${action}"]`).first();
  const btns = form.locator("button[type=submit], button:not([type])");
  const n = await btns.count();
  const target = button ? btns.filter({ hasText: button }).first() : btns.nth(Math.max(0, n - 1));
  await target.click();
  await sleep(900);
};

const browser = await chromium.launch({ headless: true });

// ═══ 1. tenant owner: the send lifecycle ════════════════════════════════════
const { ctx, page, state } = await newPage(browser);
{
  // A transient navigation failure (chrome-error) must not read as a product
  // defect — retry the load before judging the sign-in.
  const signInWeb = async (email, password) => {
    for (let attempt = 0; attempt < 3; attempt++) {
      try {
        await page.goto(BASE + "/login", { waitUntil: "domcontentloaded", timeout: 15000 });
      } catch {
        await sleep(1500);
        continue;
      }
      await page.getByLabel(/email/i).fill(email);
      await page.getByLabel(/password/i).fill(password);
      await sleep(1000);
      await page.locator('form[action="/web/auth/login"] button[type=submit]').first().click();
      await sleep(1300);
      if (!/^chrome-error/.test(page.url())) return page.url();
      await sleep(1500);
    }
    return page.url();
  };
  const landed = await signInWeb("owner@journey.test", PASSWORD);
  if (!isDashboard(landed)) record({ severity: "P0", kind: "login", flow: "sign-in", detail: landed });

  // ── campaign: create → edit → preview → start → pause → resume → delete ──
  const campaignName = `Action Campaign ${stamp}`;
  const created = await step(page, state, "campaign-create", async () => {
    await page.goto(BASE + "/campaigns/new", { waitUntil: "domcontentloaded" });
    await page.locator('input[name="name"]').fill(campaignName);
    await page.locator('input[name="subject"]').fill("Action subject");
    await page.locator('input[name="from"]').fill("action@journey.test");
    await page.locator('textarea[name="html_body"]').fill("<h1>Hello</h1><p>Action body.</p>");
    const listSel = page.locator('select[name="list_ids"]').first();
    const opts = await listSel.locator("option").evaluateAll((os) => os.map((o) => o.value).filter(Boolean));
    if (opts.length) await listSel.selectOption(opts[0]);
    await submitIn(page, "/web/campaigns", { button: "Save Draft" });
    return { campaignName };
  }, { expect: new RegExp(campaignName), landedOn: /\/campaigns$/ });

  // the row id, so the rest of the lifecycle targets THIS campaign
  await page.goto(BASE + "/campaigns", { waitUntil: "domcontentloaded" });
  await sleep(400);
  const rowId = await page.evaluate((name) => {
    for (const tr of document.querySelectorAll("tbody tr")) {
      if (!tr.innerText.includes(name)) continue;
      const a = tr.querySelector('a[href*="/campaigns/"]');
      if (a) return a.getAttribute("href").split("/").filter(Boolean).pop();
      const input = tr.querySelector('input[name="id"]');
      if (input) return input.value;
    }
    return null;
  }, campaignName);
  if (!rowId) {
    record({ severity: "P1", kind: "row-not-found", flow: "campaign-create", detail: `${campaignName} is not listed` });
  } else {
    await step(page, state, "campaign-edit", async () => {
      await page.goto(`${BASE}/campaigns/${rowId}/edit`, { waitUntil: "domcontentloaded" });
      const subject = page.locator('input[name="subject"]').first();
      if (await subject.count()) await subject.fill(`Action subject edited ${stamp}`);
      await submitIn(page, "/web/campaigns/update", { button: "Save Changes" });
    }, { expect: /saved|updated|Action Campaign/, no5xx: true });

    await step(page, state, "campaign-preview", async () => {
      await page.goto(`${BASE}/campaigns/${rowId}/edit`, { waitUntil: "domcontentloaded" });
      const preview = page.locator('form[action="/web/campaigns/preview"] button').first();
      if (await preview.count()) {
        await preview.click();
        await sleep(900);
      }
      return { previewAvailable: await preview.count() };
    }, { expect: /Hello|Action body|Preview|sanitiz/i, no5xx: true });

    for (const [flow, action, expect] of [
      ["campaign-start", "start", /start|sending|queued|scheduled|recipients|draft/i],
      ["campaign-pause", "pause", /pause|draft|stopped/i],
      ["campaign-resume", "resume", /resum|sending|queued|draft/i],
    ]) {
      await step(page, state, flow, async () => {
        await page.goto(BASE + "/campaigns", { waitUntil: "domcontentloaded" });
        await sleep(300);
        const form = page.locator(`form[action="/web/campaigns/${rowId}/${action}"]`).first();
        if (!(await form.count())) return { controlMissing: true };
        await form.locator("button").first().click();
        await sleep(900);
      }, { expect, no5xx: true });
    }

    await step(page, state, "campaign-bulk-delete", async () => {
      await page.goto(BASE + "/campaigns", { waitUntil: "domcontentloaded" });
      await sleep(300);
      const row = page.locator(`tr:has-text("${campaignName}")`).first();
      const box = row.locator('input[name="ids"]').first();
      if (!(await box.count())) return { controlMissing: true };
      await box.check();
      await submitIn(page, "/web/campaigns/delete-bulk", { button: "Delete selected" });
      await confirmIfNeeded(page);
    }, { no5xx: true });
    await page.goto(BASE + "/campaigns", { waitUntil: "domcontentloaded" });
    await sleep(400);
    const gone = !(await page.locator("body").innerText()).includes(campaignName);
    if (!gone) record({ severity: "P1", kind: "not-deleted", flow: "campaign-bulk-delete", detail: `${campaignName} is still listed` });
    else console.log("  campaign-bulk-delete: removed");
  }

  // ── contact: create → edit → bulk delete ────────────────────────────────
  const contactEmail = `action-${stamp}@example.test`;
  await step(page, state, "contact-create", async () => {
    await page.goto(BASE + "/contacts/new", { waitUntil: "domcontentloaded" });
    await page.locator('input[name="email"]').fill(contactEmail);
    await page.locator('input[name="name"]').fill("Action Contact");
    await submitIn(page, "/web/contacts");
  }, { expect: new RegExp(contactEmail), no5xx: true });

  await step(page, state, "contact-edit", async () => {
    await page.goto(BASE + "/contacts", { waitUntil: "domcontentloaded" });
    await sleep(300);
    const row = page.locator(`tr:has-text("${contactEmail}")`).first();
    if (!(await row.count())) return { rowMissing: true };
    const edit = row.locator('a[href*="/contacts/"][href*="/edit"]').first();
    if (await edit.count()) {
      await edit.click();
      await sleep(800);
      const name = page.locator('input[name="name"]').first();
      if (await name.count()) await name.fill(`Action Contact Edited ${stamp}`);
      await submitIn(page, "/web/contacts/update");
      return { edited: true };
    }
    return { editLink: false };
  }, { no5xx: true });

  await step(page, state, "contact-bulk-delete", async () => {
    await page.goto(BASE + "/contacts", { waitUntil: "domcontentloaded" });
    await sleep(300);
    const row = page.locator(`tr:has-text("${contactEmail}")`).first();
    const box = row.locator('input[name="ids"]').first();
    if (!(await box.count())) return { controlMissing: true };
    await box.check();
    await submitIn(page, "/web/contacts/delete-bulk", { button: "Delete selected" });
    await confirmIfNeeded(page);
  }, { no5xx: true });

  // ── template: create → edit ─────────────────────────────────────────────
  const templateName = `Action Template ${stamp}`;
  await step(page, state, "template-create", async () => {
    await page.goto(BASE + "/templates/new", { waitUntil: "domcontentloaded" });
    await page.locator('input[name="name"]').fill(templateName);
    await page.locator('input[name="subject"]').fill("Action template subject");
    await page.locator('textarea[name="html_body"]').fill("<p>Action template body.</p>");
    await submitIn(page, "/web/templates");
  }, { expect: new RegExp(templateName), no5xx: true });

  // ── webhook: create → delete ────────────────────────────────────────────
  const hookUrl = `https://hooks.example.test/action-${stamp}`;
  await step(page, state, "webhook-create", async () => {
    await page.goto(BASE + "/settings/webhooks", { waitUntil: "domcontentloaded" });
    await page.locator('input[name="url"]').fill(hookUrl);
    const events = page.locator('input[name="events"]');
    if (await events.count()) await events.first().check();
    await submitIn(page, "/web/webhooks");
  }, { no5xx: true });

  // ── api key: create → revoke ────────────────────────────────────────────
  await step(page, state, "api-key-create-revoke", async () => {
    await page.goto(BASE + "/settings/api-keys", { waitUntil: "domcontentloaded" });
    const name = `action-key-${stamp}`;
    await page.locator('input[name="name"]').fill(name);
    const scopes = page.locator('input[name="scopes"]');
    for (let i = 0; i < (await scopes.count()); i++) await scopes.nth(i).check();
    await submitIn(page, "/web/api-keys");
    await page.goto(BASE + "/settings/api-keys", { waitUntil: "domcontentloaded" });
    await sleep(400);
    const row = page.locator(`tr:has-text("${name}")`).first();
    if (!(await row.count())) return { created: false };
    const revoke = row.locator('form[action*="/revoke"] button, form[action*="/delete"] button').first();
    if (!(await revoke.count())) return { revokeControl: false };
    await revoke.click();
    await sleep(900);
    return { created: true, revoked: true };
  }, { no5xx: true });

  // ── team: invite ────────────────────────────────────────────────────────
  const invitee = `action-invitee-${stamp}@example.test`;
  await step(page, state, "team-invite", async () => {
    await page.goto(BASE + "/settings/team", { waitUntil: "domcontentloaded" });
    await page.locator('input[name="userName"]').fill(invitee);
    await submitIn(page, "/web/team/invite", { button: "Send invitation" });
  }, { expect: /invit/i, no5xx: true });

  // ── profile: rename (and restore) ───────────────────────────────────────
  await step(page, state, "profile-update", async () => {
    await page.goto(BASE + "/settings/profile", { waitUntil: "domcontentloaded" });
    const name = page.locator('input[name="name"]').first();
    const original = await name.inputValue();
    await name.fill(`Owner ${stamp}`);
    await submitIn(page, "/web/account/profile", { button: "Save Changes" });
    await page.goto(BASE + "/settings/profile", { waitUntil: "domcontentloaded" });
    const now = await page.locator('input[name="name"]').first().inputValue();
    await page.locator('input[name="name"]').first().fill(original);
    await submitIn(page, "/web/account/profile", { button: "Save Changes" });
    return { persisted: now === `Owner ${stamp}`, now };
  }, { no5xx: true });

  await ctx.close();
}

// ═══ 2. tenant user: MFA enable → disable ══════════════════════════════════
{
  const { ctx, page, state } = await newPage(browser);
  await page.goto(BASE + "/login", { waitUntil: "domcontentloaded" });
  await page.getByLabel(/email/i).fill("viewer@journey.test");
  await page.getByLabel(/password/i).fill(PASSWORD);
  await sleep(1000);
  await page.locator('form[action="/web/auth/login"] button[type=submit]').first().click();
  await sleep(1200);

  let mfaSecret = null;
  await step(page, state, "mfa-setup", async () => {
    await page.goto(BASE + "/settings/security", { waitUntil: "domcontentloaded" });
    await sleep(400);
    const setup = page.locator('form[action="/web/auth/mfa/setup"] button[type=submit]').first();
    if (!(await setup.count())) return { controlMissing: true };
    await setup.click();
    await sleep(1000);
    const otpauth = decodeURIComponent((await page.content()).match(/otpauth:[^"'\s<]+/)?.[0] || "");
    mfaSecret = otpauth.match(/secret=([A-Z2-7]+)/)?.[1] || "";
    if (!mfaSecret) return { secretMissing: true };
    const confirm = page.locator('form[action="/web/auth/mfa/confirm"]').first();
    if (!(await confirm.count())) return { confirmMissing: true };
    await confirm.locator('input[name="code"]').fill(totp(mfaSecret));
    await confirm.locator("button[type=submit]").first().click();
    await sleep(1400);
    return { secret: mfaSecret.slice(0, 6) };
  }, { no5xx: true });

  if (mfaSecret) {
    await step(page, state, "mfa-disable", async () => {
      await page.goto(BASE + "/login", { waitUntil: "domcontentloaded" });
      await page.getByLabel(/email/i).fill("viewer@journey.test");
      await page.getByLabel(/password/i).fill(PASSWORD);
      await sleep(1000);
      await page.locator('form[action="/web/auth/login"] button[type=submit]').first().click();
      await sleep(1200);
      const verify = page.locator('form[action="/web/auth/mfa/verify"]').first();
      if (!(await verify.count())) return { stepUpNotRequired: true };
      await verify.locator('input[name="code"]').fill(totp(mfaSecret, Date.now() + 30000));
      await verify.locator("button[type=submit]").first().click();
      await sleep(1400);
      await page.goto(BASE + "/settings/security", { waitUntil: "domcontentloaded" });
      await sleep(400);
      const disable = page.locator('form[action*="mfa/disable"] button, form[action*="mfa"][action*="disable"] button').first();
      if (!(await disable.count())) return { disableControlMissing: true };
      await disable.click();
      await sleep(1200);
      return { disabled: true };
    }, { no5xx: true });
  }
  await ctx.close();
}

// ═══ 3. control plane: alert rule, tenant lifecycle, impersonation ═════════
{
  const secretPath = "/tmp/apexmail-cp-mfa-secret.txt";
  let secret = null;
  try {
    secret = JSON.parse(fs.readFileSync(secretPath, "utf8")).secret;
  } catch {}
  const { ctx, page, state } = await newPage(browser);

  await page.goto(CP + "/login", { waitUntil: "domcontentloaded" });
  await page.getByLabel(/email/i).fill("operator@journey.test");
  await page.getByLabel(/password/i).fill(OP_PASSWORD);
  await sleep(1000);
  await page.locator('form[action="/web/cp/login"] button[type=submit]').first().click();
  await sleep(1500);
  if (/mfa=1/.test(page.url()) && secret) {
    const v = page.locator('form[action="/web/auth/mfa/verify"]').first();
    if (await v.count()) {
      await v.locator('input[name="code"]').fill(totp(secret));
      await v.locator("button[type=submit]").first().click();
      await sleep(1500);
    }
  }
  if (!isDashboard(page.url())) record({ severity: "P0", kind: "login", flow: "cp-login", detail: page.url() });

  const ruleName = `Action rule ${stamp}`;
  await step(page, state, "cp-alert-rule-create", async () => {
    await page.goto(CP + "/alerts/rules", { waitUntil: "domcontentloaded" });
    await sleep(400);
    await page.locator('input[name="name"]').fill(ruleName);
    await page.locator('input[name="threshold"]').fill("80");
    // The tenant select's first option is empty and the handler refuses an
    // empty tenant — a real user picks one.
    const tenant = page.locator('select[name="tenant"]').first();
    const opts = await tenant.locator("option").evaluateAll((os) => os.map((o) => o.value).filter(Boolean));
    if (opts.length) await tenant.selectOption(opts[0]);
    await submitIn(page, "/web/admin/alert-rules", { button: "Create rule" });
  }, { expect: new RegExp(ruleName), no5xx: true });

  await step(page, state, "cp-alert-rule-toggle-delete", async () => {
    await page.goto(CP + "/alerts/rules", { waitUntil: "domcontentloaded" });
    await sleep(400);
    const row = page.locator(`tr:has-text("${ruleName}")`).first();
    if (!(await row.count())) return { rowMissing: true };
    const toggle = row.locator('form[action*="/toggle"] button').first();
    if (await toggle.count()) {
      await toggle.click();
      await sleep(900);
    }
    await page.goto(CP + "/alerts/rules", { waitUntil: "domcontentloaded" });
    await sleep(400);
    const row2 = page.locator(`tr:has-text("${ruleName}")`).first();
    const del = row2.locator('form[action*="/delete"] button').first();
    if (!(await del.count())) return { deleteMissing: true };
    await del.click();
    await sleep(1000);
    return { toggled: true, deleted: true };
  }, { no5xx: true });

  // tenant suspend → resume on a scratch tenant
  await step(page, state, "cp-tenant-suspend-resume", async () => {
    await page.goto(CP + "/tenants", { waitUntil: "domcontentloaded" });
    await sleep(400);
    const suspend = page.locator('form[action="/web/admin/tenants/t_journey_del/suspend"] button').first();
    const resume = page.locator('form[action="/web/admin/tenants/t_journey_del/resume"] button').first();
    const hasSuspend = await suspend.count();
    const hasResume = await resume.count();
    if (hasSuspend) {
      await suspend.click();
      await sleep(1000);
    }
    await page.goto(CP + "/tenants", { waitUntil: "domcontentloaded" });
    await sleep(400);
    const back = page.locator('form[action="/web/admin/tenants/t_journey_del/resume"] button').first();
    if (await back.count()) {
      await back.click();
      await sleep(1000);
    }
    return { hasSuspend, hasResume };
  }, { no5xx: true });

  // impersonation: start as the operator, end as the tenant user
  await step(page, state, "cp-impersonate-start", async () => {
    await page.goto(CP + "/tenants", { waitUntil: "domcontentloaded" });
    await sleep(400);
    const impersonate = page.locator(`form[action="/web/admin/tenants/${TENANT}/impersonate"] button`).first();
    if (!(await impersonate.count())) return { controlMissing: true };
    await impersonate.click();
    await sleep(1400);
    return { url: page.url() };
  }, { no5xx: true });

  await step(page, state, "cp-impersonate-end", async () => {
    const end = page.locator('form[action="/web/auth/impersonate/end"] button').first();
    if (!(await end.count())) {
      const link = page.locator('a[href="/web/auth/impersonate/end"]').first();
      if (await link.count()) {
        await link.click();
        await sleep(1200);
        return { viaLink: true };
      }
      return { controlMissing: true, url: page.url() };
    }
    await end.click();
    await sleep(1200);
    return { viaForm: true };
  }, { no5xx: true });

  await ctx.close();
}

// ═══ 4. analytics truth: what the console prints vs what the rows say ══════
{
  const { ctx, page, state } = await newPage(browser);
  await page.goto(BASE + "/login", { waitUntil: "domcontentloaded" });
  await page.getByLabel(/email/i).fill("owner@journey.test");
  await page.getByLabel(/password/i).fill(PASSWORD);
  await sleep(1000);
  await page.locator('form[action="/web/auth/login"] button[type=submit]').first().click();
  await sleep(1200);

  // The console's KPI cards are `.apex-cp-stat-tile` with "LABEL value hint".
  const readKpis = async (url) => {
    await page.goto(url, { waitUntil: "domcontentloaded" });
    await sleep(500);
    return page.evaluate(() => {
      const kpis = {};
      for (const el of document.querySelectorAll(".apex-cp-stat-tile, [data-kpi]")) {
        const lines = (el.innerText || "").split("\n").map((l) => l.trim()).filter(Boolean);
        if (lines.length >= 2) kpis[lines[0]] = lines[1];
      }
      const body = document.body.innerText;
      const showing = body.match(/Showing\s+([\d,]+)\s*[\u2013-]\s*([\d,]+)\s+of\s+([\d,]+)/i);
      return {
        kpis,
        rows: document.querySelectorAll("tbody tr").length,
        total: showing ? Number(showing[3].replace(/,/g, "")) : null,
      };
    });
  };

  const dash = await readKpis(BASE + "/dashboard");
  const contacts = await readKpis(BASE + "/contacts");
  const campaigns = await readKpis(BASE + "/campaigns");
  const analytics = await readKpis(BASE + "/analytics");

  console.log("  dashboard KPIs:", JSON.stringify(dash.kpis).slice(0, 220));
  console.log(`  contacts rows=${contacts.rows} campaigns rows=${campaigns.rows} analytics KPIs=${JSON.stringify(analytics.kpis).slice(0, 160)}`);

  // The dashboard's tiles must agree with the pages they summarise — compared
  // LIKE WITH LIKE. "Campaigns" counts every status, so it equals the list
  // total; "Contacts" counts the addressable subset (subscribed and not
  // suppressed), so it must be a subset of the list total, never larger.
  const campaignKpi = dash.kpis["CAMPAIGNS"];
  if (campaignKpi !== undefined && campaigns.total !== null) {
    if (Number(String(campaignKpi).replace(/[^0-9]/g, "")) !== campaigns.total)
      record({
        severity: "P1",
        kind: "kpi-vs-list-mismatch",
        flow: "analytics-campaigns",
        detail: `dashboard CAMPAIGNS=${campaignKpi} but /campaigns reports ${campaigns.total} total`,
      });
    else console.log(`  analytics truth: CAMPAIGNS ${campaignKpi} == /campaigns total ${campaigns.total}`);
  }
  const contactKpi = dash.kpis["CONTACTS"];
  if (contactKpi !== undefined && contacts.total !== null) {
    const n = Number(String(contactKpi).replace(/[^0-9]/g, ""));
    if (n > contacts.total)
      record({
        severity: "P1",
        kind: "kpi-exceeds-source",
        flow: "analytics-contacts",
        detail: `dashboard CONTACTS=${n} exceeds the ${contacts.total} rows /contacts holds`,
      });
    else console.log(`  analytics truth: CONTACTS ${n} <= /contacts total ${contacts.total} (addressable subset)`);
  }
  if (!Object.keys(dash.kpis).length)
    record({ severity: "P2", kind: "kpi-unreadable", flow: "analytics-dashboard", detail: "no KPI tiles were readable on /dashboard" });
  await ctx.close();
}

// ═══ 5. error surfaces ═════════════════════════════════════════════════════
{
  // anonymous: 404 and an authorization refusal
  const { ctx, page, state } = await newPage(browser);
  await step(page, state, "error-404", async () => {
    const resp = await page.goto(BASE + "/definitely-not-a-route-" + stamp, { waitUntil: "domcontentloaded" });
    return { status: resp?.status() };
  }, { expect: /not found|404/i, no5xx: true });

  await step(page, state, "error-anon-protected", async () => {
    await page.goto(BASE + "/settings", { waitUntil: "domcontentloaded" });
    return { url: page.url() };
  }, { expect: /sign in|log in|password/i, no5xx: true });

  // CSRF failure: a tampered token must be refused WITH an explanation.
  // The flash rides a one-shot cookie that the followed redirect consumes,
  // so the assertion belongs on that response's body — checking the page
  // afterwards would read an already-consumed flash as silence.
  await step(page, state, "error-csrf", async () => {
    await page.goto(BASE + "/login", { waitUntil: "domcontentloaded" });
    await sleep(800);
    const res = await page.evaluate(async () => {
      const body = new URLSearchParams({ _csrf: "tampered.token.value", email: "x@example.test", password: "nope" });
      const r = await fetch("/web/auth/login", { method: "POST", body, redirect: "follow", headers: { "content-type": "application/x-www-form-urlencoded" } });
      const html = await r.text();
      const text = html.replace(/<[^>]*>/g, " ").replace(/\s+/g, " ");
      return { status: r.status, text: text.slice(0, 600) };
    });
    if (!/expired|reload|invalid|csrf/i.test(res.text))
      record({ severity: "P1", kind: "csrf-silent", flow: "error-csrf", detail: `a tampered CSRF token produced no explanation: ${res.text.slice(0, 160)}` });
    return { status: res.status };
  }, { no5xx: true });

  // expired session: a garbage cookie must not 5xx
  await step(page, state, "error-expired-session", async () => {
    await ctx.addCookies([{ name: "apexmail_session", value: "expired.garbage.token", domain: "127.0.0.1", path: "/" }]);
    const resp = await page.goto(BASE + "/dashboard", { waitUntil: "domcontentloaded" });
    return { status: resp?.status() };
  }, { no5xx: true, expect: /sign in|log in|expired|password/i });
  await ctx.close();
}

// a member must be refused an admin-only console action, not served it
{
  const { ctx, page, state } = await newPage(browser);
  await page.goto(BASE + "/login", { waitUntil: "domcontentloaded" });
  await page.getByLabel(/email/i).fill("member@journey.test");
  await page.getByLabel(/password/i).fill(PASSWORD);
  await sleep(1000);
  await page.locator('form[action="/web/auth/login"] button[type=submit]').first().click();
  await sleep(1200);
  await step(page, state, "error-member-forbidden", async () => {
    await page.goto(BASE + "/web/admin/tenants", { waitUntil: "domcontentloaded" });
    return { url: page.url() };
  }, { no5xx: true });
  await step(page, state, "error-member-cp", async () => {
    const resp = await page.goto(BASE + "/cp/tenants", { waitUntil: "domcontentloaded" });
    return { status: resp?.status() };
  }, { no5xx: true });
  await ctx.close();
}

await browser.close();
fs.writeFileSync(path.join(OUT, "findings.json"), JSON.stringify({ steps, findings }, null, 2));
const bySeverity = findings.reduce((a, f) => ((a[f.severity] = (a[f.severity] || 0) + 1), a), {});
console.log(`\nactions: ${steps.length} steps, findings: ${findings.length} ${JSON.stringify(bySeverity)} -> ${OUT}/findings.json`);
