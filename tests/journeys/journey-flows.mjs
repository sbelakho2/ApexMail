// =============================================================================
// journey-flows.mjs — the live INTERACTION journey for ApexMail.
// =============================================================================
// journey-wide.mjs walks every route and checks how each page RENDERS. This
// script does the other half: it performs the console's real create/mutate
// flows end to end through the rendered forms, and asserts the OUTCOME —
// a redirect away from the form, a success signal, and the new object
// appearing where the user would look for it.
//
// Every step records: HTTP status, console errors, page errors, the landing
// URL, the flash text, and whether the object materialised in its list.
//
// Usage:  node journey-flows.mjs [--out DIR] [--base URL]
//
// Output: $OUT/flows.json + $OUT/shots/<flow>.png
// =============================================================================
import { chromium } from "playwright";
import fs from "node:fs";
import path from "node:path";

const args = process.argv.slice(2);
const argOf = (n, d) => {
  const i = args.indexOf(n);
  return i >= 0 ? args[i + 1] : d;
};
const BASE = argOf("--base", "http://127.0.0.1:8080");
const OUT = argOf("--out", "/tmp/journey-flows");
const PASSWORD = "Journey!2026-Strong-Pass-1";
const stamp = Date.now().toString(36);

fs.mkdirSync(path.join(OUT, "shots"), { recursive: true });

const findings = [];
const flows = [];
const record = (f) => {
  findings.push(f);
  console.log(`[${f.severity}] ${f.kind}: ${f.flow} — ${f.detail}`);
};

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/** A unique-ish value so repeated runs never collide on a unique index. */
const uniq = (prefix) => `${prefix}-${stamp}`;

async function newPage(browser) {
  const ctx = await browser.newContext({ viewport: { width: 1440, height: 900 } });
  const page = await ctx.newPage();
  const state = { role: "-", page: "-", consoleErrors: [], pageErrors: [], bad: [] };
  page.on("console", (m) => {
    if (m.type() !== "error") return;
    const t = m.text();
    // A 4xx the flow deliberately provokes is not a defect.
    if (/status of 4\d\d/.test(t)) return;
    state.consoleErrors.push(t.slice(0, 200));
  });
  page.on("pageerror", (e) => state.pageErrors.push(String(e).slice(0, 200)));
  page.on("response", (r) => {
    if (r.status() >= 500) state.bad.push(`${r.status()} ${r.url()}`);
  });
  return { ctx, page, state };
}

/**
 * Run one flow: drive the form, then judge the outcome.
 *
 * `expect` names the list URL where the new object must appear, and `marker`
 * the text that identifies it. A flow fails when the form bounces back to
 * itself with an error, when the server 5xxs, or when the object never shows
 * up in its list.
 */
async function flow(page, state, name, fn, { expect, marker } = {}) {
  state.consoleErrors.length = 0;
  state.pageErrors.length = 0;
  state.bad.length = 0;

  let outcome;
  try {
    outcome = await fn();
  } catch (e) {
    record({ severity: "P1", kind: "flow-error", flow: name, detail: String(e).slice(0, 240) });
    return null;
  }

  const url = page.url();
  const flash = await page
    .locator("[role=alert], .apex-flash, [data-flash], #app-main p")
    .allInnerTexts()
    .then((t) => t.join(" | ").replace(/\s+/g, " ").slice(0, 200))
    .catch(() => "");

  const facts = { flow: name, url, flash, ...outcome };

  if (state.bad.length) {
    record({ severity: "P0", kind: "server-error", flow: name, detail: state.bad.join(", ") });
  }
  if (state.pageErrors.length) {
    record({ severity: "P0", kind: "page-error", flow: name, detail: state.pageErrors.join(" | ") });
  }
  if (state.consoleErrors.length) {
    record({ severity: "P1", kind: "console-error", flow: name, detail: state.consoleErrors.join(" | ") });
  }

  // A form that bounces straight back with an error is a refused journey.
  if (/\/(new|invite)$/.test(url) && flash) {
    record({ severity: "P1", kind: "form-refused", flow: name, detail: `bounced to ${url}: ${flash}` });
  }

  if (expect && marker) {
    await page.goto(expect, { waitUntil: "domcontentloaded" });
    await sleep(350);
    const body = await page.locator("body").innerText().catch(() => "");
    facts.materialised = body.includes(marker);
    if (!facts.materialised) {
      record({
        severity: "P1",
        kind: "not-persisted",
        flow: name,
        detail: `"${marker}" did not appear at ${expect}`,
      });
    }
  }

  await page.screenshot({ path: path.join(OUT, "shots", `${name}.png`) }).catch(() => {});
  flows.push(facts);
  console.log(`  ok ${name} -> ${url}${facts.materialised === undefined ? "" : ` materialised=${facts.materialised}`}`);
  return facts;
}

/** Fill a field by its form-control name, whatever the control type is. */
async function setField(page, name, value) {
  const sel = `[name="${name}"]`;
  const el = page.locator(sel).first();
  const tag = await el.evaluate((e) => e.tagName.toLowerCase());
  const type = (await el.getAttribute("type")) || "";
  if (tag === "select") {
    const opts = await el.locator("option").evaluateAll((os) => os.map((o) => o.value).filter(Boolean));
    if (opts.length) await el.selectOption(opts[0]);
    return;
  }
  if (type === "checkbox" || type === "radio") {
    if (!(await el.isChecked())) await el.check();
    return;
  }
  await el.fill(value);
}

async function submitForm(page, action, { button } = {}) {
  const form = page.locator(`form[action="${action}"]`).first();
  // Several editors carry more than one submit control (Preview, Save as
  // draft, Save). Pick by label when the flow names one; otherwise the LAST
  // submit, because the primary save sits at the end of the action row while
  // the leading button is Preview.
  const candidates = form.locator("button[type=submit], button:not([type])");
  const n = await candidates.count();
  const target = button ? candidates.filter({ hasText: button }).first() : candidates.nth(n - 1);
  await target.click();
  await sleep(900);
}

const browser = await chromium.launch({ headless: true });
const { ctx, page, state } = await newPage(browser);

// ── sign in ──────────────────────────────────────────────────────────────────
await page.goto(BASE + "/login", { waitUntil: "domcontentloaded" });
await page.getByLabel(/email/i).fill("owner@journey.test");
await page.getByLabel(/password/i).fill(PASSWORD);
await sleep(1300);
await page.locator("button[type=submit]").click();
await sleep(1000);
if (!/dashboard/.test(page.url())) {
  record({ severity: "P0", kind: "login", flow: "sign-in", detail: `landed ${page.url()}` });
  await browser.close();
  fs.writeFileSync(path.join(OUT, "flows.json"), JSON.stringify({ flows, findings }, null, 2));
  process.exit(1);
}

// ── 1. contact create ────────────────────────────────────────────────────────
const contactEmail = `${uniq("flow")}@example.test`;
await flow(
  page,
  state,
  "contact-create",
  async () => {
    await page.goto(BASE + "/contacts/new", { waitUntil: "domcontentloaded" });
    await setField(page, "email", contactEmail);
    await setField(page, "name", "Flow Contact");
    await submitForm(page, "/web/contacts");
    return { email: contactEmail };
  },
  { expect: BASE + "/contacts", marker: contactEmail },
);

// ── 2. list create, then add the contact to it ───────────────────────────────
const listName = uniq("Flow List");
await flow(
  page,
  state,
  "list-create",
  async () => {
    await page.goto(BASE + "/lists/new", { waitUntil: "domcontentloaded" });
    await setField(page, "name", listName);
    await submitForm(page, "/web/lists");
    return { listName };
  },
  { expect: BASE + "/lists", marker: listName },
);

// ── 3. template create ───────────────────────────────────────────────────────
const templateName = uniq("Flow Template");
await flow(
  page,
  state,
  "template-create",
  async () => {
    await page.goto(BASE + "/templates/new", { waitUntil: "domcontentloaded" });
    await setField(page, "name", templateName);
    await setField(page, "subject", "Flow subject {{name}}");
    await setField(page, "html_body", "<h1>Hello {{name}}</h1><p>Flow body.</p>");
    await submitForm(page, "/web/templates");
    return { templateName };
  },
  { expect: BASE + "/templates", marker: templateName },
);

// ── 4. domain create ─────────────────────────────────────────────────────────
const domainName = `${uniq("flow")}.example.test`;
await flow(
  page,
  state,
  "domain-create",
  async () => {
    await page.goto(BASE + "/domains/new", { waitUntil: "domcontentloaded" });
    await setField(page, "name", domainName);
    await submitForm(page, "/web/domains");
    return { domainName };
  },
  { expect: BASE + "/domains", marker: domainName },
);

// ── 5. campaign create (real list + real body) ───────────────────────────────
const campaignName = uniq("Flow Campaign");
await flow(
  page,
  state,
  "campaign-create",
  async () => {
    await page.goto(BASE + "/campaigns/new", { waitUntil: "domcontentloaded" });
    await setField(page, "name", campaignName);
    await setField(page, "subject", "Flow campaign subject");
    await setField(page, "from", "flow@journey.test");
    await setField(page, "from_name", "Flow Sender");
    await setField(page, "html_body", "<h1>Hello</h1><p>Flow campaign body.</p>");
    // The list select is the one control whose options are real list ids.
    const listSel = page.locator('select[name="list_ids"]').first();
    const listOpts = await listSel.locator("option").evaluateAll((os) => os.map((o) => o.value).filter(Boolean));
    if (listOpts.length) await listSel.selectOption(listOpts[0]);
    else record({ severity: "P1", kind: "no-lists", flow: "campaign-create", detail: "the list select offered no lists" });
    await submitForm(page, "/web/campaigns", { button: "Save Draft" });
    return { campaignName, listOpts: listOpts.length };
  },
  { expect: BASE + "/campaigns", marker: campaignName },
);

// ── 6. campaign preview (a real POST that renders the email) ─────────────────
await flow(page, state, "campaign-preview", async () => {
  await page.goto(BASE + "/campaigns", { waitUntil: "domcontentloaded" });
  await sleep(300);
  const previewBtn = page.locator('form[action="/web/campaigns/preview"] button').first();
  if (await previewBtn.count()) {
    await previewBtn.click();
    await sleep(800);
    return { clicked: true, previewLen: (await page.locator("body").innerText()).length };
  }
  return { clicked: false, note: "no preview form on the campaigns list" };
});

// ── 7. webhook create ────────────────────────────────────────────────────────
const webhookUrl = `https://hooks.example.test/${uniq("flow")}`;
await flow(
  page,
  state,
  "webhook-create",
  async () => {
    await page.goto(BASE + "/settings/webhooks", { waitUntil: "domcontentloaded" });
    await setField(page, "url", webhookUrl);
    // The handler refuses a subscription with no events, so the journey must
    // choose one — exactly what a user does.
    const events = page.locator('input[name="events"]');
    const eventCount = await events.count();
    if (!eventCount) {
      record({ severity: "P1", kind: "missing-control", flow: "webhook-create", detail: "the register form offers no event checkboxes" });
    } else {
      await events.first().check();
    }
    await submitForm(page, "/web/webhooks");
    return { webhookUrl, eventCount };
  },
  { expect: BASE + "/settings/webhooks", marker: "hooks.example.test" },
);

// ── 8. API key mint ──────────────────────────────────────────────────────────
await flow(
  page,
  state,
  "api-key-create",
  async () => {
    await page.goto(BASE + "/settings/api-keys", { waitUntil: "domcontentloaded" });
    await setField(page, "name", uniq("Flow Key"));
    await setField(page, "expires_in_days", "30");
    const scopes = page.locator('input[name="scopes"]');
    if (await scopes.count()) await scopes.first().check();
    await submitForm(page, "/web/api-keys");
    const body = await page.locator("body").innerText();
    return { keyShown: /apex_|ak_|key/i.test(body) };
  },
  { expect: BASE + "/settings/api-keys", marker: "Flow Key" },
);

// ── 9. team invite ───────────────────────────────────────────────────────────
await flow(
  page,
  state,
  "team-invite",
  async () => {
    await page.goto(BASE + "/settings/team", { waitUntil: "domcontentloaded" });
    const invitee = `${uniq("invitee")}@example.test`;
    // The handler reads `userName` for the address and requires `role`; the
    // journey uses the form's own controls, so a missing control surfaces as
    // a missing-control finding rather than a timeout.
    for (const name of ["userName", "role"]) {
      if (!(await page.locator(`[name="${name}"]`).count())) {
        record({ severity: "P1", kind: "missing-control", flow: "team-invite", detail: `the invite form offers no ${name} control` });
        return { invitee, missing: name };
      }
    }
    await setField(page, "userName", invitee);
    await submitForm(page, "/web/team/invite", { button: "Send invitation" });
    return { invitee };
  },
  { expect: BASE + "/settings/team", marker: "invitee" },
);

// ── 10. inbox placement test ─────────────────────────────────────────────────
const placementName = uniq("Flow Placement");
await flow(
  page,
  state,
  "placement-create",
  async () => {
    await page.goto(BASE + "/inbox-placement/new", { waitUntil: "domcontentloaded" });
    await setField(page, "name", placementName);
    await setField(page, "from_email", "flow@journey.test");
    await setField(page, "from_name", "Flow Sender");
    await setField(page, "subject", "Flow placement subject");
    await setField(page, "html_body", "<p>Flow placement body.</p>");
    const providers = page.locator('input[name="providers"]');
    if (await providers.count()) await providers.first().check();
    await submitForm(page, "/web/inbox-placement/tests");
    return { placementName };
  },
  { expect: BASE + "/inbox-placement", marker: placementName },
);

// ── 11. assistant question (a real LLM round-trip) ───────────────────────────
await flow(page, state, "assistant-message", async () => {
  await page.goto(BASE + "/assistant", { waitUntil: "domcontentloaded" });
  await setField(page, "message", "How many campaigns do I have?");
  await submitForm(page, "/web/assistant/message");
  await sleep(2500);
  const body = await page.locator("body").innerText();
  return { replied: /assistant|answer|campaign/i.test(body), len: body.length };
});

// ── 12. search (the console's global search) ─────────────────────────────────
await flow(page, state, "search", async () => {
  await page.goto(BASE + "/dashboard", { waitUntil: "domcontentloaded" });
  const search = page.locator('input[name="query"]').first();
  await search.fill("flow");
  await page.locator('form[action="/campaigns"] button').first().click();
  await sleep(700);
  return { landed: page.url() };
});

// ── 13. contact update, then delete ──────────────────────────────────────────
await flow(
  page,
  state,
  "contact-update-delete",
  async () => {
    await page.goto(BASE + "/contacts", { waitUntil: "domcontentloaded" });
    await sleep(300);
    const row = page.locator(`tr:has-text("${contactEmail}")`).first();
    if (!(await row.count())) return { note: "the created contact was not in the list" };
    const editBtn = row.locator('form[action="/web/contacts/update"] button').first();
    if (await editBtn.count()) {
      await editBtn.click();
      await sleep(800);
    }
    await page.goto(BASE + "/contacts", { waitUntil: "domcontentloaded" });
    await sleep(300);
    const delRow = page.locator(`tr:has-text("${contactEmail}")`).first();
    const box = delRow.locator('input[type=checkbox]').first();
    if (await box.count()) {
      await box.check();
      const del = page.locator('form[action="/web/contacts/delete-bulk"] button').first();
      if (await del.count()) {
        await del.click();
        await sleep(900);
      }
    }
    const body = await page.locator("body").innerText();
    return { gone: !body.includes(contactEmail) };
  },
);

// ── 14. CSV export ───────────────────────────────────────────────────────────
await flow(page, state, "contacts-export", async () => {
  // A granted export is a file DOWNLOAD, which Playwright surfaces as an
  // event rather than a navigation — both outcomes are real answers, so the
  // flow accepts either and reports which one happened.
  const download = page.waitForEvent("download", { timeout: 4000 }).catch(() => null);
  const nav = page
    .goto(BASE + "/web/contacts/export.csv", { waitUntil: "domcontentloaded" })
    .catch(() => null);
  const file = await download;
  if (file) {
    const p = await file.path();
    const bytes = fs.statSync(p).size;
    const head = fs.readFileSync(p, "utf8").split("\n")[0].slice(0, 120);
    return { kind: "download", filename: file.suggestedFilename(), bytes, header: head };
  }
  const resp = await nav;
  const ct = resp?.headers()["content-type"] || "";
  const text = await page.locator("body").innerText().catch(() => "");
  // A refusal is a page with a flash; a granted export that is not a file is
  // the defect this flow exists to catch.
  if (/csv|text\/plain/.test(ct)) return { kind: "inline", status: resp?.status(), contentType: ct, bytes: text.length };
  if (/not part of the current plan|upgrade/i.test(text)) return { kind: "refused-by-plan", contentType: ct };
  record({ severity: "P1", kind: "export-content-type", flow: "contacts-export", detail: `content-type ${ct}` });
  return { kind: "unexpected", status: resp?.status(), contentType: ct, bytes: text.length };
});

// ── 15. journal / audit surface ──────────────────────────────────────────────
await flow(page, state, "journal", async () => {
  await page.goto(BASE + "/settings/journal", { waitUntil: "domcontentloaded" });
  await sleep(400);
  const body = await page.locator("body").innerText();
  return { hasEntries: /journal|entry|entries|action/i.test(body), len: body.length };
});

// ── 16. suppressions surface ─────────────────────────────────────────────────
await flow(page, state, "suppressions", async () => {
  await page.goto(BASE + "/settings/suppressions", { waitUntil: "domcontentloaded" });
  await sleep(400);
  const body = await page.locator("body").innerText();
  return { len: body.length, hasContent: /suppress|bounce|complaint|unsubscribe/i.test(body) };
});

await ctx.close();
await browser.close();

const summary = {
  flows: flows.length,
  ok: flows.filter((f) => f.materialised !== false).length,
  findings: findings.length,
  bySeverity: findings.reduce((a, f) => ((a[f.severity] = (a[f.severity] || 0) + 1), a), {}),
};
fs.writeFileSync(path.join(OUT, "flows.json"), JSON.stringify({ summary, flows, findings }, null, 2));
console.log(`\nflows: ${summary.flows}, findings: ${summary.findings} ${JSON.stringify(summary.bySeverity)} -> ${OUT}/flows.json`);
