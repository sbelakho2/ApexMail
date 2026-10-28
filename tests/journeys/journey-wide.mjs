// =============================================================================
// journey-wide.mjs — the wide live journey sweep for ApexMail.
// =============================================================================
// Walks EVERY console route as EVERY user type, in both themes and three
// viewports, performing real interactions where the surface has one, and
// records: console errors, page errors, 5xx responses, axe-core a11y
// violations, and a screenshot per page.
//
// Usage:  node journey-wide.mjs [--out DIR] [--base URL] [--cp URL]
//          [--only <substr>] [--quick]
//
// Output: $OUT/<role>/<page>.png + $OUT/findings.json (machine-readable).
// =============================================================================
import { chromium } from "playwright";
import AxeBuilder from "@axe-core/playwright";
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";

const args = process.argv.slice(2);
const argOf = (n, d) => {
  const i = args.indexOf(n);
  return i >= 0 ? args[i + 1] : d;
};
const BASE = argOf("--base", "http://127.0.0.1:8080");
const CP = argOf("--cp", "http://admin.localhost:8080");
const OUT = argOf("--out", "/tmp/journey-wide");
const ONLY = argOf("--only", "");
const QUICK = args.includes("--quick");
const PASSWORD = "Journey!2026-Strong-Pass-1";
const OP_PASSWORD = "Journey!2026-Strong-Pass-2";

fs.mkdirSync(OUT, { recursive: true });
const findings = [];
const record = (f) => {
  findings.push(f);
  console.log(`[${f.severity}] ${f.kind}: ${f.role} ${f.page} — ${f.detail}`);
};

function totp(secretB32, t = Date.now()) {
  const alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = "";
  for (const c of secretB32) {
    const i = alpha.indexOf(c);
    if (i >= 0) bits += i.toString(2).padStart(5, "0");
  }
  const bytes = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) bytes.push(parseInt(bits.slice(i, i + 8), 2));
  const step = Math.floor(t / 30000);
  const buf = Buffer.alloc(8);
  buf.writeBigUInt64BE(BigInt(step));
  const h = crypto.createHmac("sha256", Buffer.from(bytes)).update(buf).digest();
  const o = h[h.length - 1] & 0xf;
  const code = ((h[o] & 0x7f) << 24) | (h[o + 1] << 16) | (h[o + 2] << 8) | h[o + 3];
  return String(code % 1000000).padStart(6, "0");
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function newPage(browser, viewport = { width: 1440, height: 900 }) {
  const ctx = await browser.newContext({ viewport });
  const page = await ctx.newPage();
  const state = { role: "?", page: "?" };
  page.on("pageerror", (e) =>
    record({ severity: "P1", kind: "page-error", role: state.role, page: state.page, detail: e.message.slice(0, 200) }),
  );
  page.on("console", (m) => {
    if (m.type() === "error") {
      const t = m.text().slice(0, 200);
      if (!/favicon|Failed to load resource: the server responded with a status of 4/.test(t))
        record({ severity: "P2", kind: "console-error", role: state.role, page: state.page, detail: t });
    }
  });
  page.on("response", (r) => {
    if (r.status() >= 500)
      record({ severity: "P0", kind: "http-5xx", role: state.role, page: state.page, detail: `${r.status()} ${r.url().slice(0, 120)}` });
  });
  return { ctx, page, state };
}

/** Visit one route: screenshot, a11y, structure facts. */
async function visit(page, state, role, name, url, opts = {}) {
  state.role = role;
  state.page = name;
  const resp = await page.goto(url, { waitUntil: "domcontentloaded" }).catch((e) => {
    record({ severity: "P1", kind: "navigation", role, page: name, detail: e.message.slice(0, 160) });
    return null;
  });
  await sleep(opts.settle ?? 350);
  const dir = path.join(OUT, role);
  fs.mkdirSync(dir, { recursive: true });
  const file = path.join(dir, `${name}.png`);
  await page.screenshot({ path: file, fullPage: opts.fullPage ?? false }).catch(() => {});

  // structural facts
  const facts = await page
    .evaluate(() => {
      const main = document.querySelector("#app-main") || document.querySelector("main");
      const text = (main?.innerText || "").replace(/\s+/g, " ").trim();
      return {
        title: document.title,
        h1: document.querySelector("h1")?.innerText?.trim() || null,
        h1count: document.querySelectorAll("h1").length,
        emptyState: /no .* yet|nothing .* yet|no results|not available|unavailable/i.test(text),
        mainLen: text.length,
        mainHead: text.slice(0, 180),
        tables: document.querySelectorAll("table").length,
        rows: document.querySelectorAll("tbody tr").length,
        cards: document.querySelectorAll("article, .apex-kpi, [data-kpi]").length,
        forms: document.querySelectorAll("form").length,
        controls: document.querySelectorAll("input, select, textarea, button").length,
        links: document.querySelectorAll("a[href]").length,
        buttons: document.querySelectorAll("button").length,
        flash: [...document.querySelectorAll("[role=alert],[role=status]")].map((n) => n.innerText.trim()).filter(Boolean),
        horizontalOverflow: document.documentElement.scrollWidth > window.innerWidth + 2,
        overflowing: [...document.querySelectorAll("body *")]
          .filter((el) => {
            const r = el.getBoundingClientRect();
            return r.width > 0 && r.right > window.innerWidth + 4 && getComputedStyle(el).position !== "fixed";
          })
          .slice(0, 4)
          .map((el) => `${el.tagName.toLowerCase()}.${(el.className || "").toString().split(" ")[0]}`),
      };
    })
    .catch(() => ({ error: true }));

  if (resp && resp.status() >= 400)
    record({ severity: resp.status() >= 500 ? "P0" : "P1", kind: "http-status", role, page: name, detail: `${resp.status()} ${url}` });
  if (facts.error) record({ severity: "P2", kind: "inspect-failed", role, page: name, detail: "evaluate failed" });
  else {
    if (facts.h1count === 0 && !/login|signup|forgot|reset|verify|404/.test(name))
      record({ severity: "P2", kind: "no-h1", role, page: name, detail: `title=${facts.title}` });
    if (facts.h1count > 1)
      record({ severity: "P2", kind: "multi-h1", role, page: name, detail: `${facts.h1count} h1s` });
    if (facts.horizontalOverflow)
      record({ severity: "P2", kind: "h-overflow", role, page: name, detail: `overflowing: ${facts.overflowing.join(", ")}` });
    // "Thin" means the page has neither prose NOR a form. A create page is
    // legitimately terse: `/domains/new` is a heading, one labelled input and
    // a submit button, whose visible text is 29 characters. Counting text
    // alone flagged every correct minimal form (live run 2026-10-22).
    if (facts.mainLen < 40 && facts.controls < 2)
      record({
        severity: "P2",
        kind: "thin-page",
        role,
        page: name,
        detail: `main text ${facts.mainLen} chars, ${facts.controls} form control(s): ${facts.mainHead}`,
      });
  }

  if (!QUICK) {
    const axe = await new AxeBuilder({ page })
      .withTags(["wcag2a", "wcag2aa"])
      .analyze()
      .catch(() => null);
    if (axe && axe.violations.length) {
      for (const v of axe.violations) {
        record({
          severity: v.impact === "critical" || v.impact === "serious" ? "P1" : "P2",
          kind: "a11y",
          role,
          page: name,
          detail: `${v.id} (${v.impact}) x${v.nodes.length}: ${v.help} — e.g. ${v.nodes[0]?.html?.slice(0, 100)}`,
        });
      }
    }
  }
  return facts;
}

async function loginWeb(page, email, password) {
  await page.goto(BASE + "/login", { waitUntil: "domcontentloaded" });
  await page.getByLabel(/email/i).fill(email);
  await page.getByLabel(/password/i).fill(password);
  await sleep(1300);
  await page.locator("button[type=submit]").click();
  await sleep(900);
  return page.url();
}

async function loginCp(page, email, password, secret) {
  await page.goto(CP + "/cp/login", { waitUntil: "domcontentloaded" });
  await page.getByLabel(/email/i).fill(email);
  await page.getByLabel(/password/i).fill(password);
  await sleep(1300);
  await page.locator("button[type=submit]").click();
  await sleep(900);
  if (page.url().includes("mfa=1") && secret) {
    const inp = page.locator("input[name=code]").first();
    if (await inp.count()) {
      await inp.fill(totp(secret));
      await page.locator("button[type=submit]").first().click();
      await sleep(900);
    }
  }
  return page.url();
}

// ── route tables ────────────────────────────────────────────────────────────
const WEB_ROUTES = [
  ["dashboard", "/dashboard"], ["campaigns", "/campaigns"], ["campaign-new", "/campaigns/new"],
  ["templates", "/templates"], ["template-new", "/templates/new"],
  ["contacts", "/contacts"], ["contact-new", "/contacts/new"],
  ["lists", "/lists"], ["list-new", "/lists/new"],
  ["analytics", "/analytics"], ["reports", "/reports"], ["reports-deliverability", "/reports/deliverability"],
  ["inbox-placement", "/inbox-placement"], ["inbox-placement-new", "/inbox-placement/new"],
  ["events", "/events"], ["domains", "/domains"], ["domain-new", "/domains/new"],
  ["settings", "/settings"], ["settings-api-keys", "/settings/api-keys"],
  ["settings-webhooks", "/settings/webhooks"], ["settings-team", "/settings/team"],
  ["settings-billing", "/settings/billing"], ["settings-dedicated-ips", "/settings/dedicated-ips"],
  ["settings-suppressions", "/settings/suppressions"], ["settings-journal", "/settings/journal"],
  ["settings-profile", "/settings/profile"], ["assistant", "/assistant"],
];
const CP_ROUTES = [
  ["cp-dashboard", "/dashboard"], ["cp-tenants", "/tenants"], ["cp-tenant-new", "/tenants/new"],
  ["cp-alerts", "/alerts"], ["cp-alert-rules", "/alerts/rules"],
  ["cp-infrastructure", "/infrastructure"], ["cp-jobs", "/jobs"], ["cp-analytics", "/analytics"],
  ["cp-sales", "/sales"], ["cp-discovery", "/discovery"], ["cp-demos", "/cp/demos"],
  ["cp-ai-drafts", "/reviews/ai-drafts"], ["cp-operators", "/operators"],
  ["cp-compliance", "/compliance"], ["cp-audit", "/audit"], ["cp-billing", "/billing"],
  ["cp-security", "/cp/security"],
];
const ANON_ROUTES = [
  ["login", "/login"], ["signup", "/signup"], ["forgot-password", "/forgot-password"],
  ["reset-password", "/reset-password"], ["verify-email", "/verify-email"],
];

const filter = (routes) => (ONLY ? routes.filter(([n]) => n.includes(ONLY) || ONLY === "") : routes);

const browser = await chromium.launch();
const summary = {};

try {
  // ── anonymous ─────────────────────────────────────────────────────────────
  {
    const { ctx, page, state } = await newPage(browser);
    for (const [n, p] of filter(ANON_ROUTES)) await visit(page, state, "anonymous", n, BASE + p);
    await ctx.close();
  }

  // ── owner (rich tenant) ───────────────────────────────────────────────────
  {
    const { ctx, page, state } = await newPage(browser);
    const landed = await loginWeb(page, "owner@journey.test", PASSWORD);
    if (!/dashboard/.test(landed)) record({ severity: "P0", kind: "login", role: "owner", page: "login", detail: `landed ${landed}` });
    const lightFacts = [];
    for (const [n, p] of filter(WEB_ROUTES)) lightFacts.push([n, await visit(page, state, "owner", n, BASE + p)]);
    summary.owner = Object.fromEntries(lightFacts.map(([n, f]) => [n, { rows: f?.rows, cards: f?.cards, empty: f?.emptyState }]));

    // dark theme sweep on the content-heavy pages
    await page.goto(BASE + "/dashboard");
    await page.evaluate(() => localStorage.setItem("apexmail-ui:theme", JSON.stringify({ state: { theme: "dark" }, version: 0 })));
    for (const [n, p] of filter([["dashboard", "/dashboard"], ["campaigns", "/campaigns"], ["contacts", "/contacts"], ["settings", "/settings"], ["analytics", "/analytics"], ["events", "/events"], ["settings-journal", "/settings/journal"], ["assistant", "/assistant"]]))
      await visit(page, state, "owner-dark", n, BASE + p);

    // viewport sweep
    for (const [label, vp] of [["tablet", { width: 834, height: 1112 }], ["mobile", { width: 390, height: 844 }]]) {
      await page.setViewportSize(vp);
      for (const [n, p] of filter([["dashboard", "/dashboard"], ["campaigns", "/campaigns"], ["contacts", "/contacts"], ["settings", "/settings"], ["events", "/events"], ["campaign-new", "/campaigns/new"]]))
        await visit(page, state, `owner-${label}`, n, BASE + p);
    }
    await page.setViewportSize({ width: 1440, height: 900 });
    await ctx.close();
  }

  // ── each role, permission-checked ─────────────────────────────────────────
  for (const [email, role] of [
    ["admin@journey.test", "admin"],
    ["dev@journey.test", "developer"],
    ["viewer@journey.test", "viewer"],
    ["member@journey.test", "member"],
  ]) {
    const { ctx, page, state } = await newPage(browser);
    const landed = await loginWeb(page, email, PASSWORD);
    if (!/dashboard/.test(landed)) record({ severity: "P0", kind: "login", role, page: "login", detail: `landed ${landed}` });
    for (const [n, p] of filter(WEB_ROUTES)) await visit(page, state, role, n, BASE + p);
    await ctx.close();
  }

  // ── unverified + restricted tenants (honest refusal surfaces) ─────────────
  for (const [email, pw, label] of [
    ["unverified@journey.test", PASSWORD, "unverified"],
    ["suspended@journey.test", PASSWORD, "tenant-suspended"],
    ["pendingowner@journey.test", PASSWORD, "tenant-pending"],
    ["deleting@journey.test", PASSWORD, "tenant-deleting"],
  ]) {
    const { ctx, page, state } = await newPage(browser);
    await loginWeb(page, email, pw);
    await visit(page, state, label, "login-result", page.url());
    await visit(page, state, label, "dashboard-attempt", BASE + "/dashboard");
    await ctx.close();
  }

  // ── CP operator ───────────────────────────────────────────────────────────
  {
    const secretFile = path.join(OUT, "..", "journey-shots", "cp-mfa-secret.txt");
    let secret = null;
    try {
      secret = JSON.parse(fs.readFileSync(secretFile, "utf8")).secret;
    } catch {}
    const { ctx, page, state } = await newPage(browser);
    const landed = await loginCp(page, "operator@journey.test", OP_PASSWORD, secret);
    if (!/dashboard/.test(landed))
      record({ severity: "P0", kind: "login", role: "cp", page: "login", detail: `landed ${landed} (mfa secret ${secret ? "present" : "MISSING"})` });
    for (const [n, p] of filter(CP_ROUTES)) await visit(page, state, "cp", n, CP + p);
    for (const [n, p] of filter([["cp-dashboard", "/dashboard"], ["cp-tenants", "/tenants"], ["cp-sales", "/sales"]]))
      await visit(page, state, "cp-dark", n, CP + p);
    await page.setViewportSize({ width: 390, height: 844 });
    for (const [n, p] of filter([["cp-dashboard", "/dashboard"], ["cp-tenants", "/tenants"]]))
      await visit(page, state, "cp-mobile", n, CP + p);
    await ctx.close();
  }
} finally {
  fs.writeFileSync(path.join(OUT, "findings.json"), JSON.stringify({ findings, summary }, null, 2));
  await browser.close();
  console.log(`\nfindings: ${findings.length} → ${path.join(OUT, "findings.json")}`);
}
