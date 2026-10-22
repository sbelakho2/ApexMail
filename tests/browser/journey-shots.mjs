import { chromium } from "playwright";
import fs from "node:fs";

const BASE = "http://127.0.0.1:8080";
const CP = "http://admin.localhost:8080";
const OUT = "/Users/sabelakhoua/IdeaProjects/ApexMail/.kiwi/journey-shots";
fs.mkdirSync(OUT, { recursive: true });

const browser = await chromium.launch();
const ctx = await browser.newContext({ viewport: { width: 1280, height: 800 } });
const page = await ctx.newPage();
const errors = [];
page.on("pageerror", (e) => errors.push("pageerror: " + e.message));
page.on("console", (m) => { if (m.type() === "error") errors.push("console: " + m.text().slice(0, 160)); });
page.on("response", (r) => { if (r.status() >= 500) errors.push(`HTTP ${r.status()} ${r.url()}`); });

// --- login as owner (web) ---
await page.goto(BASE + "/login");
await page.getByLabel(/email/i).fill("owner@journey.test");
await page.getByLabel(/password/i).fill("Journey!2026-Strong-Pass-1");
await page.waitForTimeout(1200); // captcha PoW solve
await page.locator("button[type=submit]").click();
await page.waitForURL("**/dashboard", { timeout: 15000 });

const webRoutes = [
  ["dashboard", "/dashboard"],
  ["campaigns", "/campaigns"],
  ["campaigns-new", "/campaigns/new"],
  ["templates", "/templates"],
  ["contacts", "/contacts"],
  ["contacts-new", "/contacts/new"],
  ["lists", "/lists"],
  ["analytics", "/analytics"],
  ["reports", "/reports"],
  ["reports-deliverability", "/reports/deliverability"],
  ["inbox-placement", "/inbox-placement"],
  ["events", "/events"],
  ["domains", "/domains"],
  ["settings", "/settings"],
  ["settings-api-keys", "/settings/api-keys"],
  ["settings-webhooks", "/settings/webhooks"],
  ["settings-team", "/settings/team"],
  ["settings-billing", "/settings/billing"],
  ["settings-dedicated-ips", "/settings/dedicated-ips"],
  ["settings-suppressions", "/settings/suppressions"],
  ["settings-journal", "/settings/journal"],
  ["settings-profile", "/settings/profile"],
  ["assistant", "/assistant"],
];

for (const [name, path] of webRoutes) {
  await page.goto(BASE + path);
  await page.waitForLoadState("domcontentloaded");
  await page.waitForTimeout(500);
  await page.screenshot({ path: `${OUT}/owner-${name}.png` });
  console.log("shot", name);
}

// dark theme sweep on key pages
await page.goto(BASE + "/dashboard");
await page.evaluate(() => { localStorage.setItem("apexmail-ui:theme", JSON.stringify({ theme: "dark" })); });
const darkRoutes = [["dashboard-dark", "/dashboard"], ["campaigns-dark", "/campaigns"], ["settings-dark", "/settings"], ["contacts-dark", "/contacts"]];
for (const [name, path] of darkRoutes) {
  await page.goto(BASE + path);
  await page.waitForLoadState("domcontentloaded");
  await page.evaluate(() => { const t = localStorage.getItem("apexmail-ui:theme"); if (!t || !t.includes("dark")) document.documentElement.classList.add("dark"); });
  await page.waitForTimeout(400);
  await page.screenshot({ path: `${OUT}/owner-${name}.png` });
  console.log("shot", name);
}

// mobile viewport sweep
await page.setViewportSize({ width: 390, height: 844 });
const mobileRoutes = [["dashboard-mobile", "/dashboard"], ["campaigns-mobile", "/campaigns"], ["settings-mobile", "/settings"], ["contacts-mobile", "/contacts"]];
for (const [name, path] of mobileRoutes) {
  await page.goto(BASE + path);
  await page.waitForLoadState("domcontentloaded");
  await page.waitForTimeout(400);
  await page.screenshot({ path: `${OUT}/owner-${name}.png` });
  console.log("shot", name);
}
await page.setViewportSize({ width: 1280, height: 800 });

// --- CP operator ---
const ctx2 = await browser.newContext({ viewport: { width: 1280, height: 800 } });
const cp = await ctx2.newPage();
cp.on("pageerror", (e) => errors.push("cp pageerror: " + e.message));
cp.on("response", (r) => { if (r.status() >= 500) errors.push(`cp HTTP ${r.status()} ${r.url()}`); });
await cp.goto(CP + "/cp/login");
await cp.getByLabel(/email/i).fill("operator@journey.test");
await cp.getByLabel(/password/i).fill("Journey!2026-Strong-Pass-2");
await cp.waitForTimeout(1200);
await cp.locator("button[type=submit]").click();
await cp.waitForLoadState("domcontentloaded");
await cp.waitForTimeout(600);
await cp.screenshot({ path: `${OUT}/cp-after-login.png` });
console.log("cp url after login:", cp.url());

const cpRoutes = [
  ["cp-dashboard", "/dashboard"],
  ["cp-tenants", "/tenants"],
  ["cp-alerts", "/alerts"],
  ["cp-infrastructure", "/infrastructure"],
  ["cp-jobs", "/jobs"],
  ["cp-analytics", "/analytics"],
  ["cp-sales", "/sales"],
  ["cp-discovery", "/discovery"],
  ["cp-demos", "/cp/demos"],
  ["cp-reviews-ai-drafts", "/reviews/ai-drafts"],
  ["cp-operators", "/operators"],
  ["cp-compliance", "/compliance"],
  ["cp-audit", "/audit"],
  ["cp-billing", "/billing"],
  ["cp-security", "/cp/security"],
];
for (const [name, path] of cpRoutes) {
  await cp.goto(CP + path);
  await cp.waitForLoadState("domcontentloaded");
  await cp.waitForTimeout(500);
  await cp.screenshot({ path: `${OUT}/${name}.png` });
  console.log("shot", name);
}

fs.writeFileSync(`${OUT}/console-errors.json`, JSON.stringify(errors, null, 2));
console.log("errors:", errors.length);
await browser.close();
