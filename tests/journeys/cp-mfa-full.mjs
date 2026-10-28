import { chromium } from "playwright";
import fs from "node:fs";
import crypto from "node:crypto";

const CP = "http://admin.localhost:8080";
const OUT = "/Users/sabelakhoua/IdeaProjects/ApexMail/.kiwi/journey-shots";

function totp(secretB32, t = Date.now()) {
  const alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = "";
  for (const c of secretB32) {
    const idx = alpha.indexOf(c);
    if (idx < 0) continue;
    bits += idx.toString(2).padStart(5, "0");
  }
  const bytes = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) bytes.push(parseInt(bits.slice(i, i + 8), 2));
  const key = Buffer.from(bytes);
  const step = Math.floor(t / 30000);
  const buf = Buffer.alloc(8);
  buf.writeBigUInt64BE(BigInt(step));
  const hmac = crypto.createHmac("sha256", key).update(buf).digest();
  const off = hmac[hmac.length - 1] & 0xf;
  const code = ((hmac[off] & 0x7f) << 24) | (hmac[off+1] << 16) | (hmac[off+2] << 8) | hmac[off+3];
  return String(code % 1000000).padStart(6, "0");
}

const browser = await chromium.launch();
const ctx = await browser.newContext({ viewport: { width: 1280, height: 800 } });
const page = await ctx.newPage();

await page.goto(CP + "/cp/login");
await page.getByLabel(/email/i).fill("operator@journey.test");
await page.getByLabel(/password/i).fill("Journey!2026-Strong-Pass-2");
await page.waitForTimeout(1200);
await page.locator("button[type=submit]").click();
await page.waitForLoadState("domcontentloaded");
await page.waitForTimeout(600);

await page.getByRole("button", { name: /set up mfa/i }).click();
await page.waitForLoadState("domcontentloaded");
await page.waitForTimeout(800);
let content = await page.content();
let secret = decodeURIComponent(content.match(/otpauth:[^"'\s<]+/)?.[0] || "").match(/secret=([A-Z2-7]+)/)?.[1] || "";
console.log("enroll secret:", secret.slice(0, 8) + "…");
if (!secret) { console.log("no secret found; aborting"); process.exit(1); }
fs.writeFileSync(`${OUT}/cp-mfa-secret.txt`, JSON.stringify({ secret }));

// try windows -1/0/+1 against possible clock drift; fresh setup per attempt
let enrolled = false;
for (const w of [0, -1, 1]) {
  // restart setup to get a fresh unsolated pending secret each try
  await page.goto(CP + "/cp/security");
  await page.waitForLoadState("domcontentloaded");
  const hasSetup = await page.getByRole("button", { name: /set up mfa/i }).count();
  if (hasSetup === 1) {
    await page.getByRole("button", { name: /set up mfa/i }).click();
    await page.waitForLoadState("domcontentloaded");
    await page.waitForTimeout(800);
  }
  const content = await page.content();
  const secret = decodeURIComponent(content.match(/otpauth:[^"'\s<]+/)?.[0] || "").match(/secret=([A-Z2-7]+)/)?.[1] || "";
  if (!secret) { console.log("no secret on page"); continue; }
  const code = totp(secret, Date.now() + w * 30000);
  const confirmForm = page.locator("form[action*='mfa/confirm']");
  if ((await confirmForm.count()) !== 1) { console.log("no confirm form"); continue; }
  const codeField = confirmForm.locator("input[name=code]");
  if ((await codeField.count()) !== 1) { console.log("no code field"); continue; }
  await codeField.fill(code);
  await confirmForm.locator("button[type=submit]").click();
  await page.waitForLoadState("domcontentloaded");
  await page.waitForTimeout(800);
  const flash = await page.locator("[role=alert], [role=status], .flash, [data-flash]").allTextContents().catch(() => []);
  console.log(`window ${w}: url=${page.url()} flash=${flash.join(" | ").slice(0, 160)}`);
  if (!page.url().endsWith("/cp/security") && !page.url().includes("mfa")) { enrolled = true; break; }
}
if (!enrolled) throw new Error("MFA enrollment did not complete in any window");
console.log("after enroll:", page.url());
await page.screenshot({ path: `${OUT}/cp-post-mfa.png` });

// MFA now enabled: re-login to get the MFA challenge, complete it
await page.goto(CP + "/cp/login");
await page.getByLabel(/email/i).fill("operator@journey.test");
await page.getByLabel(/password/i).fill("Journey!2026-Strong-Pass-2");
await page.waitForTimeout(1200);
await page.locator("button[type=submit]").click();
await page.waitForLoadState("domcontentloaded");
await page.waitForTimeout(600);
console.log("challenge page:", page.url());
const code2 = totp(secret, Date.now() + 30000); // next window to avoid reuse rejection
const inputs2 = page.locator("input");
const n2 = await inputs2.count();
for (let i = 0; i < n2; i++) {
  const el = inputs2.nth(i);
  const type = (await el.getAttribute("type")) || "";
  if (["text","tel","number"].includes(type)) {
    const vis = await el.isVisible();
    if (vis) { await el.fill(code2); break; }
  }
}
await page.locator("button[type=submit]").first().click();
await page.waitForLoadState("domcontentloaded");
await page.waitForTimeout(800);
console.log("after challenge:", page.url());
await page.screenshot({ path: `${OUT}/cp-post-challenge.png` });

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
];
for (const [name, path] of cpRoutes) {
  await page.goto(CP + path);
  await page.waitForLoadState("domcontentloaded");
  await page.waitForTimeout(500);
  await page.screenshot({ path: `${OUT}/${name}.png` });
  console.log("shot", name, "->", page.url().replace(CP, ""));
}
await browser.close();
