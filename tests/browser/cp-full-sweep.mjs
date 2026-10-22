import { chromium } from "playwright";
import fs from "node:fs";
import crypto from "node:crypto";

const CP = "http://admin.localhost:8080";
const OUT = "/Users/sabelakhoua/IdeaProjects/ApexMail/.kiwi/journey-shots";
const { otpauth } = JSON.parse(fs.readFileSync(`${OUT}/cp-mfa-secret.txt`, "utf8"));
const secret = decodeURIComponent(otpauth).match(/secret=([A-Z2-7]+)/)[1];

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
  const hmac = crypto.createHmac("sha1", key).update(buf).digest();
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
// MFA challenge: fill the 6-digit code
const code = totp(secret);
console.log("totp:", code);
const codeInput = page.getByLabel(/code/i).first();
await codeInput.fill(code);
await page.locator("button[type=submit]").click();
await page.waitForLoadState("domcontentloaded");
await page.waitForTimeout(800);
await page.screenshot({ path: `${OUT}/cp-post-mfa.png` });
console.log("after mfa:", page.url());

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
