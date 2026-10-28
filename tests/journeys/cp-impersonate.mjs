import { chromium } from "playwright";
import fs from "node:fs";
import crypto from "node:crypto";
const CP = "http://admin.localhost:8080";
const OUT = "/Users/sabelakhoua/IdeaProjects/ApexMail/.kiwi/journey-shots";
const { secret } = JSON.parse(fs.readFileSync(`${OUT}/cp-mfa-secret.txt`, "utf8"));
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
const page = await browser.newPage({ viewport: { width: 1280, height: 800 } });
await page.goto(CP + "/cp/login");
await page.getByLabel(/email/i).fill("operator@journey.test");
await page.getByLabel(/password/i).fill("Journey!2026-Strong-Pass-2");
await page.waitForTimeout(1200);
await page.locator("button[type=submit]").click();
await page.waitForLoadState("domcontentloaded");
await page.waitForTimeout(600);
// MFA challenge page
if (page.url().includes("mfa=1")) {
  const code = totp(secret);
  const inp = page.locator("input[name=code], input[inputmode=numeric], input[placeholder*='000000']").first();
  await inp.fill(code);
  await page.locator("button[type=submit]").first().click();
  await page.waitForLoadState("domcontentloaded");
  await page.waitForTimeout(600);
}
console.log("login:", page.url());
await page.goto(CP + "/tenants");
await page.waitForLoadState("domcontentloaded");
const row = page.locator("tr", { hasText: "Journey Co" }).first();
await row.getByRole("button", { name: /impersonate/i }).click();
await page.waitForLoadState("domcontentloaded");
await page.waitForTimeout(600);
await page.screenshot({ path: `${OUT}/cp-impersonate-confirm.png` });
console.log("step2 url:", page.url());
const snap = await page.locator("main").ariaSnapshot();
console.log(snap.slice(0, 600));
await browser.close();
