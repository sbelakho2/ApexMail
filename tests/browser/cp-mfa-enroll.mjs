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

// forced-MFA onboarding page
await page.getByRole("button", { name: /set up mfa/i }).click();
await page.waitForLoadState("domcontentloaded");
await page.waitForTimeout(800);
const content = await page.content();
const secret = decodeURIComponent(content.match(/otpauth:[^"'\s<]+/)?.[0] || "").match(/secret=([A-Z2-7]+)/)?.[1] || "";
console.log("secret:", secret.slice(0, 8) + "…");
fs.writeFileSync(`${OUT}/cp-mfa-secret.txt`, JSON.stringify({ secret }));

const code = totp(secret);
console.log("totp:", code);
// find the confirm input (any 6-digit/otp input on this page)
const inputs = page.locator("input");
const n = await inputs.count();
let filled = false;
for (let i = 0; i < n; i++) {
  const el = inputs.nth(i);
  const type = (await el.getAttribute("type")) || "";
  const name = (await el.getAttribute("name")) || "";
  const ph = (await el.getAttribute("placeholder")) || "";
  if (["text","tel","number","password"].includes(type) || /code|otp|totp/i.test(name + ph)) {
    await el.fill(code);
    filled = true;
    break;
  }
}
console.log("filled:", filled);
await page.locator("button[type=submit], button:has-text('Verify'), button:has-text('Confirm'), button:has-text('Enable')").first().click();
await page.waitForLoadState("domcontentloaded");
await page.waitForTimeout(800);
await page.screenshot({ path: `${OUT}/cp-post-mfa.png` });
console.log("after enroll:", page.url());
await browser.close();
