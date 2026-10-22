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
if (page.url().includes("mfa=1")) {
  const inp = page.locator("input[name=code]").first();
  await inp.fill(totp(secret));
  await page.locator("button[type=submit]").first().click();
  await page.waitForLoadState("domcontentloaded");
  await page.waitForTimeout(600);
}
await page.goto(CP + "/tenants");
await page.waitForLoadState("domcontentloaded");
const row = page.locator("tr", { hasText: "Journey Co" }).first();
const [resp] = await Promise.all([
  page.waitForResponse((r) => r.url().includes("impersonate"), { timeout: 10000 }),
  row.getByRole("button", { name: /impersonate/i }).click(),
]);
console.log("impersonate POST:", resp.status(), resp.headers()["set-cookie"]?.slice(0, 120) || "(no set-cookie header visible)");
await page.waitForLoadState("domcontentloaded");
await page.waitForTimeout(500);
const cookies = await page.context().cookies();
console.log("cookies:", cookies.map((c) => `${c.name}@${c.domain}`).join(", "));
console.log("landed:", page.url());
const banner = await page.locator("[role=alert], .apex-impersonation").count();
console.log("banner count:", banner);
await page.screenshot({ path: `${OUT}/cp-impersonate-landed.png` });
await browser.close();
