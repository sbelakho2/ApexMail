import { chromium } from "playwright";
import fs from "node:fs";
import crypto from "node:crypto";

const CP = "http://admin.localhost:8080";
const OUT = "/Users/sabelakhoua/IdeaProjects/ApexMail/.kiwi/journey-shots";

function totp(secretHex, t = Date.now()) {
  // mfa_secret stored as hex or base32? try hex decode first
  let key;
  try {
    key = Buffer.from(secretHex, "hex");
    if (key.length < 10) throw new Error("short");
  } catch {
    key = Buffer.from(secretHex, "utf8");
  }
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

// Set up MFA
await page.goto(CP + "/cp/security");
await page.getByRole("button", { name: /set up mfa/i }).click();
await page.waitForLoadState("domcontentloaded");
await page.waitForTimeout(800);
await page.screenshot({ path: `${OUT}/cp-mfa-setup.png` });
// find the secret on the page (otpauth URL or raw secret)
const content = await page.content();
const otpauth = content.match(/otpauth:[^"'\s<]+/)?.[0] || "";
const secretMatch = content.match(/secret[=:>\s"']+([A-Z2-7]{16,}|[0-9a-f]{40,})/i)?.[1] || "";
console.log("otpauth:", otpauth.slice(0, 60), "| secret match:", secretMatch ? "yes" : "no");
fs.writeFileSync(`${OUT}/cp-mfa-secret.txt`, JSON.stringify({ otpauth, secretMatch }));
await browser.close();
