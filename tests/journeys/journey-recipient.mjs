// =============================================================================
// journey-recipient.mjs — the RECIPIENT-side live journey.
// =============================================================================
// The recipient is a user type too: they never hold a session, and the pages
// they see (unsubscribe, preferences centre) are real UI surfaces. This walks
// them with REAL tokens, minted with the same codec the product uses:
//
//   * open pixel           GET  /o/<token>        -> 200 image/gif
//   * click redirect       GET  /c/<token>        -> 302 to the original URL
//   * unsubscribe (GET)    GET  /u/<token>        -> the confirmation page
//   * unsubscribe (POST)   POST /u/<token>/confirm-> the recorded unsubscribe
//   * preferences centre   GET  /p/<token>        -> the recipient's controls
//   * malformed tokens                            -> refused, never 500
//
// Token format (crates/tracking-service/src/codec.rs):
//   key        = HMAC-SHA256(TRACKING_SECRET_KEY, "encryption")[0..16]
//   wire       = base64url_nopad(iv[12] || authTag[16] || ciphertext)
//   open/click = u8 version | u16be-len-prefixed tenant_id, message_id,
//                recipient, link_id [, original_url when version 3]
//   unsubscribe v2 = "AXU2" | u16be-len-prefixed tenant_id, recipient,
//                message_id | ASCII decimal unix-ms
//
// Usage: node journey-recipient.mjs [--out DIR] [--tracking URL]
//        [--base URL] [--tenant ID]
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
const TRACKING = argOf("--tracking", "http://127.0.0.1:3001");
const OUT = argOf("--out", "/tmp/journey-recipient");
const TENANT = argOf("--tenant", "qvto1dgn0teqij6llg5v05upxn");
const RECIPIENT = "recipient-sweep@example.test";
const MESSAGE = "msg-sweep-0001";

// The dev secret, read from the repo .env — the same value the service uses.
function trackingSecret() {
  if (process.env.TRACKING_SECRET_KEY) return process.env.TRACKING_SECRET_KEY;
  for (const p of ["../../.env", "/Users/sabelakhoua/IdeaProjects/ApexMail/.env"]) {
    try {
      const m = fs.readFileSync(p, "utf8").match(/^TRACKING_SECRET_KEY=(.*)$/m);
      if (m) return m[1].trim();
    } catch {}
  }
  throw new Error("TRACKING_SECRET_KEY not found — export it or run from tests/browser");
}

const SECRET = trackingSecret();
const ENC_KEY = crypto.createHmac("sha256", SECRET).update("encryption").digest().subarray(0, 16);

const u16be = (n) => {
  const b = Buffer.alloc(2);
  b.writeUInt16BE(n);
  return b;
};
const field = (s) => {
  const b = Buffer.from(s, "utf8");
  return Buffer.concat([u16be(b.length), b]);
};

function seal(payload) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-128-gcm", ENC_KEY, iv);
  const ct = Buffer.concat([cipher.update(payload), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([iv, tag, ct]).toString("base64url");
}

/** Open/click token (v2 without original_url, v3 with). */
function eventToken({ linkId = "", originalUrl = null } = {}) {
  const version = originalUrl ? 3 : 2;
  const parts = [
    Buffer.from([version]),
    field(TENANT),
    field(MESSAGE),
    field(RECIPIENT),
    field(linkId),
  ];
  if (originalUrl) parts.push(field(originalUrl));
  return seal(Buffer.concat(parts));
}

/** Unsubscribe/preferences token, v2 (message-attributed). */
function unsubscribeToken() {
  const parts = [
    Buffer.from("AXU2", "ascii"),
    field(TENANT),
    field(RECIPIENT),
    field(MESSAGE),
    Buffer.from(String(Date.now()), "ascii"),
  ];
  return seal(Buffer.concat(parts));
}

fs.mkdirSync(OUT, { recursive: true });
const findings = [];
const record = (f) => {
  findings.push(f);
  console.log(`[${f.severity}] ${f.kind}: ${f.surface} — ${f.detail}`);
};

const browser = await chromium.launch({ headless: true });

// ── 1. raw protocol behaviour ───────────────────────────────────────────────
{
  const get = async (url, opts = {}) => {
    const r = await fetch(url, { redirect: "manual", ...opts });
    return { status: r.status, ct: r.headers.get("content-type") || "", loc: r.headers.get("location") || "", body: await r.text().catch(() => "") };
  };

  const pixel = await get(`${TRACKING}/o/${eventToken()}`);
  if (pixel.status !== 200) record({ severity: "P0", kind: "pixel-status", surface: "open pixel", detail: `HTTP ${pixel.status}` });
  if (!/image\/gif/.test(pixel.ct)) record({ severity: "P1", kind: "pixel-content-type", surface: "open pixel", detail: pixel.ct });
  console.log(`  open pixel: ${pixel.status} ${pixel.ct}`);

  // A real registrable domain: reserved TLDs (.test) are refused by the
  // redirect policy, and refusing them is correct — a link target that can
  // never resolve is not a destination.
  const target = "https://apexmail.ee/pricing?utm_source=apexmail";
  const click = await get(`${TRACKING}/c/${eventToken({ linkId: "link-1", originalUrl: target })}`);
  if (click.status !== 302 && click.status !== 301) record({ severity: "P0", kind: "click-not-redirected", surface: "click redirect", detail: `HTTP ${click.status}` });
  else if (!click.loc.includes("apexmail.ee")) record({ severity: "P1", kind: "click-wrong-target", surface: "click redirect", detail: `Location: ${click.loc}` });

  // The redirect policy must refuse a hostile target, not bounce to it.
  const hostile = await get(`${TRACKING}/c/${eventToken({ linkId: "link-1", originalUrl: "javascript:alert(1)" })}`);
  if (hostile.status >= 300 && hostile.status < 400)
    record({ severity: "P0", kind: "click-open-redirect", surface: "click redirect", detail: `a javascript: target was redirected to ${hostile.loc}` });
  const reserved = await get(`${TRACKING}/c/${eventToken({ linkId: "link-1", originalUrl: "https://example.test/x" })}`);
  if (reserved.status >= 300 && reserved.status < 400)
    record({ severity: "P1", kind: "click-reserved-tld-allowed", surface: "click redirect", detail: `a reserved-TLD target was redirected to ${reserved.loc}` });
  console.log(`  redirect policy: hostile=${hostile.status} reserved-tld=${reserved.status}`);
  console.log(`  click redirect: ${click.status} -> ${click.loc.slice(0, 60)}`);

  // Malformed tokens must be refused, never crash the service.
  for (const [label, tok] of [
    ["empty", ""],
    ["garbage", "not-a-token"],
    ["truncated", "AAAA"],
    ["valid-b64-wrong-key", seal(Buffer.concat([Buffer.from([2]), field("x"), field("y"), field("z"), field("")])).slice(0, 40)],
  ]) {
    const r = await get(`${TRACKING}/o/${tok}`);
    if (r.status >= 500) record({ severity: "P0", kind: "malformed-token-500", surface: "open pixel", detail: `${label} -> HTTP ${r.status}` });
    const u = await get(`${TRACKING}/u/${tok}`);
    if (u.status >= 500) record({ severity: "P0", kind: "malformed-token-500", surface: "unsubscribe", detail: `${label} -> HTTP ${u.status}` });
  }
  console.log("  malformed tokens: no 5xx");
}

// ── 2. the recipient-facing PAGES, with a real token ────────────────────────
const surfaces = [
  ["unsubscribe", `${TRACKING}/u/${unsubscribeToken()}`],
  ["preferences", `${TRACKING}/p/${unsubscribeToken()}`],
];
for (const [name, url] of surfaces) {
  const ctx = await browser.newContext({ viewport: { width: 390, height: 844 } });
  const page = await ctx.newPage();
  const errors = [];
  page.on("console", (m) => {
    if (m.type() === "error") errors.push(m.text().slice(0, 160));
  });
  page.on("pageerror", (e) => errors.push(`pageerror ${String(e).slice(0, 160)}`));
  const resp = await page.goto(url, { waitUntil: "domcontentloaded" }).catch((e) => {
    record({ severity: "P0", kind: "navigation", surface: name, detail: e.message.slice(0, 140) });
    return null;
  });
  await new Promise((r) => setTimeout(r, 400));
  await page.screenshot({ path: path.join(OUT, `${name}.png`) }).catch(() => {});
  const status = resp ? resp.status() : 0;
  const facts = await page.evaluate(() => {
    const main = document.querySelector("main") || document.body;
    const text = (main.innerText || "").replace(/\s+/g, " ").trim();
    return {
      title: document.title,
      lang: document.documentElement.getAttribute("lang"),
      h1: document.querySelector("h1")?.innerText?.trim() || null,
      mainLen: text.length,
      head: text.slice(0, 120),
      forms: document.querySelectorAll("form").length,
      buttons: [...document.querySelectorAll("button")].map((b) => b.innerText.trim()).slice(0, 6),
      overflowing: document.documentElement.scrollWidth - document.documentElement.clientWidth,
    };
  });
  if (status >= 400) record({ severity: "P1", kind: "surface-status", surface: name, detail: `HTTP ${status}` });
  if (!facts.title) record({ severity: "P1", kind: "no-title", surface: name, detail: "document has no title" });
  if (!facts.lang) record({ severity: "P2", kind: "no-lang", surface: name, detail: "<html> has no lang" });
  if (!facts.h1) record({ severity: "P2", kind: "no-h1", surface: name, detail: `title=${facts.title}` });
  if (facts.mainLen < 40) record({ severity: "P1", kind: "thin-page", surface: name, detail: `${facts.mainLen} chars: ${facts.head}` });
  if (facts.overflowing > 1) record({ severity: "P2", kind: "h-overflow", surface: name, detail: `${facts.overflowing}px at 390px wide` });
  if (errors.length) record({ severity: "P1", kind: "console-error", surface: name, detail: errors.slice(0, 2).join(" | ") });
  console.log(`  ${name}: ${status} "${facts.h1 || facts.title}" forms=${facts.forms} buttons=${JSON.stringify(facts.buttons)}`);
  await ctx.close();
}

// ── 3. the unsubscribe actually records ─────────────────────────────────────
{
  const token = unsubscribeToken();
  const ctx = await browser.newContext({ viewport: { width: 390, height: 844 } });
  const page = await ctx.newPage();
  await page.goto(`${TRACKING}/u/${token}`, { waitUntil: "domcontentloaded" });
  await new Promise((r) => setTimeout(r, 300));
  const confirm = page.locator('form[action*="/confirm"] button[type=submit], form button[type=submit]').first();
  if (!(await confirm.count())) {
    record({ severity: "P1", kind: "no-unsubscribe-control", surface: "unsubscribe", detail: "the confirmation page offers no submit control" });
  } else {
    await confirm.click();
    await new Promise((r) => setTimeout(r, 900));
    await page.screenshot({ path: path.join(OUT, "unsubscribe-confirmed.png") }).catch(() => {});
    const body = await page.locator("body").innerText();
    if (!/unsubscrib|removed|no longer|preference/i.test(body))
      record({ severity: "P1", kind: "unsubscribe-no-confirmation", surface: "unsubscribe", detail: body.replace(/\s+/g, " ").slice(0, 160) });
    else console.log("  unsubscribe confirm: acknowledged");
  }
  await ctx.close();
}

// ── 4. the public receipt-verification surface ──────────────────────────────
{
  const r = await fetch(`${BASE}/v1/routing/receipts/public-key`);
  const ct = r.headers.get("content-type") || "";
  const text = await r.text();
  if (!/json/.test(ct)) record({ severity: "P1", kind: "receipt-key-content-type", surface: "receipt verify", detail: ct });
  if (r.status === 200) {
    if (!/public|key|ed25519/i.test(text)) record({ severity: "P1", kind: "receipt-key-shape", surface: "receipt verify", detail: text.slice(0, 140) });
  } else if (r.status === 503) {
    // Fail-closed by design: with no signing key configured the endpoint
    // publishes NOTHING rather than a fabricated or empty key. What must
    // never happen is a 200 carrying no key material.
    if (!/error|unavailable|not configured|key/i.test(text))
      record({ severity: "P1", kind: "receipt-key-unconfigured-copy", surface: "receipt verify", detail: text.slice(0, 140) });
  } else {
    record({ severity: "P1", kind: "receipt-key-status", surface: "receipt verify", detail: `HTTP ${r.status}` });
  }
  console.log(`  receipt public key: ${r.status} ${ct} (503 = no key configured in this deployment, by design)`);
}

await browser.close();
fs.writeFileSync(path.join(OUT, "findings.json"), JSON.stringify({ findings }, null, 2));
const bySeverity = findings.reduce((a, f) => ((a[f.severity] = (a[f.severity] || 0) + 1), a), {});
console.log(`\nrecipient findings: ${findings.length} ${JSON.stringify(bySeverity)} -> ${OUT}/findings.json`);
