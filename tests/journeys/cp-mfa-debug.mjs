import { chromium } from "playwright";
const CP = "http://admin.localhost:8080";
const browser = await chromium.launch();
const page = await browser.newPage();
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
// capture flash text + form fields on the setup page
const snap = await page.locator("main").ariaSnapshot();
console.log(snap.slice(0, 1800));
await browser.close();
