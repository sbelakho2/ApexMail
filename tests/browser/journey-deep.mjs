// =============================================================================
// journey-deep.mjs — the wide + deep + visually-observant ApexMail sweep.
// =============================================================================
// Wider than journey-wide.mjs: EVERY route of the web console, the control
// plane and the public/recipient surfaces, for EVERY enumerated user type, in
// light AND dark, at desktop / tablet / mobile — plus the visual details a
// screenshot alone does not show:
//
//   * text contrast computed from the rendered colours (WCAG AA),
//   * text clipped without an ellipsis (a silently truncated value),
//   * interactive controls with no accessible name,
//   * duplicate element ids (they break label→control association),
//   * focus visibility walked with real Tab presses,
//   * tap targets under 24 px at the mobile viewport,
//   * broken images, zero-size interactive elements,
//   * horizontal overflow with the offending selectors,
//   * axe-core violations, console/page errors, 4xx/5xx responses.
//
// Usage: node journey-deep.mjs [--out DIR] [--only SUBSTR] [--quick]
//        [--viewports desktop,tablet,mobile] [--no-dark]
//
// Output: $OUT/<role>/<page>[@theme][@viewport].png + findings.json
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
const OUT = argOf("--out", "/tmp/journey-deep");
const ONLY = argOf("--only", "");
const QUICK = args.includes("--quick");
const NO_DARK = args.includes("--no-dark");
const PASSWORD = "Journey!2026-Strong-Pass-1";
const OP_PASSWORD = "Journey!2026-Strong-Pass-2";

fs.mkdirSync(OUT, { recursive: true });
const findings = [];
const record = (f) => {
  findings.push(f);
  console.log(`[${f.severity}] ${f.kind}: ${f.role} ${f.page} — ${f.detail}`);
};

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const slug = (s) => s.replace(/[^a-zA-Z0-9]+/g, "-").replace(/^-|-$/g, "") || "root";

/** Seconds until the current 30 s TOTP window rolls over. A code is
 *  single-use within its window, so a journey that enrols and then
 *  immediately signs in must wait for the next window or the step-up
 *  replays a code the server has already consumed. */
function secondsToNextTotpWindow(now = Date.now()) {
  return 30 - ((now / 1000) % 30);
}

function totp(secretB32, t = Date.now()) {
  const alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = "";
  for (const c of secretB32) {
    const i = alpha.indexOf(c);
    if (i >= 0) bits += i.toString(2).padStart(5, "0");
  }
  const bytes = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) bytes.push(parseInt(bits.slice(i, i + 8), 2));
  const buf = Buffer.alloc(8);
  buf.writeBigUInt64BE(BigInt(Math.floor(t / 30000)));
  const h = crypto.createHmac("sha256", Buffer.from(bytes)).update(buf).digest();
  const o = h[h.length - 1] & 0xf;
  const code = ((h[o] & 0x7f) << 24) | (h[o + 1] << 16) | (h[o + 2] << 8) | h[o + 3];
  return String(code % 1000000).padStart(6, "0");
}

// ─── the enumerated user types ──────────────────────────────────────────────
// Every identity the product can be used AS. `anon` and `recipient` never hold
// a session; the rest sign in.
const USER_TYPES = [
  { role: "anon", label: "anonymous visitor (no session)" },
  { role: "recipient", label: "email recipient (tracked contact, no session)" },
  { role: "unverified", label: "signed up, email not verified" },
  { role: "invited", label: "invited teammate (user status = invited)" },
  { role: "member", label: "workspace member (least privileged)" },
  { role: "viewer", label: "workspace viewer (read-only)" },
  { role: "developer", label: "workspace developer" },
  { role: "admin", label: "workspace admin" },
  { role: "owner", label: "workspace owner (full tenant control)" },
  { role: "tenant-pending", label: "owner of a tenant pending activation" },
  { role: "tenant-suspended", label: "owner of a suspended tenant" },
  { role: "tenant-deleting", label: "owner of a tenant scheduled for deletion" },
  { role: "cp-operator", label: "control-plane operator (ApexMail staff, MFA)" },
  { role: "cp-impersonating", label: "operator impersonating a tenant user" },
  { role: "api-key", label: "machine client holding an API key" },
];

// ─── route tables ───────────────────────────────────────────────────────────
// Detail routes take a real id discovered at runtime, so the journey opens
// what the console actually lists rather than a placeholder.
const ANON_ROUTES = [
  ["login", "/login"],
  ["signup", "/signup"],
  ["forgot-password", "/forgot-password"],
  ["reset-password", "/reset-password"],
  ["verify-email", "/verify-email"],
  ["consent", "/consent"],
  ["not-found", "/this-route-does-not-exist"],
];

const WEB_ROUTES = [
  ["root", "/"],
  ["dashboard", "/dashboard"],
  ["campaigns", "/campaigns"],
  ["campaign-detail", "DETAIL:/campaigns"],
  ["campaign-edit", "EDIT:/campaigns"],
  ["campaign-new", "/campaigns/new"],
  ["templates", "/templates"],
  ["template-new", "/templates/new"],
  ["contacts", "/contacts"],
  ["contact-new", "/contacts/new"],
  ["lists", "/lists"],
  ["list-detail", "DETAIL:/lists"],
  ["list-edit", "EDIT:/lists"],
  ["list-members", "MEMBERS:/lists"],
  ["list-new", "/lists/new"],
  ["analytics", "/analytics"],
  ["reports", "/reports"],
  ["reports-deliverability", "/reports/deliverability"],
  ["inbox-placement", "/inbox-placement"],
  ["inbox-placement-detail", "DETAIL:/inbox-placement"],
  ["inbox-placement-new", "/inbox-placement/new"],
  ["events", "/events"],
  ["message-timeline", "TIMELINE:/events"],
  ["domains", "/domains"],
  ["domain-tracking", "TRACKING:/domains"],
  ["domain-new", "/domains/new"],
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

const CP_ROUTES = [
  ["cp-root", "/"],
  ["cp-dashboard", "/dashboard"],
  ["cp-tenants", "/tenants"],
  ["cp-tenant-detail", "TENANT:/tenants"],
  ["cp-tenant-new", "/tenants/new"],
  ["cp-alerts", "/alerts"],
  ["cp-alert-rules", "/alerts/rules"],
  ["cp-infrastructure", "/infrastructure"],
  ["cp-infra-nodes", "/infrastructure/nodes"],
  ["cp-infra-queues", "/infrastructure/queues"],
  ["cp-jobs", "/jobs"],
  ["cp-analytics", "/analytics"],
  ["cp-domains", "/domains"],
  ["cp-sales", "/sales"],
  ["cp-discovery", "/discovery"],
  ["cp-demos", "/cp/demos"],
  ["cp-ai-drafts", "/reviews/ai-drafts"],
  ["cp-operators", "/operators"],
  ["cp-operator-new", "/operators/new"],
  ["cp-compliance", "/compliance"],
  ["cp-gdpr", "/compliance/gdpr"],
  ["cp-audit", "/audit"],
  ["cp-billing", "/billing"],
  ["cp-billing-plans", "/billing/plans"],
  ["cp-security", "/cp/security"],
  ["cp-settings", "/settings"],
  ["cp-settings-security", "/settings/security"],
  ["cp-cp", "/cp"],
  ["cp-cp-audit", "/cp/audit"],
  ["cp-cp-demos", "/cp/demos"],
  ["cp-cp-infrastructure", "/cp/infrastructure"],
  ["cp-cp-sales", "/cp/sales"],
  ["cp-cp-security", "/cp/security"],
  ["cp-cp-tenants", "/cp/tenants"],
];

const VIEWPORTS = {
  desktop: { width: 1440, height: 900 },
  tablet: { width: 834, height: 1112 },
  mobile: { width: 390, height: 844 },
};
const requestedViewports = (argOf("--viewports", "desktop,tablet,mobile") || "")
  .split(",")
  .map((v) => v.trim())
  .filter((v) => VIEWPORTS[v]);

const filter = (rows) =>
  ONLY ? rows.filter(([n, p]) => `${n} ${p}`.toLowerCase().includes(ONLY.toLowerCase())) : rows;

// ─── browser plumbing ───────────────────────────────────────────────────────
function attach(page, state) {
  page.on("console", (m) => {
    if (m.type() !== "error") return;
    const t = m.text();
    // 4xx the journey deliberately provokes is not a defect.
    if (/status of 4\d\d/.test(t)) return;
    state.consoleErrors.push(t.slice(0, 200));
  });
  page.on("pageerror", (e) => state.pageErrors.push(String(e).slice(0, 200)));
  page.on("response", (r) => {
    if (r.status() >= 500) state.bad.push(`${r.status()} ${r.url()}`);
    else if (r.status() === 404 && r.request().resourceType() !== "document")
      state.bad.push(`404 ${r.url()}`);
  });
}

async function newPage(browser, viewport) {
  const ctx = await browser.newContext({ viewport: viewport || VIEWPORTS.desktop });
  const page = await ctx.newPage();
  const state = { consoleErrors: [], pageErrors: [], bad: [] };
  attach(page, state);
  return { ctx, page, state };
}

/** Everything the eye would have to catch, read out of the rendered page. */
const PROBE = () => {
  const visible = (el) => {
    const s = getComputedStyle(el);
    if (s.display === "none" || s.visibility === "hidden" || Number(s.opacity) === 0) return false;
    const r = el.getBoundingClientRect();
    return r.width > 0 && r.height > 0;
  };
  const parseColor = (c) => {
    const m = c.match(/rgba?\(([^)]+)\)/);
    if (!m) return null;
    const p = m[1].split(/[,/]/).map((v) => parseFloat(v.trim()));
    return { r: p[0], g: p[1], b: p[2], a: p.length > 3 ? p[3] : 1 };
  };
  const over = (fg, bg) =>
    fg.a >= 1 ? fg : {
      r: fg.r * fg.a + bg.r * (1 - fg.a),
      g: fg.g * fg.a + bg.g * (1 - fg.a),
      b: fg.b * fg.a + bg.b * (1 - fg.a),
      a: 1,
    };
  const lum = (c) => {
    const f = (v) => {
      v /= 255;
      return v <= 0.03928 ? v / 12.92 : Math.pow((v + 0.055) / 1.055, 2.4);
    };
    return 0.2126 * f(c.r) + 0.7152 * f(c.g) + 0.0722 * f(c.b);
  };
  const ratio = (a, b) => {
    const la = lum(a), lb = lum(b);
    return (Math.max(la, lb) + 0.05) / (Math.min(la, lb) + 0.05);
  };
  const effectiveBg = (el) => {
    let node = el;
    let acc = null;
    while (node && node.nodeType === 1) {
      const c = parseColor(getComputedStyle(node).backgroundColor);
      if (c && c.a > 0) {
        acc = acc ? over(acc, c) : c;
        if (acc.a >= 1) return acc;
      }
      node = node.parentElement;
    }
    return acc && acc.a >= 1 ? acc : { r: 255, g: 255, b: 255, a: 1 };
  };
  // Deliberately hidden content is not a defect: `sr-only` text is 1x1 by
  // design, and a closed <details>/[hidden] subtree is not rendered at all.
  // Flagging either produced ~600 false positives on the first run.
  const visuallyHidden = (el) => {
    const cls = String(el.className || "");
    if (/\bsr-only\b|\bvisually-hidden\b|\bkiwi-sr-only\b/.test(cls)) return true;
    const s = getComputedStyle(el);
    const r = el.getBoundingClientRect();
    if (r.width <= 1 && r.height <= 1 && (s.overflow === "hidden" || s.overflowX === "hidden"))
      return true;
    if (/inset\(50%\)/.test(s.clipPath || "")) return true;
    return false;
  };
  const inClosedDisclosure = (el) =>
    Boolean(el.closest("[hidden], [aria-hidden='true'], details:not([open])"));
  // Walk the ancestor chain for a subtree that is not painted at all. A
  // control inside `md:hidden`/`display:none` has a zero rect but is simply
  // not shown at this viewport — the mobile nav at desktop width is the
  // common case.
  const ancestorNotRendered = (el) => {
    let node = el;
    while (node && node.nodeType === 1) {
      const s = getComputedStyle(node);
      if (s.display === "none" || s.visibility === "hidden") return true;
      node = node.parentElement;
    }
    return false;
  };

  const selectorOf = (el) => {
    if (!el || el.nodeType !== 1) return "?";
    let s = el.tagName.toLowerCase();
    if (el.id) s += `#${el.id}`;
    const cls = (el.className && String(el.className).split(/\s+/).filter(Boolean).slice(0, 3)) || [];
    if (cls.length) s += `.${cls.join(".")}`;
    return s;
  };

  const lowContrast = [];
  const clipped = [];
  const namelessControls = [];
  const zeroSizeInteractive = [];
  const smallTargets = [];
  const brokenImages = [];
  const seenContrast = new Set();

  // 1. Text contrast, over the element's real painted background.
  const textNodes = [];
  const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
  let n;
  while ((n = walker.nextNode())) {
    const t = (n.nodeValue || "").trim();
    if (t.length < 2) continue;
    const el = n.parentElement;
    if (!el || !visible(el) || visuallyHidden(el) || inClosedDisclosure(el)) continue;
    textNodes.push(el);
  }
  for (const el of textNodes.slice(0, 400)) {
    const s = getComputedStyle(el);
    const fg = parseColor(s.color);
    if (!fg) continue;
    const bg = effectiveBg(el);
    const cr = ratio(over(fg, bg), bg);
    const size = parseFloat(s.fontSize);
    const bold = Number(s.fontWeight) >= 700;
    const large = size >= 24 || (size >= 18.66 && bold);
    const min = large ? 3 : 4.5;
    if (cr < min - 0.01) {
      const key = `${Math.round(cr * 10)}:${s.color}:${selectorOf(el)}`;
      if (seenContrast.has(key)) continue;
      seenContrast.add(key);
      lowContrast.push({
        selector: selectorOf(el),
        text: (el.innerText || "").trim().slice(0, 48),
        ratio: Math.round(cr * 100) / 100,
        required: min,
        color: s.color,
        bg: `rgb(${bg.r},${bg.g},${bg.b})`,
      });
    }
  }

  // 2. Text clipped without an ellipsis — a value the user cannot read.
  for (const el of document.querySelectorAll("td, th, p, span, h1, h2, h3, li, dd, dt, a, label")) {
    if (!visible(el) || visuallyHidden(el) || inClosedDisclosure(el)) continue;
    if (el.children.length) continue;
    const s = getComputedStyle(el);
    if (s.textOverflow === "ellipsis" || s.overflow === "visible") continue;
    // An intentional multi-line clamp is a design decision, not lost content.
    if ((s.webkitLineClamp && s.webkitLineClamp !== "none") || (s.lineClamp && s.lineClamp !== "none"))
      continue;
    if (s.overflowX !== "hidden" && s.overflowX !== "clip") continue;
    if (el.scrollWidth > el.clientWidth + 1 && el.clientWidth > 0) {
      clipped.push({
        selector: selectorOf(el),
        text: (el.textContent || "").trim().slice(0, 40),
        scrollWidth: el.scrollWidth,
        clientWidth: el.clientWidth,
      });
    }
  }

  // 3. Interactive controls with no accessible name.
  for (const el of document.querySelectorAll("button, a[href], input, select, textarea, [role=button]")) {
    if (!visible(el)) continue;
    const tag = el.tagName.toLowerCase();
    if (tag === "input" && el.type === "hidden") continue;
    const name =
      (el.getAttribute("aria-label") || "").trim() ||
      (el.getAttribute("title") || "").trim() ||
      (el.innerText || "").trim() ||
      (el.getAttribute("alt") || "").trim() ||
      (el.labels && el.labels.length ? [...el.labels].map((l) => l.innerText).join(" ").trim() : "") ||
      (el.id ? (document.querySelector(`label[for="${el.id}"]`)?.innerText || "").trim() : "") ||
      (el.getAttribute("placeholder") || "").trim();
    if (!name) namelessControls.push({ selector: selectorOf(el), tag });
  }

  // 4. Broken images.
  for (const img of document.querySelectorAll("img")) {
    if (img.complete && img.naturalWidth === 0 && (img.getAttribute("src") || "").trim())
      brokenImages.push({ selector: selectorOf(img), src: (img.getAttribute("src") || "").slice(0, 90) });
  }

  // 5. Interactive elements with a zero-size box, and small tap targets.
  const mobileish = window.innerWidth <= 500;
  for (const el of document.querySelectorAll("button, a[href], input[type=submit], [role=button]")) {
    const r = el.getBoundingClientRect();
    const s = getComputedStyle(el);
    if (s.display === "none" || s.visibility === "hidden") continue;
    if (visuallyHidden(el) || inClosedDisclosure(el)) continue;
    if (ancestorNotRendered(el)) continue;
    if (r.width === 0 || r.height === 0) {
      zeroSizeInteractive.push({ selector: selectorOf(el), w: r.width, h: r.height });
    } else if (
      mobileish &&
      (r.width < 24 || r.height < 24) &&
      // WCAG 2.5.8 (Target Size Minimum) exempts a link whose target is
      // inline in a sentence: the line box, not the glyph box, is the target.
      s.display !== "inline"
    ) {
      smallTargets.push({
        selector: selectorOf(el),
        text: (el.innerText || "").trim().slice(0, 30),
        w: Math.round(r.width),
        h: Math.round(r.height),
      });
    }
  }

  // 6. Duplicate ids — they break label→control association and anchors.
  // `el.id` is NOT reliable here: HTMLFormElement has named property access,
  // so a form containing `<input name="id">` returns that INPUT for `form.id`
  // (the console's row-action forms do exactly this). The attribute is the
  // truth.
  const ids = {};
  for (const el of document.querySelectorAll("[id]")) {
    const id = el.getAttribute("id");
    if (!id) continue;
    ids[id] = (ids[id] || 0) + 1;
  }
  const duplicateIds = Object.entries(ids)
    .filter(([, c]) => c > 1)
    .map(([id, c]) => `${id}×${c}`);

  // 8. Form controls with no visible affordance.
  //
  // A text field needs SOME affordance: a painted border, or a background
  // that differs from what is behind it. Without either, the control reads as
  // static text — the user cannot see where to click or that the value is
  // editable. This is exactly what `border-surface-300` without the `border`
  // utility produces: Tailwind's `border-<color>` sets only border-COLOR, so
  // with no border-width utility nothing is drawn.
  const unstyledControls = [];
  for (const el of document.querySelectorAll("input, select, textarea")) {
    const t = (el.getAttribute("type") || el.tagName.toLowerCase()).toLowerCase();
    if (["hidden", "checkbox", "radio", "submit", "button", "reset", "image", "range", "color", "file"].includes(t))
      continue;
    if (!visible(el) || ancestorNotRendered(el) || visuallyHidden(el)) continue;
    const s = getComputedStyle(el);
    const borderPx = (node) => {
      const cs = getComputedStyle(node);
      return parseFloat(cs.borderTopWidth || "0") + parseFloat(cs.borderLeftWidth || "0");
    };
    // The background actually painted BEHIND this control: walk up through
    // transparent ancestors. Comparing with the immediate parent is not
    // enough — a white control on a transparent parent inside a white card
    // is invisible, and that is exactly the defect this looks for.
    const behind = (node) => {
      let cur = node.parentElement;
      while (cur && cur.nodeType === 1) {
        const c = parseColor(getComputedStyle(cur).backgroundColor);
        if (c && c.a >= 1) return c;
        cur = cur.parentElement;
      }
      return { r: 255, g: 255, b: 255, a: 1 };
    };
    const own = parseColor(s.backgroundColor);
    const bg = behind(el);
    const bgDiffers =
      own && own.a > 0 && Math.abs(own.r - bg.r) + Math.abs(own.g - bg.g) + Math.abs(own.b - bg.b) > 6;
    // The input-group pattern is legitimate: a transparent control sitting
    // directly inside a painted wrapper (the console header's search box).
    const affordedByParent = borderPx(el.parentElement) > 0;
    if (borderPx(el) === 0 && !bgDiffers && !affordedByParent) {
      unstyledControls.push({
        selector: selectorOf(el),
        name: el.getAttribute("name") || "",
        border: s.borderTopWidth,
        padding: s.paddingLeft,
      });
    }
  }

  // 7. Horizontal overflow, with the offenders.
  const overflowing = [];
  const docOverflow = document.documentElement.scrollWidth - document.documentElement.clientWidth;
  if (docOverflow > 1) {
    for (const el of document.querySelectorAll("*")) {
      const r = el.getBoundingClientRect();
      if (r.width === 0) continue;
      if (r.right > window.innerWidth + 1 && getComputedStyle(el).position !== "fixed") {
        overflowing.push(selectorOf(el));
        if (overflowing.length >= 5) break;
      }
    }
  }

  const main = document.querySelector("#app-main") || document.querySelector("main");
  const text = (main?.innerText || "").replace(/\s+/g, " ").trim();
  const inputs = document.querySelectorAll("input, select, textarea");

  return {
    title: document.title,
    lang: document.documentElement.getAttribute("lang"),
    h1count: document.querySelectorAll("h1").length,
    h1: document.querySelector("h1")?.innerText?.trim() || null,
    mainLen: text.length,
    mainHead: text.slice(0, 140),
    tables: document.querySelectorAll("table").length,
    rows: document.querySelectorAll("tbody tr").length,
    cards: document.querySelectorAll("article, .apex-kpi, [data-kpi]").length,
    forms: document.querySelectorAll("form").length,
    controls: document.querySelectorAll("input, select, textarea, button").length,
    unlabeledInputs: [...inputs]
      .filter((i) => !["hidden", "submit", "button", "reset", "image"].includes(i.type))
      .filter((i) => visible(i) && !ancestorNotRendered(i))
      .filter(
        (i) =>
          !(i.getAttribute("aria-label") || "").trim() &&
          !(i.labels && i.labels.length) &&
          !(i.getAttribute("id") &&
            document.querySelector(`label[for="${i.getAttribute("id")}"]`)) &&
          !(i.getAttribute("placeholder") || "").trim() &&
          !(i.getAttribute("title") || "").trim(),
      )
      .map((i) => selectorOf(i)),
    lowContrast: lowContrast.slice(0, 8),
    clipped: clipped.slice(0, 6),
    namelessControls: namelessControls.slice(0, 6),
    zeroSizeInteractive: zeroSizeInteractive.slice(0, 5),
    smallTargets: smallTargets.slice(0, 6),
    brokenImages: brokenImages.slice(0, 5),
    duplicateIds: duplicateIds.slice(0, 8),
    overflowing: overflowing.slice(0, 5),
    unstyledControls: unstyledControls.slice(0, 10),
    docOverflow,
  };
};

/** Walk focus with real Tab presses; report controls with no visible focus. */
async function focusAudit(page, max = 8) {
  const result = [];
  await page.evaluate(() => {
    if (document.activeElement && document.activeElement !== document.body)
      document.activeElement.blur();
    window.scrollTo(0, 0);
  });
  for (let i = 0; i < max; i++) {
    await page.keyboard.press("Tab");
    const info = await page.evaluate(() => {
      const el = document.activeElement;
      if (!el || el === document.body) return null;
      const s = getComputedStyle(el);
      const outlineVisible =
        s.outlineStyle !== "none" && parseFloat(s.outlineWidth || "0") > 0;
      const shadow = s.boxShadow && s.boxShadow !== "none";
      const ring = s.getPropertyValue("--tw-ring-shadow");
      const hasRing = ring && ring !== "none" && ring.trim() !== "";
      return {
        selector:
          el.tagName.toLowerCase() +
          (el.id ? `#${el.id}` : "") +
          (el.className && String(el.className).split(/\s+/).filter(Boolean).length
            ? `.${String(el.className).split(/\s+/).filter(Boolean).slice(0, 2).join(".")}`
            : ""),
        text: (el.innerText || el.getAttribute("aria-label") || "").trim().slice(0, 30),
        visible: outlineVisible || shadow || hasRing,
      };
    });
    if (info && !/sr-only|visually-hidden/.test(info.selector)) result.push(info);
  }
  return result;
}

async function visit(page, state, role, name, url, opts = {}) {
  state.consoleErrors.length = 0;
  state.pageErrors.length = 0;
  state.bad.length = 0;

  const resp = await page.goto(url, { waitUntil: "domcontentloaded" }).catch((e) => {
    record({ severity: "P1", kind: "navigation", role, page: name, detail: e.message.slice(0, 160) });
    return null;
  });
  await sleep(opts.settle ?? 320);

  const dir = path.join(OUT, role);
  fs.mkdirSync(dir, { recursive: true });
  const tag = [name, opts.theme, opts.viewport].filter(Boolean).join("@");
  await page.screenshot({ path: path.join(dir, `${tag}.png`) }).catch(() => {});

  const f = await page.evaluate(PROBE).catch((e) => ({ probeFailed: String(e).slice(0, 120) }));
  const status = resp ? resp.status() : 0;

  if (status >= 500) record({ severity: "P0", kind: "server-error", role, page: name, detail: `HTTP ${status}` });
  // A DOCUMENT 404 on a route the console links to is a missing page, not a
  // refusal — the sweep only looked at 5xx and sub-resource 404s, so a route
  // that quietly stopped resolving read as a clean visit (found live
  // 2026-10-22 while chasing a 404 in the server log).
  if (status === 404 && !/not-found|error/.test(name))
    record({ severity: "P1", kind: "route-404", role, page: name, detail: `HTTP 404 on ${url}` });
  if (status === 403 && !/forbidden/.test(name) && /owner|admin|developer|viewer|member|cp-/.test(role))
    record({ severity: "P2", kind: "route-403", role, page: name, detail: `HTTP 403 on ${url}` });
  if (state.bad.length) record({ severity: "P0", kind: "bad-subresource", role, page: name, detail: state.bad.slice(0, 3).join(", ") });
  if (state.pageErrors.length) record({ severity: "P0", kind: "page-error", role, page: name, detail: state.pageErrors.join(" | ") });
  if (state.consoleErrors.length) record({ severity: "P1", kind: "console-error", role, page: name, detail: state.consoleErrors.slice(0, 2).join(" | ") });

  if (f.probeFailed) {
    record({ severity: "P2", kind: "probe-failed", role, page: name, detail: f.probeFailed });
  } else {
    if (!f.title || /^$/.test(f.title)) record({ severity: "P1", kind: "no-title", role, page: name, detail: `title=${JSON.stringify(f.title)}` });
    if (!f.lang) record({ severity: "P2", kind: "no-lang", role, page: name, detail: "<html> has no lang" });
    if (f.h1count === 0 && !/login|signup|forgot|reset|verify|not-found|consent/.test(name))
      record({ severity: "P2", kind: "no-h1", role, page: name, detail: `title=${f.title}` });
    if (f.h1count > 1) record({ severity: "P2", kind: "multi-h1", role, page: name, detail: `${f.h1count} h1s` });
    if (f.docOverflow > 1)
      record({ severity: "P2", kind: "h-overflow", role, page: name, detail: `${f.docOverflow}px; ${f.overflowing.join(", ")}` });
    const isErrorPage = status >= 400 || /not-found|error/.test(name);
    if (!isErrorPage && f.mainLen < 40 && f.controls < 2)
      record({ severity: "P2", kind: "thin-page", role, page: name, detail: `${f.mainLen} chars, ${f.controls} controls: ${f.mainHead}` });
    if (f.lowContrast.length)
      record({
        severity: "P1",
        kind: "low-contrast",
        role,
        page: name,
        detail: f.lowContrast.map((c) => `${c.ratio}:1 (need ${c.required}) ${c.selector} "${c.text}"`).join(" | "),
      });
    if (f.clipped.length)
      record({
        severity: "P2",
        kind: "clipped-text",
        role,
        page: name,
        detail: f.clipped.map((c) => `${c.selector} "${c.text}" ${c.scrollWidth}>${c.clientWidth}`).join(" | "),
      });
    if (f.namelessControls.length)
      record({ severity: "P1", kind: "unlabeled-control", role, page: name, detail: f.namelessControls.map((c) => c.selector).join(", ") });
    if (f.unlabeledInputs.length)
      record({ severity: "P1", kind: "unlabeled-input", role, page: name, detail: f.unlabeledInputs.join(", ") });
    if (f.zeroSizeInteractive.length)
      record({ severity: "P1", kind: "zero-size-control", role, page: name, detail: f.zeroSizeInteractive.map((c) => c.selector).join(", ") });
    if (f.smallTargets.length)
      record({ severity: "P2", kind: "small-tap-target", role, page: name, detail: f.smallTargets.map((c) => `${c.selector} ${c.w}×${c.h}`).join(", ") });
    if (f.brokenImages.length)
      record({ severity: "P1", kind: "broken-image", role, page: name, detail: f.brokenImages.map((c) => `${c.selector} ${c.src}`).join(", ") });
    if (f.duplicateIds.length)
      record({ severity: "P2", kind: "duplicate-id", role, page: name, detail: f.duplicateIds.join(", ") });
    if (f.unstyledControls.length)
      record({
        severity: "P1",
        kind: "unstyled-control",
        role,
        page: name,
        detail: f.unstyledControls.map((c) => `${c.selector}[name=${c.name}] border=${c.border} pad=${c.padding}`).join(", "),
      });

    if (!QUICK && opts.focus) {
      const focus = await focusAudit(page);
      const invisible = focus.filter((x) => !x.visible);
      if (invisible.length)
        record({
          severity: "P2",
          kind: "no-focus-ring",
          role,
          page: name,
          detail: invisible.map((x) => `${x.selector} "${x.text}"`).join(", "),
        });
    }
    if (!QUICK) {
      const axe = await new AxeBuilder({ page })
        .withTags(["wcag2a", "wcag2aa"])
        .analyze()
        .catch(() => null);
      if (axe?.violations?.length)
        record({
          severity: "P1",
          kind: "a11y",
          role,
          page: name,
          detail: axe.violations.map((v) => `${v.id}(${v.impact})×${v.nodes.length}`).join(", "),
        });
    }
  }

  return f;
}

async function loginWeb(page, email, password) {
  await page.goto(BASE + "/login", { waitUntil: "domcontentloaded" });
  await page.getByLabel(/email/i).fill(email);
  await page.getByLabel(/password/i).fill(password);
  await sleep(1300);
  await page.locator("button[type=submit]").click();
  await sleep(1000);
  return page.url();
}

/** The console's own landing page — compared on the PATH, never as a
 *  substring: `/login?mfa=1&...&return_to=%2Fdashboard` contains the word
 *  "dashboard", which silently passed a `/dashboard/.test(url)` check and
 *  made the whole control-plane journey render the login page for every
 *  route (live run 2026-10-22). */
const isDashboard = (url) => {
  try {
    return new URL(url).pathname === "/dashboard";
  } catch {
    return false;
  }
};

// The TOTP enrolment lives in the DATABASE, so the secret has to outlive a
// single sweep: a per-run OUT directory meant every run re-enrolled and the
// previous secret was orphaned (the step-up then failed with a code the
// server could not match). One stable location, plus the run directory.
const STABLE_SECRET = "/tmp/apexmail-cp-mfa-secret.txt";
const SECRET_PATHS = [
  STABLE_SECRET,
  path.join(OUT, "cp-mfa-secret.txt"),
  path.join(process.cwd(), "..", "..", ".kiwi", "journey-shots", "cp-mfa-secret.txt"),
];

function readCpSecret() {
  for (const p of SECRET_PATHS) {
    try {
      const v = JSON.parse(fs.readFileSync(p, "utf8")).secret;
      if (v) return v;
    } catch {}
  }
  return null;
}

function writeCpSecret(secret) {
  try {
    fs.writeFileSync(STABLE_SECRET, JSON.stringify({ secret }));
  } catch {}
}

/**
 * Sign in to the control plane, self-provisioning the TOTP secret.
 *
 * The operator's MFA is real, so the journey completes it rather than
 * skipping it. Every step targets the FORM it belongs to: the control-plane
 * login page carries a logout form as well, and clicking the page's first
 * submit button signed the operator straight back out (live run
 * 2026-10-22 — it made every control-plane route render the login page and
 * hid the whole surface from the sweep).
 */
async function loginCp(page, email, password) {
  // Enabling MFA ends the current session by design, so the real operator
  // journey is: sign in -> forced enrolment -> enable -> sign in AGAIN with
  // the new second factor. A bounded loop walks exactly that, and every step
  // targets the FORM it belongs to (the control-plane login page also
  // carries a logout form; clicking the page's first submit button signed
  // the operator straight back out and hid the entire surface from the
  // sweep — live run 2026-10-22).
  for (let attempt = 0; attempt < 4; attempt++) {
    await page.goto(CP + "/login", { waitUntil: "domcontentloaded" });
    await page.getByLabel(/email/i).fill(email);
    await page.getByLabel(/password/i).fill(password);
    // The captcha solves in well under a second; give it room so the token
    // is populated before the submit.
    await sleep(900);
    await page.locator('form[action="/web/cp/login"] button[type=submit]').first().click();
    await sleep(1500);
    let url = page.url();
    if (isDashboard(url)) return url;

    // Step-up with an existing enrolment. Try the current window first, then
    // its neighbours: the dev stack's clock can drift from the host's, and a
    // code minted for the wrong window is indistinguishable from a wrong
    // secret. A code is single-use within its window, so the previous pass
    // must also have moved on — hence the window walk rather than a retry.
    if (/[?&]mfa=1/.test(url)) {
      const secret = readCpSecret();
      if (secret) {
        for (const offset of [0, -1, 1, -2, 2]) {
          const verify = page.locator('form[action="/web/auth/mfa/verify"]').first();
          if (!(await verify.count())) break;
          await verify
            .locator('input[name="code"]')
            .fill(totp(secret, Date.now() + offset * 30000));
          await verify.locator("button[type=submit]").first().click();
          await sleep(1400);
          url = page.url();
          if (isDashboard(url)) return url;
          if (!/[?&]mfa=1/.test(url)) break;
          await page.goto(CP + "/login", { waitUntil: "domcontentloaded" });
          await page.getByLabel(/email/i).fill(email);
          await page.getByLabel(/password/i).fill(password);
          await sleep(900);
          await page.locator('form[action="/web/cp/login"] button[type=submit]').first().click();
          await sleep(1500);
          url = page.url();
          if (isDashboard(url)) return url;
        }
      }
    }

    // First sign-in on an account with no enrolment: the console forces setup.
    const setup = page.locator('form[action="/web/auth/mfa/setup"] button[type=submit]').first();
    if (!isDashboard(url) && (await setup.count())) {
      await setup.click();
      await sleep(1300);
      const otpauth = decodeURIComponent((await page.content()).match(/otpauth:[^"'\s<]+/)?.[0] || "");
      const secret = otpauth.match(/secret=([A-Z2-7]+)/)?.[1] || "";
      const confirm = page.locator('form[action="/web/auth/mfa/confirm"]').first();
      if (secret && (await confirm.count())) {
        writeCpSecret(secret);
        await confirm.locator('input[name="code"]').fill(totp(secret));
        await confirm.locator("button[type=submit]").first().click();
        await sleep(1600);
        // Loop again: the session was ended by the enrolment, so the next
        // pass signs in with the secret we just captured — on a NEW code,
        // because the confirm consumed this window's.
        await sleep(secondsToNextTotpWindow() * 1000 + 500);
      }
    }
  }
  return page.url();
}

/** Resolve a runtime id for a detail route from the list page it lives on. */
async function resolveIds(page) {
  const ids = {};
  const grab = async (listUrl, pattern) => {
    await page.goto(listUrl, { waitUntil: "domcontentloaded" });
    await sleep(300);
    const href = await page
      .evaluate((re) => {
        for (const a of document.querySelectorAll("a[href]")) {
          const h = a.getAttribute("href") || "";
          if (new RegExp(re).test(h)) return h;
        }
        for (const f of document.querySelectorAll("form[action]")) {
          const h = f.getAttribute("action") || "";
          if (new RegExp(re).test(h)) return h;
        }
        return null;
      }, pattern)
      .catch(() => null);
    return href;
  };
  const campaigns = await grab(BASE + "/campaigns", "^/campaigns/[0-9a-zA-Z_-]+$");
  if (campaigns) ids.campaign = campaigns;
  const lists = await grab(BASE + "/lists", "^/lists/[0-9a-zA-Z_-]+$");
  if (lists) ids.list = lists;
  const domains = await grab(BASE + "/domains", "^/domains/[0-9a-zA-Z_-]+$");
  if (domains) ids.domain = domains;
  const placement = await grab(BASE + "/inbox-placement", "^/inbox-placement/[0-9a-zA-Z_-]+$");
  if (placement) ids.placement = placement;
  await page.goto(BASE + "/events", { waitUntil: "domcontentloaded" });
  await sleep(300);
  const timeline = await page
    .evaluate(() => {
      for (const a of document.querySelectorAll("a[href]")) {
        const h = a.getAttribute("href") || "";
        if (/^\/messages\/[0-9a-zA-Z_-]+\/timeline$/.test(h)) return h;
      }
      return null;
    })
    .catch(() => null);
  if (timeline) ids.timeline = timeline;
  return ids;
}

function expandRoutes(rows, ids) {
  const out = [];
  for (const [name, target] of rows) {
    if (!target.includes(":")) {
      out.push([name, target]);
      continue;
    }
    const [kind, listPath] = target.split(":");
    if (kind === "DETAIL") {
      const id = ids[listPath === "/campaigns" ? "campaign" : listPath === "/lists" ? "list" : listPath === "/domains" ? "domain" : "placement"];
      if (id) out.push([name, id]);
      else record({ severity: "P2", kind: "no-detail-row", role: "-", page: name, detail: `no row link found on ${listPath}` });
    } else if (kind === "EDIT") {
      const id = ids[listPath === "/campaigns" ? "campaign" : "list"];
      if (id) out.push([name, `${id}/edit`]);
    } else if (kind === "MEMBERS") {
      if (ids.list) out.push([name, `${ids.list}/members`]);
    } else if (kind === "TRACKING") {
      if (ids.domain) out.push([name, `${ids.domain}/tracking`]);
    } else if (kind === "TIMELINE") {
      if (ids.timeline) out.push([name, ids.timeline]);
    }
  }
  return out;
}

// ─── run ────────────────────────────────────────────────────────────────────
const browser = await chromium.launch({ headless: true });
const summary = {};

console.log("USER TYPES ENUMERATED:");
for (const t of USER_TYPES) console.log(`  - ${t.role}: ${t.label}`);
console.log("");

// 1. anonymous + recipient surfaces (no session)
{
  const { ctx, page, state } = await newPage(browser);
  for (const [n, p] of filter(ANON_ROUTES)) await visit(page, state, "anon", n, BASE + p, { focus: true });
  await ctx.close();
}

// 2. owner: discover real ids, then sweep EVERY route in every theme/viewport
let ids = {};
{
  const { ctx, page, state } = await newPage(browser);
  const landed = await loginWeb(page, "owner@journey.test", PASSWORD);
  if (!isDashboard(landed)) record({ severity: "P0", kind: "login", role: "owner", page: "login", detail: landed });
  ids = await resolveIds(page);

  const routes = expandRoutes(filter(WEB_ROUTES), ids);
  const facts = [];
  for (const [n, p] of routes) facts.push([n, await visit(page, state, "owner", n, BASE + p, { focus: true })]);
  summary.owner = Object.fromEntries(facts.map(([n, f]) => [n, { rows: f?.rows, cards: f?.cards, controls: f?.controls, mainLen: f?.mainLen }]));

  if (!NO_DARK) {
    await page.goto(BASE + "/dashboard");
    await page.evaluate(() =>
      localStorage.setItem("apexmail-ui:theme", JSON.stringify({ state: { theme: "dark" }, version: 0 })),
    );
    for (const [n, p] of routes) await visit(page, state, "owner-dark", n, BASE + p, { theme: "dark" });
  }

  for (const vp of requestedViewports.filter((v) => v !== "desktop")) {
    await page.setViewportSize(VIEWPORTS[vp]);
    for (const [n, p] of routes) await visit(page, state, `owner-${vp}`, n, BASE + p, { viewport: vp });
  }
  await page.setViewportSize(VIEWPORTS.desktop);
  await ctx.close();
}

// 3. every other role, permission-checked, at desktop
for (const [email, role, pw] of [
  ["admin@journey.test", "admin", PASSWORD],
  ["dev@journey.test", "developer", PASSWORD],
  ["viewer@journey.test", "viewer", PASSWORD],
  ["member@journey.test", "member", PASSWORD],
]) {
  const { ctx, page, state } = await newPage(browser);
  const landed = await loginWeb(page, email, pw);
  if (!isDashboard(landed)) record({ severity: "P0", kind: "login", role, page: "login", detail: landed });
  const routes = expandRoutes(filter(WEB_ROUTES), ids);
  for (const [n, p] of routes) await visit(page, state, role, n, BASE + p);
  await ctx.close();
}

// 4. unverified + restricted tenants: the honest refusal surfaces
for (const [email, label] of [
  ["unverified@journey.test", "unverified"],
  ["pendingowner@journey.test", "tenant-pending"],
  ["suspended@journey.test", "tenant-suspended"],
  ["deleting@journey.test", "tenant-deleting"],
]) {
  const { ctx, page, state } = await newPage(browser);
  const landed = await loginWeb(page, email, PASSWORD);
  await visit(page, state, label, "login-result", landed, { focus: true });
  await visit(page, state, label, "dashboard-attempt", BASE + "/dashboard");
  await visit(page, state, label, "settings-attempt", BASE + "/settings");
  await ctx.close();
}

// 5. invited teammate: holds a seat but has never accepted the invitation,
// so signing in must be refused with an honest explanation rather than a
// generic credential error.
{
  const { ctx, page, state } = await newPage(browser);
  const landed = await loginWeb(page, "invitee-mvj8zg8f@example.test", PASSWORD);
  const body = await page.locator("body").innerText().catch(() => "");
  const refused = !isDashboard(landed);
  if (!refused)
    record({ severity: "P0", kind: "invited-signin", role: "invited", page: "login", detail: `an invited (unaccepted) user reached ${landed}` });
  else if (!/invit|verif|activat|not active|pending/i.test(body))
    record({ severity: "P1", kind: "invited-refusal-copy", role: "invited", page: "login", detail: `refusal does not explain the invited state: ${body.replace(/\s+/g, " ").slice(0, 160)}` });
  await visit(page, state, "invited", "login-result", landed);
  await ctx.close();
}

// 6. machine client: mint a key through the console, then use it against the
// JSON API — the API-key user type is a real identity, not a UI variant.
{
  const { ctx, page, state } = await newPage(browser);
  const landed = await loginWeb(page, "owner@journey.test", PASSWORD);
  if (!isDashboard(landed)) record({ severity: "P0", kind: "login", role: "api-key", page: "login", detail: landed });
  await page.goto(BASE + "/settings/api-keys", { waitUntil: "domcontentloaded" });
  await sleep(300);
  await page.locator('input[name="name"]').fill(`sweep-key-${Date.now().toString(36)}`);
  // Check every scope: a full-access key is what an operator mints when the
  // journey is "can this client talk to the API at all". Checking only the
  // first box produced a key without `contacts:read` and a legitimate 403.
  const scopes = page.locator('input[name="scopes"]');
  const scopeCount = await scopes.count();
  for (let i = 0; i < scopeCount; i++) await scopes.nth(i).check();
  await page.locator('form[action="/web/api-keys"] button[type=submit]').first().click();
  await sleep(1200);
  const flash = await page.locator("body").innerText();
  const key = (flash.match(/am_live_[A-Za-z0-9]+/) || [])[0];
  if (!key) {
    record({ severity: "P1", kind: "api-key-not-shown", role: "api-key", page: "settings-api-keys", detail: "the created key secret was not rendered" });
  } else {
    const call = async (path, headers) => {
      const r = await fetch(BASE + path, { headers });
      const ct = r.headers.get("content-type") || "";
      const text = await r.text();
      return { status: r.status, ct, text };
    };
    const authed = await call("/v1/contacts", { "x-api-key": key, accept: "application/json" });
    if (authed.status >= 500)
      record({ severity: "P0", kind: "api-error", role: "api-key", page: "v1/contacts", detail: `HTTP ${authed.status}` });
    if (!/json/.test(authed.ct))
      record({ severity: "P1", kind: "api-content-type", role: "api-key", page: "v1/contacts", detail: `content-type ${authed.ct}` });
    if (authed.status === 401 || authed.status === 403)
      record({ severity: "P0", kind: "api-key-refused", role: "api-key", page: "v1/contacts", detail: `a freshly minted key was refused: ${authed.status} ${authed.text.slice(0, 120)}` });
    const anonymous = await call("/v1/contacts", { accept: "application/json" });
    if (anonymous.status !== 401 && anonymous.status !== 403)
      record({ severity: "P0", kind: "api-unauthenticated", role: "api-key", page: "v1/contacts", detail: `no credential must be refused, got ${anonymous.status}` });
    console.log(`  api-key journey: authed=${authed.status} anonymous=${anonymous.status}`);
  }
  await ctx.close();
}

// 7. control plane: every route, light + dark + mobile
{
  const { ctx, page, state } = await newPage(browser);
  const landed = await loginCp(page, "operator@journey.test", OP_PASSWORD);
  if (!isDashboard(landed))
    record({ severity: "P0", kind: "login", role: "cp-operator", page: "login", detail: landed });

  let tenantId = null;
  await page.goto(CP + "/tenants", { waitUntil: "domcontentloaded" });
  await sleep(300);
  tenantId = await page
    .evaluate(() => {
      for (const a of document.querySelectorAll("a[href]")) {
        const h = a.getAttribute("href") || "";
        const m = h.match(/^\/tenants\/([0-9a-zA-Z_-]+)$/);
        if (m && m[1] !== "new") return h;
      }
      return null;
    })
    .catch(() => null);

  const routes = [];
  for (const [n, p] of filter(CP_ROUTES)) {
    if (p.includes(":")) {
      if (tenantId) routes.push([n, tenantId]);
      continue;
    }
    routes.push([n, p]);
  }
  for (const [n, p] of routes) await visit(page, state, "cp-operator", n, CP + p, { focus: true });

  if (!NO_DARK) {
    await page.goto(CP + "/dashboard");
    await page.evaluate(() =>
      localStorage.setItem("apexmail-ui:theme", JSON.stringify({ state: { theme: "dark" }, version: 0 })),
    );
    for (const [n, p] of routes) await visit(page, state, "cp-operator-dark", n, CP + p, { theme: "dark" });
  }
  for (const vp of requestedViewports.filter((v) => v !== "desktop")) {
    await page.setViewportSize(VIEWPORTS[vp]);
    for (const [n, p] of routes) await visit(page, state, `cp-operator-${vp}`, n, CP + p, { viewport: vp });
  }
  await page.setViewportSize(VIEWPORTS.desktop);
  await ctx.close();
}

await browser.close();

const bySeverity = findings.reduce((a, f) => ((a[f.severity] = (a[f.severity] || 0) + 1), a), {});
fs.writeFileSync(path.join(OUT, "findings.json"), JSON.stringify({ summary, findings }, null, 2));
console.log(`\nfindings: ${findings.length} ${JSON.stringify(bySeverity)} -> ${OUT}/findings.json`);
