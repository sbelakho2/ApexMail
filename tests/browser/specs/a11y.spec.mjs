import { test, expect } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';

// WCAG 2.2 AA acceptance evidence within the widget's
// component scope. The functional solver behavior is covered by
// widget.spec.mjs / security.spec.mjs; this suite is the accessibility
// acceptance set:
//  - computed-color badge contrast, light AND dark, every state (1.4.3)
//  - computed non-text contrast: Retry boundary + focus indicator >= 3:1 (1.4.11)
//  - focus appearance (2.4.13, AAA): indicator area >= the 2px-perimeter
//    minimum + >= 3:1 contrast change at the same pixels, light AND dark
//  - axe scans per state, light and dark
//  - keyboard-only operation (real sequential Tab/Shift+Tab, Enter+Space)
//  - live-region contract (exactly one widget-local status in every renderer)
//  - responsive: 2x component font-scale enlargement (custom-property stress
//    test; actual 200% browser zoom stays in manual qualification),
//    320px reflow, all four 1.4.12 text-spacing conditions
//  - reduced motion + forced colors
//  - RTL + long-translation rendering (locale contract, 3.1.2)
//  - pointer-target minimums (2.5.8)
// Runs in Chromium + Firefox + WebKit via playwright.a11y.config.mjs.

function parseHex(hex) {
  const h = hex.replace('#', '');
  return [0, 2, 4].map((i) => parseInt(h.slice(i, i + 2), 16) / 255);
}

function relativeLuminance(rgb) {
  const f = (c) => (c <= 0.04045 ? c / 12.92 : Math.pow((c + 0.055) / 1.055, 2.4));
  const [r, g, b] = rgb.map(f);
  return 0.2126 * r + 0.7152 * g + 0.0722 * b;
}

function contrastRatio(a, b) {
  const la = relativeLuminance(parseHex(a));
  const lb = relativeLuminance(parseHex(b));
  return (Math.max(la, lb) + 0.05) / (Math.min(la, lb) + 0.05);
}

// Composite the badge's computed background (which may be an
// rgba tint) over the actual surface behind it (the widget's computed
// background), then contrast the computed foreground against the result.
// The test interrogates the browser — it never hard-codes surfaces or
// expected colors, so CSS regression in either theme is detected, not
// duplicated.
function computedContrast(page, state) {
  return page.evaluate((st) => {
    const w = document.querySelector('[data-kiwi-widget]');
    w.setAttribute('data-state', st);
    const badge = w.querySelector('.kiwi-badge');
    const badgeBg = getComputedStyle(badge).backgroundColor;
    const fg = getComputedStyle(badge).color;
    const surface = getComputedStyle(w).backgroundColor;
    const parse = (c) => {
      const m = c.match(/rgba?\(([\d.]+)[,\s]+([\d.]+)[,\s]+([\d.]+)(?:[,\s/]+([\d.]+))?/);
      if (!m) return null;
      return { r: Number(m[1]), g: Number(m[2]), b: Number(m[3]), a: m[4] !== undefined ? Number(m[4]) : 1 };
    };
    const lum = ({ r, g, b }) => {
      const f = (v) => { v /= 255; return v <= 0.04045 ? v / 12.92 : Math.pow((v + 0.055) / 1.055, 2.4); };
      return 0.2126 * f(r) + 0.7152 * f(g) + 0.0722 * f(b);
    };
    const composite = (fgc, bgc) => ({ r: fgc.r * fgc.a + bgc.r * (1 - fgc.a), g: fgc.g * fgc.a + bgc.g * (1 - fgc.a), b: fgc.b * fgc.a + bgc.b * (1 - fgc.a) });
    const fgc = parse(fg), bgc = parse(badgeBg), surf = parse(surface);
    if (!fgc || !bgc || !surf) return { error: JSON.stringify({ fg, badgeBg, surface }) };
    const badgeBgOverSurface = composite(bgc, surf);
    const fgOverBadge = composite(fgc, badgeBgOverSurface);
    const la = lum(fgOverBadge), lb = lum(badgeBgOverSurface);
    return { ratio: (Math.max(la, lb) + 0.05) / (Math.min(la, lb) + 0.05), fg: fgOverBadge, bg: badgeBgOverSurface };
  }, state);
}

const AXE_RULES = [
  'color-contrast', 'aria-allowed-attr', 'aria-hidden-body', 'aria-hidden-focus',
  'aria-progressbar-name', 'button-name', 'focus-order-semantics', 'html-has-lang',
  'label', 'link-in-text-block', 'select-name', 'valid-lang', 'document-title',
];

// WCAG 2.4.13 measurement, focused state: derives the focus indicator's
// geometry (solid outline width/offset, or a hard-edged spread shadow) over
// the control's bounding box, and samples the pixel at the indicator
// location — the surface the browser actually paints there (elementFromPoint,
// composited up through any translucent ancestors) and the indicator
// composited over that same surface. All colors are computed in the
// browser; none are hard-coded.
async function measuredFocusGeometry(page) {
  return page.evaluate(() => {
    const w = document.querySelector('[data-kiwi-widget]');
    const retry = w.querySelector('[data-kiwi-retry]');
    const parse = (c) => {
      const m = c.match(/rgba?\(([\d.]+)[,\s]+([\d.]+)[,\s]+([\d.]+)(?:[,\s/]+([\d.]+))?/);
      if (!m) return null;
      return { r: Number(m[1]), g: Number(m[2]), b: Number(m[3]), a: m[4] !== undefined ? Number(m[4]) : 1 };
    };
    const composite = (fgc, bgc) => ({ r: fgc.r * fgc.a + bgc.r * (1 - fgc.a), g: fgc.g * fgc.a + bgc.g * (1 - fgc.a), b: fgc.b * fgc.a + bgc.b * (1 - fgc.a) });
    const toHex = ({ r, g, b }) => '#' + [r, g, b].map((v) => Math.max(0, Math.min(255, Math.round(v))).toString(16).padStart(2, '0')).join('');
    const cs = (el) => getComputedStyle(el);
    const rect = retry.getBoundingClientRect();
    const style = cs(retry);
    const outlineWidth = parseFloat(style.outlineWidth) || 0;
    const outlineOffset = parseFloat(style.outlineOffset) || 0;
    const outline = parse(style.outlineColor);
    let indicator = null;
    let kind = null;
    let thickness = 0;
    let gap = 0;
    let areaInfeasible = null;
    if (style.outlineStyle !== 'none' && outlineWidth > 0 && outline && outline.a > 0) {
      indicator = outline;
      kind = 'outline';
      thickness = outlineWidth;
      gap = outlineOffset;
    } else {
      const shadows = (style.boxShadow.match(/rgba?\([^)]*\)/g) || []).map(parse).filter((c) => c && c.a > 0);
      if (shadows.length) {
        indicator = shadows[0];
        kind = 'box-shadow';
        const m = style.boxShadow.match(/rgba?\([^)]*\)\s+(-?[\d.]+)px\s+(-?[\d.]+)px\s+(-?[\d.]+)px(?:\s+(-?[\d.]+)px)?/);
        const blur = m ? Math.abs(parseFloat(m[3]) || 0) : -1;
        const spread = m ? Math.abs(parseFloat(m[4]) || 0) : -1;
        if (blur < 0) areaInfeasible = 'unparseable box-shadow';
        else if (blur > 0) areaInfeasible = `blurred box-shadow (blur ${blur}px)`;
        else if (spread <= 0) areaInfeasible = `box-shadow with no measurable spread band (spread ${spread}px)`;
        else { thickness = spread; gap = 0; }
      }
    }
    if (!indicator) {
      return { error: JSON.stringify({ outlineStyle: style.outlineStyle, outlineColor: style.outlineColor, outlineWidth: style.outlineWidth, boxShadow: style.boxShadow }) };
    }
    // Sample the midpoint of the ring's top band: x centered on the
    // control, y midway through the indicator thickness.
    const sample = { x: rect.left + rect.width / 2, y: rect.top - gap - thickness / 2 };
    const surfaceAt = (x, y) => {
      const el = document.elementFromPoint(x, y);
      if (!el) return null;
      let acc = null;
      let node = el;
      while (node && node !== document.documentElement) {
        const bg = parse(cs(node).backgroundColor);
        if (bg && bg.a > 0) acc = acc ? composite(bg, acc) : bg;
        if (acc && acc.a >= 1) break;
        node = node.parentElement;
      }
      if (!acc) acc = { r: 255, g: 255, b: 255, a: 1 };
      return { r: acc.r, g: acc.g, b: acc.b, a: 1 };
    };
    const surface = surfaceAt(sample.x, sample.y);
    if (!surface) return { error: 'no element at the indicator sample point' };
    return {
      kind,
      thickness,
      gap,
      areaInfeasible,
      rect: { w: rect.width, h: rect.height },
      sample,
      surface: toHex(surface),
      indicator: toHex(indicator),
      focusedPixel: toHex(composite(indicator, surface)),
      // Ring band area = outer rect (control expanded by gap + thickness)
      // minus inner rect (control expanded by gap); the 2.4.13 minimum is
      // the area of a 2 CSS px thick perimeter of the control:
      // 2 * 2 * (w + h).
      ringArea: (rect.width + 2 * (gap + thickness)) * (rect.height + 2 * (gap + thickness)) - (rect.width + 2 * gap) * (rect.height + 2 * gap),
      twoPxPerimeterArea: 4 * (rect.width + rect.height),
    };
  });
}

// The unfocused half of the same-pixel measurement: the pixel at the
// indicator location once focus has left the control. Layout is unchanged
// (outlines never affect layout), so the coordinates are re-derived from the
// same geometry and must match the focused run's sample.
async function surfacePixelAt(page, sample) {
  return page.evaluate((pt) => {
    const parse = (c) => {
      const m = c.match(/rgba?\(([\d.]+)[,\s]+([\d.]+)[,\s]+([\d.]+)(?:[,\s/]+([\d.]+))?/);
      if (!m) return null;
      return { r: Number(m[1]), g: Number(m[2]), b: Number(m[3]), a: m[4] !== undefined ? Number(m[4]) : 1 };
    };
    const composite = (fgc, bgc) => ({ r: fgc.r * fgc.a + bgc.r * (1 - fgc.a), g: fgc.g * fgc.a + bgc.g * (1 - fgc.a), b: fgc.b * fgc.a + bgc.b * (1 - fgc.a) });
    const toHex = ({ r, g, b }) => '#' + [r, g, b].map((v) => Math.max(0, Math.min(255, Math.round(v))).toString(16).padStart(2, '0')).join('');
    const cs = (el) => getComputedStyle(el);
    const el = document.elementFromPoint(pt.x, pt.y);
    if (!el) return { error: 'no element at the sample point' };
    let acc = null;
    let node = el;
    while (node && node !== document.documentElement) {
      const bg = parse(cs(node).backgroundColor);
      if (bg && bg.a > 0) acc = acc ? composite(bg, acc) : bg;
      if (acc && acc.a >= 1) break;
      node = node.parentElement;
    }
    if (!acc) acc = { r: 255, g: 255, b: 255, a: 1 };
    return { x: pt.x, y: pt.y, pixel: toHex({ r: acc.r, g: acc.g, b: acc.b, a: 1 }) };
  }, sample);
}

test.describe('KiwiCaptcha WCAG 2.2 AA evidence', () => {
  test('badge contrast (WCAG 1.4.3): COMPUTED colors, light AND dark, every state >= 4.5:1 (target >= 5:1)', async ({ page }) => {
    const themes = ['light', 'dark'];
    const states = ['idle', 'solving', 'done', 'failed'];
    for (const theme of themes) {
      await page.emulateMedia({ colorScheme: theme });
      await page.goto('/');
      await expect(page.locator('[data-kiwi-widget]')).toHaveAttribute('data-state', 'done', { timeout: 60_000 });
      for (const state of states) {
        const r = await computedContrast(page, state);
        expect(r.error, `theme=${theme} state=${state}: ${r.error}`).toBeUndefined();
        expect(r.ratio, `theme=${theme} state=${state} must be >= 4.5:1 (measured ${r.ratio.toFixed(2)}:1, fg rgb(${Object.values(r.fg).map((v) => Math.round(v)).join(',')}), bg rgb(${Object.values(r.bg).map((v) => Math.round(v)).join(',')}))`).toBeGreaterThanOrEqual(4.5);
        expect(r.ratio, `theme=${theme} state=${state} headroom (internal target >= 5:1)`).toBeGreaterThanOrEqual(5);
      }
    }
  });

  test('axe: no WCAG violations in solved/idle/failed states, in BOTH light and dark', async ({ page }) => {
    for (const theme of ['light', 'dark']) {
      await page.emulateMedia({ colorScheme: theme });
      await page.goto('/');
      await expect(page.locator('[data-kiwi-widget]')).toHaveAttribute('data-state', 'done', { timeout: 60_000 });
      for (const state of ['done', 'idle', 'failed']) {
        await page.evaluate((st) => {
          document.querySelector('[data-kiwi-widget]').setAttribute('data-state', st);
        }, state);
        const results = await new AxeBuilder({ page }).withRules(AXE_RULES).analyze();
        expect(results.violations, `theme=${theme} state=${state}: ${JSON.stringify(results.violations, null, 2)}`).toEqual([]);
      }
    }
  });

  test('keyboard-only: REAL sequential navigation — Tab from a preceding control reaches Retry, Enter + Space reacquire, Tab/S-Tab traverse without trap', async ({ page }) => {
    // Proves sequential keyboard navigation, not programmatic
    // focus. The fixture wraps the widget between #kiwi-before and
    // #kiwi-after so Tab order is genuinely exercised.
    let failing = true;
    await page.route('**/challenge', async (route) => {
      if (failing) {
        await route.fulfill({ status: 503, contentType: 'application/json', body: '{"error":"down"}' });
      } else {
        await route.continue();
      }
    });
    await page.goto('/');
    await expect(page.locator('[data-kiwi-widget]')).toHaveAttribute('data-state', 'failed', { timeout: 30_000 });
    await page.evaluate(() => {
      const w = document.querySelector('[data-kiwi-widget]');
      const container = w.closest('.kiwi-container');
      const before = document.createElement('input');
      before.id = 'kiwi-before';
      before.setAttribute('aria-label', 'before');
      container.parentNode.insertBefore(before, container);
      const after = document.createElement('button');
      after.id = 'kiwi-after';
      after.textContent = 'After';
      container.parentNode.insertBefore(after, container.nextSibling);
    });

    // The passive widget itself is NOT focusable (no tabindex, no role=checkbox).
    const focusable = await page.evaluate(() => {
      const w = document.querySelector('[data-kiwi-widget]');
      return { tabindex: w.getAttribute('tabindex'), role: w.getAttribute('role') };
    });
    expect(focusable.tabindex).toBeNull();
    expect(focusable.role).toBe('group');

    // Sequential Tab: #kiwi-before -> Retry (the widget itself is skipped).
    // WebKit emulates Safari's platform default where Tab reaches text
    // fields only — buttons need the macOS "Press Tab to highlight each
    // item" Full Keyboard Access setting (a system accessibility option,
    // not a widget defect). The strict sequential assertions therefore run
    // on Chromium + Firefox; WebKit still proves Enter/Space activation,
    // focus-visible and no-trap below.
    const engine = test.info().project.name;
    if (engine !== 'webkit') {
      await page.locator('#kiwi-before').focus();
      await page.keyboard.press('Tab');
      const reachedRetry = await page.evaluate(() => {
        const ae = document.activeElement;
        return !!ae && ae.getAttribute('data-kiwi-retry') !== null;
      });
      expect(reachedRetry, 'Tab from the preceding control must land on the Retry button').toBe(true);
    } else {
      // WebKit: reach the button via the platform-accessible path
      // (programmatic focus stands in for Full Keyboard Access here).
      await page.locator('[data-kiwi-retry]').focus();
    }

    // :focus-visible must be visually discernible (WCAG 2.4.7).
    const focusVisible = await page.evaluate(() => {
      const ae = document.activeElement;
      return !!ae && !!ae.matches && ae.matches(':focus-visible');
    });
    expect(focusVisible).toBe(true);

    // No keyboard trap — performed while the widget is still failed so the
    // Retry is visible (it is hidden by design in solved state, which
    // would legitimately remove it from the tab order): Tab from the
    // button reaches #kiwi-after and Shift+Tab returns to the Retry
    // (Chromium + Firefox; WebKit's platform Tab default does not move
    // among buttons).
    if (engine !== 'webkit') {
      await page.keyboard.press('Tab');
      const reachedAfter = await page.evaluate(() => !!document.activeElement && document.activeElement.id === 'kiwi-after');
      expect(reachedAfter, 'Tab after the Retry button must reach the following control').toBe(true);
      await page.keyboard.press('Shift+Tab');
      const backToRetry = await page.evaluate(() => {
        const ae = document.activeElement;
        return !!ae && ae.getAttribute('data-kiwi-retry') !== null;
      });
      expect(backToRetry, 'Shift+Tab must return focus to the Retry button').toBe(true);
    } else {
      // WebKit no-trap proof: Shift+Tab from the button keeps focus within
      // the page (never the browser chrome / widget).
      await page.keyboard.press('Shift+Tab');
      const stillInPage = await page.evaluate(() => {
        const ae = document.activeElement;
        return ae && ae !== document.body ? true : false;
      });
      expect(stillInPage).toBe(true);
      // WebKit's Shift+Tab moved focus off the button; return it before
      // the activation steps (in the platform's Full Keyboard Access
      // model the button would already be the focus).
      await page.locator('[data-kiwi-retry]').focus();
    }

    // Enter reacquires (first failure cycle).
    failing = false;
    await page.keyboard.press('Enter');
    await expect(page.locator('[data-kiwi-widget]')).toHaveAttribute('data-state', 'done', { timeout: 60_000 });
    await expect(page.locator('[data-kiwi-token]')).not.toHaveValue('');

    // Space activates too: drive a real second failure cycle (reset ->
    // failing endpoint -> terminal failed -> Retry visible), then Space.
    failing = true;
    const wid = await page.evaluate(() => document.querySelector('[data-kiwi-widget]').dataset.kiwiInstance);
    await page.evaluate((id) => window.KiwiCaptcha.reset(id), wid);
    await expect(page.locator('[data-kiwi-widget]')).toHaveAttribute('data-state', 'failed', { timeout: 60_000 });
    await page.locator('[data-kiwi-retry]').focus();
    failing = false;
    await page.keyboard.press('Space');
    await expect(page.locator('[data-kiwi-widget]')).toHaveAttribute('data-state', 'done', { timeout: 60_000 });
  });

  test('pointer targets: Retry >= 24x24 CSS px (32px height)', async ({ page }) => {
    let failing = true;
    await page.route('**/challenge', async (route) => {
      if (failing) {
        await route.fulfill({ status: 503, contentType: 'application/json', body: '{"error":"down"}' });
      } else {
        await route.continue();
      }
    });
    await page.goto('/');
    await expect(page.locator('[data-kiwi-widget]')).toHaveAttribute('data-state', 'failed', { timeout: 30_000 });
    const box = await page.locator('[data-kiwi-retry]').boundingBox();
    expect(box.width).toBeGreaterThanOrEqual(24);
    expect(box.height).toBeGreaterThanOrEqual(24);
    // The audit's 32px recommendation for an accessibility/security control.
    expect(box.height).toBeGreaterThanOrEqual(32);
  });

  test('non-text contrast (WCAG 1.4.11): COMPUTED Retry control boundary and focus indicator >= 3:1, light AND dark', async ({ page }) => {
    // WCAG 1.4.11 requires UI-component boundaries and the
    // focus indicator to be >= 3:1 against the adjacent surface. The test
    // computes the colors in the browser (getComputedStyle border/outline,
    // button background composited over the widget surface) — it never
    // hard-codes expected colors, so a palette regression in either theme
    // fails here. The suite computes it; a CSS comment does not.
    await page.route('**/challenge', async (route) => {
      await route.fulfill({ status: 503, contentType: 'application/json', body: '{"error":"down"}' });
    });
    for (const theme of ['light', 'dark']) {
      await page.emulateMedia({ colorScheme: theme });
      await page.goto('/');
      await expect(page.locator('[data-kiwi-widget]')).toHaveAttribute('data-state', 'failed', { timeout: 30_000 });
      await page.evaluate(() => {
        const w = document.querySelector('[data-kiwi-widget]');
        const container = w.closest('.kiwi-container');
        const before = document.createElement('input');
        before.id = 'kiwi-before';
        before.setAttribute('aria-label', 'before');
        container.parentNode.insertBefore(before, container);
      });
      // Real keyboard Tab reaches the Retry (Chromium + Firefox); WebKit's
      // platform Tab default skips buttons, so programmatic focus stands in
      // for Full Keyboard Access, mirroring the keyboard-only test.
      const engine = test.info().project.name;
      if (engine !== 'webkit') {
        await page.locator('#kiwi-before').focus();
        await page.keyboard.press('Tab');
      } else {
        await page.locator('[data-kiwi-retry]').focus();
      }
      const focused = await page.evaluate(() => {
        const ae = document.activeElement;
        return !!ae && ae.getAttribute('data-kiwi-retry') !== null && ae.matches(':focus-visible');
      });
      expect(focused, `theme=${theme}: the Retry button must be focused with :focus-visible`).toBe(true);

      const colors = await page.evaluate(() => {
        const w = document.querySelector('[data-kiwi-widget]');
        const retry = w.querySelector('[data-kiwi-retry]');
        const parse = (c) => {
          const m = c.match(/rgba?\(([\d.]+)[,\s]+([\d.]+)[,\s]+([\d.]+)(?:[,\s/]+([\d.]+))?/);
          if (!m) return null;
          return { r: Number(m[1]), g: Number(m[2]), b: Number(m[3]), a: m[4] !== undefined ? Number(m[4]) : 1 };
        };
        const composite = (fgc, bgc) => ({ r: fgc.r * fgc.a + bgc.r * (1 - fgc.a), g: fgc.g * fgc.a + bgc.g * (1 - fgc.a), b: fgc.b * fgc.a + bgc.b * (1 - fgc.a) });
        const toHex = ({ r, g, b }) => '#' + [r, g, b].map((v) => Math.max(0, Math.min(255, Math.round(v))).toString(16).padStart(2, '0')).join('');
        const cs = (el) => getComputedStyle(el);
        const surface = parse(cs(w).backgroundColor);
        const retryBg = parse(cs(retry).backgroundColor);
        const border = parse(cs(retry).borderTopColor);
        let indicator = null;
        let indicatorKind = null;
        const outlineStyle = cs(retry).outlineStyle;
        const outlineWidth = parseFloat(cs(retry).outlineWidth);
        if (outlineStyle !== 'none' && outlineWidth > 0) {
          indicator = parse(cs(retry).outlineColor);
          indicatorKind = 'outline';
        } else {
          const shadowColors = (cs(retry).boxShadow.match(/rgba?\([^)]*\)/g) || []).map(parse).filter((c) => c && c.a > 0);
          if (shadowColors.length) { indicator = shadowColors[0]; indicatorKind = 'box-shadow'; }
        }
        if (!surface || !retryBg || !border || !indicator) {
          return { error: JSON.stringify({ surface: cs(w).backgroundColor, retryBg: cs(retry).backgroundColor, border: cs(retry).borderTopColor, outline: cs(retry).outlineColor, boxShadow: cs(retry).boxShadow }) };
        }
        return {
          boundary: { border: toHex(border), adjacent: toHex(composite(retryBg, surface)) },
          indicator: { color: toHex(indicator), adjacent: toHex(surface), kind: indicatorKind },
        };
      });
      expect(colors.error, `theme=${theme}: ${colors.error}`).toBeUndefined();
      const boundaryRatio = contrastRatio(colors.boundary.border, colors.boundary.adjacent);
      const indicatorRatio = contrastRatio(colors.indicator.color, colors.indicator.adjacent);
      expect(boundaryRatio, `theme=${theme}: Retry control boundary must be >= 3:1 (WCAG 1.4.11; measured ${boundaryRatio.toFixed(2)}:1 ${colors.boundary.border} vs ${colors.boundary.adjacent})`).toBeGreaterThanOrEqual(3);
      expect(indicatorRatio, `theme=${theme}: focus indicator (${colors.indicator.kind}) must be >= 3:1 (WCAG 1.4.11; measured ${indicatorRatio.toFixed(2)}:1 ${colors.indicator.color} vs ${colors.indicator.adjacent})`).toBeGreaterThanOrEqual(3);
    }
  });

  test('focus appearance (WCAG 2.4.13): indicator AREA >= the 2px-perimeter minimum AND >= 3:1 contrast CHANGE at the SAME pixels, light AND dark', async ({ page }) => {
    // 2.4.13 is not met by 1.4.11-style adjacent-surface contrast alone:
    // it requires (a) a minimum indicator area — at least the area of a
    // 2 CSS px thick perimeter of the unfocused control — and (b) a
    // >= 3:1 contrast change between the focused and unfocused states at
    // the same pixels. Both are genuinely measured here: (a) from the
    // indicator's computed geometry over the control's bounding box;
    // (b) by sampling the pixel at the indicator location in both states —
    // the surface the browser actually paints there unfocused, and the
    // indicator composited over that same surface focused. All colors are
    // computed in the browser; none are hard-coded, so a palette regression
    // in either theme fails here.
    await page.route('**/challenge', async (route) => {
      await route.fulfill({ status: 503, contentType: 'application/json', body: '{"error":"down"}' });
    });
    for (const theme of ['light', 'dark']) {
      await page.emulateMedia({ colorScheme: theme });
      await page.goto('/');
      await expect(page.locator('[data-kiwi-widget]')).toHaveAttribute('data-state', 'failed', { timeout: 30_000 });
      await page.evaluate(() => {
        const w = document.querySelector('[data-kiwi-widget]');
        const container = w.closest('.kiwi-container');
        const before = document.createElement('input');
        before.id = 'kiwi-before';
        before.setAttribute('aria-label', 'before');
        container.parentNode.insertBefore(before, container);
      });
      const engine = test.info().project.name;
      if (engine !== 'webkit') {
        await page.locator('#kiwi-before').focus();
        await page.keyboard.press('Tab');
      } else {
        await page.locator('[data-kiwi-retry]').focus();
      }
      const focused = await page.evaluate(() => {
        const ae = document.activeElement;
        return !!ae && ae.getAttribute('data-kiwi-retry') !== null && ae.matches(':focus-visible');
      });
      expect(focused, `theme=${theme}: the Retry button must be focused with :focus-visible`).toBe(true);

      const focusedM = await measuredFocusGeometry(page);
      expect(focusedM.error, `theme=${theme}: ${focusedM.error}`).toBeUndefined();

      // Unfocus and re-measure at the same coordinates: the pixel at the
      // ring location must go back to the surface the indicator covers.
      await page.locator('#kiwi-before').focus();
      const unfocusedM = await surfacePixelAt(page, focusedM.sample);
      expect(unfocusedM.error, `theme=${theme}: ${unfocusedM.error}`).toBeUndefined();
      expect(Math.abs(focusedM.sample.x - unfocusedM.x), `theme=${theme}: the unfocused sample must be the SAME pixel (x)`).toBeLessThan(0.5);
      expect(Math.abs(focusedM.sample.y - unfocusedM.y), `theme=${theme}: the unfocused sample must be the SAME pixel (y)`).toBeLessThan(0.5);
      expect(unfocusedM.pixel, `theme=${theme}: the pixel at the ring location must return to the surface (${focusedM.surface}) when unfocused`).toBe(focusedM.surface);

      const change = contrastRatio(focusedM.focusedPixel, unfocusedM.pixel);
      expect(change, `theme=${theme}: the SAME pixel must change >= 3:1 between unfocused (${unfocusedM.pixel}) and focused (${focusedM.focusedPixel}); measured ${change.toFixed(2)}:1`).toBeGreaterThanOrEqual(3);

      if (focusedM.kind === 'outline') {
        expect(focusedM.thickness, `theme=${theme}: the ring must be >= 2 CSS px thick (measured ${focusedM.thickness}px)`).toBeGreaterThanOrEqual(2);
        expect(focusedM.ringArea, `theme=${theme}: indicator area ${focusedM.ringArea.toFixed(1)}px^2 must be >= the 2px-perimeter minimum ${focusedM.twoPxPerimeterArea.toFixed(1)}px^2`).toBeGreaterThanOrEqual(focusedM.twoPxPerimeterArea - 0.5);
      } else if (focusedM.areaInfeasible) {
        throw new Error(`theme=${theme}: the 2.4.13 area measurement is genuinely infeasible for the computed indicator (${focusedM.areaInfeasible}) with the suite's primitives — the document must fall back to manual-qualification wording for 2.4.13`);
      } else {
        expect(focusedM.ringArea, `theme=${theme}: indicator area ${focusedM.ringArea.toFixed(1)}px^2 must be >= the 2px-perimeter minimum ${focusedM.twoPxPerimeterArea.toFixed(1)}px^2`).toBeGreaterThanOrEqual(focusedM.twoPxPerimeterArea - 0.5);
      }
    }
  });

  test('semantics: progress track hidden from AT, status live region polite + meaningful only', async ({ page }) => {
    await page.goto('/');
    const sem = await page.evaluate(() => {
      const w = document.querySelector('[data-kiwi-widget]');
      const track = w.querySelector('.kiwi-track');
      const status = w.querySelector('[data-kiwi-status]');
      return {
        trackAriaHidden: track ? track.getAttribute('aria-hidden') : null,
        trackRole: track ? track.getAttribute('role') : null,
        statusRole: status ? status.getAttribute('role') : null,
        statusLive: status ? status.getAttribute('aria-live') : null,
        statusText: status ? status.textContent : null,
      };
    });
    expect(sem.trackAriaHidden).toBe('true');
    expect(sem.trackRole).toBeNull();
    expect(sem.statusRole).toBe('status');
    expect(sem.statusLive).toBe('polite');
    // The announcer reports only meaningful transitions (verified here).
    await expect(page.locator('[data-kiwi-status]')).toHaveText('Verification complete', { timeout: 60_000 });
  });

  test('semantics: exactly ONE widget-local live region, in the static AND initialized markup', async ({ page }) => {
    await page.goto('/');
    const before = await page.evaluate(() => {
      const w = document.querySelector('[data-kiwi-widget]');
      const container = w.closest('.kiwi-container');
      return {
        inWidget: w.querySelectorAll('[data-kiwi-status]').length,
        inContainerOutsideWidget: container.querySelectorAll(':scope > [data-kiwi-status]').length,
        statusRoles: w.querySelectorAll('[data-kiwi-status][role="status"]').length,
        polite: w.querySelectorAll('[data-kiwi-status][aria-live="polite"]').length,
        pageLive: document.querySelectorAll('[role="status"], [aria-live]').length,
        progressbars: document.querySelectorAll('[role="progressbar"]').length,
        countdownInLive: (() => {
          const s = w.querySelector('[data-kiwi-status]');
          return s ? s.querySelectorAll('.kiwi-timer').length : 0;
        })(),
      };
    });
    expect(before.inWidget).toBe(1);
    expect(before.inContainerOutsideWidget).toBe(0);
    expect(before.statusRoles).toBe(1);
    expect(before.polite).toBe(1);
    expect(before.pageLive).toBe(1);
    expect(before.progressbars).toBe(0);
    expect(before.countdownInLive).toBe(0);

    await expect(page.locator('[data-kiwi-widget]')).toHaveAttribute('data-state', 'done', { timeout: 60_000 });
    const after = await page.evaluate(() => {
      const w = document.querySelector('[data-kiwi-widget]');
      return {
        inWidget: w.querySelectorAll('[data-kiwi-status]').length,
        statusRoles: w.querySelectorAll('[data-kiwi-status][role="status"]').length,
        pageLive: document.querySelectorAll('[role="status"], [aria-live]').length,
      };
    });
    expect(after.inWidget).toBe(1);
    expect(after.statusRoles).toBe(1);
    expect(after.pageLive).toBe(1);
  });

  test('responsive: 320px reflow loses no content or function', async ({ page }) => {
    await page.setViewportSize({ width: 320, height: 720 });
    await page.goto('/');
    await expect(page.locator('[data-kiwi-widget]')).toHaveAttribute('data-state', 'done', { timeout: 60_000 });

    const reflow = await page.evaluate(() => {
      const tk = document.querySelector('[data-kiwi-token]');
      const w = document.querySelector('[data-kiwi-widget]');
      const visible = (el) => { const r = el.getBoundingClientRect(); return r.width > 0 && r.height > 0 && r.left < innerWidth && r.right > 0; };
      const retry = w.querySelector('[data-kiwi-retry]');
      return {
        overflowX: document.documentElement.scrollWidth > document.documentElement.clientWidth,
        widgetVisible: visible(w),
        labelVisible: visible(w.querySelector('[data-kiwi-label]')),
        badgeVisible: visible(w.querySelector('[data-kiwi-badge]')),
        retryVisible: retry && getComputedStyle(retry).display !== 'none' ? visible(retry) : true,
        token: tk ? tk.value.length > 0 : false,
        liveRegion: !!w.querySelector('[data-kiwi-status][role="status"]'),
      };
    });
    expect(reflow.overflowX).toBe(false);
    expect(reflow.widgetVisible).toBe(true);
    expect(reflow.labelVisible).toBe(true);
    expect(reflow.badgeVisible).toBe(true);
    expect(reflow.retryVisible).toBe(true);
    expect(reflow.token).toBe(true);
    expect(reflow.liveRegion).toBe(true);
  });

  test('responsive: 2x component font-scale enlargement loses no content or function', async ({ page }) => {
    // Component-level custom-property stress test: the widget typography
    // derives from --kiwi-font-scale, and doubling the custom property is
    // a 2x component font-scale enlargement. This is NOT actual browser/
    // user text zoom — real 200% browser zoom (WCAG 1.4.4) remains part
    // of the manual accessibility qualification. overflow:hidden on the
    // widget is tested explicitly — enlarged content must not be clipped
    // by it.
    await page.setViewportSize({ width: 900, height: 900 });
    await page.goto('/');
    await expect(page.locator('[data-kiwi-widget]')).toHaveAttribute('data-state', 'done', { timeout: 60_000 });
    const before = await page.evaluate(() => {
      const w = document.querySelector('[data-kiwi-widget]');
      return getComputedStyle(w.querySelector('[data-kiwi-label]')).fontSize;
    });
    await page.evaluate(() => {
      document.querySelector('.kiwi-container').style.setProperty('--kiwi-font-scale', '2');
    });
    const at200 = await page.evaluate((beforeSize) => {
      const w = document.querySelector('[data-kiwi-widget]');
      const label = w.querySelector('[data-kiwi-label]');
      const badge = w.querySelector('.kiwi-badge');
      const info = w.querySelector('[data-kiwi-info]');
      const retry = w.querySelector('[data-kiwi-retry]');
      const rect = (el) => { const r = el.getBoundingClientRect(); return { x: r.x, y: r.y, w: r.width, h: r.height, right: r.right, bottom: r.bottom }; };
      const labelR = rect(label), badgeR = rect(badge), infoR = rect(info);
      const widgetR = rect(w);
      const now = parseFloat(getComputedStyle(label).fontSize);
      const overlaps = (a, b) => !(a.right <= b.x + 1 || b.right <= a.x + 1 || a.bottom <= b.y + 1 || b.bottom <= a.y + 1);
      return {
        scaled: now >= parseFloat(beforeSize) * 1.9,
        labelVisible: labelR.w > 0 && labelR.h > 0 && labelR.right <= widgetR.right + 1 && labelR.x >= widgetR.x - 1,
        badgeVisible: badgeR.w > 0 && badgeR.h > 0 && badgeR.right <= widgetR.right + 1,
        infoVisible: infoR.w > 0 && infoR.h > 0,
        retryVisible: retry && getComputedStyle(retry).display !== 'none' ? rect(retry).w > 0 && rect(retry).h > 0 : true,
        clippedByOverflow: labelR.right > widgetR.right + 1 || infoR.right > widgetR.right + 1,
        overlapLabelBadge: overlaps(labelR, badgeR),
        overlapBadgeInfo: overlaps(badgeR, infoR),
        overflowX: document.documentElement.scrollWidth > document.documentElement.clientWidth,
        liveRegion: !!w.querySelector('[data-kiwi-status][role="status"]'),
        token: document.querySelector('[data-kiwi-token]').value.length > 0,
      };
    }, before);
    expect(at200.scaled, 'font must actually double').toBe(true);
    expect(at200.labelVisible).toBe(true);
    expect(at200.badgeVisible).toBe(true);
    expect(at200.infoVisible).toBe(true);
    expect(at200.retryVisible).toBe(true);
    expect(at200.clippedByOverflow, 'enlarged text must not be clipped by the widget overflow:hidden').toBe(false);
    expect(at200.overlapLabelBadge).toBe(false);
    expect(at200.overlapBadgeInfo).toBe(false);
    expect(at200.overflowX).toBe(false);
    expect(at200.liveRegion).toBe(true);
    expect(at200.token).toBe(true);
  });

  test('responsive: WCAG 1.4.12 text-spacing overrides (all FOUR conditions) lose no content or function', async ({ page }) => {
    await page.goto('/');
    await expect(page.locator('[data-kiwi-widget]')).toHaveAttribute('data-state', 'done', { timeout: 60_000 });
    // 1.4.12 requires all four conditions simultaneously: line-height >=
    // 1.5x, paragraph spacing >= 2x, letter-spacing >= 0.12x, word-spacing
    // >= 0.16x.
    await page.evaluate(() => {
      const style = document.createElement('style');
      style.textContent = `
        * { line-height: 1.5 !important; letter-spacing: 0.12em !important; word-spacing: 0.16em !important; }
        p { margin-bottom: 2em !important; }
      `;
      document.head.appendChild(style);
    });
    const spaced = await page.evaluate(() => {
      const w = document.querySelector('[data-kiwi-widget]');
      const label = w.querySelector('[data-kiwi-label]');
      const badge = w.querySelector('.kiwi-badge');
      const info = w.querySelector('[data-kiwi-info]');
      const lr = label.getBoundingClientRect(), br = badge.getBoundingClientRect(), ir = info.getBoundingClientRect();
      const wr = w.getBoundingClientRect();
      return {
        overflowX: document.documentElement.scrollWidth > document.documentElement.clientWidth,
        widgetVisible: wr.width > 0,
        labelVisible: lr.width > 0 && lr.height > 0 && lr.right <= wr.right + 1,
        badgeVisible: br.width > 0 && br.height > 0 && br.right <= wr.right + 1,
        infoVisible: ir.width > 0 && ir.height > 0 && ir.right <= wr.right + 1,
        liveRegion: !!w.querySelector('[data-kiwi-status][role="status"]'),
        token: document.querySelector('[data-kiwi-token]').value.length > 0,
      };
    });
    expect(spaced.overflowX).toBe(false);
    expect(spaced.widgetVisible).toBe(true);
    expect(spaced.labelVisible).toBe(true);
    expect(spaced.badgeVisible).toBe(true);
    expect(spaced.infoVisible).toBe(true);
    expect(spaced.liveRegion).toBe(true);
    expect(spaced.token).toBe(true);
  });

  test('reduced motion: no decorative CSS animation and the SMIL wink is removed', async ({ page }) => {
    await page.emulateMedia({ reducedMotion: 'reduce' });
    await page.goto('/');
    await expect(page.locator('[data-kiwi-widget]')).toHaveAttribute('data-state', 'done', { timeout: 60_000 });
    const motion = await page.evaluate(() => {
      const w = document.querySelector('[data-kiwi-widget]');
      const anims = Array.from(w.querySelectorAll('*')).map((el) => getComputedStyle(el).animationName).filter((n) => n && n !== 'none');
      return { anims, wink: !!w.querySelector('.kiwi-icon-wrapper svg animate') };
    });
    expect(motion.anims).toEqual([]);
    expect(motion.wink).toBe(false);
  });

  test('forced colors: the widget and Retry stay discernible with system colors', async ({ page }) => {
    await page.emulateMedia({ forcedColors: 'active' });
    await page.goto('/');
    const forced = await page.evaluate(() => {
      const w = document.querySelector('[data-kiwi-widget]');
      const style = getComputedStyle(w);
      const retry = w.querySelector('[data-kiwi-retry]');
      return {
        border: style.borderTopStyle !== 'none' && style.borderTopColor,
        retryBorder: retry ? getComputedStyle(retry).borderTopStyle !== 'none' : false,
      };
    });
    expect(forced.border).toBeTruthy();
    expect(forced.retryBorder).toBe(true);
  });

  test('locale contract: RTL (ar) sets dir=rtl + lang on the subtree; fallback stays lang=en', async ({ page }) => {
    await page.goto('/?lang=ar');
    await expect(page.locator('[data-kiwi-widget]')).toHaveAttribute('data-state', 'done', { timeout: 60_000 });
    const rtl = await page.evaluate(() => {
      const w = document.querySelector('[data-kiwi-widget]');
      return { lang: w.getAttribute('lang'), dir: w.getAttribute('dir'), label: w.querySelector('[data-kiwi-label]').textContent };
    });
    expect(rtl.lang).toBe('ar');
    expect(rtl.dir).toBe('rtl');
    expect(rtl.label.length).toBeGreaterThan(0);

    // A page with an unknown locale marks lang=en.
    await page.goto('/?lang=xx');
    await expect(page.locator('[data-kiwi-widget]')).toHaveAttribute('data-state', 'done', { timeout: 60_000 });
    const fallback = await page.evaluate(() => document.querySelector('[data-kiwi-widget]').getAttribute('lang'));
    expect(fallback).toBe('en');
  });

  test('locale contract: German long strings fit the widget without overflow', async ({ page }) => {
    await page.goto('/?lang=de');
    await expect(page.locator('[data-kiwi-widget]')).toHaveAttribute('data-state', 'done', { timeout: 60_000 });
    const de = await page.evaluate(() => {
      const w = document.querySelector('[data-kiwi-widget]');
      const label = w.querySelector('[data-kiwi-label]').textContent;
      const badge = w.querySelector('[data-kiwi-badge]').textContent;
      const hint = w.querySelector('[data-kiwi-info]').textContent;
      const retry = w.querySelector('[data-kiwi-retry]');
      return {
        lang: w.getAttribute('lang'),
        label, badge, hint,
        retryText: retry ? retry.textContent : null,
        overflowX: document.documentElement.scrollWidth > document.documentElement.clientWidth,
      };
    });
    expect(de.lang).toBe('de');
    expect(de.label).toContain('Sicherheitspr');
    expect(de.badge).toBe('Erfolgreich');
    expect(de.retryText).toBe('Erneut');
    expect(de.overflowX).toBe(false);
  });
});
