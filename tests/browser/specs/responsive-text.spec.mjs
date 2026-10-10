import { test, expect } from '@playwright/test';

// Narrow-container status-text regression gate (the mobile ellipsis
// defect). Meaningful status text must never be clipped with
// text-overflow: ellipsis or refused a wrap: a 240px sidebar on a
// desktop browser (or a small phone) must keep every localized word,
// such as "Kontrola bezpieczeństwa" or the long failure/help messages.
// Box-visibility and page-scrollbar checks alone cannot see ellipsized
// text; this suite proves real glyph fit:
//
// This suite measures the container box itself (not the viewport) at
// 240/280/320px, across English, German, French, Portuguese, Polish and
// Arabic, and proves real glyph fit:
//   - getComputedStyle(el).textOverflow !== 'ellipsis'
//   - white-space wraps (normal)
//   - el.scrollWidth <= el.clientWidth + 1
//   - el.scrollHeight <= el.clientHeight + 1
//   - a Range over the text yields client rects inside the visible box
//   - the widget box stays inside its container
// States: done, connecting (held challenge), failed, worker-unavailable
// and solver-mismatch ("solver-version-error"), plus a 2x font scale at
// the narrow widths. Runs on Chromium, Firefox and WebKit through
// playwright.a11y.config.mjs.

const WIDTHS = [240, 280, 320];
const ALL_LANGUAGES = ['en', 'de', 'fr', 'pt', 'pl', 'ar'];
const LONG_LANGUAGES = ['de', 'pl', 'ar'];

// Every text-bearing element of the widget. The badge carries the
// localized state word ("Fehlgeschlagen", "Erreur de version"), the
// retry button its localized label when the state offers it, and the
// timer its countdown when running.
const TEXT_SELECTORS = [
  { sel: '[data-kiwi-label]', required: true },
  { sel: '[data-kiwi-badge]', required: true },
  { sel: '[data-kiwi-info]', required: true },
  { sel: '[data-kiwi-retry]', required: false, visibleOnly: true },
  { sel: '[data-kiwi-timer]', required: false, nonEmptyOnly: true },
];

async function measureTextFit(page, selector) {
  return page.evaluate((sel) => {
    const el = document.querySelector(sel);
    if (!el) return { missing: true };
    const cs = getComputedStyle(el);
    const elRect = el.getBoundingClientRect();
    const range = document.createRange();
    range.selectNodeContents(el);
    const rects = [...range.getClientRects()];
    // Horizontal overflow is a hard 1px bound (wrapping must keep the
    // text inside the element). Vertically the glyph ink extents can
    // round a couple of pixels beyond the CSS line box in Firefox for
    // Arabic; a genuinely clipped line overflows by a full line-height
    // (13-28px), so 3px keeps the gate sharp.
    const clipped = rects.some(
      (r) => r.right > elRect.right + 1 || r.left < elRect.left - 1 || r.bottom > elRect.bottom + 3 || r.top < elRect.top - 3,
    );
    // Clipping ancestors can mask an overflow that the element's own
    // scroll metrics hide (the widget itself is overflow: hidden), so
    // the glyph rects must also stay inside every clipping ancestor's
    // box.
    let clipRect = { left: elRect.left, right: elRect.right, top: elRect.top, bottom: elRect.bottom };
    for (let node = el.parentElement; node && node !== document.body; node = node.parentElement) {
      const ancestorStyle = getComputedStyle(node);
      if (ancestorStyle.overflowX !== 'visible' || ancestorStyle.overflowY !== 'visible') {
        const nr = node.getBoundingClientRect();
        clipRect = {
          left: Math.max(clipRect.left, nr.left),
          right: Math.min(clipRect.right, nr.right),
          top: Math.max(clipRect.top, nr.top),
          bottom: Math.min(clipRect.bottom, nr.bottom),
        };
      }
    }
    const clippedByAncestors = rects.some(
      (r) => r.right > clipRect.right + 1 || r.left < clipRect.left - 1 || r.bottom > clipRect.bottom + 3 || r.top < clipRect.top - 3,
    );
    const container = el.closest('.kiwi-container');
    const widget = el.closest('[data-kiwi-widget]');
    return {
      text: (el.textContent || '').trim(),
      visible: cs.display !== 'none' && elRect.width > 0 && elRect.height > 0,
      textOverflow: cs.textOverflow,
      whiteSpace: cs.whiteSpace,
      overflowVisible: cs.overflowY === 'visible',
      scrollFitsX: el.scrollWidth <= el.clientWidth + 1,
      // Vertical font-metric rounding: Firefox reports the Arabic glyph
      // ink extents a couple of pixels beyond the CSS line box even
      // though nothing is clipped (overflow stays visible and the Range
      // rects stay inside). A genuinely clipped line overflows by a
      // full line-height (13-28px), so a 3px tolerance keeps the gate
      // sharp while tolerating engine rounding.
      scrollFitsY: el.scrollHeight <= el.clientHeight + 3,
      clipped,
      clippedByAncestors,
      rects: rects.length,
      widgetFits:
        widget && container
          ? widget.getBoundingClientRect().right <= container.getBoundingClientRect().right + 1
          : true,
    };
  }, selector);
}

async function assertTextFits(page, label) {
  for (const { sel, required, visibleOnly, nonEmptyOnly } of TEXT_SELECTORS) {
    const m = await measureTextFit(page, sel);
    if (m.missing) {
      expect(required, `${label} ${sel} exists`).not.toBe(true);
      continue;
    }
    if (visibleOnly && !m.visible) continue;
    if (nonEmptyOnly && m.text.length === 0) continue;
    expect(m.visible, `${label} ${sel} is visible while measured`).toBe(true);
    expect(m.text.length, `${label} ${sel} carries real text`).toBeGreaterThan(0);
    expect(m.textOverflow, `${label} ${sel} never ellipsizes`).not.toBe('ellipsis');
    expect(m.whiteSpace, `${label} ${sel} wraps`).toBe('normal');
    expect(m.overflowVisible, `${label} ${sel} never hides overflow`).toBe(true);
    expect(m.scrollFitsX, `${label} ${sel} scrollWidth fits`).toBe(true);
    expect(m.scrollFitsY, `${label} ${sel} scrollHeight fits`).toBe(true);
    expect(m.clipped, `${label} ${sel} Range glyph rects stay inside the element`).toBe(false);
    expect(m.clippedByAncestors, `${label} ${sel} glyph rects survive clipping ancestors`).toBe(false);
    expect(m.rects, `${label} ${sel} has measurable glyph rects`).toBeGreaterThan(0);
    expect(m.widgetFits, `${label} widget fits its container`).toBe(true);
  }
}

async function setContainerWidth(page, width) {
  await page.evaluate((w) => {
    const container = document.querySelector('.kiwi-container');
    container.style.width = `${w}px`;
    container.style.maxWidth = `${w}px`;
  }, width);
}

async function assertAcrossWidths(page, label) {
  for (const width of WIDTHS) {
    await setContainerWidth(page, width);
    await assertTextFits(page, `${label} @${width}px`);
  }
}

async function assertFontScale(page, label) {
  await page.evaluate(() => {
    document.querySelector('.kiwi-container').style.setProperty('--kiwi-font-scale', '2');
  });
  for (const width of [240, 320]) {
    await setContainerWidth(page, width);
    await assertTextFits(page, `${label} 2x-scale @${width}px`);
  }
}

test.describe('narrow-container status text never clips', () => {
  test('done state: 240/280/320px containers across six languages', async ({ page }) => {
    for (const lang of ALL_LANGUAGES) {
      await page.goto(`/?lang=${lang}`);
      await expect(page.locator('[data-kiwi-widget]')).toHaveAttribute('data-state', 'done', { timeout: 60_000 });
      await assertAcrossWidths(page, `${lang} done`);
    }
  });

  test('connecting state: held challenge across RTL and long-word languages', async ({ page }) => {
    for (const lang of LONG_LANGUAGES) {
      let release;
      const held = new Promise((resolvePromise) => {
        release = resolvePromise;
      });
      const route = async (r) => {
        await held;
        await r.abort().catch(() => {});
      };
      await page.route('**/challenge', route);
      await page.goto(`/?lang=${lang}`);
      await expect(page.locator('[data-kiwi-widget]')).toHaveAttribute('data-state', 'connecting', { timeout: 30_000 });
      await assertAcrossWidths(page, `${lang} connecting`);
      release();
      await page.unroute('**/challenge', route);
      await page.goto('about:blank');
    }
  });

  test('failed state: 503 challenge across RTL and long-word languages', async ({ page }) => {
    for (const lang of LONG_LANGUAGES) {
      await page.route('**/challenge', async (route) => {
        await route.fulfill({ status: 503, contentType: 'application/json', body: '{"error":"down"}' });
      });
      await page.goto(`/?lang=${lang}`);
      await expect(page.locator('[data-kiwi-widget]')).toHaveAttribute('data-state', 'failed', { timeout: 30_000 });
      await assertAcrossWidths(page, `${lang} failed`);
      await page.unroute('**/challenge');
    }
  });

  test('worker-unavailable state: failing runtime fetch across RTL and long-word languages', async ({ page }) => {
    for (const lang of LONG_LANGUAGES) {
      await page.route('**/assets/runtime*.js', async (route) => {
        await route.fulfill({ status: 500, contentType: 'application/javascript', body: 'boom' });
      });
      await page.goto(`/?assets=files&algorithm=argon2id&lang=${lang}`);
      await expect(page.locator('[data-kiwi-widget]')).toHaveAttribute('data-state', 'kiwi:worker-unavailable', { timeout: 60_000 });
      await assertAcrossWidths(page, `${lang} worker-unavailable`);
      await page.unroute('**/assets/runtime*.js');
    }
  });

  test('solver-version-error state: stale worker build id across RTL and long-word languages', async ({ page }) => {
    for (const lang of LONG_LANGUAGES) {
      await page.goto(`/?worker-stale=1&algorithm=argon2id&lang=${lang}`);
      await expect(page.locator('[data-kiwi-widget]')).toHaveAttribute('data-state', 'kiwi:solver-mismatch', { timeout: 60_000 });
      await assertAcrossWidths(page, `${lang} solver-mismatch`);
    }
  });

  test('2x font scale at the narrowest container widths still fits', async ({ page }) => {
    for (const lang of LONG_LANGUAGES) {
      await page.goto(`/?lang=${lang}`);
      await expect(page.locator('[data-kiwi-widget]')).toHaveAttribute('data-state', 'done', { timeout: 60_000 });
      await assertFontScale(page, `${lang} done`);
    }
    await page.route('**/challenge', async (route) => {
      await route.fulfill({ status: 503, contentType: 'application/json', body: '{"error":"down"}' });
    });
    await page.goto('/?lang=de');
    await expect(page.locator('[data-kiwi-widget]')).toHaveAttribute('data-state', 'failed', { timeout: 30_000 });
    await assertFontScale(page, 'de failed');
  });

  test('2x localized badges at 240px: the widest shipped state words stay inside the widget', async ({ page }) => {
    // The badge carries the localized state word. At 2x the 11px mono
    // face renders at 22px, and the widest shipped words (German
    // "Fehlgeschlagen" / "Versionsfehler" / "Nicht verfügbar", French
    // "Erreur de version" / "Indisponible", the Arabic set) exceed the
    // narrow main column if the badge refuses to wrap. Every case is
    // probed for actual glyph containment, including clipping ancestors.
    const cases = [
      { lang: 'de', state: 'failed', expect: 'Fehlgeschlagen', setup: '503' },
      { lang: 'de', state: 'kiwi:solver-mismatch', expect: 'Versionsfehler', setup: 'worker-stale' },
      { lang: 'de', state: 'kiwi:worker-unavailable', expect: 'Nicht verf', setup: 'runtime-500' },
      { lang: 'fr', state: 'kiwi:solver-mismatch', expect: 'Erreur de version', setup: 'worker-stale' },
      { lang: 'fr', state: 'kiwi:worker-unavailable', expect: 'Indisponible', setup: 'runtime-500' },
      { lang: 'ar', state: 'failed', expect: null, setup: '503' },
      { lang: 'ar', state: 'kiwi:worker-unavailable', expect: null, setup: 'runtime-500' },
    ];
    for (const { lang, state, expect: expectedText, setup } of cases) {
      if (setup === '503' || setup === 'runtime-500') {
        const pattern = setup === '503' ? '**/challenge' : '**/assets/runtime*.js';
        await page.route(pattern, async (route) => {
          await route.fulfill(
            setup === '503'
              ? { status: 503, contentType: 'application/json', body: '{"error":"down"}' }
              : { status: 500, contentType: 'application/javascript', body: 'boom' },
          );
        });
        const url =
          setup === '503'
            ? `/?lang=${lang}`
            : `/?assets=files&algorithm=argon2id&lang=${lang}`;
        await page.goto(url);
        await expect(page.locator('[data-kiwi-widget]')).toHaveAttribute('data-state', state, { timeout: 60_000 });
        await page.unroute(pattern);
      } else {
        await page.goto(`/?worker-stale=1&algorithm=argon2id&lang=${lang}`);
        await expect(page.locator('[data-kiwi-widget]')).toHaveAttribute('data-state', state, { timeout: 60_000 });
      }
      if (expectedText) {
        await expect(page.locator('[data-kiwi-badge]')).toContainText(expectedText);
      }
      await page.evaluate(() => {
        document.querySelector('.kiwi-container').style.setProperty('--kiwi-font-scale', '2');
      });
      await setContainerWidth(page, 240);
      await assertTextFits(page, `${lang} ${state} 2x @240px`);
    }
  });
});
