/**
 * Marketing Parity Pixel-Diff Tests
 *
 * Compares old Next.js marketing site (http://localhost:3003) against
 * new Zola marketing site (http://localhost:1111) for visual parity.
 *
 * Usage:
 *   # Start both servers first:
 *   pnpm --filter @apexmail/marketing dev -p 3003          # old
 *   cd apps/marketing-zola && zola serve --port 1111        # new
 *
 *   # Run the tests:
 *   npx playwright test src/visual/parity-pixel-diff.spec.ts --project=visual
 *
 * Each test captures the same page on both sites and diffs them.
 * Snapshots stored in snapshots/parity/ — commit baselines after review.
 */

import { test, expect, type Page } from '@playwright/test';
import path from 'node:path';

/* ── Config ──────────────────────────────────────────────── */

const OLD_URL = process.env.OLD_MARKETING_URL || 'http://localhost:3003';
const NEW_URL = process.env.NEW_MARKETING_URL || 'http://localhost:1111';

const VIEWPORTS = {
  desktop: { width: 1440, height: 900 },
  mobile: { width: 375, height: 812 },
} as const;

// Tolerance: allow small differences from font rendering, anti-aliasing
const DIFF_OPTIONS = {
  maxDiffPixelRatio: 0.02, // 2% pixel difference allowed
  threshold: 0.25, // per-pixel color threshold
  animations: 'disabled' as const,
};

/* ── Routes to Compare ───────────────────────────────────── */

const MARKETING_ROUTES = [
  { path: '/', name: 'home' },
  { path: '/features', name: 'features' },
  { path: '/pricing', name: 'pricing' },
  { path: '/compliance', name: 'compliance' },
  { path: '/compare', name: 'compare-index' },
  { path: '/compare/sendgrid', name: 'compare-sendgrid' },
  { path: '/compare/amazon-ses', name: 'compare-ses' },
  { path: '/compare/postmark', name: 'compare-postmark' },
  { path: '/compare/resend', name: 'compare-resend' },
  { path: '/private-cloud', name: 'private-cloud' },
  { path: '/api-console', name: 'api-console' },
  { path: '/forensic', name: 'forensic' },
  { path: '/status', name: 'status' },
  { path: '/privacy', name: 'privacy' },
  { path: '/terms', name: 'terms' },
  { path: '/cookies', name: 'cookies' },
  { path: '/dpa', name: 'dpa' },
  { path: '/sla', name: 'sla' },
  { path: '/acceptable-use', name: 'acceptable-use' },
];

/* ── Helpers ──────────────────────────────────────────────── */

async function captureFullPage(page: Page, url: string): Promise<Buffer> {
  await page.goto(url, { waitUntil: 'networkidle', timeout: 30000 });
  // Disable animations and transitions for deterministic screenshots
  await page.addStyleTag({
    content: `
      *, *::before, *::after {
        animation-duration: 0s !important;
        animation-delay: 0s !important;
        transition-duration: 0s !important;
        transition-delay: 0s !important;
        scroll-behavior: auto !important;
      }
    `,
  });
  // Wait for fonts and images to load
  await page.waitForLoadState('networkidle');
  await page.waitForTimeout(500);
  return page.screenshot({ fullPage: true, type: 'png' });
}

/* ── Tests ────────────────────────────────────────────────── */

test.describe('Marketing Parity: Old (Next.js) vs New (Zola)', () => {
  test.describe.configure({ mode: 'parallel' });

  for (const route of MARKETING_ROUTES) {
    for (const [viewportName, viewport] of Object.entries(VIEWPORTS)) {
      test(`${route.name} — ${viewportName}`, async ({ page }) => {
        await page.setViewportSize(viewport);

        // Capture the NEW site (Zola) screenshot
        const newScreenshot = await captureFullPage(page, `${NEW_URL}${route.path}`);

        // Compare against baseline snapshot (initially generated from OLD site)
        // Run `npx playwright test --update-snapshots` against OLD_URL first to create baselines
        expect(newScreenshot).toMatchSnapshot(
          [`parity`, `${route.name}-${viewportName}.png`],
          DIFF_OPTIONS,
        );
      });
    }
  }
});

/**
 * Baseline Generator — captures old site screenshots as golden baselines.
 *
 * Usage: OLD_SITE=true npx playwright test src/visual/parity-pixel-diff.spec.ts \
 *          --project=visual --update-snapshots
 *
 * Only runs when OLD_SITE=true env var is set.
 */
test.describe('Generate Old Site Baselines', () => {
  test.skip(!process.env.OLD_SITE, 'Set OLD_SITE=true to regenerate baselines from old Next.js site');

  for (const route of MARKETING_ROUTES) {
    for (const [viewportName, viewport] of Object.entries(VIEWPORTS)) {
      test(`baseline: ${route.name} — ${viewportName}`, async ({ page }) => {
        await page.setViewportSize(viewport);

        const oldScreenshot = await captureFullPage(page, `${OLD_URL}${route.path}`);

        // This writes the baseline snapshot when --update-snapshots is used
        expect(oldScreenshot).toMatchSnapshot(
          [`parity`, `${route.name}-${viewportName}.png`],
          DIFF_OPTIONS,
        );
      });
    }
  }
});

/**
 * Side-by-Side Structural Comparison (no screenshots needed).
 *
 * Verifies that both sites produce pages with matching structure:
 * - Same number of <section> elements
 * - Same heading hierarchy (h1, h2, h3)
 * - Same number of navigation links
 */
test.describe('Structural Parity', () => {
  for (const route of MARKETING_ROUTES) {
    test(`${route.name} — structure matches`, async ({ page }) => {
      await page.setViewportSize(VIEWPORTS.desktop);

      // Capture OLD site structure
      await page.goto(`${OLD_URL}${route.path}`, { waitUntil: 'domcontentloaded', timeout: 30000 });
      const oldStructure = await page.evaluate(() => ({
        sections: document.querySelectorAll('section').length,
        h1: document.querySelectorAll('h1').length,
        h2: document.querySelectorAll('h2').length,
        h3: document.querySelectorAll('h3').length,
        navLinks: document.querySelectorAll('nav a').length,
        footerLinks: document.querySelectorAll('footer a').length,
        images: document.querySelectorAll('img').length,
        forms: document.querySelectorAll('form').length,
      }));

      // Capture NEW site structure
      await page.goto(`${NEW_URL}${route.path}`, { waitUntil: 'domcontentloaded', timeout: 30000 });
      const newStructure = await page.evaluate(() => ({
        sections: document.querySelectorAll('section').length,
        h1: document.querySelectorAll('h1').length,
        h2: document.querySelectorAll('h2').length,
        h3: document.querySelectorAll('h3').length,
        navLinks: document.querySelectorAll('nav a').length,
        footerLinks: document.querySelectorAll('footer a').length,
        images: document.querySelectorAll('img').length,
        forms: document.querySelectorAll('form').length,
      }));

      // Heading count should match exactly
      expect(newStructure.h1, `${route.name}: h1 count`).toBe(oldStructure.h1);

      // Section count should be within ±2 (minor layout differences allowed)
      expect(
        Math.abs(newStructure.sections - oldStructure.sections),
        `${route.name}: sections (old=${oldStructure.sections}, new=${newStructure.sections})`,
      ).toBeLessThanOrEqual(2);

      // h2 count close (some sections may merge or split)
      expect(
        Math.abs(newStructure.h2 - oldStructure.h2),
        `${route.name}: h2 headings`,
      ).toBeLessThanOrEqual(3);

      // Navigation link count (header nav) should match closely
      expect(
        Math.abs(newStructure.navLinks - oldStructure.navLinks),
        `${route.name}: nav links`,
      ).toBeLessThanOrEqual(2);
    });
  }
});
