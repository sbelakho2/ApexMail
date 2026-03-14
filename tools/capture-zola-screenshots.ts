/**
 * Zola Site Screenshot Capture
 *
 * Captures full-page screenshots of every route on the Zola marketing site.
 * Used for before/after visual comparison during dead code cleanup.
 *
 * Usage:
 *   npx playwright test tools/capture-zola-screenshots.ts --config tools/capture-config.ts
 *   PHASE=before npx tsx tools/capture-zola-screenshots.ts
 */

import { chromium } from 'playwright';
import { mkdirSync, writeFileSync } from 'fs';
import { join } from 'path';
import { createHash } from 'crypto';

const ZOLA_URL = process.env.ZOLA_URL || 'http://127.0.0.1:1111';
const PHASE = process.env.PHASE || 'before';
const OUT_DIR = join(process.cwd(), 'reports', 'visual-parity', PHASE);

const ROUTES = [
  '/',
  '/features',
  '/pricing',
  '/compliance',
  '/compare',
  '/compare/sendgrid',
  '/compare/amazon-ses',
  '/compare/postmark',
  '/compare/resend',
  '/private-cloud',
  '/api-console',
  '/forensic',
  '/status',
  '/privacy',
  '/terms',
  '/cookies',
  '/dpa',
  '/sla',
  '/acceptable-use',
];

const VIEWPORTS = {
  desktop: { width: 1440, height: 900 },
  mobile: { width: 375, height: 812 },
};

interface ScreenshotResult {
  route: string;
  viewport: string;
  file: string;
  size: number;
  hash: string;
}

async function main() {
  mkdirSync(OUT_DIR, { recursive: true });

  const browser = await chromium.launch({ headless: true });
  const results: ScreenshotResult[] = [];

  for (const [vpName, vpSize] of Object.entries(VIEWPORTS)) {
    const context = await browser.newContext({
      viewport: vpSize,
      reducedMotion: 'reduce',
      ignoreHTTPSErrors: true,
    });

    const page = await context.newPage();

    // Disable all animations for deterministic screenshots
    await page.addInitScript(() => {
      const style = document.createElement('style');
      style.textContent = `
        *, *::before, *::after {
          animation-duration: 0s !important;
          animation-delay: 0s !important;
          transition-duration: 0s !important;
          transition-delay: 0s !important;
          scroll-behavior: auto !important;
        }
      `;
      document.head.appendChild(style);
    });

    for (const route of ROUTES) {
      const url = `${ZOLA_URL}${route}`;
      const safeName = route === '/' ? 'home' : route.replace(/\//g, '-').replace(/^-/, '');
      const filename = `${safeName}-${vpName}.png`;

      try {
        await page.goto(url, { waitUntil: 'networkidle', timeout: 15000 });
        // Extra wait for fonts and images
        await page.waitForTimeout(500);

        const screenshot = await page.screenshot({ fullPage: true, type: 'png' });
        const filepath = join(OUT_DIR, filename);
        writeFileSync(filepath, screenshot);

        const hash = createHash('sha256').update(screenshot).digest('hex').slice(0, 16);
        results.push({
          route,
          viewport: vpName,
          file: filename,
          size: screenshot.length,
          hash,
        });
        
        console.log(`  ✓ ${route} [${vpName}] → ${filename} (${(screenshot.length / 1024).toFixed(1)} KB, sha256:${hash})`);
      } catch (err) {
        console.error(`  ✗ ${route} [${vpName}] — ${(err as Error).message}`);
        results.push({
          route,
          viewport: vpName,
          file: filename,
          size: 0,
          hash: 'ERROR',
        });
      }
    }

    await context.close();
  }

  await browser.close();

  // Write manifest
  const manifest = {
    phase: PHASE,
    timestamp: new Date().toISOString(),
    zolaUrl: ZOLA_URL,
    routeCount: ROUTES.length,
    viewportCount: Object.keys(VIEWPORTS).length,
    totalScreenshots: results.length,
    results,
  };

  writeFileSync(join(OUT_DIR, 'manifest.json'), JSON.stringify(manifest, null, 2));
  console.log(`\n${PHASE.toUpperCase()} capture complete: ${results.length} screenshots → ${OUT_DIR}`);
}

main().catch((err) => {
  console.error('Fatal error:', err);
  process.exit(1);
});
