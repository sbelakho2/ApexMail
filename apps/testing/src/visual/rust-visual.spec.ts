import fs from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { Page, test } from '@playwright/test';
import pixelmatch from 'pixelmatch';
import { PNG } from 'pngjs';

import {
  buildLegacyForgotPasswordHtml,
  buildLegacyLoginHtml,
  buildLegacySignupHtml,
} from './reference-auth-pages';

type FixtureManifest = {
  fixtures: Array<{
    id: string;
    surface: string;
    route: string;
    htmlFile: string;
    snapshotFile: string;
    viewport: { width: number; height: number };
  }>;
};

const FIXTURE_ROOT = path.resolve(__dirname, '../../fixtures/rust-ui');
const AUTH_CONTRACT_CSS_PATH = path.join(FIXTURE_ROOT, 'assets', 'globals.css');
const SNAPSHOT_ROOT = path.resolve(__dirname, '__snapshots__');
const MARKETING_STATIC_ROOT = path.resolve(__dirname, '../../../marketing-zola/static');
const MARKETING_PUBLIC_ROOT = path.resolve(__dirname, '../../../marketing-zola/public');
const MOTION_RESET_CSS = `
  *, *::before, *::after {
    animation-duration: 0s !important;
    animation-delay: 0s !important;
    transition-duration: 0s !important;
    transition-delay: 0s !important;
    scroll-behavior: auto !important;
  }
`;

function rewriteStaticAssetUrls(css: string, staticRoot: string): string {
  return css.replace(/url\((['"]?)\/([^\)"']+)\1\)/g, (_match, _quote: string, relativePath: string) => {
    const absolute = path.join(staticRoot, relativePath);
    return `url(${pathToFileURL(absolute).href})`;
  });
}

function loadAuthContractCss(): string | null {
  if (!fs.existsSync(AUTH_CONTRACT_CSS_PATH)) {
    return null;
  }

  return fs.readFileSync(AUTH_CONTRACT_CSS_PATH, 'utf8');
}

function loadMarketingCss(): string {
  const stylesCss = fs.readFileSync(path.join(MARKETING_STATIC_ROOT, 'css', 'styles.css'), 'utf8');
  const noJsCss = fs.readFileSync(path.join(MARKETING_STATIC_ROOT, 'css', 'no-js.css'), 'utf8');
  return [stylesCss, noJsCss]
    .map((css) => rewriteStaticAssetUrls(css, MARKETING_STATIC_ROOT))
    .join('\n');
}

function loadManifest(): FixtureManifest {
  const manifest = JSON.parse(fs.readFileSync(path.join(FIXTURE_ROOT, 'manifest.json'), 'utf8')) as FixtureManifest;

  for (const fixture of manifest.fixtures) {
    if (!fixture.htmlFile || !fixture.snapshotFile) {
      throw new Error(`Invalid visual fixture manifest entry for ${fixture.id}`);
    }

    const htmlPath = path.join(FIXTURE_ROOT, fixture.htmlFile);
    if (!fs.existsSync(htmlPath)) {
      throw new Error(`Missing HTML fixture for ${fixture.id}`);
    }
  }

  return manifest;
}

const MARKETING_PUBLIC_HTML: Record<string, string> = {
  '/': 'index.html',
  '/acceptable-use': 'acceptable-use/index.html',
  '/api-console': 'api-console/index.html',
  '/case-studies': 'case-studies/index.html',
  '/compliance': 'compliance/index.html',
  '/compare': 'compare/index.html',
  '/compare/postmark': 'compare/postmark/index.html',
  '/compare/resend': 'compare/resend/index.html',
  '/compare/sendgrid': 'compare/sendgrid/index.html',
  '/cookies': 'cookies/index.html',
  '/dpa': 'dpa/index.html',
  '/features': 'features/index.html',
  '/forensic': 'forensic/index.html',
  '/pricing': 'pricing/index.html',
  '/pricing/calculator': 'pricing/calculator/index.html',
  '/privacy': 'privacy/index.html',
  '/private-cloud': 'private-cloud/index.html',
  '/sla': 'sla/index.html',
  '/status': 'status/index.html',
  '/terms': 'terms/index.html',
};

function loadMarketingPublicHtml(route: string): string | null {
  const relativePath = MARKETING_PUBLIC_HTML[route];
  if (!relativePath) {
    return null;
  }

  const htmlPath = path.join(MARKETING_PUBLIC_ROOT, relativePath);
  if (!fs.existsSync(htmlPath)) {
    return null;
  }

  return fs.readFileSync(htmlPath, 'utf8');
}

function inlineCss(html: string, stylesheetHref: string, css: string): string {
  const styleTag = `<style>${css}\n${MOTION_RESET_CSS}</style>`;
  const linkTag = `<link rel="stylesheet" href="${stylesheetHref}">`;

  if (html.includes(linkTag)) {
    return html.replace(linkTag, styleTag);
  }

  if (html.includes('</head>')) {
    return html.replace('</head>', `${styleTag}</head>`);
  }

  const bodyTag = html.match(/<body\b[^>]*>/i)?.[0];
  if (bodyTag) {
    return html.replace(bodyTag, `${styleTag}${bodyTag}`);
  }

  return `${styleTag}${html}`;
}

async function captureScreenshot(
  page: Page,
  html: string,
  stylesheetHref: string,
  css: string,
  viewport: { width: number; height: number },
  fullPage: boolean,
  waitForMs: number,
): Promise<Buffer> {
  await page.setViewportSize(viewport);
  await page.emulateMedia({ reducedMotion: 'reduce' });
  await page.setContent(inlineCss(html, stylesheetHref, css), { waitUntil: 'load' });
  await page.evaluate(async () => {
    document.documentElement.style.overflowX = 'hidden';
    document.body.style.overflowX = 'hidden';

    if ('fonts' in document) {
      await document.fonts.ready;
    }
  });
  await page.waitForTimeout(waitForMs);

  return page.screenshot({
    animations: 'disabled',
    caret: 'hide',
    fullPage,
    scale: 'css',
  });
}

function diffScreenshots(expected: Buffer, actual: Buffer) {
  const expectedPng = PNG.sync.read(expected);
  const actualPng = PNG.sync.read(actual);

  if (
    expectedPng.width !== actualPng.width ||
    expectedPng.height !== actualPng.height
  ) {
    throw new Error(
      `Image dimensions do not match: expected ${expectedPng.width}x${expectedPng.height}, received ${actualPng.width}x${actualPng.height}`,
    );
  }

  const diffPng = new PNG({ width: expectedPng.width, height: expectedPng.height });
  const diffPixels = pixelmatch(
    expectedPng.data,
    actualPng.data,
    diffPng.data,
    expectedPng.width,
    expectedPng.height,
    { threshold: 0 },
  );

  return {
    diffPixels,
    diffRatio: diffPixels / (expectedPng.width * expectedPng.height),
    diffPng,
  };
}

const runtimeAuthReferences: Record<string, () => string> = {
  'web-login': buildLegacyLoginHtml,
  'web-signup': buildLegacySignupHtml,
  'web-forgot-password': buildLegacyForgotPasswordHtml,
};

function isMarketingFixture(fixture: FixtureManifest['fixtures'][number]): boolean {
  return fixture.surface === 'marketing' || fixture.surface === 'marketing-zola';
}

function buildRouteSet(routes: string[]): Set<string> {
  return new Set(routes);
}

function assertMarketingPublicCoverage(fixtures: FixtureManifest['fixtures']) {
  const marketingFixtureRoutes = buildRouteSet(
    fixtures.filter(isMarketingFixture).map((fixture) => fixture.route),
  );
  const publicHtmlRoutes = buildRouteSet(Object.keys(MARKETING_PUBLIC_HTML));
  const missingPublicBaselines = [...marketingFixtureRoutes].filter((route) => !publicHtmlRoutes.has(route));

  if (missingPublicBaselines.length === 0) {
    return;
  }

  throw new Error(
    `current marketing routes without pre-migration public HTML baselines: ${missingPublicBaselines.join(', ')}`,
  );
}

function assertAuthArchiveCoverage(fixtures: FixtureManifest['fixtures']) {
  const missingAuthFixtures = Object.keys(runtimeAuthReferences).filter(
    (id) => !fixtures.some((fixture) => fixture.id === id),
  );

  if (missingAuthFixtures.length > 0) {
    throw new Error(
      `auth visual fixtures missing from manifest: ${missingAuthFixtures.join(', ')}`,
    );
  }

  const missingAuthSnapshots = fixtures
    .filter((fixture) => fixture.id in runtimeAuthReferences)
    .filter((fixture) => !fs.existsSync(path.join(SNAPSHOT_ROOT, fixture.snapshotFile)))
    .map((fixture) => fixture.snapshotFile);

  if (missingAuthSnapshots.length > 0) {
    throw new Error(
      `auth visual snapshot baselines missing from repository: ${missingAuthSnapshots.join(', ')}`,
    );
  }
}

test.describe('Rust visual parity against pre-migration baselines', () => {
  const authContractCss = loadAuthContractCss();
  const compiledMarketingCss = loadMarketingCss();
  const manifest = loadManifest();

  test('auth visual coverage matches repository assets', () => {
    assertAuthArchiveCoverage(manifest.fixtures);

    if (authContractCss) {
      return;
    }

    throw new Error(`Missing checked-in auth CSS contract: ${AUTH_CONTRACT_CSS_PATH}`);
  });

  test('marketing public-html coverage matches migrated routes', () => {
    assertMarketingPublicCoverage(manifest.fixtures);
  });

  for (const fixture of manifest.fixtures) {
    test(`${fixture.id} matches baseline screenshot`, async ({ page }, testInfo) => {
      const runtimeReferenceBuilder = runtimeAuthReferences[fixture.id];
      const rustHtmlPath = path.join(FIXTURE_ROOT, fixture.htmlFile);
      const rustHtml = fs.readFileSync(rustHtmlPath, 'utf8');

      if (runtimeReferenceBuilder) {
        if (!authContractCss) {
          throw new Error(`Missing checked-in auth CSS contract: ${AUTH_CONTRACT_CSS_PATH}`);
        }

        const snapshotPath = path.join(SNAPSHOT_ROOT, fixture.snapshotFile);
        if (!fs.existsSync(snapshotPath)) {
          throw new Error(`Missing auth snapshot baseline for ${fixture.id}`);
        }

        const referenceScreenshot = await captureScreenshot(
          page,
          runtimeReferenceBuilder(),
          '/assets/globals.css',
          authContractCss,
          fixture.viewport,
          false,
          150,
        );
        const rustScreenshot = await captureScreenshot(
          page,
          rustHtml,
          '/assets/globals.css',
          authContractCss,
          fixture.viewport,
          false,
          150,
        );

        const { diffPixels, diffRatio, diffPng } = diffScreenshots(referenceScreenshot, rustScreenshot);

        if (diffPixels > 0) {
          const expectedPath = testInfo.outputPath(`${fixture.id}-legacy-reference.png`);
          const actualPath = testInfo.outputPath(`${fixture.id}-rust-actual.png`);
          const diffPath = testInfo.outputPath(`${fixture.id}-runtime-diff.png`);

          fs.writeFileSync(expectedPath, referenceScreenshot);
          fs.writeFileSync(actualPath, rustScreenshot);
          fs.writeFileSync(diffPath, PNG.sync.write(diffPng));

          await testInfo.attach('legacy reference', {
            path: expectedPath,
            contentType: 'image/png',
          });
          await testInfo.attach('rust actual', {
            path: actualPath,
            contentType: 'image/png',
          });
          await testInfo.attach('runtime diff', {
            path: diffPath,
            contentType: 'image/png',
          });

          throw new Error(
            `Legacy auth reference mismatch for ${fixture.id}: ${diffPixels} pixels differ (ratio ${diffRatio.toFixed(4)})`,
          );
        }

        return;
      }

      if (!isMarketingFixture(fixture)) {
        throw new Error(`No baseline strategy configured for ${fixture.id}`);
      }

      const baselineHtml = loadMarketingPublicHtml(fixture.route);
      if (!baselineHtml) {
        throw new Error(`Missing pre-migration public HTML baseline for ${fixture.route}`);
      }

      const baselinePage = await page.context().newPage();
      const rustPage = await page.context().newPage();
      let baselineScreenshot: Buffer;
      let rustScreenshot: Buffer;

      try {
        baselineScreenshot = await captureScreenshot(
          baselinePage,
          baselineHtml,
          '/css/styles.css',
          compiledMarketingCss,
          fixture.viewport,
          true,
          500,
        );
        rustScreenshot = await captureScreenshot(
          rustPage,
          rustHtml,
          '/assets/marketing.css',
          compiledMarketingCss,
          fixture.viewport,
          true,
          500,
        );
      } finally {
        await Promise.all([baselinePage.close(), rustPage.close()]);
      }

      const { diffPixels, diffRatio, diffPng } = diffScreenshots(baselineScreenshot, rustScreenshot);

      if (diffPixels === 0) {
        return;
      }

      const expectedPath = testInfo.outputPath(`${fixture.id}-pre-migration-baseline.png`);
      const actualPath = testInfo.outputPath(`${fixture.id}-rust-actual.png`);
      const diffPath = testInfo.outputPath(`${fixture.id}-marketing-diff.png`);

      fs.writeFileSync(expectedPath, baselineScreenshot);
      fs.writeFileSync(actualPath, rustScreenshot);
      fs.writeFileSync(diffPath, PNG.sync.write(diffPng));

      await testInfo.attach('pre-migration public-html baseline', {
        path: expectedPath,
        contentType: 'image/png',
      });
      await testInfo.attach('rust actual', {
        path: actualPath,
        contentType: 'image/png',
      });
      await testInfo.attach('runtime diff', {
        path: diffPath,
        contentType: 'image/png',
      });

      throw new Error(
        `Pre-migration public-html baseline mismatch for ${fixture.route}: ${diffPixels} pixels differ (ratio ${diffRatio.toFixed(4)})`,
      );
    });
  }
});