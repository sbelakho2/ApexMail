import { expect, test } from '@playwright/test';

import { discoverUiRoutes, materializeDynamicPath } from '../support/discovery';

const VIEWPORTS = [
  { width: 390, height: 844, label: 'mobile' },
  { width: 820, height: 1180, label: 'tablet' },
  { width: 1440, height: 900, label: 'desktop' },
];

function appForProject(projectName: string): string {
  if (projectName.includes('control-plane')) {
    return 'control-plane';
  }
  return 'web';
}

test('critical pages remain usable across breakpoints and keyboard navigation', async ({ page }, testInfo) => {
  const app = appForProject(testInfo.project.name);
  const allRoutes = await discoverUiRoutes();
  const discovered = allRoutes
    .filter((route) => route.app === app)
    .map((route) => route.path);

  const criticalCandidates = app === 'control-plane'
    ? ['/', '/audit', '/sales']
    : ['/', '/login', '/register', '/forgot-password', '/dashboard'];

  const critical = criticalCandidates.filter((candidate) => discovered.includes(candidate));
  expect(critical.length, `No critical routes found for ${app}`).toBeGreaterThan(0);

  for (const viewport of VIEWPORTS) {
    await page.setViewportSize({ width: viewport.width, height: viewport.height });

    for (const rawPath of critical) {
      const routePath = materializeDynamicPath(rawPath);
      const response = await page.goto(routePath, { waitUntil: 'domcontentloaded' });

      if (response) {
        expect(response.status(), `${app} ${routePath} should render`).toBeLessThan(500);
      }

      const hasLayoutOverflow = await page.evaluate(() => {
        const root = document.documentElement;
        return root.scrollWidth > window.innerWidth + 1;
      });

      expect(hasLayoutOverflow, `${app} ${routePath} overflows viewport ${viewport.label}`).toBe(false);

      await page.keyboard.press('Tab');
      await page.keyboard.press('Tab');

      const hasFocusableElement = await page.evaluate(() => {
        return document.activeElement !== null && document.activeElement !== document.body;
      });

      expect(hasFocusableElement, `${app} ${routePath} lacks keyboard focus progression`).toBe(true);

      const landmarkCount = await page.locator('main, [role="main"], h1').count();
      expect(landmarkCount, `${app} ${routePath} missing primary content landmarks`).toBeGreaterThan(0);
    }
  }
});
