import { test, expect } from '@playwright/test';

test('framework theme classes override the host and OS palettes', async ({ page }) => {
  await page.goto('/');
  await expect(page.locator('[data-kiwi-widget]')).toHaveAttribute('data-state', 'done');
  for (const os of ['light', 'dark']) {
    await page.emulateMedia({ colorScheme: os });
    for (const host of ['light', 'dark']) {
      for (const theme of ['light', 'dark']) {
        await page.evaluate(({ host, theme }) => {
          document.body.setAttribute('data-theme', host);
          const container = document.querySelector('.kiwi-container');
          container.classList.remove('kiwi-theme-light', 'kiwi-theme-dark');
          container.classList.add(`kiwi-theme-${theme}`);
        }, { host, theme });
        await expect(page.locator('[data-kiwi-widget]')).toHaveCSS(
          'background-color', theme === 'dark' ? 'rgb(22, 27, 34)' : 'rgb(255, 255, 255)',
        );
      }
    }
  }
});

test('a per-widget data-theme pin overrides the host palette', async ({ page }) => {
  await page.goto('/');
  await expect(page.locator('[data-kiwi-widget]')).toHaveAttribute('data-state', 'done');
  for (const theme of ['light', 'dark']) {
    await page.evaluate((theme) => {
      document.body.setAttribute('data-theme', theme === 'light' ? 'dark' : 'light');
      document.querySelector('.kiwi-container').setAttribute('data-theme', theme);
    }, theme);
    await expect(page.locator('[data-kiwi-widget]')).toHaveCSS(
      'background-color', theme === 'dark' ? 'rgb(22, 27, 34)' : 'rgb(255, 255, 255)',
    );
  }
});
