import { test, expect } from '@playwright/test';

const MARKETING_URL = process.env.MARKETING_URL || 'http://localhost:3003';

const VISUAL_ROUTES = [
    { path: '/', name: 'home' },
    { path: '/features', name: 'features' },
    { path: '/pricing', name: 'pricing' },
    { path: '/compliance', name: 'compliance' },
    { path: '/status', name: 'status' },
];

const FIXED_VISUAL_TIME = '2025-02-01T12:00:00.000Z';

async function stabilizeMarketingPage(page: Parameters<typeof test>[0]['page']) {
    await page.emulateMedia({ reducedMotion: 'reduce' });
    await page.addInitScript(fixedTime => {
        const fixed = new Date(fixedTime as string).getTime();
        const OriginalDate = Date;
        const globalDate = globalThis as typeof globalThis & { Date: DateConstructor };
        // @ts-expect-error - override Date in the browser context for stability
        globalDate.Date = class extends OriginalDate {
            constructor(...args: unknown[]) {
                if (args.length === 0) {
                    return new OriginalDate(fixed);
                }
                return new OriginalDate(...args);
            }

            static now() {
                return fixed;
            }
        } as DateConstructor;

        window.setInterval = () => 0 as unknown as number;
    }, FIXED_VISUAL_TIME);
}

async function waitForMarketingSettled(page: Parameters<typeof test>[0]['page']) {
    await page.waitForLoadState('networkidle');
    await page.evaluate(async () => {
        const images = Array.from(document.images || []);
        await Promise.all(
            images.map(image => {
                if (image.complete) return Promise.resolve();
                return new Promise<void>(resolve => {
                    image.addEventListener('load', () => resolve(), { once: true });
                    image.addEventListener('error', () => resolve(), { once: true });
                });
            }),
        );
    });
    await page.evaluate(() => {
        document.querySelectorAll('video').forEach(video => {
            try {
                video.pause();
                video.currentTime = 0;
            } catch {
                // Ignore media errors in test snapshots.
            }
        });
    });
    await page.waitForTimeout(300);
}

test.describe('Marketing Visual - Full Coverage', () => {
    test.beforeEach(async ({ page }) => {
        await stabilizeMarketingPage(page);
        await page.addStyleTag({
            content: `
                *, *::before, *::after {
                    transition-duration: 0s !important;
                    animation-duration: 0s !important;
                    animation-delay: 0s !important;
                }
            `,
        });
    });

    for (const route of VISUAL_ROUTES) {
        test(`visual snapshot: ${route.name}`, async ({ page }) => {
            await page.goto(`${MARKETING_URL}${route.path}`, { waitUntil: 'domcontentloaded' });
            await waitForMarketingSettled(page);
            await expect(page).toHaveScreenshot(`marketing-${route.name}.png`, {
                fullPage: true,
                timeout: 10000,
            });
        });
    }
});
