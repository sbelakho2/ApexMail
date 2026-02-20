import type { Browser, Page } from '@playwright/test';

export const WEB_URL = process.env.WEB_URL || 'http://localhost:3000';
export const CONTROL_PLANE_URL = process.env.CONTROL_PLANE_URL || 'http://localhost:3020';
export const E2E_BYPASS_KEY = process.env.E2E_BYPASS_KEY || 'apexmail-e2e-bypass-key';

export async function createBypassPage(browser: Browser): Promise<Page> {
    const context = await browser.newContext({
        extraHTTPHeaders: {
            'x-e2e-bypass-key': E2E_BYPASS_KEY,
        },
        reducedMotion: 'reduce',
    });
    return context.newPage();
}

export async function stabilizePage(page: Page): Promise<void> {
    await page.addStyleTag({
        content: `
            *, *::before, *::after {
                transition-duration: 0s !important;
                animation-duration: 0s !important;
                animation-delay: 0s !important;
                caret-color: transparent !important;
            }
            [data-e2e-hide] { visibility: hidden !important; }
        `,
    });
}

export async function assertNoHorizontalOverflow(page: Page, label: string): Promise<void> {
    const offenders = await page.evaluate(() => {
        const vw = window.innerWidth;

        function isInsideScrollContainer(el: Element): boolean {
            let parent = el.parentElement;
            while (parent && parent !== document.body) {
                const ps = window.getComputedStyle(parent);
                const ox = ps.overflowX;
                if (ox === 'auto' || ox === 'hidden' || ox === 'scroll') return true;
                parent = parent.parentElement;
            }
            return false;
        }

        const elements = Array.from(document.querySelectorAll('body *'));
        const issues: Array<{ tag: string; id: string; cls: string; left: number; right: number; width: number }> = [];
        for (const el of elements) {
            const style = window.getComputedStyle(el);
            if (style.display === 'none' || style.visibility === 'hidden') continue;
            const rect = el.getBoundingClientRect();
            if (rect.width === 0 || rect.height === 0) continue;
            // Skip elements entirely off-screen (e.g. hidden mobile sidebars via -translate-x-full)
            if (rect.right <= 2 || rect.left >= vw - 2) continue;
            // Skip elements inside scroll containers (overflow-x: auto/hidden/scroll)
            if (isInsideScrollContainer(el)) continue;
            if (rect.right > vw + 1 || rect.left < -1) {
                issues.push({
                    tag: el.tagName.toLowerCase(),
                    id: el.id || '',
                    cls: el.className ? String(el.className).slice(0, 120) : '',
                    left: rect.left,
                    right: rect.right,
                    width: rect.width,
                });
            }
            if (issues.length >= 8) break;
        }
        return issues;
    });

    if (offenders.length > 0) {
        throw new Error(`[layout] ${label} has horizontal overflow: ${JSON.stringify(offenders)}`);
    }
}

export function stripHash(url: string): string {
    return url.split('#')[0];
}
