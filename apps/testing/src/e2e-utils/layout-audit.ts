import type { Page } from '@playwright/test';

type LayoutIssue = {
    type: 'horizontal-overflow' | 'out-of-bounds';
    selector: string;
    details: string;
};

type LayoutAuditResult = {
    viewport: { width: number; height: number };
    issues: LayoutIssue[];
};

function buildSelector(el: Element): string {
    const parts: string[] = [];
    let node: Element | null = el;
    while (node && parts.length < 4) {
        const tag = node.tagName.toLowerCase();
        if (node.id) {
            parts.unshift(`${tag}#${node.id}`);
            break;
        }
        const className = node.className && typeof node.className === 'string'
            ? node.className.split(' ').filter(Boolean)[0]
            : '';
        parts.unshift(className ? `${tag}.${className}` : tag);
        node = node.parentElement;
    }
    return parts.join(' > ');
}

export async function auditLayout(page: Page): Promise<LayoutAuditResult> {
    const viewport = page.viewportSize() || { width: 0, height: 0 };

    const issues = await page.evaluate(() => {
        const result: LayoutIssue[] = [];
        const html = document.documentElement;
        const vw = html.clientWidth;
        const vh = html.clientHeight;

        if (html.scrollWidth > vw + 2) {
            result.push({
                type: 'horizontal-overflow',
                selector: 'html',
                details: `scrollWidth=${html.scrollWidth} clientWidth=${vw}`,
            });
        }

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

        const excludedTags = new Set(['html', 'head', 'meta', 'link', 'style', 'script']);
        const elements = Array.from(document.querySelectorAll('body *'));
        for (const el of elements) {
            const tag = el.tagName.toLowerCase();
            if (excludedTags.has(tag)) continue;

            const style = window.getComputedStyle(el);
            if (style.display === 'none' || style.visibility === 'hidden' || style.opacity === '0') {
                continue;
            }

            const rect = el.getBoundingClientRect();
            if (rect.width < 1 || rect.height < 1) continue;

            // Skip elements entirely off-screen (e.g. hidden mobile sidebars via CSS transform)
            if (rect.right <= 2 || rect.left >= vw - 2) continue;

            // Skip elements inside scroll containers (overflow-x: auto/hidden/scroll)
            if (isInsideScrollContainer(el)) continue;

            if (rect.left < -2 || rect.right > vw + 2) {
                result.push({
                    type: 'out-of-bounds',
                    selector: buildSelector(el),
                    details: `left=${Math.round(rect.left)} right=${Math.round(rect.right)} vw=${vw}`,
                });
            }

            if (style.position === 'fixed' && (rect.top < -2 || rect.bottom > vh + 2)) {
                result.push({
                    type: 'out-of-bounds',
                    selector: buildSelector(el),
                    details: `top=${Math.round(rect.top)} bottom=${Math.round(rect.bottom)} vh=${vh}`,
                });
            }
        }

        return result;

        function buildSelector(el: Element): string {
            const parts: string[] = [];
            let node: Element | null = el;
            while (node && parts.length < 4) {
                const tag = node.tagName.toLowerCase();
                if (node.id) {
                    parts.unshift(`${tag}#${node.id}`);
                    break;
                }
                const className = node.className && typeof node.className === 'string'
                    ? node.className.split(' ').filter(Boolean)[0]
                    : '';
                parts.unshift(className ? `${tag}.${className}` : tag);
                node = node.parentElement;
            }
            return parts.join(' > ');
        }
    });

    return { viewport, issues };
}
