import { expect, type Browser, type BrowserContext, type Response } from '@playwright/test';

export const WEB_URL = process.env.WEB_URL || 'http://localhost:3000';
export const CONTROL_PLANE_URL = process.env.CONTROL_PLANE_URL || 'http://localhost:3020';
export const API_URL = process.env.API_URL || 'http://localhost:3001';
export const E2E_BYPASS_KEY = process.env.E2E_BYPASS_KEY || 'apexmail-e2e-bypass-key';

export async function createBypassContext(browser: Browser): Promise<BrowserContext> {
    return browser.newContext({
        extraHTTPHeaders: {
            'x-e2e-bypass-key': E2E_BYPASS_KEY,
        },
        reducedMotion: 'reduce',
    });
}

export async function gotoWithStatusExpectation(
    context: BrowserContext,
    url: string,
    expected: ReadonlyArray<number> = [200],
): Promise<Response | null> {
    const page = await context.newPage();
    const response = await page.goto(url, { waitUntil: 'domcontentloaded' });
    if (response) {
        expect(expected).toContain(response.status());
    }
    await page.close();
    return response;
}

export function assertSecurityHeaders(response: Response, extraHeaders: string[] = []): void {
    const headers = response.headers();
    expect(headers['x-frame-options']).toBeTruthy();
    expect(headers['content-security-policy']).toBeTruthy();
    for (const header of extraHeaders) {
        expect(headers[header]).toBeTruthy();
    }
}

export function stripHash(url: string): string {
    return url.split('#')[0];
}

export async function probe(url: string): Promise<boolean> {
    try {
        const response = await fetch(url, {
            method: 'GET',
            signal: AbortSignal.timeout(3000),
        });
        return response.ok;
    } catch {
        return false;
    }
}
