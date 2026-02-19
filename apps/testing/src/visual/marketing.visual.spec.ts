/**
 * @apexmail/testing - Marketing Visual Regression Tests
 */

import { test, expect } from '@playwright/test';

const viewports = {
    desktop: { width: 1920, height: 1080 },
    mobile: { width: 375, height: 667 },
};

test.describe('Marketing Visual Regression', () => {
    // Only run this when explicit env var is set or via specific command to avoid snapshot churn
    // But for this task, we want to debug UI/UX so we run it.
    
    test.beforeEach(async ({ page }) => {
        const MARKETING_URL = process.env.MARKETING_URL || 'http://localhost:3003';
        await page.goto(MARKETING_URL);
    });

    for (const [viewportName, viewport] of Object.entries(viewports)) {
        test(`landing page - ${viewportName}`, async ({ page }) => {
            await page.setViewportSize(viewport);
            
            // Wait for animations
            await page.waitForTimeout(1000); 
            
            // Snapshot of Hero
            await expect(page.locator('section').first()).toHaveScreenshot(`marketing-hero-${viewportName}.png`, {
                threshold: 0.2
            });
            
            // Snapshot of Pricing
            await expect(page.locator('section').filter({ hasText: 'Monthly Email Volume' })).toHaveScreenshot(`marketing-pricing-${viewportName}.png`, {
                threshold: 0.2
            });
        });
    }
});
