/**
 * @apexmail/testing - Marketing Site E2E Tests
 * 
 * Tests for landing page content, SEO keywords, and interactive elements.
 */

import { test, expect } from '@playwright/test';

test.describe('Marketing Site', () => {
    
    // Use a specific URL if provided, otherwise default to baseURL (which might need to be adjusted during run)
    // For now we assume the marketing app is running on the baseURL or we can override slightly.
    // If the marketing app is on a different port in CI, we'd handle it via env vars.
    const MARKETING_URL = process.env.MARKETING_URL || 'http://localhost:3001';

    test.beforeEach(async ({ page }) => {
        await page.goto(MARKETING_URL);
    });

    test('should match SEO-optimized Hero content', async ({ page }) => {
        // Check Title
        await expect(page).toHaveTitle(/ApexMail/);
        
        // Check new Headline
        const headline = page.locator('h1');
        await expect(headline).toBeVisible();
        await expect(headline).toContainText('The Email API That');
        await expect(headline).toContainText('Keeps You Out of Court');
        
        // Check Subheadline for Keywords (HIPAA, GDPR)
        const subhead = page.locator('h1 + p'); // Adjusted selector based on structure
        await expect(subhead).toBeVisible();
        await expect(subhead).toContainText('HIPAA & GDPR-ready');
        await expect(subhead).toContainText('transactional emails');
        
        // Check CTAs
        await expect(page.getByText('Get API Keys')).toBeVisible();
        // Updated text from "Start Sending Free" to "Deploy to Production"? No, we set "Get API Keys" in the Hero.
        // And "Deploy to Production" in the CTA section at the bottom.
    });

    test('should match Feature Section updates', async ({ page }) => {
       const features = page.locator('section').filter({ hasText: 'Automated Compliance Ledger' });
       await expect(features).toBeVisible();
       
       await expect(page.getByRole('heading', { name: 'True Single-Tenant' })).toBeVisible();
       await expect(page.getByRole('heading', { name: 'Air-Gapped AI' })).toBeVisible();
    });

    test('should have interactive Pricing Calculator', async ({ page }) => {
        const calculator = page.locator('section').filter({ hasText: 'Monthly Email Volume' });
        await expect(calculator).toBeVisible();
        
        // Check for Free Tier keywords
        await expect(page.getByText('Shared IP (High Reputation)')).toBeVisible();
        await expect(page.getByText('Forensic Logs (24h)')).toBeVisible();
        
        // Interact with slider (if possible, simplified check for now)
        const slider = calculator.locator('input[type="range"]');
        await expect(slider).toBeVisible();
    });

    test('should display Security Section', async ({ page }) => {
        await expect(page.getByText('Zero-Retention Mode')).toBeVisible();
        await expect(page.getByText('End-to-End Encryption')).toBeVisible();
    });

    test('should have CTA at the bottom', async ({ page }) => {
        await expect(page.getByRole('link', { name: 'Deploy to Production' })).toBeVisible();
        await expect(page.getByRole('link', { name: 'Book Architecture Review' })).toBeVisible();
    });
});
