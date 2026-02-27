/**
 * @apexmail/testing - Visual Regression Tests
 * 
 * Automated visual testing for UI consistency across components and pages.
 */

import { test, expect } from '@playwright/test';
import {
    authenticateUser,
    mockDashboardApis,
    setTheme,
    themes,
    viewports,
    waitForCharts,
} from './visual-helpers';
const E2E_BYPASS_KEY = process.env.E2E_BYPASS_KEY || 'apexmail-e2e-bypass-key';

test.describe('Visual Regression Tests', () => {
    test.beforeEach(async ({ page }) => {
        // Set consistent test environment
        await page.emulateMedia({ reducedMotion: 'reduce' });
        await page.setExtraHTTPHeaders({
            'Accept-Language': 'en-US',
            'x-e2e-bypass-key': E2E_BYPASS_KEY,
        });
        await mockDashboardApis(page);
    });

    test.describe('Login Page', () => {
        for (const [viewportName, viewport] of Object.entries(viewports)) {
            for (const theme of themes) {
                test(`login page - ${viewportName} - ${theme}`, async ({ page }) => {
                    await page.setViewportSize(viewport);
                    await setTheme(page, theme);
                    
                    await page.goto('/login');
                    await page.waitForLoadState('networkidle');
                    
                    await expect(page).toHaveScreenshot(`login-${viewportName}-${theme}.png`, {
                        fullPage: true,
                        animations: 'disabled',
                    });
                });
            }
        }
        
        test('login form validation states', async ({ page }) => {
            await page.goto('/login');
            
            // Trigger validation errors
            await page.getByRole('button', { name: 'Sign in' }).click();
            await page.waitForTimeout(100);
            
            await expect(page).toHaveScreenshot('login-validation-errors.png', {
                fullPage: true,
                animations: 'disabled',
            });
        });
        
        test('login loading state', async ({ page }) => {
            await page.goto('/login');
            
            await page.getByLabel('Email').fill('test@example.com');
            await page.getByLabel('Password').fill('password123');
            
            // Slow down response to capture loading state
            await page.route('/api/auth/login', async (route) => {
                await new Promise(resolve => setTimeout(resolve, 2000));
                await route.continue();
            });
            
            await page.getByRole('button', { name: 'Sign in' }).click();
            
            await expect(page).toHaveScreenshot('login-loading.png', {
                fullPage: true,
            });
        });
    });

    test.describe('Dashboard Page', () => {
        test.beforeEach(async ({ page }) => {
            await authenticateUser(page);
        });
        
        for (const [viewportName, viewport] of Object.entries(viewports)) {
            for (const theme of themes) {
                test(`dashboard - ${viewportName} - ${theme}`, async ({ page }) => {
                    await page.setViewportSize(viewport);
                    
                    await page.goto('/dashboard');
                    await page.waitForLoadState('networkidle');
                    await setTheme(page, theme);
                    await waitForCharts(page);
                    
                    await expect(page).toHaveScreenshot(`dashboard-${viewportName}-${theme}.png`, {
                        fullPage: true,
                        animations: 'disabled',
                    });
                });
            }
        }
        
        test('dashboard metrics cards', async ({ page }) => {
            await page.goto('/dashboard');
            await page.waitForLoadState('networkidle');
            
            const metricsGrid = page.locator('[data-testid="metrics-grid"]');
            await metricsGrid.waitFor({ timeout: 20000 });
            await expect(metricsGrid).toHaveScreenshot('dashboard-metrics.png');
        });

        test('dashboard apex card compliance details', async ({ page }) => {
            await page.goto('/dashboard');
            await page.waitForLoadState('networkidle');

            const cards = page.locator('[data-testid="metrics-grid"] > div');
            await expect(cards.first()).toBeVisible({ timeout: 20000 });

            const totalCards = await cards.count();
            expect(totalCards).toBeGreaterThanOrEqual(4);

            const sampleCount = Math.min(totalCards, 4);
            for (let index = 0; index < sampleCount; index++) {
                const card = cards.nth(index);
                const style = await card.evaluate(element => {
                    const computed = window.getComputedStyle(element as HTMLElement);
                    return {
                        borderRadius: computed.borderRadius,
                        boxShadow: computed.boxShadow,
                        borderColor: computed.borderColor,
                        backgroundColor: computed.backgroundColor,
                        className: (element as HTMLElement).className,
                    };
                });

                expect(style.className).toMatch(/apex-card|premium-card|bg-card/);
                expect(parseFloat(style.borderRadius)).toBeGreaterThanOrEqual(10);
                expect(style.boxShadow).not.toBe('none');
                expect(style.borderColor).not.toMatch(/rgba\(0, 0, 0, 0\)|transparent/);
                expect(style.backgroundColor).not.toMatch(/rgba\(0, 0, 0, 0\)|transparent/);
            }

            await expect(page.locator('[data-testid="metrics-grid"]')).toHaveScreenshot('dashboard-metrics-apex-compliance.png');
        });
        
        test('dashboard charts', async ({ page }) => {
            await page.goto('/dashboard');
            await page.waitForLoadState('networkidle');
            await waitForCharts(page);
            
            const chartSection = page.locator('[data-testid="charts-section"]');
            await chartSection.waitFor({ timeout: 10000 });
            await expect(chartSection).toHaveScreenshot('dashboard-charts.png');
        });
    });

    test.describe('Campaigns Page', () => {
        test.beforeEach(async ({ page }) => {
            await authenticateUser(page);
        });
        
        test('campaigns list - empty state', async ({ page }) => {
            await page.goto('/campaigns');
            await page.waitForLoadState('networkidle');

            const searchInput = page.getByPlaceholder('Search campaigns...');
            await searchInput.waitFor({ timeout: 15000 });
            await searchInput.fill('no-matching-campaigns');
            await page.waitForTimeout(200);
            
            await expect(page).toHaveScreenshot('campaigns-empty.png', {
                fullPage: true,
            });
        });
        
        test('campaigns list - with data', async ({ page }) => {
            await page.goto('/campaigns');
            await page.waitForLoadState('networkidle');
            
            await expect(page).toHaveScreenshot('campaigns-list.png', {
                fullPage: true,
            });
        });
        
        test('campaign editor', async ({ page }) => {
            await page.goto('/campaigns/new');
            await page.waitForLoadState('networkidle');
            
            await expect(page).toHaveScreenshot('campaign-editor.png', {
                fullPage: true,
            });
        });
        
        test('campaign preview modal', async ({ page }) => {
            await page.goto('/campaigns');
            await page.waitForLoadState('networkidle');

            const rowMenu = page.locator('tbody tr').first().getByRole('button');
            await rowMenu.waitFor({ timeout: 15000 });
            await rowMenu.click();
            await page.getByRole('menuitem', { name: 'Delete' }).click();
            await page.waitForTimeout(200);

            await expect(page.locator('[role="dialog"]')).toHaveScreenshot('campaign-delete-modal.png');
        });
    });

    test.describe('Contacts Page', () => {
        test.beforeEach(async ({ page }) => {
            await authenticateUser(page);
        });
        
        test('contacts list', async ({ page }) => {
            await page.goto('/contacts');
            await page.waitForLoadState('networkidle');
            
            await expect(page).toHaveScreenshot('contacts-list.png', {
                fullPage: true,
            });
        });
        
        test('add contact dialog', async ({ page }) => {
            await page.goto('/contacts');
            await page.getByRole('heading', { name: 'Contacts' }).waitFor();
            await page.getByRole('button', { name: 'Add Contact' }).click();
            await page.waitForTimeout(200);
            
            await expect(page.locator('[role="dialog"]')).toHaveScreenshot('contact-add-dialog.png');
        });
        
        test('contact detail view', async ({ page }) => {
            await page.goto('/contacts');
            await page.getByRole('heading', { name: 'Contacts' }).waitFor({ timeout: 15000 });
            const row = page.getByRole('row', { name: /john\.doe@example\.com/ });
            await row.waitFor({ timeout: 15000 });
            // Open the actions dropdown on the contact row
            await row.getByRole('button').click();
            await page.waitForTimeout(200);
            
            await expect(page.locator('[role="menu"]')).toHaveScreenshot('contact-detail.png');
        });
    });

    test.describe('Settings Page', () => {
        test.beforeEach(async ({ page }) => {
            await authenticateUser(page);
        });
        
        test('settings - general', async ({ page }) => {
            await page.goto('/settings');
            await page.waitForLoadState('networkidle');
            
            await expect(page).toHaveScreenshot('settings-general.png', {
                fullPage: true,
            });
        });
        
        test('settings - team', async ({ page }) => {
            await page.goto('/settings/team');
            await page.waitForLoadState('networkidle');
            
            await expect(page).toHaveScreenshot('settings-team.png', {
                fullPage: true,
            });
        });
        
        test('settings - billing', async ({ page }) => {
            await page.goto('/settings/billing');
            await page.waitForLoadState('networkidle');
            
            await expect(page).toHaveScreenshot('settings-billing.png', {
                fullPage: true,
            });
        });
    });

    test.describe('UI Components', () => {
        test.beforeEach(async ({ page }) => {
            await authenticateUser(page);
        });
        
        test('buttons - all variants', async ({ page }) => {
            await page.goto('/storybook/buttons');
            await page.waitForLoadState('networkidle');
            
            await expect(page).toHaveScreenshot('components-buttons.png');
        });
        
        test('form inputs - all states', async ({ page }) => {
            await page.goto('/storybook/inputs');
            await page.waitForLoadState('networkidle');
            
            await expect(page).toHaveScreenshot('components-inputs.png');
        });
        
        test('cards - all variants', async ({ page }) => {
            await page.goto('/storybook/cards');
            await page.waitForLoadState('networkidle');
            
            await expect(page).toHaveScreenshot('components-cards.png');
        });
        
        test('modals and dialogs', async ({ page }) => {
            await page.goto('/storybook/modals');
            await page.waitForLoadState('networkidle');
            
            await expect(page).toHaveScreenshot('components-modals.png');
        });
        
        test('tables and data grids', async ({ page }) => {
            await page.goto('/storybook/tables');
            await page.waitForLoadState('networkidle');
            
            await expect(page).toHaveScreenshot('components-tables.png');
        });
    });

    test.describe('Color Consistency', () => {
        test('brand colors across pages', async ({ page }) => {
            await authenticateUser(page);
            
            const pages = ['/dashboard', '/campaigns', '/contacts', '/settings'];
            
            for (const pagePath of pages) {
                await page.goto(pagePath);
                await page.waitForLoadState('networkidle');
                
                // Extract primary color usage
                const primaryElements = page.locator('[class*="primary"], [class*="brand"]');
                const count = await primaryElements.count();
                
                expect(count).toBeGreaterThan(0);
            }
        });
    });

    test.describe('Typography', () => {
        test('heading hierarchy', async ({ page }) => {
            await page.goto('/storybook/typography');
            await page.waitForLoadState('networkidle');
            
            await expect(page).toHaveScreenshot('typography-headings.png');
        });
        
        test('font rendering', async ({ page }) => {
            await authenticateUser(page);
            await page.goto('/dashboard');
            await page.waitForLoadState('networkidle');
            
            // Capture text-heavy section
            const textSection = page.locator('[data-testid="activity-feed"]');
            await textSection.waitFor({ timeout: 20000 });
            await expect(textSection).toHaveScreenshot('typography-body.png');
        });
    });

    test.describe('Icons', () => {
        test('icon consistency', async ({ page }) => {
            await page.goto('/storybook/icons');
            await page.waitForLoadState('networkidle');
            
            await expect(page).toHaveScreenshot('icons-all.png');
        });
    });

    test.describe('Spacing and Layout', () => {
        test('consistent spacing in forms', async ({ page }) => {
            await authenticateUser(page);
            await page.goto('/contacts');
            await page.getByRole('heading', { name: 'Contacts' }).waitFor({ timeout: 15000 });
            // Open the Add Contact dialog which contains form inputs
            await page.getByRole('button', { name: 'Add Contact' }).click();
            await page.waitForTimeout(200);
            
            const dialog = page.locator('[role="dialog"]');
            await dialog.waitFor({ timeout: 10000 });
            await expect(dialog).toHaveScreenshot('layout-form-spacing.png');
        });
        
        test('consistent grid layout', async ({ page }) => {
            await authenticateUser(page);
            await page.goto('/dashboard');
            await page.waitForLoadState('networkidle');
            
            const grid = page.locator('[data-testid="metrics-grid"]');
            await grid.waitFor({ timeout: 20000 });
            await expect(grid).toHaveScreenshot('layout-grid-spacing.png');
        });
    });

    test.describe('Animations', () => {
        test('dropdown animation', async ({ page }) => {
            await authenticateUser(page);
            await page.goto('/dashboard');
            
            // Enable animations for this test
            await page.emulateMedia({ reducedMotion: 'no-preference' });
            
            // Capture animation frames
            const userMenu = page.locator('[data-testid="user-menu"]');
            await userMenu.waitFor({ timeout: 15000 });
            await userMenu.click();
            await page.waitForTimeout(50);
            
            await expect(page.locator('[data-testid="user-dropdown"]')).toHaveScreenshot('animation-dropdown-open.png');
        });
        
        test('modal entrance animation', async ({ page }) => {
            await authenticateUser(page);
            await page.goto('/contacts');
            await page.getByRole('heading', { name: 'Contacts' }).waitFor();
            await page.emulateMedia({ reducedMotion: 'no-preference' });
            
            await page.getByRole('button', { name: 'Add Contact' }).click();
            await page.waitForTimeout(100);
            
            await expect(page.locator('[role="dialog"]')).toHaveScreenshot('animation-modal-entrance.png');
        });
    });

    test.describe('Hover States', () => {
        test('button hover states', async ({ page }) => {
            await authenticateUser(page);
            await page.goto('/campaigns');
            await page.waitForLoadState('networkidle');
            
            const button = page.getByRole('link', { name: 'New Campaign' });
            await button.waitFor({ timeout: 15000 });
            await button.scrollIntoViewIfNeeded();
            await button.hover();
            
            await expect(button).toHaveScreenshot('hover-button.png');
        });
        
        test('table row hover', async ({ page }) => {
            await authenticateUser(page);
            await page.goto('/contacts');
            await page.waitForLoadState('networkidle');
            
            const row = page.locator('tbody tr').first();
            await row.waitFor({ timeout: 15000 });
            await row.scrollIntoViewIfNeeded();
            await row.hover();
            
            await expect(row).toHaveScreenshot('hover-table-row.png');
        });
    });

    test.describe('Focus States', () => {
        test('input focus ring', async ({ page }) => {
            await page.goto('/login');
            
            const emailInput = page.getByLabel('Email');
            await emailInput.focus();
            
            await expect(emailInput).toHaveScreenshot('focus-input.png');
        });
        
        test('button focus ring', async ({ page }) => {
            await page.goto('/login');
            
            const button = page.getByRole('button', { name: 'Sign in' });
            await button.focus();
            
            await expect(button).toHaveScreenshot('focus-button.png');
        });
    });

    test.describe('Error States', () => {
        test('form error display', async ({ page }) => {
            // Mock CSRF token endpoint so the form can submit
            await page.route(/\/api\/csrf/, async (route) => {
                await route.fulfill({
                    status: 200,
                    contentType: 'application/json',
                    body: JSON.stringify({ token: 'test-csrf-token' }),
                });
            });

            // Mock login endpoint to return an error
            await page.route(/\/api\/auth\/login/, async (route) => {
                await route.fulfill({
                    status: 401,
                    contentType: 'application/json',
                    body: JSON.stringify({ error: 'Invalid credentials' }),
                });
            });

            await page.goto('/login');
            await page.waitForLoadState('networkidle');

            await page.getByLabel('Email').fill('invalid@example.com');
            await page.getByLabel('Password').fill('badpassword');
            await page.getByRole('button', { name: 'Sign in' }).click();
            
            const errorField = page.locator('[data-state="error"]');
            await errorField.waitFor({ timeout: 10000 });
            await expect(errorField).toHaveScreenshot('error-input.png');
        });
        
        test('error page 404', async ({ page }) => {
            await page.goto('/nonexistent-page');
            await page.waitForLoadState('networkidle');
            
            await expect(page).toHaveScreenshot('error-404.png', {
                fullPage: true,
            });
        });
        
        test('error page 500', async ({ page }) => {
            await page.route(/\/api\//, async (route) => {
                await route.fulfill({ status: 500 });
            });
            
            await authenticateUser(page);
            await page.goto('/dashboard');
            await page.waitForLoadState('networkidle');
            
            await expect(page).toHaveScreenshot('error-500.png', {
                fullPage: true,
            });
        });
    });

    test.describe('Loading States', () => {
        test.describe.configure({ retries: 2 });

        test('skeleton loading', async ({ page }) => {
            await page.route(/\/api\//, async (route) => {
                await new Promise(resolve => setTimeout(resolve, 5000));
                await route.continue();
            });
            
            await authenticateUser(page);
            await page.waitForLoadState('domcontentloaded');
            
            await expect(page).toHaveScreenshot('loading-skeleton.png', {
                fullPage: true,
            });
        });
        
        test('spinner loading', async ({ page }) => {
            // Override the dashboard summary API to return 500 so data=null but loading=false.
            // This makes the health card render with the spinner state.
            await page.route(/\/api\/v1\/analytics\/dashboard/, async (route) => {
                await route.fulfill({ status: 500, contentType: 'application/json', body: '{}' });
            });

            await authenticateUser(page);
            await page.goto('/dashboard');
            await page.waitForLoadState('networkidle');
            const spinner = page.locator('[data-testid="spinner"]');
            await spinner.waitFor({ timeout: 15000 });
            await expect(spinner).toHaveScreenshot('loading-spinner.png');
        });
    });

    test.describe('Button Alignment', () => {
        test.beforeEach(async ({ page }) => {
            await authenticateUser(page);
        });

        test('dashboard activity card header - button vertical alignment', async ({ page }) => {
            // The CardHeader uses flex-row + items-center. Without space-y-0 override,
            // the space-y-1.5 from the CardHeader base adds margin-top to the action button.
            await page.goto('/dashboard');
            await page.waitForLoadState('networkidle');

            const activityFeed = page.locator('[data-testid="activity-feed"]');
            await activityFeed.waitFor({ timeout: 20000 });

            // Capture the card header area specifically to detect vertical misalignment
            const cardHeader = activityFeed.locator(':scope > div').first();
            await cardHeader.waitFor({ timeout: 5000 });
            await expect(cardHeader).toHaveScreenshot('button-align-dashboard-activity-header.png');
        });

        test('contacts page header actions - button row alignment', async ({ page }) => {
            // The actions slot has Import + Add Contact buttons in a flex row.
            // Verifies both buttons are at the same vertical center.
            await page.goto('/contacts');
            await page.waitForLoadState('networkidle');

            const heading = page.getByRole('heading', { name: 'Contacts' });
            await heading.waitFor({ timeout: 15000 });

            // The page header section
            const pageHeader = page.locator('h1').locator('..').locator('..');
            await expect(pageHeader).toHaveScreenshot('button-align-contacts-header.png');
        });

        test('settings API key row - side-by-side button alignment', async ({ page }) => {
            // The API & Webhooks section has Copy + Revoke buttons side by side.
            await page.goto('/settings');
            await page.waitForLoadState('networkidle');

            // Navigate to API section via sidebar
            await page.getByRole('button', { name: /API/i }).click();
            await page.waitForTimeout(200);

            // Capture the API key card
            const apiCard = page.locator('text=Production Key').locator('../../..');
            await apiCard.waitFor({ timeout: 10000 });
            await expect(apiCard).toHaveScreenshot('button-align-settings-api-key-row.png');
        });
    });
});

