/**
 * @apexmail/testing - Visual Regression Tests
 * 
 * Automated visual testing for UI consistency across components and pages.
 */

import { test, expect, Page } from '@playwright/test';

const viewports = {
    desktop: { width: 1920, height: 1080 },
    laptop: { width: 1440, height: 900 },
    tablet: { width: 768, height: 1024 },
    mobile: { width: 375, height: 667 },
};

const themes = ['light', 'dark'] as const;

test.describe('Visual Regression Tests', () => {
    test.beforeEach(async ({ page }) => {
        // Set consistent test environment
        await page.emulateMedia({ reducedMotion: 'reduce' });
        await page.setExtraHTTPHeaders({ 'Accept-Language': 'en-US' });
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
                    await setTheme(page, theme);
                    
                    await page.goto('/dashboard');
                    await page.waitForLoadState('networkidle');
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
            await expect(metricsGrid).toHaveScreenshot('dashboard-metrics.png');
        });
        
        test('dashboard charts', async ({ page }) => {
            await page.goto('/dashboard');
            await waitForCharts(page);
            
            const chartSection = page.locator('[data-testid="charts-section"]');
            await expect(chartSection).toHaveScreenshot('dashboard-charts.png');
        });
    });

    test.describe('Campaigns Page', () => {
        test.beforeEach(async ({ page }) => {
            await authenticateUser(page);
        });
        
        test('campaigns list - empty state', async ({ page }) => {
            await page.route('/api/campaigns', async (route) => {
                await route.fulfill({
                    status: 200,
                    body: JSON.stringify({ campaigns: [], total: 0 }),
                });
            });
            
            await page.goto('/campaigns');
            await page.waitForLoadState('networkidle');
            
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
            await page.goto('/campaigns/test-campaign-1/edit');
            await page.waitForLoadState('networkidle');
            
            await page.getByRole('button', { name: 'Preview' }).click();
            await page.waitForTimeout(200);
            
            await expect(page.locator('[role="dialog"]')).toHaveScreenshot('campaign-preview-modal.png');
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
            await page.getByRole('button', { name: 'Add Contact' }).click();
            await page.waitForTimeout(200);
            
            await expect(page.locator('[role="dialog"]')).toHaveScreenshot('contact-add-dialog.png');
        });
        
        test('contact detail view', async ({ page }) => {
            await page.goto('/contacts');
            await page.getByRole('row', { name: /test@example.com/ }).click();
            await page.waitForTimeout(200);
            
            await expect(page.locator('[role="dialog"]')).toHaveScreenshot('contact-detail.png');
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
            await page.goto('/dashboard');
            await page.waitForLoadState('networkidle');
            
            // Capture text-heavy section
            const textSection = page.locator('[data-testid="activity-feed"]');
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
            await page.goto('/campaigns/new');
            await page.waitForLoadState('networkidle');
            
            const form = page.locator('form');
            await expect(form).toHaveScreenshot('layout-form-spacing.png');
        });
        
        test('consistent grid layout', async ({ page }) => {
            await authenticateUser(page);
            await page.goto('/dashboard');
            await page.waitForLoadState('networkidle');
            
            const grid = page.locator('[data-testid="metrics-grid"]');
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
            await page.locator('[data-testid="user-menu"]').click();
            await page.waitForTimeout(50);
            
            await expect(page.locator('[data-testid="user-dropdown"]')).toHaveScreenshot('animation-dropdown-open.png');
        });
        
        test('modal entrance animation', async ({ page }) => {
            await authenticateUser(page);
            await page.goto('/contacts');
            await page.emulateMedia({ reducedMotion: 'no-preference' });
            
            await page.getByRole('button', { name: 'Add Contact' }).click();
            await page.waitForTimeout(100);
            
            await expect(page.locator('[role="dialog"]')).toHaveScreenshot('animation-modal-entrance.png');
        });
    });

    test.describe('Hover States', () => {
        test('button hover states', async ({ page }) => {
            await authenticateUser(page);
            await page.goto('/dashboard');
            
            const button = page.getByRole('button', { name: 'New Campaign' });
            await button.hover();
            
            await expect(button).toHaveScreenshot('hover-button.png');
        });
        
        test('table row hover', async ({ page }) => {
            await authenticateUser(page);
            await page.goto('/contacts');
            
            const row = page.locator('tbody tr').first();
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
            await page.goto('/login');
            
            await page.getByLabel('Email').fill('invalid');
            await page.getByRole('button', { name: 'Sign in' }).click();
            
            const errorField = page.locator('[data-state="error"]');
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
            await page.route('/api/**', async (route) => {
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
        test('skeleton loading', async ({ page }) => {
            await page.route('/api/**', async (route) => {
                await new Promise(resolve => setTimeout(resolve, 5000));
                await route.continue();
            });
            
            await authenticateUser(page);
            await page.goto('/dashboard', { waitUntil: 'domcontentloaded' });
            
            await expect(page).toHaveScreenshot('loading-skeleton.png', {
                fullPage: true,
            });
        });
        
        test('spinner loading', async ({ page }) => {
            await authenticateUser(page);
            await page.goto('/campaigns');
            
            await page.route('/api/campaigns', async (route) => {
                await new Promise(resolve => setTimeout(resolve, 5000));
                await route.continue();
            });
            
            await page.reload({ waitUntil: 'domcontentloaded' });
            
            const spinner = page.locator('[data-testid="spinner"]');
            await expect(spinner).toHaveScreenshot('loading-spinner.png');
        });
    });
});

// Helper functions

async function authenticateUser(page: Page): Promise<void> {
    await page.goto('/login');
    await page.getByLabel('Email').fill('test@example.com');
    await page.getByLabel('Password').fill('password123');
    await page.getByRole('button', { name: 'Sign in' }).click();
    await page.waitForURL('/dashboard');
}

async function setTheme(page: Page, theme: 'light' | 'dark'): Promise<void> {
    await page.evaluate((t) => {
        document.documentElement.setAttribute('data-theme', t);
        document.documentElement.classList.toggle('dark', t === 'dark');
    }, theme);
}

async function waitForCharts(page: Page): Promise<void> {
    // Wait for chart animations to complete
    await page.waitForFunction(() => {
        const charts = document.querySelectorAll('[data-testid*="chart"]');
        return charts.length > 0 && 
            Array.from(charts).every(chart => !chart.classList.contains('loading'));
    });
    await page.waitForTimeout(500); // Extra buffer for chart rendering
}
