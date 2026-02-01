/**
 * @apexmail/testing - Dashboard E2E Tests
 * 
 * Tests for dashboard functionality, widgets, and analytics.
 */

import { test, expect, helpers } from '../fixtures.js';

test.describe('Dashboard', () => {
    test.describe('Overview', () => {
        test('should display dashboard after login', async ({ authenticatedPage: _authenticatedPage, dashboardPage }) => {
            await dashboardPage.goto();
            
            await expect(dashboardPage.welcomeMessage).toBeVisible();
        });
        
        test('should display key metrics', async ({ authenticatedPage: _authenticatedPage, dashboardPage }) => {
            await dashboardPage.goto();
            
            const metrics = await dashboardPage.getMetrics();
            
            expect(metrics).toHaveProperty('totalContacts');
            expect(metrics).toHaveProperty('emailsSent');
            expect(metrics).toHaveProperty('openRate');
            expect(metrics).toHaveProperty('clickRate');
        });
        
        test('should display recent campaigns', async ({ authenticatedPage: _authenticatedPage, dashboardPage }) => {
            await dashboardPage.goto();
            
            await expect(dashboardPage.recentCampaigns).toBeVisible();
        });
        
        test('should display activity feed', async ({ authenticatedPage: _authenticatedPage, dashboardPage }) => {
            await dashboardPage.goto();
            
            await expect(dashboardPage.activityFeed).toBeVisible();
        });
    });
    
    test.describe('Metrics Cards', () => {
        test('should show total contacts metric', async ({ authenticatedPage: _authenticatedPage, page }) => {
            await page.goto('/dashboard');
            
            const contactsCard = page.locator('[data-testid="metric-contacts"]');
            await expect(contactsCard).toBeVisible();
            
            const value = await contactsCard.locator('[data-testid="metric-value"]').textContent();
            expect(Number(value?.replace(/,/g, ''))).toBeGreaterThanOrEqual(0);
        });
        
        test('should show emails sent metric', async ({ authenticatedPage: _authenticatedPage, page }) => {
            await page.goto('/dashboard');
            
            const emailsCard = page.locator('[data-testid="metric-emails"]');
            await expect(emailsCard).toBeVisible();
        });
        
        test('should show trend indicators', async ({ authenticatedPage: _authenticatedPage, page }) => {
            await page.goto('/dashboard');
            
            const trendIndicator = page.locator('[data-testid="metric-trend"]').first();
            await expect(trendIndicator).toBeVisible();
            
            const trendClass = await trendIndicator.getAttribute('class');
            expect(trendClass).toMatch(/positive|negative|neutral/);
        });
        
        test('should navigate to detail on metric click', async ({ authenticatedPage: _authenticatedPage, page }) => {
            await page.goto('/dashboard');
            
            await page.locator('[data-testid="metric-contacts"]').click();
            
            await expect(page).toHaveURL('/contacts');
        });
    });
    
    test.describe('Charts and Graphs', () => {
        test('should display email performance chart', async ({ authenticatedPage: _authenticatedPage, page }) => {
            await page.goto('/dashboard');
            
            const chart = page.locator('[data-testid="performance-chart"]');
            await expect(chart).toBeVisible();
        });
        
        test('should change chart time range', async ({ authenticatedPage: _authenticatedPage, page }) => {
            await page.goto('/dashboard');
            
            await page.getByRole('button', { name: '30 days' }).click();
            
            // Chart should update
            await helpers.waitForApi(page, '/api/analytics');
        });
        
        test('should display engagement rate chart', async ({ authenticatedPage: _authenticatedPage, page }) => {
            await page.goto('/dashboard');
            
            const engagementChart = page.locator('[data-testid="engagement-chart"]');
            await expect(engagementChart).toBeVisible();
        });
        
        test('should toggle chart data series', async ({ authenticatedPage: _authenticatedPage, page }) => {
            await page.goto('/dashboard');
            
            // Click on legend to toggle series
            await page.locator('[data-testid="chart-legend"]').getByText('Opens').click();
            
            // Series should be hidden/shown
            const series = page.locator('[data-testid="series-opens"]');
            await expect(series).toHaveClass(/hidden/);
        });
    });
    
    test.describe('Recent Campaigns Widget', () => {
        test('should display recent campaigns', async ({ authenticatedPage: _authenticatedPage, page }) => {
            await page.goto('/dashboard');
            
            const widget = page.locator('[data-testid="recent-campaigns"]');
            await expect(widget).toBeVisible();
            
            const campaigns = widget.locator('[data-testid="campaign-item"]');
            await expect(campaigns).toHaveCount(5); // Default shows 5
        });
        
        test('should show campaign status', async ({ authenticatedPage: _authenticatedPage, page }) => {
            await page.goto('/dashboard');
            
            const campaignItem = page.locator('[data-testid="campaign-item"]').first();
            const status = campaignItem.locator('[data-testid="campaign-status"]');
            
            await expect(status).toHaveText(/Draft|Scheduled|Sent|Sending/);
        });
        
        test('should navigate to campaign on click', async ({ authenticatedPage: _authenticatedPage, page }) => {
            await page.goto('/dashboard');
            
            await page.locator('[data-testid="campaign-item"]').first().click();
            
            await expect(page).toHaveURL(/\/campaigns\//);
        });
        
        test('should show view all link', async ({ authenticatedPage: _authenticatedPage, page }) => {
            await page.goto('/dashboard');
            
            await page.getByRole('link', { name: 'View all campaigns' }).click();
            
            await expect(page).toHaveURL('/campaigns');
        });
    });
    
    test.describe('Activity Feed', () => {
        test('should display recent activity', async ({ authenticatedPage: _authenticatedPage, page }) => {
            await page.goto('/dashboard');
            
            const feed = page.locator('[data-testid="activity-feed"]');
            await expect(feed).toBeVisible();
        });
        
        test('should show activity details', async ({ authenticatedPage: _authenticatedPage, page }) => {
            await page.goto('/dashboard');
            
            const activity = page.locator('[data-testid="activity-item"]').first();
            
            await expect(activity.locator('[data-testid="activity-type"]')).toBeVisible();
            await expect(activity.locator('[data-testid="activity-time"]')).toBeVisible();
        });
        
        test('should filter activity by type', async ({ authenticatedPage: _authenticatedPage, page }) => {
            await page.goto('/dashboard');
            
            await page.getByRole('combobox', { name: 'Activity Type' }).selectOption('opens');
            
            // Only open activities should show
            const activities = page.locator('[data-testid="activity-item"]');
            const firstType = await activities.first().locator('[data-testid="activity-type"]').textContent();
            expect(firstType?.toLowerCase()).toContain('open');
        });
        
        test('should auto-refresh activity feed', async ({ authenticatedPage: _authenticatedPage, page }) => {
            await page.goto('/dashboard');
            
            // Wait for auto-refresh (simulated by checking API call)
            await helpers.waitForApi(page, '/api/activity', { timeout: 35000 });
        });
    });
    
    test.describe('Quick Actions', () => {
        test('should show quick action buttons', async ({ authenticatedPage: _authenticatedPage, page }) => {
            await page.goto('/dashboard');
            
            await expect(page.getByRole('button', { name: 'New Campaign' })).toBeVisible();
            await expect(page.getByRole('button', { name: 'Add Contact' })).toBeVisible();
        });
        
        test('should navigate to campaign creation', async ({ authenticatedPage: _authenticatedPage, page }) => {
            await page.goto('/dashboard');
            
            await page.getByRole('button', { name: 'New Campaign' }).click();
            
            await expect(page).toHaveURL('/campaigns/new');
        });
        
        test('should open add contact dialog', async ({ authenticatedPage: _authenticatedPage, page }) => {
            await page.goto('/dashboard');
            
            await page.getByRole('button', { name: 'Add Contact' }).click();
            
            await expect(page.getByRole('dialog')).toBeVisible();
        });
    });
    
    test.describe('Date Range Selector', () => {
        test('should display date range selector', async ({ authenticatedPage: _authenticatedPage, page }) => {
            await page.goto('/dashboard');
            
            await expect(page.getByRole('button', { name: /Last \d+ days/ })).toBeVisible();
        });
        
        test('should change date range', async ({ authenticatedPage: _authenticatedPage, page }) => {
            await page.goto('/dashboard');
            
            await page.getByRole('button', { name: /Last \d+ days/ }).click();
            await page.getByRole('option', { name: 'Last 90 days' }).click();
            
            // Dashboard should reload with new data
            await helpers.waitForApi(page, '/api/analytics');
        });
        
        test('should support custom date range', async ({ authenticatedPage: _authenticatedPage, page }) => {
            await page.goto('/dashboard');
            
            await page.getByRole('button', { name: /Last \d+ days/ }).click();
            await page.getByRole('option', { name: 'Custom' }).click();
            
            // Date picker should open
            await expect(page.getByRole('dialog', { name: 'Select date range' })).toBeVisible();
        });
    });
    
    test.describe('Notifications', () => {
        test('should display notifications badge', async ({ authenticatedPage: _authenticatedPage, page }) => {
            await page.goto('/dashboard');
            
            const badge = page.locator('[data-testid="notifications-badge"]');
            await expect(badge).toBeVisible();
        });
        
        test('should open notifications panel', async ({ authenticatedPage: _authenticatedPage, page }) => {
            await page.goto('/dashboard');
            
            await page.locator('[data-testid="notifications-button"]').click();
            
            await expect(page.locator('[data-testid="notifications-panel"]')).toBeVisible();
        });
        
        test('should mark notification as read', async ({ authenticatedPage: _authenticatedPage, page }) => {
            await page.goto('/dashboard');
            
            await page.locator('[data-testid="notifications-button"]').click();
            
            const notification = page.locator('[data-testid="notification-item"]').first();
            await notification.getByRole('button', { name: 'Mark as read' }).click();
            
            await expect(notification).toHaveClass(/read/);
        });
    });
    
    test.describe('Responsive Layout', () => {
        test('should adapt to mobile viewport', async ({ authenticatedPage: _authenticatedPage, page }) => {
            await page.setViewportSize({ width: 375, height: 667 });
            await page.goto('/dashboard');
            
            // Sidebar should be collapsed
            await expect(page.locator('[data-testid="sidebar"]')).not.toBeVisible();
            
            // Hamburger menu should be visible
            await expect(page.locator('[data-testid="mobile-menu-button"]')).toBeVisible();
        });
        
        test('should open mobile sidebar', async ({ authenticatedPage: _authenticatedPage, page }) => {
            await page.setViewportSize({ width: 375, height: 667 });
            await page.goto('/dashboard');
            
            await page.locator('[data-testid="mobile-menu-button"]').click();
            
            await expect(page.locator('[data-testid="mobile-sidebar"]')).toBeVisible();
        });
        
        test('should stack cards on tablet', async ({ authenticatedPage: _authenticatedPage, page }) => {
            await page.setViewportSize({ width: 768, height: 1024 });
            await page.goto('/dashboard');
            
            const metricsGrid = page.locator('[data-testid="metrics-grid"]');
            const columns = await metricsGrid.evaluate((el) => {
                return getComputedStyle(el).gridTemplateColumns;
            });
            
            // Should have 2 columns on tablet
            expect(columns.split(' ').length).toBeLessThanOrEqual(2);
        });
    });
    
    test.describe('Loading States', () => {
        test('should show skeleton loading state', async ({ authenticatedPage: _authenticatedPage, page }) => {
            // Slow down API to see loading state
            await page.route('/api/**', async (route) => {
                await new Promise(resolve => setTimeout(resolve, 1000));
                await route.continue();
            });
            
            await page.goto('/dashboard');
            
            await expect(page.locator('[data-testid="skeleton"]').first()).toBeVisible();
        });
        
        test('should handle API errors gracefully', async ({ authenticatedPage: _authenticatedPage, page }) => {
            await page.route('/api/analytics', async (route) => {
                await route.fulfill({
                    status: 500,
                    body: JSON.stringify({ error: 'Server error' }),
                });
            });
            
            await page.goto('/dashboard');
            
            await expect(page.getByText(/error|failed/i)).toBeVisible();
        });
    });
});
