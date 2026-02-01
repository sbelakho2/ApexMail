/**
 * @apexmail/testing - E2E Test Fixtures
 * 
 * Extended Playwright fixtures for ApexMail testing.
 */

import { test as base, expect, Page, Route, Response } from '@playwright/test';
import {
    LoginPage,
    DashboardPage,
    CampaignsPage,
    CampaignEditorPage,
    ContactsPage,
    SettingsPage,
} from './pages/index.js';

/**
 * Test user type
 */
interface TestUser {
    id: string;
    email: string;
    password: string;
    name: string;
    role?: string;
}

/**
 * Extended fixtures type
 */
interface ApexMailFixtures {
    // Page objects
    loginPage: LoginPage;
    dashboardPage: DashboardPage;
    campaignsPage: CampaignsPage;
    campaignEditorPage: CampaignEditorPage;
    contactsPage: ContactsPage;
    settingsPage: SettingsPage;
    
    // Test data
    testUser: TestUser;
    adminUser: TestUser;
    
    // Helpers
    authenticatedPage: DashboardPage;
    adminPage: DashboardPage;
}

/**
 * Extended test with ApexMail fixtures
 */
export const test = base.extend<ApexMailFixtures>({
    // Page objects
    loginPage: async ({ page }, use) => {
        const loginPage = new LoginPage(page);
        await use(loginPage);
    },
    
    dashboardPage: async ({ page }, use) => {
        const dashboardPage = new DashboardPage(page);
        await use(dashboardPage);
    },
    
    campaignsPage: async ({ page }, use) => {
        const campaignsPage = new CampaignsPage(page);
        await use(campaignsPage);
    },
    
    campaignEditorPage: async ({ page }, use) => {
        const campaignEditorPage = new CampaignEditorPage(page);
        await use(campaignEditorPage);
    },
    
    contactsPage: async ({ page }, use) => {
        const contactsPage = new ContactsPage(page);
        await use(contactsPage);
    },
    
    settingsPage: async ({ page }, use) => {
        const settingsPage = new SettingsPage(page);
        await use(settingsPage);
    },
    
    // Test users
    testUser: async ({}, use) => {
        const testUser: TestUser = {
            id: 'test-user-1',
            email: 'test@apexmail.test',
            password: 'testpassword123',
            name: 'Test User',
        };
        await use(testUser);
    },
    
    adminUser: async ({}, use) => {
        const adminUser: TestUser = {
            id: 'test-admin-1',
            email: 'admin@apexmail.test',
            password: 'adminpassword123',
            name: 'Test Admin',
            role: 'admin',
        };
        await use(adminUser);
    },
    
    // Authenticated page (automatically logs in as test user)
    authenticatedPage: async ({ page, loginPage, dashboardPage, testUser }, use) => {
        // Check if already authenticated
        await page.goto('/dashboard');
        
        if (page.url().includes('/login')) {
            await loginPage.goto();
            await loginPage.login(testUser.email, testUser.password);
            await loginPage.expectSuccess();
        }
        
        await use(dashboardPage);
    },
    
    // Admin page (automatically logs in as admin)
    adminPage: async ({ page, loginPage, dashboardPage, adminUser }, use) => {
        // Check if already authenticated
        await page.goto('/dashboard');
        
        if (page.url().includes('/login')) {
            await loginPage.goto();
            await loginPage.login(adminUser.email, adminUser.password);
            await loginPage.expectSuccess();
        }
        
        await use(dashboardPage);
    },
});

/**
 * Re-export expect
 */
export { expect };

/**
 * Test tags for categorization
 */
export const tags = {
    smoke: '@smoke',
    regression: '@regression',
    critical: '@critical',
    slow: '@slow',
    flaky: '@flaky',
    mobile: '@mobile',
    a11y: '@a11y',
};

/**
 * Test data generators
 */
export const generators = {
    /**
     * Generate a unique email address
     */
    email: (): string => {
        const timestamp = Date.now();
        const random = Math.random().toString(36).slice(2, 8);
        return `test-${timestamp}-${random}@example.com`;
    },
    
    /**
     * Generate a unique campaign name
     */
    campaignName: (): string => {
        const timestamp = Date.now();
        return `Test Campaign ${timestamp}`;
    },
    
    /**
     * Generate a unique list name
     */
    listName: (): string => {
        const timestamp = Date.now();
        return `Test List ${timestamp}`;
    },
    
    /**
     * Generate a random subject line
     */
    subjectLine: (): string => {
        const subjects = [
            'Check out our latest offers!',
            '🎉 Special promotion just for you',
            "Don't miss out on these deals",
            'Your weekly newsletter is here',
            'Breaking news: Amazing updates inside',
        ];
        return subjects[Math.floor(Math.random() * subjects.length)];
    },
};

/**
 * Common test helpers
 */
export const helpers = {
    /**
     * Wait for API response
     */
    waitForApi: async (page: Page, urlPattern: string | RegExp, options?: { timeout?: number }): Promise<void> => {
        await page.waitForResponse(
            (response: Response) =>
                typeof urlPattern === 'string'
                    ? response.url().includes(urlPattern)
                    : urlPattern.test(response.url()),
            options
        );
    },
    
    /**
     * Intercept and mock API response
     */
    mockApi: async (
        page: Page,
        urlPattern: string | RegExp,
        response: unknown
    ): Promise<void> => {
        await page.route(urlPattern, (route: Route) => {
            route.fulfill({
                status: 200,
                contentType: 'application/json',
                body: JSON.stringify(response),
            });
        });
    },
    
    /**
     * Clear all local storage
     */
    clearStorage: async (page: Page): Promise<void> => {
        await page.evaluate(() => {
            localStorage.clear();
            sessionStorage.clear();
        });
    },
    
    /**
     * Set authentication cookie
     */
    setAuthCookie: async (page: Page, token: string): Promise<void> => {
        await page.context().addCookies([
            {
                name: 'auth_token',
                value: token,
                domain: 'localhost',
                path: '/',
                httpOnly: true,
                secure: false,
            },
        ]);
    },
};
