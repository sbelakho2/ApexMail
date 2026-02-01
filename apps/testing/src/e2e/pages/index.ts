/**
 * @apexmail/testing - Page Object Models
 * 
 * Reusable page objects for E2E tests.
 */

import { Page, Locator, expect } from '@playwright/test';

/**
 * Base page object with common functionality
 */
export abstract class BasePage {
    readonly page: Page;
    readonly url: string;

    constructor(page: Page, url: string) {
        this.page = page;
        this.url = url;
    }

    async goto(): Promise<void> {
        await this.page.goto(this.url);
        await this.waitForLoad();
    }

    async waitForLoad(): Promise<void> {
        await this.page.waitForLoadState('networkidle');
    }

    async getTitle(): Promise<string> {
        return this.page.title();
    }

    async takeScreenshot(name: string): Promise<void> {
        await this.page.screenshot({ path: `reports/screenshots/${name}.png` });
    }
}

/**
 * Login page object
 */
export class LoginPage extends BasePage {
    readonly emailInput: Locator;
    readonly passwordInput: Locator;
    readonly submitButton: Locator;
    readonly errorMessage: Locator;
    readonly forgotPasswordLink: Locator;
    readonly signUpLink: Locator;

    constructor(page: Page) {
        super(page, '/login');
        this.emailInput = page.getByLabel('Email');
        this.passwordInput = page.getByLabel('Password');
        this.submitButton = page.getByRole('button', { name: 'Sign In' });
        this.errorMessage = page.getByRole('alert');
        this.forgotPasswordLink = page.getByRole('link', { name: 'Forgot password' });
        this.signUpLink = page.getByRole('link', { name: 'Sign up' });
    }

    async login(email: string, password: string): Promise<void> {
        await this.emailInput.fill(email);
        await this.passwordInput.fill(password);
        await this.submitButton.click();
    }

    async expectError(message: string): Promise<void> {
        await expect(this.errorMessage).toContainText(message);
    }

    async expectSuccess(): Promise<void> {
        await this.page.waitForURL('/dashboard');
    }
}

/**
 * Dashboard page object
 */
export class DashboardPage extends BasePage {
    readonly welcomeMessage: Locator;
    readonly statsCards: Locator;
    readonly recentCampaignsTable: Locator;
    readonly quickActions: Locator;
    readonly searchInput: Locator;
    readonly userMenu: Locator;
    readonly notificationsButton: Locator;

    constructor(page: Page) {
        super(page, '/dashboard');
        this.welcomeMessage = page.getByRole('heading', { level: 1 });
        this.statsCards = page.locator('[data-testid="stats-card"]');
        this.recentCampaignsTable = page.getByRole('table');
        this.quickActions = page.locator('[data-testid="quick-actions"]');
        this.searchInput = page.getByPlaceholder('Search');
        this.userMenu = page.getByRole('button', { name: 'User menu' });
        this.notificationsButton = page.getByRole('button', { name: 'Notifications' });
    }

    async getStatsCount(): Promise<number> {
        return this.statsCards.count();
    }

    async search(query: string): Promise<void> {
        await this.searchInput.fill(query);
        await this.searchInput.press('Enter');
    }

    async openUserMenu(): Promise<void> {
        await this.userMenu.click();
    }

    async logout(): Promise<void> {
        await this.openUserMenu();
        await this.page.getByRole('menuitem', { name: 'Logout' }).click();
        await this.page.waitForURL('/login');
    }
}

/**
 * Campaigns page object
 */
export class CampaignsPage extends BasePage {
    readonly createButton: Locator;
    readonly searchInput: Locator;
    readonly filterDropdown: Locator;
    readonly campaignsTable: Locator;
    readonly campaignRows: Locator;
    readonly pagination: Locator;
    readonly emptyState: Locator;

    constructor(page: Page) {
        super(page, '/campaigns');
        this.createButton = page.getByRole('button', { name: 'Create Campaign' });
        this.searchInput = page.getByPlaceholder('Search campaigns');
        this.filterDropdown = page.getByRole('button', { name: 'Filter' });
        this.campaignsTable = page.getByRole('table');
        this.campaignRows = page.getByRole('row').filter({ hasNot: page.getByRole('columnheader') });
        this.pagination = page.locator('[data-testid="pagination"]');
        this.emptyState = page.locator('[data-testid="empty-state"]');
    }

    async clickCreate(): Promise<void> {
        await this.createButton.click();
    }

    async searchCampaigns(query: string): Promise<void> {
        await this.searchInput.fill(query);
        await this.page.waitForTimeout(500); // Debounce
    }

    async filterByStatus(status: string): Promise<void> {
        await this.filterDropdown.click();
        await this.page.getByRole('option', { name: status }).click();
    }

    async getCampaignCount(): Promise<number> {
        return this.campaignRows.count();
    }

    async clickCampaign(name: string): Promise<void> {
        await this.page.getByRole('cell', { name }).click();
    }

    async deleteCampaign(name: string): Promise<void> {
        const row = this.page.getByRole('row', { name: new RegExp(name) });
        await row.getByRole('button', { name: 'Actions' }).click();
        await this.page.getByRole('menuitem', { name: 'Delete' }).click();
        await this.page.getByRole('button', { name: 'Confirm' }).click();
    }
}

/**
 * Campaign editor page object
 */
export class CampaignEditorPage extends BasePage {
    readonly nameInput: Locator;
    readonly subjectInput: Locator;
    readonly preheaderInput: Locator;
    readonly fromNameInput: Locator;
    readonly fromEmailInput: Locator;
    readonly contentEditor: Locator;
    readonly saveButton: Locator;
    readonly sendButton: Locator;
    readonly scheduleButton: Locator;
    readonly previewButton: Locator;
    readonly testSendButton: Locator;
    readonly recipientsSelector: Locator;

    constructor(page: Page, campaignId?: string) {
        super(page, campaignId ? `/campaigns/${campaignId}/edit` : '/campaigns/new');
        this.nameInput = page.getByLabel('Campaign Name');
        this.subjectInput = page.getByLabel('Subject Line');
        this.preheaderInput = page.getByLabel('Preheader');
        this.fromNameInput = page.getByLabel('From Name');
        this.fromEmailInput = page.getByLabel('From Email');
        this.contentEditor = page.locator('[data-testid="email-editor"]');
        this.saveButton = page.getByRole('button', { name: 'Save' });
        this.sendButton = page.getByRole('button', { name: 'Send' });
        this.scheduleButton = page.getByRole('button', { name: 'Schedule' });
        this.previewButton = page.getByRole('button', { name: 'Preview' });
        this.testSendButton = page.getByRole('button', { name: 'Send Test' });
        this.recipientsSelector = page.locator('[data-testid="recipients-selector"]');
    }

    async fillBasicInfo(data: {
        name: string;
        subject: string;
        preheader?: string;
        fromName?: string;
        fromEmail?: string;
    }): Promise<void> {
        await this.nameInput.fill(data.name);
        await this.subjectInput.fill(data.subject);
        if (data.preheader) await this.preheaderInput.fill(data.preheader);
        if (data.fromName) await this.fromNameInput.fill(data.fromName);
        if (data.fromEmail) await this.fromEmailInput.fill(data.fromEmail);
    }

    async save(): Promise<void> {
        await this.saveButton.click();
        await this.page.waitForSelector('[data-testid="save-success"]');
    }

    async sendTestEmail(email: string): Promise<void> {
        await this.testSendButton.click();
        await this.page.getByLabel('Test Email').fill(email);
        await this.page.getByRole('button', { name: 'Send' }).click();
    }

    async selectRecipients(listName: string): Promise<void> {
        await this.recipientsSelector.click();
        await this.page.getByRole('option', { name: listName }).click();
    }

    async preview(): Promise<void> {
        await this.previewButton.click();
    }
}

/**
 * Contacts page object
 */
export class ContactsPage extends BasePage {
    readonly addContactButton: Locator;
    readonly importButton: Locator;
    readonly searchInput: Locator;
    readonly contactsTable: Locator;
    readonly contactRows: Locator;
    readonly listsSidebar: Locator;
    readonly bulkActionsMenu: Locator;

    constructor(page: Page) {
        super(page, '/contacts');
        this.addContactButton = page.getByRole('button', { name: 'Add Contact' });
        this.importButton = page.getByRole('button', { name: 'Import' });
        this.searchInput = page.getByPlaceholder('Search contacts');
        this.contactsTable = page.getByRole('table');
        this.contactRows = page.getByRole('row').filter({ hasNot: page.getByRole('columnheader') });
        this.listsSidebar = page.locator('[data-testid="lists-sidebar"]');
        this.bulkActionsMenu = page.getByRole('button', { name: 'Bulk Actions' });
    }

    async addContact(data: {
        email: string;
        firstName?: string;
        lastName?: string;
    }): Promise<void> {
        await this.addContactButton.click();
        await this.page.getByLabel('Email').fill(data.email);
        if (data.firstName) await this.page.getByLabel('First Name').fill(data.firstName);
        if (data.lastName) await this.page.getByLabel('Last Name').fill(data.lastName);
        await this.page.getByRole('button', { name: 'Add' }).click();
    }

    async searchContacts(query: string): Promise<void> {
        await this.searchInput.fill(query);
        await this.page.waitForTimeout(500);
    }

    async selectList(listName: string): Promise<void> {
        await this.listsSidebar.getByText(listName).click();
    }

    async getContactCount(): Promise<number> {
        return this.contactRows.count();
    }

    async selectContacts(emails: string[]): Promise<void> {
        for (const email of emails) {
            const row = this.page.getByRole('row', { name: email });
            await row.getByRole('checkbox').check();
        }
    }

    async bulkDelete(): Promise<void> {
        await this.bulkActionsMenu.click();
        await this.page.getByRole('menuitem', { name: 'Delete' }).click();
        await this.page.getByRole('button', { name: 'Confirm' }).click();
    }
}

/**
 * Settings page object
 */
export class SettingsPage extends BasePage {
    readonly tabs: Locator;
    readonly saveButton: Locator;
    readonly cancelButton: Locator;

    constructor(page: Page) {
        super(page, '/settings');
        this.tabs = page.getByRole('tablist');
        this.saveButton = page.getByRole('button', { name: 'Save' });
        this.cancelButton = page.getByRole('button', { name: 'Cancel' });
    }

    async selectTab(tabName: string): Promise<void> {
        await this.tabs.getByRole('tab', { name: tabName }).click();
    }

    async save(): Promise<void> {
        await this.saveButton.click();
        await this.page.waitForSelector('[data-testid="save-success"]');
    }
}

/**
 * Export all page objects
 */
export const pages = {
    LoginPage,
    DashboardPage,
    CampaignsPage,
    CampaignEditorPage,
    ContactsPage,
    SettingsPage,
};
