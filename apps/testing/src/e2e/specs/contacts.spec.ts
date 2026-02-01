/**
 * @apexmail/testing - Contacts E2E Tests
 * 
 * Tests for contact management, list creation, and segmentation.
 */

import { test, expect, generators, helpers } from '../fixtures.js';

test.describe('Contacts', () => {
    test.describe('Contact List', () => {
        test('should display contacts page', async ({ authenticatedPage, contactsPage }) => {
            await contactsPage.goto();
            
            await expect(contactsPage.addButton).toBeVisible();
            await expect(contactsPage.searchInput).toBeVisible();
        });
        
        test('should display contacts in table', async ({ authenticatedPage, contactsPage }) => {
            await contactsPage.goto();
            
            const count = await contactsPage.getContactCount();
            expect(count).toBeGreaterThanOrEqual(0);
        });
        
        test('should search contacts by email', async ({ authenticatedPage, contactsPage }) => {
            await contactsPage.goto();
            
            await contactsPage.searchContacts('test@example.com');
            
            await helpers.waitForApi(contactsPage.page, '/api/contacts');
        });
        
        test('should filter contacts by list', async ({ authenticatedPage, contactsPage }) => {
            await contactsPage.goto();
            
            await contactsPage.filterByList('Newsletter');
            
            await expect(contactsPage.page).toHaveURL(/list=/);
        });
        
        test('should sort contacts by date', async ({ authenticatedPage, contactsPage }) => {
            await contactsPage.goto();
            
            await contactsPage.contactTable.getByRole('columnheader', { name: 'Created' }).click();
            
            // Should toggle sort direction
            await expect(contactsPage.page).toHaveURL(/sort=created/);
        });
    });
    
    test.describe('Contact Creation', () => {
        test('should open add contact dialog', async ({ authenticatedPage, contactsPage }) => {
            await contactsPage.goto();
            await contactsPage.clickAdd();
            
            await expect(contactsPage.page.getByRole('dialog')).toBeVisible();
        });
        
        test('should add a new contact', async ({ authenticatedPage, contactsPage }) => {
            await contactsPage.goto();
            
            const email = generators.email();
            
            await contactsPage.addContact({
                email,
                firstName: 'Test',
                lastName: 'User',
            });
            
            await expect(contactsPage.page.getByText('Contact added')).toBeVisible();
        });
        
        test('should validate email format', async ({ authenticatedPage, contactsPage }) => {
            await contactsPage.goto();
            await contactsPage.clickAdd();
            
            await contactsPage.page.getByLabel('Email').fill('invalid-email');
            await contactsPage.page.getByRole('button', { name: 'Save' }).click();
            
            await expect(contactsPage.page.getByText('Invalid email format')).toBeVisible();
        });
        
        test('should prevent duplicate emails', async ({ authenticatedPage, contactsPage }) => {
            await contactsPage.goto();
            
            // Try to add existing contact
            await contactsPage.addContact({
                email: 'existing@example.com',
                firstName: 'Existing',
            });
            
            await expect(contactsPage.page.getByText('Contact already exists')).toBeVisible();
        });
        
        test('should add custom attributes', async ({ authenticatedPage, contactsPage }) => {
            await contactsPage.goto();
            await contactsPage.clickAdd();
            
            await contactsPage.page.getByLabel('Email').fill(generators.email());
            await contactsPage.page.getByRole('button', { name: 'Add Custom Field' }).click();
            
            await contactsPage.page.getByLabel('Field Name').fill('company');
            await contactsPage.page.getByLabel('Field Value').fill('ACME Corp');
            
            await contactsPage.page.getByRole('button', { name: 'Save' }).click();
            
            await expect(contactsPage.page.getByText('Contact added')).toBeVisible();
        });
    });
    
    test.describe('Contact Editing', () => {
        test('should open contact details', async ({ authenticatedPage, contactsPage }) => {
            await contactsPage.goto();
            
            await contactsPage.clickContact('test@example.com');
            
            await expect(contactsPage.page.getByRole('dialog')).toBeVisible();
        });
        
        test('should edit contact details', async ({ authenticatedPage, page }) => {
            await page.goto('/contacts');
            
            await page.getByRole('row', { name: /test@example.com/ }).click();
            await page.getByLabel('First Name').fill('Updated');
            await page.getByRole('button', { name: 'Save' }).click();
            
            await expect(page.getByText('Contact updated')).toBeVisible();
        });
        
        test('should add contact to list', async ({ authenticatedPage, page }) => {
            await page.goto('/contacts');
            
            await page.getByRole('row', { name: /test@example.com/ }).click();
            await page.getByRole('button', { name: 'Add to List' }).click();
            await page.getByRole('option', { name: 'Newsletter' }).click();
            
            await expect(page.getByText('Contact added to list')).toBeVisible();
        });
        
        test('should remove contact from list', async ({ authenticatedPage, page }) => {
            await page.goto('/contacts');
            
            await page.getByRole('row', { name: /test@example.com/ }).click();
            await page.locator('[data-testid="list-tag"]').first().getByRole('button', { name: 'Remove' }).click();
            
            await expect(page.getByText('Contact removed from list')).toBeVisible();
        });
    });
    
    test.describe('Contact Deletion', () => {
        test('should delete a contact', async ({ authenticatedPage, contactsPage }) => {
            await contactsPage.goto();
            
            await contactsPage.deleteContact('delete-me@example.com');
            
            await expect(contactsPage.page.getByText('Contact deleted')).toBeVisible();
        });
        
        test('should bulk delete contacts', async ({ authenticatedPage, page }) => {
            await page.goto('/contacts');
            
            // Select multiple contacts
            await page.getByRole('checkbox', { name: 'Select all' }).check();
            await page.getByRole('button', { name: 'Delete Selected' }).click();
            
            // Confirm deletion
            await page.getByRole('button', { name: 'Delete' }).click();
            
            await expect(page.getByText(/contacts deleted/)).toBeVisible();
        });
    });
    
    test.describe('Contact Import', () => {
        test('should open import dialog', async ({ authenticatedPage, page }) => {
            await page.goto('/contacts');
            
            await page.getByRole('button', { name: 'Import' }).click();
            
            await expect(page.getByRole('dialog')).toBeVisible();
        });
        
        test('should validate CSV format', async ({ authenticatedPage, page }) => {
            await page.goto('/contacts');
            await page.getByRole('button', { name: 'Import' }).click();
            
            // Upload invalid file
            const fileChooser = await page.waitForEvent('filechooser');
            await fileChooser.setFiles({
                name: 'invalid.txt',
                mimeType: 'text/plain',
                buffer: Buffer.from('invalid content'),
            });
            
            await expect(page.getByText('Please upload a CSV file')).toBeVisible();
        });
        
        test('should preview import data', async ({ authenticatedPage, page }) => {
            await page.goto('/contacts');
            await page.getByRole('button', { name: 'Import' }).click();
            
            const fileChooser = await page.waitForEvent('filechooser');
            await fileChooser.setFiles({
                name: 'contacts.csv',
                mimeType: 'text/csv',
                buffer: Buffer.from('email,firstName,lastName\ntest1@example.com,Test,One\ntest2@example.com,Test,Two'),
            });
            
            // Preview table should show data
            await expect(page.getByText('test1@example.com')).toBeVisible();
            await expect(page.getByText('2 contacts to import')).toBeVisible();
        });
        
        test('should complete import', async ({ authenticatedPage, page }) => {
            await page.goto('/contacts');
            await page.getByRole('button', { name: 'Import' }).click();
            
            const fileChooser = await page.waitForEvent('filechooser');
            await fileChooser.setFiles({
                name: 'contacts.csv',
                mimeType: 'text/csv',
                buffer: Buffer.from('email,firstName\ntest@example.com,Test'),
            });
            
            await page.getByRole('button', { name: 'Import' }).click();
            
            await expect(page.getByText('Import completed')).toBeVisible();
        });
    });
    
    test.describe('Contact Export', () => {
        test('should export all contacts', async ({ authenticatedPage, page }) => {
            await page.goto('/contacts');
            
            const [download] = await Promise.all([
                page.waitForEvent('download'),
                page.getByRole('button', { name: 'Export' }).click(),
            ]);
            
            expect(download.suggestedFilename()).toMatch(/contacts.*\.csv$/);
        });
        
        test('should export filtered contacts', async ({ authenticatedPage, page }) => {
            await page.goto('/contacts?list=newsletter');
            
            const [download] = await Promise.all([
                page.waitForEvent('download'),
                page.getByRole('button', { name: 'Export' }).click(),
            ]);
            
            expect(download.suggestedFilename()).toMatch(/contacts.*\.csv$/);
        });
    });
    
    test.describe('Contact Lists', () => {
        test('should create a new list', async ({ authenticatedPage, page }) => {
            await page.goto('/contacts/lists');
            
            await page.getByRole('button', { name: 'Create List' }).click();
            await page.getByLabel('List Name').fill(generators.listName());
            await page.getByRole('button', { name: 'Create' }).click();
            
            await expect(page.getByText('List created')).toBeVisible();
        });
        
        test('should rename a list', async ({ authenticatedPage, page }) => {
            await page.goto('/contacts/lists');
            
            await page.getByRole('row', { name: /Test List/ }).getByRole('button', { name: 'Actions' }).click();
            await page.getByRole('menuitem', { name: 'Rename' }).click();
            
            await page.getByLabel('List Name').fill('Renamed List');
            await page.getByRole('button', { name: 'Save' }).click();
            
            await expect(page.getByText('List renamed')).toBeVisible();
        });
        
        test('should delete an empty list', async ({ authenticatedPage, page }) => {
            await page.goto('/contacts/lists');
            
            await page.getByRole('row', { name: /Empty List/ }).getByRole('button', { name: 'Actions' }).click();
            await page.getByRole('menuitem', { name: 'Delete' }).click();
            await page.getByRole('button', { name: 'Delete' }).click();
            
            await expect(page.getByText('List deleted')).toBeVisible();
        });
    });
    
    test.describe('Contact Segments', () => {
        test('should create a segment', async ({ authenticatedPage, page }) => {
            await page.goto('/contacts/segments');
            
            await page.getByRole('button', { name: 'Create Segment' }).click();
            await page.getByLabel('Segment Name').fill('Active Subscribers');
            
            // Add conditions
            await page.getByRole('button', { name: 'Add Condition' }).click();
            await page.getByRole('combobox', { name: 'Field' }).selectOption('lastActivity');
            await page.getByRole('combobox', { name: 'Operator' }).selectOption('within');
            await page.getByLabel('Value').fill('30');
            
            await page.getByRole('button', { name: 'Create' }).click();
            
            await expect(page.getByText('Segment created')).toBeVisible();
        });
        
        test('should preview segment size', async ({ authenticatedPage, page }) => {
            await page.goto('/contacts/segments/new');
            
            await page.getByRole('button', { name: 'Add Condition' }).click();
            await page.getByRole('combobox', { name: 'Field' }).selectOption('email');
            await page.getByRole('combobox', { name: 'Operator' }).selectOption('contains');
            await page.getByLabel('Value').fill('@example.com');
            
            await page.getByRole('button', { name: 'Preview' }).click();
            
            await expect(page.getByText(/contacts match/)).toBeVisible();
        });
    });
    
    test.describe('Contact Activity', () => {
        test('should display contact activity history', async ({ authenticatedPage, page }) => {
            await page.goto('/contacts/test-contact-1');
            
            await page.getByRole('tab', { name: 'Activity' }).click();
            
            await expect(page.getByText('Activity History')).toBeVisible();
        });
        
        test('should filter activity by type', async ({ authenticatedPage, page }) => {
            await page.goto('/contacts/test-contact-1?tab=activity');
            
            await page.getByRole('combobox', { name: 'Activity Type' }).selectOption('open');
            
            // Only open events should be shown
            await expect(page.getByText('Opens').first()).toBeVisible();
        });
    });
    
    test.describe('Contact Tags', () => {
        test('should add tag to contact', async ({ authenticatedPage, page }) => {
            await page.goto('/contacts');
            
            await page.getByRole('row', { name: /test@example.com/ }).click();
            await page.getByRole('button', { name: 'Add Tag' }).click();
            await page.getByPlaceholder('Enter tag').fill('VIP');
            await page.keyboard.press('Enter');
            
            await expect(page.locator('[data-testid="tag-VIP"]')).toBeVisible();
        });
        
        test('should remove tag from contact', async ({ authenticatedPage, page }) => {
            await page.goto('/contacts');
            
            await page.getByRole('row', { name: /test@example.com/ }).click();
            await page.locator('[data-testid="tag-VIP"]').getByRole('button', { name: 'Remove' }).click();
            
            await expect(page.locator('[data-testid="tag-VIP"]')).not.toBeVisible();
        });
        
        test('should filter contacts by tag', async ({ authenticatedPage, contactsPage }) => {
            await contactsPage.goto();
            
            await contactsPage.filterByTag('VIP');
            
            await expect(contactsPage.page).toHaveURL(/tag=VIP/);
        });
    });
});
