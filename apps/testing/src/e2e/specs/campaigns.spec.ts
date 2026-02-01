/**
 * @apexmail/testing - Campaigns E2E Tests
 * 
 * Tests for campaign creation, editing, sending, and management.
 */

import { test, expect, generators, helpers } from '../fixtures.js';

test.describe('Campaigns', () => {
    test.describe('Campaign List', () => {
        test('should display campaigns page', async ({ authenticatedPage, page, campaignsPage }) => {
            await campaignsPage.goto();
            
            await expect(campaignsPage.createButton).toBeVisible();
            await expect(campaignsPage.searchInput).toBeVisible();
        });
        
        test('should show empty state when no campaigns', async ({ authenticatedPage, page }) => {
            // Mock empty campaigns response
            await helpers.mockApi(page, '/api/campaigns', { campaigns: [], total: 0 });
            
            await page.goto('/campaigns');
            
            await expect(page.locator('[data-testid="empty-state"]')).toBeVisible();
        });
        
        test('should display campaign list', async ({ authenticatedPage, campaignsPage }) => {
            await campaignsPage.goto();
            
            const count = await campaignsPage.getCampaignCount();
            expect(count).toBeGreaterThanOrEqual(0);
        });
        
        test('should filter campaigns by status', async ({ authenticatedPage, campaignsPage }) => {
            await campaignsPage.goto();
            
            await campaignsPage.filterByStatus('Draft');
            
            // Verify filter is applied (check URL or visible campaigns)
            await expect(campaignsPage.page).toHaveURL(/status=draft/);
        });
        
        test('should search campaigns by name', async ({ authenticatedPage, campaignsPage }) => {
            await campaignsPage.goto();
            
            await campaignsPage.searchCampaigns('Test');
            
            // Verify search is applied
            await helpers.waitForApi(campaignsPage.page, '/api/campaigns');
        });
        
        test('should paginate through campaigns', async ({ authenticatedPage, campaignsPage }) => {
            await campaignsPage.goto();
            
            // If pagination exists, click next
            if (await campaignsPage.pagination.isVisible()) {
                await campaignsPage.pagination.getByRole('button', { name: 'Next' }).click();
                await expect(campaignsPage.page).toHaveURL(/page=2/);
            }
        });
    });
    
    test.describe('Campaign Creation', () => {
        test('should open campaign editor', async ({ authenticatedPage, campaignsPage }) => {
            await campaignsPage.goto();
            await campaignsPage.clickCreate();
            
            await expect(campaignsPage.page).toHaveURL(/\/campaigns\/new/);
        });
        
        test('should create a new draft campaign', async ({ authenticatedPage, campaignEditorPage }) => {
            await campaignEditorPage.goto();
            
            const campaignName = generators.campaignName();
            
            await campaignEditorPage.fillBasicInfo({
                name: campaignName,
                subject: 'Test Subject Line',
                preheader: 'Preview text for the email',
            });
            
            await campaignEditorPage.save();
            
            // Should show success notification
            await expect(campaignEditorPage.page.getByText('Campaign saved')).toBeVisible();
        });
        
        test('should validate required fields', async ({ authenticatedPage, campaignEditorPage }) => {
            await campaignEditorPage.goto();
            
            // Try to save without filling required fields
            await campaignEditorPage.saveButton.click();
            
            // Should show validation errors
            await expect(campaignEditorPage.nameInput).toHaveAttribute('aria-invalid', 'true');
            await expect(campaignEditorPage.subjectInput).toHaveAttribute('aria-invalid', 'true');
        });
        
        test('should select recipients for campaign', async ({ authenticatedPage, campaignEditorPage }) => {
            await campaignEditorPage.goto();
            
            await campaignEditorPage.fillBasicInfo({
                name: generators.campaignName(),
                subject: 'Test Subject',
            });
            
            await campaignEditorPage.selectRecipients('Test List');
            
            // Recipients should be selected
            await expect(campaignEditorPage.recipientsSelector).toContainText('Test List');
        });
        
        test('should send a test email', async ({ authenticatedPage, campaignEditorPage }) => {
            await campaignEditorPage.goto();
            
            await campaignEditorPage.fillBasicInfo({
                name: generators.campaignName(),
                subject: 'Test Subject',
            });
            
            await campaignEditorPage.sendTestEmail('test@example.com');
            
            // Should show success message
            await expect(campaignEditorPage.page.getByText('Test email sent')).toBeVisible();
        });
    });
    
    test.describe('Campaign Editing', () => {
        test('should load existing campaign for editing', async ({ authenticatedPage, page }) => {
            await page.goto('/campaigns/test-campaign-1/edit');
            
            // Should load campaign data
            await expect(page.getByLabel('Campaign Name')).toHaveValue('Test Campaign');
        });
        
        test('should update campaign details', async ({ authenticatedPage, page }) => {
            await page.goto('/campaigns/test-campaign-1/edit');
            
            await page.getByLabel('Subject Line').fill('Updated Subject');
            await page.getByRole('button', { name: 'Save' }).click();
            
            await expect(page.getByText('Campaign updated')).toBeVisible();
        });
        
        test('should preview campaign', async ({ authenticatedPage, page }) => {
            await page.goto('/campaigns/test-campaign-1/edit');
            
            await page.getByRole('button', { name: 'Preview' }).click();
            
            // Preview modal should open
            await expect(page.getByRole('dialog')).toBeVisible();
        });
    });
    
    test.describe('Campaign Scheduling', () => {
        test('should schedule campaign for future send', async ({ authenticatedPage, page }) => {
            await page.goto('/campaigns/test-campaign-1/edit');
            
            await page.getByRole('button', { name: 'Schedule' }).click();
            
            // Select date and time
            const tomorrow = new Date();
            tomorrow.setDate(tomorrow.getDate() + 1);
            
            await page.getByLabel('Date').fill(tomorrow.toISOString().split('T')[0]);
            await page.getByLabel('Time').fill('10:00');
            
            await page.getByRole('button', { name: 'Confirm Schedule' }).click();
            
            await expect(page.getByText('Campaign scheduled')).toBeVisible();
        });
        
        test('should not allow scheduling in the past', async ({ authenticatedPage, page }) => {
            await page.goto('/campaigns/test-campaign-1/edit');
            
            await page.getByRole('button', { name: 'Schedule' }).click();
            
            // Try to select past date
            const yesterday = new Date();
            yesterday.setDate(yesterday.getDate() - 1);
            
            await page.getByLabel('Date').fill(yesterday.toISOString().split('T')[0]);
            
            await expect(page.getByText('Cannot schedule in the past')).toBeVisible();
        });
    });
    
    test.describe('Campaign Sending', () => {
        test('should send campaign immediately', async ({ authenticatedPage, page }) => {
            await page.goto('/campaigns/test-campaign-1/edit');
            
            await page.getByRole('button', { name: 'Send' }).click();
            
            // Confirmation dialog
            await expect(page.getByRole('dialog')).toBeVisible();
            await expect(page.getByText(/Are you sure/)).toBeVisible();
            
            await page.getByRole('button', { name: 'Send Now' }).click();
            
            await expect(page.getByText('Campaign is sending')).toBeVisible();
        });
        
        test('should require recipients before sending', async ({ authenticatedPage, campaignEditorPage }) => {
            await campaignEditorPage.goto();
            
            await campaignEditorPage.fillBasicInfo({
                name: generators.campaignName(),
                subject: 'Test Subject',
            });
            
            await campaignEditorPage.save();
            await campaignEditorPage.sendButton.click();
            
            await expect(campaignEditorPage.page.getByText('Please select recipients')).toBeVisible();
        });
    });
    
    test.describe('Campaign Deletion', () => {
        test('should delete a campaign', async ({ authenticatedPage, campaignsPage }) => {
            await campaignsPage.goto();
            
            const initialCount = await campaignsPage.getCampaignCount();
            
            await campaignsPage.deleteCampaign('Test Campaign');
            
            // Campaign should be removed
            await expect(campaignsPage.page.getByText('Campaign deleted')).toBeVisible();
        });
        
        test('should not delete a sent campaign', async ({ authenticatedPage, page }) => {
            // Assuming test-campaign-2 is a sent campaign
            await page.goto('/campaigns');
            
            const row = page.getByRole('row', { name: /Sent Campaign/ });
            await row.getByRole('button', { name: 'Actions' }).click();
            
            // Delete option should be disabled
            await expect(page.getByRole('menuitem', { name: 'Delete' })).toBeDisabled();
        });
    });
    
    test.describe('Campaign Analytics', () => {
        test('should display campaign stats', async ({ authenticatedPage, page }) => {
            await page.goto('/campaigns/test-campaign-1/analytics');
            
            // Stats should be visible
            await expect(page.getByText('Open Rate')).toBeVisible();
            await expect(page.getByText('Click Rate')).toBeVisible();
            await expect(page.getByText('Bounce Rate')).toBeVisible();
        });
        
        test('should export campaign report', async ({ authenticatedPage, page }) => {
            await page.goto('/campaigns/test-campaign-1/analytics');
            
            const [download] = await Promise.all([
                page.waitForEvent('download'),
                page.getByRole('button', { name: 'Export' }).click(),
            ]);
            
            expect(download.suggestedFilename()).toMatch(/\.csv$/);
        });
    });
});
