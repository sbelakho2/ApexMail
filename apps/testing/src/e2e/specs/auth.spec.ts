/**
 * @apexmail/testing - Authentication E2E Tests
 * 
 * Tests for login, logout, signup, and password reset flows.
 */

import { test, expect, generators, helpers } from '../fixtures.js';

test.describe('Authentication', () => {
    test.describe('Login', () => {
        test('should display login page with all elements', async ({ loginPage }) => {
            await loginPage.goto();
            
            await expect(loginPage.emailInput).toBeVisible();
            await expect(loginPage.passwordInput).toBeVisible();
            await expect(loginPage.submitButton).toBeVisible();
            await expect(loginPage.forgotPasswordLink).toBeVisible();
            await expect(loginPage.signUpLink).toBeVisible();
        });
        
        test('should login successfully with valid credentials', async ({ loginPage, testUser }) => {
            await loginPage.goto();
            await loginPage.login(testUser.email, testUser.password);
            await loginPage.expectSuccess();
        });
        
        test('should show error with invalid email', async ({ loginPage }) => {
            await loginPage.goto();
            await loginPage.login('invalid@example.com', 'wrongpassword');
            await loginPage.expectError('Invalid email or password');
        });
        
        test('should show error with invalid password', async ({ loginPage, testUser }) => {
            await loginPage.goto();
            await loginPage.login(testUser.email, 'wrongpassword');
            await loginPage.expectError('Invalid email or password');
        });
        
        test('should show validation error for empty email', async ({ loginPage }) => {
            await loginPage.goto();
            await loginPage.submitButton.click();
            await expect(loginPage.emailInput).toHaveAttribute('aria-invalid', 'true');
        });
        
        test('should show validation error for invalid email format', async ({ loginPage }) => {
            await loginPage.goto();
            await loginPage.emailInput.fill('notanemail');
            await loginPage.passwordInput.fill('password123');
            await loginPage.submitButton.click();
            await loginPage.expectError('Invalid email format');
        });
        
        test('should redirect to intended page after login', async ({ page, loginPage, testUser }) => {
            // Try to access protected page
            await page.goto('/campaigns');
            
            // Should redirect to login
            await expect(page).toHaveURL(/\/login/);
            
            // Login
            await loginPage.login(testUser.email, testUser.password);
            
            // Should redirect back to campaigns
            await expect(page).toHaveURL(/\/campaigns/);
        });
        
        test('should persist session across page refreshes', async ({ page, loginPage, testUser }) => {
            await loginPage.goto();
            await loginPage.login(testUser.email, testUser.password);
            await loginPage.expectSuccess();
            
            // Refresh page
            await page.reload();
            
            // Should still be on dashboard
            await expect(page).toHaveURL(/\/dashboard/);
        });
    });
    
    test.describe('Logout', () => {
        test('should logout successfully', async ({ authenticatedPage }) => {
            await authenticatedPage.logout();
        });
        
        test('should clear session on logout', async ({ page, authenticatedPage }) => {
            await authenticatedPage.logout();
            
            // Try to access protected page
            await page.goto('/dashboard');
            
            // Should redirect to login
            await expect(page).toHaveURL(/\/login/);
        });
    });
    
    test.describe('Password Reset', () => {
        test('should display forgot password page', async ({ loginPage, page }) => {
            await loginPage.goto();
            await loginPage.forgotPasswordLink.click();
            
            await expect(page.getByRole('heading', { name: 'Reset Password' })).toBeVisible();
            await expect(page.getByLabel('Email')).toBeVisible();
        });
        
        test('should send password reset email', async ({ loginPage, page, testUser }) => {
            await loginPage.goto();
            await loginPage.forgotPasswordLink.click();
            
            await page.getByLabel('Email').fill(testUser.email);
            await page.getByRole('button', { name: 'Send Reset Link' }).click();
            
            await expect(page.getByText('Password reset email sent')).toBeVisible();
        });
        
        test('should show error for non-existent email', async ({ loginPage, page }) => {
            await loginPage.goto();
            await loginPage.forgotPasswordLink.click();
            
            await page.getByLabel('Email').fill('nonexistent@example.com');
            await page.getByRole('button', { name: 'Send Reset Link' }).click();
            
            // Note: For security, we show the same message even for non-existent emails
            await expect(page.getByText('Password reset email sent')).toBeVisible();
        });
    });
    
    test.describe('Sign Up', () => {
        test('should display signup page', async ({ loginPage, page }) => {
            await loginPage.goto();
            await loginPage.signUpLink.click();
            
            await expect(page.getByRole('heading', { name: 'Create Account' })).toBeVisible();
        });
        
        test('should create account successfully', async ({ loginPage, page }) => {
            await loginPage.goto();
            await loginPage.signUpLink.click();
            
            const email = generators.email();
            
            await page.getByLabel('Name').fill('New Test User');
            await page.getByLabel('Email').fill(email);
            await page.getByLabel('Password').fill('SecurePassword123!');
            await page.getByLabel('Confirm Password').fill('SecurePassword123!');
            await page.getByRole('button', { name: 'Create Account' }).click();
            
            // Should redirect to verification page or dashboard
            await expect(page).toHaveURL(/\/(verify|dashboard)/);
        });
        
        test('should show error for existing email', async ({ loginPage, page, testUser }) => {
            await loginPage.goto();
            await loginPage.signUpLink.click();
            
            await page.getByLabel('Name').fill('Another User');
            await page.getByLabel('Email').fill(testUser.email);
            await page.getByLabel('Password').fill('SecurePassword123!');
            await page.getByLabel('Confirm Password').fill('SecurePassword123!');
            await page.getByRole('button', { name: 'Create Account' }).click();
            
            await expect(page.getByRole('alert')).toContainText('already exists');
        });
        
        test('should validate password requirements', async ({ loginPage, page }) => {
            await loginPage.goto();
            await loginPage.signUpLink.click();
            
            await page.getByLabel('Name').fill('Test User');
            await page.getByLabel('Email').fill(generators.email());
            await page.getByLabel('Password').fill('weak');
            await page.getByLabel('Confirm Password').fill('weak');
            await page.getByRole('button', { name: 'Create Account' }).click();
            
            await expect(page.getByText(/password.*8 characters/i)).toBeVisible();
        });
        
        test('should validate password confirmation match', async ({ loginPage, page }) => {
            await loginPage.goto();
            await loginPage.signUpLink.click();
            
            await page.getByLabel('Name').fill('Test User');
            await page.getByLabel('Email').fill(generators.email());
            await page.getByLabel('Password').fill('SecurePassword123!');
            await page.getByLabel('Confirm Password').fill('DifferentPassword123!');
            await page.getByRole('button', { name: 'Create Account' }).click();
            
            await expect(page.getByText(/passwords.*match/i)).toBeVisible();
        });
    });
    
    test.describe('Session Security', () => {
        test('should handle expired session gracefully', async ({ page, authenticatedPage }) => {
            // Clear auth cookie to simulate expired session
            await page.context().clearCookies();
            
            // Try to access protected page
            await page.goto('/campaigns');
            
            // Should redirect to login with session expired message
            await expect(page).toHaveURL(/\/login/);
        });
        
        test('should handle concurrent sessions', async ({ browser, testUser }) => {
            // Create two browser contexts
            const context1 = await browser.newContext();
            const context2 = await browser.newContext();
            
            const page1 = await context1.newPage();
            const page2 = await context2.newPage();
            
            // Login on both
            await page1.goto('/login');
            await page1.getByLabel('Email').fill(testUser.email);
            await page1.getByLabel('Password').fill(testUser.password);
            await page1.getByRole('button', { name: 'Sign In' }).click();
            
            await page2.goto('/login');
            await page2.getByLabel('Email').fill(testUser.email);
            await page2.getByLabel('Password').fill(testUser.password);
            await page2.getByRole('button', { name: 'Sign In' }).click();
            
            // Both should be logged in
            await expect(page1).toHaveURL(/\/dashboard/);
            await expect(page2).toHaveURL(/\/dashboard/);
            
            // Cleanup
            await context1.close();
            await context2.close();
        });
    });
});
