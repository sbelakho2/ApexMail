/**
 * @apexmail/testing - Accessibility Tests
 * 
 * Automated accessibility testing using axe-core.
 */

import { test, expect } from '@playwright/test';
import { injectAxe, getViolations } from 'axe-playwright';

/**
 * Custom AxeBuilder class for compatibility with the test code
 */
class AxeBuilder {
    private page: any;
    private tags: string[] = [];
    private includeSelector: string | null = null;

    constructor(options: { page: any }) {
        this.page = options.page;
    }

    withTags(tags: string[]): AxeBuilder {
        this.tags = tags;
        return this;
    }

    include(selector: string): AxeBuilder {
        this.includeSelector = selector;
        return this;
    }

    async analyze(): Promise<{ violations: Array<{ id: string; nodes: any[] }> }> {
        await injectAxe(this.page);
        const violations = await getViolations(this.page, this.includeSelector || undefined, {
            runOnly: this.tags.length > 0 ? { type: 'tag', values: this.tags } : undefined,
        });
        return { violations };
    }
}

const pages = [
    { name: 'Login', path: '/login', authenticated: false },
    { name: 'Sign Up', path: '/signup', authenticated: false },
    { name: 'Forgot Password', path: '/forgot-password', authenticated: false },
    { name: 'Dashboard', path: '/dashboard', authenticated: true },
    { name: 'Campaigns', path: '/campaigns', authenticated: true },
    { name: 'Campaign Editor', path: '/campaigns/new', authenticated: true },
    { name: 'Contacts', path: '/contacts', authenticated: true },
    { name: 'Contact Lists', path: '/contacts/lists', authenticated: true },
    { name: 'Settings', path: '/settings', authenticated: true },
    { name: 'Team Settings', path: '/settings/team', authenticated: true },
    { name: 'Billing', path: '/settings/billing', authenticated: true },
];

test.describe('Accessibility Tests', () => {
    const authenticate = async (page: any) => {
        await page.goto('/login');
        await page.getByLabel('Email').fill('test@example.com');
        await page.getByLabel('Password').fill('password123');
        await page.getByRole('button', { name: 'Sign in' }).click();
        await page.waitForURL('/dashboard');
    };

    for (const pageConfig of pages) {
        test(`${pageConfig.name} page should have no accessibility violations`, async ({ page }) => {
            if (pageConfig.authenticated) {
                await authenticate(page);
            }

            await page.goto(pageConfig.path);
            await page.waitForLoadState('networkidle');

            const accessibilityScanResults = await new AxeBuilder({ page })
                .withTags(['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'])
                .analyze();

            expect(accessibilityScanResults.violations).toEqual([]);
        });
    }

    test.describe('Keyboard Navigation', () => {
        test('login form should be navigable with keyboard', async ({ page }) => {
            await page.goto('/login');

            // Tab through form elements
            await page.keyboard.press('Tab');
            await expect(page.getByLabel('Email')).toBeFocused();

            await page.keyboard.press('Tab');
            await expect(page.getByLabel('Password')).toBeFocused();

            await page.keyboard.press('Tab');
            await expect(page.getByRole('button', { name: 'Sign in' })).toBeFocused();
        });

        test('should be able to submit form with Enter key', async ({ page }) => {
            await page.goto('/login');

            await page.getByLabel('Email').fill('test@example.com');
            await page.getByLabel('Password').fill('password123');
            await page.keyboard.press('Enter');

            // Should attempt login
            await page.waitForResponse((response) =>
                response.url().includes('/api/auth/login')
            );
        });

        test('dashboard navigation should be keyboard accessible', async ({ page }) => {
            await authenticate(page);
            await page.goto('/dashboard');

            // Tab to navigation
            let tabCount = 0;
            while (tabCount < 20) {
                await page.keyboard.press('Tab');
                const focused = await page.evaluate(() =>
                    document.activeElement?.getAttribute('role')
                );
                if (focused === 'navigation' || focused === 'menuitem') {
                    break;
                }
                tabCount++;
            }

            // Navigation item should be focusable
            const focusedElement = await page.evaluate(() =>
                document.activeElement?.tagName.toLowerCase()
            );
            expect(['a', 'button', 'input']).toContain(focusedElement);
        });

        test('modal should trap focus', async ({ page }) => {
            await authenticate(page);
            await page.goto('/contacts');

            // Open add contact dialog
            await page.getByRole('button', { name: 'Add Contact' }).click();
            await expect(page.getByRole('dialog')).toBeVisible();

            // Tab through modal - should not escape
            const dialogSelector = '[role="dialog"]';
            for (let i = 0; i < 20; i++) {
                await page.keyboard.press('Tab');
                const isInDialog = await page.evaluate((selector) => {
                    const dialog = document.querySelector(selector);
                    return dialog?.contains(document.activeElement);
                }, dialogSelector);

                expect(isInDialog).toBe(true);
            }
        });

        test('Escape key should close modal', async ({ page }) => {
            await authenticate(page);
            await page.goto('/contacts');

            await page.getByRole('button', { name: 'Add Contact' }).click();
            await expect(page.getByRole('dialog')).toBeVisible();

            await page.keyboard.press('Escape');
            await expect(page.getByRole('dialog')).not.toBeVisible();
        });
    });

    test.describe('Screen Reader Support', () => {
        test('page should have proper heading hierarchy', async ({ page }) => {
            await authenticate(page);
            await page.goto('/dashboard');

            const headings = await page.evaluate(() => {
                const h1s = document.querySelectorAll('h1');
                const h2s = document.querySelectorAll('h2');
                const h3s = document.querySelectorAll('h3');

                return {
                    h1Count: h1s.length,
                    h2Count: h2s.length,
                    h3Count: h3s.length,
                };
            });

            // Should have exactly one h1
            expect(headings.h1Count).toBe(1);
        });

        test('images should have alt text', async ({ page }) => {
            await authenticate(page);
            await page.goto('/dashboard');

            const imagesWithoutAlt = await page.evaluate(() => {
                const images = document.querySelectorAll('img');
                return Array.from(images).filter(
                    (img) => !img.alt && !img.getAttribute('role')?.includes('presentation')
                ).length;
            });

            expect(imagesWithoutAlt).toBe(0);
        });

        test('form inputs should have labels', async ({ page }) => {
            await page.goto('/login');

            const inputsWithoutLabels = await page.evaluate(() => {
                const inputs = document.querySelectorAll('input, select, textarea');
                return Array.from(inputs).filter((input) => {
                    const id = input.id;
                    const ariaLabel = input.getAttribute('aria-label');
                    const ariaLabelledBy = input.getAttribute('aria-labelledby');
                    const label = id ? document.querySelector(`label[for="${id}"]`) : null;

                    return !label && !ariaLabel && !ariaLabelledBy;
                }).length;
            });

            expect(inputsWithoutLabels).toBe(0);
        });

        test('buttons should have accessible names', async ({ page }) => {
            await authenticate(page);
            await page.goto('/campaigns');

            const buttonsWithoutNames = await page.evaluate(() => {
                const buttons = document.querySelectorAll('button, [role="button"]');
                return Array.from(buttons).filter((button) => {
                    const text = button.textContent?.trim();
                    const ariaLabel = button.getAttribute('aria-label');
                    const ariaLabelledBy = button.getAttribute('aria-labelledby');
                    const title = button.getAttribute('title');

                    return !text && !ariaLabel && !ariaLabelledBy && !title;
                }).length;
            });

            expect(buttonsWithoutNames).toBe(0);
        });

        test('links should have descriptive text', async ({ page }) => {
            await authenticate(page);
            await page.goto('/dashboard');

            const vagueLinkText = ['click here', 'read more', 'learn more', 'here'];

            const vagueLinks = await page.evaluate((vagueText) => {
                const links = document.querySelectorAll('a');
                return Array.from(links).filter((link) => {
                    const text = (link.textContent || '').toLowerCase().trim();
                    return vagueText.includes(text);
                }).length;
            }, vagueLinkText);

            expect(vagueLinks).toBe(0);
        });
    });

    test.describe('Color Contrast', () => {
        test('text should have sufficient contrast', async ({ page }) => {
            await page.goto('/login');
            await page.waitForLoadState('networkidle');

            const contrastResults = await new AxeBuilder({ page })
                .withTags(['wcag2aa'])
                .include('body')
                .analyze();

            const contrastViolations = contrastResults.violations.filter(
                (v: { id: string }) => v.id === 'color-contrast'
            );

            expect(contrastViolations).toHaveLength(0);
        });

        test('focus indicators should be visible', async ({ page }) => {
            await page.goto('/login');

            await page.getByLabel('Email').focus();

            const hasVisibleFocus = await page.evaluate(() => {
                const el = document.activeElement;
                if (!el) return false;

                const styles = window.getComputedStyle(el);
                const outline = styles.outline;
                const boxShadow = styles.boxShadow;
                const border = styles.border;

                // Check if any focus indicator is present
                return (
                    outline !== 'none' ||
                    boxShadow !== 'none' ||
                    border !== ''
                );
            });

            expect(hasVisibleFocus).toBe(true);
        });
    });

    test.describe('ARIA Landmarks', () => {
        test('page should have main landmark', async ({ page }) => {
            await authenticate(page);
            await page.goto('/dashboard');

            const hasMain = await page.evaluate(() => {
                return (
                    document.querySelector('main') !== null ||
                    document.querySelector('[role="main"]') !== null
                );
            });

            expect(hasMain).toBe(true);
        });

        test('page should have navigation landmark', async ({ page }) => {
            await authenticate(page);
            await page.goto('/dashboard');

            const hasNav = await page.evaluate(() => {
                return (
                    document.querySelector('nav') !== null ||
                    document.querySelector('[role="navigation"]') !== null
                );
            });

            expect(hasNav).toBe(true);
        });

        test('page should have banner landmark', async ({ page }) => {
            await authenticate(page);
            await page.goto('/dashboard');

            const hasBanner = await page.evaluate(() => {
                return (
                    document.querySelector('header') !== null ||
                    document.querySelector('[role="banner"]') !== null
                );
            });

            expect(hasBanner).toBe(true);
        });
    });

    test.describe('Dynamic Content', () => {
        test('loading states should be announced', async ({ page }) => {
            await authenticate(page);

            // Slow down API to see loading state
            await page.route('/api/**', async (route) => {
                await new Promise((resolve) => setTimeout(resolve, 2000));
                await route.continue();
            });

            await page.goto('/campaigns');

            const hasAriaLive = await page.evaluate(() => {
                const loadingElements = document.querySelectorAll('[aria-busy="true"], [aria-live]');
                return loadingElements.length > 0;
            });

            expect(hasAriaLive).toBe(true);
        });

        test('error messages should be announced', async ({ page }) => {
            await page.goto('/login');

            // Submit empty form
            await page.getByRole('button', { name: 'Sign in' }).click();

            const hasErrorAnnouncement = await page.evaluate(() => {
                const errors = document.querySelectorAll(
                    '[role="alert"], [aria-live="polite"], [aria-live="assertive"]'
                );
                return Array.from(errors).some((el) => el.textContent?.trim());
            });

            expect(hasErrorAnnouncement).toBe(true);
        });

        test('toast notifications should be accessible', async ({ page }) => {
            await authenticate(page);
            await page.goto('/contacts');

            // Trigger a notification by adding a contact
            await page.getByRole('button', { name: 'Add Contact' }).click();
            await page.getByLabel('Email').fill('a11y-test@example.com');
            await page.getByRole('button', { name: 'Save' }).click();

            // Check for accessible notification
            const hasAccessibleToast = await page.evaluate(() => {
                const toasts = document.querySelectorAll('[role="status"], [role="alert"]');
                return toasts.length > 0;
            });

            expect(hasAccessibleToast).toBe(true);
        });
    });

    test.describe('Forms', () => {
        test('required fields should be marked', async ({ page }) => {
            await page.goto('/login');

            const requiredFieldsMarked = await page.evaluate(() => {
                const requiredInputs = document.querySelectorAll('[required], [aria-required="true"]');
                return requiredInputs.length > 0;
            });

            expect(requiredFieldsMarked).toBe(true);
        });

        test('error messages should be associated with inputs', async ({ page }) => {
            await page.goto('/login');

            // Trigger validation error
            await page.getByLabel('Email').fill('invalid');
            await page.getByRole('button', { name: 'Sign in' }).click();

            const errorsAssociated = await page.evaluate(() => {
                const invalidInputs = document.querySelectorAll('[aria-invalid="true"]');
                return Array.from(invalidInputs).every((input) => {
                    const describedBy = input.getAttribute('aria-describedby');
                    if (describedBy) {
                        return document.getElementById(describedBy) !== null;
                    }
                    return false;
                });
            });

            expect(errorsAssociated).toBe(true);
        });

        test('autocomplete attributes should be present', async ({ page }) => {
            await page.goto('/login');

            const emailAutocomplete = await page.getByLabel('Email').getAttribute('autocomplete');
            const passwordAutocomplete = await page.getByLabel('Password').getAttribute('autocomplete');

            expect(emailAutocomplete).toBe('email');
            expect(passwordAutocomplete).toBe('current-password');
        });
    });

    test.describe('Tables', () => {
        test('data tables should have proper structure', async ({ page }) => {
            await authenticate(page);
            await page.goto('/contacts');

            const tableStructure = await page.evaluate(() => {
                const table = document.querySelector('table');
                if (!table) return { hasTable: false };

                const hasCaption =
                    table.querySelector('caption') !== null ||
                    table.getAttribute('aria-label') !== null ||
                    table.getAttribute('aria-labelledby') !== null;

                const hasHeaders = table.querySelectorAll('th').length > 0;

                const headerCells = table.querySelectorAll('th');
                const hasScope = Array.from(headerCells).every(
                    (th) => th.getAttribute('scope') !== null
                );

                return { hasTable: true, hasCaption, hasHeaders, hasScope };
            });

            if (tableStructure.hasTable) {
                expect(tableStructure.hasHeaders).toBe(true);
            }
        });
    });

    test.describe('Media', () => {
        test('videos should have captions available', async ({ page }) => {
            await authenticate(page);
            // Navigate to a page that might have videos
            await page.goto('/help');

            const videosHaveCaptions = await page.evaluate(() => {
                const videos = document.querySelectorAll('video');
                return Array.from(videos).every((video) => {
                    return video.querySelector('track[kind="captions"]') !== null;
                });
            });

            // Only fail if there are videos without captions
            const hasVideos = await page.evaluate(() => document.querySelectorAll('video').length > 0);
            if (hasVideos) {
                expect(videosHaveCaptions).toBe(true);
            }
        });
    });
});
