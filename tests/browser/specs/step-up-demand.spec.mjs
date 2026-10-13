import { test, expect } from '@playwright/test';

// The rendered step-up demand. A refused form re-renders its widget
// container with the demand id the server minted for that field
// (`data-kiwi-step-up-demand`, the exact markup the Symfony form theme
// emits; the fixture page reproduces it through ?step_up_demand=<id>).
// The driver reads the attribute and presents it to the email begin and
// complete endpoints when the typed `STEP_UP_REQUIRED` refusal arrives,
// so the dialog flow completes on the very form that was refused.

test.describe('KiwiCaptcha rendered step-up demand', () => {
  const RENDERED = 'rendered-demand-000000001';
  const WIRE = 'wire-demand-00000000001';

  function mockStepUpFlow(page, { wireDemand }) {
    const beginBodies = [];
    const completeBodies = [];
    const stepUp = { kind: 'email_ownership', begin: '/kiwi/step-up/email/begin' };
    if (wireDemand) stepUp.demand = wireDemand;
    page.route('**/challenge', async (route) => {
      await route.fulfill({
        status: 403,
        contentType: 'application/json',
        body: JSON.stringify({
          error: {
            code: 'STEP_UP_REQUIRED',
            message: 'Additional verification is required for this request.',
            step_up: stepUp,
          },
        }),
      });
    });
    page.route('**/kiwi/step-up/email/begin', async (route) => {
      const body = route.request().postDataJSON();
      beginBodies.push(body);
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          kind: 'email_ownership',
          challenge: 'demand-ticket',
          expires_in: 600,
          complete_path: '/kiwi/step-up/email/complete',
          scope: body.scope,
        }),
      });
    });
    page.route('**/kiwi/step-up/email/complete', async (route) => {
      const body = route.request().postDataJSON();
      completeBodies.push(body);
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          status: 'succeeded',
          grant: 'kiwiemg1.demand000000000000000000.sig',
          expires_in: 600,
          scope: 'login',
        }),
      });
    });

    return { beginBodies, completeBodies };
  }

  async function completeDialog(page) {
    const dialog = page.locator('[data-kiwi-stepup] [role="dialog"]');
    await expect(dialog).toBeVisible({ timeout: 30_000 });
    await dialog.locator('input[type="email"]').fill('visitor@example.com');
    await dialog.locator('button[type="submit"]').first().click();
    const codeInput = dialog.locator('input[autocomplete="one-time-code"]');
    await expect(codeInput).toBeVisible({ timeout: 30_000 });
    await codeInput.fill('123456');
    await codeInput.press('Enter');
    await expect(dialog).toHaveCount(0, { timeout: 30_000 });
  }

  test('a signup form under the abuse refusal: the 403 demand renders the dialog and the grant completes the flow', async ({ page }) => {
    const { beginBodies, completeBodies } = mockStepUpFlow(page, { wireDemand: WIRE });

    await page.goto(`/?step_up_demand=${RENDERED}&form=1`);

    // The demand attribute the server rendered reaches the DOM on the
    // widget container of the refused form.
    await expect(page.locator('.kiwi-container')).toHaveAttribute('data-kiwi-step-up-demand', RENDERED);

    await completeDialog(page);

    // The begin consumed the demand id and the complete answered the
    // same one, exactly the pair the 403 minted.
    expect(beginBodies).toHaveLength(1);
    expect(beginBodies[0].demand).toBe(WIRE);
    expect(beginBodies[0].email).toBe('visitor@example.com');
    expect(completeBodies).toHaveLength(1);
    expect(completeBodies[0].demand).toBe(WIRE);
    expect(completeBodies[0].kiwi_step_up_ticket).toBe('demand-ticket');
    expect(completeBodies[0].kiwi_step_up_code).toMatch(/^[0-9]{6}$/);

    // The grant rides the token field of the hosted form and the widget
    // reads done, so the resubmission carries the completed factor.
    await expect(page.locator('[data-kiwi-token]')).toHaveValue(/^kiwiemg1\./, { timeout: 30_000 });
    await expect(page.locator('[data-kiwi-widget]')).toHaveAttribute('data-state', 'done', { timeout: 30_000 });
  });

  test('the rendered attribute is the demand fallback when the 403 answers bare', async ({ page }) => {
    const { beginBodies } = mockStepUpFlow(page, { wireDemand: null });

    await page.goto(`/?step_up_demand=${RENDERED}`);
    await completeDialog(page);

    expect(beginBodies).toHaveLength(1);
    expect(beginBodies[0].demand).toBe(RENDERED);
  });

  test('no rendered attribute and a bare 403 sends no invented demand', async ({ page }) => {
    const { beginBodies } = mockStepUpFlow(page, { wireDemand: null });

    await page.goto('/');
    await completeDialog(page);

    expect(beginBodies).toHaveLength(1);
    expect(beginBodies[0].demand).toBe('');
  });
});
