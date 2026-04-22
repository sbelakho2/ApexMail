import fs from 'node:fs';
import path from 'node:path';
import { expect, test } from '@playwright/test';

import {
  buildLegacyLoginHtml,
  buildLegacySignupHtml,
} from '../visual/reference-auth-pages';

const TEST_ORIGIN = 'http://app.apexmail.test';
const FIXTURE_ROOT = path.resolve(__dirname, '../../fixtures/rust-ui');
const AUTH_CONTRACT_CSS_PATH = path.join(FIXTURE_ROOT, 'assets', 'globals.css');

type PendingVerification = {
  name: string;
  email: string;
  token: string;
  registerRequests: number;
  verifyRequests: number;
  verified: boolean;
};

function loadAuthContractCss(): string {
  return fs.readFileSync(AUTH_CONTRACT_CSS_PATH, 'utf8');
}

function escapeHtml(value: string): string {
  return value
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}

function withSignupHarness(html: string): string {
  const script = String.raw`
<script>
document.addEventListener('DOMContentLoaded', () => {
  const form = document.querySelector('form');
  const submitButton = form?.querySelector('button[type="submit"]');
  if (!form || !submitButton) {
    return;
  }

  const feedback = document.createElement('p');
  feedback.className = 'text-sm text-destructive';
  feedback.setAttribute('role', 'alert');

  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    submitButton.setAttribute('aria-busy', 'true');
    feedback.remove();

    const formData = new FormData(form);
    const payload = {
      name: String(formData.get('name') || ''),
      email: String(formData.get('email') || ''),
      password: String(formData.get('password') || ''),
    };

    try {
      const registerResponse = await fetch('/api/auth/register', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(payload),
      });

      if (!registerResponse.ok) {
        const errorPayload = await registerResponse.json().catch(() => ({}));
        feedback.textContent = errorPayload.error?.message || 'Unable to create your account.';
        form.appendChild(feedback);
        return;
      }

      const previewResponse = await fetch(
        '/api/auth/verification-email-preview?email=' + encodeURIComponent(payload.email),
      );
      const preview = await previewResponse.json();

      const shell = form.parentElement;
      if (!shell) {
        return;
      }

      shell.innerHTML = [
        '<div class="p-8 space-y-5" data-auth-state="verification-pending">',
        '<div class="space-y-2 text-center">',
        '<p class="text-sm font-semibold uppercase tracking-[0.2em] text-primary">Verification pending</p>',
        '<h2 class="text-2xl font-bold tracking-tight text-foreground">Check your email</h2>',
        '<p class="text-sm text-muted-foreground">We sent a verification link to <strong>' + payload.email + '</strong>. Open that email and follow the secure link to activate your account.</p>',
        '</div>',
        '<div class="space-y-3">',
        '<a id="open-verification-link" href="' + preview.verificationUrl + '" class="inline-flex w-full items-center justify-center rounded-xl bg-primary px-4 py-3 text-sm font-semibold text-primary-foreground shadow-lg shadow-primary/25 transition-all hover:bg-primary/90">Open verification link</a>',
        '<a href="/login" class="inline-flex w-full items-center justify-center rounded-xl border border-surface-200 px-4 py-3 text-sm font-semibold text-foreground transition-all hover:bg-surface-50">Back to sign in</a>',
        '</div>',
        '</div>',
      ].join('');
    } catch (error) {
      feedback.textContent = error instanceof Error ? error.message : 'Unable to create your account.';
      form.appendChild(feedback);
    } finally {
      submitButton.setAttribute('aria-busy', 'false');
    }
  });
});
</script>`;

  return html.replace('</body>', `${script}</body>`);
}

function buildVerifyEmailHtml(params: {
  email?: string;
  token?: string;
  status?: string;
  message?: string;
}): string {
  const email = params.email ? escapeHtml(params.email) : 'your email address';
  const message = escapeHtml(
    params.message ?? 'Your secure verification token is ready. Continue to activate your account.',
  );

  let noticeLabel = 'Verification ready';
  let heading = 'Verify your email';
  let description = message;
  let actions = `
    <button id="complete-verification" type="button" class="inline-flex w-full items-center justify-center rounded-xl bg-primary px-4 py-3 text-sm font-semibold text-primary-foreground shadow-lg shadow-primary/25 transition-all hover:bg-primary/90">Complete verification</button>
    <a href="/login" class="inline-flex w-full items-center justify-center rounded-xl border border-surface-200 px-4 py-3 text-sm font-semibold text-foreground transition-all hover:bg-surface-50">Back to sign in</a>
  `;

  if (params.status === 'success') {
    noticeLabel = 'Verification complete';
    heading = 'Verification complete';
    description = escapeHtml(
      params.message ?? 'Your email is verified and your workspace is ready.',
    );
    actions = `
      <a href="/login" class="inline-flex w-full items-center justify-center rounded-xl bg-primary px-4 py-3 text-sm font-semibold text-primary-foreground shadow-lg shadow-primary/25 transition-all hover:bg-primary/90">Back to sign in</a>
      <a href="/signup" class="inline-flex w-full items-center justify-center rounded-xl border border-surface-200 px-4 py-3 text-sm font-semibold text-foreground transition-all hover:bg-surface-50">Create another account</a>
    `;
  } else if (!params.token) {
    noticeLabel = 'Verification failed';
    heading = 'Verification link unavailable';
    description = 'This verification link is invalid or has expired.';
    actions = `
      <a href="/signup" class="inline-flex w-full items-center justify-center rounded-xl bg-primary px-4 py-3 text-sm font-semibold text-primary-foreground shadow-lg shadow-primary/25 transition-all hover:bg-primary/90">Create a new account</a>
      <a href="/login" class="inline-flex w-full items-center justify-center rounded-xl border border-surface-200 px-4 py-3 text-sm font-semibold text-foreground transition-all hover:bg-surface-50">Back to sign in</a>
    `;
  }

  const script = params.status === 'success' || !params.token
    ? ''
    : `<script>
document.addEventListener('DOMContentLoaded', () => {
  const button = document.getElementById('complete-verification');
  if (!button) {
    return;
  }

  button.addEventListener('click', async () => {
    button.setAttribute('aria-busy', 'true');
    const response = await fetch('/api/auth/verify-email', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        token: ${JSON.stringify(params.token)},
        email: ${JSON.stringify(params.email ?? '')}
      }),
    });
    const payload = await response.json();
    const nextUrl = new URL('/verify-email', window.location.origin);
    nextUrl.searchParams.set('status', response.ok ? 'success' : 'error');
    nextUrl.searchParams.set('email', ${JSON.stringify(params.email ?? '')});
    nextUrl.searchParams.set('message', payload.message || payload.error?.message || 'Verification failed.');
    window.location.assign(nextUrl.toString());
  });
});
</script>`;

  return `<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width,initial-scale=1" />
    <title>ApexMail</title>
    <link rel="stylesheet" href="/assets/globals.css" />
  </head>
  <body class="font-apex antialiased text-[16px] leading-[1.55]">
    <main class="min-h-screen bg-background">
      <div class="min-h-screen bg-surface-50 relative overflow-hidden">
        <div class="relative mx-auto flex min-h-screen w-full max-w-3xl items-center justify-center px-6 py-12">
          <div class="w-full max-w-xl">
            <div class="bg-card rounded-3xl shadow-[0_24px_60px_rgba(15,23,42,0.15)] border border-surface-200/70 overflow-hidden">
              <div class="p-8 space-y-5" data-auth-state="verify-email">
                <div class="space-y-2 text-center">
                  <p class="text-sm font-semibold uppercase tracking-[0.2em] text-primary">${noticeLabel}</p>
                  <h1 class="text-2xl font-bold tracking-tight text-foreground">${heading}</h1>
                  <p class="text-sm text-muted-foreground">${description}</p>
                  <p class="text-xs text-muted-foreground">Verification target: <strong>${email}</strong></p>
                </div>
                <div class="space-y-3">
                  ${actions}
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </main>
    ${script}
  </body>
</html>`;
}

test('registration flows into browser verification and returns to sign-in', async ({ page }) => {
  const authCss = loadAuthContractCss();
  const pending: PendingVerification = {
    name: '',
    email: '',
    token: '',
    registerRequests: 0,
    verifyRequests: 0,
    verified: false,
  };

  await page.route('**/*', async (route) => {
    const request = route.request();
    const url = new URL(request.url());

    if (url.origin !== TEST_ORIGIN) {
      await route.abort();
      return;
    }

    if (request.method() === 'GET' && url.pathname === '/assets/globals.css') {
      await route.fulfill({
        status: 200,
        contentType: 'text/css',
        body: authCss,
      });
      return;
    }

    if (request.method() === 'GET' && (url.pathname === '/signup' || url.pathname === '/register')) {
      await route.fulfill({
        status: 200,
        contentType: 'text/html; charset=utf-8',
        body: withSignupHarness(buildLegacySignupHtml()),
      });
      return;
    }

    if (request.method() === 'GET' && url.pathname === '/login') {
      await route.fulfill({
        status: 200,
        contentType: 'text/html; charset=utf-8',
        body: buildLegacyLoginHtml(),
      });
      return;
    }

    if (request.method() === 'GET' && url.pathname === '/verify-email') {
      await route.fulfill({
        status: 200,
        contentType: 'text/html; charset=utf-8',
        body: buildVerifyEmailHtml({
          email: url.searchParams.get('email') ?? undefined,
          token: url.searchParams.get('token') ?? undefined,
          status: url.searchParams.get('status') ?? undefined,
          message: url.searchParams.get('message') ?? undefined,
        }),
      });
      return;
    }

    if (request.method() === 'POST' && url.pathname === '/api/auth/register') {
      pending.registerRequests += 1;
      const payload = JSON.parse(request.postData() ?? '{}') as {
        name?: string;
        email?: string;
        password?: string;
      };
      pending.name = payload.name ?? '';
      pending.email = payload.email ?? '';
      pending.token = 'tok_registration_flow';

      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          message: 'Check your email for a verification link.',
        }),
      });
      return;
    }

    if (request.method() === 'GET' && url.pathname === '/api/auth/verification-email-preview') {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          verificationUrl: `${TEST_ORIGIN}/verify-email?token=${encodeURIComponent(pending.token)}&email=${encodeURIComponent(pending.email)}`,
        }),
      });
      return;
    }

    if (request.method() === 'POST' && url.pathname === '/api/auth/verify-email') {
      pending.verifyRequests += 1;
      const payload = JSON.parse(request.postData() ?? '{}') as {
        token?: string;
        email?: string;
      };
      const valid = payload.token === pending.token && payload.email === pending.email;
      pending.verified = valid;

      await route.fulfill({
        status: valid ? 200 : 400,
        contentType: 'application/json',
        body: JSON.stringify(
          valid
            ? { message: 'Your email is verified and your workspace is ready.' }
            : { error: { message: 'This verification link is invalid or has expired.' } },
        ),
      });
      return;
    }

    await route.fulfill({
      status: 404,
      contentType: 'text/plain; charset=utf-8',
      body: 'not found',
    });
  });

  await page.goto(`${TEST_ORIGIN}/signup`);

  await expect(page.getByRole('heading', { name: 'Create your account' })).toBeVisible();
  await page.getByLabel('Full name').fill('Jane Doe');
  await page.getByLabel('Email').fill('jane@example.com');
  await page.getByLabel('Password').fill('StrongPass123!');
  await page.getByRole('button', { name: 'Create Account' }).click();

  await expect(page.getByRole('heading', { name: 'Check your email' })).toBeVisible();
  await expect(page.getByText('jane@example.com')).toBeVisible();

  await page.getByRole('link', { name: 'Open verification link' }).click();

  await expect(page).toHaveURL(/\/verify-email\?token=tok_registration_flow/);
  await expect(page.getByRole('heading', { name: 'Verify your email' })).toBeVisible();
  await expect(page.getByText('Verification ready')).toBeVisible();

  await page.getByRole('button', { name: 'Complete verification' }).click();

  await expect(page.getByRole('heading', { name: 'Verification complete' })).toBeVisible();
  await expect(page.getByText('Your email is verified and your workspace is ready.')).toBeVisible();
  await page.getByRole('link', { name: 'Back to sign in' }).click();

  await expect(page).toHaveURL(`${TEST_ORIGIN}/login`);
  await expect(page.getByRole('heading', { name: 'Welcome back' })).toBeVisible();

  expect(pending.registerRequests).toBe(1);
  expect(pending.verifyRequests).toBe(1);
  expect(pending.name).toBe('Jane Doe');
  expect(pending.email).toBe('jane@example.com');
  expect(pending.verified).toBe(true);
});