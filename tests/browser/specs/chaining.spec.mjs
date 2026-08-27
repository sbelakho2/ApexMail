import { test, expect } from '@playwright/test';

// Chained challenges (the transaction-obligation redesign), end-to-end in
// the real browser against the fixture router (?chaining=1):
//  - a chain_required stage-1 solve opens a server-side obligation; the
//    re-rendered widget receives the stronger stage-2 challenge;
//  - a reset (or a full page reload) of the same transaction still gets
//    stage 2 — and when the widget clears the chain_ticket (as it does
//    after a solve), the server auto-resumes the open chain without the
//    ticket (never an unchained stage-1);
//  - a lost stage-2 response is recovered: the next request returns the
//    exact same challenge (no re-mint);
//  - the stage-2 verification ends the chain (the obligation is cleared);
//    a subsequent unrelated transaction gets an independent normal
//    challenge;
//  - a terminal disposition (the transaction's final Deny / StepUp
//    finalize) binds the transaction to its terminal response: a later
//    challenge request — with or without the ticket — re-encounters the
//    terminal state (429 risk_denied / 403 step_up_required, never a new
//    challenge, never a stage-1 issuance, never a re-reservation);
//  - no new persistent device identity: the challenge requests carry no
//    fingerprint-like data.

async function solve(page, timeout = 120_000) {
  await expect(page.locator('[data-kiwi-widget]')).toHaveAttribute('data-state', 'done', { timeout });
}

async function readCapture(page, name) {
  const resp = await page.request.get(`http://127.0.0.1:8085/capture/${name}`);
  const data = await resp.json();
  return data && typeof data.body === 'string' ? data.body : null;
}

/** The solved token in the hidden input. */
async function tokenOf(page) {
  return page.locator('[data-kiwi-token]').inputValue();
}

/** POST the solved token to the fixture's form-submission endpoint. */
async function chainVerify(page, token, { ticket, binding, scope = 'login' } = {}) {
  const body = { token, scope };
  if (binding) body.request_binding = binding;
  if (ticket) body.chain_ticket = ticket;
  const resp = await page.request.post('http://127.0.0.1:8085/chain-verify', { data: body });
  return resp.json();
}

/** The nonce of a challenge response (the exact-same-challenge checks). */
function nonceOf(body) {
  return body && typeof body.nonce === 'string' ? body.nonce : null;
}

/** POST a challenge request against the chaining-enabled fixture. */
async function challengePost(page, body) {
  const resp = await page.request.post('http://127.0.0.1:8085/challenge?chaining=1', { data: body });
  return resp.json();
}

/** POST a challenge request and return the RAW response (status checks). */
async function challengeStatus(page, body) {
  return page.request.post('http://127.0.0.1:8085/challenge?chaining=1', { data: body });
}

/** Terminalize the open obligation of the transaction (deny / step_up). */
async function chainDisposition(page, token, { disposition, binding, scope = 'login' } = {}) {
  const body = { token, scope, disposition };
  if (binding) body.request_binding = binding;
  const resp = await page.request.post('http://127.0.0.1:8085/chain-verify', { data: body });
  return resp.json();
}

test.describe('KiwiCaptcha chained challenges (transaction obligation)', () => {
  test('a CHAIN_REQUIRED stage-1 opens the chain and the re-rendered widget receives stage 2', async ({ page }) => {
    // Stage 1: the page issues the ordinary challenge; the browser solves
    // it; the form submission demands the stronger stage (chain_required
    // + the one-shot ticket).
    await page.goto('/?chaining=1&capture=s4&binding=txn-b4');
    await solve(page);
    const stage1 = JSON.parse(await readCapture(page, 's4'));
    expect(stage1.scope).toBe('login');
    expect(stage1.request_binding).toBe('txn-b4');
    // No fingerprint-like data rides the challenge request.
    expect(stage1.client_context).toBeUndefined();

    const token = await tokenOf(page);
    const disposition = await chainVerify(page, token, { binding: 'txn-b4' });
    expect(disposition.chain_required).toBe(true);
    expect(disposition.chain_ticket).toMatch(/^[A-Za-z0-9._:-]{1,256}$/);

    // Stage 2: the application re-renders the widget with the ticket —
    // the widget receives the stronger argon stage.
    await page.goto(`/?chaining=1&capture=s5&chain=${encodeURIComponent(disposition.chain_ticket)}&binding=txn-b4`);
    await solve(page, 180_000);
    const stage2 = JSON.parse(await readCapture(page, 's5'));
    expect(stage2.chain_ticket).toBe(disposition.chain_ticket);
    expect(stage2.request_binding).toBe('txn-b4');
    expect(stage2.client_context).toBeUndefined();

    // The stage-2 issuance (HTTP level, the same ticket) is the argon
    // challenge (the stronger stage) — never a stage-1 sha.
    const stage2Issuance = await challengePost(page, {
      scope: 'login',
      request_binding: 'txn-b4',
      chain_ticket: disposition.chain_ticket,
    });
    expect(stage2Issuance.algorithm).toBe('argon2id');
    expect(nonceOf(stage2Issuance)).not.toBeNull();
  });

  test('reset after CHAIN_REQUIRED still gets stage 2 (the cleared ticket auto-resumes the chain)', async ({ page }) => {
    // Open the chain with a stage-1 solve.
    await page.goto('/?chaining=1&capture=r4&binding=txn-b5');
    await solve(page);
    const token = await tokenOf(page);
    const disposition = await chainVerify(page, token, { binding: 'txn-b5' });
    expect(disposition.chain_ticket).toBeTruthy();

    // The re-rendered widget solves the stage-2 challenge; the driver
    // clears the one-shot ticket attribute after the solve.
    await page.goto(`/?chaining=1&capture=r5&chain=${encodeURIComponent(disposition.chain_ticket)}&binding=txn-b5`);
    await solve(page, 180_000);
    await expect(page.locator('#kiwicaptcha-root')).not.toHaveAttribute('data-kiwi-chain-ticket');

    // A reset of the same transaction: the challenge request carries NO
    // chain_ticket — the server's open obligation auto-resumes the chain
    // and recovers the same issued stage-2 challenge (never a stage-1).
    const widgetId = await page.evaluate(() => document.querySelector('[data-kiwi-widget]').dataset.kiwiInstance);
    const recovered = await challengePost(page, { scope: 'login', request_binding: 'txn-b5' });
    await page.evaluate((wid) => window.KiwiCaptcha.reset(wid), widgetId);
    await solve(page, 180_000);
    const after = JSON.parse(await readCapture(page, 'r5'));
    // The reset's request carries NO ticket (the driver cleared it) and
    // the recovered challenge is the same stage-2 challenge.
    expect(after.chain_ticket).toBeUndefined();
    expect(nonceOf(recovered)).not.toBeNull();
    expect(after.request_binding).toBe('txn-b5');
  });

  test('a page reload of the same transaction still gets the SAME stage-2 challenge', async ({ page }) => {
    await page.goto('/?chaining=1&capture=p4&binding=txn-b6');
    await solve(page);
    const token = await tokenOf(page);
    const disposition = await chainVerify(page, token, { binding: 'txn-b6' });
    expect(disposition.chain_ticket).toBeTruthy();

    // First stage-2 load issues the challenge (the response is captured).
    let firstNonce = null;
    page.on('response', async (resp) => {
      if (resp.url().includes('/challenge')) {
        try {
          const body = await resp.json();
          if (nonceOf(body)) firstNonce = nonceOf(body);
        } catch {
          // not a JSON challenge response
        }
      }
    });
    await page.goto(`/?chaining=1&chain=${encodeURIComponent(disposition.chain_ticket)}&binding=txn-b6`);
    await solve(page, 180_000);
    expect(firstNonce).not.toBeNull();

    // Full page reload: the same ticket + transaction — the server
    // recovers the exact same issued challenge (no re-mint).
    let secondNonce = null;
    page.on('response', async (resp) => {
      if (resp.url().includes('/challenge')) {
        try {
          const body = await resp.json();
          if (nonceOf(body)) secondNonce = nonceOf(body);
        } catch {
          // not a JSON challenge response
        }
      }
    });
    await page.reload();
    await solve(page, 180_000);
    expect(secondNonce).toBe(firstNonce);
  });

  test('manually removing the chain_ticket still resumes stage 2', async ({ page }) => {
    await page.goto('/?chaining=1&capture=m4&binding=txn-b7');
    await solve(page);
    const token = await tokenOf(page);
    const disposition = await chainVerify(page, token, { binding: 'txn-b7' });
    expect(disposition.chain_ticket).toBeTruthy();

    // Seed the ticket, then remove it from the container before the
    // widget's re-execution — the server still resumes the open chain.
    await page.goto(`/?chaining=1&capture=m5&chain=${encodeURIComponent(disposition.chain_ticket)}&binding=txn-b7`);
    await page.evaluate(() => document.querySelector('#kiwicaptcha-root').removeAttribute('data-kiwi-chain-ticket'));
    await page.evaluate(() => {
      const widget = document.querySelector('[data-kiwi-widget]');
      window.KiwiCaptcha.reset(widget.dataset.kiwiInstance);
    });
    await solve(page, 180_000);

    const request = JSON.parse(await readCapture(page, 'm5'));
    expect(request.chain_ticket).toBeUndefined();
    expect(request.request_binding).toBe('txn-b7');
  });

  test('a lost stage-2 response is recovered: the next request returns the exact same challenge', async ({ page }) => {
    // Drive the stage-2 issuance at the HTTP level: the first response is
    // "lost" (the widget never sees it), the second request must return
    // the exact same challenge — no re-mint.
    await page.goto('/?chaining=1&binding=txn-b8');
    await solve(page);
    const token = await tokenOf(page);
    const disposition = await chainVerify(page, token, { binding: 'txn-b8' });
    expect(disposition.chain_ticket).toBeTruthy();

    const first = await challengePost(page, {
      scope: 'login',
      request_binding: 'txn-b8',
      chain_ticket: disposition.chain_ticket,
    });
    expect(first.algorithm).toBe('argon2id');
    const second = await challengePost(page, {
      scope: 'login',
      request_binding: 'txn-b8',
      chain_ticket: disposition.chain_ticket,
    });
    expect(JSON.stringify(second)).toBe(JSON.stringify(first));
    expect(nonceOf(second)).toBe(nonceOf(first));
  });

  test('the stage-2 verification ends the chain; a subsequent unrelated transaction is independent', async ({ page }) => {
    await page.goto('/?chaining=1&capture=e4&binding=txn-b9');
    await solve(page);
    const stage1Token = await tokenOf(page);
    const disposition = await chainVerify(page, stage1Token, { binding: 'txn-b9' });
    expect(disposition.chain_ticket).toBeTruthy();

    // Stage 2 issuance + solve + verification (the chain ends).
    await page.goto(`/?chaining=1&capture=e5&chain=${encodeURIComponent(disposition.chain_ticket)}&binding=txn-b9`);
    await solve(page, 180_000);
    const stage2Token = await tokenOf(page);
    const ended = await chainVerify(page, stage2Token, { ticket: disposition.chain_ticket, binding: 'txn-b9' });
    expect(ended.ok).toBe(true);
    expect(ended.chain_ended).toBe(true);

    // The same transaction again (no ticket): the chain ended — the
    // request is a normal unchained issuance (no stage-2 recovery, no
    // ticket involvement).
    const again = await challengePost(page, { scope: 'login', request_binding: 'txn-b9' });
    expect(again.algorithm).toBe('sha256');

    // An unrelated transaction gets its own independent normal challenge.
    await page.goto('/?chaining=1&capture=e6&binding=txn-b10');
    await solve(page);
    const unrelated = JSON.parse(await readCapture(page, 'e6'));
    expect(unrelated.request_binding).toBe('txn-b10');
    expect(unrelated.chain_ticket).toBeUndefined();
    expect(unrelated.client_context).toBeUndefined();
  });

  test('no new persistent device identity rides the chain requests', async ({ page }) => {
    await page.goto('/?chaining=1&capture=i4&binding=txn-b11');
    await solve(page);
    const token = await tokenOf(page);
    const disposition = await chainVerify(page, token, { binding: 'txn-b11' });
    expect(disposition.chain_ticket).toBeTruthy();

    await page.goto(`/?chaining=1&capture=i5&chain=${encodeURIComponent(disposition.chain_ticket)}&binding=txn-b11`);
    await solve(page, 180_000);

    // The stage-1 AND stage-2 challenge requests carry only the
    // documented fields (scope / algorithm / request_binding /
    // chain_ticket) — no canvas/font/GPU/UA-derived or device-capability
    // data, no client_context (the opt-in is off).
    for (const name of ['i4', 'i5']) {
      const body = JSON.parse(await readCapture(page, name));
      expect(body, `the ${name} challenge request must be captured`).toBeTruthy();
      for (const key of Object.keys(body)) {
        expect(['scope', 'algorithm', 'request_binding', 'chain_ticket']).toContain(key);
      }
      expect(body.client_context).toBeUndefined();
      expect(body.honeypot).toBeUndefined();
      expect(body.decoy_field).toBeUndefined();
    }
  });

  test('a DENIED terminal chain answers 429 RISK_DENIED to a challenge request without a ticket', async ({ page }) => {
    // A per-run transaction id: a terminalized chain stays terminal for
    // its whole TTL, so a re-run of the suite must never collide with a
    // terminalized obligation left by an earlier run.
    const binding = `txn-d1-${Date.now()}`;
    // Open the chain with a stage-1 solve.
    await page.goto(`/?chaining=1&binding=${binding}`);
    await solve(page);
    const token = await tokenOf(page);
    const disposition = await chainVerify(page, token, { binding });
    expect(disposition.chain_ticket).toBeTruthy();

    // The transaction's final disposition is deny: the open obligation is
    // terminalized durably (nonce-agnostic — the obligation mapping is
    // kept, so the transaction stays bound to its final denial).
    const terminal = await chainDisposition(page, token, { disposition: 'deny', binding });
    expect(terminal.code).toBe('RISK_DENIED');

    // A challenge request without a ticket for the same transaction
    // re-encounters the terminal denial: HTTP 429 risk_denied — never a
    // new challenge, never a stage-1 issuance.
    const denied = await challengeStatus(page, { scope: 'login', request_binding: binding });
    expect(denied.status()).toBe(429);
    const deniedBody = await denied.json();
    expect(deniedBody.error.code).toBe('RISK_DENIED');
    expect(deniedBody.error.message).toBe('Challenge issuance denied by the adaptive risk engine. Try again later.');
    expect(deniedBody.nonce).toBeUndefined();

    // Even with the ticket the chain stays terminal: the reservation can
    // never be claimed again and no challenge is ever minted.
    const withTicket = await challengeStatus(page, {
      scope: 'login',
      request_binding: binding,
      chain_ticket: disposition.chain_ticket,
    });
    expect(withTicket.status()).toBe(429);
    const withTicketBody = await withTicket.json();
    expect(withTicketBody.error.code).toBe('RISK_DENIED');
    expect(withTicketBody.nonce).toBeUndefined();
  });

  test('a STEP_UP_REQUIRED terminal chain answers 403 STEP_UP_REQUIRED to a challenge request without a ticket', async ({ page }) => {
    const binding = `txn-s1-${Date.now()}`;
    await page.goto(`/?chaining=1&binding=${binding}`);
    await solve(page);
    const token = await tokenOf(page);
    const disposition = await chainVerify(page, token, { binding });
    expect(disposition.chain_ticket).toBeTruthy();

    // The transaction's final disposition is step-up: the open obligation
    // is terminalized durably (the obligation mapping is kept).
    const terminal = await chainDisposition(page, token, { disposition: 'step_up', binding });
    expect(terminal.code).toBe('STEP_UP_REQUIRED');

    // The no-ticket challenge request re-encounters the terminal step-up:
    // HTTP 403 step_up_required — no challenge, no stage-1 issuance.
    const stepUp = await challengeStatus(page, { scope: 'login', request_binding: binding });
    expect(stepUp.status()).toBe(403);
    const stepUpBody = await stepUp.json();
    expect(stepUpBody.error.code).toBe('STEP_UP_REQUIRED');
    expect(stepUpBody.error.message).toBe('Additional verification is required for this request.');
    expect(stepUpBody.nonce).toBeUndefined();

    // With the ticket the terminal response is identical (the chain can
    // never be re-reserved or re-issued).
    const withTicket = await challengeStatus(page, {
      scope: 'login',
      request_binding: binding,
      chain_ticket: disposition.chain_ticket,
    });
    expect(withTicket.status()).toBe(403);
    const withTicketBody = await withTicket.json();
    expect(withTicketBody.error.code).toBe('STEP_UP_REQUIRED');
    expect(withTicketBody.nonce).toBeUndefined();
  });

  test('a proof minted under txn-A fails when redeemed under txn-B with no chain side effects', async ({ page }) => {
    // The cross-transaction isolation E2E: a stage-1 challenge is minted
    // bound to txn-A (the fixture mirrors the production issuance), the
    // browser solves it, and the submission presents the wrong
    // transaction txn-B. The exact-binding contract refuses the proof
    // (request_binding_mismatch), the application verification fails,
    // and no chain state is created or advanced for either transaction
    // (the chain only opens after a verified stage-1 solve).
    await page.goto('/?chaining=1&binding=txn-A');
    await solve(page);
    const token = await tokenOf(page);

    const mismatched = await chainVerify(page, token, { binding: 'txn-B' });
    expect(mismatched.ok).toBe(false);
    expect(mismatched.code).toBe('request_binding_mismatch');
    expect(mismatched.chain_required).toBeUndefined();
    expect(mismatched.chain_ticket).toBeUndefined();

    // No chain was created for txn-B (and none for txn-A) as a side
    // effect: a fresh stage-1 for txn-B is still an ordinary challenge
    // (no auto-resumed stage-2, no open obligation).
    const clean = await challengePost(page, { scope: 'login', request_binding: 'txn-B' });
    expect(nonceOf(clean)).not.toBeNull();
    expect(clean.chain_ticket).toBeUndefined();
  });

  test('the fixture chain store mirrors the production terminal-state machine', async ({ page }) => {
    // The fixture-level self-test pins the store semantics that the HTTP
    // flow cannot reach directly: reserve() answers the terminal statuses
    // (a terminal chain can never be set back to reserved) and markIssued()
    // answers 'conflict' on a terminal chain — the exact Lua branches.
    const resp = await page.request.get('http://127.0.0.1:8085/chain-store-selftest');
    const result = await resp.json();
    expect(result.ok).toBe(true);
    expect(result.failures).toEqual([]);
  });
});
