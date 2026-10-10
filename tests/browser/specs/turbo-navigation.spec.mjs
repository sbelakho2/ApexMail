import { test, expect } from '@playwright/test';

// The idempotency guard must not break Turbo/htmx navigation. In files
// mode the driver script is emitted once per rendered page, but Turbo
// re-executes body scripts on every navigation, and htmx processes
// swapped subtrees. The first copy owns the API/bridge; every later
// copy must rescan the (new) DOM through the bridge instead of
// returning silently, or a widget reached via navigation never starts
// and the form submits an empty token.

async function driverSrc(page) {
  return page.evaluate(() => {
    const script = [...document.querySelectorAll('script[src]')].find((el) => el.src.includes('/driver.'));
    return script ? script.src : null;
  });
}

// The reuse counter lives on a Symbol key (a string-named window property
// is DOM-clobberable and must never carry the boot state). Read it
// through the same Symbol.for key the driver installs.
async function driverReuseCount(page) {
  return page.evaluate(() => window[Symbol.for('kiwicaptcha.driver-reused')] || 0);
}

// A Turbo/htmx navigation replaces the container with the server's
// rendered markup (endpoint/runtime/module attributes AND the widget
// skeleton: status, hint, token input). Clone the live container's
// markup and strip only the per-instance initialization markers, which
// is exactly what the server re-render produces on the next page.
async function freshContainerMarkup(page, containerId) {
  await page.evaluate((id) => {
    const origin = document.querySelector('.kiwi-container');
    const clone = origin.cloneNode(true);
    clone.id = id;
    clone.querySelectorAll('[data-kiwi-instance]').forEach((el) => el.removeAttribute('data-kiwi-instance'));
    const widget = clone.querySelector('[data-kiwi-widget]');
    widget.removeAttribute('data-kiwi-started');
    // The server re-render ships an idle widget with no token: strip the
    // cloned finish state so the assertions can only pass if this
    // generation actually initialized and solved.
    widget.removeAttribute('data-state');
    for (const input of clone.querySelectorAll('[data-kiwi-token]')) input.value = '';
    document.body.appendChild(clone);
  }, containerId);
}

test.describe('driver reuse under Turbo/htmx navigation', () => {
  test('a Turbo navigation re-executes the driver and the newly parsed widget starts', async ({ page }) => {
    const pageErrors = [];
    page.on('pageerror', (e) => pageErrors.push(String(e)));
    await page.goto('/?assets=files&bits=4');
    await expect(page.locator('#kiwicaptcha-root [data-kiwi-widget]')).toHaveAttribute('data-state', 'done', { timeout: 120_000 });
    expect(await page.evaluate(() => typeof window.__kiwiCaptchaCore.core.scan)).toBe('function');

    // Turbo replaces the body and re-executes its scripts: a new widget
    // appears, then the driver copy runs again.
    await freshContainerMarkup(page, 'kiwicaptcha-turbo');
    const src = await driverSrc(page);
    expect(src, 'the files-mode page must emit a driver script src').toBeTruthy();
    await page.addScriptTag({ url: src });

    await expect(page.locator('#kiwicaptcha-turbo [data-kiwi-widget]')).toHaveAttribute('data-state', 'done', { timeout: 120_000 });
    const token = await page.locator('#kiwicaptcha-turbo [data-kiwi-token]').inputValue();
    expect(token.length, 'the navigated widget must write a real token, never submit empty').toBeGreaterThan(0);
    expect(await driverReuseCount(page), 'the guard must have taken the reuse branch').toBe(1);
    // The original widget is untouched and still verified.
    expect(await page.locator('#kiwicaptcha-root [data-kiwi-widget]').getAttribute('data-state')).toBe('done');
    expect(pageErrors).toEqual([]);
  });

  test('an htmx body swap re-runs the driver and initializes the swapped widget', async ({ page }) => {
    await page.goto('/?assets=files&bits=4');
    await expect(page.locator('#kiwicaptcha-root [data-kiwi-widget]')).toHaveAttribute('data-state', 'done', { timeout: 120_000 });

    // htmx swaps the subtree's markup, then processes scripts inside it.
    await page.evaluate(() => {
      const container = document.querySelector('.kiwi-container');
      const replacement = container.cloneNode(true);
      replacement.id = 'kiwicaptcha-htmx';
      replacement.querySelectorAll('[data-kiwi-instance]').forEach((el) => el.removeAttribute('data-kiwi-instance'));
      const widget = replacement.querySelector('[data-kiwi-widget]');
      widget.removeAttribute('data-kiwi-started');
      widget.removeAttribute('data-state');
      for (const input of replacement.querySelectorAll('[data-kiwi-token]')) input.value = '';
      container.replaceWith(replacement);
    });
    const src = await driverSrc(page);
    await page.addScriptTag({ url: src });

    await expect(page.locator('#kiwicaptcha-htmx [data-kiwi-widget]')).toHaveAttribute('data-state', 'done', { timeout: 120_000 });
    const token = await page.locator('#kiwicaptcha-htmx [data-kiwi-token]').inputValue();
    expect(token.length).toBeGreaterThan(0);
    expect(await driverReuseCount(page)).toBe(1);
  });

  // A navigation that lands while a solve is still in flight is the
  // dangerous half of the reuse path: the removed widget's registry
  // record outlives its element, so without the scan's dead-record
  // pre-pass the cancelled generation would keep running against the
  // detached node (its late fetch response could paint a token no form
  // would ever read) and the record would keep counting as a live
  // widget forever. The first widget's challenge fetch is held on a
  // route gate, so the mid-flight moment is deterministic, not
  // sleep-based.
  test('a mid-flight Turbo navigation cancels the removed widget and its dead record never lingers', async ({ page }) => {
    const pageErrors = [];
    page.on('pageerror', (e) => pageErrors.push(String(e)));

    let calls = 0;
    let release;
    const gate = new Promise((r) => { release = r; });
    // The files-mode fixture page carries the difficulty knob on the
    // endpoint itself (/challenge?bits=4), so the route matches on the
    // path-plus-query form (a bare **/challenge glob would miss it and
    // the fast bits=4 solve would finish before the navigation).
    await page.route(/\/challenge\?/, async (route) => {
      calls++;
      if (calls === 1) {
        // Hold the first widget's challenge until the navigation has
        // happened; fulfilling into an already-aborted request is a
        // no-op wrapped in the same try/catch shape the BFCache spec
        // uses.
        await gate;
        try {
          await route.fulfill({ status: 503, contentType: 'application/json', body: '{"error":"late"}' });
        } catch (e) {}
        return;
      }
      await route.continue();
    });

    await page.goto('/?assets=files&bits=4');
    await page.waitForFunction(
      () => document.querySelector('[data-kiwi-widget]').getAttribute('data-state') === 'connecting',
      null,
      { timeout: 30_000 },
    );

    // The removed widget's spies, installed while it is still in the
    // document: a listener on its own container catches every kiwi:*
    // event the driver dispatches on the widget (the events bubble
    // through the detached subtree too), and the kept element reference
    // observes state/token writes after the removal.
    await page.evaluate(() => {
      const container = document.querySelector('.kiwi-container');
      window.__kiwiDeadSpy = {
        verified: 0,
        error: 0,
        widget: container.querySelector('[data-kiwi-widget]'),
        token: container.querySelector('[data-kiwi-token]'),
      };
      container.addEventListener('kiwi:verified', () => { window.__kiwiDeadSpy.verified++; });
      container.addEventListener('kiwi:error', () => { window.__kiwiDeadSpy.error++; });
    });

    // The Turbo navigation proper: the replacement container is
    // rendered, the first page's DOM is swapped OUT (the removal is the
    // point — a body swap never calls destroy()), and the re-executed
    // driver copy rescans.
    await freshContainerMarkup(page, 'kiwicaptcha-turbo');
    await page.evaluate(() => {
      document.querySelectorAll('.kiwi-container').forEach((c) => {
        if (c.id !== 'kiwicaptcha-turbo') c.remove();
      });
    });
    const src = await driverSrc(page);
    expect(src, 'the files-mode page must emit a driver script src').toBeTruthy();
    await page.addScriptTag({ url: src });
    await page.waitForFunction(() => window[Symbol.for('kiwicaptcha.driver-reused')] === 1, null, { timeout: 30_000 });

    // The scan's pre-pass cancelled and deleted the dead record before
    // initializing the new widget, so the registry count equals the
    // live widget count exactly — never one dead record more.
    const liveCount = await page.evaluate(() => document.querySelectorAll('[data-kiwi-widget]').length);
    const countsAfterScan = await page.evaluate(() => window.__kiwiCaptchaCore.core.counts().widgets);
    expect(countsAfterScan, 'the dead record must be deleted by the scan, not lingering').toBe(liveCount);
    expect(liveCount).toBe(1);

    // Release the held fetch: the cancelled generation must settle
    // silently while the navigated widget solves normally.
    release();
    await expect(page.locator('#kiwicaptcha-turbo [data-kiwi-widget]')).toHaveAttribute('data-state', 'done', { timeout: 120_000 });
    const token = await page.locator('#kiwicaptcha-turbo [data-kiwi-token]').inputValue();
    expect(token.length, 'the navigated widget must write a real token').toBeGreaterThan(0);

    const after = await page.evaluate(() => ({
      verified: window.__kiwiDeadSpy.verified,
      error: window.__kiwiDeadSpy.error,
      state: window.__kiwiDeadSpy.widget.getAttribute('data-state'),
      token: window.__kiwiDeadSpy.token.value,
      widgets: window.__kiwiCaptchaCore.core.counts().widgets,
      connected: window.__kiwiDeadSpy.widget.isConnected,
    }));
    expect(after.connected, 'the spy target is the removed widget').toBe(false);
    expect(after.verified, 'no token callback event may fire for the removed widget').toBe(0);
    expect(after.error).toBe(0);
    expect(after.state, 'the removed widget must never reach done').not.toBe('done');
    expect(after.token, 'the removed widget must never receive a token').toBe('');
    expect(after.widgets, 'the dead record stays deleted after the settle').toBe(1);
    expect(pageErrors).toEqual([]);
  });
});
