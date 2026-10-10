import { test, expect } from '@playwright/test';

// ── The post-destroy progress-write race ──────────
// The SHA-256 solver runs on the main thread in time-budgeted chunks and
// reports each chunk through the driver's setProgress() callback, which
// writes the widget's data-progress attribute (the fill bar). The chunk
// loop itself carries NO generation guard: once a solve has started, the
// loop keeps yielding and reporting until it finds a proof, hits the
// hash cap or passes the challenge deadline. destroy() marks the widget
// (data-kiwi-destroyed), cancels the generation record, tears the
// listeners/timers down and clears the token — but a solve already in
// flight keeps running to completion in the background and keeps calling
// setProgress() for every chunk after the destroy. The race is a
// race on CI where those queued progress writes landed on a destroyed —
// but still in-DOM — widget. The invariant: setProgress() no-ops when the
// widget is destroyed, the same dataset flag destroy sets first, so a
// stale solve can never paint progress into a dead widget.
//
// This spec pins that invariant with a deterministic reproduction of the race,
// not a broad lifecycle sweep. The deterministic core is an event-loop
// ordering argument, not a timing bet:
//
//   1. The fixture issues a SHA-256 challenge at the max ceiling
//      (?bits=20). Inline-mode wasm chunks scan the search space in
//      ~10 ms slices, and every chunk that does NOT find the proof emits
//      one progress callback with a distinct non-100 value — measured
//      across all three engines as 45-55 ticks over roughly half a
//      second. A plain bits=8 challenge solves inside the first chunk,
//      so the ceiling makes progress writes observable at all.
//   2. A MutationObserver on the fill bar destroys the widget (via
//      window.KiwiCaptcha.destroy) synchronously from the observer
//      callback the moment the first mid-solve tick (a value other than
//      100, while data-state="solving") is observed. Because the
//      observer callback runs in the microtask checkpoint right after
//      the chunk that produced the tick, and the next chunk only runs as
//      a later macrotask, the destroy is guaranteed to land while the
//      solve is still in flight and before any further progress write:
//      a data-progress tick exists only when the chunk that emitted it
//      did NOT find the proof, so at least one more chunk is queued
//      behind the destroy. If the widget instead reached done before the
//      observer ever saw a mid-solve tick (the ~1-2% of solves that end
//      inside the first chunk), the iteration is discarded and retried —
//      a discarded iteration proves nothing and never counts.
//   3. The post-destroy MutationObserver starts in the same microtask,
//      immediately after destroy() returns, so it can only ever see
//      stale writes. The test then lets the background solve run to
//      completion (≥2 s settle; the expected residual after the first
//      tick is well under a second and the run is capped by the 20M-hash
//      ceiling) and asserts that nothing mutated the widget since the
//      destroy: no data-progress write, no state/lang/label change, no
//      childList activity, no token, no kiwi:* event, no error.
//
// Each iteration is a full create → solve → destroy cycle on a fresh
// container cloned from the fixture's own rendered markup (so the spec
// tracks whatever widget markup the current tree renders — it never
// hard-codes the asset bytes). Iterations are fully cleaned up per
// cycle: observers disconnected, container removed from the DOM. The
// cycle count is parameterized (60 by default; the env knob
// KIWI_DESTROY_RACE_ITERATIONS overrides it) because one stale chunk
// write fails the whole test, while the conforming driver performs zero
// writes, so it passes 60/60 iterations on every run and a non-conforming
// driver fails the run with overwhelming probability (a mid-solve destroy has
// multiple queued chunks behind it, so a single iteration already
// catches the regression in ~97% of cases and 60 independent iterations
// make a clean miss practically impossible).

const ITERATIONS = Number.parseInt(process.env.KIWI_DESTROY_RACE_ITERATIONS || '60', 10);
const BATCH_SIZE = 10;
const MAX_ATTEMPTS = ITERATIONS + 40;

// The second closure case's cycle parameters (the describe block at the
// bottom of this file): 15 provable two-widget cycles by default, inside
// the agreed 10-20 band. The env knob KIWI_DESTROY_ALL_ITERATIONS
// overrides the count, and the widget count per cycle is fixed at two.
const MULTI_ITERATIONS = Number.parseInt(process.env.KIWI_DESTROY_ALL_ITERATIONS || '15', 10);
const MULTI_BATCH_SIZE = 5;
const MULTI_MAX_ATTEMPTS = MULTI_ITERATIONS + 40;
const MULTI_WIDGETS = 2;

test.describe('destroy mid-solve: no progress write, no state mutation, no event, no error after destruction', () => {
  test('the destroyed widget stays exactly as destroy left it while the background solve finishes', async ({ page }) => {
    test.setTimeout(480_000);

    const pageErrors = [];
    page.on('pageerror', (e) => pageErrors.push(String(e)));
    const consoleErrors = [];
    page.on('console', (msg) => {
      if (msg.type() === 'error') consoleErrors.push({ t: Date.now(), text: msg.text() });
    });
    const failedRequests = [];
    page.on('requestfailed', (req) => {
      failedRequests.push({ t: Date.now(), url: req.url(), method: req.method(), failure: req.failure() && req.failure().errorText });
    });

    // The fixture page at the max SHA-256 ceiling: every solve spans
    // many progress ticks (the driver writes data-progress only at
    // chunk boundaries, and the wasm/JS chunk loop reports every chunk).
    await page.goto('/?bits=20');
    await expect(page.locator('[data-kiwi-widget]')).toHaveCount(1);

    // ── Page-side harness ──────────────────────────────────────────
    // Template: a scrubbed deep clone of the fixture's own rendered
    // container, so the cycle always runs the current tree's markup.
    // The fixture's original widget is destroyed and removed right away
    // so its own auto-solve never pollutes the page. Error/event
    // collectors are global (installed before any iteration exists);
    // per-iteration assertions slice them by the destroy timestamp.
    await page.evaluate(() => {
      const source = document.querySelector('.kiwi-container');
      const widgetRoot = source.querySelector('[data-kiwi-widget]');
      const tpl = source.cloneNode(true);
      tpl.removeAttribute('id');
      for (const el of tpl.querySelectorAll('[data-kiwi-instance],[data-kiwi-started],[data-kiwi-destroyed]')) {
        el.removeAttribute('data-kiwi-instance');
        el.removeAttribute('data-kiwi-started');
        el.removeAttribute('data-kiwi-destroyed');
      }
      for (const el of tpl.querySelectorAll('[data-state]')) el.removeAttribute('data-state');
      for (const el of tpl.querySelectorAll('[data-kiwi-bar]')) el.removeAttribute('data-progress');
      const t0 = tpl.querySelector('[data-kiwi-token]');
      if (t0) t0.value = '';
      const c0 = tpl.querySelector('[data-kiwi-timer]');
      if (c0) c0.textContent = '';

      // Retire the fixture's own widget: destroy it (it is mid-init or
      // already solving by now) and remove the container.
      if (widgetRoot) {
        try { window.KiwiCaptcha.destroy(widgetRoot); } catch (e) {}
      }
      source.parentNode.removeChild(source);

      window.__kiwiRace = {
        tpl,
        seq: 0,
        errors: [],
        rejections: [],
        events: [],
      };
      window.addEventListener('error', (e) => {
        window.__kiwiRace.errors.push(String(e.error || e.message));
      });
      window.addEventListener('unhandledrejection', (e) => {
        window.__kiwiRace.rejections.push(String(e.reason));
      });
      for (const name of ['kiwi:ready', 'kiwi:verifying', 'kiwi:verified', 'kiwi:error', 'kiwi:expired', 'kiwi:worker-unavailable', 'kiwi:execution-unavailable', 'kiwi:solver-mismatch']) {
        document.addEventListener(name, (e) => {
          window.__kiwiRace.events.push({ name: e.type, t: e.timeStamp });
        }, true);
      }
    });

    // One create → solve → destroy cycle. Resolves the iteration result,
    // or { skipped: reason } when the cycle never produced a provable
    // mid-solve destroy (solve ended before the first observed tick, or
    // nothing happened within the deadline). A skipped iteration is
    // never counted and never asserted.
    await page.evaluate(() => {
      window.__kiwiRace.runOne = async function runOne() {
        const race = window.__kiwiRace;
        const container = race.tpl.cloneNode(true);
        container.id = 'race-' + (++race.seq);
        const widget = container.querySelector('[data-kiwi-widget]');
        const fill = widget.querySelector('[data-kiwi-bar]');
        const tokenInput = container.querySelector('[data-kiwi-token]');
        document.body.appendChild(container);

        let state = 'pending';
        let destroyAt = null;
        let eventsBefore = -1;
        let tickValue = null;
        let snapshot = null;
        let post = null;
        let failure = null;

        // The state poll: healthy solves go idle → solving (ticks) →
        // done. A done state before any mid-solve tick, a failed state
        // or a stall makes the iteration void (skipped, retried).
        const deadline = performance.now() + 15000;
        const tickObserver = new MutationObserver(() => {
          if (state !== 'pending') return;
          const st = widget.getAttribute('data-state');
          const v = fill.getAttribute('data-progress');
          if (st !== 'solving' || v === null || v === '0' || v === '100') return;
          // ── The deterministic destroy point ──────────────────────
          // This callback is a microtask queued by the chunk's
          // data-progress write; the next chunk is only a later
          // macrotask, so the destroy provably lands mid-computation,
          // before any further progress callback can run.
          tickValue = v;
          state = 'destroyed';
          try {
            window.KiwiCaptcha.destroy(widget);
          } catch (e) {
            failure = String(e);
          }
          destroyAt = performance.now();
          eventsBefore = race.events.length;
          const read = () => ({
            state: widget.getAttribute('data-state'),
            lang: widget.getAttribute('lang'),
            label: widget.querySelector('[data-kiwi-label]').textContent,
            badge: widget.querySelector('[data-kiwi-badge]').textContent,
            hint: widget.querySelector('[data-kiwi-info]').textContent,
            progress: fill.getAttribute('data-progress'),
            token: tokenInput.value,
            started: widget.dataset.kiwiStarted === undefined ? null : widget.dataset.kiwiStarted,
            destroyed: widget.dataset.kiwiDestroyed === undefined ? null : widget.dataset.kiwiDestroyed,
          });
          snapshot = read();
          // Post-destroy baseline: attached in the same microtask, after
          // destroy() returned — every record from here on is a stale
          // write of the cancelled generation.
          const records = [];
          const postObserver = new MutationObserver((recs) => {
            for (const r of recs) {
              records.push({
                type: r.type,
                attr: r.attributeName || null,
                target: r.target.nodeName,
                added: r.addedNodes.length,
                removed: r.removedNodes.length,
              });
            }
          });
          postObserver.observe(widget, {
            attributes: true,
            childList: true,
            characterData: true,
            subtree: true,
          });
          post = { postObserver, records };
        });
        tickObserver.observe(fill, { attributes: true, attributeFilter: ['data-progress'] });

        try {
          window.KiwiCaptcha.render(widget);
        } catch (e) {
          failure = String(e);
        }

        // Wait for the observer's destroy, or for a state that voids the
        // iteration.
        while (state === 'pending' && !failure) {
          const st = widget.getAttribute('data-state');
          if (st === 'done') { state = 'skipped'; break; }
          if (st !== null && st !== 'idle' && st !== 'solving' && st !== 'connecting' && st !== 'pending') {
            state = 'skipped';
            break;
          }
          if (performance.now() > deadline) { state = 'skipped'; break; }
          await new Promise((r) => setTimeout(r, 10));
        }

        tickObserver.disconnect();

        if (state === 'skipped' || state === 'pending') {
          // Void: nothing was destroyed mid-solve. Retire the container
          // cleanly (a live solve may still be running — destroy first)
          // and let the caller retry the cycle.
          try { window.KiwiCaptcha.destroy(widget); } catch (e) {}
          if (container.parentNode) container.parentNode.removeChild(container);
          return { skipped: state === 'pending' ? 'no-tick-timeout' : 'ended-before-mid-tick' };
        }

        // ── The settle: let every queued progress callback of the
        // cancelled generation fire (the background solve keeps running
        // to completion — find, cap or deadline) before asserting.
        await new Promise((r) => setTimeout(r, 2000));

        const end = {
          state: widget.getAttribute('data-state'),
          lang: widget.getAttribute('lang'),
          label: widget.querySelector('[data-kiwi-label]').textContent,
          badge: widget.querySelector('[data-kiwi-badge]').textContent,
          hint: widget.querySelector('[data-kiwi-info]').textContent,
          progress: fill.getAttribute('data-progress'),
          token: tokenInput.value,
          started: widget.dataset.kiwiStarted === undefined ? null : widget.dataset.kiwiStarted,
          destroyed: widget.dataset.kiwiDestroyed === undefined ? null : widget.dataset.kiwiDestroyed,
        };
        post.postObserver.disconnect();
        const result = {
          ok: !failure && post.records.length === 0,
          tickValue,
          failure,
          destroyAt,
          snapshot,
          end,
          records: post.records,
          eventsAfter: race.events.length - eventsBefore,
          eventsAfterList: race.events.slice(eventsBefore),
        };
        if (container.parentNode) container.parentNode.removeChild(container);
        return result;
      };

      window.__kiwiRace.runBatch = async function runBatch(n) {
        const out = { results: [], skipped: [] };
        for (let i = 0; i < n; i++) {
          let r = null;
          try {
            r = await window.__kiwiRace.runOne();
          } catch (e) {
            out.skipped.push({ reason: 'exception: ' + String(e) });
            continue;
          }
          if (r && r.skipped) out.skipped.push({ reason: r.skipped });
          else if (r) out.results.push(r);
        }
        return out;
      };
    });

    // ── Drive the cycles in batches (each batch runs entirely in the
    // page, so the settle waits never round-trip) ───────────────────
    const results = [];
    const skipped = [];
    let attempts = 0;
    while (results.length < ITERATIONS && attempts < MAX_ATTEMPTS) {
      const need = Math.min(BATCH_SIZE, ITERATIONS - results.length);
      const batch = await page.evaluate((n) => window.__kiwiRace.runBatch(n), need);
      results.push(...batch.results);
      skipped.push(...batch.skipped);
      attempts += need;
    }

    expect(results.length, `must collect ${ITERATIONS} provable mid-solve destroy cycles (got ${results.length} valid, ${skipped.length} void after ${attempts} attempts; void reasons: ${JSON.stringify(skipped.slice(0, 10))})`)
      .toBe(ITERATIONS);

    // ── The assertions, over every valid iteration ─────────────────
    for (const [i, r] of results.entries()) {
      expect(r.ok, `iteration ${i}: destroy mid-solve must leave zero post-destroy mutations (got ${JSON.stringify(r.records)})`).toBe(true);
      expect(r.failure, `iteration ${i}: destroy must raise no exception`).toBeNull();
      // The destroy must provably have landed mid-solve: the observed
      // tick is a real progress write (non-100), never the final 100.
      const pct = Number.parseFloat(r.tickValue);
      expect(Number.isFinite(pct) && pct >= 10 && pct < 100, `iteration ${i}: destroy must happen on a mid-solve progress tick, not the terminal write (tick ${r.tickValue})`).toBe(true);
      expect(r.snapshot.state, `iteration ${i}: destroy must clear data-state (got ${r.snapshot.state})`).toBeNull();
      expect(r.snapshot.token, `iteration ${i}: destroy must clear the token (got "${r.snapshot.token}")`).toBe('');
      expect(r.snapshot.destroyed, `iteration ${i}: destroy must mark the widget destroyed`).toBe('1');
      // The destroyed widget must stay exactly as destroy left it while
      // the cancelled generation's solve ran to completion behind it.
      expect(r.end, `iteration ${i}: no state/lang/label/token/progress mutation after destruction`).toEqual(r.snapshot);
      expect(r.records, `iteration ${i}: no data-progress write and no DOM mutation after destruction`).toEqual([]);
      expect(r.eventsAfter, `iteration ${i}: no kiwi:* event after destruction (got ${JSON.stringify(r.eventsAfterList)})`).toBe(0);
    }

    // Page-wide: nothing anywhere threw or rejected during the cycles.
    const pageSide = await page.evaluate(() => ({
      errors: window.__kiwiRace.errors,
      rejections: window.__kiwiRace.rejections,
    }));
    expect(pageErrors, 'the destroy race must raise no page error').toEqual([]);
    // The only tolerated console noise is the browser's automatic
    // "Failed to load resource" line for a challenge POST refused by the
    // fixture server itself (net::ERR_CONNECTION_REFUSED), and the same
    // automatic line for a challenge POST the driver aborts on destroy
    // (net::ERR_ABORTED): cancelling an in-flight acquisition is the
    // designed destroy semantics, so the aborted request is expected.
    // The fixture
    // port is shared with other lanes on this machine, and a foreign
    // teardown can briefly take the server down mid-run; the driver's
    // designed bounded retry absorbs exactly that, the iteration still
    // reaches a provable mid-solve destroy, and every post-destroy invariant
    // above stays strict. Anything else — a driver console.error(), an
    // uncaught rejection, any other failed resource — fails the test.
    const refusedNoise = 'Failed to load resource: net::ERR_CONNECTION_REFUSED';
    const abortedNoise = 'Failed to load resource: net::ERR_ABORTED';
    const unexpectedConsole = consoleErrors.filter((e) => e.text !== refusedNoise && e.text !== abortedNoise);
    expect(unexpectedConsole, `the destroy race must raise no console error other than the fixture-refusal noise (unexpected: ${JSON.stringify(unexpectedConsole)}; failed requests: ${JSON.stringify(failedRequests)})`).toEqual([]);
    const unexpectedFailures = failedRequests.filter((f) => {
      if (f.failure === 'net::ERR_ABORTED') {
        // A challenge POST aborted client-side is the driver's own
        // destroy-time cancellation of an in-flight acquisition.
        try {
          const p = new URL(f.url).pathname;
          return !(f.method === 'POST' && p === '/challenge');
        } catch (e) {
          return true;
        }
      }
      if (f.failure !== 'net::ERR_CONNECTION_REFUSED') return true;
      try {
        const p = new URL(f.url).pathname;
        return !(f.method === 'POST' && p === '/challenge');
      } catch (e) {
        return true;
      }
    });
    expect(unexpectedFailures, 'the only tolerated failed requests are a fixture /challenge POST refused by the server and a /challenge POST aborted by the destroy-time cancellation').toEqual([]);
    expect(consoleErrors.length, `transient fixture refusals must stay bounded (${consoleErrors.length} refused POSTs; a longer outage would have voided iterations instead)`).toBeLessThanOrEqual(30);
    expect(pageSide.errors, 'the destroy race must raise no window error').toEqual([]);
    expect(pageSide.rejections, 'the destroy race must raise no unhandled rejection').toEqual([]);
    expect(skipped.length, 'void cycles must stay a small minority (a large share means the mid-solve window is being missed)').toBeLessThan(ITERATIONS / 2);
  });
});

// ── The second closure case: the bulk destroy over several widgets ──
// The first spec pins the post-destroy progress race for a single
// widget destroyed mid-solve. A multi-widget SPA teardown exercises the
// other documented shape of the same API: destroy(element|selector)
// walks querySelectorAll when given a selector, so one call retires
// every widget on the page. The driver exposes no destroyAll member:
// the selector form IS the bulk API, and [data-kiwi-widget] sits on
// the exact element a per-widget destroy() would receive, so the bulk
// call below marks, cancels and tears down each widget identically.
// The race under test is the same closure, widened to several in-flight
// generations: every widget is mid-solve with queued chunk callbacks
// behind its observed tick when the bulk call lands, so a stale write
// from any cancelled generation would paint into a destroyed widget.
// The deterministic core mirrors the first spec's ordering argument:
//
//   1. The cycle renders two containers cloned from the fixture's own
//      rendered markup (the same scrubbed-template machinery the first
//      spec uses, so the cycle always runs the current tree's widget
//      markup). Both widgets fetch SHA-256 challenges at the maximum
//      ceiling (?bits=20), so every solve spans many progress chunks,
//      and each chunk that does not find the proof emits one non-100
//      data-progress write while its widget reads data-state="solving".
//   2. A MutationObserver per fill bar records its own widget's first
//      mid-solve tick. The cycle proceeds only when each widget has
//      ticked once and still reads data-state="solving": the bulk call
//      then provably lands while every generation is still in flight,
//      with further chunks queued behind the observed ticks. When a
//      solve ends inside its first chunk (the measured 1-2% minority),
//      or a widget settles before the destroy point, the cycle is void
//      and retried; a void cycle proves nothing and never counts.
//   3. One call, window.KiwiCaptcha.destroy('[data-kiwi-widget]'),
//      retires both widgets. The post-destroy observers start only
//      after the call returns (same synchronous task, so they can only
//      ever see stale writes of the cancelled generations), the cycle
//      settles 2 s so every queued callback drains, and each widget is
//      then asserted byte-identical to its destroy-time state: no
//      data-progress write, no state/lang/label/badge/token change, no
//      childList or characterData activity, no kiwi:* event, no error.
//
// Every cycle runs on fresh containers and cleans up fully (observers
// disconnected, containers removed). The cycle count defaults to 15,
// inside the agreed 10-20 band, with the env knob
// KIWI_DESTROY_ALL_ITERATIONS as the override; a reverted driver fails
// with overwhelming probability for the same reason 60 single-widget
// cycles do: one stale write from either cancelled generation fails
// the whole test, and the fixed driver passes 15/15 on every run.
test.describe('closure case 2: the bulk destroy over a page of two solving widgets leaves both untouched', () => {
  test('one destroy call retires every mid-solve widget and no cancelled generation writes back', async ({ page }) => {
    test.setTimeout(480_000);

    const pageErrors = [];
    page.on('pageerror', (e) => pageErrors.push(String(e)));
    const consoleErrors = [];
    page.on('console', (msg) => {
      if (msg.type() === 'error') consoleErrors.push({ t: Date.now(), text: msg.text() });
    });
    const failedRequests = [];
    page.on('requestfailed', (req) => {
      failedRequests.push({ t: Date.now(), url: req.url(), method: req.method(), failure: req.failure() && req.failure().errorText });
    });

    // The fixture page at the max SHA-256 ceiling: every solve spans
    // many progress ticks, so two concurrent widgets both reach a
    // provable mid-solve point before the bulk destroy.
    await page.goto('/?bits=20');
    await expect(page.locator('[data-kiwi-widget]')).toHaveCount(1);

    // ── Page-side harness ──────────────────────────────────────────
    // The same scrubbed clone template as the first spec, retired
    // fixture widget included; per-cycle clones below make two fresh
    // containers from it. Error/event collectors are global (installed
    // before any iteration exists); per-iteration assertions slice
    // them by the destroy timestamp.
    await page.evaluate((count) => {
      const source = document.querySelector('.kiwi-container');
      const widgetRoot = source.querySelector('[data-kiwi-widget]');
      const tpl = source.cloneNode(true);
      tpl.removeAttribute('id');
      for (const el of tpl.querySelectorAll('[data-kiwi-instance],[data-kiwi-started],[data-kiwi-destroyed]')) {
        el.removeAttribute('data-kiwi-instance');
        el.removeAttribute('data-kiwi-started');
        el.removeAttribute('data-kiwi-destroyed');
      }
      for (const el of tpl.querySelectorAll('[data-state]')) el.removeAttribute('data-state');
      for (const el of tpl.querySelectorAll('[data-kiwi-bar]')) el.removeAttribute('data-progress');
      const t0 = tpl.querySelector('[data-kiwi-token]');
      if (t0) t0.value = '';
      const c0 = tpl.querySelector('[data-kiwi-timer]');
      if (c0) c0.textContent = '';

      // Retire the fixture's own widget: destroy it (it is mid-init or
      // already solving by now) and remove the container.
      if (widgetRoot) {
        try { window.KiwiCaptcha.destroy(widgetRoot); } catch (e) {}
      }
      source.parentNode.removeChild(source);

      window.__kiwiMulti = {
        tpl,
        count,
        seq: 0,
        errors: [],
        rejections: [],
        events: [],
      };
      window.addEventListener('error', (e) => {
        window.__kiwiMulti.errors.push(String(e.error || e.message));
      });
      window.addEventListener('unhandledrejection', (e) => {
        window.__kiwiMulti.rejections.push(String(e.reason));
      });
      for (const name of ['kiwi:ready', 'kiwi:verifying', 'kiwi:verified', 'kiwi:error', 'kiwi:expired', 'kiwi:worker-unavailable', 'kiwi:execution-unavailable', 'kiwi:solver-mismatch']) {
        document.addEventListener(name, (e) => {
          window.__kiwiMulti.events.push({ name: e.type, t: e.timeStamp });
        }, true);
      }
    }, MULTI_WIDGETS);

    // One create-two → solve-both → bulk-destroy cycle. Resolves the
    // iteration result, or { skipped: reason } when the cycle never
    // produced a provable two-widget mid-solve destroy (a solve ended
    // before its widget's first observed tick, or nothing happened
    // within the deadline). A skipped iteration is never counted and
    // never asserted.
    await page.evaluate(() => {
      const readWidget = (p) => ({
        state: p.widget.getAttribute('data-state'),
        lang: p.widget.getAttribute('lang'),
        label: p.widget.querySelector('[data-kiwi-label]').textContent,
        badge: p.widget.querySelector('[data-kiwi-badge]').textContent,
        hint: p.widget.querySelector('[data-kiwi-info]').textContent,
        progress: p.fill.getAttribute('data-progress'),
        token: p.tokenInput.value,
        started: p.widget.dataset.kiwiStarted === undefined ? null : p.widget.dataset.kiwiStarted,
        destroyed: p.widget.dataset.kiwiDestroyed === undefined ? null : p.widget.dataset.kiwiDestroyed,
      });

      window.__kiwiMulti.runOne = async function runOne() {
        const multi = window.__kiwiMulti;
        const parts = [];
        for (let i = 0; i < multi.count; i++) {
          const container = multi.tpl.cloneNode(true);
          container.id = 'bulk-' + (++multi.seq) + '-' + i;
          const widget = container.querySelector('[data-kiwi-widget]');
          parts.push({
            container,
            widget,
            fill: widget.querySelector('[data-kiwi-bar]'),
            tokenInput: container.querySelector('[data-kiwi-token]'),
          });
          document.body.appendChild(container);
        }

        // One tick observer per fill bar: it records the widget's
        // first genuine mid-solve progress write (a non-100 value read
        // while the widget is still in data-state="solving").
        const ticked = parts.map(() => null);
        const tickObservers = parts.map((p, i) => {
          const obs = new MutationObserver(() => {
            if (ticked[i] !== null) return;
            const st = p.widget.getAttribute('data-state');
            const v = p.fill.getAttribute('data-progress');
            if (st !== 'solving' || v === null || v === '0' || v === '100') return;
            ticked[i] = v;
          });
          obs.observe(p.fill, { attributes: true, attributeFilter: ['data-progress'] });
          return obs;
        });

        let failure = null;
        let outcome = 'ready';
        try {
          for (const p of parts) window.KiwiCaptcha.render(p.widget);
        } catch (e) {
          failure = String(e);
          outcome = 'render-failed';
        }

        // The state poll: every widget must reach one mid-solve tick
        // while it still reads data-state="solving". A widget that
        // settles (done or failed) first, or a stall past the
        // deadline, voids the cycle (skipped, retried).
        const deadline = performance.now() + 15000;
        const transient = ['idle', 'solving', 'connecting', 'pending'];
        while (outcome === 'ready') {
          const states = parts.map((p) => p.widget.getAttribute('data-state'));
          if (ticked.every((v) => v !== null) && states.every((s) => s === 'solving')) break;
          if (states.some((s) => s !== null && transient.indexOf(s) === -1)) {
            outcome = 'ended-before-both-mid-tick';
            break;
          }
          if (performance.now() > deadline) {
            outcome = 'no-tick-timeout';
            break;
          }
          await new Promise((r) => setTimeout(r, 10));
        }
        for (const obs of tickObservers) obs.disconnect();

        if (outcome !== 'ready') {
          // Void: nothing was destroyed mid-solve. Retire every widget
          // cleanly (live solves may still run — destroy first) and
          // let the caller retry the cycle.
          for (const p of parts) {
            try { window.KiwiCaptcha.destroy(p.widget); } catch (e) {}
          }
          for (const p of parts) {
            if (p.container.parentNode) p.container.parentNode.removeChild(p.container);
          }
          return { skipped: outcome === 'render-failed' ? 'render-failed: ' + failure : outcome };
        }

        // ── The deterministic bulk-destroy point ────────────────────
        // Every widget is mid-solve with queued chunks behind its
        // observed tick, so the single selector call provably lands
        // while all generations are in flight. destroy() accepts an
        // element or a selector; the selector form walks every match,
        // which is the documented bulk shape (no destroyAll member).
        const preStates = parts.map((p) => p.widget.getAttribute('data-state'));
        const destroyAt = performance.now();
        const eventsBefore = multi.events.length;
        try {
          window.KiwiCaptcha.destroy('[data-kiwi-widget]');
        } catch (e) {
          failure = String(e);
        }

        // Destroy-time snapshot per widget, then the post-destroy
        // observers. They start in the same synchronous task, after
        // the bulk call returned, so every record from here on is a
        // stale write of a cancelled generation.
        const watched = parts.map((p) => {
          const snapshot = readWidget(p);
          const records = [];
          const postObserver = new MutationObserver((recs) => {
            for (const r of recs) {
              records.push({
                type: r.type,
                attr: r.attributeName || null,
                target: r.target.nodeName,
                added: r.addedNodes.length,
                removed: r.removedNodes.length,
              });
            }
          });
          postObserver.observe(p.widget, {
            attributes: true,
            childList: true,
            characterData: true,
            subtree: true,
          });
          return { snapshot, records, postObserver };
        });

        // ── The settle: let every queued progress callback of both
        // cancelled generations fire (the background solves keep
        // running to completion behind the destroy) before asserting.
        await new Promise((r) => setTimeout(r, 2000));

        const widgets = parts.map((p, i) => {
          const w = watched[i];
          w.postObserver.disconnect();
          return {
            tick: ticked[i],
            snapshot: w.snapshot,
            records: w.records,
            end: readWidget(p),
          };
        });
        for (const p of parts) {
          if (p.container.parentNode) p.container.parentNode.removeChild(p.container);
        }
        return {
          ok: !failure && widgets.every((w) => w.records.length === 0),
          failure,
          preStates,
          destroyAt,
          widgets,
          eventsAfter: multi.events.length - eventsBefore,
          eventsAfterList: multi.events.slice(eventsBefore),
        };
      };

      window.__kiwiMulti.runBatch = async function runBatch(n) {
        const out = { results: [], skipped: [] };
        for (let i = 0; i < n; i++) {
          let r = null;
          try {
            r = await window.__kiwiMulti.runOne();
          } catch (e) {
            out.skipped.push({ reason: 'exception: ' + String(e) });
            continue;
          }
          if (r && r.skipped) out.skipped.push({ reason: r.skipped });
          else if (r) out.results.push(r);
        }
        return out;
      };
    });

    // ── Drive the cycles in batches (each batch runs entirely in the
    // page, so the settle waits never round-trip) ───────────────────
    const results = [];
    const skipped = [];
    let attempts = 0;
    while (results.length < MULTI_ITERATIONS && attempts < MULTI_MAX_ATTEMPTS) {
      const need = Math.min(MULTI_BATCH_SIZE, MULTI_ITERATIONS - results.length);
      const batch = await page.evaluate((n) => window.__kiwiMulti.runBatch(n), need);
      results.push(...batch.results);
      skipped.push(...batch.skipped);
      attempts += need;
    }

    expect(results.length, `must collect ${MULTI_ITERATIONS} provable two-widget mid-solve bulk-destroy cycles (got ${results.length} valid, ${skipped.length} void after ${attempts} attempts; void reasons: ${JSON.stringify(skipped.slice(0, 10))})`)
      .toBe(MULTI_ITERATIONS);

    // ── The assertions, over every valid iteration and every widget
    const preStatesExpected = new Array(MULTI_WIDGETS).fill('solving');
    for (const [i, r] of results.entries()) {
      expect(r.failure, `iteration ${i}: the bulk destroy must raise no exception (got ${r.failure})`).toBeNull();
      // The destroy must provably have landed while both widgets were
      // mid-solve: each read data-state="solving" at the destroy point
      // and each had emitted a genuine progress tick (non-100, never
      // the terminal write).
      expect(r.preStates, `iteration ${i}: every widget must read data-state="solving" at the destroy point (got ${JSON.stringify(r.preStates)})`).toEqual(preStatesExpected);
      expect(r.widgets.length, `iteration ${i}: the cycle must run ${MULTI_WIDGETS} widgets`).toBe(MULTI_WIDGETS);
      for (const [wi, w] of r.widgets.entries()) {
        const pct = Number.parseFloat(w.tick);
        expect(Number.isFinite(pct) && pct >= 10 && pct < 100, `iteration ${i} widget ${wi}: the destroy must happen after a mid-solve progress tick, not the terminal write (tick ${w.tick})`).toBe(true);
        expect(w.snapshot.state, `iteration ${i} widget ${wi}: the bulk destroy must clear data-state (got ${w.snapshot.state})`).toBeNull();
        expect(w.snapshot.token, `iteration ${i} widget ${wi}: the bulk destroy must leave the token blank (got "${w.snapshot.token}")`).toBe('');
        expect(w.snapshot.destroyed, `iteration ${i} widget ${wi}: the bulk destroy must mark the widget destroyed`).toBe('1');
        // The destroyed widget must stay exactly as the bulk destroy
        // left it while its cancelled generation's solve ran out.
        expect(w.end, `iteration ${i} widget ${wi}: no state/lang/label/token/progress mutation after the bulk destroy`).toEqual(w.snapshot);
        expect(w.records, `iteration ${i} widget ${wi}: no data-progress write and no DOM mutation after the bulk destroy (got ${JSON.stringify(w.records)})`).toEqual([]);
      }
      expect(r.eventsAfter, `iteration ${i}: no kiwi:* event after the bulk destroy (got ${JSON.stringify(r.eventsAfterList)})`).toBe(0);
    }

    // Page-wide: nothing anywhere threw or rejected during the cycles.
    const pageSide = await page.evaluate(() => ({
      errors: window.__kiwiMulti.errors,
      rejections: window.__kiwiMulti.rejections,
    }));
    expect(pageErrors, 'the bulk destroy must raise no page error').toEqual([]);
    // The only tolerated console noise is the browser's automatic
    // "Failed to load resource" line for a challenge POST refused by the
    // fixture server itself (net::ERR_CONNECTION_REFUSED), and the same
    // automatic line for a challenge POST the driver aborts on destroy
    // (net::ERR_ABORTED): cancelling an in-flight acquisition is the
    // designed destroy semantics, so the aborted request is expected.
    // The fixture
    // port is shared with other lanes on this machine, and a foreign
    // teardown can briefly take the server down mid-run; the driver's
    // designed bounded retry absorbs exactly that, the iteration still
    // reaches a provable two-widget mid-solve destroy, and every
    // invariant above stays strict. Anything else — a driver
    // console.error(), an uncaught rejection, any other failed
    // resource — fails the test.
    const refusedNoise = 'Failed to load resource: net::ERR_CONNECTION_REFUSED';
    const abortedNoise = 'Failed to load resource: net::ERR_ABORTED';
    const unexpectedConsole = consoleErrors.filter((e) => e.text !== refusedNoise && e.text !== abortedNoise);
    expect(unexpectedConsole, `the bulk destroy must raise no console error other than the fixture-refusal noise (unexpected: ${JSON.stringify(unexpectedConsole)}; failed requests: ${JSON.stringify(failedRequests)})`).toEqual([]);
    const unexpectedFailures = failedRequests.filter((f) => {
      if (f.failure === 'net::ERR_ABORTED') {
        // A challenge POST aborted client-side is the driver's own
        // destroy-time cancellation of an in-flight acquisition.
        try {
          const p = new URL(f.url).pathname;
          return !(f.method === 'POST' && p === '/challenge');
        } catch (e) {
          return true;
        }
      }
      if (f.failure !== 'net::ERR_CONNECTION_REFUSED') return true;
      try {
        const p = new URL(f.url).pathname;
        return !(f.method === 'POST' && p === '/challenge');
      } catch (e) {
        return true;
      }
    });
    expect(unexpectedFailures, 'the only tolerated failed requests are a fixture /challenge POST refused by the server and a /challenge POST aborted by the destroy-time cancellation').toEqual([]);
    expect(consoleErrors.length, `transient fixture refusals must stay bounded (${consoleErrors.length} refused POSTs; a longer outage would have voided iterations instead)`).toBeLessThanOrEqual(30);
    expect(pageSide.errors, 'the bulk destroy must raise no window error').toEqual([]);
    expect(pageSide.rejections, 'the bulk destroy must raise no unhandled rejection').toEqual([]);
    expect(skipped.length, 'void cycles must stay a small minority (a large share means the two-widget mid-solve window is being missed)').toBeLessThan(MULTI_ITERATIONS / 2);
  });
});
