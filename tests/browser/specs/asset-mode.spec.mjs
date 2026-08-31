import { test, expect } from '@playwright/test';
import { createHash } from 'node:crypto';

// The files-mode asset delivery tier (kiwi_captcha.asset_mode "files"):
// versioned immutable first-party asset URLs with exact content hashes,
// long cache lifetimes, SRI, once-per-page dedup, and the lazy heavy
// modules: the driver fetches the WASM runtime AND the Argon worker asset
// only when a memory-hard challenge arrives, so a plain SHA-256 page pays
// nothing for the Argon machinery.
// The worker runs as a same-origin Worker whose source the driver
// cryptographically preflights: the fetched bytes are hashed and
// compared against the page-issued digest, then the content-addressed
// URL is loaded by the Worker constructor (no Blob, no blob: CSP).
// The integrity verification fails closed when the page cannot
// compute the digest.
// The inline compatibility tier keeps its zero-request Blob-worker
// behavior; this spec pins both modes explicitly.
test.describe('KiwiCaptcha files-mode asset delivery', () => {
  // Collects the asset request URLs into a live array; the assertions
  // filter it at check time (a snapshot at collection time would be
  // empty, since the requests arrive after the page load).
  function collectAssetRequests(page) {
    const urls = [];
    page.on('request', (req) => {
      if (req.url().includes('/kiwi-captcha/assets/')) urls.push(req.url());
    });
    return urls;
  }

  // The driver's lazy asset fetches (the WASM runtime glue and the Argon
  // worker asset) go through window.fetch, so wrapping it captures exactly
  // the driver-initiated fetches — deduplicated per URL across widgets.
  // The browser's Worker constructor and importScripts load the same
  // content-addressed URLs through their own worker-script fetchers (which
  // bypass the page's HTTP cache by platform design), so counting
  // window.fetch is the precise measure of "the driver downloads the
  // runtime/worker exactly once".
  async function trackDriverFetches(page) {
    await page.addInitScript(() => {
      window.__kiwiDriverFetches = [];
      const nativeFetch = window.fetch;
      window.fetch = function (...args) {
        try {
          const url = typeof args[0] === 'string' ? args[0] : (args[0] && args[0].url);
          if (url && url.includes('/kiwi-captcha/assets/')) window.__kiwiDriverFetches.push(url);
        } catch (e) {}
        return nativeFetch.apply(this, args);
      };
    });
    return () => page.evaluate(() => window.__kiwiDriverFetches ?? []);
  }

  function runtimeCount(all) {
    return all.filter((u) => u.includes('/assets/runtime.')).length;
  }

  function workerCount(all) {
    return all.filter((u) => u.includes('/assets/worker.')).length;
  }

  function sha256Base64(text) {
    return 'sha256-' + createHash('sha256').update(text, 'utf8').digest('base64');
  }

  test('asset requests carry immutable headers, exact hashes and SRI', async ({ page }) => {
    const assetResponses = [];
    page.on('response', (res) => {
      if (res.url().includes('/kiwi-captcha/assets/')) assetResponses.push(res);
    });
    await page.goto('/?assets=files');
    await expect(page.locator('[data-kiwi-widget]')).toHaveAttribute('data-state', 'done', { timeout: 60_000 });

    // The page references exactly two assets: the stylesheet and the driver.
    const hrefs = await page.evaluate(() => {
      const links = Array.from(document.querySelectorAll('link[rel="stylesheet"]')).map((l) => l.getAttribute('href'));
      const scripts = Array.from(document.querySelectorAll('script[src]')).map((s) => s.getAttribute('src'));
      return links.concat(scripts);
    });
    const assetUrls = hrefs.filter((h) => h.includes('/kiwi-captcha/assets/'));
    expect(assetUrls).toHaveLength(2);
    expect(assetUrls.some((u) => u.endsWith('.css'))).toBe(true);
    expect(assetUrls.some((u) => u.includes('driver.') && u.endsWith('.js'))).toBe(true);

    for (const url of assetUrls) {
      const res = await page.request.get(url);
      expect(res.status(), `the referenced asset must exist: ${url}`).toBe(200);
      const body = await res.body();
      const fullHash = createHash('sha256').update(body).digest('hex');
      const expectedUrl = url.replace(/\.([0-9a-f]{12})\./, '.' + fullHash.slice(0, 12) + '.');
      expect(expectedUrl).toBe(url);

      const headers = res.headers();
      expect(headers['cache-control']).toContain('immutable');
      expect(headers['cache-control']).toContain('max-age=31536000');
      expect(headers['cache-control']).toContain('public');
      expect(headers.etag).toBe(`"${fullHash}"`);
      expect(Number(headers['content-length'])).toBe(body.length);
      expect(headers['content-type']).toMatch(/^(text\/css|application\/javascript)/);

      // The SRI integrity of the emitted tag matches the served bytes.
      const integrity = await page.evaluate(
        (assetUrl) => {
          const el = document.querySelector(`link[href="${assetUrl}"]`) || document.querySelector(`script[src="${assetUrl}"]`);
          return el ? el.getAttribute('integrity') : null;
        },
        url,
      );
      expect(integrity, `the emitted tag must carry the SRI of ${url}`).toBe(sha256Base64(body.toString('utf8')));
    }
  });

  test('an unknown hash is a 404 and a matching ETag revalidates to 304', async ({ page }) => {
    await page.goto('/?assets=files');
    await expect(page.locator('[data-kiwi-widget]')).toHaveAttribute('data-state', 'done', { timeout: 60_000 });
    const driverUrl = await page.evaluate(() => {
      const s = document.querySelector('script[src*="/kiwi-captcha/assets/driver."]');
      return s ? s.getAttribute('src') : null;
    });
    expect(driverUrl).toBeTruthy();

    const good = await page.request.get(driverUrl);
    expect(good.status()).toBe(200);
    const etag = good.headers().etag;
    const body = await good.body();

    // A wrong hash under the same asset name is a 404 (never stale bytes).
    const wrongHash = body.toString('utf8').slice(0, 12).replace(/[0-9a-f]/g, (c) => (c === '0' ? '1' : '0'));
    const badUrl = driverUrl.replace(/\.([0-9a-f]{12})\./, '.' + wrongHash + '.');
    const bad = await page.request.get(badUrl);
    expect(bad.status()).toBe(404);

    // Revalidation: the content-hash ETag returns 304 with no body.
    const revalidated = await page.request.get(driverUrl, { headers: { 'If-None-Match': etag } });
    expect(revalidated.status()).toBe(304);
    expect((await revalidated.body()).length).toBe(0);
  });

  test('each emitted asset appears exactly once on a two-widget page (dedup)', async ({ page }) => {
    await page.goto('/?assets=files&widgets=2');
    await expect(page.locator('[data-kiwi-widget]')).toHaveCount(2);

    const counts = await page.evaluate(() => {
      const links = Array.from(document.querySelectorAll('link[rel="stylesheet"][href*="/kiwi-captcha/assets/"]'));
      const scripts = Array.from(document.querySelectorAll('script[src*="/kiwi-captcha/assets/"]'));
      const runtimeTags = Array.from(document.querySelectorAll('script[src*="/assets/runtime."]'));
      return {
        css: links.length,
        driver: scripts.filter((s) => s.getAttribute('src').includes('driver.')).length,
        runtimeTags: runtimeTags.length,
        runtimeSrc: Array.from(document.querySelectorAll('[data-kiwi-runtime-src]')).map((el) => el.getAttribute('data-kiwi-runtime-src')),
      };
    });
    expect(counts.css).toBe(1);
    expect(counts.driver).toBe(1);
    expect(counts.runtimeTags).toBe(0);
    expect(counts.runtimeSrc).toHaveLength(2);
    expect(new Set(counts.runtimeSrc).size).toBe(1);

    await expect(page.locator('[data-kiwi-widget]').first()).toHaveAttribute('data-state', 'done', { timeout: 60_000 });
    await expect(page.locator('[data-kiwi-widget]').nth(1)).toHaveAttribute('data-state', 'done', { timeout: 60_000 });
  });

  test('a SHA challenge triggers no runtime or worker asset fetch (lazy)', async ({ page }) => {
    const driverFetches = await trackDriverFetches(page);
    await page.goto('/?assets=files');
    await expect(page.locator('[data-kiwi-widget]')).toHaveAttribute('data-state', 'done', { timeout: 60_000 });

    const token = await page.locator('[data-kiwi-token]').inputValue();
    expect(token.length).toBeGreaterThan(0);
    const resp = await page.request.post('http://127.0.0.1:8085/verify', { data: { token } });
    expect((await resp.json()).ok).toBe(true);
    const fetches = await driverFetches();
    expect(runtimeCount(fetches), 'a SHA-256 solve must never download the Argon runtime').toBe(0);
    expect(workerCount(fetches), 'a SHA-256 solve must never download the Argon worker').toBe(0);
  });

  test('an Argon challenge triggers exactly one driver runtime fetch and one driver worker fetch and verifies', async ({ page }) => {
    const driverFetches = await trackDriverFetches(page);
    await page.goto('/?assets=files&algorithm=argon2id');
    await expect(page.locator('[data-kiwi-widget]')).toHaveAttribute('data-state', 'done', { timeout: 120_000 });

    const fetches = await driverFetches();
    expect(runtimeCount(fetches), 'exactly one driver runtime fetch for the memory-hard challenge').toBe(1);
    expect(workerCount(fetches), 'exactly one driver worker fetch for the memory-hard challenge').toBe(1);
    const token = await page.locator('[data-kiwi-token]').inputValue();
    expect(token.length).toBeGreaterThan(0);
    const resp = await page.request.post('http://127.0.0.1:8085/verify', { data: { token } });
    expect((await resp.json()).ok).toBe(true);
  });

  test('the worker never probes a non-versioned runtime URL (no eager relative import, zero failed/extra requests)', async ({ page }) => {
    // The historical eager importScripts("kiwicaptcha-wasm.js") resolved
    // against the worker's own URL — in files mode that is a NON-versioned
    // URL next to worker.<hash>.js, a 404 probe against the versioned
    // asset route (and, on an app serving a stale unversioned file, a
    // runtime that could initialize before the driver-preflight-verified
    // one arrives).
    // The worker must boot with no runtime and the driver must direct it:
    // every request the page makes for the assets must be a versioned
    // content-addressed URL — zero requests to any non-versioned asset
    // name, failed or not.
    const requests = [];
    page.on('request', (req) => requests.push(req.url()));
    page.on('requestfailed', (req) => requests.push(req.url()));
    await page.goto('/?assets=files&algorithm=argon2id');
    await expect(page.locator('[data-kiwi-widget]')).toHaveAttribute('data-state', 'done', { timeout: 120_000 });

    const unversioned = requests.filter(
      (u) => u.includes('/kiwi-captcha/assets/') && !/\.([0-9a-f]{12})\.(js|css)$/.test(u),
    );
    expect(
      unversioned,
      'no non-versioned asset URL may ever be requested (the eager relative import is gone)',
    ).toEqual([]);
    const token = await page.locator('[data-kiwi-token]').inputValue();
    expect(token.length).toBeGreaterThan(0);
    const resp = await page.request.post('http://127.0.0.1:8085/verify', { data: { token } });
    expect((await resp.json()).ok).toBe(true);
  });

  test('the worker runs as a same-origin Worker constructed from the fetched asset (no Blob URL, no blob: worker)', async ({ page }) => {
    // The files-mode worker asset is fetched and cryptographically
    // preflight-verified by the driver (the bytes are hashed and compared
    // against the page-issued digest), and the content-addressed URL is
    // then loaded by new Worker(workerUrl): a same-origin
    // Worker. No URL.createObjectURL is ever called for the files-mode
    // worker, so worker-src 'self' (never blob:) is the CSP requirement.
    await page.addInitScript(() => {
      window.__kiwiBlobUrlCount = 0;
      const nativeCreateObjectURL = URL.createObjectURL;
      URL.createObjectURL = function (...args) {
        window.__kiwiBlobUrlCount++;
        return nativeCreateObjectURL.apply(this, args);
      };
    });
    await page.goto('/?assets=files&algorithm=argon2id');
    await expect(page.locator('[data-kiwi-widget]')).toHaveAttribute('data-state', 'done', { timeout: 120_000 });

    const workerUsed = await page.evaluate(() => window.__kiwiWorkerUsed === true);
    expect(workerUsed, 'the files-mode worker must be used for Argon2id').toBe(true);
    const blobUrlsCreated = await page.evaluate(() => window.__kiwiBlobUrlCount ?? 0);
    expect(blobUrlsCreated, 'files mode must construct the worker without a Blob URL').toBe(0);
    const token = await page.locator('[data-kiwi-token]').inputValue();
    expect(token.length).toBeGreaterThan(0);
    const resp = await page.request.post('http://127.0.0.1:8085/verify', { data: { token } });
    expect((await resp.json()).ok).toBe(true);
  });

  test('adaptive escalation: a SHA page receiving an Argon challenge fetches the runtime and the worker exactly once and verifies', async ({ page }) => {
    const driverFetches = await trackDriverFetches(page);
    // The page asks for sha256; the fixture escalates to argon2id (the
    // server-side adaptive decision). The driver accepts the stronger
    // algorithm and lazily fetches the runtime and the worker only now.
    await page.goto('/?assets=files&escalate=argon');
    await expect(page.locator('[data-kiwi-widget]')).toHaveAttribute('data-state', 'done', { timeout: 120_000 });

    const fetches = await driverFetches();
    expect(runtimeCount(fetches), 'the runtime fetch must happen exactly once, at the Argon challenge').toBe(1);
    expect(workerCount(fetches), 'the worker fetch must happen exactly once, at the Argon challenge').toBe(1);
    const token = await page.locator('[data-kiwi-token]').inputValue();
    expect(token.length).toBeGreaterThan(0);
    const resp = await page.request.post('http://127.0.0.1:8085/verify', { data: { token } });
    expect((await resp.json()).ok).toBe(true);
  });

  test('two Argon widgets share exactly one driver runtime fetch and one driver worker fetch', async ({ page }) => {
    const driverFetches = await trackDriverFetches(page);
    await page.goto('/?assets=files&widgets=2&algorithm=argon2id');
    await expect(page.locator('[data-kiwi-widget]').first()).toHaveAttribute('data-state', 'done', { timeout: 120_000 });
    await expect(page.locator('[data-kiwi-widget]').nth(1)).toHaveAttribute('data-state', 'done', { timeout: 120_000 });

    const fetches = await driverFetches();
    expect(runtimeCount(fetches), 'the shared per-URL promise must deduplicate the runtime fetch').toBe(1);
    expect(workerCount(fetches), 'the shared per-URL promise must deduplicate the worker fetch').toBe(1);
    const tokens = [];
    for (const el of await page.locator('[data-kiwi-token]').all()) {
      tokens.push(await el.inputValue());
    }
    expect(new Set(tokens).size).toBe(2);
    for (const token of tokens) {
      const resp = await page.request.post('http://127.0.0.1:8085/verify', { data: { token } });
      expect((await resp.json()).ok).toBe(true);
    }
  });

  test('a failing runtime fetch is a controlled worker-unavailable state with bounded retries', async ({ page }) => {
    let runtimeHits = 0;
    await page.route('**/assets/runtime*.js', async (route) => {
      runtimeHits++;
      await route.fulfill({ status: 500, contentType: 'application/javascript', body: 'boom' });
    });
    await page.goto('/?assets=files&algorithm=argon2id');
    await expect(page.locator('[data-kiwi-widget]')).toHaveAttribute('data-state', 'kiwi:worker-unavailable', { timeout: 60_000 });

    // The bounded retry: the initial attempt plus two retries, then the
    // controlled state — never an infinite loop, never a main-thread
    // Argon hash.
    expect(runtimeHits).toBe(3);
    expect(await page.locator('[data-kiwi-token]').inputValue()).toBe('');
  });

  test('a failing worker asset fetch is a controlled worker-unavailable state with bounded retries', async ({ page }) => {
    let workerHits = 0;
    await page.route('**/assets/worker*.js', async (route) => {
      workerHits++;
      await route.fulfill({ status: 500, contentType: 'application/javascript', body: 'boom' });
    });
    await page.goto('/?assets=files&algorithm=argon2id');
    await expect(page.locator('[data-kiwi-widget]')).toHaveAttribute('data-state', 'kiwi:worker-unavailable', { timeout: 60_000 });

    // The bounded retry: the initial attempt plus two retries, then the
    // controlled state. The runtime fetch still succeeds (its route is
    // untouched); only the worker asset is refused.
    expect(workerHits).toBe(3);
    expect(await page.locator('[data-kiwi-token]').inputValue()).toBe('');
  });

  test('integrity verification fails closed: a page that cannot compute the digest never accepts the runtime or the worker', async ({ page }) => {
    // item 15: when the page supplies an integrity value and the digest
    // cannot be performed (no crypto.subtle.digest), the lazy fetch must
    // fails closed into kiwi:worker-unavailable with the
    // integrity-unverifiable reason — never an implicit success, never a
    // main-thread Argon hash.
    let runtimeHits = 0;
    await page.addInitScript(() => {
      // Replace the entire SubtleCrypto with a digest-less stub: the page
      // still demands SRI (data-kiwi-runtime-integrity), but it can no
      // longer compute the digest. (window.crypto.subtle is a getter that
      // returns a fresh object per access, so shadowing .digest on one
      // instance would not stick.)
      try {
        Object.defineProperty(window.crypto, 'subtle', { value: {}, configurable: true });
      } catch (e) {}
      // Capture the worker-unavailable reason on the widget element as
      // soon as it exists (the listener must be attached before the
      // bounded retries exhaust). document is always available in the
      // init script (documentElement may not be).
      window.__kiwiReason = null;
      const observer = new MutationObserver(() => {
        const w = document.querySelector('[data-kiwi-widget]');
        if (w && !w.dataset.kiwiReasonBound) {
          w.dataset.kiwiReasonBound = '1';
          w.addEventListener('kiwi:worker-unavailable', (ev) => {
            window.__kiwiReason = (ev && ev.detail && ev.detail.reason) || null;
          });
        }
      });
      observer.observe(document, { childList: true, subtree: true });
    });
    await page.route('**/assets/runtime*.js', async (route) => {
      runtimeHits++;
      await route.continue();
    });
    await page.goto('/?assets=files&algorithm=argon2id');
    await expect(page.locator('[data-kiwi-widget]')).toHaveAttribute('data-state', 'kiwi:worker-unavailable', { timeout: 60_000 });

    // The integrity check fails closed before any accept: the runtime is
    // fetched (the initial attempt), its digest cannot be computed, and
    // the bounded retries do not change that.
    expect(runtimeHits).toBe(3);
    const reason = await page.evaluate(() => window.__kiwiReason);
    expect(reason, 'the worker-unavailable reason must name the unverifiable integrity').toBe('integrity-unverifiable');
    expect(await page.locator('[data-kiwi-token]').inputValue()).toBe('');
  });

  test('a tampered worker asset (digest mismatch) is refused before construction', async ({ page }) => {
    // The worker bytes served differ from the page-issued digest: the
    // driver must fail closed (worker-unavailable, integrity-mismatch),
    // never construct a Worker from unverified bytes.
    await page.route('**/assets/worker*.js', async (route) => {
      const body = await route.request().url();
      await route.fulfill({ contentType: 'application/javascript', body: '/* tampered */' });
    });
    await page.goto('/?assets=files&algorithm=argon2id');
    await expect(page.locator('[data-kiwi-widget]')).toHaveAttribute('data-state', 'kiwi:worker-unavailable', { timeout: 60_000 });
    expect(await page.locator('[data-kiwi-token]').inputValue()).toBe('');
  });

  test('a cross-origin lookalike runtime URL is refused by the worker origin guard (parsed origin equality, never a prefix check)', async ({ page }) => {
    // Serve the files-mode widget page from the http://localhost origin
    // (route-fulfilled; the same-origin assets and the challenge are
    // forwarded to the real fixture) with data-kiwi-runtime-src rewritten
    // to a lookalike of that origin: http://localhost:8085/... starts with
    // the origin string http://localhost (a prefix-based indexOf check
    // would accept it) but parses to a different origin, and it resolves
    // to the real fixture, which serves the real glue. The driver's lazy
    // preflight fetch of the lookalike is fulfilled with the real glue
    // bytes (CORS-open), so the page-issued digest verifies; the worker's
    // own importScripts of the same URL reaches the real fixture. Only
    // the worker's origin guard stands between the lookalike and that
    // importScripts. The guard must refuse it: the worker never loads
    // the foreign-origin runtime, the solve fails closed, and no token
    // is minted. (A prefix-based check would accept the lookalike, import
    // the real glue, and mint a token.)
    const real = 'http://127.0.0.1:8085';
    const lookalikeRequests = [];
    page.on('request', (req) => {
      const u = req.url();
      if (u.includes('http://localhost:8085/')) lookalikeRequests.push(u);
    });
    await page.route('**', async (route) => {
      if (route.request().resourceType() !== 'document') {
        await route.continue();
        return;
      }
      const res = await page.request.get(real + '/?assets=files&algorithm=argon2id');
      let html = await res.text();
      const m = html.match(/data-kiwi-runtime-src="([^"]+)"/);
      if (m) {
        // The fixture emits a relative runtime URL; rewrite it into the
        // absolute lookalike of the http://localhost page origin.
        html = html.replace(
          `data-kiwi-runtime-src="${m[1]}"`,
          `data-kiwi-runtime-src="http://localhost:8085${m[1]}"`,
        );
      }
      await route.fulfill({ response: res, body: html });
    });
    await page.route(/\/kiwi-captcha\/assets\/runtime/, async (route) => {
      // The driver's preflight fetch of the lookalike: real glue bytes,
      // CORS-open so the cross-origin read succeeds. The worker's
      // importScripts of the same URL bypasses the page routes and is
      // served the same bytes by the real fixture.
      const res = await route.fetch();
      const body = await res.body();
      await route.fulfill({
        response: res,
        headers: { 'access-control-allow-origin': '*' },
        body,
      });
    });
    await page.route(/\/kiwi-captcha\/assets\//, async (route) => {
      const res = await page.request.get(real + new URL(route.request().url()).pathname);
      await route.fulfill({ response: res });
    });
    await page.route(/\/challenge/, async (route) => {
      // The challenge POST must reach the real fixture (it persists the
      // issued record its verify endpoint checks later).
      const req = route.request();
      const body = req.postData() ? JSON.parse(req.postData()) : undefined;
      const res = await page.request.post(real + new URL(req.url()).pathname, {
        headers: { 'Content-Type': 'application/json' },
        data: body,
      });
      await route.fulfill({ response: res });
    });
    await page.goto('http://localhost/?assets=files&algorithm=argon2id');
    await expect(page.locator('[data-kiwi-widget]')).toHaveAttribute('data-state', 'kiwi:worker-unavailable', { timeout: 60_000 });
    expect(await page.locator('[data-kiwi-token]').inputValue(), 'the refused lookalike runtime must never mint a token').toBe('');
    expect(lookalikeRequests.length, 'the driver preflight fetch of the lookalike must have happened').toBeGreaterThanOrEqual(1);
  });
});

test.describe('KiwiCaptcha inline (compatibility) asset delivery', () => {
  // The inline tier is the documented compatibility / zero-request mode:
  // every asset is embedded at render time, the page makes no asset
  // requests, and the Argon worker is the historical Blob worker. The
  // bundle default is files; this block pins the explicit inline tier.
  function collectAssetRequests(page) {
    const urls = [];
    page.on('request', (req) => {
      if (req.url().includes('/kiwi-captcha/assets/')) urls.push(req.url());
    });
    return urls;
  }

  test('the inline page embeds every asset and makes zero asset requests (SHA)', async ({ page }) => {
    const all = collectAssetRequests(page);
    await page.goto('/?assets=inline');
    await expect(page.locator('[data-kiwi-widget]')).toHaveAttribute('data-state', 'done', { timeout: 60_000 });

    // No stylesheet link, no external script, no lazy asset attributes:
    // the glue and the driver ride the page as inline scripts.
    const tags = await page.evaluate(() => {
      const links = Array.from(document.querySelectorAll('link[rel="stylesheet"][href*="/kiwi-captcha/assets/"]'));
      const scripts = Array.from(document.querySelectorAll('script[src*="/kiwi-captcha/assets/"]'));
      return { links: links.length, scripts: scripts.length, runtimeSrc: document.querySelectorAll('[data-kiwi-runtime-src]').length, workerSrc: document.querySelectorAll('[data-kiwi-worker-src]').length };
    });
    expect(tags.links).toBe(0);
    expect(tags.scripts).toBe(0);
    expect(tags.runtimeSrc).toBe(0);
    expect(tags.workerSrc).toBe(0);
    expect(all, 'inline mode must make zero asset requests').toHaveLength(0);

    const token = await page.locator('[data-kiwi-token]').inputValue();
    expect(token.length).toBeGreaterThan(0);
    const resp = await page.request.post('http://127.0.0.1:8085/verify', { data: { token } });
    expect((await resp.json()).ok).toBe(true);
  });

  test('inline Argon2id solves through the historical Blob worker (zero asset requests)', async ({ page }) => {
    const all = collectAssetRequests(page);
    await page.goto('/?assets=inline&algorithm=argon2id');
    await expect(page.locator('[data-kiwi-widget]')).toHaveAttribute('data-state', 'done', { timeout: 120_000 });

    expect(all, 'inline Argon2id must make zero asset requests (Blob worker from embedded code)').toHaveLength(0);
    const token = await page.locator('[data-kiwi-token]').inputValue();
    expect(token.length).toBeGreaterThan(0);
    const resp = await page.request.post('http://127.0.0.1:8085/verify', { data: { token } });
    expect((await resp.json()).ok).toBe(true);
  });
});
