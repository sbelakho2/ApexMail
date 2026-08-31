import { test, expect } from '@playwright/test';

// Targeted-bot adversarial model: a Kiwi-aware bot that reads the
// challenge response before the widget renders, learns the decoy name
// and the rendering strategy, and adapts its fill or skip decision per
// issuance.
//
// The spec pins five claims. First, the bot can learn both dimensions,
// and the strategy is chosen per challenge independently of the name:
// one pinned name renders all six presentations deterministically
// through the fixture knobs. Second, fresh unforced challenges draw
// fresh authenticated names and a varying strategy set from the client
// `CSPRNG` (the independence property). Third, knowing the decoy changes
// nothing about the security boundary: a correct solve verifies
// whether the bot ignores the decoy or fills it, and a fill is
// additive evidence, never a gate. Fourth, the documented evasion
// surfaces (array-shaped parameters, duplicate form keys, forged decoy
// values in the submission and in the challenge request, an injected
// unauthenticated name in the response) answer deterministically,
// never a server error. Fifth, a deployment can bound the strategy
// subset through the hint seam and every invariant holds.
//
// The fixture knobs (tests/browser/router.php): ?decoy=pool arms the
// real authenticated issuance (protocol-v3 record, grammar prefix plus
// fresh 16-hex suffix, a 2^-64 per-issuance collision probability);
// ?decoyname=<name> pins the armed name; ?strategy=<0..5> emits the
// non-authenticated rendering hint the driver honors when present
// (production responses omit it). POST /verify answers the proof
// verdict. POST /honeypot-check mirrors the validator's
// formDecoyEvidence: a non-empty value under the exact authenticated
// name of the verified record reports the hit, additively, and any
// other name is ignored.
//
// The decoy name is response-known; the DOM carries no ownership
// marker and no name-tracking attribute. The assertions below use the
// response names plus the same DOM signatures a targeted classifier
// would use, so the spec is portable across Chromium, Firefox and
// WebKit with no engine-specific API and no timing dependence: every
// wait is state-driven.

const PINNED_NAME = 'secondary_contact_number_a3f9c21d8e5b7401';

const DECOY_NAME_SHAPE = /^[a-z]+_[a-z]+_[a-z]+_[0-9a-f]{16}$/;

const WRAP_CLASSES = ['kiwi-form-aux', 'kiwi-form-aux-alt', 'kiwi-field-aux', 'kiwi-aux-group'];

// The settled presentation buckets a DOM classifier can discriminate.
// The deferred variant (5) renders the variant-0 look after the solve,
// so its settled bucket is none-bare-after; only a pre-solve observer
// of the form host sees the deferral.
const KNOWN_BUCKETS = ['none-bare-after', 'none-wrapped-after', 'hidden-bare-before', 'offscreen-after', 'hidden-wrapped-before'];

const EXPECTED_BUCKET = {
  0: 'none-bare-after',
  1: 'none-wrapped-after',
  2: 'hidden-bare-before',
  3: 'offscreen-after',
  4: 'hidden-wrapped-before',
  5: 'none-bare-after',
};

async function solve(page, timeout = 60_000) {
  await expect(page.locator('[data-kiwi-widget]')).toHaveAttribute('data-state', 'done', { timeout });
}

// The targeted bot's learn step: the challenge response carries the
// server-issued name and, when the fixture hint is present, the
// strategy. The promise must be registered before the navigation or
// reset that triggers the fetch. The same read is what a Kiwi-aware
// bot does over the network.
function learnChallenge(page) {
  return page.waitForResponse((r) => r.request().method() === 'POST' && r.url().includes('/challenge') && !r.url().includes('/cancel'))
    .then((resp) => resp.json())
    .then((data) => ({
      name: typeof data.decoy_field === 'string' ? data.decoy_field : null,
      strategy: typeof data.strategy === 'number' ? data.strategy : null,
    }));
}

// The rendered decoy facts read in one browser round trip, using the
// same signatures a targeted DOM classifier would use: the
// accessibility union, the visibility mechanism, the wrapper and the
// placement relative to the token input.
async function decoyFacts(page, name) {
  return page.evaluate(([n, wrapClasses]) => {
    const token = document.querySelector('[data-kiwi-token]');
    const host = token ? token.parentNode : null;
    const input = host ? host.querySelector(`input[name="${n}"]`) : null;
    if (!input) return { present: false };
    const cs = getComputedStyle(input);
    const wrap = input.parentNode;
    const els = host ? Array.prototype.slice.call(host.children) : [];
    const self = host && wrap !== host ? wrap : input;
    return {
      present: true,
      tabIndex: input.tabIndex,
      ariaHidden: input.getAttribute('aria-hidden'),
      autocomplete: input.getAttribute('autocomplete'),
      hiddenAttr: input.hasAttribute('hidden'),
      display: cs.display,
      offscreen: cs.position === 'absolute' && cs.left === '-9999px',
      wrapped: !!(host && wrap !== host && wrapClasses.indexOf(wrap.className) !== -1),
      beforeToken: !!(host && els.indexOf(self) < els.indexOf(token)),
      inHost: !!(host && host.contains(input)),
      sameNameCount: host ? host.querySelectorAll(`input[name="${n}"]`).length : 0,
      unionCount: document.querySelectorAll('input[aria-hidden="true"][tabindex="-1"]').length,
      unionName: (document.querySelector('input[aria-hidden="true"][tabindex="-1"]') || {}).name ?? null,
    };
  }, [name, WRAP_CLASSES]);
}

function presentationBucket(facts) {
  if (!facts.present) return null;
  if (facts.offscreen) return 'offscreen-after';
  if (facts.hiddenAttr) return facts.wrapped ? 'hidden-wrapped-before' : 'hidden-bare-before';
  if (facts.display === 'none') return facts.wrapped ? 'none-wrapped-after' : 'none-bare-after';
  return 'unclassified';
}

// The invariant surface every strategy keeps, asserted in one place so
// every test below pins the same claims: exactly one decoy input with
// the learned name, invisible to humans, non-interactive, autofill
// neutral, inside the token's form host, and identifiable by the exact
// accessibility-union selector a targeted classifier would use.
async function assertInvariantSurface(page, name) {
  const facts = await decoyFacts(page, name);
  expect(facts.present, 'the learned name must render its decoy input').toBe(true);
  expect(facts.sameNameCount).toBe(1);
  expect(facts.tabIndex).toBe(-1);
  expect(facts.ariaHidden).toBe('true');
  expect(facts.inHost, 'the decoy must live inside the token form host').toBe(true);
  expect(['off', 'new-password'], 'the decoy stays off the autofill candidate surface').toContain(facts.autocomplete);
  const invisible = facts.display === 'none' || facts.hiddenAttr || facts.offscreen;
  expect(invisible, `the decoy must be invisible to humans (display=${facts.display}, hidden=${facts.hiddenAttr}, offscreen=${facts.offscreen})`).toBe(true);
  expect(facts.unionCount, 'the accessibility union selects exactly the decoy').toBe(1);
  expect(facts.unionName).toBe(name);
  return facts;
}

async function widgetId(page) {
  return page.evaluate(() => document.querySelector('[data-kiwi-widget]').dataset.kiwiInstance);
}

test.describe('KiwiCaptcha targeted-bot decoy adaptation', () => {
  test('the bot learns the name and the strategy, and one pinned name renders all six presentations', async ({ page }) => {
    // The deterministic independence proof: the name stays pinned
    // while the fixture forces each strategy, so the presentation is
    // chosen per challenge independently of the name. The bot's
    // learned strategy is validated against the settled DOM on every
    // iteration, which makes the inference honest.
    for (const strategy of [0, 1, 2, 3, 4, 5]) {
      const learnedP = learnChallenge(page);
      await page.goto(`/?decoy=pool&decoyname=${PINNED_NAME}&strategy=${strategy}`);
      await solve(page);
      const learned = await learnedP;
      expect(learned.name, 'the pinned armed name must ride the response').toBe(PINNED_NAME);
      expect(learned.strategy, 'the hint must ride the response so the bot can learn it').toBe(strategy);
      const facts = await assertInvariantSurface(page, PINNED_NAME);
      expect(presentationBucket(facts), `strategy ${strategy} must render its own presentation`).toBe(EXPECTED_BUCKET[strategy]);
      if (strategy === 1 || strategy === 4) {
        expect(facts.wrapped).toBe(true);
      } else {
        expect(facts.wrapped).toBe(false);
      }
      if (strategy === 2 || strategy === 4) {
        expect(facts.beforeToken).toBe(true);
      } else {
        expect(facts.beforeToken).toBe(false);
      }
    }
  });

  test('fresh challenges draw fresh names and a varying unforced strategy set', async ({ page }) => {
    // No hint: production-like issuance. Twelve fresh challenges must
    // carry twelve fresh authenticated names and more than one
    // presentation bucket. The system draws the strategy from the
    // client `CSPRNG` uniformly over six; the probability that twelve
    // draws share one bucket is below one in a billion, so the
    // assertion fails deterministically if the strategy dimension is
    // stuck, not if the draw is fair.
    await page.goto('/?decoy=pool');
    await solve(page);
    const wid = await widgetId(page);
    const observations = [];
    for (let i = 0; i < 12; i++) {
      const learnedP = learnChallenge(page);
      await page.evaluate((id) => window.KiwiCaptcha.reset(id), wid);
      await solve(page);
      const learned = await learnedP;
      expect(learned.name, 'every armed issuance must carry a decoy name').toMatch(DECOY_NAME_SHAPE);
      const facts = await assertInvariantSurface(page, learned.name);
      observations.push({ name: learned.name, bucket: presentationBucket(facts) });
    }
    const names = observations.map((o) => o.name);
    const buckets = observations.map((o) => o.bucket);
    expect(new Set(names).size, 'each issuance must carry its own fresh authenticated name').toBe(names.length);
    expect(buckets.every((b) => KNOWN_BUCKETS.includes(b)), 'every observed presentation must be a known bucket').toBe(true);
    expect(new Set(buckets).size, 'the unforced strategy set must vary across fresh challenges').toBeGreaterThanOrEqual(2);
  });

  test('knowing the decoy changes nothing: the correct solve verifies with the decoy ignored or filled', async ({ page }) => {
    // Phase one: the bot ignores the decoy. It learns the name and
    // strips the field from the submission entirely. The proof still
    // verifies and the absence produces no false hit.
    const learned1P = learnChallenge(page);
    await page.goto('/?decoy=pool');
    await solve(page);
    const learned1 = await learned1P;
    const origin = await page.evaluate(() => window.location.origin);
    const token1 = await page.locator('[data-kiwi-token]').inputValue();
    const ignored = await page.request.post(`${origin}/honeypot-check`, {
      form: { kiwi__token: token1 },
    });
    expect(ignored.status()).toBe(200);
    expect(await ignored.json()).toEqual({ ok: true, honeypot_hit: false, decoy_field: learned1.name });

    // Phase two: the bot fills the decoy to look human. The evidence
    // fires additively and the proof verdict is unchanged.
    const wid = await widgetId(page);
    const learned2P = learnChallenge(page);
    await page.evaluate((id) => window.KiwiCaptcha.reset(id), wid);
    await solve(page);
    const learned2 = await learned2P;
    const token2 = await page.locator('[data-kiwi-token]').inputValue();
    await page.locator(`input[name="${learned2.name}"]`).evaluate((el) => {
      el.value = 'bot@example.com';
    });
    const filled = await page.request.post(`${origin}/honeypot-check`, {
      form: { kiwi__token: token2, [learned2.name]: 'bot@example.com' },
    });
    expect(filled.status()).toBe(200);
    expect(await filled.json()).toEqual({ ok: true, honeypot_hit: true, decoy_field: learned2.name });
  });

  test('forged submission shapes under the decoy name answer deterministically, never a server error', async ({ page }) => {
    await page.goto(`/?decoy=pool&decoyname=${PINNED_NAME}`);
    await solve(page);
    const origin = await page.evaluate(() => window.location.origin);
    const wid = await widgetId(page);

    const check = async (pairs, expectedHit) => {
      const token = await page.locator('[data-kiwi-token]').inputValue();
      const wire = `kiwi__token=${encodeURIComponent(token)}&${pairs.map((p) => `${encodeURIComponent(PINNED_NAME)}${p}`).join('&')}`;
      const resp = await page.request.post(`${origin}/honeypot-check`, {
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        data: wire,
      });
      expect(resp.status(), 'the forged wire body must answer deterministically, never a 500').toBe(200);
      const body = await resp.json();
      expect(body.ok, 'the proof stays valid under the forged submission').toBe(true);
      expect(body.honeypot_hit).toBe(expectedHit);
      expect(body.decoy_field).toBe(PINNED_NAME);
    };

    // Array-shaped parameter: an array is no scalar decoy value, so
    // the deterministic answer is no hit.
    await check(['[]=x'], false);

    // Duplicate keys, value then empty: PHP form parsing is
    // deterministic last-wins, so the parsed value is empty and the
    // answer is no hit.
    await page.evaluate((id) => window.KiwiCaptcha.reset(id), wid);
    await solve(page);
    await check(['=forged%20value', '='], false);

    // Duplicate keys, empty then value: last-wins parses the value,
    // the exact authenticated name reads as a hit, additively.
    await page.evaluate((id) => window.KiwiCaptcha.reset(id), wid);
    await solve(page);
    await check(['=', '=forged%20value'], true);
  });

  test('forged decoy markers and an injected response name are ignored: issuance and verification stay deterministic', async ({ page }) => {
    // Phase one: the bot forges the risk markers into the challenge
    // request body (decoy_field and honeypot). The issuance reads no
    // such fields, mints normally and the correct solve verifies.
    await page.goto('/?decoy=pool');
    await solve(page);
    const origin = await page.evaluate(() => window.location.origin);
    const wid = await widgetId(page);
    await page.route('**/challenge?*', async (route) => {
      const body = route.request().postDataJSON();
      if (body) {
        body.decoy_field = 'forged_marker_name';
        body.honeypot = 'forged@example.com';
        await route.continue({ postData: JSON.stringify(body) });
        return;
      }
      await route.continue();
    });
    const learnedP = learnChallenge(page);
    await page.evaluate((id) => window.KiwiCaptcha.reset(id), wid);
    await solve(page);
    expect((await learnedP).name, 'the forged markers must not disturb the response name').toMatch(DECOY_NAME_SHAPE);
    const token = await page.locator('[data-kiwi-token]').inputValue();
    const verify = await page.request.post(`${origin}/verify`, { data: { token } });
    expect(verify.status()).toBe(200);
    expect((await verify.json()).ok, 'forged request markers must not poison the issuance').toBe(true);
    await page.unroute('**/challenge?*');

    // Phase two: the bot injects a decoy name the record does not
    // authenticate into an unarmed challenge response. The input
    // renders, but the server verifies against the record and the
    // unauthenticated name is ignored: no hit, and the record answers
    // decoy_field null.
    await page.route('**/challenge', async (route) => {
      const resp = await route.fetch();
      const data = await resp.json();
      data.decoy_field = 'forged_contact_field';
      await route.fulfill({ contentType: 'application/json', body: JSON.stringify(data) });
    });
    await page.goto('/');
    await solve(page);
    await expect(page.locator('input[name="forged_contact_field"]'), 'the injected response renders its input').toHaveCount(1);
    await page.locator('input[name="forged_contact_field"]').evaluate((el) => {
      el.value = 'bot@example.com';
    });
    const token2 = await page.locator('[data-kiwi-token]').inputValue();
    const hit = await page.request.post(`${origin}/honeypot-check`, {
      form: { kiwi__token: token2, forged_contact_field: 'bot@example.com' },
    });
    expect(hit.status()).toBe(200);
    const hitBody = await hit.json();
    expect(hitBody.ok, 'the proof stays valid under an injected name').toBe(true);
    expect(hitBody.honeypot_hit, 'an unauthenticated name is not this challenge decoy').toBe(false);
    expect(hitBody.decoy_field).toBeNull();
  });

  test('a deployment can bound the strategy subset through the hint seam and every invariant holds', async ({ page }) => {
    // The per-deployment variation seam: a deployment that pins a
    // strategy subset (here the hidden-attribute family) through the
    // hint sees only that subset across fresh challenges, the names
    // stay fresh per issuance, and every invariant holds on every
    // iteration. Production responses omit the hint; the seam is what
    // a server-side per-sitekey policy would emit.
    let issued = 0;
    await page.route('**/challenge?*', async (route) => {
      const resp = await route.fetch();
      const data = await resp.json();
      data.strategy = issued % 2 === 0 ? 2 : 4;
      issued++;
      await route.fulfill({ contentType: 'application/json', body: JSON.stringify(data) });
    });
    await page.goto('/?decoy=pool');
    await solve(page);
    const wid = await widgetId(page);
    const subset = ['hidden-bare-before', 'hidden-wrapped-before'];
    const buckets = [];
    const names = [];
    for (let i = 0; i < 5; i++) {
      const learnedP = learnChallenge(page);
      await page.evaluate((id) => window.KiwiCaptcha.reset(id), wid);
      await solve(page);
      const learned = await learnedP;
      const facts = await assertInvariantSurface(page, learned.name);
      buckets.push(presentationBucket(facts));
      names.push(learned.name);
    }
    expect(buckets, 'the pinned subset must bound every presentation').toEqual([...Array(5)].map((_, i) => subset[(i + 1) % 2]));
    expect(new Set(names).size, 'the bound subset must not couple the names').toBe(names.length);
  });
});
