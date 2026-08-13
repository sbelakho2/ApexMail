# KiwiCaptcha Symfony Bundle

A **self-contained**, privacy-preserving proof-of-work anti-abuse integration
for Symfony 6/7, with first-party behavioral heuristics as a supplementary
signal.

**No third-party services. No third-party requests. No third-party tracking.**
Challenges are issued and verified **locally** by the verified
[`kiwicaptcha/kiwicaptcha-php`] core (HMAC-SHA256 signing, IP binding,
single-use storage, SHA-256 + Argon2id proof-of-work) — the widget inlines its
own CSS, WASM solver, and driver, so no request ever leaves your application.
Your secret key never leaves your server.

This bundle is the **only** Symfony integration of KiwiCaptcha. Earlier
versions also bundled a Symfony layer inside `kiwicaptcha/kiwicaptcha-php`
(the `KiwiCaptcha\Symfony` namespace); that layer has been **removed** — the
core package is framework-neutral, and this bundle is the single source of
truth for Symfony apps. If you previously used the bundled layer, migrate by
requiring `bel-consulting/kiwicaptcha-symfony` and registering this bundle
(see below); the config keys, form type, constraint, Twig function, and
endpoint path are the same.

KiwiCaptcha is anti-abuse protection, **not** a reliable human-vs-bot
discriminator: a human never solves the challenge — their CPU does, and a
bot's CPU can do the same work. The core value is that every
signup/login/reset/scraping attempt carries a real, tunable computational
cost, making mass abuse uneconomical. Browser behavioral telemetry is
client-controlled and forgeable — a **supplement**, never the security
boundary.

Copyright (c) 2026 Bel Consulting OÜ · MIT License

## Privacy guarantees

**No third-party tracking or runtime services. Privacy Strict collects no
behavioral, device, hardware, or screen telemetry. Raw IP addresses are not
persisted; short-lived keyed pseudonyms are used only where required for
abuse prevention.**

Concretely, KiwiCaptcha stores no raw IP and no stable IP-derived identifier:
the challenge record holds a nonce-bound binding tag (unique per challenge)
and the rate limiter keys are peppered HMACs of the IP — rotated per epoch
(`rate_limit_rotation_secs`, default 3600), so the same IP yields a
DIFFERENT keyed pseudonym in every epoch and Redis snapshots cannot
correlate one source across time periods. Linkability within one epoch is
unavoidable for rate limiting.

The optional adaptive risk engine (OFF by default) follows the same rule:
its Redis state is keyed by 128-bit keyed pseudonyms of the source
(rotating every epoch) and subnet, and by a keyed pseudonym of the first-party
continuity cookie's random nonce — never raw IPs, never stable identifiers.
Enabling risk adds one HttpOnly first-party cookie carrying a fresh random
nonce (see the risk section below).

## Installation

1. Require the bundle (from this repository, or once published to Packagist):

```bash
composer require bel-consulting/kiwicaptcha-symfony
```

2. Register the bundle in `config/bundles.php`:

```php
return [
    // ...
    BelConsulting\KiwiCaptchaBundle\KiwiCaptchaBundle::class => ['all' => true],
];
```

3. Configure in `config/packages/kiwi_captcha.yaml`:

```yaml
kiwi_captcha:
    secret_key: '%env(KIWI_SECRET_KEY)%'   # required, min 16 bytes
    algorithm: sha256                       # sha256 | argon2id
    difficulty_bits: 20                     # SHA-256 leading zero bits
    argon_m_kib: 0                          # Argon2id memory (KiB); 0 = sha256 only
    argon_t: 3                              # Argon2id requires t >= 3 and p == 1
    argon_p: 1
    challenge_ttl_secs: 120
    route_prefix: /kiwi-captcha             # challenge endpoint prefix; the form
                                            # widget and standalone widget both
                                            # derive their endpoint from it
    # Production requires a shared storage (Redis). The bundle fails fast with
    # a LogicException if ArrayStorage is configured outside the test/dev
    # environment (kernel.environment or APP_ENV).
    # storage: kiwicaptcha.storage.redis    # atomic single-use via GETDEL

    # ── Privacy posture ──────────────────────────────────────────────────
    # privacy_mode: strict | standard (default strict). In STRICT mode the
    # extension FORCES telemetry 'off', same_origin_only true and
    # min_duration_ms 0 (the server-side solve-timing floor is a timing
    # heuristic and is disabled) — operator values for those keys are
    # overridden. In STANDARD mode the operator's choices pass through.
    # privacy_mode: strict
    # telemetry: off | minimal | full       # widget signal collection;
    #                                       # forced 'off' under strict
    # binding_mode: nonce_ip_hmac | none    # challenge IP binding; stored
    #                                       # tag is nonce-bound, never a
    #                                       # stable IP identifier; 'none'
    #                                       # issues challenges with an
    #                                       # EMPTY binding tag (maximum
    #                                       # privacy; relay protection
    #                                       # off) — fully wired through
    #                                       # to the core BindingMode.
    # same_origin_only: true                # reject cross-origin challenge
    #                                       # POSTs with 403
    #                                       # CROSS_ORIGIN_DENIED; forced
    #                                       # true under strict
    # min_duration_ms: null                 # explicit solve-timing floor in
    #                                       # ms (null = derive from
    #                                       # difficulty); forced 0 under
    #                                       # strict
    # enforce_telemetry: false              # reject bot-scored telemetry at
    #                                       # verification time
    #                                       # (defense-in-depth only)

    # ── Production hardening ──────────────────────────────────────────────
    # Per-IP rate limit on challenge issuance (default 10 per window; 0 =
    # disabled). Mass challenge minting is what makes aggregate verification
    # work unbounded, so keep this on in production.
    # rate_limit: 10
    # Deployment-GLOBAL rate limit (default 500 per window; 0 = disabled),
    # enforced ATOMICALLY against Redis so ALL workers share one sliding
    # window. Without a Redis client the global cap is not enforced (the
    # in-memory/PSR-6 fallbacks are per-process/best-effort).
    # rate_limit_global: 500
    # rate_limit_window_secs: 60            # sliding window (default 60)
    # rate_limit_cache: null                # optional PSR-6 pool service id
    #                                       # used as the SHARED multi-process
    #                                       # fallback when no Redis client
    #                                       # exists (e.g. a Redis-backed
    #                                       # Symfony Cache pool). Without it,
    #                                       # the fallback is a per-process
    #                                       # in-memory window.
    #                                       # Raw client IPs are never stored:
    #                                       # every key is a peppered HMAC of
    #                                       # the IP (rate_limit_pepper
    #                                       # defaults to secret_key).
    # Aggregate Argon2id verification concurrency cap (default 2; 0 =
    # unlimited). Each Argon2id verification allocates argon_m_kib of memory —
    # size this to available memory. With a Redis client the cap is enforced
    # across ALL PHP-FPM workers (see the Argon2 section below).
    # argon2_max_concurrent_verifications: 2
    # argon2_semaphore_namespace: '%kernel.project_dir%'
    #                                       # per-deployment discriminator for
    #                                       # the Redis lease set and the
    #                                       # global rate-limit key; two
    #                                       # deployments sharing one Redis
    #                                       # instance must use different
    #                                       # namespaces
    # redis_service: null                   # optional Redis client service id
    #                                       # (\Redis or Predis\Client) for the
    #                                       # cross-worker Argon2 admission
    #                                       # gate and the atomic rate
    #                                       # limiter; when null, the
    #                                       # storage's own client is reused
    #                                       # if storage is RedisStorage
```

> `KIWI_SECRET_KEY` is the same key used by the Rust implementation, so a
> Symfony app and a Rust service can verify each other's challenges.

## Privacy modes

`privacy_mode` (default **strict**) is the audit-driven privacy contract:

- **strict** — the extension *forces* the privacy-sensitive options
  regardless of what the operator wrote in the config file:
  `telemetry: off` (the widget never collects signal fields),
  `same_origin_only: true` (cross-origin challenge requests are rejected),
  and `min_duration_ms: 0` (no server-side solve-timing floor — the timing
  heuristic is off). Rate limits default to nonzero (10 per client / 500
  global per window) so abuse mitigation stays on.
- **standard** — the operator's explicit values for those keys are honored
  (`telemetry: minimal|full`, `same_origin_only: false`, a positive
  `min_duration_ms`).

`binding_mode` is NOT forced under strict: IP binding is a relay mitigation,
and the stored tag is a per-challenge, nonce-bound HMAC — never a stable
identifier that follows the client.

## Adaptive risk engine

The bundle can run the **KiwiCaptcha Adaptive Risk Engine**
(`kiwicaptcha/kiwicaptcha-risk-php`, the cross-language risk-v1 contract,
byte-identical with the Rust implementation) **before every challenge is
minted**:

- **Pre-issue assessment** — one `PreIssue` observation per request updates
  leaky fixed-point counters (per-source, per-/24 subnet, per-session, plus a
  deployment-global pressure level, all in Redis via the canonical `risk.lua`
  script) and returns a decision: `allow` (issue with the configured
  difficulty), `sha16/18/20` (raise SHA-256 difficulty), `argon16/32/64`
  (issue memory-hard Argon2id profiles), `step_up`, or **`deny`** (HTTP 429
  `{"error":{"code":"RISK_DENIED"}}` before any challenge is written).
- **Post-issue signal** — every minted challenge records `ChallengeIssued`
  (issue-debt) and increments the atomic per-second issuance counter that
  feeds the resource-pressure provider's `issuanceCapacity`
  (`{kiwi:<ns>}:issuance:<second>`, INCR + EXPIRE 1).
- **Post-solve feedback** — the validator feeds every verification outcome
  back into the engine (`SolveSuccess`, `InvalidProof`, `MalformedToken`,
  `ExpiredChallenge`, `ReplayAttempt`; `CapacityExceeded` is never recorded
  as client abuse), so repeated failed solves raise the source's score.
- **Post-solve check** — when a scope opts in (`post_solve_check`), a VALID
  solve additionally runs a fresh `SolveSuccess` re-assessment. A `deny`
  there fails the form with `kiwi.post_solve_rejected`; a `step_up` fails it
  with `kiwi.post_solve_step_up_required` (the application routes the user
  to MFA/passkey/email confirmation). The bundle never confirms its own
  post-solve decision — `confirmedLegitimate` / `confirmedAbuse` are
  application-only signals that REQUIRE the decision id being confirmed.
- **Degraded operation** — a risk-backend outage (Redis down, script errors)
  trips the circuit breaker and the engine returns the scope's `degraded`
  action (default `allow`): challenges are still issued with the bundle's
  configured difficulty. The risk layer is a hardening layer, never a
  single point of failure. The engine's degraded mode consumes the shared
  circuit breaker directly (no per-request PING), and the resource-pressure
  provider caches its snapshots in-process (~100 ms).

**Opt-in and off by default** (privacy posture — enabling it adds a
first-party continuity cookie, see below):

```yaml
kiwi_captcha:
    risk:
        enabled: true
        # The risk-v1 state lives in Redis (EVALSHA of the canonical Lua).
        # Required: risk.redis_service (a Predis\Client service id) — or the
        # bundle's redis_service / RedisStorage client when it is a Predis
        # client. phpredis (\Redis) is NOT supported by the risk engine, and
        # risk.enabled without any Predis client fails at container compile.
        # redis_service: kiwicaptcha.risk.redis
        namespace: '%kernel.project_dir%'   # {kiwi:<namespace>} hash tag
        # source_epoch_secs: 900            # source identity rotation
        # subnet_epoch_secs: 900            # subnet (/24, /56) rotation
        # state_ttl_secs: 1800              # live counter TTL
        # principal_ttl_secs: 86400
        # dedupe_ttl_secs: 60               # identical event_id applied once
        # hysteresis_ms: 60000              # global-level hysteresis window
        # network_classifier_file: null     # optional "cidr,flag" file
        # region: eu-central-1              # OPTIONAL deployment region baked
        #                                   # into every issued challenge and
        #                                   # enforced at verification (a
        #                                   # result token issued in one
        #                                   # region is never redeemable
        #                                   # elsewhere — failover-replay
        #                                   # Option A)
        # redis:                            # challenge-storage hardening
        #     wait_replicas: 1              # WAIT for N replicas after storing
        #                                   # a challenge (async-replication
        #                                   # failover can otherwise lose the
        #                                   # record and replay a consumed
        #                                   # token against a "fresh" record)
        #     wait_timeout_ms: 100          # WAIT timeout for the replicas
        #     ttl_margin_secs: 60           # extra retention on challenge /
        #                                   # replay-security state BEYOND
        #                                   # token validity (must exceed max
        #                                   # clock skew + failover margin;
        #                                   # pair with a noeviction policy
        #                                   # on the security Redis)
        # max_outstanding_challenges: 20    # anti-stockpiling: unsolved
        #                                   # challenges per source
        # max_outstanding_challenges_global: 100000  # deployment-wide cap
        # challenge_origin_allowlist:       # origin-laundering defense: when
        #     - https://app.example.com     # non-empty, challenge POSTs must
        #                                   # carry an allowlisted Origin (or
        #                                   # Referer origin); everything else
        #                                   # gets 403 origin_rejected
        # enforce_fetch_metadata: false     # reject Sec-Fetch-Site:
        #                                   # cross-site challenge requests
        #                                   # (browser-laundering signal;
        #                                   # defense-in-depth only)
        policy_version: 1
        # weights: { ... }                  # 13 risk-v1 weights (defaults = contract)
        # global_floors:                    # minimum action per global level
        #     1: sha16
        #     2: sha18
        #     3: sha20
        #     4: sha20
        scopes:
            login:                         # the app scope string
                # id: 1                     # int scope in Redis state; MUST
                #                           # stay stable once deployed
                #                           # (defaults to crc32(scope name))
                base_risk: 100
                minimum: allow              # floor: never weaker than this
                degraded: allow             # action while the backend is down
                # post_solve_check: true    # valid solves re-assessed after
                #                           # the proof (deny -> 422
                #                           # kiwi.post_solve_rejected,
                #                           # step_up -> 422
                #                           # kiwi.post_solve_step_up_required)
            signup:
                base_risk: 200
        # unknown_scope:                    # scopes NOT configured above
        #     mode: baseline                # baseline (default): engine
        #                                   # declines, default challenge is
        #                                   # issued; reject: TRUE rejection
        #                                   # (HTTP 429 RISK_DENIED, no
        #                                   # challenge); minimum: synthetic
        #                                   # policy (base_risk 100, min/
        #                                   # degraded sha20)
         # calibration:
         #     enabled: false                # Redis score-bucket bias
         #     min_samples: 1000             # passed to the AggregateCalibrator
         #     max_adjustment: 150           #   (bias clamp bound)
         #     max_change_per_minute: 10     #   (adjustment rate bound)
         #     outcome_receipt_ttl_secs: 86400 # outcome/calibration receipt
         #                                   # + outcome-ledger lifetime (24 h
         #                                   # default; 3600..604800) — long
         #                                   # enough for fraud review /
         #                                   # moderation / chargeback labels
         #     mode: random_sample           # label selection: complete |
         #                                   # random_sample (Kiwi samples at
         #                                   # assessment time; unsampled
         #                                   # confirmations are consumed but
         #                                   # not recorded — status 2 — so
         #                                   # the label can never select
         #                                   # itself into the population) |
         #                                   # weighted (the app supplies the
         #                                   # inverse sampling probability
         #                                   # per confirmation)
         #     sampling_probability_ppm: 100000  # PPM chance a decision is
         #                                   # sampled (random_sample mode)
         #     minimum_resolution_ratio: 0.8 # random_sample resolution gate:
         #                                   # bias adjustment is suspended
         #                                   # while sampled total >=
         #                                   # min_samples but resolved/total
         #                                   # < this ratio (0 disables)
         #     false_positive_cost: 1.0      # class-normalized calibration:
         #     false_negative_cost: 2.0      #   price of a false positive vs
         #                                   #   a false negative (default:
         #                                   #   abuse slipping through costs
         #                                   #   twice a false rejection)
         # nonce_to_decision_ttl_secs: 300   # short-lived challenge-nonce ->
         #                                   # decision-id handle TTL
         #                                   # (60..3600; independent of the
         #                                   # outcome lifetime)
        continuity_cookie:
            name: kiwi_risk_session
            ttl_secs: 15552000              # 180 days; 0 = session cookie
            # secure: null                  # null = follow the request scheme
            # samesite: lax
            # http_only: true
```

**Scope ids are part of the Redis state identity.** The `id` (or the
crc32-derived default) must stay stable once deployed — renaming a scope or
reordering ids silently fragments its risk history. Two scopes sharing an id
collide and are refused at compile time.

**Continuity cookie.** The risk-v1 "session" signal links observations from
the same browser across requests, so repeated failed solves are attributable
to one source. The link material is a **random 16-byte nonce** (hex) in a
first-party, HttpOnly, SameSite=Lax cookie (`kiwi_risk_session` by default)
— no IP-derived or device-derived identity, no PII; the engine only ever
stores the keyed pseudonym of the value. Browsers that reject cookies simply
fall back to a session-less identity (availability is never coupled to
cookie acceptance).

**Escalation stays within your algorithm family** (the app's configured
difficulty is the floor, decisions can only raise it): on a sha256
deployment `sha16/18/20` raise the target bits and `argon16/32/64` map to
the strongest SHA profile (sha20); on an argon2id deployment the argon
actions map to 16/32/64 MiB profiles at your `argon2_difficulty_bits` and
sha actions are no-ops. `step_up` issues the strongest profile of the
configured family — the bundle cannot perform application-level step-up
(MFA), so applications may also react to the decision themselves.

**Application hooks.** `kiwi_captcha.risk.engine` (public) exposes the
`KiwiCaptcha\Risk\AdaptiveRiskEngine`, and `RiskGateway` (public) exposes
first-class feedback methods for the remaining server-derived events —
`protectedActionSuccess()` / `protectedActionFailure()`,
`authenticationSuccess()` / `authenticationFailure()`, `rateLimitHit()`
(called automatically by the challenge controller before every 429,
including the risk-denied responses) and `expiredChallenge()` (the verifier
path already covers expiry via `solveOutcome`). Application-level
confirmations split into two paths:
`recordConfirmedReputation()` / `confirmedLegitimate()` /
`confirmedAbuse()` (all requiring the `decisionId` of the decision being
confirmed — the engine throws `InvalidArgumentException` without it; the
gateway passes it through) are the CONTEXT-FUL path — the engine settles
the decision's outcome ledger atomically (consuming the calibration
receipt when one exists) and records the reputation event against the
source/session/principal signals. All three accept the optional inverse
sampling probability (`$samplingProbabilityPpm`, weight = 1_000_000/ppm)
for weighted calibration; a null ppm in weighted mode propagates the
engine's `InvalidArgumentException` (the label cannot be re-weighted
without its inverse probability).
`confirmDecisionOutcome()` is the CALIBRATION-ONLY path for DELAYED
confirmations (email confirmation, fraud review, chargeback, moderation):
just a decision id + outcome — no IP, no scope, no session — and an
optional inverse sampling probability (`$samplingProbabilityPpm`,
weight = 1_000_000/ppm) for weighted calibration. It returns the engine's
shared status: `0` = missing/already confirmed (a webhook retry is a
no-op — at most one reputation mutation per decision), `1` = first
confirmation recorded, `2` = first confirmation but deliberately unsampled
(random_sample mode). `confirmCorrection()` (a label correction of a
decision, same signature/weight mapping) is the engine's compensating
once-only API guarded by the outcome ledger — it WORKS WITHOUT
CALIBRATION (the guard lives in the state store) and, with a calibration
store attached, flips the ledger and REVERSES the recorded bucket counts;
it returns `true` when the compensation was applied and `false` on
retries (the aggregates return to the pre-confirmation state).
`samplingMetrics($scope)` exposes the random_sample resolution-gate
counters (`sampledTotal` / `sampledResolved` / `resolutionRatio` /
`sampledExpired`; zeros when calibration is disabled).
`metricsSnapshot()`
returns aggregate decision counters, global level, store latency — no
identity labels. Decisions are logged through the app's `logger` (info for
decisions, warning for denials) with scope/action/score/reasons only —
never an IP or cookie value, never a decision id or nonce, and the metric
keys are bounded (algorithm/result/reason/profile tuples — no
challenge_id/ip/user_agent labels), so log/metrics cardinality can never be
driven by identity material.

### Region binding (failover-replay mitigation — Option A)

`risk.region` (optional deployment region string, e.g. `eu-central-1`) is
baked into every issued challenge record by the core `Issuer` and enforced
by the core `Verifier`: a result token issued in one region is never
redeemable elsewhere. This is the *Option A* mitigation for the
failover-replay attack (a challenge record replicated to a DR region whose
verifier accepts tokens minted by the failed-over primary would let a
captured token be replayed after failback). Set the SAME region on every
node of one logical deployment and a DIFFERENT region on every failover
target. When unset, no region is recorded and no region check applies.

### Replay-safety Redis hardening (WAIT replicas + TTL margin)

`risk.redis` hardens the CHALLENGE storage when it is a
`KiwiCaptcha\Storage\RedisStorage` definition (the knobs are applied to the
storage service automatically):

- `wait_replicas` (default 0 = disabled): `store()` issues a Redis `WAIT`
  after writing a challenge, blocking until at least this many replicas
  acknowledged the record. Without it, an async-replication failover can
  lose the primary's un-replicated records — and after failback, a captured
  token replays against a "fresh" record the new primary never knew was
  consumed. `wait_timeout_ms` (default 100) bounds the WAIT.
- `ttl_margin_secs` (default 0): extra retention on challenge/replay-security
  state BEYOND the token validity window. The consumed-state guards (the
  GETDEL single-use gate, the replayed-token checks) and the challenge
  records themselves must outlive token validity + max clock skew + failover
  margin, or a replayed/expired token can land on state that already expired
  and re-accepted it.

**Operational guidance for the security Redis (mandatory for replay
safety):** the Redis holding challenge/replay-security state (the storage
keyspace plus the outstanding counters, `{kiwi:<ns>}:outstanding:*`) MUST
run with `maxmemory-policy noeviction` and memory alarms (e.g. `used_memory`
> 70% of `maxmemory` paged, plus `evicted_keys` > 0 as a CRITICAL alert).
KiwiCaptcha state is **never a cache with opportunistic eviction**: a
challenge record or consumed-state guard evicted early silently re-enables
replay/stockpiling windows. Size `maxmemory` for the worst case:
`max_outstanding_challenges_global` outstanding records × (record size +
counter overhead), plus the concurrent verification lease sets, plus the
risk-v1 state, with headroom. If eviction is ever observed, treat it as a
security incident, not a capacity event.

### Outstanding-challenge anti-stockpiling

`risk.max_outstanding_challenges` (default 20) and
`risk.max_outstanding_challenges_global` (default 100000) bound the number
of UNSOLVED challenges a single source — and the whole deployment — may
hold at once:

- On issuance, one atomic Lua script checks BOTH counters and refuses
  BEFORE anything is written: the source counter
  `{kiwi:<ns>}:outstanding:<hex>` and the global counter
  `{kiwi:<ns>}:outstanding:global` are incremented with EXPIRE =
  challenge lifetime + `risk.redis.ttl_margin_secs`. The source identity is
  `hex(hmac_sha256(canonical-ip-bytes, RiskKeys::event))` — the raw IP
  never appears in Redis, and the same canonical-IP normalization as the
  challenge binding tag is used.
- Exhaustion returns the standard 429 `RISK_DENIED` response (never a
  CAPTCHA issuance; a minted-but-refused record is discarded server-side).
- A VALID verification decrements the per-source counter (best-effort,
  floored at 0). The GLOBAL counter is deployment-wide and identity-neutral:
  it decays only by EXPIRE.

Bounded memory: an attacker can never stockpile an unbounded number of live
challenges for one source or one deployment — the counters cap the aggregate
outstanding verification work an attacker can hoard.

### Origin laundering defense

- `risk.challenge_origin_allowlist` (default `[]`): when NON-EMPTY, the
  challenge POST must carry an `Origin` header (or a `Referer`-origin
  fallback) whose scheme+host+port EXACTLY matches one allowlisted origin —
  otherwise HTTP 403 `{"error":{"code":"origin_rejected"}}` **before any
  CAPTCHA is issued** (no state written, no rate-limit budget consumed).
  Requests with neither header cannot be matched and are rejected. Exact
  scheme/host/port comparison (host case-insensitive, default ports
  normalized). A launderer framing a victim browser cannot control the
  Origin of a cross-site request; raw HTTP bots without the header are
  rejected too.
- `risk.enforce_fetch_metadata` (default `false`): when true, challenge
  requests whose `Sec-Fetch-Site` header is present and equals `cross-site`
  are rejected with HTTP 403 `{"error":{"code":"CROSS_SITE_REJECTED"}}` — a
  browser-laundering signal. Raw HTTP bots lack the header and are
  unaffected, so this is defense-in-depth only, never the security boundary.

### Argon2 admission wait-queue bound

`argon2_max_waiters` (default 64) bounds the Redis semaphore's waiters
counter (`{..}:sem:waiters`, hash-tagged with the lease set): when the
concurrency cap is saturated, contenders are counted with the lease
lifetime's TTL; once the waiter count EXCEEDS `argon2_max_waiters`,
`acquire()` returns null IMMEDIATELY (CapacityExceeded → the captcha
violation / 429) instead of queueing behind the saturated gate. A waiter is
removed when a lease is granted or the acquire returns null (best-effort,
same Lua). During an Argon2id saturation storm the waiters counter can never
grow unboundedly.

## Usage

### In a Form Type

```php
use BelConsulting\KiwiCaptchaBundle\Form\Type\KiwiCaptchaType;

public function buildForm(FormBuilderInterface $builder, array $options): void
{
    $builder
        ->add('email')
        ->add('password')
        ->add('captcha', KiwiCaptchaType::class, [
            'scope' => 'login', // optional; defaults to 'login'
            'nonce' => $cspNonce, // optional CSP nonce for the inline style/script tags
            'telemetry' => 'off', // optional; defaults to the bundle config (strict: 'off')
        ]);
```

The type renders a hidden `kiwi__token` input; the `KiwiCaptcha` validator
constraint (attached automatically) verifies the token **locally** on submit.
The widget posts to `route_prefix . '/challenge'` by default — the form's
endpoint follows the configured prefix like the standalone widget does — and
stays overridable per form with the `endpoint` option. The telemetry mode is
rendered as `data-kiwi-telemetry` on the widget container (default `off`);
invalid values are rejected by the options resolver.

### Verified-token jti and the (jti, action) idempotency contract

A successful verification exposes the **canonical jti** of the consumed
challenge — `VerifyOutcome::nonce()`, the challenge nonce of the record that
was verified — to the application:

```php
use BelConsulting\KiwiCaptchaBundle\Validator\Constraints\KiwiCaptchaValidator;
use Symfony\Component\HttpFoundation\Request;

// After the form validates (valid captcha):
/** @var Request $request */
$jti = $request->attributes->get(KiwiCaptchaValidator::VERIFIED_JTI_ATTRIBUTE);
```

The same value is available via the validator service's `verifiedJti()`
(non-web contexts). The jti is set ONLY on a successful verification, on the
request's attribute bag — request-scoped and race-free.

**Idempotency contract (audit #37):** the application MUST key its protected
business operation on **(jti, action)** and make it idempotent — a retry
carrying the same jti must never create a second operation. KiwiCaptcha
guarantees each jti verifies at most once (single-use consumption), but the
HTTP request itself can be retried (network retries, double-submits, a
client that received the response but the app crashed before the DB write):
the same token, already consumed, must not be re-solvable — but a retried
request carrying the SAME token/jti reaches the application again. Persist
`(jti, action)` as the idempotency key of the business operation (e.g. a
UNIQUE constraint on the order/password-reset row), and return the stored
result on a duplicate instead of executing the operation twice. The jti is
high-entropy (256-bit random challenge nonce), unguessable, and never reused
across challenges — it is safe to expose in application tables and logs.

### In a Template

Add the form theme to `config/packages/twig.yaml`:

```yaml
twig:
    form_themes:
        - '@KiwiCaptcha/form_div_layout.html.twig'
```

The theme renders the full widget (container + hidden token + inlined CSS,
WASM solver, and driver). No `<link>` or `<script src>` needed — everything
is embedded at render time.

Alternatively, render a standalone widget anywhere. Pass a `nonce` option to
emit CSP-safe markup:

```twig
{{ kiwi_captcha_widget({ 'endpoint': path('kiwicaptcha_challenge'), 'scope': 'login', 'nonce': csp_nonce('script') }) }}
```

With a nonce, the emitted `<style>` and `<script>` tags carry `nonce="..."`;
without one the widget still works under CSP that allows `'unsafe-inline'`,
or where the application post-processes the HTML (as ApexMail does).

**WebAssembly requires `'wasm-unsafe-eval'`** in `script-src` (CSP3) — the
embedded WASM solver is compiled at runtime, which strict policies must
explicitly allow. SHA-256 mode falls back to pure JS when WASM is blocked;
**Argon2id mode requires WASM** (no JS fallback exists for the memory-hard
solver).

Recommended CSP profile:

```
default-src 'self';
script-src 'self' 'nonce-{NONCE}' 'wasm-unsafe-eval';
style-src 'self' 'nonce-{NONCE}';
connect-src 'self';
object-src 'none';
frame-src 'none';
frame-ancestors 'none';
base-uri 'none';
form-action 'self'
```

### Challenge endpoint

The bundle ships `POST /kiwi-captcha/challenge` (prefix configurable via
`route_prefix`), which issues and stores a challenge locally. The widget
fetches it, solves the proof-of-work in the browser, and submits the token.

**Route registration.** The route is **auto-registered**: when the bundle is
enabled and the application has not configured `framework.router` itself, the
extension prepends its routing resource
(`src/Resources/config/routes.php`) as `framework.router.resource`, so the
endpoint works out of the box on a fresh app. The path is built from the
`route_prefix` config option by the bundle's route loader
(`src/Routing/KiwiCaptchaRouteLoader.php`, a `routing.loader`-tagged
`LoaderInterface` implementation) — so the configured prefix changes the
ACTUAL route, not just the widget's requested endpoint.

If your application configures `framework.router` itself (every real
Symfony app does — e.g. the recipe's `config/routes.yaml`), the extension
**never overrides** your router resource. Import the bundle's routes file
manually in your routing config:

```yaml
# config/routes.yaml
kiwi_captcha:
    resource: '@KiwiCaptchaBundle/Resources/config/routes.php'
```

After importing (or auto-registering), the route is available at
`path('kiwicaptcha_challenge')` and responds to `POST`.

**Private JSON responses.** Every response — success, error, 422, 429, 403 —
is a private JSON document:

```
Cache-Control: no-store, private, max-age=0
Pragma: no-cache
Referrer-Policy: no-referrer
X-Content-Type-Options: nosniff
```

Challenge bytes and rate-limit signals are never cached or mirrored, no
referrer leaks from the widget context, and the JSON can never be re-sniffed
as HTML.

**Same-origin enforcement.** When `same_origin_only` is true (default, and
forced under strict), requests whose `Origin` header is not the
application's own origin (scheme + host, constant-time compare) are rejected
with HTTP 403 `{"error":{"code":"CROSS_ORIGIN_DENIED"}}` **before any state
is written** — cross-site abuse and CSRF-style challenge minting are
stopped, and rejected requests consume no rate-limit budget. Requests
without an `Origin` header (same-origin navigation, curl, non-browser
clients) are allowed. The check happens before rate limiting, so an
attacker's cross-origin traffic never pollutes the per-client window.

**Origin laundering + Fetch Metadata (optional).** With a non-empty
`risk.challenge_origin_allowlist` the POST must additionally be attributable
to an allowlisted origin (Origin header or Referer-origin fallback; exact
scheme/host/port) — otherwise HTTP 403 `{"error":{"code":"origin_rejected"}}`
and no CAPTCHA is ever issued. With `risk.enforce_fetch_metadata: true`,
`Sec-Fetch-Site: cross-site` requests are rejected with
`{"error":{"code":"CROSS_SITE_REJECTED"}}` (defense-in-depth; bots without
the header are unaffected). Both checks run before any state is written.

**Outstanding-challenge cap.** `risk.max_outstanding_challenges` /
`risk.max_outstanding_challenges_global` bound the unsolved challenges a
source (or the deployment) may hold; exhaustion returns the standard 429
`{"error":{"code":"RISK_DENIED"}}` — see the anti-stockpiling section above.

**Rate limiting.** Challenge issuance is rate-limited per client IP
(`rate_limit` challenges per `rate_limit_window_secs` sliding window; HTTP
429 with `{"error":{"code":"RATE_LIMITED"}}` when exceeded) and
deployment-wide (`rate_limit_global` per window across ALL clients; HTTP 429
with the distinct `{"error":{"code":"GLOBAL_RATE_LIMITED"}}` code). Three
backends, in priority order:

- **Redis (atomic, cross-worker — the gate).** When a Redis client is
  available (`redis_service`, or `RedisStorage` as the storage backend),
  both windows are enforced by a single Lua script using the Redis server
  clock (`TIME`): per-client and global ZSETs are pruned and checked
  atomically, so all PHP-FPM workers share one consistent window and the
  limit holds under concurrency. Keys:
  `kiwi:rl:client:<namespace>:<hmac>` and `kiwi:rl:global:<namespace>`.
- **PSR-6 pool (shared, best-effort).** `rate_limit_cache` — used when no
  Redis client exists. PSR-6 cannot express an atomic read-modify-write, so
  concurrent requests may briefly exceed the limit — a bound, not a gate.
- **In-memory (per-process).** Single-worker fallback.

All backends use a TRUE sliding window — the state is a set of hit
timestamps pruned on every check, so a burst straddling a window boundary
can never double the rate. **Raw client IPs are never stored**: every key is
a peppered HMAC of the IP (`hash_hmac('sha256', $ip, $pepper)` with
`rate_limit_pepper`, defaulting to the bundle secret), in Redis, the shared
pool, and the in-memory buckets. `rate_limit: 0` and `rate_limit_global: 0`
disable the respective limit; both default to nonzero (10 / 500).

**Argon2id verification concurrency cap.** When `algorithm: argon2id`, the
core `KiwiCaptcha\Verifier` is constructed with a
`KiwiCaptcha\VerificationAdmissionGate` enforcing
`argon2_max_concurrent_verifications` (default 2) concurrent verifications.
The gate is consulted only when the STORED record's algorithm is Argon2id
and only after the cheap validation checks. Two gate backends:

- **Redis-backed admission (cross-worker) — tokenized leases.** When the
  bundle has a Redis client — the `redis_service` config option, or the
  configured storage itself when it is `KiwiCaptcha\Storage\RedisStorage`
  (its client is reused) — the cap is enforced with the audit's
  tokenized-lease design (`src/Security/RedisAdmissionSemaphore.php`): each
  `acquire()` mints a unique 16-byte lease token stored as a sorted-set
  member scored at its expiry (45 s), and `release()` removes EXACTLY that
  token. A stale release — releasing a lease that expired or was already
  released — can never remove a newer lease (ZREM of an absent member is a
  no-op). Expired leases (crashed workers) are reaped by the acquire script.
  The acquire script additionally carries the bounded WAITERS guard
  (`argon2_max_waiters`, default 64): saturated contenders are counted in a
  `{..}:sem:waiters` counter (lease-lifetime TTL, hash-tagged with the lease
  set) and refused immediately once the count exceeds the bound — the
  wait-queue behind a saturated gate can never grow unboundedly (see the
  risk section above).
  For the cap to be an absolute operational invariant, the maximum
  verification request runtime must stay BELOW the lease lifetime
  (`argon2_lease_ms`, default 45000 ms) — otherwise a lease can expire while
  its Argon2 hash is still running and another worker may enter. Example:
  PHP `request_terminate_timeout = 30s` with the default 45 s lease (plus a
  safety margin).
  before admission, so the cap self-heals with no watchdog counter to drift.
  Key: `kiwicaptcha:argon2:leases:<namespace>` (namespace defaults to
  `kernel.project_dir`; sanitized to `[A-Za-z0-9_.-]`).
- **In-process gate (per-process).** Without a Redis client the cap is
  enforced per PHP process (`src/Security/InProcessArgonGate.php`, token-set
  based). Honest caveat: PHP-FPM workers share no memory, so this bounds
  concurrency per worker, NOT per deployment — multi-worker deployments
  without Redis should also limit worker counts and rely on the rate limit
  to bound the inflow; ideally, run Redis and let the bundle use the
  cross-worker gate. Infrastructure-level admission control (e.g. limiting
  concurrent PHP-FPM workers or per-instance request concurrency) remains a
  complementary knob in every case.

Exhaustion fails verification closed as a normal captcha violation (never a
500), and — per the core's one-shot semantics — the challenge record is NOT
burned by a capacity refusal, so the client may retry shortly.

**Trusted proxies.** Both the challenge endpoint and the validator use
`Request::getClientIp()` (the same source), so configure Symfony's
`trusted_proxies`/`trusted_headers` consistently when running behind a
reverse proxy — that is also the IP the challenge binds to when `bind_ip` is
enabled. Never read `$_SERVER['REMOTE_ADDR']` in the application, or IP
binding will mismatch the issued challenge.

For production multi-instance deployments you must provide a **shared**
storage service implementing `KiwiCaptcha\StorageInterface` via the `storage`
config option. Redis-backed storage (`RedisStorage`, atomic single-use via
`GETDEL`, Redis 6.2+) is recommended; the bundle fails fast with a
`LogicException` if `ArrayStorage` is configured outside the test/dev
environment, since it cannot enforce single-use across workers. PSR-6 pools
work but cannot express atomic get-and-delete, so single-use under
concurrency is best-effort (read-then-delete).

## Widget assets

The widget markup/CSS/JS is a **single source of truth** in the Rust
repository. After updating it, re-sync the bundled copies:

```bash
bin/sync-assets.sh
```

## Limitations

1. **Proof of computation, not proof of human.** KiwiCaptcha verifies that a
   client spent CPU time — not that a human did. Any automated client that
   pays the same cost passes.
2. **Telemetry is client-controlled and forgeable.** Input events and
   whatever the widget reports, a custom client can omit or fake. Treat
   telemetry as a supplementary
   signal, never the security boundary. Under strict privacy mode the widget
   collects nothing (`telemetry: off`).
3. **IP binding is best-effort.** IPs legitimately change behind NAT/proxies,
   so a strict binding would reject real users. Operators can disable the
   check entirely (`binding_mode: none` issues challenges with an EMPTY
   binding tag — the core BindingMode is fully wired through the DI layer);
   it is a relay mitigation, not a guarantee.
4. **Server-side timing is a heuristic, off by default.** The
   minimum-duration floor is measured by your server, so a client cannot buy
   its way out of it — but the server clock must be correct, and strict
   privacy mode disables the floor entirely (`min_duration_ms: 0`).
5. **The WASM solver and its JS fallback are open source.** An attacker can
   always write their own solver (or reuse the source). The value is the
   **cost** per attempt, not the impossibility of solving.

## License

MIT — Copyright (c) 2026 Bel Consulting OÜ.

[`kiwicaptcha/kiwicaptcha-php`]: https://github.com/Bel-Consulting-OU/kiwicaptcha
