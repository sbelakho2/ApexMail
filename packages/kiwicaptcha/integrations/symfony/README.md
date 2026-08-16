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
    # argon2_max_waiters: 64             # bounded waiters guard (see below)
    # argon2_max_per_tenant: 8           # PER-SCOPE Argon2 budget: each scope
    #                                    # gets its own lease set in addition
    #                                    # to the global cap (multi-tenant
    #                                    # fairness; audit #47)
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
  deployment-global pressure level, all in Redis via the canonical `risk-v1.lua`
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
    # public_base_url: https://captcha.example.com  # audit #78: the
    #                                               # deployment's PUBLIC
    #                                               # origin from SERVER
    #                                               # CONFIG — the same-
    #                                               # origin check compares
    #                                               # against it, never the
    #                                               # Host header (set it in
    #                                               # production)
    risk:
        enabled: true
        # client_ip_mode: symfony_trusted_proxies  # audit #64: how the
        #                                           # canonical client IP is
        #                                           # derived — Symfony's
        #                                           # trusted-proxy machinery
        #                                           # (ignores forwarding
        #                                           # headers from untrusted
        #                                           # peers) or "direct"
        #                                           # (socket peer ONLY —
        #                                           # forwarding headers are
        #                                           # ALWAYS ignored)
        # trusted_proxies:                          # CIDRs of the trusted
        #     - 10.0.0.0/8                          # reverse proxies
        # reject_ambiguous_forwarding: false        # true = 400
        #                                           # AMBIGUOUS_FORWARDING
        #                                           # when a trusted peer
        #                                           # sends BOTH
        #                                           # X-Forwarded-For and
        #                                           # Forwarded; false = log
        # container_memory_mib: null                # audit #68: readiness
        #                                           # requires concurrency x
        #                                           # the FIXED Argon
        #                                           # verification envelope
        #                                           # (risk.argon_verification_
        #                                           # memory_kib, audit #79)
        #                                           # + 256 MiB headroom <=
        #                                           # budget; null = invariant
        #                                           # skipped (documented)
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
        #                                   # Referer origin when
        #                                   # enforce_origin is false);
        #                                   # everything else gets 403
        #                                   # origin_rejected. Comparison is
        #                                   # STRUCTURED NORMALIZATION:
        #                                   # scheme/host/effective-port,
        #                                   # host lowercased, default ports
        #                                   # normalized (https 443 / http
        #                                   # 80), trailing dots stripped,
        #                                   # IDN -> punycode (ext-intl),
        #                                   # IPv6 kept bracketed —
        #                                   # "https://example.com" matches
        #                                   # "https://example.com:443",
        #                                   # "https://EXAMPLE.COM." and the
        #                                   # IDN/punycode spellings, never
        #                                   # ":444" / "http://" /
        #                                   # "evil-example.com"
        # enforce_origin: false             # true = Origin REQUIRED: missing
        #                                   # or "null" Origin -> 403
        #                                   # origin_rejected even without an
        #                                   # allowlist. Server-to-server
        #                                   # integrations (no Origin) keep
        #                                   # this false — the explicitly
        #                                   # trusted mode
        # enforce_fetch_metadata: false     # reject Sec-Fetch-Site:
        #                                   # cross-site challenge requests
        #                                   # (browser-laundering signal;
        #                                   # defense-in-depth only)
        # request_binding: null             # OPTIONAL STATIC transaction
        #                                   # binding (1..128 chars of
        #                                   # [A-Za-z0-9._:-], audit #96):
        #                                   # signed into every challenge when
        #                                   # the request sends no
        #                                   # request_binding field. For
        #                                   # DYNAMIC per-transaction
        #                                   # bindings the application
        #                                   # supplies one per request (the
        #                                   # widget carries it end-to-end,
        #                                   # see "Transaction binding")
        # health:
        #     enabled: true                 # registers {prefix}/health/live
        #                                   # + /health/ready (rollback-
        #                                   # resistant readiness split)
        # argon_verification_memory_kib: 16384  # audit #79: the FIXED memory
        #                                   # envelope of ALL adaptive Argon
        #                                   # challenges (1024..65536) — the
        #                                   # server verification cost is
        #                                   # bounded by this ONE value;
        #                                   # risk escalates the TARGET
        #                                   # DIFFICULTY, never the memory
        # argon_escalation_target_bits: [1, 4, 8] # audit #79: EXACTLY 3
        #                                   # entries (Argon16/32/64), each
        #                                   # 1..20 — the expected nonce
        #                                   # search space escalation
        # security_epoch_cache_secs: 1      # audit #81: cache of the central
        #                                   # security-policy read (1..30) —
        #                                   # revocation latency is one window
        # security_epoch_max_stale_secs: 60 # audit #108: max-stale FAIL-
        #                                   # CLOSED window (min 10) — past
        #                                   # last_success + window the
        #                                   # validator returns
        #                                   # temporary_unavailable and the
        #                                   # controller refuses issuance 503
        # result_receipt_signing_key: null  # audit #80/#106: OPTIONAL base64
        #                                   # 32-byte Ed25519 seed; when set,
        #                                   # valid verifications export
        #                                   # signed receipts (the HMAC
        #                                   # result verification stays
        #                                   # CENTRAL-ONLY)
        # max_challenges_per_scope_per_minute: 0 # audit #89/#112: per-scope
        #                                   # fixed-window issuance cap
        #                                   # (0 = unlimited); > 0 requires
        #                                   # Redis; the window key carries
        #                                   # hex(hmac_sha256(scope, K_scope))
        #                                   # — the raw scope is never a
        #                                   # Redis key component
        policy_version: 1                  # CHALLENGE security-policy epoch
                                           # (audit #42): signed into every
                                           # issued record and enforced at
                                           # verification — BUMP it to
                                           # immediately invalidate ALL
                                           # outstanding challenges
                                           # (origin/action-policy changes,
                                           # emergency revocation,
                                           # compromised tenant); cosmetic
                                           # changes must NOT bump it.
                                           # Independent of the risk-v1
                                           # contract version.
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
deployment `sha16/18/20` raise the target bits and `argon16/32/64` issue
Argon2id work at the FIXED verification envelope
(`risk.argon_verification_memory_kib`, audit #79 — the memory NEVER
escalates; the target difficulty does, along
`risk.argon_escalation_target_bits` 1/4/8); on an argon2id deployment the
argon actions issue the same envelope and sha actions are no-ops.
`step_up` issues the strongest profile of the configured family — the
bundle cannot perform application-level step-up (MFA), so applications may
also react to the decision themselves.

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

- `wait_replicas` (default 0 = disabled): a Redis `WAIT` follows EVERY
  durability-critical write — challenge issuance (`store()`), the
  pending→consumed transition (`consume()`), and the deterministic-result
  commit (`commitResult()`) — and the acknowledgement count is VERIFIED:
  fewer than the requested replicas acked raises
  `KiwiCaptcha\Storage\ReplicaWaitException` and the operation fails
  closed (`ConsumeIndeterminate` in the verifier, issuance refused — the
  challenge endpoint maps it to a private 503 SERVICE_UNAVAILABLE). A
  configured barrier on a replica-less server fails closed by design — the
  promise is unconditional. Without it, an async-replication failover can
  lose the primary's un-replicated records — and after failback, a captured
  token replays against a "fresh" record the new primary never knew was
  consumed. `wait_timeout_ms` (default 100) bounds the WAIT.
  **Promotion invariant (audit round 15):** `WAIT N` proves that at least
  N replicas acknowledged the write — it does not constrain WHICH
  replicas your failover manager may promote. For replay-safe promotion,
  set the threshold to cover EVERY eligible failover target during the
  challenge lifetime, or configure the failover policy/topology so a
  lagging replica can never be promoted. Without that deployment
  invariant, a promotion can resurrect a consumed record from a stale
  replica.
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

### Origin laundering defense (structured normalization)

- `risk.challenge_origin_allowlist` (default `[]`): when NON-EMPTY, the
  challenge POST must carry an `Origin` header (or a `Referer`-origin
  fallback when `enforce_origin` is false) whose NORMALIZED
  scheme+host+effective-port matches one allowlisted origin — otherwise
  HTTP 403 `{"error":{"code":"origin_rejected"}}` **before any CAPTCHA is
  issued** (no state written, no rate-limit budget consumed). Requests with
  neither header cannot be matched and are rejected. A launderer framing a
  victim browser cannot control the Origin of a cross-site request; raw
  HTTP bots without the header are rejected too.
  **Structured normalization (audit #43)** — both sides of the comparison
  are canonicalized component-wise: scheme lowercased; host lowercased with
  the trailing dot stripped and IDN converted to punycode when ext-intl is
  available; the effective port defaulted per scheme (https 443, http 80);
  IPv6 literals kept bracketed. So `https://example.com` matches
  `https://example.com:443`, `https://EXAMPLE.COM`, `https://example.com.`
  and the `https://bücher.example` / `https://xn--bcher-kva.example`
  spellings — but never `https://example.com:444`, `http://example.com`,
  `https://evil-example.com` or `https://example.com.evil.com`.
- `risk.enforce_origin` (default `false`): when TRUE, a request WITHOUT an
  `Origin` header — or carrying the literal `"null"` Origin (opaque/
  sandboxed origins) — is rejected with 403 `origin_rejected` even when the
  allowlist is empty; with an allowlist the required Origin must additionally
  be allowlisted. **Server-to-server integrations** (raw HTTP, no Origin)
  MUST keep `enforce_origin: false` — that is the explicitly trusted mode
  (the Referer-origin fallback or no check at all).
- `risk.enforce_fetch_metadata` (default `false`): when true, challenge
  requests whose `Sec-Fetch-Site` header is present and equals `cross-site`
  are rejected with HTTP 403 `{"error":{"code":"CROSS_SITE_REJECTED"}}` — a
  browser-laundering signal. Raw HTTP bots lack the header and are
  unaffected, so this is defense-in-depth only, never the security boundary.

### Security-policy epoch (emergency revocation)

`risk.policy_version` (default **1**, min 1) is the CHALLENGE security-policy
epoch (audit #42): the core Issuer signs it into every issued challenge
record, and the core Verifier — constructed with
`expectedPolicyVersion = risk.policy_version` — rejects any record whose
epoch differs (`WrongPolicyVersion`, collapsed to `invalid_or_expired` by
the validator). **Bumping it immediately invalidates ALL outstanding
challenges** — the emergency-revocation knob for origin/action-policy
changes, a compromised tenant, or a protocol incident. Cosmetic
configuration changes must NOT bump it (every bump forces every live
visitor to re-solve). It is independent of the risk-v1 contract version
(which stays internal to the risk package) and of the readiness
`min_policy_epoch` (see "Health endpoints" below).

### Bounded-revocation-latency security epoch (audit #81)

A redeploy is NOT required to revoke: the bundle's `SecurityEpochMonitor`
reads the CENTRAL policy hash `{kiwi:<ns>}:security-policy`'s
`min_policy_epoch` field — the same key the readiness probe consults — with
a SHORT cache (`risk.security_epoch_cache_secs`, default 1 s, 1..30) and
feeds the verifier's expected epoch PER VERIFICATION, so a central bump
revokes outstanding challenges within one cache window on every running
node. Three hardening properties:

- **MONOTONIC max** — once a node observes epoch N it never accepts a lower
  epoch, even if the central value regresses (a misconfigured rollback of
  the policy hash must not silently re-validate revoked challenges). The
  observed max lives in-process on each node.
- **Fail-safe on Redis failure** — when the central read fails (Redis down,
  timeout), the monitor serves the LAST OBSERVED max: the newest epoch ever
  seen stays enforced, never a weaker one.
- **Bounded latency** — the central value is re-read at most once per cache
  window; revocation latency is one TTL, never unbounded.
- **MAX-STALE FAIL-CLOSED (audit #108)** — `risk.security_epoch_max_stale_secs`
  (default **60** s, min 10 s) bounds how long a node may serve from a
  cached read: once `now > last_successful_read + max_stale`, the monitor
  reports stale — the cached epoch may be outdated (an emergency revocation
  could have landed while the node could not read). A stale monitor fails
  CLOSED on both sides: the validator returns the distinct
  `temporary_unavailable` violation (the token is NOT burned — retryable,
  never `invalid_or_expired`) and the challenge controller refuses issuance
  with HTTP 503 `{"error":{"code":"SERVICE_UNAVAILABLE"}}`. The availability
  trade-off is deliberate and documented: within the window a bounded Redis
  outage keeps serving the cached max; past it the node stops issuing and
  stops verifying rather than trusting a potentially-revoked cache forever.
  A deployment WITHOUT a security Redis client (no central state by design)
  is never stale — the configured epoch is authoritative.

The effective epoch is `max(risk.policy_version, observedCentral)` — the
local configuration is the floor (a node's own challenges must verify), and
the central value only ever raises it. The readiness gate keeps a binary
whose configured epoch is behind the central value out of the pool, so a
serving node's floor is always >= the central value. Operation:

```bash
# Emergency revocation WITHOUT a redeploy: bump the central epoch (the
# nodes observe it within `security_epoch_cache_secs` and start rejecting
# every pre-bump challenge).
redis-cli HSET "{kiwi:<namespace>}:security-policy" \
    min_protocol_version 2 min_policy_epoch 2
```

(The issuance side must then ALSO bump `risk.policy_version` before new
challenges are minted — the monitor revokes OLD challenges; the issuer
stamps the NEW epoch.)

### Asymmetric result receipts (audit #80/#106)

**The result verification itself is CENTRAL-ONLY by design: the HMAC secret
never leaves the server**, so no third party can ever re-derive a
verification result on its own. For EXPORTED results the bundle adds an
OPTIONAL **Ed25519 receipt signer**: configure
`risk.result_receipt_signing_key` (base64 32-byte Ed25519 seed — generate
with `sodium_crypto_sign_seed_keypair()` and export the seed); on every
VALID verification the validator then signs the canonical receipt from the
CONSUMED RECORD's own fields — the FULL REPLAY-CRITICAL SET (audit #106):

```json
{"jti":"<challenge nonce>","tenant":"<scope>","action":"sha256|argon2id","request_binding":"<signed binding|null>","issued_at":<epoch seconds>,"expires_at":<epoch seconds>,"issuer":"<deployment issuer|null>"}
```

with `sodium_crypto_sign_detached` and exposes it via
`KiwiCaptchaValidator::verifiedReceiptPayload()` (the exact signed JSON) and
`KiwiCaptchaValidator::verifiedReceiptSignature()` (base64 64-byte detached
signature). The payload is public by construction — jti, tenant (the flow
scope), action (the PoW algorithm the challenge required),
request_binding, issued_at/expires_at (epoch seconds — the record wire
unit) and issuer; no secret material. Customers verify with the PUBLIC
key — never the private seed:

```php
// Hand the customer ONLY the public key:
$publicKey = (new ResultReceiptSigner($seedBase64))->publicKeyBase64();
// Customer-side verification (the seed must never leave the server):
sodium_crypto_sign_verify_detached(
    base64_decode($signature),
    $payload,
    base64_decode($publicKeyBase64),
);
```

**SINGLE-USE SEMANTICS (audit #106): signature verification alone is NOT
sufficient for single-use actions.** A valid signature proves the payload
was signed by the server — it does NOT prove the jti has not already been
consumed elsewhere (the receipt is an EXPORT, the consumption happened at
the verifying server). An integrator accepting a receipt for a one-time
action MUST additionally record the jti atomically and treat a pre-existing
jti as a replay — the recommended primitive:

```sql
-- verify_and_consume: FIRST verify the signature + freshness (now <=
-- expires_at), THEN atomically insert the jti. Only a FIRST insert may
-- proceed with the action; a duplicate jti is a replay.
INSERT INTO captcha_receipts (jti, tenant, action, binding, received_at)
VALUES (:jti, :tenant, :action, :binding, NOW())
ON CONFLICT (jti) DO NOTHING
RETURNING jti;          -- NULL row = the jti was already consumed
```

(Redis equivalent: `SET captcha:receipt:<jti> 1 NX EX <ttl>` — nil reply =
already consumed.) Verify the signature FIRST, then attempt the atomic
insert, and only execute the protected action when the insert succeeded:
**verify_and_consume**. Key the idempotency table on the jti alone (it is
high-entropy, 256-bit random, never reused); `tenant`/`action`/
`request_binding`/`expires_at` are the additional binding and freshness
checks the payload now carries. Without the key, both accessors stay
`null`; a failed verification never produces a receipt.

### Fixed Argon verification envelope (audit #79)

**The adaptive risk engine never increases the SERVER verification cost as
its difficulty mechanism.** All three adaptive Argon actions
(Argon16/32/64) issue challenges at the SAME server-controlled memory
envelope — `risk.argon_verification_memory_kib` (default **16384** KiB,
1024..65536, t=3, p=1) — so the per-verification memory cost is bounded by
one value regardless of the risk decision. Risk escalates the TARGET
DIFFICULTY (the expected nonce search space), not the memory:
`risk.argon_escalation_target_bits` (EXACTLY 3 entries, each 1..20,
default `[1, 4, 8]`) maps Argon16 → 1, Argon32 → 4, Argon64 → 8 leading
zero bits. Argon target bits are additionally capped by the core's
browser-solvable ceiling (`Config::MAX_ARGON2_TARGET_BITS` = 10) at
issuance. Consequence for capacity planning: the worst-case per-verification
memory of the risk ladder IS the envelope — the readiness memory-budget
invariant (`risk.container_memory_mib`) uses the configured envelope, and
`argon2_max_concurrent_verifications × envelope + headroom` is the honest
ceiling. (The SHA ladder already escalates bits on a fixed SHA cost — no
change.)

### Per-scope issuance cap (audit #89/#112)

`risk.max_challenges_per_scope_per_minute` (default **0** = unlimited):
when > 0, a Redis fixed-window counter
`{kiwi:<ns>}:issuance:<hex(hmac_sha256(scope, K_scope))>:<minute>` — INCR +
EXPIRE 60 in ONE atomic Lua script — bounds how many challenges a scope may
issue per minute; the controller denies HTTP 429
`{"error":{"code":"SCOPE_LIMITED"}}` beyond the cap, BEFORE any challenge is
minted. The public site key + claimed origin can therefore no longer create
unlimited billed verification work per scope. **The RAW SCOPE STRING IS
NEVER A REDIS KEY COMPONENT (audit #112):** the scope is attacker-controlled
(bounded alphabet `[A-Za-z0-9._:-]{1,128}`, unbounded cardinality), so the
window key carries the keyed pseudonym `hex(hmac_sha256(scope, K_scope))`
where `K_scope = hash_hkdf('sha256', master, 32, 'kiwi/v2/scope-rate')`
derived from the risk master (`risk.master_secret`, falling back to
`secret_key`) — purpose-separated from the risk identity keys, identical
across the bundle and the risk package's calibration scope keys. Each scope
gets an independent window; a Redis failure propagates (fail closed — no
challenge without a checked scope bound), and the config is refused at
compile time when no Redis client is available. The minute is derived from
the Redis server clock so all workers share one window.

### Sitekey publicity (audit #82)

**No client-visible identifier confers any privileged capability.** The
bundle defines three strictly separated credential classes:

1. **Public site identifier** — the challenge/verify surface is fully
   public by design: `POST {prefix}/challenge` succeeds with NO identifier
   at all, and the bundle's route surface is exactly challenge + health
   (there is no admin route that could be keyed off a client-supplied
   value). A payload carrying a `site_key`/`api_key`/`secret`-style field is
   refused as an unknown-field probe (422 `UNKNOWN_FIELDS`, audit #72) —
   client-supplied identifiers are never accepted, so none can be abused.
2. **Server API credential** — `kiwi_captcha.secret_key` (and
   `risk.master_secret`, `rate_limit_pepper`) signs/verifies challenges and
   derives every keyed pseudonym. It must live ONLY in server
   configuration/environment; the widget never receives it.
3. **Admin + control-plane** — the security Redis (policy hash, calibration
   state) and the deployment secrets are control-plane material with
   independent privileges: read vs write roles, scoped machine credentials,
   audit logging (see "Control-plane threat model" below). No component of
   the client-facing protocol can reach this plane.

### Identifier validation (audit #96)

Scope/tenant identifiers and request bindings are validated against
`[A-Za-z0-9._:-]+` with the 128-char ceiling BEFORE they reach the issuer —
separator, control and out-of-charset bytes can never be signed into a
challenge record (scope: 422 `INVALID_SCOPE`; binding: 422
`INVALID_REQUEST_BINDING`). The static `risk.request_binding` is validated
against the same charset at COMPILE time. The verification side enforces
exact equality between the signed record values and what the final POST
carries, so a challenge minted under a valid identifier is never redeemable
under a different one.

### HTTP framing (audit #83)

The challenge endpoint rejects request-smuggling ambiguity BEFORE any body
is read: a request carrying BOTH `Content-Length` and `Transfer-Encoding`
— or a DUPLICATE `Content-Length` (two values) — is refused with HTTP 400
`{"error":{"code":"FRAMING_REJECTED"}}`. Symfony's `HeaderBag` keeps every
raw header value, so a crafted duplicate survives into the controller; at
the wire level the PROXY STACK must reject the ambiguity first:

- **nginx** — reject requests carrying both framing families, a duplicate
  `Content-Length`, or `Transfer-Encoding` + `Content-Length` (the classic
  CL.TE / TE.CL smuggling combos); reject `Transfer-Encoding` with
  anything but `chunked`; disallow request `Trailer` headers unless you
  actually process chunked trailers; on ANY framing ambiguity respond 400
  AND close the connection (`Connection: close` — never reuse a connection
  whose framing was ambiguous):

  ```nginx
  # Reject CL+TE / duplicate CL / trailers before the app sees them
  server {
      # exact-match rejections first
      if ($http_transfer_encoding) {
          if ($http_content_length) { return 400; }        # CL + TE
          if ($http_transfer_encoding != "chunked") { return 400; }
      }
      if ($http_trailer) { return 400; }                    # trailers
      # Duplicate Content-Length is normalized away by nginx itself
      # (it keeps the first and logs a warning) — upgrade to a recent
      # nginx that REJECTS duplicates outright, or check via a Lua
      # module / WAF.
      ...
  }
  ```

  (Prefer `nginx`'s native duplicate-CL rejection: modern nginx refuses
  requests whose duplicate `Content-Length` headers disagree; test your
  version. A WAF rule that matches a raw duplicate `Content-Length` is the
  portable fallback.)

- **Body ceiling at the edge (audit round 14):** the controller refuses
  challenge bodies over 8 KiB (413 `BODY_TOO_LARGE`; declared
  Content-Length is rejected before any body is read, and the read length
  is capped for chunked uploads). Mirror the same cap in the proxy so the
  bytes never reach PHP at all:

  ```nginx
  location /kiwi-captcha/challenge {
      client_max_body_size 8k;   # challenge bodies are tens of bytes
      limit_except POST { deny all; }
      ...
  }
  ```

  For Apache: `LimitRequestBody 8192` on the location; for Envoy:
  `max_request_bytes: 8192` in the HTTP connection manager; for
  CloudFront/ALB: the request size limits / WAF `Body` size rule.
- **AWS ALB / NLG** — ALB rejects requests with both `Content-Length` and
  `Transfer-Encoding` (400) and requests with conflicting duplicate
  `Content-Length` values; identical duplicates are tolerated by some
  versions — add a WAF rule (`AWSManagedRulesCommonRuleSet` /
  `CrossSiteScripting` / a custom regex on the raw header) if you need
  strict rejection.
- **General rule** — on any framing ambiguity: 400, `Connection: close`,
  log the peer. NEVER let a downstream layer (PHP-FPM, proxy) pick one
  interpretation and continue.

### Canonical request targets (audit #99)

The challenge endpoint serves ONE canonical path
(`{route_prefix}/challenge`, a fixed ASCII target). The controller rejects
any NONCANONICAL request target — measured on the RAW REQUEST_URI, never a
normalized route — with HTTP 404
`{"error":{"code":"CANONICAL_PATH_REQUIRED"}}` BEFORE any handling:

- empty segments: `/kiwi-captcha//challenge`, `/challenge/` (trailing slash);
- dot segments: `/./challenge`, `/foo/../challenge`;
- percent-encoded bytes: `/%76hallenge` (encoding of the first path byte),
  `%2F`/`%5C` (encoded separators), double encodings — the canonical path
  is pure ASCII, so ANY `%` in the path is a probe;
- backslashes (Windows path separators on some stacks).

The bundle never redirects, rewrites or normalizes a noncanonical target —
the typed target does not exist on this server. **The proxy stack must
reach the same decision at the edge — prefer rejecting there too**, so the
noncanonical bytes are dropped before they consume application resources:

```nginx
# nginx: reject noncanonical request targets before routing
if ($request_uri ~ "(//|/\./|/\.\./|%[0-9a-fA-F]{2}|\\\\)") { return 404; }
# (an even stricter posture: 404 any path containing '%' at all)
```

AWS ALB / CloudFront: add a WAF rule matching the same patterns on the
request URI (and consider rejecting any `%` in the path — the challenge
path is fixed ASCII). The controller-level check is the SECOND layer for
direct invocations and for proxies that normalize; the edge rejection is
the first.

### Duplicate security-singular headers (audit #100)

Origin, Forwarded, X-Forwarded-For and X-Real-IP are SECURITY-SINGULAR
headers: each carries identity or forwarding trust and MUST appear at most
once. A duplicate occurrence is parser ambiguity — one intermediary trusts
the first value, another the last, so the same-origin check and the
client-IP resolution would disagree — and the challenge endpoint refuses it
with HTTP 400 `{"error":{"code":"DUPLICATE_HEADER"}}` before any
header-derived identity is trusted (the client-IP resolver treats a
duplicate as ambiguous; the controller rejects it earlier, so the resolver
is never consulted with one). The count is value-agnostic: two IDENTICAL
values are still a duplicate. Symfony's `HeaderBag` keeps every raw value,
so HTTP/1.1-style multi-line duplicates survive into the controller; at the
wire level the proxy should also refuse them (most servers collapse
duplicates — verify with a raw-socket test; a WAF rule on the raw headers
is the portable fallback).

### Transaction binding (audit #41)

A challenge can be bound to ONE application transaction: the issuing side
signs a `request_binding` (1..128 chars of `[A-Za-z0-9._:-]`, audit #96)
into the record, and verification only accepts the solve when the final
POST presents the SAME binding — a challenge minted for one transaction is
never redeemable for another. The widget carries the binding end-to-end.
**The binding is ALWAYS server-originated in the bundle (audit #107): the
widget driver never generates a binding of its own** — the rendered widget
container carries exactly the value the backend rendered, nothing else.

TWO BINDING MODES (audit #107):

1. **Client-chosen binding (public, basic anti-abuse).** The application
   lets the CLIENT choose the binding — e.g. a per-page random nonce the
   page JavaScript generates and passes to the widget. This is fine for
   basic anti-abuse (it proves the browser chose a nonce and carries it
   back), but the binding is client-controlled: it proves nothing about a
   trusted backend decision. Suitable when the binding is a transaction
   correlation tag, not an authorization signal.
2. **BACKEND-ORIGINATED binding (the recommended sensitive-flow mode).**
   The application backend renders the binding server-side from a
   `flow_id` stored server-side: the Symfony form type's `request_binding`
   option (or the static `risk.request_binding` config, or a per-render
   `request_binding` passed to the standalone widget) carries a value the
   backend itself issued — a flow/session identifier the backend created
   and persists. The widget renders that value and only ever forwards it;
   the verification side enforces it against the signed record. A binding
   minted by the backend (and stored server-side) can be checked against
   the backend's own flow state after verification — a client can never
   invent a binding the backend did not issue.

- **Config** — `risk.request_binding` sets a STATIC binding used whenever
  the request sends no `request_binding` field (e.g. server-side
  integrations). For DYNAMIC per-transaction bindings (recommended: a
  backend-issued `flow_id` nonce per page load) the application supplies
  the value per request/form:
  - `KiwiCaptchaType` option `'request_binding' => $flowId` (defaults to the
    static config) → rendered as `data-kiwi-request-binding` on the widget
    container;
  - the standalone widget accepts `'request_binding'` in the
    `kiwi_captcha_widget({...})` context.
- **Widget flow** — the driver reads `data-kiwi-request-binding`, includes
  `request_binding` in the challenge POST body (the controller validates
  1..128 chars of `[A-Za-z0-9._:-]` — audit #96 — 422
  `INVALID_REQUEST_BINDING` otherwise, then
  passes it to the core Issuer, which signs it into the record), and — on a
  successful solve — creates the hidden `kiwi_request_binding` input in the
  form, next to the token input. The driver contains NO binding-generation
  code (no `crypto.randomUUID`-style synthesis — pinned by test): the
  rendered container carries ONLY the server-provided binding.
- **Verification** — after a VALID verification, the validator compares the
  consumed record's signed binding against the request binding. The
  application controller copies the POSTed field into the request attribute
  before validating:

  ```php
  $request->attributes->set(
      KiwiCaptchaValidator::REQUEST_BINDING_ATTRIBUTE,
      (string) $request->request->get('kiwi_request_binding'),
  );
  $form->handleRequest($request);
  ```

  (The validator also falls back to the raw POSTed `kiwi_request_binding`
  field, so the plain widget flow works without the shim.) A bound record
  with a missing or mismatched binding fails with the SAME
  `invalid_or_expired` violation — no jti is exposed, the solve is burned
  (single-use), and the client re-solves. An UNBOUND record skips the check
  entirely. The verified binding is exposed via
  `KiwiCaptchaValidator::verifiedRequestBinding()`
  (`VerifyOutcome::requestBinding()`).

### Ambiguous-consume deterministic retry (audit #74)

The storage's `consume()` is a consumed-state TRANSITION: records persist
until their TTL with a `state` / `consumed_result`, and the verifier commits
the derivation outcome (`commitResult(nonce, valid, binding)`). A re-verify
of a consumed record WITH a stored result returns the SAME outcome WITHOUT
re-deriving; WITHOUT a stored result it returns `ConsumeIndeterminate`. The
validator resolves both cases deterministically:

- **Stored-result retry (a lost response, same binding):** a re-submission
  of the same token with the SAME request binding returns the SAME success —
  the canonical jti (`verifiedJti()`) and the stored signed binding
  (`verifiedRequestBinding()`) are exposed, no second derivation happens
  (assertable via the storage counters: no second consume/commit), and no
  side effects repeat (risk feedback, post-solve assessment, outstanding
  decrement all ran exactly once on the original verification).
- **Stored-result retry, DIFFERENT binding:** `invalid_or_expired` — a
  challenge bound to one transaction is never redeemable for another,
  retries included (the round-9 binding rule applied to the retry).
- **Stored INVALID result:** `invalid_or_expired` — the original derivation
  failed; its outcome is authoritative.
- **Consumed without a committed result** (the original attempt died
  mid-proof) **or a still-pending record** (the consume never landed) **or
  no storage wired:** the outcome stays indeterminate and collapses to the
  DISTINCT public code `temporary_unavailable` — retryable, never a guessed
  success, never `invalid_or_expired` (the client must not be told its
  token is burned when it may still redeem). A retry after recovery consumes
  and derives exactly once.

The validator's resolution reads the consumed state from the STORED RECORD
(`ChallengeRecord::$consumed` / `$consumedResult` / `$consumedBinding` — the
round-10 core fields; the bundle probes them defensively, so cores predating
the transition keep the legacy behavior: an ambiguous consume stays
`temporary_unavailable` and a retry burns nothing).

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

### Per-scope Argon2 fairness (audit #47)

`argon2_max_per_tenant` (default 8, min 1) gives every SCOPE string its own
Argon2id admission budget: the semaphore checks a per-scope lease set
(`{kiwicaptcha:argon2:leases:<ns>}:<scope>`) IN ADDITION to the global
`argon2_max_concurrent_verifications` cap. One busy scope (tenant/endpoint
mapped to a scope) can fill its own budget without starving the other
scopes' share of the memory-hard capacity, while the global cap stays the
deployment-wide memory invariant. The validator passes the constraint scope
into `acquire()` (via the request-scope-aware gate wrapper); the waiters
guard stays global. The in-process fallback gate has no per-scope budget
(per-process, single-worker best-effort).

### Health endpoints (rollback-resistant readiness)

`risk.health.enabled` (default true) registers two GET endpoints under the
route prefix:

- **`{prefix}/health/live`** — ALWAYS 200 while the process runs. Never tied
  to saturation, Redis, or policy state: the orchestrator only learns
  "process up" vs "process gone".
- **`{prefix}/health/ready`** — 200 ONLY when:
  1. the issuer/verifier signing keys are configured (the bundle secret);
  2. the security Redis answers a PING (probe cached ~1 s in-process;
     TRANSIENT probe timeouts never fail readiness on their own — the first
     failure is debounced for one cache window, two consecutive failures
     flip readiness);
  3. the CENTRAL security-policy state is compatible: the Redis hash
     `{kiwi:<ns>}:security-policy` (fields `min_protocol_version`,
     `min_policy_epoch`) — when PRESENT, ready requires
     `min_protocol_version <= 2` (this binary's max protocol) AND
     `min_policy_epoch <= risk.policy_version`; when ABSENT, the binary's
     own configuration is authoritative;
  4. the MEMORY-BUDGET invariant holds (audit #68, only when
     `risk.container_memory_mib` is configured):
     `argon2_max_concurrent_verifications × the FIXED Argon verification
     envelope (risk.argon_verification_memory_kib — the risk ladder's
     worst-case per-verification memory, audit #79; default 16384 KiB) +
     256 MiB headroom <= container_memory_mib`.
     A violated invariant refuses startup (503
     `memory_budget_invariant`): a container that cannot hold the
     worst-case memory-hard verification load plus headroom must not serve
     traffic (an OOM mid-hash is a security failure, not just an
     availability one). When `container_memory_mib` is null (default) the
     check is SKIPPED — document this in your deployment; with a concurrency
     cap of 0 (= unlimited) the invariant uses 1 hash (only the headroom is
     guaranteed — set a finite cap for a meaningful check).

Argon queue fullness and transient timeouts NEVER fail readiness. All
responses carry `Cache-Control: no-store` + `Pragma: no-cache`.

**Operator contract (mixed-version deployments):** set the policy hash on
the security Redis to keep OLD binaries out of the pool during a rolling
upgrade, and to protect ROLLBACKS after a protocol/policy bump:

```bash
# The fleet is moving to protocol v2 / policy epoch 2: old binaries
# (max protocol 1, or policy_version 1) must not serve traffic.
redis-cli HSET "{kiwi:<namespace>}:security-policy" \
    min_protocol_version 2 min_policy_epoch 2
```

A binary whose max protocol or configured `risk.policy_version` is below
the hash exits readiness (503) and is drained by the load balancer BEFORE it
can issue or verify challenges it cannot honor. Remove the key (or lower
the fields) only after every node runs a compatible binary. When the key is
absent, every binary's own configuration is authoritative (the pre-round-9
behavior).

## Operational deployment guidance

**Disable TLS 1.3 0-RTT (early data) for the verification surface (audit
#61).** TLS 1.3 0-RTT replays the client's first flight: a captured
challenge-verify request (the form POST carrying the solution token, and
the Rust service's `/verify` + `/redeem` paths) can be replayed verbatim to
the server. KiwiCaptcha's token is single-use — the FIRST 0-RTT replay wins
the consume and the application's own operation must be keyed on the
(jti, action) idempotency — but the replay can still burn the solve and
create duplicate first-flight work. Disable early data for every endpoint
that receives solution tokens or result tokens:

```nginx
# nginx: no early data for the challenge/verify surface
server {
    listen 443 ssl;
    ssl_early_data off;               # TLS 1.3 0-RTT disabled
    ...
}
```

On Cloudflare: turn **0-RTT (TLS 1.3)** OFF for the host(s) that serve the
captcha endpoints (SSL/TLS settings), or configure a WAF rule that strips
`Early-Data: 1` from verification requests. The challenge-ISSUANCE endpoint
and the health probes are also better off with 0-RTT off (their responses
are never cached and replays only waste work), but the /verify + /redeem
equivalents are the ones that MUST be 0-RTT-free.

**Autoscale on ADMITTED demand, never raw hostile CPU (audit #69).** Scale
the captcha workers on the admission-side metrics, not on CPU: the
deployment-wide issuance rate (the `{kiwi:<ns>}:issuance:<second>` counter
the controller increments on every MINTED challenge — exposed via the
resource-pressure provider / Redis) and the outstanding-challenge pressure
are the honest demand signals. A hostile flood that is being DENIED (rate
limiter, risk engine, emergency cap) must not trigger scale-up — those
requests never mint and never consume verification CPU on the workers.
Concretely:

```yaml
# HorizontalPodAutoscaler (Kubernetes): scale on ADMITTED issuance demand
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: kiwicaptcha
spec:
  maxReplicas: 12            # hard cost ceiling — NEVER unbounded
  metrics:
    - type: External
      external:
        metric:
          name: kiwicaptcha_issued_per_second   # admitted minted challenges
        target:
          type: Value
          value: "400"        # ~1 worker per 400 issued/s (per worker cap)
```

Pair the scale-down with COST alarms: `maxReplicas` is the budget ceiling,
and CloudWatch/GCP cost alerts on the replica count and on the security
Redis connections keep a demand spike from silently multiplying cloud cost.
Never autoscale on raw CPU alone: Argon2id verification is CPU-bound, so
hostile traffic that reaches the verifier (e.g. a replay storm) pushes CPU
while being refused — CPU-only scaling amplifies the attack's cost instead
of containing it.

**Issuer identity / public origin come from SERVER CONFIG, never the Host
header (audit #78).** The deployment's public origin is `public_base_url`
(see "Same-origin enforcement" above); the issued records carry NO
Host-derived material. If your infrastructure terminates TLS and rewrites
Host headers (shared hosting, multiple vhosts on one pool), set
`public_base_url` explicitly — the same-origin check then ignores whatever
Host the request carries.

### QUIC IP migration policy (audit #92)

HTTP/3/QUIC clients legitimately change source IPs mid-session (connection
migration, NAT rebinding, cellular handover). The bundle's documented
policy — and its actual behavior — is:

- **Exact IP** → normal verification (the nonce-bound binding tag matches).
- **Same network** (same /24 IPv4 or /56 IPv6 cohort) → acceptable, WITH a
  risk penalty: the risk engine's SUBNET dimension is exactly this signal —
  the migrated source scores through the subnet pseudonym while the source
  pseudonym changes, so the engine tightens difficulty instead of refusing.
- **Different network** → treat as a fresh visitor: the strict binding
  rejects the solve (the test suite documents the `IpMismatch` behavior —
  the challenge is burned single-use), and the client re-solves; the
  application should additionally require a stronger
  `request_binding`/session check for high-value scopes.
- **Mobile clients** → prefer `request_binding` (a per-page nonce bound to
  the transaction, immune to IP changes) over IP binding; keep
  `binding_mode` strict for desktop/relay-mitigation posture and let the
  binding mismatch drive the documented re-solve path.

**The strict binding stays**: a challenge bound to IP A verified from IP B
fails closed (`IpMismatch` at the core, collapsed to `invalid_or_expired`
by the validator) — the binding tag is a nonce-bound HMAC, never a stable
IP-derived identifier, so the check is relay-mitigation, not a privacy
leak. The QUIC policy above is the OPERATOR's deployment policy (which
scopes bind, when to step up), implemented with the existing knobs; the
protocol's fail-closed behavior is unchanged and documented by test.

### Control-plane threat model (audit #90)

The captcha control plane — the security Redis (central policy hash,
calibration state, admission leases), deployment secrets, and the bundle
configuration surface — is a separate trust domain from the public
challenge/verify surface. Requirements:

- **MFA + scoped machine credentials** — every human and service principal
  reaching the control plane authenticates with MFA; machine credentials
  are per-role (a calibration reader must not be able to bump the policy
  epoch), short-lived, and rotated.
- **Read/write roles** — split readers (metrics, calibration sampling,
  audit review) from writers (policy hash, calibration confirmations,
  lease state). No client-facing component holds a writer role.
- **Audit log with change attribution** — every control-plane mutation
  (policy-hash bumps, calibration corrections, config changes, credential
  rotation) lands in an append-only audit log carrying WHO, WHAT, WHEN and
  the PREVIOUS value; mutations without attribution are treated as an
  incident.
- **High-signal alerts** — alert specifically on: policy-hash
  `min_policy_epoch`/`min_protocol_version` changes (emergency revocation
  is a rare, sensitive act), origin-allowlist / `public_base_url` changes,
  legacy-protocol acceptance flips, difficulty/`argon_verification_memory_kib`
  changes, and any credential rotation outside the change window. These are
  the few control-plane actions that can silently weaken the captcha
  boundary; everything else is routine.

### HTTP/2/3 transport limits at the ingress (audit #84/#85)

HTTP/2 and HTTP/3 connection multiplexing removes the classic per-IP
connection limit, so the transport limits MUST be enforced at the ingress
BEFORE the application: per-IP connection caps, per-connection stream caps,
header-size ceilings and per-connection request rates. Example nginx:

```nginx
http {
    # per-IP connection budget (HTTP/1.x + HTTP/2)
    limit_conn_zone $binary_remote_addr zone=kiwi_conns:10m;
    limit_conn kiwi_conns 32;

    # per-IP request rate (applies to every connection incl. h2 streams)
    limit_req_zone $binary_remote_addr zone=kiwi_req:10m rate=50r/s;
    limit_req zone=kiwi_req burst=100 nodelay;
}
server {
    listen 443 ssl http2;
    http2_max_concurrent_streams 16;   # per-connection stream cap
    http2_max_header_size 8k;          # header bytes per request
    http2_max_field_size 4k;
    client_header_buffer_size 4k;
    large_client_header_buffers 2 8k;
    # h3 (QUIC) equivalents: http3_max_concurrent_streams,
    # http3_max_header_size (nginx + quiche builds)
}
```

The challenge/verify surface should ALSO cap request bodies
(`client_max_body_size 16k` — the JSON documents are tiny) and keep
`keepalive_timeout` modest. ALB: connection idle timeout + the WAF rate
rules per source IP. The bundle's own rate limiters (per-IP issuance,
per-scope issuance, process emergency cap) are the SECOND layer — the
ingress caps exist so a single source can never saturate a worker's
connection/stream/header budget before the app's logic runs.

### Graceful shutdown sequence (audit #93)

The deployment must drain verification work, not kill it mid-hash. The
documented sequence: **SIGTERM → readiness false → stop accepting new
connections → drain RUNNING KDF work → complete/rollback leases → flush →
terminate**. Concretely:

1. `SIGTERM` → the pod sets `/health/ready` to 503 (readiness probe fails;
   the load balancer stops routing NEW requests) and stops accepting new
   connections (preStop hook / LB deregistration delay).
2. DRAIN: in-flight verification requests — including memory-hard Argon2id
   hashes that are already running — complete. The admission-gate LEASES
   held by these requests are released on completion (release() in the
   verifier's finally block); a request killed mid-hash leaks its lease,
   which is recovered by the lease TTL (`argon2_lease_ms`) — the drain
   window must therefore exceed the maximum KDF runtime plus the lease
   safety margin.
3. FLUSH: pending rate-limit/issuance/outstanding counter writes are
   best-effort (the Redis side is authoritative); the process exits after
   the drain window.
4. TERMINATE: the orchestrator's terminationGracePeriod must be
   `max-KDF-runtime + lease margin + LB-drain + headroom` — if the worker
   is killed BEFORE a running KDF finishes, the lease TTL recovery is the
   safety net (never a correctness hole: a mid-hash request returns 5xx and
   the client retries; the challenge is still pending until its TTL).

### Dedicated Argon worker pool (audit #94)

Run the memory-hard verification work on a dedicated worker pool, separate
from the HTTP runtime: **N fixed workers + a bounded channel (capacity M)**,
disconnected from the web process lifecycle. The sync Rust crate (and the
PHP libsodium verifier) is naturally isolated — no async runtime to starve,
no event-loop stall — but only if the PROCESS topology keeps the KDF
workers off the HTTP worker threads: one PHP-FPM worker never runs two
Argon hashes at once (the admission gate's per-process cap), and a
dedicated pool (e.g. separate FPM pools / sidecar replicas that only serve
the verify surface) guarantees that a KDF burst can never delay HTTP
framing, header parsing or health responses. The bundle's
`argon2_max_concurrent_verifications` + Redis tokenized leases then
coordinate the N workers ACROSS the pool (each worker's in-process gate is
a floor; the Redis leases are the cross-worker ceiling).

### Concurrency must be benchmark-derived (audit #93/#94)

Size `argon2_max_concurrent_verifications` from MEASUREMENTS, not memory
arithmetic: with the fixed verification envelope
(`risk.argon_verification_memory_kib`), the honest sizing procedure is —
benchmark the actual deployment: p99 verification latency and the RSS
footprint of N concurrent hashes at the chosen envelope (the libsodium
allocator's real peak differs from `m_kib` by allocator overhead, thread
arenas, and the per-hash working set), and the memory-bandwidth ceiling
(Argon2id is bandwidth-bound — two cores can starve each other on shared
L3/memory bandwidth long before the memory budget is exhausted). Then set
the cap to the measured p99 latency / RSS / bandwidth point with deliberate
headroom (20-30%), and re-verify with the readiness memory-budget invariant
(`container_memory_mib`). NEVER size by `floor(container_memory / envelope)`
alone: the invariant is a ceiling check, the benchmark is the sizing
decision.

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
            'request_binding' => $txnId, // optional transaction binding (audit #41);
                                        // defaults to the configured static
                                        // risk.request_binding; a random
                                        // nonce per page load is recommended
        ]);
```

The type renders a hidden `kiwi__token` input; the `KiwiCaptcha` validator
constraint (attached automatically) verifies the token **locally** on submit.
The widget posts to `route_prefix . '/challenge'` by default — the form's
endpoint follows the configured prefix like the standalone widget does — and
stays overridable per form with the `endpoint` option. The telemetry mode is
rendered as `data-kiwi-telemetry` on the widget container (default `off`);
invalid values are rejected by the options resolver. With a
`request_binding` the widget container carries
`data-kiwi-request-binding`, the challenge POST sends the field, and the
driver writes the hidden `kiwi_request_binding` input into the form (see
"Transaction binding" above).

**Public violation codes (audit #57):** token-level failures — wrong scope,
IP mismatch, expired, malformed/badly-signed tokens, too-fast solves, wrong
region, wrong policy epoch, missing client IP, counter/length violations,
insufficient work, indeterminate consumption — ALL collapse to the single
public code **`invalid_or_expired`** (the client gets no oracle for which
check failed; the precise reason stays in the logs). Two refusals stay
distinct: **`rate_limited`** (the Argon2id admission budget is saturated —
retryable, the challenge is NOT burned) and
**`temporary_unavailable`** (the security storage or admission backend is
unavailable). The risk-decision codes stay as-is:
`kiwi.post_solve_rejected` / `kiwi.post_solve_step_up_required`.

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

With `risk.result_receipt_signing_key` configured (audit #80/#106 — see
"Asymmetric result receipts" above), a successful verification additionally
exposes `verifiedReceiptPayload()` (the canonical `{jti, tenant, action,
request_binding, issued_at, expires_at, issuer}` JSON — the full
replay-critical set, signed from the consumed record) and
`verifiedReceiptSignature()` (base64 Ed25519 detached signature) — the
exportable, PUBLIC-key-verifiable receipt of the server-side result. The
HMAC-based verification itself remains central-only: the secret never
leaves the server. Signature verification alone is NOT sufficient for
single-use actions: the integrator must atomically record the jti
(INSERT IF NOT EXISTS / SET NX) and treat a pre-existing jti as a replay
(verify_and_consume — see the receipts section).

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
{{ kiwi_captcha_widget({ 'endpoint': path('kiwicaptcha_challenge'), 'scope': 'login', 'nonce': csp_nonce('script'), 'request_binding': txn_id }) }}
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
as HTML. The health responses (`/health/live`, `/health/ready`) carry the
same `Cache-Control: no-store` + `Pragma: no-cache` contract (audit #40).

**Caching/CDN guidance (audit #40).** The bundle's DYNAMIC endpoints —
`POST {prefix}/challenge` and the health routes — must NEVER be served from
a cache: every response is explicitly `Cache-Control: no-store` +
`Pragma: no-cache` (the latter for older intermediaries that ignore
`Cache-Control`), and the application's reverse proxy / CDN must bypass
them entirely (e.g. `proxy_cache_bypass` / `Cache-Control` passthrough on
the location). The widget's static assets, in contrast, are CONTENT-
ADDRESSED or versioned and are the only KiwiCaptcha material worth caching:
serve them with

```
Cache-Control: public, max-age=31536000, immutable
```

If you host the widget assets separately (they are inlined by the bundle by
default — nothing to cache), use Symfony's `asset()` versioning /
`assets.version` (or a content-hash filename) so every deployment of the
assets gets a NEW URL and `immutable` can never serve a stale solver/
driver; never apply `immutable` to any non-versioned URL.

**Same-origin enforcement.** When `same_origin_only` is true (default, and
forced under strict), requests whose `Origin` header is not the application's
own origin (scheme + host, constant-time compare) are rejected with HTTP 403
`{"error":{"code":"CROSS_ORIGIN_DENIED"}}` **before any state is written** —
cross-site abuse and CSRF-style challenge minting are stopped, and rejected
requests consume no rate-limit budget. Requests without an `Origin` header
(same-origin navigation, curl, non-browser clients) are allowed. The check
happens before rate limiting, so an attacker's cross-origin traffic never
pollutes the per-client window.

**Host-context hardening (audit #78).** The EXPECTED same-origin comes from
SERVER CONFIG, never from the `Host` header: set `public_base_url`
(e.g. `https://captcha.example.com`) and the check compares the request
Origin against that canonical origin (structured normalization — same rules
as the allowlist). A forged `Host: evil.example` header then can never make
`Origin: https://evil.example` look same-origin, and the expected origin
stays stable behind load balancers and shared hosting. Without
`public_base_url` (null, the default — fine for localhost/dev) the expected
origin is derived from the request's own scheme+host; production deployments
behind shared infrastructure SHOULD set it. The issuer itself never derives
anything from `Host` — a forged Host cannot alter the issued challenge
(scope and the socket peer's binding tag are the only context).

**Narrow HTTP (audit #77) + no decompression bombs (audit #65).** The
challenge endpoint accepts ONLY `POST` with an uncompressed
`application/json` body:

- the RAW request target must be the canonical path (audit #99) — no `//`,
  no `/./` or `/../`, no percent-encoded bytes, no trailing slash; a
  noncanonical target is 404 `CANONICAL_PATH_REQUIRED` before any handling
  (see "Canonical request targets" above);
- non-`POST` methods (including `OPTIONS` preflights) stay HTTP 405 with
  `Allow: POST` — a preflight alone NEVER authorizes anything;
- HTTP framing ambiguity (audit #83) — `Content-Length` + `Transfer-Encoding`
  together, or a duplicate `Content-Length` — is rejected with 400
  `FRAMING_REJECTED` BEFORE the body is read (see "HTTP framing" above);
- duplicate SECURITY-SINGULAR headers (audit #100) — `Origin`, `Forwarded`,
  `X-Forwarded-For`, `X-Real-IP` appearing more than once — are rejected
  with 400 `DUPLICATE_HEADER` before any header-derived identity is trusted
  (see "Duplicate security-singular headers" above);
- `Content-Encoding` other than `identity` (gzip/br/deflate) is rejected
  with 415 `UNSUPPORTED_CONTENT_ENCODING` BEFORE the body is read — no
  transparent decompression into unbounded memory;
- a PRESENT `Content-Type` other than `application/json` (form-encoded,
  multipart, text/plain...) is rejected with 415 `UNSUPPORTED_MEDIA_TYPE`;
- query parameters (`?debug=1`, `?skip_pow=1`, `?algorithm=...`) are
  rejected with 422 `QUERY_PARAMETERS_NOT_ALLOWED`;
- a STALE security-policy state (audit #108: the epoch monitor's central
  read is past `risk.security_epoch_max_stale_secs`) refuses issuance with
  503 `SERVICE_UNAVAILABLE` (see "Bounded-revocation-latency security
  epoch" above);
- duplicate JSON object keys in the raw body (audit #111) —
  `{"scope":"login","scope":"signup"}` — are rejected with 422
  `DUPLICATE_FIELD` (nested objects included) before decoding;
- the JSON body must be an OBJECT with ONLY the documented fields
  `scope`, `algorithm` (accepted for forward-compatibility; the issued
  algorithm always comes from the server), `request_binding` — unknown
  fields are debug/override probes and get 422 `UNKNOWN_FIELDS`, a
  non-object document gets 422 `INVALID_JSON`.

The widget's own POSTs are plain uncompressed JSON and pass unchanged.

**Challenge-issuance sequence (audits #103/#104).** The scoped syntactic
rejection runs FIRST and locally: an invalid scope/request-binding
identifier (charset or > 128 bytes) is refused at 422 with ZERO Redis
operations — a malformed identifier never touches shared infrastructure.
Then, in order, every quota check runs BEFORE the challenge state is
created: the process-local emergency cap (no Redis), the issuance rate
limiter (per-client + global), the pre-issue risk assessment, the
per-scope issuance cap, and the anti-stockpiling outstanding admission
(with the configured TTL wired, the outstanding counters are admitted
BEFORE the mint — a refused admission never creates challenge state), and
only then the challenge is minted and stored. A Redis failure in any quota
check propagates (fail closed — no challenge without a checked bound).

**CORS is not authorization (audit #63).** The bundle emits NO CORS headers
— no `Access-Control-Allow-Origin`, no `Access-Control-Allow-Methods` — on
any response, success or error. Cross-origin access control for the
application's own endpoints is the application / reverse-proxy's business;
KiwiCaptcha's origin enforcement (same-origin + allowlist, above) is
AUTHORIZATION and runs on EVERY security response regardless of any CORS
configuration. Because no CORS header is ever emitted, no `Vary: Origin` is
needed either. If your reverse proxy adds CORS headers, it must add
`Vary: Origin` itself on any response it decorates with
`Access-Control-Allow-Origin`.

**Frame-ancestors CSP (audit #71).** When `risk.challenge_origin_allowlist`
is non-empty, EVERY challenge response carries an explicit
`Content-Security-Policy: frame-ancestors <allowlisted origins,
space-separated>` header — always the full directive, never inherited from
`default-src` — so the allowlist is exactly the framing contract of the
endpoint. An empty allowlist emits no CSP header. For the WIDGET PAGE (the
application's own form page — the bundle does not own its response headers)
the Twig function `kiwi_captcha_csp_frame_ancestors()` returns the same
directive (null when the allowlist is empty) — append it to the page's
`Content-Security-Policy` header in your own listener/controller
(`frame-ancestors` is ignored inside `<meta>` tags, so the header is the
only effective delivery):

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

**Local admission before Redis (audit #70).** The PROCESS-LOCAL emergency
window (`risk.hard_limits.process_per_second`, default 10000 — the engine's
`ProcessEmergencyCap`) is checked BEFORE any Redis issuance limiter: a
saturated window refuses immediately with the standard 429
`{"error":{"code":"RISK_DENIED"}}` (retry_after_ms 1000) without a single
Redis round trip. The check is NON-CONSUMING (`isOpen()`), so the engine's
own consuming check inside `assessPreIssue()` remains the single consumer
of the per-process budget — a request admitted here can still be denied
there, never double-counted. Order: narrow HTTP → origin checks → LOCAL
cap → Redis rate limiter → risk assessment → issuance.

**Bounded Redis pool + short timeouts (operational).** The security Redis
(rate limiter, risk state, challenge storage, admission leases) must be a
BOUNDED connection pool: configure `persistent_connections` off / a small
`connections` limit (e.g. 5-10 per worker) and SHORT command timeouts
(e.g. `timeout: 0.3` read, `read_write_timeout: 0.5`) — the bundle treats a
slow/failed Redis command as a typed refusal (429 / temporary_unavailable),
never as a hang, so the pool must fail fast rather than queue. Run it with
`maxmemory-policy noeviction` so challenge/replay state can never be evicted
mid-window, and size `maxmemory` for the outstanding/rate windows
(`max_outstanding_challenges_global` records + the sliding windows; the
consumed-state records persist until their TTL).

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
  risk section above). The acquire script also enforces the PER-SCOPE
  budget (`argon2_max_per_tenant`, default 8): the validator passes the
  constraint scope into `acquire()` (request-scope-aware gate wrapper), and
  the scope's own lease set (`{kiwicaptcha:argon2:leases:<ns>}:<scope>`)
  is checked in ADDITION to the global cap — one busy scope can never
  starve the other scopes' share of the memory-hard budget (see the risk
  section above). The waiters guard stays global.
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

**Trusted client-IP policy (audit #64).** The canonical client IP — the one
the challenge binds to, the rate-limit identity derives from, and the risk
source pseudonym is built on — is decided by ONE explicit knob,
`risk.client_ip_mode` (default `symfony_trusted_proxies`), never by ad-hoc
header reading:

- **`symfony_trusted_proxies` (default):** the bundle configures Symfony's
  `Request::setTrustedProxies()` from `risk.trusted_proxies` (a list of
  CIDRs / exact IPs; default `[]`) with `X-Forwarded-For` + `Forwarded`
  trusted-header flags. Symfony's trusted-proxy machinery then ALREADY
  ignores forwarding headers from untrusted peers: a forged
  `X-Forwarded-For` from the open internet can never change the canonical
  IP. With a NON-EMPTY list the bundle takes ownership of the trusted-proxy
  configuration (it is global Symfony state); an empty list leaves the
  application's own configuration untouched (nothing new is trusted).
- **`direct`:** forwarding headers are ALWAYS ignored — the socket peer
  (`REMOTE_ADDR`) is the canonical IP, regardless of any application-level
  trusted-proxy configuration. Use this when the deployment has no
  proxy-layer that rewrites forwarding headers, or when you do not want the
  Symfony machinery involved at all.

**Ambiguous forwarding.** When a TRUSTED peer sends BOTH `X-Forwarded-For`
AND `Forwarded`, the two chains can disagree and the canonical IP is
ambiguous (Symfony itself refuses to derive one). With
`risk.reject_ambiguous_forwarding: true` the request is rejected with HTTP
400 `{"error":{"code":"AMBIGUOUS_FORWARDING"}}` (the validator fails closed
as `invalid_or_expired`); with the default `false` the anomaly is logged and
the request proceeds with the only unambiguous value — the socket peer.
Headers from an UNTRUSTED peer are never ambiguous: they are ignored
entirely.

The controller, the validator and every risk signal derive the IP through
this policy, so the binding tag, the rate-limit identity and the risk source
pseudonym ALWAYS see the same canonical IP — never read
`$_SERVER['REMOTE_ADDR']` or `Request::getClientIp()` in the application for
KiwiCaptcha context, or IP binding will mismatch the issued challenge.

For production multi-instance deployments you must provide a **shared**
storage service implementing `KiwiCaptcha\StorageInterface` via the `storage`
config option. Redis-backed storage (`RedisStorage`, atomic single-use via
`GETDEL`, Redis 6.2+) is recommended; the bundle fails fast with a
`LogicException` if `ArrayStorage` is configured outside the test/dev
environment, since it cannot enforce single-use across workers. PSR-6 pools
work but cannot express atomic get-and-delete, so single-use under
concurrency is best-effort (read-then-delete).

## Incumbent migration (reCAPTCHA / hCaptcha / Turnstile)

A one-script migration surface (round 24):

- `GET {prefix}/api.js?compat=recaptcha|hcaptcha|turnstile` — the
  same-origin loader (wasm glue + driver, immutable asset). Incumbent
  pages change only their provider script URL: `.g-recaptcha` /
  `.h-captcha` / `.cf-turnstile` containers render implicitly, invisible
  controls (buttons / `data-size="invisible"`) execute on click,
  `data-callback` / `data-expired-callback` / `data-error-callback` fire
  with the same token, and the provider globals (`grecaptcha` /
  `hcaptcha` / `turnstile`) plus the provider response fields
  (`g-recaptcha-response`, `h-captcha-response`, `cf-turnstile-response`)
  all share the ONE underlying Kiwi token.
- `POST {prefix}/siteverify` — provider-shaped JSON (`success`,
  `challenge_ts`, `hostname`, `error-codes`) over the SAME atomic
  verifier. Disabled unless `risk.siteverify_secrets` is configured (a
  map of secret -> expected scope, so each backend's secret enforces its
  own policy scope server-side). `remoteip` is syntactically optional,
  but REQUIRED whenever IP binding is enabled (the default) — a bound
  challenge without the end-user IP fails closed (`missing-input-response`
  / `invalid-input-response`), exactly like the incumbent providers; the
  secret authenticates server-to-server use, `remoteip` is honored only
  after the secret, and a replayed `response` resolves to the stored
  deterministic outcome (safe retries).
- `risk.sitekey_allowlist` maps a public sitekey to a scope
  (server-owned; unknown sitekeys stay scope names subject to
  `allowed_scopes` + the risk assessment — never a policy reduction).
- Solved-token expiry is a first-class lifecycle state: `kiwi:expired`
  clears the token/binding/alias and fires the provider
  expired-callback; the server remains the authoritative expiry check.

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
