# Adaptive risk engine

The bundle can run the **KiwiCaptcha Adaptive Risk Engine**
(`kiwicaptcha/kiwicaptcha-risk-php`) before every challenge is minted.
It implements the cross-language risk-v1 contract, byte-identical with the
Rust implementation. The engine is opt-in and off by default. Enabling it
adds a first-party continuity cookie; see [privacy.md](privacy.md) for the
privacy contract and [configuration.md](configuration.md) for the complete
`risk` configuration.

## Behavior

- **Pre-issue assessment**: each request submits one `PreIssue`
  observation. The engine updates leaky fixed-point counters in Redis via
  the canonical `risk-v1.lua` script: per-source, per-/24 subnet,
  per-session, plus a deployment-global pressure level. It returns a
  decision: `allow` (issue with the configured difficulty),
  `sha16`/`sha18`/`sha20` (raise SHA-256 difficulty),
  `argon16`/`argon32`/`argon64` (issue memory-hard Argon2id profiles),
  `step_up`, or `deny` (HTTP 429 `{"error":{"code":"RISK_DENIED"}}`
  before any challenge is written).

- **Post-issue signal**: every minted challenge records `ChallengeIssued`
  (issue-debt) and increments the atomic per-second issuance counter that
  feeds the resource-pressure provider's `issuanceCapacity`
  (`{kiwi:<ns>}:issuance:<second>`, `INCR` + `EXPIRE` 1).

- **Post-solve feedback**: the validator feeds every verification outcome
  back into the engine: `SolveSuccess`, `InvalidProof`, `MalformedToken`,
  `ExpiredChallenge`, `ReplayAttempt`. `CapacityExceeded` is never recorded
  as client abuse. Repeated failed solves raise the source's score.

- **Post-solve check**: when a scope opts in (`post_solve_check`), a valid
  solve runs a fresh `SolveSuccess` re-assessment. A `deny` fails the form
  with `kiwi.post_solve_rejected`; a `step_up` fails it with
  `kiwi.post_solve_step_up_required` (the application routes the user to
  MFA/passkey/email confirmation). The bundle never confirms its own
  post-solve decision: `confirmedLegitimate` / `confirmedAbuse` are
  application-only signals that require the decision id being confirmed.

- **Degraded operation**: a risk-backend outage (Redis down, script
  errors) trips the circuit breaker. The engine then returns the scope's
  `degraded` action (default `allow`), and challenges are still issued with
  the bundle's configured difficulty. The risk layer is a hardening layer,
  never a single point of failure. The degraded mode consumes the shared
  circuit breaker directly (no per-request `PING`), and the
  resource-pressure provider caches its snapshots in-process (~100 ms).

## Escalation stays within your algorithm family

The app's configured difficulty is the floor; decisions can only raise it.
On a sha256 deployment, `sha16`/`sha18`/`sha20` raise the target bits, and
`argon16`/`argon32`/`argon64` issue Argon2id work at the fixed verification
envelope (`risk.argon_verification_memory_kib`). The memory never escalates;
the target difficulty does, along `risk.argon_escalation_target_bits`
(1/4/8). On an argon2id deployment the argon actions issue the same envelope
and the sha actions are no-ops. `step_up` issues the strongest profile of
the configured family. The bundle cannot perform application-level step-up
(MFA), so applications may also react to the decision themselves.

## Fixed Argon verification envelope

The adaptive risk engine never increases the server verification cost as
its difficulty mechanism. All three adaptive Argon actions
(`Argon16`/`Argon32`/`Argon64`) issue challenges at the same
server-controlled memory envelope, `risk.argon_verification_memory_kib`
(default 16384 KiB, 1024..65536, t=3, p=1). The per-verification memory cost
is therefore bounded by one value regardless of the risk decision. Risk
escalates the target difficulty (the expected nonce search space), not the
memory. `risk.argon_escalation_target_bits` has exactly 3 entries, each
1..20, default `[1, 4, 8]`; it maps Argon16 → 1, Argon32 → 4, Argon64 → 8
leading zero bits. Argon target bits are additionally capped by the core's
browser-solvable ceiling (`Config::MAX_ARGON2_TARGET_BITS` = 10) at
issuance. Consequence for capacity planning: the worst-case
per-verification memory of the risk ladder is the envelope. The readiness
memory-budget invariant (`risk.container_memory_mib`) uses the configured
envelope, and `argon2_max_concurrent_verifications × envelope + headroom`
is the honest ceiling. The SHA ladder already escalates bits on a fixed SHA
cost, so it needs no change.

## Application hooks

`kiwi_captcha.risk.engine` (public) exposes the
`KiwiCaptcha\Risk\AdaptiveRiskEngine`. `RiskGateway` (public) exposes
first-class feedback methods for the remaining server-derived events:
`protectedActionSuccess()` / `protectedActionFailure()`,
`authenticationSuccess()` / `authenticationFailure()`, `rateLimitHit()`
(called automatically by the challenge controller before every 429,
including the risk-denied responses) and `expiredChallenge()` (the verifier
path already covers expiry via `solveOutcome`). Application-level
confirmations split into two paths.

`recordConfirmedReputation()`, `confirmedLegitimate()` and
`confirmedAbuse()` are the context-ful path. All three require the
`decisionId` of the decision being confirmed; the engine throws
`InvalidArgumentException` without it, and the gateway passes it through.
The engine settles the decision's outcome ledger atomically (consuming the
calibration receipt when one exists) and records the reputation event
against the source/session/principal signals. All three accept the optional
inverse sampling probability (`$samplingProbabilityPpm`, weight =
1_000_000/ppm) for weighted calibration. A null ppm in weighted mode
propagates the engine's `InvalidArgumentException`, because the label
cannot be re-weighted without its inverse probability.

`confirmDecisionOutcome()` is the calibration-only path for delayed
confirmations (email confirmation, fraud review, chargeback, moderation).
It takes just a decision id + outcome, with no IP, no scope, no session,
plus an optional inverse sampling probability (`$samplingProbabilityPpm`,
weight = 1_000_000/ppm) for weighted calibration. It returns the engine's
shared status: `0` = missing/already confirmed (a webhook retry is a no-op,
so at most one reputation mutation per decision), `1` = first confirmation
recorded, `2` = first confirmation but deliberately unsampled
(random_sample mode). `confirmCorrection()` (a label correction of a
decision, same signature/weight mapping) is the engine's compensating
once-only API guarded by the outcome ledger. It works without calibration;
the guard lives in the state store. With a calibration store attached it
flips the ledger and reverses the recorded bucket counts. It returns `true`
when the compensation was applied and `false` on retries; the aggregates
return to the pre-confirmation state. `samplingMetrics($scope)` exposes
the random_sample resolution-gate counters (`sampledTotal` /
`sampledResolved` / `resolutionRatio` / `sampledExpired`; zeros when
calibration is disabled).

Decisions are logged through the app's `logger`, at info for decisions
and warning for denials, with scope/action/score/reasons only. The full
redaction contract (never an IP or cookie value, never a decision id or
nonce, bounded metric keys) is in
[privacy.md](privacy.md#logs-and-metrics-never-carry-identity).

## Region binding (failover-replay mitigation — Option A)

`risk.region` (optional deployment region string, e.g. `eu-central-1`) is
baked into every issued challenge record by the core `Issuer` and enforced
by the core `Verifier`: a result token issued in one region is never
redeemable elsewhere. This is the Option A mitigation for the
failover-replay attack, where a challenge record replicated to a DR region
whose verifier accepts tokens minted by the failed-over primary would let a
captured token be replayed after failback. Set the same region on every
node of one logical deployment and a different region on every failover
target. When unset, no region is recorded and no region check applies.

## Outstanding-challenge anti-stockpiling

`risk.max_outstanding_challenges` (default 20) and
`risk.max_outstanding_challenges_global` (default 100000) bound the number
of unsolved challenges a single source, and the whole deployment, may hold
at once.

On issuance, one atomic Lua script checks both counters and refuses before
anything is written. The source counter `{kiwi:<ns>}:outstanding:<hex>` and
the global counter `{kiwi:<ns>}:outstanding:global` are incremented with
`EXPIRE` = challenge lifetime + `risk.redis.ttl_margin_secs`. The source
identity is `hex(hmac_sha256(canonical-ip-bytes, RiskKeys::event))`; the
raw IP never appears in Redis, and the same canonical-IP normalization as
the challenge binding tag is used. Exhaustion returns the standard 429
`RISK_DENIED` response, never a captcha issuance; a minted-but-refused
record is discarded server-side. A valid verification decrements the
per-source counter (best-effort, floored at 0). The global counter is
deployment-wide and identity-neutral; it decays only by `EXPIRE`.

Bounded memory: an attacker can never stockpile an unbounded number of live
challenges for one source or one deployment. The counters cap the aggregate
outstanding verification work an attacker can hoard.

## Per-scope issuance cap

`risk.max_challenges_per_scope_per_minute` (default 0 = unlimited): when >
0, a Redis fixed-window counter
`{kiwi:<ns>}:issuance:<hex(hmac_sha256(scope, K_scope))>:<minute>` uses
`INCR` + `EXPIRE` 60 in one atomic Lua script and bounds how many challenges
a scope may issue per minute. The controller denies HTTP 429
`{"error":{"code":"SCOPE_LIMITED"}}` beyond the cap, before any challenge
is minted. The public site key plus claimed origin can therefore no longer
create unlimited billed verification work per scope. The raw scope string
is never a Redis key component. The scope is attacker-controlled (bounded
alphabet `[A-Za-z0-9._:-]{1,128}`, unbounded cardinality), so the window
key carries the keyed pseudonym `hex(hmac_sha256(scope, K_scope))`.
`K_scope = hash_hkdf('sha256', master, 32, 'kiwi/v2/scope-rate')` is
derived from the risk master (`risk.master_secret`, falling back to
`secret_key`), purpose-separated from the risk identity keys, and identical
across the bundle and the risk package's calibration scope keys. Each scope
gets an independent window. A Redis failure propagates (fail closed, no
challenge without a checked scope bound), and the config is refused at
compile time when no Redis client is available. The minute is derived from
the Redis server clock so all workers share one window.

## Related material

- [configuration.md](configuration.md): the full `risk` configuration and
  scope identity rules.
- [privacy.md](privacy.md): continuity cookie, telemetry, log redaction.
- [chained-challenges.md](chained-challenges.md): the chain ticket and
  post-solve disposition flow built on the same decisions.
- [operations.md](operations.md): rate limiting, admission gates, health
  endpoints.
