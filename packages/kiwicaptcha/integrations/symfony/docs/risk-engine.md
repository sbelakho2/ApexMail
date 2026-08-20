# Adaptive risk engine

The bundle can run the **KiwiCaptcha Adaptive Risk Engine**
(`kiwicaptcha/kiwicaptcha-risk-php`, the cross-language risk-v1 contract,
byte-identical with the Rust implementation) **before every challenge is
minted**. It is **opt-in and off by default** (privacy posture — enabling it
adds a first-party continuity cookie, see [privacy.md](privacy.md) for the
privacy contract and [configuration.md](configuration.md) for the complete
`risk` configuration).

## Behavior

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

## Escalation stays within your algorithm family

The app's configured difficulty is the floor, decisions can only raise it:
on a sha256 deployment `sha16/18/20` raise the target bits and `argon16/32/64`
issue Argon2id work at the FIXED verification envelope
(`risk.argon_verification_memory_kib` — the memory NEVER
escalates; the target difficulty does, along
`risk.argon_escalation_target_bits` 1/4/8); on an argon2id deployment the
argon actions issue the same envelope and sha actions are no-ops.
`step_up` issues the strongest profile of the configured family — the
bundle cannot perform application-level step-up (MFA), so applications may
also react to the decision themselves.

## Fixed Argon verification envelope

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

## Application hooks

`kiwi_captcha.risk.engine` (public) exposes the
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

Decisions are logged through the app's `logger` (info for decisions,
warning for denials) with scope/action/score/reasons only — the full
redaction contract (never an IP or cookie value, never a decision id or
nonce, bounded metric keys) is in [privacy.md](privacy.md#logs-and-metrics-never-carry-identity).

## Region binding (failover-replay mitigation — Option A)

`risk.region` (optional deployment region string, e.g. `eu-central-1`) is
baked into every issued challenge record by the core `Issuer` and enforced
by the core `Verifier`: a result token issued in one region is never
redeemable elsewhere. This is the *Option A* mitigation for the
failover-replay attack (a challenge record replicated to a DR region whose
verifier accepts tokens minted by the failed-over primary would let a
captured token be replayed after failback). Set the SAME region on every
node of one logical deployment and a DIFFERENT region on every failover
target. When unset, no region is recorded and no region check applies.

## Outstanding-challenge anti-stockpiling

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

## Per-scope issuance cap

`risk.max_challenges_per_scope_per_minute` (default **0** = unlimited):
when > 0, a Redis fixed-window counter
`{kiwi:<ns>}:issuance:<hex(hmac_sha256(scope, K_scope))>:<minute>` — INCR +
EXPIRE 60 in ONE atomic Lua script — bounds how many challenges a scope may
issue per minute; the controller denies HTTP 429
`{"error":{"code":"SCOPE_LIMITED"}}` beyond the cap, BEFORE any challenge is
minted. The public site key + claimed origin can therefore no longer create
unlimited billed verification work per scope. **The RAW SCOPE STRING IS
NEVER A REDIS KEY COMPONENT:** the scope is attacker-controlled
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

## Related

- [configuration.md](configuration.md) — the full `risk` configuration and
  scope identity rules.
- [privacy.md](privacy.md) — continuity cookie, telemetry, log redaction.
- [chained-challenges.md](chained-challenges.md) — the chain ticket and
  post-solve disposition flow built on the same decisions.
- [operations.md](operations.md) — rate limiting, admission gates, health
  endpoints.
