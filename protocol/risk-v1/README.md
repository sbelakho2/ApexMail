# Risk Protocol v1

Shared cross-language contract for the KiwiCaptcha Adaptive Risk Engine.

The Rust implementation (`packages/kiwicaptcha-risk`) and the PHP
implementation (`packages/kiwicaptcha-risk-php`) MUST be byte-for-byte
identical in:

1) `RiskEventKind` — fixed enum, values 1..17:

   | value | name |
   |-------|------|
   | 1 | PreIssue |
   | 2 | ChallengeIssued |
   | 3 | SolveSuccess |
   | 4 | InvalidProof |
   | 5 | MalformedToken |
   | 6 | ExpiredChallenge |
   | 7 | ReplayAttempt |
   | 8 | ProtectedActionSuccess |
   | 9 | ProtectedActionFailure |
   | 10 | AuthenticationSuccess |
   | 11 | AuthenticationFailure |
   | 12 | ConfirmedLegitimate |
   | 13 | ConfirmedAbuse |
   | 14 | RateLimitHit |
   | 15 | SourceRateLimitHit |
   | 16 | GlobalCapacityHit |
   | 17 | RiskDenied |

   Event semantics: only `PreIssue` (1) counts as a request (velocity);
   feedback events mutate only their own channels. `SourceRateLimitHit`
   (15) adds bad pressure to source/session only. `GlobalCapacityHit`
   (16) raises the global attack/resource pressure without touching any
   source/session/principal reputation, since deployment overload must not
   contaminate an individual visitor. `RiskDenied` (17) performs no state
   mutation, so a risk decision that already denied is never double-counted.

2) `SignalVector` — 13 fixed-point fields (u16/int, each 0..1000), in this
   exact order (JSON keys in `fixtures.json`):

   `source_fast, source_slow, subnet_fast, issue_debt, bad_proof, malformed,
   replay, action_failure, scope_switch, global_pressure, network_risk,
   trust_credit, principal_credit`

3) `RiskWeights` — same 13 fields, u16/int.

4) Scoring — `weighted(v, w) = (v * w) / 1000` integer division;
   `score(base, signals, weights)`:
   ```
   risk = base
   for the 11 positive signals in SignalVector order: risk += weighted(sig, w)
   risk -= weighted(trust_credit, w.trust_credit)
   risk -= weighted(principal_credit, w.principal_credit)
   return clamp(risk, 0, 1000)
   ```
   Rust uses saturating arithmetic; PHP clamps at the end with
   `max(0, min(1000, risk))`.

5) `RiskAction` — ordered enum:

   `Allow < Sha16 < Sha18 < Sha20 < Argon16 < Argon32 < Argon64 < StepUp < Deny`

   Default score bands (configurable in policy, hard floors on top):

   | band | action |
   |------|--------|
   | 000–149 | Allow |
   | 150–299 | Sha16 |
   | 300–449 | Sha18 |
   | 450–599 | Sha20 |
   | 600–749 | Argon16 |
   | 750–849 | Argon32 |
   | 850–929 | Argon64 |
   | 930–979 | StepUp |
   | 980–1000 | Deny |

6) Clock: all pressure decay, hysteresis, cooldown and state timestamps
   derive from the Redis `TIME` command inside the risk script (`ARGV[3]`
   now_ms is kept for wire compatibility but unused). Multi-node app
   clocks can never change shared risk-state behavior. Application wall
   clocks remain only for the HMAC pseudonym epoch, where ±1 epoch
   lookups tolerate boundary skew.

7) `RiskReason` — enum: SourceBurst, SourceSustained, NetworkBurst,
   ChallengeDebt, InvalidProofs, MalformedTraffic, ReplayTraffic,
   ActionFailures, ScopeHopping, GlobalAttack, LocalNetworkRisk,
   CapacityPressure, HardRateLimit, Cooldown. Top 3–4 reasons are
   returned in the application-facing decision and operator logs only.
   They are never exposed to the end-user client; the browser-facing
   APIs emit opaque error codes, never reasons.

8) Identity: `HKDF-SHA256` derives four 32-byte keys (`source`,
   `subnet`, `session`, `principal`) from
   `hash_hkdf('sha256', master, 32, info, 'kiwicaptcha-risk-v1')` and
   `Hkdf::<Sha256>::new(Some(b"kiwicaptcha-risk-v1"), master)`.

   Ephemeral pseudonym (128 bits, the first 16 bytes of the HMAC):

   ```
   HMAC-SHA256(key, "kiwi-risk-id-v1\0" || context || "\0" ||
               epoch.to_be_bytes() || material)
   ```

   - source material: canonical IP bytes (family byte 0x04/0x06 + packed
     bytes; IPv4-mapped IPv6 normalized to IPv4); context `b"src"`;
     epoch = floor(now / 900).
   - subnet material: masked canonical network (IPv4 /24, IPv6 /56) in the
     same family+bytes form; context `b"net"`; epoch = floor(now / 900).
   - session: HMAC over the raw 16-byte session cookie value; context
     `b"sess"`; no epoch.
   - principal: HMAC over the application principal ID bytes; context
     `b"prin"`; no epoch.

9) State: leaky fixed-point counters (1000 = one unit) with the canonical
   Lua in `risk-v1.lua` (embedded verbatim by both implementations, loaded via
   `EVALSHA` with `NOSCRIPT` fallback). Redis keys use the hash tag
   `{kiwi:<deployment>}`:

   `{kiwi:d}:risk:src:<epoch>:<hex16>` · `...:net:<epoch>:<hex16>` ·
   `...:session:<hex16>` · `...:principal:<hex16>` · `...:global` ·
   `...:dedupe:<event_id>`

10) Global pressure levels 0..4 with hysteresis (enter at the normalized
   thresholds 300/550/750/900, i.e. 30/55/75/90% of global saturation —
   raw 21000/38500/52500/63000 against the default sat_global 70000
   fixed-point; exit at 250/450/650/850 after the hysteresis window; the
   Lua implements it).

11. Golden fixtures — `fixtures.json` (22 vectors + weights + base 100).
    Both implementations MUST reproduce `expected_score` exactly.

Files:
- `fixtures.json` — golden scoring fixtures (authoritative).
- `risk-v1.lua` — canonical Redis state script (authoritative, embedded).

12. Request vs feedback: only `PreIssue` (1) counts as a request. It
   increments `rf`/`rs` and the scope-switch channel. Feedback events
   (2..14) mutate only their own channels; they never inflate velocity
   or the emergency limiters. `assess()` (PreIssue) enforces the source
   and global emergency windows; `record_feedback()` runs neither.

13. Session and principal state: the Lua updates and saves the session
   state (when `has_session=1`) and principal state (when
   `has_principal=1`) with event-specific semantics. Principal trust
   applies for AuthenticationSuccess / ProtectedActionSuccess /
   ConfirmedLegitimate, failure pressure for AuthenticationFailure /
   ProtectedActionFailure / ConfirmedAbuse. `principal_credit` in the
   SignalVector is real.

14. Epoch pseudonym continuity: the observation carries prev/current/next
    pseudonyms, each HMAC'd with its own epoch
    (`source_id_for_epoch(ip, epoch-1/0/+1)`); the ±1 keys are
    observer-only until a later epoch writes them.

15. Idempotency: the caller-supplied `idempotency_key` is HMAC-SHA256'd
    under the event key over `pack('N', scope) || event || key`. The 64-hex
    digest is the event_id; raw keys are never written to Redis state, and
    equal keys in different scopes/event kinds stay domain-separated. A
    duplicate returns the current signals with `is_duplicate=1` (state
    untouched), identically in both languages.

16. Calibration: bounded Redis aggregate buckets with exact scores.
    `{kiwi:<ns>}:cal:<scope>:<hour>` (fields `legit_count`,
    `legit_score_sum`, `abuse_count`, `abuse_score_sum`, 48 h TTL, at most
    24 keys per scope) with JSON-string decision receipts
    `{kiwi:<ns>}:cal:receipt:<decision_id>` (EX = receipt TTL, default 300):
    `{"scope","band","action","score","sampled"}` — no IP or identity.
    Confirmation is atomic via the canonical `confirm.lua` (GET receipt →
    validate → DEL receipt → `HINCRBYFLOAT` bucket → `EXPIRE` → return
    scope); a confirmed outcome is either fully recorded or not consumed.
    Bias is exact score calibration on class-normalized means. fp_mean =
    legit_score_sum/legit_count, fn_mean = (abuse_count*1000 −
    abuse_score_sum)/abuse_count, and error = fn_mean·fn_cost −
    fp_mean·fp_cost. raw = (error*2)/10, clamped to ±max_adjustment, and
    moved toward the
    target through the proportional per-minute rate limiter (milli-points,
    max change per minute). Below min_samples the target is 0 but the path
    is still rate-limited. Applied to the score before band mapping in both
    languages.
    Sampling contract: at assessment time the engine marks each receipt
    `sampled` (mode complete → always; random_sample →
    random < sampling_probability_ppm; weighted → always, the application
    supplies the inverse sampling probability as the weight). In
    random_sample mode an unsampled confirmation is discarded by
    confirm.lua — the label can never select itself into the calibration
    population.

17. Outcome ledger (always on, independent of calibration):
    `{kiwi:<ns>}:outcome:<decision_id>` holds the decision's outcome state
    as JSON `{"o":"P|L|A","scope","hour","score","w"}` (pending /
    legitimate / abuse, exact decision score, recorded weight), EX =
    outcome receipt TTL. Registration is atomic with the calibration
    receipt + sample denominator (register_decision.lua: SET receipt NX
    EX + pending ledger + sample_total `INCR` in the decision-hour
    bucket); when calibration is disabled the store still registers the
    ledger (outcome_register.lua). Confirmation performs a pending -> L/A
    CAS exactly once (confirm.lua / outcome_confirm.lua) and returns the
    shared status 0/1/2. Reputation mutation is gated on 1|2, so
    ConfirmedLegitimate/ConfirmedAbuse work identically with or without
    calibration, and webhook retries can never amplify reputation.
    Corrections flip the ledger (correction.lua / outcome_correct.lua):
    the original bucket contribution is reversed using the recorded
    weight and the corrected contribution added (clamped at zero). The
    corrected outcome is authoritative for future events while the prior
    ephemeral reputation pressure decays naturally, so no synthetic
    identities are created. `record_feedback` rejects confirmation events
    (LogicException / ConfirmationApiRequired): the exactly-once property
    is structural.
    Confirmed outcomes are bucketed by decision time (receipt carries
    `decision_hour`), never confirmation time; receipt TTLs split into a
    5-minute nonce->decision mapping and a 24-168h outcome receipt
    (score/scope/sample metadata only, no identity). Weighted mode is
    propagated through the context-full APIs (samplingProbabilityPpm ->
    weight) and null weight in weighted mode is rejected. Sampling
    counters (sample_total/sample_resolved) live in the same scope/hour
    buckets as the observations; samplingMetrics(scope) exposes
    sampledTotal/sampledResolved/resolutionRatio/sampledExpired per
    scope.

18. Degraded mode applies `strongest(scope.degraded, scope.minimum,
    global_floors[min(last_known_level, 4)])` — the last known global
    attack floor survives backend failure.

19. Argon capacity is checked last: `action = strongest(ladder, minimum,
    floor)` then, if the final action is Argon and argon capacity < 300 →
    StepUp. Floors can never reintroduce Argon.

20. Scope ids are u32 (1..=4294967295; 0 rejected) in both languages.
