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

   - source material: canonical IP bytes with IPv6 masked to its /64
     (family byte 0x04 or 0x06 + packed bytes, the bytes after the
     prefix zeroed; IPv4 keeps the full address). A host controls at
     least a /64, so a /128-keyed source would let it rotate addresses
     for a fresh pseudonym on every request. IPv4-mapped IPv6 and the
     deprecated IPv4-compatible `0::/96` form `::a.b.c.d` — excluding
     the unspecified `::` and the loopback `::1` — normalize to the
     4-byte IPv4 family first. The context is `b"src"`; the epoch is
     floor(now / 900).
   - subnet material: masked canonical network (IPv4 /24, IPv6 /56) in the
     same family+bytes form; context `b"net"`; epoch = floor(now / 900).
   - session: HMAC over the raw 16-byte session cookie value; context
     `b"sess"`; no epoch.
   - principal: HMAC over the application principal ID bytes; context
     `b"prin"`; no epoch.

    Rotation: only the source and subnet pseudonyms rotate with their
    epochs. Session pseudonyms are stable for the lifetime of the session
    cookie or its record TTL, and principal pseudonyms for the principal
    TTL (`principal_ttl_s`, default 24 h). There is no per-request
    rotation for either stable identity.

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
- `hysteresis-vectors.json`: shared scope-action hysteresis edge-fallback
  vectors (authoritative). Both implementations iterate the identical
  steps and must select identical actions.
- `target-vectors.json`: shared target-identifier vectors (authoritative).
    Both implementations run every input through the identical versioned
    normalization pipeline and must derive the identical HMAC pseudonym.
- `asn-vectors.json`: shared ASN-resolution vectors (authoritative).
    Both implementations load the versioned sample dataset
    (`protocol/asn/sample-asn.tsv`, digest pinned in the corpus) and must
    resolve every query IP to the identical bucket id, with the identical
    valid/malformed row accounting.
- `trust-vectors.json`: shared context-bound-trust vectors
    (authoritative). Both implementations must derive the identical
    bucket id and credit decision (applied credit, home verdict) for
    every recorded raw trust value.
- `risk-v1.lua` — canonical Redis state script (authoritative, embedded).
- `assess_v2.lua`: canonical consolidated assessment script (the full
  risk-v1 observation plus the risk-v2 first-seen session tag records and
  the outcome-ledger registration in ONE atomic invocation; authoritative,
  embedded verbatim by both packages).
- `calibration.lua`, `confirm.lua`, `correction.lua`,
  `register_decision.lua`, `sampling_metrics.lua`,
  `outcome_register.lua`, `outcome_confirm.lua`, `outcome_correct.lua`:
  canonical calibration / outcome-ledger scripts (authoritative, embedded
  verbatim by both packages).
- `marks.lua`: the canonical long-memory outcome-mark write (one atomic
  hash update under a refreshed whole-key TTL; authoritative, embedded
  verbatim by both packages).
- `trust.lua`: the canonical context-bound session-trust record (one
  atomic read, credit or decay of `trust[session][asn_bucket]` under a
  refreshed whole-key TTL aligned with the session dimension;
  authoritative, embedded verbatim by both packages).
- `outcomes-vectors.json`: shared typed-outcome mapping vectors
  (authoritative). Both implementations resolve every vector to the
  identical event channel, ledger action, mark behavior and polarity
  decision.
- `pricing-vectors.json`: shared continuous-pricing vectors
  (authoritative). The header records the price model's consts table,
  which both implementations must equal byte for byte, and every vector
  carries the risk, value class, bucket trust and scope pressure inputs
  plus the expected work score and ladder rung. Both implementations
  (`RISK_PRICING_VECTORS_PATH` overrides the location) must resolve
  every vector identically. The corpus ships 100000 vectors (grid
  corners, a band-edge sweep and seeded interior draws) in the columnar
  schema version 2; the committed generator at
  packages/kiwicaptcha-risk-php/tools/gen-pricing-vectors.php
  reproduces it and self-checks the previously shipped corpus
- `quarantine-vectors.json`: shared quarantine-selection vectors
  (authoritative). Quarantine is a decision disposition of the marks
  stage, never a ladder rung: a server-confirmed spam identity (every
  in-TTL own mark of the spamReported kind) with a clean request and a
  plain Allow decision quarantines, wire-identical to allow. Every
  vector carries the plain decision inputs plus the marks view and must
  resolve to the identical action, quarantine flag, retry hint and
  ordered reason list. The severity-monotonic precedence (deny, the
  non-spam rung floor, the target step-up ceiling and any plain action
  above Allow all outrank quarantine; an expired mark is inert) is part
  of the pinned surface. Both implementations read the corpus with the
  selection armed (the engine posture); the legacy
  `attacker-denial-vectors.json` corpus keeps pinning the deny and rung
  rules of the same stage with the selection off.

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
    validate → DEL receipt → ledger CAS → `HINCRBYFLOAT` bucket →
    `EXPIRE` → return status 0/1/2); a confirmed outcome is either fully
    recorded or not consumed.
    Bias is boundary-relative exact score calibration on class-normalized
    means. T = 600 is the decision boundary where the default ladder
    leaves the sha20 band and enters the first Argon band
    (`action.rs`/`score.rs`). fp_mean = Σ max(0, legit_score − T) /
    legit_count and fn_mean = Σ max(0, T − abuse_score) / abuse_count,
    then error = fn_mean·fn_cost − fp_mean·fp_cost. The clipped sums
    (`legit_above_sum`, `abuse_below_sum`) are accumulated at confirmation
    for every counted sample and reversed/redone by correction only for a
    counted v=2 sample (`ledger.c == 1` AND `ledger.v == 2`); an unsampled
    (c=0) or legacy (no v) ledger leaves them untouched. A legacy bucket
    without them contributes 0. raw = (error*2)/10, clamped to
    ±max_adjustment, and moved toward the target through the proportional
    per-minute rate limiter (milli-points, max change per minute). Below
    min_samples the target is 0 but the path is still rate-limited.
    Applied to the score before band mapping in both languages.

    Label sources: only human- or support-verified outcomes may feed
    `confirmOutcome`, never an automatic success signal such as any
    successful login. A credentialed attacker can otherwise manufacture
    "legitimate" labels and pull the calibration bias down.
    Sampling contract: at assessment time the engine marks each receipt
    `sampled` (mode complete → always; random_sample →
    random < sampling_probability_ppm; weighted → always, the application
    supplies the inverse sampling probability as the weight). In
    random_sample mode an unsampled confirmation is discarded by
    confirm.lua — the label can never select itself into the calibration
    population.

17. Outcome ledger (always on, independent of calibration):
    `{kiwi:<ns>}:outcome:<decision_id>` holds the decision's outcome state
    as JSON `{"o":"P|L|A","scope","hour","score","w","c","v"}` (pending /
    legitimate / abuse, exact decision score, recorded weight, counted
    flag `c`, writer generation `v`), EX = outcome receipt TTL. Registration is atomic with the
    calibration receipt + sample denominator (register_decision.lua:
    validate → SET receipt NX EX → pending ledger `SET NX EX` → gated
    sample_total `INCR`). The ledger NX means a late re-registration can
    never reset an authoritative L/A ledger to pending. When the ledger
    already exists, the just-created receipt is removed and no second
    denominator is booked. When calibration is disabled the store still
    registers the ledger (outcome_register.lua). Confirmation performs a pending -> L/A
    CAS exactly once (confirm.lua / outcome_confirm.lua) and returns the
    shared status 0/1/2; the confirm preserves the ledger's stored TTL
    (`SET ... KEEPTTL`) instead of re-arming it. Reputation mutation is gated on 1|2, so
    ConfirmedLegitimate/ConfirmedAbuse work identically with or without
    calibration, and webhook retries can never amplify reputation.
    Corrections flip the ledger (correction.lua / outcome_correct.lua).
    Arguments are validated first, and a pending ledger is refused: the
    confirmation is the only transition out of pending. Only a counted
    sample (`c == 1`; a missing marker reads as 0) reverses the original
    bucket contribution, using the recorded weight, and adds the
    corrected one (clamped at zero), so an unsampled decision never
    deletes another decision's sample. The clipped legs are reversed and
    redone only for a counted v=2 sample (`c == 1` AND `v == 2`). The
    generation-2 writer stamps `v = 2` on every first confirmation it
    writes, counted or deliberately unsampled c=0. A legacy ledger
    (no `v`) reverses the count/score sums without touching the clipped
    legs. `outcome_correct.lua` preserves
    the stored TTL (`SET ... KEEPTTL`) instead of extending it on every
    correction. The
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

21. Policy table: the score bands are configurable, and the shared
    `global_floors` plus per-scope `minimum`/`degraded` rows clamp the
    result. A scope id the table does not list uses the `default_scope`
    row (base risk 100, minimum/degraded sha20 unless the operator
    overrides it) — never Allow. Velocity (`source_fast >= 950`)
    records the HardRateLimit reason. It floors the action at Argon32.
    A hard deny needs corroboration from another hard signal:
    `bad_proof`, `malformed` or `replay >= 300`. A shared IPv4 address
    (carrier NAT, office, campus) therefore cannot be denied on volume
    alone, and a saturated argon backend re-escalates the floor to
    StepUp.

22. ASN resolution (dataset plane): a free, redistributable dataset (a
    public routing-table export or the free IPtoASN dataset) ships as a
    versioned tab-separated file and is loaded from local disk; no
    network call, no paid feed, ever. The loader accepts the
    `first_ip last_ip asn` row shape, the extended
    `first_ip last_ip asn cc registry allocated` shape and the
    registry-first `registry first_ip last_ip asn cc allocated` shape.
    Rows are read once into sorted interval tables and resolved by
    binary search; a malformed row (unparsable IP, mixed family,
    reversed range, an ASN outside 1..4294967294) is skipped and
    counted, never fatal. Addresses follow the canonical IP rules of
    item 8, so a v4-mapped or v4-compatible IPv6 resolves as its IPv4
    address. Every load exposes the sha256 of the file bytes, the file
    mtime (the doctor prints digest and age) and the row counts. Hot
    reload parses the new file fully off to the side, optionally
    verifies a caller-supplied digest and swaps the table atomically,
    so a torn or rejected reload never serves a half-swapped table.
    The reserved unlisted namespace encodes an unknown ASN as its own
    bucket per prefix: `u4/<decimal /16 prefix>` for IPv4 and
    `u6/<8 lowercase hex of the /32 prefix>` for IPv6; a listed ASN
    encodes as `a<decimal asn>` (canonical decimal, no leading zeros).
    Both cores mirror the identical grammar and the shared
    `asn-vectors.json` pins it.

23. Context-bound trust: trust earned by a session is stored per ASN
    bucket, `trust[session][asn_bucket]`, through the canonical
    `trust.lua` record (`trust:{kiwi:<ns>}:<session>:<bucket>`, the
    session-dimension TTL, fixed-point trust leaking at 2 units per
    second and clamped at the 10000 ceiling). A session presenting from
    a bucket where it earned nothing gets zero credit there, full
    credit in its home bucket(s): the applied credit is the bucket
    local record alone (normalized with the identical
    `floor(value * 1000 / saturation)` rule, saturation 10000). The
    read op is pure, so a foreign presentation never reduces home
    credit and a genuine home to mobile commute keeps trust. This
    defeats shared-cookie botnets: a trusted cookie replayed from a
    thousand foreign networks earns nothing. The risk-v1 observation
    argv stays frozen, so the bucket layer rides an additive store
    surface (like the marks). The assessment plane swaps the aggregate
    session trust contribution for the bucket local credit when the
    request context carries the session's ASN bucket, and the shared
    `trust-vectors.json` pins the decisions both cores must derive.
