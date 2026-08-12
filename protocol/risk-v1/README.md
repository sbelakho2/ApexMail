# Risk Protocol v1

Shared cross-language contract for the KiwiCaptcha Adaptive Risk Engine.

The Rust implementation (`packages/kiwicaptcha-risk`) and the PHP
implementation (`packages/kiwicaptcha-risk-php`) MUST be byte-for-byte
identical in:

1. `RiskEventKind` — fixed enum, values 1..14:

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

2. `SignalVector` — 13 fixed-point fields (u16/int, each 0..1000), in this
   exact order (JSON keys in `fixtures.json`):

   `source_fast, source_slow, subnet_fast, issue_debt, bad_proof, malformed,
   replay, action_failure, scope_switch, global_pressure, network_risk,
   trust_credit, principal_credit`

3. `RiskWeights` — same 13 fields, u16/int.

4. Scoring — `weighted(v, w) = (v * w) / 1000` integer division;
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

5. `RiskAction` — ordered enum:

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

6. `RiskReason` — enum: SourceBurst, SourceSustained, NetworkBurst,
   ChallengeDebt, InvalidProofs, MalformedTraffic, ReplayTraffic,
   ActionFailures, ScopeHopping, GlobalAttack, LocalNetworkRisk,
   CapacityPressure, HardRateLimit, Cooldown. Top 3–4 reasons returned
   internally; never exposed to the client.

7. Identity — HKDF-SHA256 (`hash_hkdf('sha256', master, 32, info,
   'kiwicaptcha-risk-v1')` / `Hkdf::<Sha256>::new(Some(b"kiwicaptcha-risk-v1"),
   master)`) deriving four 32-byte keys: `source`, `subnet`, `session`,
   `principal`.

   Ephemeral pseudonym (128 bits — first 16 bytes of the HMAC):

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

8. State — leaky fixed-point counters (1000 = one unit) with the canonical
   Lua in `risk.lua` (embedded verbatim by both implementations, loaded via
   EVALSHA with NOSCRIPT fallback). Redis keys use the hash tag
   `{kiwi:<deployment>}`:

   `{kiwi:d}:risk:src:<epoch>:<hex16>` · `...:net:<epoch>:<hex16>` ·
   `...:session:<hex16>` · `...:principal:<hex16>` · `...:global` ·
   `...:dedupe:<event_id>`

9. Global pressure levels 0..4 with hysteresis (enter at thresholds
   3000/5500/7500/9000 raw pressure; leave only after the hysteresis
   window; the Lua implements it).

10. Golden fixtures — `fixtures.json` (22 vectors + weights + base 100).
    Both implementations MUST reproduce `expected_score` exactly.

Files:
- `fixtures.json` — golden scoring fixtures (authoritative).
- `risk.lua` — canonical Redis state script (authoritative, embedded).

8. Request vs feedback — ONLY `PreIssue` (1) counts as a REQUEST: it
   increments `rf`/`rs` and the scope-switch channel. Feedback events
   (2..14) mutate only their own channels; they never inflate velocity
   or the emergency limiters. `assess()` (PreIssue) enforces the source
   AND global emergency windows; `record_feedback()` runs neither.

9. Session and principal state — the Lua updates and saves the session
   state (when `has_session=1`) and principal state (when
   `has_principal=1`) with event-specific semantics: principal trust for
   AuthenticationSuccess / ProtectedActionSuccess / ConfirmedLegitimate,
   failure pressure for AuthenticationFailure / ProtectedActionFailure /
   ConfirmedAbuse. `principal_credit` in the SignalVector is REAL.

10. Epoch pseudonym continuity — the observation carries prev/current/next
    pseudonyms, each HMAC'd with ITS OWN epoch
    (`source_id_for_epoch(ip, epoch-1/0/+1)`); the ±1 keys are
    observer-only until a later epoch writes them.

11. Idempotency — a caller-supplied `idempotency_key` is used verbatim as
    the event_id; a duplicate returns the CURRENT signals with
    `is_duplicate=1` (state untouched) — identical in both languages.

12. Calibration — bounded Redis aggregate buckets
    `{kiwi:<ns>}:cal:<scope>:<hour>` (fields `b<band>a<action>:legit|abuse`,
    48 h TTL, at most 24 keys per scope) with JSON-string decision receipts
    `{kiwi:<ns>}:cal:receipt:<decision_id>` (EX 300, consumed via GETDEL).
    Bias = clamp(((abuse - legit) * 1000 / total) * 2 / 10, -200, 200),
    integer division; applied to the score BEFORE band mapping in both
    languages.

13. Degraded mode applies `strongest(scope.degraded, scope.minimum,
    global_floors[min(last_known_level, 4)])` — the last known global
    attack floor survives backend failure.

14. Argon capacity is checked LAST: `action = strongest(ladder, minimum,
    floor)` then, if the final action is Argon and argon capacity < 300 →
    StepUp. Floors can never reintroduce Argon.

15. Scope ids are u32 (1..=4294967295; 0 rejected) in both languages.
