-- Risk Protocol v1 — consolidated assessment script (v4 semantics).
--
-- ONE atomic assessment call: the full risk-v1 observation plus the
-- risk-v2 first-seen session records (client-context tag + trusted-edge
-- TLS tag) and the outcome-ledger registration, returning the signal
-- vector, the recorded tag values and the registration status. The
-- v1 observation body below is byte-identical to risk-v1.lua — the v1
-- contract (the 13-signal vector, the weights, the fixed-point semantics)
-- is unchanged; this script only extends the key set, the argv set and
-- the return with the two ephemeral session records and the pending
-- outcome-ledger entry.
--
-- SCRIPT BOUNDS — all bounded constants, no attacker-sized
-- collections anywhere in this script:
--   max keys touched:     18 (KEYS[1..17] plus the per-event effect
--                          completion key derived below as
--                          KEYS[10] .. ':fxdone', same hash tag)
--   max Redis calls:      51 (17 TYPE + 1 TIME + 10 HMGET + 5 GET/
--                           EXISTS + 6 HSET + 3 PEXPIRE + 5 SET +
--                           2 PFADD + 2 PFCOUNT — every call is
--                           fixed-cost; no KEYS/SCAN/EVAL nesting, no
--                           iteration over attacker-sized collections;
--                           the HLL cardinality is bounded by Redis'
--                           sparse representation and the target TTL)
--   max collection cardinality: 13 flat fields per state hash (the
--                           HMGET reply of STATE_FIELDS: 12 state
--                           fields plus the per-event `fx` effect
--                           marker); 5 flat fields in the target hash
--                           (ts, fails, first_ms, last_ms, fx); the
--                           sum3/max3/max4 aggregation touches at most
--                           4 elements.
-- The script's runtime is therefore O(1) in the state size and bounded
-- by the constants above regardless of traffic volume.
--
-- One atomic assessment: read → decay → apply event → aggregate → normalize,
-- across (KEYS[1..13] share the hash tag {kiwi:<deployment>}; the target
-- slots KEYS[14..16] ride their own family tag
-- {kiwi:<deployment>:target:<hex2>} so a stuffing storm never hammers
-- the shared primary):
--   KEYS[1]  source current-epoch state (hash)   — updated
--   KEYS[2]  source epoch-1 state (hash)         — read-only (boundary)
--   KEYS[3]  source epoch+1 state (hash)         — read-only (boundary)
--   KEYS[4]  subnet current-epoch state (hash)   — updated
--   KEYS[5]  subnet epoch-1 state (hash)         — read-only
--   KEYS[6]  subnet epoch+1 state (hash)         — read-only
--   KEYS[7]  session state (hash)                — updated when ARGV[19]=1
--   KEYS[8]  principal state (hash)              — updated when ARGV[20]=1
--   KEYS[9]  global state (hash)                 — updated (rolling)
--   KEYS[10] dedupe key (string)                 — event_id guard
--   KEYS[11] session first-seen client-context tag record (string) —
--            SET NX when ARGV[23] is non-empty (first write wins)
--   KEYS[12] session first-seen trusted-edge TLS tag record (string) —
--            SET NX when ARGV[24] is non-empty (first write wins)
--   KEYS[13] outcome-ledger entry (string, JSON) — SET NX EX when
--            ARGV[25] is non-empty (the pending entry mirrors
--            outcome_register.lua byte-for-byte)
--   KEYS[14] target failure state (hash: ts, fails, first_ms, last_ms) —
--            the leaky-bucket auth-failure counter of the target
--            dimension (change.md 3.2.1), touched when ARGV[48]=1;
--            on the target family tag
--   KEYS[15] target source-spread HyperLogLog — PFADD of the failing
--            source on a target failure (target family tag)
--   KEYS[16] target asn-spread HyperLogLog — PFADD of the failing asn
--            bucket on a target failure (target family tag)
--   KEYS[17] OPTIONAL per-report target-failure dedupe marker, on the
--            same hash tag as KEYS[14..16]. The canonical
--            target_failure.lua writes the same marker, so one report
--            event id books one target failure whichever report path
--            reaches the state first. A caller that passes no 17th key
--            keeps the previous semantics (absent marker = no claim).
--
-- ARGV:
--   [1]  event             RiskEventKind int (1..22)
--   [2]  scope             int (0 = unknown)
--   [3]  now_ms            UNUSED — Redis TIME is the distributed state
--                           clock authority (decay, hysteresis, cooldown and
--                           state timestamps all derive from TIME inside
--                           this script, so app-node clock skew can never
--                           change shared risk-state behavior). The slot is
--                           kept for wire compatibility.
--   [4]  event_id          128-bit hex ('' = dedupe disabled)
--   [5]  dedupe_ttl_s      60
--   [6]  state_ttl_s       source/subnet retention
--   [7]  hysteresis_ms     global level hysteresis window
--   [8]  sat_src_fast      raw saturation (8000)
--   [9]  sat_src_slow      raw saturation (100000)
--   [10] sat_issue         raw saturation (6000)
--   [11] sat_bad           raw saturation (4000)
--   [12] sat_mal           raw saturation (3000)
--   [13] sat_rep           raw saturation (2000)
--   [14] sat_action        raw saturation (6000)
--   [15] sat_switch        raw saturation (10000)
--   [16] sat_global        raw saturation (70000)
--   [17] sat_trust         raw saturation (10000)
--   [18] sat_principal     raw saturation (10000)
--   [19] has_session       0/1 — when 0 the session state is read-only
--   [20] has_principal     0/1 — when 0 the principal state is read-only
--   [21] session_ttl_s
--   [22] principal_ttl_s
--   [23] presented client-context tag ('' = none — the record is
--        untouched and the existing value is reported as '')
--   [24] presented trusted-edge TLS tag ('' = none — the record is
--        untouched and the existing value is reported as '')
--   [25] decision_id ('' = no outcome registration — KEYS[13] is
--        untouched and the registration status is reported as 0)
--   [26] decision_hour     the decision's hour (now_ms / 3_600_000)
--   [27] outcome_ttl_s     outcome-ledger lifetime
--   [28] network_risk      the observation's classifier network risk
--        (slot 10 of the vector is always 0; this value feeds the
--        ledger score, exactly as the engines' scorer does)
--   [29] global_pressure_enabled 0/1 — when 0 the global pressure signal
--        is zeroed for the ledger score (the engines zero it before
--        scoring when the feature is disabled)
--   [30] base_risk         the effective policy base risk for the ledger
--        score (calibration-null assessment: baseRisk(scope))
--   [31] honeypot_hit      0/1 — the v2 context's honeypot flag (the
--        event-derived honeypot kinds 18..20 are derived from ARGV[1])
--   [32..44] the 13 risk-v1 weights in RiskWeights order (source_fast,
--        source_slow, subnet_fast, issue_debt, bad_proof, malformed,
--        replay, action_failure, scope_switch, global_pressure,
--        network_risk, trust_credit, principal_credit)
--   [45..47] the 3 risk-v2 weights in RiskV2Weights order (honeypot,
--        session_inconsistency, tls)
--   [48] has_target       0/1 — when 1 the target dimension (KEYS[14..16])
--        is maintained and reported for this assessment
--   [49] spread source element ('' = none; PFADDed to KEYS[15] on a
--        target failure)
--   [50] spread asn element ('' = none; PFADDed to KEYS[16] on a
--        target failure)
--   [51] target_ttl_s     the target-dimension retention (24h default;
--        required when has_target = 1)
--   [52] target_failure_pressure weight (default 0 when absent)
--   [53] target_spread weight (default 0 when absent)
--
-- Returns (SignalVector order + extras):
--   source_fast, source_slow, subnet_fast, issue_debt, bad_proof, malformed,
--   replay, action_failure, scope_switch, global_pressure, network_risk(0),
--   trust_credit, principal_credit, global_level(0..4), cooldown_until_ms,
--   is_duplicate (0/1), existing_context_tag ('' when none), existing_tls_tag
--   ('' when none), registration_status (0/1; 0 when no registration
--   requested or the decision is already registered), target_failures
--   (the decayed failure count of the target dimension; 0 without a
--   target), target_spread_sources (the distinct-source spread of the
--   target dimension; 0 without a target), target_spread_asns (the
--   distinct-ASN spread; 0 without a target — the two counts are kept
--   separate, never summed)
--
-- Event semantics (risk-v1 v3):
--   PreIssue (1)            → request velocity + scope-hopping
--   ChallengeIssued (2)     → issue_debt
--   SolveSuccess (3)        → repay debt only (no trust credit)
--   InvalidProof (4)        → bad
--   MalformedToken (5)      → mal
--   ExpiredChallenge (6)    → small issue-debt effect (not automatically
--                             malicious): iss + 300
--   ReplayAttempt (7)       → rep
--   ProtectedActionSuccess (8) → trust (meaningful server-confirmed credit)
--   ProtectedActionFailure (9) → action-failure pressure
--   AuthenticationSuccess (10) → strong PRINCIPAL trust
--   AuthenticationFailure (11) → PRINCIPAL/action failure pressure
--   ConfirmedLegitimate (12)   → trust
--   ConfirmedAbuse (13)         → bad + mal
--   RateLimitHit (14)           → bad (source/global abuse pressure)
--   SourceRateLimitHit (15)     → bad on source/session (per-source limit)
--   GlobalCapacityHit (16)      → global-only bad pressure; never touches
--                                 source/session/principal reputation
--                                 (deployment overload must not contaminate
--                                 an individual visitor)
--   RiskDenied (17)             → no state mutation (a risk decision that
--                                 already denied must not be double-counted)
--   ChallengeCancelled (21)     → risk-neutral (no state change): an
--                                 issued challenge that was cancelled keeps
--                                 its issue-debt contribution — the
--                                 issued-and-abandoned signal decays
--                                 naturally, and only an actual
--                                 SolveSuccess repays it. The event kind
--                                 stays for observability: cancellation is
--                                 a resource-lifecycle operation, never a
--                                 debt refund
--
-- Only PreIssue counts as a REQUEST for velocity purposes; feedback events
-- mutate only their own channels.
--
-- Aggregation (v3):
--   Rotated pseudonyms belong to the same identity, so their decayed
--   pressure SUMS (sum3) before normalization (the cap keeps the signal in
--   0..1000); splitting a burst across an epoch boundary can no longer
--   halve the observed pressure.
--   Different identity DIMENSIONS (source vs session vs principal) observe
--   the same request, so they MAX — never double-count one request.
--   trust_credit covers source+session trust; principal_credit is the
--   principal's own trust (no double subtraction).

-- BEGIN KIWI PERSISTED-STATE DECODER
-- Shared decoder block: keep byte-identical across the risk scripts.
-- Missing values keep their documented defaults; a present value must be
-- a finite number of the required shape. Anything else is storage
-- corruption and fails closed before the first mutation.
local function kiwi_decode_number(raw, label)
    if raw == nil or raw == false then
        return nil
    end
    local n = tonumber(raw)
    if n == nil or n ~= n or n == math.huge or n == -math.huge then
        error('storage-corruption: ' .. label .. ' is not a finite number')
    end
    return n
end

local function kiwi_decode_integer(raw, label)
    local n = kiwi_decode_number(raw, label)
    if n ~= nil and n ~= math.floor(n) then
        error('storage-corruption: ' .. label .. ' is not an integer')
    end
    return n
end

local function kiwi_assert_type(key, expected)
    local actual = redis.call('TYPE', key).ok
    if actual ~= 'none' and actual ~= expected then
        error('storage-corruption: ' .. key .. ' holds ' .. actual .. ', expected ' .. expected)
    end
end

local function kiwi_effect_marker(event_id, now_ms, ttl_seconds)
    return event_id .. ':' .. (now_ms + ttl_seconds * 1000)
end

local function kiwi_effect_matches(raw, event_id, now_ms)
    if raw == nil or raw == false then
        return false
    end
    local id, expiry = string.match(raw, '^(.*):(%d+)$')
    if id == nil then
        return raw == event_id
    end
    local expires = tonumber(expiry)
    return id == event_id and expires ~= nil and now_ms <= expires
end
-- END KIWI PERSISTED-STATE DECODER

-- ── Every TTL argument is validated here, BEFORE the first write. A
-- non-positive TTL would make a state/session/principal hash or the
-- outcome ledger persistent (save() skips EXPIRE on ttl <= 0) or issue
-- an invalid `SET ... EX 0`; a TTL above the Redis expire ceiling would
-- abort the script after a write had already landed, leaving persistent
-- state behind. The ceiling (2147483647 seconds) is the largest expire
-- value every Redis version accepts. The PHP and Rust store
-- constructors enforce the identical positive-and-bounded rule before
-- the script is ever called; the outcome TTL is required only when a
-- registration is requested (ARGV[25] non-empty).
local EXPIRY_CEILING_SECS = 2147483647

local function ttl_out_of_bounds(value)
    if value == nil or value < 1 or value > EXPIRY_CEILING_SECS then
        return true
    end
    return value ~= math.floor(value)
end

local session_ttl = tonumber(ARGV[21])
local state_ttl = tonumber(ARGV[6])
local principal_ttl = tonumber(ARGV[22])
local dedupe_ttl = tonumber(ARGV[5])
if ttl_out_of_bounds(session_ttl) then
    return redis.error_reply('assess_v2: session_ttl_s must be a positive integer no greater than 2147483647 (a persistent session record is not admissible)')
end
if ttl_out_of_bounds(state_ttl) then
    return redis.error_reply('assess_v2: state_ttl_s must be a positive integer no greater than 2147483647 (a persistent source/subnet risk hash is not admissible)')
end
if ttl_out_of_bounds(principal_ttl) then
    return redis.error_reply('assess_v2: principal_ttl_s must be a positive integer no greater than 2147483647 (a persistent principal risk hash is not admissible)')
end
if ttl_out_of_bounds(dedupe_ttl) then
    return redis.error_reply('assess_v2: dedupe_ttl_s must be a positive integer no greater than 2147483647 (a persistent or immediately-expired risk hash is not admissible)')
end

-- ── Numeric argument validation BEFORE any write. ──
-- Redis does not roll back: a missing or non-numeric numeric ARGV used
-- to error mid-transition AFTER the dedupe marker was written, losing
-- the event and refusing an identical retry as a duplicate. A value
-- that passes a bare tonumber() check but is NaN or infinite can abort
-- a later arithmetic or cjson step after the first write, so every
-- numeric slot is validated as a FINITE number here. Event ids, scopes,
-- capability flags and saturations carry their exact integer contract.
local function finite_number(value)
    local n = tonumber(value)
    if n == nil or n ~= n or n == math.huge or n == -math.huge then
        return nil
    end
    return n
end

-- Required numeric slots: a missing value would reach a nil comparison
-- mid-transition, so it is refused here.
for _, i in ipairs({1, 2, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20}) do
    if finite_number(ARGV[i]) == nil then
        return redis.error_reply('assess_v2: ARGV['..i..'] must be a finite number')
    end
end
-- Optional numeric slots (registration/outcome fields): callers that do
-- not request the feature legitimately omit trailing arguments, so a
-- missing slot is left to the feature-specific checks below; any slot
-- that IS present must be finite, or it would error after a write.
for _, i in ipairs({26, 27, 28, 30, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 52, 53}) do
    if ARGV[i] ~= nil and ARGV[i] ~= '' and finite_number(ARGV[i]) == nil then
        return redis.error_reply('assess_v2: ARGV['..i..'] must be a finite number when present')
    end
end
local event_arg = finite_number(ARGV[1])
if event_arg ~= math.floor(event_arg) or event_arg < 1 or event_arg > 22 then
    return redis.error_reply('assess_v2: event must be an integer within 1..22')
end
local scope_arg = finite_number(ARGV[2])
if scope_arg ~= math.floor(scope_arg) then
    return redis.error_reply('assess_v2: scope must be an integer')
end
local hysteresis_arg = finite_number(ARGV[7])
if hysteresis_arg < 1 or hysteresis_arg ~= math.floor(hysteresis_arg) then
    return redis.error_reply('assess_v2: hysteresis_ms must be a positive integer')
end
for _, i in ipairs({8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18}) do
    local saturation = finite_number(ARGV[i])
    if saturation < 1 or saturation ~= math.floor(saturation) then
        return redis.error_reply('assess_v2: ARGV['..i..'] must be a positive integer saturation')
    end
end
-- Capability flags are exactly the canonical 0/1 strings: a malformed
-- flag must not silently read as "absent", which would drop state.
if ARGV[19] ~= '0' and ARGV[19] ~= '1' then
    return redis.error_reply('assess_v2: has_session must be 0 or 1')
end
if ARGV[20] ~= '0' and ARGV[20] ~= '1' then
    return redis.error_reply('assess_v2: has_principal must be 0 or 1')
end
if ARGV[25] and ARGV[25] ~= '' and ttl_out_of_bounds(tonumber(ARGV[27])) then
    return redis.error_reply('assess_v2: outcome_ttl_s must be a positive integer no greater than 2147483647 (a persistent outcome ledger is not admissible)')
end
local has_target_arg = ARGV[48] or '0'
if has_target_arg ~= '0' and has_target_arg ~= '1' then
    return redis.error_reply('assess_v2: has_target must be 0 or 1')
end
local has_target = has_target_arg == '1'
if has_target and ttl_out_of_bounds(tonumber(ARGV[51])) then
    return redis.error_reply('assess_v2: target_ttl_s must be a positive integer no greater than 2147483647 (a persistent target record is not admissible)')
end

-- Distributed clock authority: Redis TIME, not the application clock.
-- App-node skew can otherwise make pressure decay faster or slower on
-- different nodes sharing one state namespace.
local time = redis.call('TIME')
local now = tonumber(time[1]) * 1000 + math.floor(tonumber(time[2]) / 1000)

local function leak(value, elapsed_ms, leak_per_sec)
    local leaked = math.floor(elapsed_ms * leak_per_sec / 1000)
    local next = value - leaked
    if next < 0 then return 0 end
    return next
end

local function normalize(value, saturation)
    if saturation <= 0 then return 0 end
    local scaled = math.floor(value * 1000 / saturation)
    if scaled > 1000 then return 1000 end
    return scaled
end

local function weighted(value, weight)
    return math.floor(value * weight / 1000)
end

local function sum3(a, b, c)
    return a + b + c
end

local function max3(a, b, c)
    local m = a
    if b > m then m = b end
    if c > m then m = c end
    return m
end

local function max4(a, b, c, d)
    local m = a
    if b > m then m = b end
    if c > m then m = c end
    if d > m then m = d end
    return m
end

local STATE_FIELDS = { 'ts','rf','rs','iss','bad','mal','rep','af','sw','trust','scope','cool','fx' }

local function read_state(key, now)
    local v = redis.call('HMGET', key, unpack(STATE_FIELDS))
    local ts = kiwi_decode_integer(v[1], key .. ':ts')
    if ts == nil or ts == 0 then ts = now end
    local elapsed = now - ts
    if elapsed < 0 then elapsed = 0 end
    return {
        ts = now,
        rf    = leak(kiwi_decode_integer(v[2], key .. ':rf') or 0, elapsed, 250),
        rs    = leak(kiwi_decode_integer(v[3], key .. ':rs') or 0, elapsed, 20),
        iss   = leak(kiwi_decode_integer(v[4], key .. ':iss') or 0, elapsed, 40),
        bad   = leak(kiwi_decode_integer(v[5], key .. ':bad') or 0, elapsed, 10),
        mal   = leak(kiwi_decode_integer(v[6], key .. ':mal') or 0, elapsed, 5),
        rep   = leak(kiwi_decode_integer(v[7], key .. ':rep') or 0, elapsed, 5),
        af    = leak(kiwi_decode_integer(v[8], key .. ':af') or 0, elapsed, 5),
        sw    = leak(kiwi_decode_integer(v[9], key .. ':sw') or 0, elapsed, 10),
        trust = leak(kiwi_decode_integer(v[10], key .. ':trust') or 0, elapsed, 2),
        scope = kiwi_decode_integer(v[11], key .. ':scope') or 0,
        cool  = kiwi_decode_integer(v[12], key .. ':cool') or 0,
        fx    = v[13]
    }
end

local function save(key, s, ttl, effect_id)
    local fields = {
        'ts', s.ts, 'rf', s.rf, 'rs', s.rs, 'iss', s.iss,
        'bad', s.bad, 'mal', s.mal, 'rep', s.rep, 'af', s.af,
        'sw', s.sw, 'trust', s.trust, 'scope', s.scope, 'cool', s.cool
    }
    if effect_id ~= '' then
        fields[#fields + 1] = 'fx'
        fields[#fields + 1] = effect_id
    end
    redis.call('HSET', key, unpack(fields))
    if ttl > 0 then
        redis.call('EXPIRE', key, ttl)
    end
end

-- Feedback events mutate the per-identity channels; scope-hopping is a
-- REQUEST property (PreIssue only) so feedback never counts as velocity.
local function apply_feedback(s, event, scope)
    if event == 2 then            -- ChallengeIssued
        s.iss = s.iss + 1000
    elseif event == 3 then        -- SolveSuccess: repay the issued challenge
        -- debt ONLY (trust-neutral, matching canonical risk-v1.lua). A
        -- valid PoW proves expenditure, never legitimacy: trust credit may
        -- come only from server/application-confirmed outcomes, so
        -- attacker-controllable evidence can add risk or pay a specific
        -- debt, never subtract risk.
        s.iss = math.max(0, s.iss - 1000)
    elseif event == 4 then        -- InvalidProof
        s.bad = s.bad + 1500
    elseif event == 5 then        -- MalformedToken
        s.mal = s.mal + 2000
    elseif event == 6 then        -- ExpiredChallenge: small debt effect
        s.iss = s.iss + 300
    elseif event == 7 then        -- ReplayAttempt
        s.rep = s.rep + 3000
    elseif event == 8 then        -- ProtectedActionSuccess: meaningful credit
        s.trust = s.trust + 800
    elseif event == 9 then        -- ProtectedActionFailure
        s.af = s.af + 1200
    elseif event == 10 then       -- AuthenticationSuccess: strong trust
        s.trust = s.trust + 1500
    elseif event == 11 then       -- AuthenticationFailure
        s.af = s.af + 2000
    elseif event == 12 then       -- ConfirmedLegitimate
        s.trust = s.trust + 1000
    elseif event == 13 then       -- ConfirmedAbuse
        s.bad = s.bad + 5000
        s.mal = s.mal + 2500
    elseif event == 14 then       -- RateLimitHit
        s.bad = s.bad + 3000
    -- event 15 (SourceRateLimitHit): handled ONLY for source/session at
    -- the call sites below — a per-source limit must never contaminate
    -- subnet or global pressure (spec: source/session only).
    elseif event == 16 then       -- GlobalCapacityHit: identity-neutral
        -- deliberately nothing: the global state carries the pressure
    elseif event == 17 then       -- RiskDenied: already scored, no-op
        -- deliberately nothing
    elseif event == 21 then       -- ChallengeCancelled: risk-neutral
        -- Deliberately nothing: the issued-and-abandoned challenge keeps
        -- its issue-debt contribution (the signal decays naturally; only
        -- an actual SolveSuccess repays it). The event kind stays for
        -- observability — the cancellation is a resource-lifecycle
        -- operation, never a debt refund.
    elseif event == 22 then       -- StepUpCompleted: server-confirmed trust
        -- Same trust credit as ProtectedActionSuccess (8): a completed
        -- step-up is a server-verified secondary authentication, so it
        -- may decrement risk under the trust-source invariant. NOT 18
        -- (18..20 are the honeypot/decoy kinds). Mixed-version: an older
        -- script falls through here as a no-op — safe in the trust
        -- direction only (a missed credit can never add risk).
        s.trust = s.trust + 800
    end
end

local function apply_event(s, event, scope)
    if event == 1 then
        -- PreIssue: REQUEST velocity + scope hopping.
        s.rf = s.rf + 1000
        s.rs = s.rs + 1000
        if s.scope ~= 0 and s.scope ~= scope then
            s.sw = s.sw + 1000
        end
        s.scope = scope
    end
    apply_feedback(s, event, scope)
end

-- Session state: continuity signal — velocity + feedback, saved when present.
local function apply_session_event(s, event, scope)
    if event == 1 then
        s.rf = s.rf + 1000
        s.rs = s.rs + 1000
        s.scope = scope
    end
    apply_feedback(s, event, scope)
end

-- Principal state: server-confirmed reputation. Trust-centric semantics:
-- successful authenticated/protected operations build principal_credit;
-- failures and confirmed abuse accumulate pressure.
local function apply_principal_event(s, event, scope)
    if event == 8 or event == 10 or event == 12 or event == 22 then
        s.trust = s.trust + 2000
    elseif event == 11 then
        s.af = s.af + 2500
    elseif event == 9 then
        s.af = s.af + 1500
    elseif event == 13 then
        s.bad = s.bad + 6000
        s.mal = s.mal + 3000
    end
end

-- ── Contract bounds (last line of defense): the presented session tags
-- are bounded to 64 bytes by the engines; a direct script caller that
-- exceeds the bound rejects the whole assessment BEFORE any state
-- mutation — never a silent truncation, which would split one session's
-- identity across tag records.
if #ARGV[23] > 64 or #ARGV[24] > 64 then
    return redis.error_reply('session tag exceeds 64 bytes')
end

-- ── Persisted-state preflight: every participating key is type-checked
-- BEFORE the first mutation. Optional slots (session tags, the outcome
-- ledger, the target family) are checked exactly when this invocation
-- uses them; a direct caller that omits unused trailing keys keeps the
-- established wire contract. The per-key `fx` field, written atomically
-- with each state HSET, is the recoverable effect record: a retry of an
-- interrupted invocation re-enters and skips exactly the dimensions
-- whose effect already landed.
for _, i in ipairs({1, 2, 3, 4, 5, 6, 7, 8, 9}) do
    kiwi_assert_type(KEYS[i], 'hash')
end
kiwi_assert_type(KEYS[10], 'string')
if ARGV[23] ~= '' then
    kiwi_assert_type(KEYS[11], 'string')
end
if ARGV[24] ~= '' then
    kiwi_assert_type(KEYS[12], 'string')
end
if ARGV[25] ~= '' then
    kiwi_assert_type(KEYS[13], 'string')
end
if has_target then
    kiwi_assert_type(KEYS[14], 'hash')
    -- The two spread records are HyperLogLogs, which Redis stores as
    -- strings; the target dedupe marker is a string too.
    kiwi_assert_type(KEYS[15], 'string')
    kiwi_assert_type(KEYS[16], 'string')
    kiwi_assert_type(KEYS[17], 'string')
end

-- ── Dedupe: identical event_id must not double-increment state. The
-- marker is written LAST, after every effect. On a duplicate, SKIP the
-- event application but still decay/read/return the current signals.
--
-- The per-event effect completion key (`fxdone`, derived from the
-- dedupe key's own event-id namespace and expiring with the same dedupe
-- TTL as the `fx` marker values) closes the one interleaving the
-- per-key markers cannot: A applies its effects (fx = A everywhere),
-- aborts before its claim; B then runs to completion (fx = B
-- everywhere); A retries — fx no longer says A, so the effects would
-- apply twice. The completion key is written in the same invocation,
-- immediately after the guarded effects and before the claim, and the
-- guards below accept "fx == me OR the completion key exists", so the
-- retry skips the effects and converges by (re)writing the claim.
local event_id = ARGV[4] or ''
local effect_marker = event_id ~= '' and kiwi_effect_marker(event_id, now, dedupe_ttl) or ''
local effect_done_key = event_id ~= '' and KEYS[10] .. ':fxdone' or ''
local is_duplicate = false
if event_id ~= '' and redis.call('GET', KEYS[10]) then
    is_duplicate = true
end
-- The completion record of THIS event id: when it exists, every guarded
-- effect of the event has already landed (it is written only after the
-- last of them), whatever later events did to the per-key markers.
local event_done = event_id ~= ''
    and redis.call('EXISTS', effect_done_key) == 1
    or false

local event = event_arg
local scope = scope_arg
local has_session = ARGV[19] == '1'
local has_principal = ARGV[20] == '1'
-- The optional per-report target dedupe marker. An older caller passes
-- only the sixteen keys and keeps the previous semantics.
local target_marker = KEYS[17]

-- ── Every participating hash is read and strictly decoded BEFORE the
-- first write. An interleaved read-write order would let a corrupt later
-- key abort after an earlier dimension had already been saved. The
-- target record is pre-read with the same rule.
local src = read_state(KEYS[1], now)
local src_prev = read_state(KEYS[2], now)
local src_next = read_state(KEYS[3], now)
local net = read_state(KEYS[4], now)
local net_prev = read_state(KEYS[5], now)
local net_next = read_state(KEYS[6], now)
local sess = read_state(KEYS[7], now)
local prin = read_state(KEYS[8], now)
local g = read_state(KEYS[9], now)
local target_ts = 0
local target_fails = 0
local target_first_ms = 0
local target_fx = false
if has_target then
    local tv = redis.call('HMGET', KEYS[14], 'ts', 'fails', 'first_ms', 'fx')
    target_ts = kiwi_decode_integer(tv[1], KEYS[14] .. ':ts') or 0
    target_fails = kiwi_decode_integer(tv[2], KEYS[14] .. ':fails') or 0
    target_first_ms = kiwi_decode_integer(tv[3], KEYS[14] .. ':first_ms') or 0
    target_fx = tv[4]
end

-- ── Source: update current epoch; the ±1 keys above are boundary reads.
local src_done = event_done or kiwi_effect_matches(src.fx, event_id, now)
if not is_duplicate and not src_done then
    apply_event(src, event, scope)
    if event == 15 then
        -- SourceRateLimitHit: per-source limit — source/session ONLY.
        src.bad = src.bad + 3000
    end
    save(KEYS[1], src, state_ttl, effect_marker)
end

-- ── Subnet: same pattern.
local net_done = event_done or kiwi_effect_matches(net.fx, event_id, now)
if not is_duplicate and not net_done then
    apply_event(net, event, scope)
    save(KEYS[4], net, state_ttl, effect_marker)
end

-- ── Session (continuity) and principal (authenticated reputation).
local sess_done = event_done or kiwi_effect_matches(sess.fx, event_id, now)
if has_session and not is_duplicate and not sess_done then
    apply_session_event(sess, event, scope)
    if event == 15 then
        -- SourceRateLimitHit: session half of the source/session-only rule.
        sess.bad = sess.bad + 3000
    end
    save(KEYS[7], sess, session_ttl, effect_marker)
end
local prin_done = event_done or kiwi_effect_matches(prin.fx, event_id, now)
if has_principal and not is_duplicate and not prin_done then
    apply_principal_event(prin, event, scope)
    save(KEYS[8], prin, principal_ttl, effect_marker)
end

-- ── Global: rolling (no expiry). The global hash's `scope` field carries
-- the CURRENT LEVEL; apply_event clobbers it with the event scope, so the
-- level is captured BEFORE the event and restored after the ratchet. The
-- state is saved ONCE, after the ratchet. A retry whose effect already
-- landed (fx match) keeps the stored level and cooldown untouched.
-- (The global hash was read with the other dimensions above.)
-- Corrupt or tampered stored levels above the hysteresis table are
-- clamped into range (the Rust core applies the same .min(4)). The floor
-- stays 0: a fresh state legitimately starts at level 0.
local prev_level = math.min(4, g.scope)
local g_done = event_done or kiwi_effect_matches(g.fx, event_id, now)
if not is_duplicate and not g_done then
    apply_event(g, event, scope)
    if event == 16 then
        -- GlobalCapacityHit: deployment overload raises the global
        -- attack/resource pressure WITHOUT contaminating the visitor's
        -- source/session/principal reputation.
        g.bad = g.bad + 3000
    end
end

local gp = g.rf + g.rs + g.iss + g.bad + g.mal + g.rep + g.af
local level = prev_level
-- The ratchet and the decayed save run even for a duplicate or an
-- already-applied retry: a repeated probe still advances the global
-- clock and may lower the level after the cooldown.
do
    -- ── Global pressure level with hysteresis (normalized thresholds). ──
    local gnorm = normalize(gp, tonumber(ARGV[16]))
    local enter = { 300, 550, 750, 900 }
    local exit = { 250, 450, 650, 850 }
    local target = 0
    for i = 4, 1, -1 do
        if gnorm >= enter[i] then
            target = i
            break
        end
    end
    if target > level then
        level = target
        g.cool = now + tonumber(ARGV[7])
    elseif target < level and gnorm < exit[math.max(1, level)] then
        if now >= g.cool then
            level = target
            g.cool = 0
        end
    end
    g.scope = level
    -- A duplicate or a converged retry never claims the current event
    -- id: the former already carries whichever effect marker the first
    -- delivery wrote, the latter holds its completion key instead.
    save(KEYS[9], g, 0, (is_duplicate or event_done) and '' or effect_marker)
end

-- ── Aggregate (v3) + normalize (SignalVector order). ──
-- Rotated-epoch pseudonyms of one identity SUM (decay already applied);
-- different identity dimensions (source/session/principal) MAX.
local src_rf = sum3(src.rf, src_prev.rf, src_next.rf)
local src_rs = sum3(src.rs, src_prev.rs, src_next.rs)
local src_iss = sum3(src.iss, src_prev.iss, src_next.iss)
local src_bad = sum3(src.bad, src_prev.bad, src_next.bad)
local src_mal = sum3(src.mal, src_prev.mal, src_next.mal)
local src_rep = sum3(src.rep, src_prev.rep, src_next.rep)
local src_af = sum3(src.af, src_prev.af, src_next.af)
local src_sw = sum3(src.sw, src_prev.sw, src_next.sw)
local src_trust = sum3(src.trust, src_prev.trust, src_next.trust)
local net_rf = sum3(net.rf, net_prev.rf, net_next.rf)

-- ── Risk-v2 first-seen session records (SET NX, session TTL). ──
-- The presented client-context / trusted-edge TLS tags (ARGV[23] /
-- ARGV[24], '' = none presented) are recorded first-write-wins under the
-- session TTL (ARGV[21]); the recorded values are returned with the
-- vector so the engine derives the session-consistency signals without
-- extra round trips. The records are keyed by the session pseudonym only
-- (the raw cookie value never appears in Redis), share the hash tag with
-- the risk-v1 state keys (Cluster safe) and expire with the session —
-- the tags stay ephemeral and session-keyed.
local existing_ctx = ''
if ARGV[23] ~= '' then
    local ok = redis.call('SET', KEYS[11], ARGV[23], 'EX', session_ttl, 'NX')
    if ok then
        existing_ctx = ARGV[23]
    else
        local v = redis.call('GET', KEYS[11])
        if v then existing_ctx = v end
    end
end
local existing_tls = ''
if ARGV[24] ~= '' then
    local ok = redis.call('SET', KEYS[12], ARGV[24], 'EX', session_ttl, 'NX')
    if ok then
        existing_tls = ARGV[24]
    else
        local v = redis.call('GET', KEYS[12])
        if v then existing_tls = v end
    end
end

-- ── SignalVector (13 slots, fixed order). ──
local sig_src_fast = normalize(max3(src_rf, sess.rf, 0), tonumber(ARGV[8]))
local sig_src_slow = normalize(max3(src_rs, sess.rs, 0), tonumber(ARGV[9]))
local sig_subnet_fast = normalize(net_rf, tonumber(ARGV[8]))
local sig_issue_debt = normalize(max3(src_iss, sess.iss, 0), tonumber(ARGV[10]))
local sig_bad_proof = normalize(max4(src_bad, sess.bad, prin.bad, 0), tonumber(ARGV[11]))
local sig_malformed = normalize(max4(src_mal, sess.mal, prin.mal, 0), tonumber(ARGV[12]))
local sig_replay = normalize(max3(src_rep, sess.rep, 0), tonumber(ARGV[13]))
local sig_action_failure = normalize(max4(src_af, sess.af, prin.af, 0), tonumber(ARGV[14]))
local sig_scope_switch = normalize(max3(src_sw, sess.sw, 0), tonumber(ARGV[15]))
local sig_global_pressure = normalize(gp, tonumber(ARGV[16]))
local sig_network_risk = 0
local sig_trust_credit = normalize(max3(src_trust, sess.trust, 0), tonumber(ARGV[17]))
local sig_principal_credit = normalize(prin.trust, tonumber(ARGV[18]))

-- ── Outcome-ledger registration (SET NX EX, pending entry). ──
-- The pending entry mirrors outcome_register.lua byte-for-byte
-- {"o":"P","scope","hour","score","w":1}. The ledger score is the exact
-- decision score the engines compute (base + the weighted 13 signals
-- minus trust/principal credit, then the weighted risk-v2 factors,
-- clamped 0..1000): the risk-v2 signals are derived here from the
-- recorded tags exactly as the engine derives them from the returned
-- tags, so the ledger is byte-identical to the calibration-less
-- registerOutcome path without an extra round trip. Failures are not
-- possible here beyond the SET NX collision (a retried decision_id);
-- a script error still fails the whole assessment (fail-closed), exactly
-- as any risk-v1 observation error does.
-- ── Target-account protection (change.md 3.2.1 / 3.3.3): the failure
-- counter and the source/asn spread HLLs of the target dimension. An
-- AuthenticationFailure (11) reported against the target increments the
-- leaky bucket and PFADDs the failing source/asn; the assessment reply
-- carries the decayed failure pressure and the spread so the decision
-- path can protect the account (the marks stage maps an attacked target
-- to exactly the interactive step-up). Failures are stored by THIS
-- engine state, never by callers: a denied attempt never reaches
-- authentication and so never writes here. The same pressure and spread
-- feed the ledger score so the numeric decision reacts to a stuffed
-- target, not only the policy stage.
local target_failures = 0
local target_spread_sources = 0
local target_spread_asns = 0
if has_target then
    local LEAK_MS = 60000
    local ts = target_ts
    local fails = target_fails
    local first_ms = target_first_ms
    local target_done = event_done or kiwi_effect_matches(target_fx, event_id, now)
    if ts > 0 then
        local elapsed = now - ts
        if elapsed < 0 then elapsed = 0 end
        -- The leak watermark advances only by whole leaked minutes
        -- (ts + leaked * LEAK_MS), never to `now`: resetting it on
        -- every failure would erase the sub-minute remainder and
        -- suspend the leak for as long as failures keep arriving less
        -- than a minute apart (mirror of target_failure.lua).
        local leaked = math.floor(elapsed / LEAK_MS)
        fails = fails - leaked
        if fails < 0 then fails = 0 end
        ts = ts + leaked * LEAK_MS
    end
    if event == 11 and not is_duplicate and not target_done then
        -- One report event id books one target failure. The target
        -- marker is the same key target_failure.lua writes, so a report
        -- delivered through both paths is booked once. The counter HSET
        -- carries this invocation's `fx` marker, so a retry after an
        -- abort skips only the booking that already landed; the PFADDs
        -- below stay idempotent for the same elements.
        local target_duplicate = false
        if target_marker and event_id ~= '' and redis.call('GET', target_marker) then
            target_duplicate = true
        end
        if not target_duplicate then
            fails = fails + 1
            if ts == 0 then ts = now end
            if first_ms == 0 then first_ms = now end
            local target_fields = {
                'ts', ts, 'fails', fails,
                'last_ms', now, 'first_ms', first_ms
            }
            if event_id ~= '' then
                target_fields[#target_fields + 1] = 'fx'
                target_fields[#target_fields + 1] = effect_marker
            end
            redis.call('HSET', KEYS[14], unpack(target_fields))
            redis.call('PEXPIRE', KEYS[14], tonumber(ARGV[51]) * 1000)
        end
    end
    if event == 11 and not is_duplicate then
        -- A recoverable retry re-runs the idempotent spread writes even
        -- when the counter booking already landed: PFADD of the same
        -- element adds no cardinality, and a missing PFADD on the failed
        -- attempt is repaired here. The target claim is written LAST.
        if ARGV[49] and ARGV[49] ~= '' then
            redis.call('PFADD', KEYS[15], ARGV[49])
            redis.call('PEXPIRE', KEYS[15], tonumber(ARGV[51]) * 1000)
        end
        if ARGV[50] and ARGV[50] ~= '' then
            redis.call('PFADD', KEYS[16], ARGV[50])
            redis.call('PEXPIRE', KEYS[16], tonumber(ARGV[51]) * 1000)
        end
        if target_marker and event_id ~= '' then
            redis.call('SET', target_marker, '1', 'EX', dedupe_ttl)
        end
    end
    target_failures = fails
    -- The source and ASN spreads are kept separate: summing them would
    -- let one dimension's growth masquerade as the other's.
    target_spread_sources = redis.call('PFCOUNT', KEYS[15])
    target_spread_asns = redis.call('PFCOUNT', KEYS[16])
end

local registration_status = 0
if ARGV[25] ~= '' then
    local score_gp = sig_global_pressure
    if ARGV[29] ~= '1' then score_gp = 0 end
    local risk = tonumber(ARGV[30])
    risk = risk + weighted(sig_src_fast, tonumber(ARGV[32]))
    risk = risk + weighted(sig_src_slow, tonumber(ARGV[33]))
    risk = risk + weighted(sig_subnet_fast, tonumber(ARGV[34]))
    risk = risk + weighted(sig_issue_debt, tonumber(ARGV[35]))
    risk = risk + weighted(sig_bad_proof, tonumber(ARGV[36]))
    risk = risk + weighted(sig_malformed, tonumber(ARGV[37]))
    risk = risk + weighted(sig_replay, tonumber(ARGV[38]))
    risk = risk + weighted(sig_action_failure, tonumber(ARGV[39]))
    risk = risk + weighted(sig_scope_switch, tonumber(ARGV[40]))
    risk = risk + weighted(score_gp, tonumber(ARGV[41]))
    risk = risk + weighted(tonumber(ARGV[28]), tonumber(ARGV[42]))
    risk = risk - weighted(sig_trust_credit, tonumber(ARGV[43]))
    risk = risk - weighted(sig_principal_credit, tonumber(ARGV[44]))
    if risk < 0 then risk = 0 elseif risk > 1000 then risk = 1000 end
    local v2_honeypot = 0
    if ARGV[31] == '1' or event == 18 or event == 19 or event == 20 then
        v2_honeypot = 1000
    end
    local v2_session = 0
    if existing_ctx ~= '' and existing_ctx ~= ARGV[23] then
        v2_session = 1000
    end
    local v2_tls = 0
    if existing_tls ~= '' and existing_tls ~= ARGV[24] then
        v2_tls = 1000
    end
    risk = risk + weighted(v2_honeypot, tonumber(ARGV[45]))
    risk = risk + weighted(v2_session, tonumber(ARGV[46]))
    risk = risk + weighted(v2_tls, tonumber(ARGV[47]))
    -- Target pressure and spread: five failures or twenty distinct
    -- sources saturate at 1000, matching the engine's target helpers.
    -- The scored spread is the wider of the two dimensions (never the
    -- sum: sources+asns would double-count one campaign's growth).
    local v2_tfail = normalize(target_failures, 5)
    local v2_tspread = normalize(math.max(target_spread_sources, target_spread_asns), 20)
    risk = risk + weighted(v2_tfail, tonumber(ARGV[52] or '0'))
    risk = risk + weighted(v2_tspread, tonumber(ARGV[53] or '0'))
    if risk < 0 then risk = 0 elseif risk > 1000 then risk = 1000 end
    local ledger = cjson.encode({
        o = 'P',
        scope = scope,
        hour = tonumber(ARGV[26]),
        score = risk,
        w = 1
    })
    if redis.call('SET', KEYS[13], ledger, 'NX', 'EX', tonumber(ARGV[27])) then
        registration_status = 1
    end
end

-- The effect completion key lands immediately after the guarded effects
-- (terminal ledger registration included) and BEFORE the dedupe claim:
-- an attempt that stops anywhere short of the claim is finished by a
-- retry that finds this key (or its own fx markers) and rewrites the
-- claim instead of re-applying the effects. It expires with the same
-- dedupe TTL as the fx marker values, so it cannot outlive the claims
-- and markers it complements.
if event_id ~= '' and not is_duplicate then
    redis.call('SET', effect_done_key, '1', 'EX', dedupe_ttl)
    redis.call('SET', KEYS[10], '1', 'EX', dedupe_ttl)
end

return {
    sig_src_fast,
    sig_src_slow,
    sig_subnet_fast,
    sig_issue_debt,
    sig_bad_proof,
    sig_malformed,
    sig_replay,
    sig_action_failure,
    sig_scope_switch,
    sig_global_pressure,
    sig_network_risk,                                -- network_risk (classifier side-channel)
    sig_trust_credit,
    sig_principal_credit,
    level,
    g.cool,
    is_duplicate and 1 or 0,
    existing_ctx,
    existing_tls,
    registration_status,
    target_failures,
    target_spread_sources,
    target_spread_asns
}
