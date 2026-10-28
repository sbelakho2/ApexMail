-- Risk Protocol v1 — canonical production state script (v4 semantics).
--
-- SCRIPT BOUNDS — all bounded constants, no attacker-sized
-- collections anywhere in this script:
--   max keys touched:     11 (KEYS[1..10] plus the per-event effect
--                          completion key derived below as
--                          KEYS[10] .. ':fxdone', same hash tag)
--   max Redis calls:      33 (10 TYPE + 1 TIME + 9 HMGET + 5 HSET +
--                           4 EXPIRE + 2 GET/EXISTS + 2 SET — every call
--                           is fixed-cost;
--                           no KEYS/SCAN/EVAL nesting, no iteration over
--                           attacker-sized collections)
--   max collection cardinality: 13 flat fields per state hash (the
--                           HMGET reply of STATE_FIELDS, which carries
--                           the 12 state fields plus the per-event `fx`
--                           effect marker); the sum3/max3/max4
--                           aggregation touches at most 4 elements.
-- The script's runtime is therefore O(1) in the state size and bounded
-- by the constants above regardless of traffic volume.
--
-- One atomic assessment: read → decay → apply event → aggregate → normalize,
-- across (all keys share the hash tag {kiwi:<deployment>} — Redis Cluster safe):
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
--
-- Returns (SignalVector order + extras):
--   source_fast, source_slow, subnet_fast, issue_debt, bad_proof, malformed,
--   replay, action_failure, scope_switch, global_pressure, network_risk(0),
--   trust_credit, principal_credit, global_level(0..4), cooldown_until_ms,
--   is_duplicate (0/1)
--
-- Event semantics (risk-v1 v3):
--   PreIssue (1)            → request velocity + scope-hopping
--   ChallengeIssued (2)     → issue_debt
--   SolveSuccess (3)        → repay debt only (NEVER trust: a valid PoW
--                              proves expenditure, which the economic
--                              model explicitly permits bots to pay —
--                              legitimacy credit comes only from
--                              server/application-confirmed outcomes)
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
        -- debt ONLY. A valid PoW proves the actor spent the required
        -- resource, which the economic model explicitly permits bots to
        -- do — it does not prove legitimacy. Trust credit (negative
        -- risk) must come only from server/application-confirmed
        -- outcomes (ProtectedActionSuccess, AuthenticationSuccess,
        -- ConfirmedLegitimate): attacker-controllable evidence may add
        -- risk or pay a specific debt, never subtract risk.
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

-- ── Every TTL argument is validated here, BEFORE the first write. A
-- non-positive TTL would make a risk hash persistent (save() skips
-- EXPIRE on ttl <= 0) or issue an invalid `SET ... EX 0`; a TTL above
-- the Redis expire ceiling would abort the script after the HSET had
-- already landed, leaving a persistent risk hash behind. The ceiling
-- (2147483647 seconds) is the largest expire value every Redis version
-- accepts. The PHP and Rust store constructors enforce the identical
-- positive-and-bounded rule at their public boundary.
local EXPIRY_CEILING_SECS = 2147483647

local function ttl_out_of_bounds(value)
    if value == nil or value < 1 or value > EXPIRY_CEILING_SECS then
        return true
    end
    return value ~= math.floor(value)
end

local dedupe_ttl = tonumber(ARGV[5])
local state_ttl = tonumber(ARGV[6])
local session_ttl = tonumber(ARGV[21])
local principal_ttl = tonumber(ARGV[22])
if ttl_out_of_bounds(dedupe_ttl) then
    return redis.error_reply('risk-v1: dedupe_ttl_s must be a positive integer no greater than 2147483647 (a persistent or immediately-expired risk hash is not admissible)')
end
if ttl_out_of_bounds(state_ttl) then
    return redis.error_reply('risk-v1: state_ttl_s must be a positive integer no greater than 2147483647 (a persistent source/subnet risk hash is not admissible)')
end
if ttl_out_of_bounds(session_ttl) then
    return redis.error_reply('risk-v1: session_ttl_s must be a positive integer no greater than 2147483647 (a persistent session risk hash is not admissible)')
end
if ttl_out_of_bounds(principal_ttl) then
    return redis.error_reply('risk-v1: principal_ttl_s must be a positive integer no greater than 2147483647 (a persistent principal risk hash is not admissible)')
end

-- ── Numeric argument validation BEFORE any write. ──
-- Redis does not roll back: the historical order wrote the dedupe marker
-- first and parsed the numeric arguments afterwards, so a missing or
-- non-numeric saturation ARGV errored (nil comparison) AFTER the event
-- was marked seen. The event was silently lost and an identical retry
-- was refused as a duplicate. A value that passes a bare tonumber()
-- check but is NaN or infinite can corrupt a state field or abort a
-- later operation after the first write, so every numeric argument is
-- validated as a FINITE number here, before the first write.
local function finite_number(value)
    local n = tonumber(value)
    if n == nil or n ~= n or n == math.huge or n == -math.huge then
        return nil
    end
    return n
end

for _, i in ipairs({1, 2, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20}) do
    if finite_number(ARGV[i]) == nil then
        return redis.error_reply('risk-v1: ARGV['..i..'] must be a finite number')
    end
end
local event_arg = finite_number(ARGV[1])
if event_arg ~= math.floor(event_arg) or event_arg < 1 or event_arg > 22 then
    return redis.error_reply('risk-v1: event must be an integer within 1..22')
end
local scope_arg = finite_number(ARGV[2])
if scope_arg ~= math.floor(scope_arg) then
    return redis.error_reply('risk-v1: scope must be an integer')
end
local hysteresis_arg = finite_number(ARGV[7])
if hysteresis_arg < 1 or hysteresis_arg ~= math.floor(hysteresis_arg) then
    return redis.error_reply('risk-v1: hysteresis_ms must be a positive integer')
end
for _, i in ipairs({8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18}) do
    local saturation = finite_number(ARGV[i])
    if saturation < 1 or saturation ~= math.floor(saturation) then
        return redis.error_reply('risk-v1: ARGV['..i..'] must be a positive integer saturation')
    end
end
if ARGV[19] ~= '0' and ARGV[19] ~= '1' then
    return redis.error_reply('risk-v1: has_session must be 0 or 1')
end
if ARGV[20] ~= '0' and ARGV[20] ~= '1' then
    return redis.error_reply('risk-v1: has_principal must be 0 or 1')
end

-- ── Persisted-state preflight: every participating key is type-checked
-- BEFORE the first mutation. A collision (a restored backup, a legacy
-- writer or an operator mistake) must fail with no write at all, so a
-- retry can never observe a marker for an event whose state was lost.
-- The per-key effect marker (`fx`, written atomically with the state
-- HSET below) is what makes a retried invocation finish exactly the
-- dimensions a failed attempt left unwritten.
for _, i in ipairs({1, 2, 3, 4, 5, 6, 7, 8, 9}) do
    kiwi_assert_type(KEYS[i], 'hash')
end
kiwi_assert_type(KEYS[10], 'string')

-- ── Dedupe: identical event_id must not double-increment state. The
-- marker is written LAST, after every state effect. A script that aborts
-- does not roll back, so a marker written first would turn a partial
-- application into an event that a retry refuses as a duplicate. With
-- the marker last, a retry re-enters; each dimension's own `fx` marker
-- makes the already-applied dimensions a no-op.
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

-- The zero-skip in save() stays intentional for the GLOBAL rolling state
-- (KEYS[9], the one no-expiry record, written with ttl 0 below). The
-- ephemeral per-identity TTLs were already validated above, before the
-- first write.

-- ── Every participating hash is read and strictly decoded BEFORE the
-- first write. An interleaved read-write order would let a corrupt later
-- key abort after an earlier dimension had already been saved.
local src = read_state(KEYS[1], now)
local src_prev = read_state(KEYS[2], now)
local src_next = read_state(KEYS[3], now)
local net = read_state(KEYS[4], now)
local net_prev = read_state(KEYS[5], now)
local net_next = read_state(KEYS[6], now)
local sess = read_state(KEYS[7], now)
local prin = read_state(KEYS[8], now)
local g = read_state(KEYS[9], now)

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
-- state is saved ONCE, after the ratchet — the event application only
-- mutates the in-memory table `g`; the single unconditional save below
-- persists the final level, cooldown and channels in one HSET (a save
-- inside the non-duplicate branch here would be a strict subset of it:
-- the same fields one HSET earlier, doubled for no effect).
-- (The global hash was read with the other dimensions above.)
-- Corrupt or tampered stored levels above the hysteresis table are
-- clamped into range (the Rust core applies the same .min(4)); a nil
-- exit entry would otherwise error mid-transition. The floor stays 0: a
-- fresh state legitimately starts at level 0, and forcing a minimum of
-- 1 here would raise every namespace's baseline pressure.
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

-- The effect completion key lands immediately after the guarded effects
-- and BEFORE the dedupe claim: an attempt that stops anywhere short of
-- the claim is finished by a retry that finds this key (or its own fx
-- markers) and rewrites the claim instead of re-applying the effects.
-- It expires with the same dedupe TTL as the fx marker values, so it
-- cannot outlive the claims and markers it complements.
if event_id ~= '' and not is_duplicate then
    redis.call('SET', effect_done_key, '1', 'EX', dedupe_ttl)
    redis.call('SET', KEYS[10], '1', 'EX', dedupe_ttl)
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

return {
    normalize(max3(src_rf, sess.rf, 0),              tonumber(ARGV[8])),
    normalize(max3(src_rs, sess.rs, 0),              tonumber(ARGV[9])),
    normalize(net_rf,                                tonumber(ARGV[8])),
    normalize(max3(src_iss, sess.iss, 0),            tonumber(ARGV[10])),
    normalize(max4(src_bad, sess.bad, prin.bad, 0),  tonumber(ARGV[11])),
    normalize(max4(src_mal, sess.mal, prin.mal, 0),  tonumber(ARGV[12])),
    normalize(max3(src_rep, sess.rep, 0),            tonumber(ARGV[13])),
    normalize(max4(src_af, sess.af, prin.af, 0),     tonumber(ARGV[14])),
    normalize(max3(src_sw, sess.sw, 0),              tonumber(ARGV[15])),
    normalize(gp,                                    tonumber(ARGV[16])),
    0,                                                         -- network_risk (classifier side-channel)
    normalize(max3(src_trust, sess.trust, 0),        tonumber(ARGV[17])),
    normalize(prin.trust,                            tonumber(ARGV[18])),
    level,
    g.cool,
    is_duplicate and 1 or 0
}
