-- Risk Protocol v1 — canonical production state script (v2 semantics).
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
--   [1]  event             RiskEventKind int (1..14)
--   [2]  scope             int (0 = unknown)
--   [3]  now_ms            server clock, ms
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
-- Event semantics (risk-v1 v2):
--   PreIssue (1)            → request velocity + scope-hopping
--   ChallengeIssued (2)     → issue_debt
--   SolveSuccess (3)        → repay debt, tiny trust
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
--
-- Only PreIssue counts as a REQUEST for velocity purposes; feedback events
-- mutate only their own channels.

local function num(v)
    if not v then return 0 end
    return tonumber(v) or 0
end

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

local function max3(a, b, c)
    local m = a
    if b > m then m = b end
    if c > m then m = c end
    return m
end

local STATE_FIELDS = { 'ts','rf','rs','iss','bad','mal','rep','af','sw','trust','scope','cool' }

local function read_state(key, now)
    local v = redis.call('HMGET', key, unpack(STATE_FIELDS))
    local ts = num(v[1])
    if ts == 0 then ts = now end
    local elapsed = now - ts
    if elapsed < 0 then elapsed = 0 end
    return {
        ts = now,
        rf    = leak(num(v[2]),  elapsed, 250),
        rs    = leak(num(v[3]),  elapsed, 20),
        iss   = leak(num(v[4]),  elapsed, 40),
        bad   = leak(num(v[5]),  elapsed, 10),
        mal   = leak(num(v[6]),  elapsed, 5),
        rep   = leak(num(v[7]),  elapsed, 5),
        af    = leak(num(v[8]),  elapsed, 5),
        sw    = leak(num(v[9]),  elapsed, 10),
        trust = leak(num(v[10]), elapsed, 2),
        scope = num(v[11]),
        cool  = num(v[12])
    }
end

local function save(key, s, ttl)
    redis.call('HSET', key,
        'ts', s.ts, 'rf', s.rf, 'rs', s.rs, 'iss', s.iss,
        'bad', s.bad, 'mal', s.mal, 'rep', s.rep, 'af', s.af,
        'sw', s.sw, 'trust', s.trust, 'scope', s.scope, 'cool', s.cool)
    if ttl > 0 then
        redis.call('EXPIRE', key, ttl)
    end
end

-- Feedback events mutate the per-identity channels; scope-hopping is a
-- REQUEST property (PreIssue only) so feedback never counts as velocity.
local function apply_feedback(s, event, scope)
    if event == 2 then            -- ChallengeIssued
        s.iss = s.iss + 1000
    elseif event == 3 then        -- SolveSuccess: repay debt, tiny trust
        s.iss = math.max(0, s.iss - 1000)
        s.trust = s.trust + 150
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
    if event == 8 or event == 10 or event == 12 then
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

-- ── Dedupe: identical event_id must not double-increment state. On a
-- duplicate, SKIP the event application but still decay/read/return the
-- current signals (shared risk-v1 semantics across Rust and PHP).
local is_duplicate = false
if ARGV[4] ~= '' then
    if redis.call('GET', KEYS[10]) then
        is_duplicate = true
    else
        redis.call('SET', KEYS[10], '1', 'EX', tonumber(ARGV[5]))
    end
end

local now = tonumber(ARGV[3])
local event = tonumber(ARGV[1])
local scope = tonumber(ARGV[2])
local state_ttl = tonumber(ARGV[6])
local has_session = tonumber(ARGV[19]) == 1
local has_principal = tonumber(ARGV[20]) == 1

-- ── Source: update current epoch, read ±1 for boundary continuity. ──
local src = read_state(KEYS[1], now)
if not is_duplicate then
    apply_event(src, event, scope)
    save(KEYS[1], src, state_ttl)
end
local src_prev = read_state(KEYS[2], now)
local src_next = read_state(KEYS[3], now)

-- ── Subnet: same pattern. ──
local net = read_state(KEYS[4], now)
if not is_duplicate then
    apply_event(net, event, scope)
    save(KEYS[4], net, state_ttl)
end
local net_prev = read_state(KEYS[5], now)
local net_next = read_state(KEYS[6], now)

-- ── Session (continuity) and principal (authenticated reputation). ──
local sess = read_state(KEYS[7], now)
if has_session and not is_duplicate then
    apply_session_event(sess, event, scope)
    save(KEYS[7], sess, tonumber(ARGV[21]))
end
local prin = read_state(KEYS[8], now)
if has_principal and not is_duplicate then
    apply_principal_event(prin, event, scope)
    save(KEYS[8], prin, tonumber(ARGV[22]))
end

-- ── Global: rolling (no expiry). The global hash's `scope` field carries
-- the CURRENT LEVEL; apply_event clobbers it with the event scope, so the
-- level is captured BEFORE the event and restored after the ratchet. ──
local g = read_state(KEYS[9], now)
local prev_level = g.scope
if not is_duplicate then
    apply_event(g, event, scope)
    save(KEYS[9], g, 0)
end

-- ── Global pressure level with hysteresis (normalized thresholds). ──
local gp = g.rf + g.rs + g.iss + g.bad + g.mal + g.rep + g.af
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
local level = prev_level
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
save(KEYS[9], g, 0)

-- ── Aggregate + normalize (SignalVector order). ──
local trust = max3(src.trust, sess.trust, prin.trust)

return {
    normalize(max3(src.rf, src_prev.rf, src_next.rf),   tonumber(ARGV[8])),
    normalize(max3(src.rs, src_prev.rs, src_next.rs),   tonumber(ARGV[9])),
    normalize(max3(net.rf, net_prev.rf, net_next.rf),   tonumber(ARGV[8])),
    normalize(max3(src.iss, src_prev.iss, src_next.iss), tonumber(ARGV[10])),
    normalize(max3(src.bad, src_prev.bad, src_next.bad), tonumber(ARGV[11])),
    normalize(max3(src.mal, src_prev.mal, src_next.mal), tonumber(ARGV[12])),
    normalize(max3(src.rep, src_prev.rep, src_next.rep), tonumber(ARGV[13])),
    normalize(max3(src.af, src_prev.af, src_next.af),    tonumber(ARGV[14])),
    normalize(max3(src.sw, src_prev.sw, src_next.sw),    tonumber(ARGV[15])),
    normalize(gp,                                        tonumber(ARGV[16])),
    0,                                                             -- network_risk (classifier side-channel)
    normalize(trust,                                     tonumber(ARGV[17])),
    normalize(prin.trust,                                tonumber(ARGV[18])),
    level,
    g.cool,
    is_duplicate and 1 or 0
}
