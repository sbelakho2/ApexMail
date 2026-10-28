-- Principal first-seen network tags: one atomic seen/record/trust.
--
-- SCRIPT BOUNDS — all bounded constants:
--   max keys touched:     1 (the principal's tag hash; key form
--                           pnet:{kiwi:<ns>:<principal_hex>}, the hash
--                           tag carrying the whole principal identity,
--                           so one principal owns one Cluster slot)
--   max Redis calls:      9 + 2*evicted (1 TYPE + 1 TIME + 2 HGETALL +
--                          1 HGET + 1 HSET
--                           [+ 1 HSET trust] + 1 HGETALL + up to 2
--                           HDELs per evicted victim, bounded by the
--                           cap ceiling, + 1 further HGETALL when that
--                           eviction removed fields + 1 PEXPIRE on the
--                           record path; strictly fewer on the read
--                           paths. The forget_devices and
--                           has_any_trusted paths touch 2: 1 TIME + 1
--                           HGETALL each, and neither reads a field one
--                           at a time)
--   max collection cardinality: 224 hash fields (32 session + 16 device
--                           + 64 net + 64 asn + 32+16+64+64 trust flags)
--
-- KEYS[1] principal tag hash (key form pnet:{kiwi:<ns>:<principal_hex>}.
-- The older spellings {kiwi:<ns>}:pnet:<principal> and
-- kiwi:<ns>:pnet:{<principal_hex>} named two different key forms for
-- the same hash in earlier headers; this one is canonical: the hash
-- tag carries the whole principal, so a Cluster never routes two
-- principals to one hot slot).
-- ARGV[1] operation: 'seen', 'record', 'has_trusted', 'has_any_trusted',
--         or 'forget_devices'.
-- ARGV[2] tag (net:<hex>, asn:<decimal|u4/prefix|u6/prefix>,
--         session:<hex>, device:<hex>) — not read by forget_devices
--         and has_any_trusted.
-- ARGV[3] class_ttl_ms (REQUIRED for seen, record and has_trusted: the
--         caller's CONFIGURED class TTL, validated against the class
--         range. The read paths answer "not seen" past the caller's
--         TTL, never past the class maximum — a stored value can never
--         vouch past the lifetime the deployment actually configured.
--         forget_devices and has_any_trusted need no TTL: one deletes,
--         the other probes against each field's own class ceiling.)
-- ARGV[4] class_cap (record only).
-- ARGV[5] trust ('1' = mint trust on record, '' or absent = do not).
--
-- The hash holds two kinds of field per tag: the bare tag carries the
-- last-use ms (Redis TIME, never a client clock), and a `t:` prefixed
-- mirror carries the trust flag ('1'). Trust is minted only on an Allow
-- or a completed step-up — a Deny path can never create a `t:` field.
-- has_trusted checks both the bare tag (for expiry, against the
-- caller's ARGV[3] TTL) and the trust flag.
--
-- Class policy (validated against the TTL/cap bounds below):
--   session:  cap 32, TTL = 2x the continuity cookie TTL (default 3600 s)
--   device:   cap 16, TTL = the trusted-device TTL (default 90 days)
--   net/asn:  cap 64 each, TTL = 400 days
--
-- LRU: the record path evicts the least-recently-used entries in the
-- same class above the cap, reading the last-use value (never insertion
-- order). The tag just written is excluded from the eviction
-- candidates: a same-millisecond tie must never evict the entry the
-- caller just wrote (Lua's sort is not stable, so without the
-- exclusion a tie would be free to pick it). A trust flag is evicted
-- with its tag.
--
-- PEXPIRE is computed AFTER the eviction, over the surviving fields,
-- so the key expires when its oldest surviving class would.
--
-- Every argument is validated BEFORE the first write: a hostile tag,
-- TTL or cap errors with the hash untouched. RESP2 false/nil is
-- treated as absent, matching assess_v2.
local EXPIRY_CEILING_MS = 2147483647 * 1000
local MAX_CAP = 256

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

-- Class bounds: the TTL range each class may request and its cap ceiling.
local CLASS_TTL_MIN = {
    session = 60000,        -- 1 minute
    device = 60000,
    net = 86400000,         -- 1 day
    asn = 86400000,
}
local CLASS_TTL_MAX = {
    session = 86400000,     -- 1 day (2x a 12-hour cookie at most)
    device = 31536000000,   -- 365 days
    net = 34560000000,      -- 400 days
    asn = 34560000000,
}

local function classify(tag)
    local prefix = string.match(tag, '^([a-z]+):')
    if prefix == 'net' or prefix == 'session' or prefix == 'device' or prefix == 'asn' then
        return prefix
    end
    return nil
end

local function valid_tag(tag)
    if tag == nil or tag == '' or #tag > 80 then
        return false
    end
    -- net:<hex 1-64>, session:<hex 1-64>, device:<hex 1-64>
    if string.match(tag, '^net:[0-9a-f]+$') and #tag > 4 and #tag <= 68 then
        return true
    end
    if string.match(tag, '^session:[0-9a-f]+$') and #tag > 8 and #tag <= 72 then
        return true
    end
    if string.match(tag, '^device:[0-9a-f]+$') and #tag > 7 and #tag <= 71 then
        return true
    end
    -- asn:<decimal 1-10> and the unlisted-namespace buckets:
    -- asn:u4/<decimal /16 prefix>, asn:u6/<8 hex of the /32 prefix>.
    -- A refused unlisted bucket fails tag validation and the novelty
    -- gate then fails open for exactly those networks.
    if string.match(tag, '^asn:[1-9]%d*$') and #tag <= 14 then return true end
    if tag == 'asn:0' then return true end
    if string.match(tag, '^asn:u4/[1-9]%d*$') and #tag <= 12 then return true end
    if tag == 'asn:u4/0' then return true end
    if string.match(tag, '^asn:u6/[0-9a-f]+$') and #tag == 15 then return true end
    -- bare hex: the engine's networkBucket() spelling (no prefix)
    if string.match(tag, '^[0-9a-f]+$') and #tag >= 2 and #tag <= 68 then
        return true
    end
    return false
end

local op = ARGV[1]
if op ~= 'seen' and op ~= 'record' and op ~= 'has_trusted'
    and op ~= 'has_any_trusted' and op ~= 'forget_devices' then
    return redis.error_reply('pnet: op must be seen, record, has_trusted, has_any_trusted or forget_devices')
end

kiwi_assert_type(KEYS[1], 'hash')

if op == 'forget_devices' then
    -- Atomic revocation (F15): the session and device tags of the
    -- principal and every trust mirror go in one HDEL, so a record
    -- racing the revocation cannot survive half-deleted. The op takes
    -- no tag and no TTL: it deletes whole classes and never reads a
    -- lifetime. Bare-hex and net/asn seen-ness survives (the
    -- deployment's long-memory network evidence), but the trust
    -- mirrors go with the credentials: a network whose only vouches
    -- came from the compromised credentials re-runs the first-attempt
    -- gate on its own evidence at the next login, and the
    -- trusted-network answer of a compromised account re-arms.
    local all = redis.call('HGETALL', KEYS[1])
    local doomed = {}
    for i = 1, #all, 2 do
        local f = all[i]
        if string.sub(f, 1, 8) == 'session:' or string.sub(f, 1, 7) == 'device:'
            or string.sub(f, 1, 2) == 't:' then
            doomed[#doomed + 1] = f
        end
    end
    if #doomed > 0 then
        redis.call('HDEL', KEYS[1], unpack(doomed))
    end
    return #doomed
end

if op == 'has_any_trusted' then
    -- Whether ANY network-class tag of this principal carries a minted
    -- trust flag whose bare tag is still live: the "no prior trusted
    -- network" half of the novel-network gate, answered inside the
    -- script so the read stays atomic and the field walk stays bounded
    -- by the script's own cardinality ceiling. Takes no tag and no
    -- TTL: it is an any-network probe, judged against each field's own
    -- class ceiling (a probe can never vouch past the class lifetime).
    -- Session and device mirrors are the continuity plane's evidence:
    -- a bound cookie vouches for a browser, never for a network, so
    -- only net, asn and the engine's bare-hex bucket spelling count
    -- toward a trusted NETWORK.
    local time = redis.call('TIME')
    local now = tonumber(time[1]) * 1000 + math.floor(tonumber(time[2]) / 1000)
    local fields = redis.call('HGETALL', KEYS[1])
    -- The reply already carries every field's value: one pass records the
    -- bare tags' values and the mirrors, and the walk below reads each
    -- bare tag's lifetime from that table instead of one HGET per mirror.
    -- A mirror name is skipped when the values are recorded: a name of
    -- the form t:<x> carries a colon and so can never classify as a
    -- network class, which is the only thing the walk below asks of the
    -- field it looks up.
    local last_use = {}
    local mirrors = {}
    for i = 1, #fields, 2 do
        local f = fields[i]
        if string.sub(f, 1, 2) == 't:' then
            mirrors[#mirrors + 1] = string.sub(f, 3)
        else
            last_use[f] = fields[i + 1]
        end
    end
    for i = 1, #mirrors do
        local bare = mirrors[i]
        local v = last_use[bare]
        if v then
            local last = kiwi_decode_integer(v, KEYS[1] .. ':' .. bare)
            if last ~= nil then
                local fclass = classify(bare)
                local isNetworkClass = fclass == 'net' or fclass == 'asn'
                    or (fclass == nil and string.match(bare, '^[0-9a-f]+$') ~= nil)
                if isNetworkClass then
                    local class_ttl = CLASS_TTL_MAX[fclass] or CLASS_TTL_MAX.net
                    if now - last <= class_ttl then
                        return 1
                    end
                end
            end
        end
    end

    return 0
end

local tag = ARGV[2]
if not valid_tag(tag) then
    return redis.error_reply('pnet: tag must match net|session|device:<hex> or asn:<decimal|u4/prefix|u6/prefix>')
end

local class = classify(tag)

-- Distributed clock authority: Redis TIME.
local time = redis.call('TIME')
local now_ms = tonumber(time[1]) * 1000 + math.floor(tonumber(time[2]) / 1000)

local trust_key = 't:' .. tag

-- The caller's configured class TTL is REQUIRED on every read path:
-- seen and has_trusted answer "not seen" past the caller's TTL, never
-- past the class maximum. Without this a stolen device value would
-- vouch server-side for the whole 365-day class ceiling even where the
-- deployment configured days. Validated BEFORE any read, so an
-- out-of-range TTL errors with the hash untouched.
local ttl_ms = tonumber(ARGV[3])
if ttl_ms == nil or ttl_ms ~= math.floor(ttl_ms)
    or ttl_ms < (CLASS_TTL_MIN[class] or CLASS_TTL_MIN.net)
    or ttl_ms > (CLASS_TTL_MAX[class] or CLASS_TTL_MAX.net) then
    return redis.error_reply('pnet: ttl_ms outside the class range')
end

if op == 'seen' then
    local v = redis.call('HGET', KEYS[1], tag)
    if not v then
        return 0
    end
    local last = kiwi_decode_integer(v, KEYS[1] .. ':' .. tag)
    if last == nil then
        return 0
    end
    if now_ms - last > ttl_ms then
        return 0
    end
    return 1
end

if op == 'has_trusted' then
    local v = redis.call('HGET', KEYS[1], tag)
    if not v then
        return 0
    end
    local last = kiwi_decode_integer(v, KEYS[1] .. ':' .. tag)
    if last == nil then
        return 0
    end
    if now_ms - last > ttl_ms then
        return 0
    end
    local t = redis.call('HGET', KEYS[1], trust_key)
    if not t then
        return 0
    end
    return 1
end

-- op == 'record'
local cap = tonumber(ARGV[4])
if cap == nil or cap < 1 or cap > MAX_CAP or cap ~= math.floor(cap) then
    return redis.error_reply('pnet: cap must be a positive integer within bounds')
end
local trust = ARGV[5]
if trust == nil then
    trust = '0'
end

-- Upsert the tag: the last-use ms refreshes on every record (the LRU
-- touch), the trust flag only ever mints (never revokes), and the
-- answer says whether the tag was newly created (0 = existed). This is
-- a touch-upsert, not SET NX: the first WRITE wins the trust flag, the
-- newest write wins the last-use.
-- Preflight the current hash before the touch: every class tag the
-- eviction may rank is strictly decoded here, so a corrupt last-use can
-- never become zero and be evicted as "oldest". The same reply supplies
-- the pre-write field set for the eviction walk.
local all = redis.call('HGETALL', KEYS[1])
local existed = false
local class_tags = {}
for i = 1, #all, 2 do
    local f = all[i]
    if f == tag then
        existed = true
    elseif f ~= trust_key and string.sub(f, 1, 2) ~= 't:' then
        local fclass = classify(f)
        if fclass == class then
            class_tags[#class_tags + 1] = {
                f,
                kiwi_decode_integer(all[i + 1], KEYS[1] .. ':' .. f) or 0
            }
        end
    end
end

redis.call('HSET', KEYS[1], tag, tostring(now_ms))
if trust == '1' then
    redis.call('HSET', KEYS[1], trust_key, '1')
end

-- LRU eviction within the class: collect the OTHER class tags with
-- their last-use, excluding the tag just written (a same-millisecond
-- tie must never evict the entry the caller just wrote — Lua's sort is
-- not stable, so without the exclusion a tie would be free to pick
-- it), then evict the oldest above the cap together with their trust
-- flags.
local scan = redis.call('HGETALL', KEYS[1])
if #class_tags + 1 > cap then
    -- Sort ascending by last-use (oldest first).
    table.sort(class_tags, function(a, b) return a[2] < b[2] end)
    local to_evict = #class_tags + 1 - cap
    for i = 1, to_evict do
        local victim = class_tags[i][1]
        redis.call('HDEL', KEYS[1], victim)
        redis.call('HDEL', KEYS[1], 't:' .. victim)
    end
    -- An evicted victim left the hash, so the surviving set is read back.
    scan = redis.call('HGETALL', KEYS[1])
end

-- PEXPIRE computed AFTER the eviction, over the surviving fields: the
-- key expires when its oldest surviving class would (an evicted
-- victim's class TTL can no longer hold the key alive past its own
-- eviction). Without an eviction the fields read above, after the
-- writes, ARE the surviving set, so that reply is scanned directly.
local max_class_ttl = ttl_ms
for i = 1, #scan, 2 do
    local f = scan[i]
    if string.sub(f, 1, 2) ~= 't:' then
        local fclass = classify(f)
        local fttl = CLASS_TTL_MAX[fclass] or CLASS_TTL_MAX.net
        if fttl > max_class_ttl then
            max_class_ttl = fttl
        end
    end
end
if max_class_ttl > EXPIRY_CEILING_MS then
    max_class_ttl = EXPIRY_CEILING_MS
end
redis.call('PEXPIRE', KEYS[1], max_class_ttl)

if existed then
    return 0
end
return 1
