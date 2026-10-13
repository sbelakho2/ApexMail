<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Security\StepUp;

use Predis\ClientInterface;

/**
 * The Redis step-up store: the production state backend of the
 * step-up plane, keyed under the deployment's risk namespace family
 * ({kiwi:<ns>}:stepup:*) like every other risk-side key family.
 *
 * The single-use boundary is Redis-native: consume is GETDEL, so one
 * record answers exactly one completion across every PHP-FPM worker.
 * The attempt accounting and the begin-window counter are small Lua
 * scripts, atomic over their key like the bundle's other state
 * transitions. Every record is written and read through the strict
 * wire schema of {@see StepUpChallenge}; a record the script cannot
 * decode is removed and answered corrupt, fail-closed.
 */
final class RedisStepUpChallengeStore implements StepUpChallengeStore
{
    /**
     * The attempt-accounting script: bump the attempts field, keep the
     * record within its remaining TTL, remove it at the cap. Answers
     * the attempts now used (>= 1), 0 at the cap (removed), -1 when
     * absent, -2 when the stored value violates the schema (removed).
     */
    private const ATTEMPT_SCRIPT = <<<'LUA'
        -- Step-up attempt accounting: bump attempts, delete on exhaustion.
        local raw = redis.call('GET', KEYS[1])
        if not raw then return -1 end
        local ok, rec = pcall(cjson.decode, raw)
        if not ok or type(rec) ~= 'table' or type(rec['attempts']) ~= 'number'
            or type(rec['max_attempts']) ~= 'number' then
          redis.call('DEL', KEYS[1])
          return -2
        end
        rec['attempts'] = rec['attempts'] + 1
        if rec['attempts'] >= tonumber(ARGV[1]) then
          redis.call('DEL', KEYS[1])
          return 0
        end
        local ttl = redis.call('TTL', KEYS[1])
        if ttl > 0 then
          redis.call('SET', KEYS[1], cjson.encode(rec), 'EX', ttl)
        else
          redis.call('DEL', KEYS[1])
          return -1
        end
        return rec['attempts']
        LUA;

    /**
     * The begin-window script: fixed-window admission counter for one
     * principal pseudonym, the expiry armed exactly once and atomically
     * with the first admission (a counter whose expiry was lost to a
     * process death can never strand a principal at the cap forever).
     * Answers the window's new admission count.
     */
    private const BEGIN_SCRIPT = <<<'LUA'
        -- Step-up begin window: fixed-window admission counter.
        local n = redis.call('INCR', KEYS[1])
        if n == 1 then
          redis.call('EXPIRE', KEYS[1], tonumber(ARGV[1]))
        end
        return n
        LUA;

    /**
     * The replay-guard script: the last-used time-step of a principal
     * compared and advanced atomically. A step strictly newer than the
     * stored one wins and is stored (TTL refreshed); anything at or
     * below the stored step is a replay and answers 0.
     */
    private const STEP_SCRIPT = <<<'LUA'
        -- Step-up totp step: compare-and-advance the replay guard.
        local current = redis.call('GET', KEYS[1])
        if current and tonumber(current) >= tonumber(ARGV[1]) then
          return 0
        end
        redis.call('SET', KEYS[1], ARGV[1], 'EX', tonumber(ARGV[2]))
        return 1
        LUA;

    /**
     * The demand lifecycle script: one atomic compare-and-set over the
     * demand record's lifecycle state, one op per call. complete moves
     * open to completed (re-arming the TTL for the finalizer), claim
     * moves completed to finalizing (a stale claim past its window is
     * retaken), settle moves finalizing to the named terminal state.
     * The record is kept through claim and settle within its remaining
     * TTL. Every other shape answers nil, fail closed.
     */
    private const DEMAND_TRANSITION_SCRIPT = <<<'LUA'
        -- Step-up demand transition: one lifecycle compare-and-set.
        local raw = redis.call('GET', KEYS[1])
        if not raw then return nil end
        local ok, rec = pcall(cjson.decode, raw)
        if not ok or type(rec) ~= 'table' or type(rec['state']) ~= 'string' then
          redis.call('DEL', KEYS[1])
          return nil
        end
        local op = ARGV[1]
        if op == 'complete' then
          if type(rec['superseded_by']) == 'string' and rec['superseded_by'] ~= '' then return nil end
          if rec['state'] ~= 'open' then return nil end
          rec['state'] = 'completed'
          rec['state_at'] = tonumber(ARGV[2])
          redis.call('SET', KEYS[1], cjson.encode(rec), 'EX', tonumber(ARGV[3]))
          return cjson.encode(rec)
        end
        if op == 'claim' then
          -- A superseded demand finalizes nothing: escalation replaced
          -- it, so no retake may drive it to a terminal. The marker is
          -- checked inside the same script as the state CAS, so a
          -- supersede that interleaves a stale claimant's read still
          -- refuses it.
          if type(rec['superseded_by']) == 'string' and rec['superseded_by'] ~= '' then return nil end
          -- The finalization claim runs on the store-owned clock: the
          -- stale-claim retake decision reads the Redis server time,
          -- never a PHP worker's clock, so two workers cannot disagree
          -- about whether a dead owner's window has passed.
          local t = redis.call('TIME')
          local now = tonumber(t[1])
          if rec['state'] == 'completed' then
            rec['state'] = 'finalizing'
            rec['state_at'] = now
          elseif rec['state'] == 'finalizing' then
            local claimedAt = tonumber(rec['state_at'] or '0') or 0
            if (now - claimedAt) < tonumber(ARGV[3]) then return nil end
            rec['state_at'] = now
          else
            return nil
          end
          local ttl = redis.call('TTL', KEYS[1])
          if ttl <= 0 then
            redis.call('DEL', KEYS[1])
            return nil
          end
          redis.call('SET', KEYS[1], cjson.encode(rec), 'EX', ttl)
          return cjson.encode(rec)
        end
        if op == 'settle' then
          if rec['state'] ~= 'finalizing' then return nil end
          local terminal = ARGV[2]
          if terminal ~= 'authorized' and terminal ~= 'denied' and terminal ~= 'superseded' then return nil end
          -- A superseded demand authorizes nothing ever again: only
          -- the superseded settlement itself (the escalator's follow-up)
          -- and the fail-closed denied terminal may still land. The
          -- denied terminal is allowed because losing the supersede
          -- race settles the loser denied, and denial carries no
          -- authorization power.
          if terminal == 'authorized' and type(rec['superseded_by']) == 'string' and rec['superseded_by'] ~= '' then return nil end
          rec['state'] = terminal
          rec['state_at'] = tonumber(ARGV[3])
          if terminal == 'authorized' then
            rec['authorized_at'] = tonumber(ARGV[3])
            if ARGV[4] and ARGV[4] ~= '' then
              rec['factor'] = ARGV[4]
            end
          end
          local ttl = redis.call('TTL', KEYS[1])
          if ttl <= 0 then
            redis.call('DEL', KEYS[1])
            return nil
          end
          redis.call('SET', KEYS[1], cjson.encode(rec), 'EX', ttl)
          return cjson.encode(rec)
        end
        if op == 'fx' then
          -- The effects journal write of the durable authorized
          -- terminal: one known effect moves to its landed stamp, and
          -- only the authorized terminal journals anything. The write
          -- keeps the remaining lifetime exactly.
          if rec['state'] ~= 'authorized' then return nil end
          local effect = ARGV[2]
          if effect ~= 'authorization_settled' and effect ~= 'outcome_credited'
            and effect ~= 'session_restored' and effect ~= 'trust_written' then
            return nil
          end
          local fx = rec['fx']
          if type(fx) ~= 'table' then fx = {} end
          fx[effect] = tonumber(ARGV[3])
          rec['fx'] = fx
          local ttl = redis.call('TTL', KEYS[1])
          if ttl <= 0 then
            redis.call('DEL', KEYS[1])
            return nil
          end
          redis.call('SET', KEYS[1], cjson.encode(rec), 'EX', ttl)
          return cjson.encode(rec)
        end
        return nil
        LUA;

    /**
     * The factor completion script: one atomic transition over the two
     * records of a completion. The script loads the challenge and the
     * demand and decodes both. It then asserts the identity (the
     * challenge names exactly this demand), the state (the demand is
     * open), the liveness (both records inside their lifetime) and the
     * binding (the presented hash equals the stored session binding or
     * the stateless client secret). On a pass it consumes the challenge
     * and moves the demand to completed in the same step, the record
     * kept and re-armed within its remaining lifetime, exactly like the
     * lifecycle complete op. The escalation index write rides the same
     * script: the completed factor is recorded under the session hash
     * and scope, but only when the hint matches the stored session
     * binding. The factor requirement rides the same script: the
     * demand's stored requirement is judged against the factor identity
     * the stored challenge record carries, never a caller argument.
     * That identity is the record's server-held snapshot resolved at
     * begin; the kind tables are the drain-period fallback and the
     * snapshot's coherence check. A
     * completion below the required assurance rank, or of a factor
     * neither the snapshot's family nor its exact id answers at or
     * below that rank, refuses before anything moves. Every refusal
     * answers a typed reason table and leaves both records untouched; a
     * corrupt record is removed, fail closed.
     */
    private const COMPLETE_FACTOR_SCRIPT = <<<'LUA'
        -- Step-up factor completion: one atomic challenge+demand transition.
        -- The ladder of the challenge kinds: the assurance family and
        -- rank each stored kind proves. The anonymous email-ownership
        -- grant proves the email_otp rung, the weakest of the ladder.
        -- The tables are also the coherence check of the record's own
        -- factor snapshot and the fallback for the pre-snapshot shape.
        local KIND_FAMILY = { email_otp = 'email_otp', email_ownership = 'email_otp', totp = 'totp', webauthn = 'webauthn' }
        local KIND_RANK = { email_otp = 1, email_ownership = 1, totp = 2, webauthn = 3 }
        local craw = redis.call('GET', KEYS[1])
        if not craw then return {'missing_challenge'} end
        local cok, ch = pcall(cjson.decode, craw)
        if not cok or type(ch) ~= 'table' then
          redis.call('DEL', KEYS[1])
          return {'corrupt_challenge'}
        end
        local draw = redis.call('GET', KEYS[2])
        if not draw then return {'missing_demand'} end
        local dok, de = pcall(cjson.decode, draw)
        if not dok or type(de) ~= 'table' then
          redis.call('DEL', KEYS[2])
          return {'corrupt_demand'}
        end
        if type(ch['demand_id']) ~= 'string' or ch['demand_id'] ~= ARGV[1]
          or type(de['id']) ~= 'string' or de['id'] ~= ARGV[1] then
          return {'crossed'}
        end
        -- A superseded demand completes nothing, whatever its state
        -- field still says: escalation replaced it with a stronger
        -- child, and the weak proof must not land behind the family's
        -- back. The marker rides the record, so the check is one
        -- atomic read here.
        if type(de['superseded_by']) == 'string' and de['superseded_by'] ~= '' then return {'spent'} end
        if de['state'] ~= 'open' then return {'spent'} end
        local now = tonumber(ARGV[2])
        if type(ch['expires_at']) ~= 'number' or ch['expires_at'] <= now then return {'expired'} end
        if type(de['expires_at']) ~= 'number' or de['expires_at'] <= now then return {'expired'} end
        local bound = (type(ch['session_hash']) == 'string' and ch['session_hash'] == ARGV[3])
          or (type(ch['client_secret_hash']) == 'string' and ch['client_secret_hash'] == ARGV[3])
        if not bound then return {'binding'} end
        -- The factor identity gate. The judged identity is the stored
        -- challenge's own server-held snapshot, the factor the record
        -- was begun under, never a caller argument. The snapshot must
        -- agree with its kind's family and rank: the kind decides what
        -- proof material the completion verified, and the snapshot can
        -- name the handler identity, never another family's rung. An
        -- incoherent snapshot is a corrupt record, removed fail-closed.
        -- A record without the snapshot (the pre-snapshot wire shape)
        -- falls back to the kind tables. A rank below the required one
        -- refuses, and so does a factor neither the family nor the
        -- exact id the requirement names at or below that rank. A
        -- strictly stronger completion satisfies a weaker floor, the
        -- ladder is a floor.
        local family = nil
        local rank = nil
        local fid = nil
        if type(ch['factor_family']) == 'string' and ch['factor_family'] ~= ''
          and type(ch['factor_id']) == 'string' and ch['factor_id'] ~= ''
          and type(ch['factor_rank']) == 'number' then
          if KIND_FAMILY[ch['kind']] ~= ch['factor_family']
            or KIND_RANK[ch['kind']] ~= ch['factor_rank'] then
            redis.call('DEL', KEYS[1])
            return {'corrupt_challenge'}
          end
          family = ch['factor_family']
          rank = ch['factor_rank']
          fid = ch['factor_id']
        else
          family = KIND_FAMILY[ch['kind']]
          rank = KIND_RANK[ch['kind']]
          fid = family
        end
        local requiredRank = nil
        if type(de['required_rank']) == 'number' then requiredRank = de['required_rank'] end
        if requiredRank ~= nil and requiredRank >= 1 then
          if rank == nil or rank < requiredRank then return {'weaker_factor'} end
        end
        if type(de['required_factor_id']) == 'string' and de['required_factor_id'] ~= ''
          and family ~= de['required_factor_id'] and fid ~= de['required_factor_id']
          and (requiredRank == nil or rank == nil or rank <= requiredRank) then
          return {'foreign_factor'}
        end
        redis.call('DEL', KEYS[1])
        de['state'] = 'completed'
        de['state_at'] = now
        local ttl = tonumber(de['expires_at']) - now
        if ttl < 1 then ttl = 1 end
        redis.call('SET', KEYS[2], cjson.encode(de), 'EX', ttl)
        -- The escalation index stores the factor identity the record
        -- itself carries, never a caller argument: a completion cannot
        -- poison the future assurance escalation by claiming a stronger
        -- factor than its challenge proves.
        if ARGV[4] ~= '' and type(ch['session_hash']) == 'string' and ch['session_hash'] == ARGV[4]
          and type(ch['scope']) == 'string' and type(de['expires_at']) == 'number'
          and type(family) == 'string' and family ~= '' then
          redis.call('SET', KEYS[3], ch['scope']..'|'..family..'|'..tostring(math.floor(de['expires_at'])), 'EX', ttl)
        end
        return {'ok', craw, cjson.encode(de)}
        LUA;

    /**
     * The demand root-mint script: the operation family index gates the
     * root, atomically. When the index names a still-live demand,
     * nothing is written and the standing tip is answered — a
     * reassessment can never refresh the first demand's window by
     * minting a second root. Otherwise the demand record and the index
     * are written in this one transaction. The index liveness is the
     * demand key's own TTL: Redis expires both together.
     */
    private const DEMAND_ROOT_SCRIPT = <<<'LUA'
        -- Step-up demand root mint: one live demand per operation.
        local tip = redis.call('GET', KEYS[2])
        if tip and tip ~= '' then
          if redis.call('EXISTS', ARGV[3] .. tip) == 1 then
            return cjson.encode({existing = tip})
          end
        end
        local ok = redis.call('SET', KEYS[1], ARGV[1], 'PX', tonumber(ARGV[2]), 'NX')
        if not ok then return nil end
        redis.call('SET', KEYS[2], ARGV[4], 'PX', tonumber(ARGV[2]))
        return cjson.encode({created = ARGV[4]})
        LUA;

    /**
     * The demand escalation script: the atomic supersede-parent and
     * create-child transaction. The script asserts the parent record is
     * present, decodable, live (expiry judged on the Redis server
     * time), never superseded before, and carrying remaining lifetime.
     * It asserts the child key is absent, then writes the child: its
     * created_at stamped from the server time, its expiry already
     * verified equal to the parent's (a child never outlives the
     * authorization it inherits). It marks the parent superseded and
     * repoints the family index, each within the parent's remaining
     * PTTL. Marking the parent and creating the child cannot be
     * separated by a crash: they are one script. Any refusal answers
     * nil, fail closed.
     */
    private const DEMAND_SUPERSEDE_SCRIPT = <<<'LUA'
        -- Step-up demand escalation: supersede parent + create child.
        local raw = redis.call('GET', KEYS[1])
        if not raw then return nil end
        local ok, parent = pcall(cjson.decode, raw)
        if not ok or type(parent) ~= 'table' or type(parent['expires_at']) ~= 'number' then
          return nil
        end
        if type(parent['superseded_by']) == 'string' and parent['superseded_by'] ~= '' then return nil end
        -- A terminal demand is history, not a family head: only an
        -- open demand (the mint lane) or a claimed finalizing one (the
        -- escalator holding its own claim) may be superseded. An
        -- authorized or denied record already settled, and completed
        -- is mid-finalization; superseding any of them would hand the
        -- operation a fresh live sibling it never earned.
        if parent['state'] ~= 'open' and parent['state'] ~= 'finalizing' then return nil end
        local t = redis.call('TIME')
        local nowS = tonumber(t[1])
        if nowS >= parent['expires_at'] then return nil end
        if redis.call('EXISTS', KEYS[2]) == 1 then return nil end
        local okc, child = pcall(cjson.decode, ARGV[1])
        if not okc or type(child) ~= 'table' then return nil end
        if child['expires_at'] ~= parent['expires_at'] then return nil end
        -- The child names the parent it replaces: the lineage is exact
        -- in both directions (parent.superseded_by = child.id and
        -- child.parent_demand_id = parent.id), the same rule the
        -- reference store enforces, so a forged link can never sit in
        -- the family index.
        if type(child['parent_demand_id']) ~= 'string' or child['parent_demand_id'] ~= parent['id'] then return nil end
        local pttl = redis.call('PTTL', KEYS[1])
        if pttl <= 0 then return nil end
        child['created_at'] = nowS
        -- The whole terminal transition is this one script: the child
        -- lands, the parent reaches the superseded terminal (state,
        -- stamp and child link together, on the Redis clock), and the
        -- family index repoints. No follow-up settlement exists, so a
        -- crash can never leave parent-superseded and child-present
        -- half-written or the parent in a claimed state behind the
        -- marker.
        redis.call('SET', KEYS[2], cjson.encode(child), 'PX', pttl)
        parent['state'] = 'superseded'
        parent['state_at'] = nowS
        parent['superseded_by'] = ARGV[2]
        redis.call('SET', KEYS[1], cjson.encode(parent), 'PX', pttl)
        redis.call('SET', KEYS[3], ARGV[2], 'PX', pttl)
        return cjson.encode({superseded = parent})
        LUA;

    /**
     * The send-lease script: the atomic send-credit claim of one
     * delivery, with every clock decision taken on the Redis server
     * time — the expiry, the bounded-resend spacing, the liveness of
     * another worker's lease and the recovery of a crashed one. The
     * record is written back with its remaining PTTL, never a fresh
     * TTL. A live foreign lease refuses; an expired lease is recovered
     * (the same send slot re-leased, no second credit); the spacing
     * refusal answers the Redis-owned wait seconds.
     */
    private const DEMAND_SEND_LEASE_SCRIPT = <<<'LUA'
        -- Step-up demand send lease: Redis TIME owns every clock decision.
        local raw = redis.call('GET', KEYS[1])
        if not raw then return nil end
        local ok, rec = pcall(cjson.decode, raw)
        if not ok or type(rec) ~= 'table' or type(rec['sends']) ~= 'number'
            or type(rec['expires_at']) ~= 'number' then
          redis.call('DEL', KEYS[1])
          return nil
        end
        if type(rec['superseded_by']) == 'string' and rec['superseded_by'] ~= '' then return nil end
        if rec['state'] ~= 'open' then return nil end
        local t = redis.call('TIME')
        local nowS = tonumber(t[1])
        local nowMs = nowS * 1000 + math.floor(tonumber(t[2]) / 1000)
        if nowS >= rec['expires_at'] then return nil end
        local pttl = redis.call('PTTL', KEYS[1])
        if pttl <= 0 then return nil end
        local leaseUntil = 0
        if type(rec['lease_until']) == 'number' then leaseUntil = rec['lease_until'] end
        if leaseUntil > nowMs then return nil end
        local priorSends = rec['sends']
        local priorLast = nil
        if type(rec['last_sent_at']) == 'number' then priorLast = rec['last_sent_at'] end
        local recovered = 0
        if leaseUntil > 0 then
          -- The previous holder crashed before its settlement: the same
          -- send slot is re-leased without being charged a second credit.
          recovered = 1
        else
          if priorSends >= tonumber(ARGV[1]) then return nil end
          if priorSends >= 1 and type(priorLast) == 'number' then
            local wait = (priorLast + tonumber(ARGV[2])) - nowS
            if wait > 0 then
              return cjson.encode({refused = 'resend_wait', wait = wait})
            end
          end
          rec['sends'] = priorSends + 1
          rec['last_sent_at'] = nowS
        end
        rec['lease_until'] = nowMs + tonumber(ARGV[3])
        redis.call('SET', KEYS[1], cjson.encode(rec), 'PX', pttl)
        return cjson.encode({claim_at = nowS, recovered = recovered, prior_sends = priorSends, prior_last_sent_at = priorLast, record = rec})
        LUA;

    /**
     * The send-lease settlement script: the compare-and-set on the
     * lease stamp the claim answered. A commit clears the lease and
     * keeps the advanced send state; a pre-handoff refusal restores the
     * exact pre-claim state the claim answered. A stale claimant (its
     * lease stamp no longer on the record — the window expired and
     * another worker recovered the slot) settles nothing. The record is
     * written back with its remaining PTTL.
     */
    private const DEMAND_SEND_SETTLE_SCRIPT = <<<'LUA'
        -- Step-up demand send settlement: CAS on the lease stamp.
        local raw = redis.call('GET', KEYS[1])
        if not raw then return 0 end
        local ok, rec = pcall(cjson.decode, raw)
        if not ok or type(rec) ~= 'table' then return 0 end
        local stamp = 0
        if type(rec['lease_until']) == 'number' then stamp = rec['lease_until'] end
        if stamp ~= tonumber(ARGV[1]) then return 0 end
        rec['lease_until'] = cjson.null
        if ARGV[2] == '0' then
          rec['sends'] = tonumber(ARGV[3])
          if ARGV[4] == '-1' then
            rec['last_sent_at'] = cjson.null
          else
            rec['last_sent_at'] = tonumber(ARGV[4])
          end
        end
        local pttl = redis.call('PTTL', KEYS[1])
        if pttl <= 0 then
          redis.call('DEL', KEYS[1])
          return 0
        end
        redis.call('SET', KEYS[1], cjson.encode(rec), 'PX', pttl)
        return 1
        LUA;

    /**
     * The mail-quota reservation script: every budget increments inside
     * its fixed window, or the whole reservation rolls back. The
     * reservation record (the commit/release marker) carries the lease
     * as its own TTL on the Redis clock: past it the reservation has
     * committed by default and no release can refund it.
     */
    private const MAIL_QUOTA_RESERVE_SCRIPT = <<<'LUA'
        -- Step-up mail quota: reserve on every budget or roll back.
        -- ARGV[1] window secs, ARGV[2] lease secs, ARGV[3] the marker,
        -- ARGV[4..] the per-key limits in KEYS order.
        local over = false
        for i = 2, #KEYS do
          local n = redis.call('INCR', KEYS[i])
          if n == 1 then
            redis.call('EXPIRE', KEYS[i], tonumber(ARGV[1]))
          end
          local limit = tonumber(ARGV[i + 2])
          if n > limit then over = true end
        end
        if over then
          for i = 2, #KEYS do
            local n = redis.call('GET', KEYS[i])
            if n and tonumber(n) > 0 then
              redis.call('DECR', KEYS[i])
            end
          end
          return 0
        end
        redis.call('SET', KEYS[1], ARGV[3], 'EX', tonumber(ARGV[2]))
        return 1
        LUA;

    /**
     * The mail-quota settlement script: a release undoes this
     * reservation's increments while its lease record still lives (the
     * Redis clock decided liveness); past the lease, or on a commit,
     * the counters stand and only the marker is dropped. The marker
     * itself names the reservation's budget counters (the reserve
     * wrote them), so the release refunds exactly the increments the
     * reservation made. A counter that already left its window reads
     * as absent and is skipped, never driven negative.
     */
    private const MAIL_QUOTA_SETTLE_SCRIPT = <<<'LUA'
        -- Step-up mail quota settlement: release or commit.
        local marker = redis.call('GET', KEYS[1])
        if ARGV[1] == '1' then
          redis.call('DEL', KEYS[1])
          return 1
        end
        if not marker then return 0 end
        local ok, saved = pcall(cjson.decode, marker)
        if ok and type(saved) == 'table' and type(saved['keys']) == 'table' then
          for i = 1, #saved['keys'] do
            local n = redis.call('GET', saved['keys'][i])
            if n and tonumber(n) > 0 then
              redis.call('DECR', saved['keys'][i])
            end
          end
        end
        redis.call('DEL', KEYS[1])
        return 1
        LUA;

    /**
     * The lockout-arm script: extend the deadline to at least the
     * requested one (a shorter request never shortens a live lock),
     * with a TTL matching the deadline. The key-level TTL also bounds
     * the ledger: an abandoned budget key expires with its lockout.
     */
    private const LOCK_ARM_SCRIPT = <<<'LUA'
        -- Step-up lockout: arm-or-extend the deadline. The stored
        -- value is epoch SECONDS, the unit the store contract names
        -- (the consumer subtracts the current second); the key carries
        -- the millisecond PX budget.
        local current = tonumber(redis.call('GET', KEYS[1]) or '0')
        local until_s = tonumber(ARGV[1])
        if until_s > current then
          redis.call('SET', KEYS[1], tostring(until_s), 'PX', tonumber(ARGV[2]))
        end
        return 1
        LUA;

    public function __construct(
        private readonly ClientInterface $redis,
        private readonly string $prefix,
    ) {
        if (!str_starts_with($prefix, '{') || !str_contains($prefix, '}:')) {
            throw new \InvalidArgumentException('The step-up store prefix must be a hash-tagged key family like {kiwi:<ns>}:stepup:');
        }
    }

    public function create(StepUpChallenge $challenge, int $ttlSecs): string
    {
        $key = $this->prefix.'challenge:'.$challenge->id;
        $json = (string) json_encode($challenge->toArray(), JSON_UNESCAPED_SLASHES);
        // NX: a minted id colliding with a live record refuses rather
        // than overwriting it; the caller mints a fresh id and retries.
        $stored = $this->redis->set($key, $json, 'EX', max(1, $ttlSecs), 'NX');
        if (!$this->isAffirmativeSetReply($stored)) {
            throw new \RuntimeException('The step-up challenge record could not be persisted (id collision or backend refusal)');
        }

        return $challenge->id;
    }

    /**
     * Whether a SET reply affirms the write. The reply shape is
     * client-specific: a real Predis client answers a
     * {@see \Predis\Response\Status} object whose string form is 'OK'.
     * phpredis answers a boolean and some proxies the bare string.
     * The comparison normalizes all three shapes and fails closed on
     * everything else; a nil answer is a refused NX, never a success.
     */
    private function isAffirmativeSetReply(mixed $reply): bool
    {
        if ($reply instanceof \Stringable) {
            return (string) $reply === 'OK';
        }
        if (\is_bool($reply)) {
            return $reply;
        }

        return \is_string($reply) && ($reply === 'OK' || $reply === '1');
    }

    public function read(string $challengeId): ?StepUpChallenge
    {
        return $this->decode($this->redis->get($this->challengeKey($challengeId)));
    }

    public function consume(string $challengeId): ?StepUpChallenge
    {
        // GETDEL: the atomic single-use boundary. Exactly one caller of
        // a concurrent pair receives the record.
        return $this->decode($this->redis->getdel($this->challengeKey($challengeId)));
    }

    public function recordFailure(string $challengeId, int $maxAttempts): int
    {
        $answer = $this->redis->eval(
            self::ATTEMPT_SCRIPT,
            1,
            $this->challengeKey($challengeId),
            (string) max(1, $maxAttempts),
        );
        if (\is_array($answer)) {
            throw new \RuntimeException('The step-up attempt accounting answered an unexpected shape');
        }

        return (int) $answer;
    }

    public function countBegin(string $principalPseudonym, int $windowSecs): int
    {
        $answer = $this->redis->eval(self::BEGIN_SCRIPT, 1, $this->prefix.'begins:'.$principalPseudonym, (string) max(1, $windowSecs));

        return (int) $answer;
    }

    public function createDemand(StepUpDemand $demand, int $ttlSecs): string
    {
        $key = $this->demandKey($demand->id);
        $json = (string) json_encode($demand->toArray(), JSON_UNESCAPED_SLASHES);
        // NX: a minted id colliding with a live demand refuses rather
        // than overwriting it; the caller mints a fresh id and retries.
        $stored = $this->redis->set($key, $json, 'EX', max(1, $ttlSecs), 'NX');
        if (!$this->isAffirmativeSetReply($stored)) {
            throw new \RuntimeException('The step-up demand record could not be persisted (id collision or backend refusal)');
        }

        return $demand->id;
    }

    public function readDemand(string $demandId): ?StepUpDemand
    {
        return $this->decodeDemand($this->redis->get($this->demandKey($demandId)));
    }

    public function consumeDemand(string $demandId): ?StepUpDemand
    {
        // GETDEL: the atomic single-use boundary of the demand (the
        // send-credit claim). Exactly one caller of a concurrent pair
        // receives the record.
        return $this->decodeDemand($this->redis->getdel($this->demandKey($demandId)));
    }

    public function completeDemand(string $demandId, int $now, int $ttlSecs): ?StepUpDemand
    {
        return $this->demandTransition($demandId, 'complete', (string) $now, (string) max(1, $ttlSecs));
    }

    public function completeFactor(string $challengeId, string $demandId, string $presentedBindingHash, int $now, ?string $sessionHash = null): ?StepUpFactorCompletion
    {
        // The index key rides as a declared key even when the hint is
        // absent: the script skips the write, and a declared-but-unused
        // key keeps the eval cluster-safe.
        $indexKey = $sessionHash !== null && preg_match('/^[0-9a-f]{64}$/D', $sessionHash) === 1
            ? $this->completedIndexKey($sessionHash)
            : $this->completedIndexKey(str_repeat('0', 64));
        $answer = $this->redis->eval(
            self::COMPLETE_FACTOR_SCRIPT,
            3,
            $this->challengeKey($challengeId),
            $this->demandKey($demandId),
            $indexKey,
            $demandId,
            (string) $now,
            $presentedBindingHash,
            $sessionHash ?? '',
        );
        if (!\is_array($answer) || ($answer[0] ?? null) !== 'ok' || \count($answer) !== 3) {
            return null;
        }
        try {
            $challenge = StepUpChallenge::fromJson((string) $answer[1]);
        } catch (MalformedStepUpChallengeException) {
            // The script consumed a record the strict decode refuses:
            // nothing verifiable remains, fail closed.
            return null;
        }
        $demand = StepUpDemand::fromJson((string) $answer[2]);
        if ($demand === null || $demand->state !== StepUpDemandState::Completed || $challenge->demandId !== $demandId) {
            return null;
        }

        // The completed factor is the record's own: the consumed
        // challenge's server-held snapshot, never a caller argument.
        return StepUpFactorCompletion::fromRecords($challenge, $demand);
    }

    public function completedFactorOf(string $sessionHash, string $scope, int $now): ?string
    {
        if (preg_match('/^[0-9a-f]{64}$/D', $sessionHash) !== 1) {
            return null;
        }
        $value = $this->redis->get($this->completedIndexKey($sessionHash));
        if (!\is_string($value) || $value === '') {
            return null;
        }
        $parts = explode('|', $value);
        if (\count($parts) !== 3 || $parts[0] !== $scope || (int) $parts[2] <= $now) {
            return null;
        }

        return FactorRequirement::isFamily($parts[1]) ? $parts[1] : null;
    }

    /** The escalation index key of one continuity session hash. */
    private function completedIndexKey(string $sessionHash): string
    {
        return $this->prefix.'emdone:'.$sessionHash;
    }

    public function claimDemandFinalization(string $demandId, int $now, int $claimSecs): ?StepUpDemand
    {
        return $this->demandTransition($demandId, 'claim', (string) $now, (string) max(1, $claimSecs));
    }

    public function settleDemandFinalization(string $demandId, StepUpDemandState $state, int $now, ?string $factor = null): ?StepUpDemand
    {
        return $this->demandTransition($demandId, 'settle', $state->value, (string) $now, $factor ?? '');
    }

    public function recordDemandEffect(string $demandId, string $effect, int $now): ?StepUpDemand
    {
        return $this->demandTransition($demandId, 'fx', $effect, (string) $now);
    }

    /**
     * One lifecycle compare-and-set through the demand transition
     * script. The script answers the updated record's JSON, nil on a
     * lost race or a refused transition, and removes a record the
     * decode refuses, fail closed.
     */
    private function demandTransition(string $demandId, string $op, string $arg2, string $arg3, string $arg4 = ''): ?StepUpDemand
    {
        $answer = $this->redis->eval(
            self::DEMAND_TRANSITION_SCRIPT,
            1,
            $this->demandKey($demandId),
            $op,
            $arg2,
            $arg3,
            $arg4,
        );
        if (\is_array($answer)) {
            throw new \RuntimeException('The step-up demand transition answered an unexpected shape');
        }

        return $this->decodeDemand($answer);
    }

    public function demandIdForOperation(string $operationDigest): ?string
    {
        if (preg_match('/^[0-9a-f]{64}$/D', $operationDigest) !== 1) {
            throw new \InvalidArgumentException('The step-up operation digest must be a 64-char lowercase hex digest');
        }
        $tip = $this->redis->get($this->operationIndexKey($operationDigest));

        return \is_string($tip) && $tip !== '' && $this->demandExists($tip) ? $tip : null;
    }

    public function createRootDemand(StepUpDemand $demand, int $ttlSecs): string
    {
        $answer = $this->redis->eval(
            self::DEMAND_ROOT_SCRIPT,
            2,
            $this->demandKey($demand->id),
            $this->operationIndexKey($demand->operationDigest),
            (string) json_encode($demand->toArray(), JSON_UNESCAPED_SLASHES),
            (string) (max(1, $ttlSecs) * 1000),
            $this->prefix.'emd:',
            $demand->id,
        );
        $decoded = \is_string($answer) ? json_decode($answer, true) : null;
        if (!\is_array($decoded) || !\is_string($decoded['existing'] ?? $decoded['created'] ?? null)) {
            throw new \RuntimeException('The step-up demand root could not be persisted (id collision or backend refusal)');
        }

        return $decoded['existing'] ?? $decoded['created'];
    }

    public function supersedeDemandWithChild(string $parentDemandId, StepUpDemand $child): ?StepUpDemand
    {
        $answer = $this->redis->eval(
            self::DEMAND_SUPERSEDE_SCRIPT,
            3,
            $this->demandKey($parentDemandId),
            $this->demandKey($child->id),
            $this->operationIndexKey($child->operationDigest),
            (string) json_encode($child->toArray(), JSON_UNESCAPED_SLASHES),
            $child->id,
        );
        $decoded = \is_string($answer) ? json_decode($answer, true) : null;
        if (\is_array($decoded) && isset($decoded['superseded']) && \is_array($decoded['superseded'])) {
            return StepUpDemand::fromArray($decoded['superseded']);
        }

        return null;
    }

    public function claimDemandSendLease(string $demandId, int $resendAfterSecs, int $leaseSecs): ?StepUpDemandSendLease
    {
        $answer = $this->redis->eval(
            self::DEMAND_SEND_LEASE_SCRIPT,
            1,
            $this->demandKey($demandId),
            (string) StepUpDemand::MAX_SENDS,
            (string) max(0, $resendAfterSecs),
            (string) (max(1, $leaseSecs) * 1000),
        );
        $decoded = \is_string($answer) ? json_decode($answer, true) : null;
        if (!\is_array($decoded) || isset($decoded['refused'])) {
            return null;
        }
        $record = StepUpDemand::fromArray(\is_array($decoded['record'] ?? null) ? $decoded['record'] : []);
        if ($record === null || !\is_int($decoded['claim_at'] ?? null) || !\is_int($record->leaseUntilMs)) {
            return null;
        }

        return new StepUpDemandSendLease(
            $record,
            $decoded['claim_at'],
            $record->leaseUntilMs,
            (int) ($decoded['prior_sends'] ?? 0),
            \is_int($decoded['prior_last_sent_at'] ?? null) ? $decoded['prior_last_sent_at'] : null,
            ($decoded['recovered'] ?? 0) === 1,
        );
    }

    public function settleDemandSendLease(StepUpDemandSendSettlement $settlement): bool
    {
        $answer = $this->redis->eval(
            self::DEMAND_SEND_SETTLE_SCRIPT,
            1,
            $this->demandKey($settlement->demandId),
            (string) $settlement->leaseUntilMs,
            $settlement->delivered ? '1' : '0',
            (string) $settlement->priorSends,
            (string) ($settlement->priorLastSentAt ?? -1),
        );

        return (int) $answer === 1;
    }

    public function reserveMailQuota(string $reservationId, array $budgetKeys, array $limits, int $windowSecs, int $leaseSecs): bool
    {
        $budgetKeys = array_values($budgetKeys);
        if (\count($budgetKeys) !== \count($limits) || $budgetKeys === []) {
            throw new \InvalidArgumentException('A mail quota reservation names a limit for every budget key');
        }
        foreach (array_values($limits) as $limit) {
            if (!\is_int($limit) || $limit < 1) {
                throw new \InvalidArgumentException('A mail quota limit must be a positive integer');
            }
        }
        // The store owns its key family: the caller names the budgets
        // semantically (dom, src, global), the key carries the
        // deployment namespace.
        $fullKeys = array_map(fn (string $key): string => $this->budgetKey($key), $budgetKeys);
        // The marker carries this reservation's own budget counters, so
        // a release can refund exactly the increments the reservation
        // made (the settle script reads them off the marker).
        $args = [
            (string) max(1, $windowSecs),
            (string) max(1, $leaseSecs),
            (string) json_encode(['id' => $reservationId, 'keys' => $fullKeys]),
        ];
        foreach (array_values($limits) as $limit) {
            $args[] = (string) $limit;
        }
        $answer = $this->redis->eval(self::MAIL_QUOTA_RESERVE_SCRIPT, 1 + \count($fullKeys), $this->quotaKey($reservationId), ...$fullKeys, ...$args);

        return (int) $answer === 1;
    }

    public function commitMailQuota(string $reservationId): void
    {
        // The marker is dropped; the counters stand. Past its lease the
        // reservation already committed by default, so this is
        // idempotent either way.
        $this->redis->del($this->quotaKey($reservationId));
    }

    public function releaseMailQuota(string $reservationId): bool
    {
        // The marker's TTL is the lease: once expired (Redis clock),
        // there is nothing to release and the spend stands.
        $answer = $this->redis->eval(
            self::MAIL_QUOTA_SETTLE_SCRIPT,
            1,
            $this->quotaKey($reservationId),
            '0',
        );

        return (int) $answer === 1;
    }

    private function demandExists(string $demandId): bool
    {
        return (int) $this->redis->exists($this->demandKey($demandId)) === 1;
    }

    /** The escalation family index key: the digest is the family identity. */
    private function operationIndexKey(string $operationDigest): string
    {
        if (preg_match('/^[0-9a-f]{64}$/D', $operationDigest) !== 1) {
            throw new \InvalidArgumentException('The step-up operation digest must be a 64-char lowercase hex digest');
        }

        return $this->prefix.'emi:'.$operationDigest;
    }

    private function quotaKey(string $reservationId): string
    {
        if (preg_match('/^[A-Za-z0-9_.:-]{3,160}$/D', $reservationId) !== 1) {
            throw new \InvalidArgumentException('The mail quota reservation id must be dot-atom safe');
        }

        return $this->prefix.'emq:'.$reservationId;
    }

    /**
     * The budget counter key of one semantic delivery budget (the
     * domain, source or global dimension the factor names): the
     * deployment namespace family, then the bounded semantic key.
     */
    private function budgetKey(string $key): string
    {
        if (preg_match('/^[a-z]{3,8}:[0-9a-f]{0,32}$/', $key) !== 1) {
            throw new \InvalidArgumentException('The mail quota budget key must be a bounded semantic name (dom/src/global plus its pseudonym)');
        }

        return $this->prefix.'emb:'.$key;
    }

    private function demandKey(string $demandId): string
    {
        if (preg_match('/^[A-Za-z0-9_-]{16,43}$/D', $demandId) !== 1) {
            throw new \InvalidArgumentException('The step-up demand id must be the base64url id shape');
        }

        return $this->prefix.'emd:'.$demandId;
    }

    private function decodeDemand(mixed $raw): ?StepUpDemand
    {
        if (!\is_string($raw) || $raw === '') {
            return null;
        }

        // A record the strict decode refuses reads as an absent demand,
        // fail-closed: corrupt state never funds a code delivery.
        return StepUpDemand::fromJson($raw);
    }

    public function saveTotpSecret(string $principalPseudonym, string $secretRaw): void
    {
        // Durable enrollment: no TTL.
        $this->redis->set($this->prefix.'totp:secret:'.$principalPseudonym, $secretRaw);
    }

    public function findTotpSecret(string $principalPseudonym): ?string
    {
        $value = $this->redis->get($this->prefix.'totp:secret:'.$principalPseudonym);

        return \is_string($value) && $value !== '' ? $value : null;
    }

    public function markTotpStep(string $principalPseudonym, int $step, int $ttlSecs): bool
    {
        $answer = $this->redis->eval(
            self::STEP_SCRIPT,
            1,
            $this->prefix.'totp:step:'.$principalPseudonym,
            (string) $step,
            (string) max(1, $ttlSecs),
        );

        return (int) $answer === 1;
    }

    private function challengeKey(string $challengeId): string
    {
        if (preg_match('/^[A-Za-z0-9_-]{16,43}$/D', $challengeId) !== 1) {
            throw new \InvalidArgumentException('The step-up challenge id must be the base64url id shape');
        }

        return $this->prefix.'challenge:'.$challengeId;
    }

    private function decode(mixed $raw): ?StepUpChallenge
    {
        if (!\is_string($raw) || $raw === '') {
            return null;
        }

        return StepUpChallenge::fromJson($raw);
    }
    public function markStepUpSuccess(string $principalPseudonym, int $ttlSecs, int $now): void
    {
        // The marker's own TTL is the window: a completed step-up
        // gates enrollment for exactly that long.
        $this->redis->set($this->prefix.'stepup-done:'.$principalPseudonym, (string) $now, 'EX', max(1, $ttlSecs));
    }

    public function recentStepUpSuccess(string $principalPseudonym, int $withinSecs, int $now): bool
    {
        $value = $this->redis->get($this->prefix.'stepup-done:'.$principalPseudonym);

        return \is_string($value) && $value !== '' && ($now - (int) $value) <= $withinSecs;
    }

    public function markSessionStepUpSuccess(string $sessionId, string $principalPseudonym, string $factor, int $ttlSecs, int $now): void
    {
        if ($sessionId === '' || $principalPseudonym === '') {
            return;
        }
        $this->redis->set(
            $this->prefix.'stepup-sess:'.hash('sha256', $sessionId."\0".$principalPseudonym),
            $now.'|'.$factor,
            'EX',
            max(1, $ttlSecs),
        );
    }

    public function recentSessionStepUpSuccess(string $sessionId, string $principalPseudonym, ?string $minFactor, int $withinSecs, int $now): bool
    {
        if ($sessionId === '' || $principalPseudonym === '') {
            return false;
        }
        $value = $this->redis->get($this->prefix.'stepup-sess:'.hash('sha256', $sessionId."\0".$principalPseudonym));
        if (!\is_string($value) || $value === '') {
            return false;
        }
        [$at, $factor] = array_pad(explode('|', $value, 2), 2, '');
        if (($now - (int) $at) > $withinSecs) {
            return false;
        }
        if ($minFactor !== null && self::factorRank($factor) < self::factorRank($minFactor)) {
            return false;
        }

        return true;
    }

    /** webauthn > totp > email_otp > unknown. */
    private static function factorRank(string $factor): int
    {
        return match ($factor) {
            'webauthn' => 3,
            'totp' => 2,
            'email_otp' => 1,
            default => 0,
        };
    }

    public function countLockoutFailure(string $dimension, string $pseudonym, int $windowSecs): int
    {
        $answer = $this->redis->eval(
            self::BEGIN_SCRIPT,
            1,
            $this->lockoutKey('fails', $dimension, $pseudonym),
            (string) max(1, $windowSecs),
        );

        return (int) $answer;
    }

    public function lockoutUntil(string $dimension, string $pseudonym, int $now): int
    {
        $value = $this->redis->get($this->lockoutKey('lock', $dimension, $pseudonym));
        if (!\is_string($value) || $value === '') {
            return 0;
        }
        $until = (int) $value;

        return $until > $now ? $until : 0;
    }

    public function armLockout(string $dimension, string $pseudonym, int $now, int $ttlSecs): void
    {
        $ttlSecs = max(1, $ttlSecs);
        $this->redis->eval(
            self::LOCK_ARM_SCRIPT,
            1,
            $this->lockoutKey('lock', $dimension, $pseudonym),
            (string) ($now + $ttlSecs),
            (string) ($ttlSecs * 1000 + 60_000),
        );
    }

    public function clearLockout(string $dimension, string $pseudonym): void
    {
        $this->redis->del(
            $this->lockoutKey('fails', $dimension, $pseudonym),
            $this->lockoutKey('lock', $dimension, $pseudonym),
        );
    }

    /**
     * The budget key of one (dimension, pseudonym) pair. The dimension
     * is a fixed short token ("principal" / "target") and the
     * pseudonym is the canonical hex form, so the key is as safe as
     * every other step-up key family.
     */
    private function lockoutKey(string $kind, string $dimension, string $pseudonym): string
    {
        if (preg_match('/^[a-z_]{1,16}$/D', $dimension) !== 1) {
            throw new \InvalidArgumentException('The lockout dimension must be 1-16 lowercase letters');
        }
        if (preg_match('/^[0-9a-f]{32}([0-9a-f]{32})?$/D', $pseudonym) !== 1) {
            throw new \InvalidArgumentException('The lockout pseudonym must be the canonical lowercase hex form');
        }

        return $this->prefix.'lockout:'.$kind.':'.$dimension.':'.$pseudonym;
    }
}
