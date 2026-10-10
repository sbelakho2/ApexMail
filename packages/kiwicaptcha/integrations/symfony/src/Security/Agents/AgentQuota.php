<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Security\Agents;

use BelConsulting\KiwiCaptchaBundle\Security\Authority\RedisSecurityCommandExecutor;

/**
 * The dual sliding-window quota of one configured agent: a
 * per-minute and a per-day bound on challenge issuance, both keyed
 * on the server-configured agent name (bounded cardinality by
 * construction — an attacker can never mint fresh quota windows).
 *
 * Keys: {kiwi:<ns>}:agent-quota:<name>:min:sw / :min:seq and the
 * day pair, one ZSET per window carrying one member per admitted
 * issuance scored at the admission ms, mirroring the scope cap's
 * proven shape. The window slides by score pruning, so a burst
 * straddling a boundary yields exactly the cap, never twice the
 * fixed-window allowance.
 *
 * One atomic Lua script decides both windows: the minute window is
 * checked first (the tighter bound in every sane configuration),
 * the day window second, and only a request with room in both is
 * admitted into both. A refusal returns the window that bound and
 * a Retry-After computed from the window's oldest live member, so
 * the hint is the true wait until one slot frees, never a guess.
 *
 * The admission clock is the Redis server clock (all workers share
 * one window regardless of host drift), and a TIME failure raises:
 * fail closed, no quota proof means no agent issuance. A Redis
 * failure propagates the same way — the caller refuses rather than
 * silently unbounding the agent's quota.
 */
final class AgentQuota
{
    /** The per-minute sliding window length in ms. */
    private const MINUTE_WINDOW_MS = 60000;

    /** The per-day sliding window length in ms. */
    private const DAY_WINDOW_MS = 86400000;

    /**
     * Atomic dual-window admission. Keys and arguments:
     *   KEYS[1] = {kiwi:<ns>}:agent-quota:<name>:min:sw,
     *   KEYS[2] = ...:min:seq, KEYS[3] = ...:day:sw,
     *   KEYS[4] = ...:day:seq.
     *   ARGV[1] = now_ms, ARGV[2] = minute window ms,
     *   ARGV[3] = day window ms, ARGV[4] = per-minute cap,
     *   ARGV[5] = per-day cap.
     * Returns {1, liveMin, liveDay, 0} on admission and
     * {0, 1|2 (the binding window), liveCountOfTheBindingWindow,
     * retryAfterSecs} on refusal.
     */
    private const ADMIT_SCRIPT = <<<'LUA'
-- Verified-agent quota: dual sliding-window admission
local cutoffMin = tonumber(ARGV[1]) - tonumber(ARGV[2])
local cutoffDay = tonumber(ARGV[1]) - tonumber(ARGV[3])
redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', cutoffMin)
redis.call('ZREMRANGEBYSCORE', KEYS[3], '-inf', cutoffDay)
local nMin = redis.call('ZCARD', KEYS[1])
if nMin >= tonumber(ARGV[4]) then
    local oldest = redis.call('ZRANGE', KEYS[1], 0, 0, 'WITHSCORES')
    local retry = math.ceil(tonumber(ARGV[2]) / 1000)
    if #oldest == 2 then
        retry = math.max(1, math.ceil((tonumber(ARGV[2]) - (tonumber(ARGV[1]) - tonumber(oldest[2]))) / 1000))
    end
    return {0, 1, nMin, retry}
end
local nDay = redis.call('ZCARD', KEYS[3])
if nDay >= tonumber(ARGV[5]) then
    local oldest = redis.call('ZRANGE', KEYS[3], 0, 0, 'WITHSCORES')
    local retry = math.ceil(tonumber(ARGV[3]) / 1000)
    if #oldest == 2 then
        retry = math.max(1, math.ceil((tonumber(ARGV[3]) - (tonumber(ARGV[1]) - tonumber(oldest[2]))) / 1000))
    end
    return {0, 2, nDay, retry}
end
local seq = redis.call('INCR', KEYS[2])
local member = tostring(ARGV[1]) .. ':' .. tostring(seq)
redis.call('ZADD', KEYS[1], tonumber(ARGV[1]), member)
redis.call('ZADD', KEYS[3], tonumber(ARGV[1]), member)
redis.call('PEXPIRE', KEYS[1], tonumber(ARGV[2]) + 1000)
redis.call('PEXPIRE', KEYS[2], tonumber(ARGV[2]) + 1000)
redis.call('PEXPIRE', KEYS[3], tonumber(ARGV[3]) + 1000)
redis.call('PEXPIRE', KEYS[4], tonumber(ARGV[3]) + 1000)
return {1, nMin + 1, nDay + 1, 0}
LUA;

    /**
     * @param \Redis|\Predis\Client $redis     the security Redis (the
     *                                         risk client of the
     *                                         deployment)
     * @param string                $keyPrefix the deployment key prefix
     *                                         including the hash tag,
     *                                         e.g. "{kiwi:prod}:"
     */
    public function __construct(
        private readonly \Redis|\Predis\Client $redis,
        private readonly string $keyPrefix = '{kiwi:kiwi}:',
    ) {
    }

    /**
     * Consumes one admission slot for the agent's issuance.
     *
     * @throws \Throwable when Redis fails (fail closed — the caller
     *                   refuses issuance rather than unbounding the
     *                   agent's quota)
     */
    public function admit(AgentDefinition $agent): AgentQuotaDecision
    {
        $nowMs = $this->redisClockMs();
        $base = sprintf('%sagent-quota:%s:', $this->keyPrefix, $agent->name);
        $result = ($this->luaSeam ??= new RedisSecurityCommandExecutor($this->redis))
            ->executeMutation(self::ADMIT_SCRIPT, [
                $base.'min:sw',
                $base.'min:seq',
                $base.'day:sw',
                $base.'day:seq',
            ], [
                (string) $nowMs,
                (string) self::MINUTE_WINDOW_MS,
                (string) self::DAY_WINDOW_MS,
                (string) max(1, $agent->perMinute),
                (string) max(1, $agent->perDay),
            ]);
        if (!\is_array($result) || !isset($result[0], $result[1], $result[2], $result[3])) {
            throw new \RuntimeException('The agent quota script returned an invalid response');
        }
        $admitted = (int) $result[0] === 1;

        return new AgentQuotaDecision(
            $admitted,
            $admitted ? null : ((int) $result[1] === 2 ? 'day' : 'minute'),
            $admitted ? null : max(1, (int) $result[3]),
            (int) $result[2],
            (int) $result[3],
        );
    }

    private ?RedisSecurityCommandExecutor $luaSeam = null;

    /**
     * The admission clock from the Redis server, shared by every
     * worker of the deployment. The invariant fails closed: a TIME
     * failure raises instead of silently switching to each host's
     * wall clock, which around window boundaries would let skewed
     * hosts use different windows.
     *
     * @throws \RuntimeException when the clock read is invalid
     */
    private function redisClockMs(): int
    {
        $time = $this->redis->time();
        if (!\is_array($time) || !isset($time[0])) {
            throw new \RuntimeException('Redis TIME returned an invalid response for the agent quota');
        }

        return (int) $time[0] * 1000 + (int) floor(((int) ($time[1] ?? 0)) / 1000);
    }
}
