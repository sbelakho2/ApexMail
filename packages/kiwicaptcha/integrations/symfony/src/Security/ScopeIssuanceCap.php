<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Security;

/**
 * PER-SCOPE issuance cap (audit #89): a Redis fixed-window counter bounding
 * how many challenges a scope may issue per minute.
 *
 * Key: `{kiwi:<ns>}:issuance:<hex(hmac_sha256(scope, derived key))>:<minute>`
 * — one independent window per scope per minute. The RAW SCOPE STRING IS
 * NEVER A REDIS KEY COMPONENT (audit #112): the scope is attacker-controlled
 * (bounded alphabet, unbounded cardinality), so the key carries
 * `hex(hmac_sha256(scope, K_scope))` — 64 hex chars of keyed pseudonym. The
 * HMAC key K_scope is derived from the bundle's risk master (master_secret,
 * falling back to the captcha secret_key) with
 * `hash_hkdf('sha256', master, 32, 'kiwi/v2/scope-rate')` —
 * {@see self::deriveScopeHmacKey()} — purpose-separated from the risk
 * identity keys, so a scope pseudonym is never derivable from any other
 * keyed material. The minute is derived from the Redis server clock when
 * Redis is the backend, so all workers share one window even when an
 * application host's wall clock drifts. The key shares the risk store's
 * hash-tag family (Cluster safe).
 *
 * ONE atomic Lua script (INCR + EXPIRE in a single round trip): the first
 * increment of a fresh window stamps its 60 s TTL, and the cap is checked on
 * the returned count — a concurrent reader can never observe an INCR-ed
 * value without its expiry, and the counter can never persist past its
 * minute.
 *
 * The cap is a GATE, not a bound: a request that consumes the last slot is
 * admitted, the next one in the same window is refused (the controller
 * returns 429 SCOPE_LIMITED before any challenge is minted).
 *
 * A Redis failure PROPAGATES (fail closed): the caller refuses issuance
 * rather than minting an unbilled challenge — the deployment-wide billed-work
 * cap must not silently degrade to unlimited.
 */
final class ScopeIssuanceCap
{
    /**
     * HKDF info for the scope-rate HMAC key (audit #112): the key is
     * derived from the bundle's risk master with this purpose tag, so the
     * scope pseudonyms are independent of every other derived key.
     */
    public const SCOPE_RATE_HKDF_INFO = 'kiwi/v2/scope-rate';

    /**
     * Atomic increment + expiry + cap check:
     *   KEYS[1] = {kiwi:<ns>}:issuance:<hex(hmac_sha256(scope, K_scope))>:<minute>
     *   ARGV[1] = cap
     * Returns 1 when the window has room, 0 when the cap is exhausted.
     */
    private const CHECK_SCRIPT = <<<'LUA'
-- Scope issuance cap: fixed-window INCR + EXPIRE 60, refuse beyond the cap
local n = redis.call('INCR', KEYS[1])
if n == 1 then redis.call('EXPIRE', KEYS[1], 60) end
if n > tonumber(ARGV[1]) then return 0 end
return 1
LUA;

    /**
     * @param \Redis|\Predis\Client|null $redis       the security Redis
     *                                                (null = cap disabled —
     *                                                no-op)
     * @param string                     $keyPrefix   full key prefix
     *                                                including the hash tag,
     *                                                e.g. "{kiwi:prod}:
     *                                                issuance:"
     * @param int                        $cap         per-scope per-minute cap
     *                                                (0 = unlimited, no-op)
     * @param string                     $scopeHmacKey the 32-byte scope-HMAC
     *                                                key (audit #112 —
     *                                                {@see self::deriveScopeHmacKey()});
     *                                                the raw scope is never
     *                                                a Redis key component
     * @param \Closure|null              $now         epoch-seconds clock
     *                                                override for tests
     *                                                (falls back to the Redis
     *                                                server clock when Redis
     *                                                is the backend)
     */
    public function __construct(
        private readonly \Redis|\Predis\Client|null $redis = null,
        private readonly string $keyPrefix = '{kiwi:kiwi}:issuance:',
        private readonly int $cap = 0,
        private readonly string $scopeHmacKey = '',
        private readonly ?\Closure $now = null,
    ) {
        if ($scopeHmacKey === '' && $redis !== null && $cap > 0) {
            throw new \InvalidArgumentException(
                'scopeHmacKey is required when the cap is enabled — the raw scope string must never be a Redis key component (audit #112); use ScopeIssuanceCap::deriveScopeHmacKey($master)'
            );
        }
    }

    /**
     * The scope-rate HMAC key (audit #112): `hash_hkdf('sha256', master,
     * 32, 'kiwi/v2/scope-rate')` — derived from the bundle's risk master
     * (risk.master_secret, falling back to the captcha secret_key) with the
     * purpose-separated info tag. The SAME derivation is used by the risk
     * package's calibration scope keys (both languages), so scope
     * pseudonyms stay consistent across the bundle and the engine.
     */
    public static function deriveScopeHmacKey(string $master): string
    {
        // Salt fixed for cross-language parity with the risk packages.
        return hash_hkdf('sha256', $master, 32, self::SCOPE_RATE_HKDF_INFO, 'kiwicaptcha/deploy-salt/v1');
    }

    /**
     * Whether the scope's window has room for one more issuance. CONSUMING:
     * an allowed check increments the window counter (the callers counts the
     * issuance it then performs). Never throws for a disabled cap (null
     * Redis or cap 0) — always allowed.
     *
     * @throws \Throwable when Redis fails (fail closed — the caller refuses
     *                    issuance rather than minting an unbilled challenge)
     */
    public function allow(string $scope): bool
    {
        if ($this->redis === null || $this->cap <= 0) {
            return true;
        }

        $result = $this->eval(self::CHECK_SCRIPT, [$this->windowKey($scope)], [(string) $this->cap]);

        return (int) $result === 1;
    }

    /**
     * The fixed-window key for a scope:
     * `{kiwi:<ns>}:issuance:<hex(hmac_sha256(scope, K_scope))>:<minute>` —
     * the RAW scope never appears in Redis (audit #112: attacker-controlled
     * cardinality stays out of the keyspace). The minute comes from the
     * Redis server clock (one TIME read shared with the script's EXPIRE) or
     * the injected clock when Redis is unavailable.
     */
    public function windowKey(string $scope): string
    {
        return sprintf('%s%s:%d', $this->keyPrefix, $this->scopeKey($scope), $this->minute());
    }

    /**
     * The keyed scope pseudonym: hex(hmac_sha256(scope, K_scope)) — 64 hex
     * chars, constant-length regardless of the scope, so distinct scopes
     * never collide structurally and the raw string is never a key
     * component (audit #112).
     */
    public function scopeKey(string $scope): string
    {
        return hash_hmac('sha256', $scope, $this->scopeHmacKey);
    }

    /**
     * Run the Lua script against whichever client implementation is in use.
     *
     * @param list<string> $keys
     * @param list<string> $args
     */
    private function eval(string $script, array $keys, array $args): mixed
    {
        if ($this->redis instanceof \Redis) {
            // phpredis signature: eval($script, $args, $numKeys)
            return $this->redis->eval($script, [...$keys, ...$args], \count($keys));
        }

        // Predis signature: eval($script, $numkeys, ...$keysAndArgs)
        return $this->redis->eval($script, \count($keys), ...$keys, ...$args);
    }

    private function minute(): int
    {
        if ($this->now !== null) {
            return intdiv((int) ($this->now)(), 60);
        }
        try {
            $time = $this->redis->time();
            if (\is_array($time) && isset($time[0])) {
                return intdiv((int) $time[0], 60);
            }
        } catch (\Throwable) {
            // Fall through to the local clock; the script still expires the
            // key, so a drifted window is bounded by the EXPIRE.
        }

        return intdiv(time(), 60);
    }
}
