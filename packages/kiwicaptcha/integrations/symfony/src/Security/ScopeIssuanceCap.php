<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Security;

/**
 * PER-SCOPE issuance cap (audit #89): a Redis fixed-window counter bounding
 * how many challenges a scope may issue per minute.
 *
 * Key: `{kiwi:<ns>}:issuance:<scopeIdentity>:<minute>` — one independent
 * window per scope per minute.
 *
 * SCOPE IDENTITY (audit rounds 15–16 — the trust boundary): a security
 * quota must operate over a SERVER-OWNED identity, not an attacker-chosen
 * dimension. The key component is the risk policy's canonical server-side
 * scope id: the configured `risk.scopes.<name>.id` (a stable u32 that two
 * scopes can never share), the shared synthetic id the extension reserves
 * for unknown scopes in 'minimum' mode, or — for ANY scope the server
 * cannot resolve in ANY mode, including risk-disabled deployments —
 * {@see self::UNKNOWN_QUOTA_ID}, one reserved bucket shared by every
 * unresolved name.
 * CLUSTER CLOCK ASSUMPTION (audit round 20): the window minute is read
 * via Redis TIME and the quota key is then executed against the hash-slot
 * owner — on a single primary or Sentinel deployment the TIME read and
 * the Lua share one server, which is the supported topology. On a genuine
 * multi-primary Redis Cluster the TIME read is NOT intrinsically tied to
 * the slot owner executing the script, so skew between nodes can shift
 * window boundaries; Cluster deployments should route TIME and the keyed
 * EVAL to the same node or accept the skew bound. The cardinality of the
 * quota namespace is therefore
 * ALWAYS bounded by the server-owned configuration; an attacker can never
 * mint fresh quota windows by inventing scope names. The raw scope string
 * is never a Redis key component (audit #112): the controller always
 * passes a server-owned id; the HMAC fallback in {@see self::scopeKey()}
 * exists only for defensive/direct construction and only keeps
 * attacker-controlled BYTES out of the key name — it does NOT bound
 * cardinality (per-name soft limiting, never an independent security
 * bound).
 *
 * The HMAC key K_scope is derived from the bundle's risk master
 * (master_secret, falling back to the captcha secret_key) with
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
     * The RESERVED quota identity for scopes the server cannot resolve to
     * a configured policy scope id (audit round 16): unknown scopes in ANY
     * risk mode — including risk-disabled deployments — share this one
     * bucket, so an attacker can never mint fresh per-scope quota windows
     * by inventing scope names. Configured scope ids are 1..=4294967295
     * (risk-v1), so 0 never collides with a real policy id.
     */
    public const UNKNOWN_QUOTA_ID = 0;

    /**
     * HKDF info for the scope-rate HMAC key (audit #112): the key is
     * derived from the bundle's risk master with this purpose tag, so the
     * scope pseudonyms are independent of every other derived key.
     */
    public const SCOPE_RATE_HKDF_INFO = 'kiwi/v2/scope-rate';

    /**
     * Atomic increment + expiry + cap check:
     *   KEYS[1] = {kiwi:<ns>}:issuance:<scopeIdentity>:<minute>
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
     * @param int|null $canonicalScopeId the server-owned scope identity
     *                                   (audit rounds 15–16): the configured
     *                                   `risk.scopes.<name>.id`, the shared
     *                                   synthetic unknown-scope id, or
     *                                   {@see self::UNKNOWN_QUOTA_ID} for
     *                                   every unresolved scope — the
     *                                   controller ALWAYS passes one, so
     *                                   the quota namespace is bounded by
     *                                   the server-owned set. null (only
     *                                   direct/defensive construction) falls
     *                                   back to the keyed pseudonym, which
     *                                   hides the raw bytes but does NOT
     *                                   bound cardinality (per-name soft
     *                                   limiting only).
     *
     * @throws \Throwable when Redis fails (fail closed — the caller refuses
     *                    issuance rather than minting an unbilled challenge)
     */
    public function allow(string $scope, ?int $canonicalScopeId = null): bool
    {
        if ($this->redis === null || $this->cap <= 0) {
            return true;
        }

        $result = $this->eval(self::CHECK_SCRIPT, [$this->windowKey($scope, $canonicalScopeId)], [(string) $this->cap]);

        return (int) $result === 1;
    }

    /**
     * The fixed-window key for a scope:
     * `{kiwi:<ns>}:issuance:<scopeIdentity>:<minute>` where scopeIdentity is
     * the canonical server-owned scope id (decimal, when provided) or
     * `hex(hmac_sha256(scope, K_scope))` otherwise — the RAW scope never
     * appears in Redis. The canonical id is the security-quota identity
     * (cardinality bounded by the server-owned set); the HMAC fallback only
     * keeps attacker-controlled BYTES out of the key name (audit round 15 —
     * it does not bound cardinality). The minute comes from the Redis
     * server clock (one TIME read shared with the script's EXPIRE) or the
     * injected clock when Redis is unavailable.
     */
    public function windowKey(string $scope, ?int $canonicalScopeId = null): string
    {
        $identity = $canonicalScopeId !== null
            ? (string) $canonicalScopeId
            : $this->scopeKey($scope);

        return sprintf('%s%s:%d', $this->keyPrefix, $identity, $this->minute());
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
        // Audit round 19: the window minute comes from the REDIS SERVER
        // clock (all application workers share one window) and the clock
        // invariant FAILS CLOSED — a TIME failure raises instead of
        // silently switching to each host's wall clock (which around
        // minute boundaries would let skewed hosts use different window
        // keys). Redis is the configured security backend here: no Redis
        // TIME proof -> no quota proof -> no challenge issuance (the
        // controller maps the exception to 503 SERVICE_UNAVAILABLE).
        $time = $this->redis->time();
        if (!\is_array($time) || !isset($time[0])) {
            throw new \RuntimeException('Redis TIME returned an invalid response for the scope issuance cap');
        }

        return intdiv((int) $time[0], 60);
    }
}
