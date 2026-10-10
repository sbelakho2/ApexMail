<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Security;

use BelConsulting\KiwiCaptchaBundle\Security\Authority\RedisSecurityCommandExecutor;
use Psr\Log\LoggerInterface;

/**
 * Per-scope issuance cap: a Redis sliding-window log bounding how many
 * challenges a scope may issue per 60 s.
 *
 * Key: `{kiwi:<ns>}:issuance:<scopeIdentity>:sw`, one per-scope sorted
 * set carrying the whole window (one member per admitted issuance,
 * scored at the admission ms).
 *
 * Scope identity, the trust boundary: a security quota must operate over
 * a server-owned identity, not an attacker-chosen dimension. The key
 * component is the risk policy's canonical server-side scope id: the
 * configured `risk.scopes.<name>.id`, a stable u32 that two scopes can
 * never share, or the shared synthetic id the extension reserves for
 * unknown scopes in 'minimum' mode. Any scope the server cannot resolve
 * in any mode, risk-disabled deployments included, falls back to
 * {@see self::UNKNOWN_QUOTA_ID}: one reserved bucket shared by every
 * unresolved name.
 *
 * Cluster clock assumption: the window's now_ms is read via Redis TIME
 * and the quota keys are then executed against the hash-slot owner. On
 * a single primary or Sentinel deployment the TIME read and the Lua
 * share one server, which is the supported topology. On a genuine
 * multi-primary Redis Cluster the TIME read has no intrinsic tie to
 * the slot owner executing the script, so skew between nodes can
 * shift window boundaries. Cluster deployments should route TIME and
 * the keyed EVAL to the same node or accept the skew bound. The
 * cardinality of the quota namespace is always bounded by the
 * server-owned configuration: an attacker can never mint fresh quota
 * windows by inventing scope names. The raw scope string is never a
 * Redis key component: the controller always passes a server-owned id;
 * the HMAC fallback in {@see self::scopeKey()} exists only for
 * defensive/direct construction and only keeps attacker-controlled
 * bytes out of the key name. It does not bound cardinality: per-name
 * soft limiting, never an independent security bound.
 *
 * The HMAC key K_scope is derived from the bundle's risk master
 * (master_secret, falling back to the captcha secret_key) with
 * `hash_hkdf('sha256', master, 32, 'kiwi/v2/scope-rate')`,
 * {@see self::deriveScopeHmacKey()}, purpose-separated from the risk
 * identity keys. A scope pseudonym is never derivable from any other
 * keyed material. The admission timestamps are derived from the Redis
 * server clock when Redis is the backend, so all workers share one
 * window even when an application host's wall clock drifts. The keys
 * share the risk store's hash-tag family (Cluster safe).
 *
 * One atomic Lua script (prune + count + admit in a single round
 * trip). The window slides: every entry at or older than
 * now - 60 000 ms is pruned and the live count is checked against
 * the cap. An admission adds a unique member (now_ms:seq, the seq
 * from a dedicated INCR counter so two admissions in one ms never
 * collide) and refreshes both keys' TTLs. The invariant: any 60 s sliding
 * window admits at most the cap, so a burst straddling a minute
 * boundary yields exactly the cap, never twice the fixed-window
 * boundary allowance.
 *
 * The cap is a gate, not a bound: a request that consumes the last slot
 * is admitted, the next one inside the window is refused (the
 * controller returns 429 `SCOPE_LIMITED` before any challenge is minted).
 *
 * Operational contract: the counter is global to the scope rather than
 * per user or per source. Exhausting a well-known scope's cap such as
 * the login scope refuses every user of that scope for the rest of the
 * window with a rate-limited response. Treat the cap as an emergency
 * billed-work ceiling set well above peak issuance, and alert when it
 * fires instead of letting it fire routinely. Once the live count
 * reaches 80% of the cap, {@see self::alertOnApproach()} logs a
 * warning (scope, count, cap) at most once per scope per window,
 * so the ceiling being approached is visible before it starts
 * refusing requests.
 *
 * A Redis failure propagates, fail closed: the caller refuses issuance
 * rather than minting an unbilled challenge, so the deployment-wide
 * billed-work cap must not silently degrade to unlimited.
 */
final class ScopeIssuanceCap
{
    /**
     * The reserved quota identity for scopes the server cannot resolve
     * to a configured policy scope id: unknown scopes in any risk mode,
     * risk-disabled deployments included, share this one bucket. An
     * attacker can never mint fresh per-scope quota windows by inventing
     * scope names. Configured scope ids are 1..=4294967295 (risk-v1), so
     * 0 never collides with a real policy id.
     */
    public const UNKNOWN_QUOTA_ID = 0;

    /**
     * `HKDF` info for the scope-rate HMAC key: the key is
     * derived from the bundle's risk master with this purpose tag, so the
     * scope pseudonyms are independent of every other derived key.
     */
    public const SCOPE_RATE_HKDF_INFO = 'kiwi/v2/scope-rate';

    /** The sliding window length in ms (60 s, the per-minute cap knob). */
    private const WINDOW_MS = 60000;

    /**
     * The approach-alert factor: a warning is logged once the live
     * count reaches ceil(0.8 x cap) of the window.
     */
    private const APPROACH_FACTOR = 0.8;

    /**
     * The approach-alert de-dup TTL in s: at most one warning per scope
     * per window; the bound keeps the APCu marker finite.
     */
    private const ALERT_TTL_SECS = 60;

    /**
     * Atomic sliding-window admission. Keys and arguments:
     *   KEYS[1] = {kiwi:<ns>}:issuance:<scopeIdentity>:sw (the window
     *   ZSET) and KEYS[2] = ...:sw:seq (the unique-member counter).
     *   ARGV[1] = now_ms, ARGV[2] = window_ms, ARGV[3] = cap.
     * Prunes every entry at or older than now-window (the window is
     * (now-window, now]: an entry exactly at the cutoff has expired).
     * It returns {1, count-after-admission} when the window has room
     * and {0, live-count} when the cap is exhausted.
     */
    private const CHECK_SCRIPT = <<<'LUA'
-- Scope issuance cap: sliding-window admission over a per-scope ZSET
local cutoff = tonumber(ARGV[1]) - tonumber(ARGV[2])
redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', cutoff)
local n = redis.call('ZCARD', KEYS[1])
if n >= tonumber(ARGV[3]) then return {0, n} end
local seq = redis.call('INCR', KEYS[2])
redis.call('ZADD', KEYS[1], tonumber(ARGV[1]), tostring(ARGV[1]) .. ':' .. tostring(seq))
redis.call('PEXPIRE', KEYS[1], tonumber(ARGV[2]) + 1000)
redis.call('PEXPIRE', KEYS[2], tonumber(ARGV[2]) + 1000)
return {1, n + 1}
LUA;

    /**
     * @param \Redis|\Predis\Client|null $redis       the security Redis
     *                                                (null = cap disabled,
     *                                                no-op).
     * @param string                     $keyPrefix   full key prefix
     *                                                including the hash tag,
     *                                                e.g. "{kiwi:prod}:
     *                                                issuance:".
     * @param int                        $cap         per-scope per-minute cap
     *                                                (0 = unlimited, no-op).
     * @param string                     $scopeHmacKey the 32-byte scope-HMAC
     *                                                key,
     *                                                {@see self::deriveScopeHmacKey()};
     *                                                the raw scope is never
     *                                                a Redis key component.
     * @param \Closure|null              $now         epoch-seconds clock
     *                                                override for tests
     *                                                (integer or float
     *                                                seconds; the window is
     *                                                evaluated in ms —
     *                                                falls back to the Redis
     *                                                server clock when Redis
     *                                                is the backend).
     * @param LoggerInterface|null       $logger      receives the
     *                                                cap-approaching
     *                                                warning (null = no
     *                                                alerts).
     */
    public function __construct(
        private readonly \Redis|\Predis\Client|null $redis = null,
        private readonly string $keyPrefix = '{kiwi:kiwi}:issuance:',
        private readonly int $cap = 0,
        private readonly string $scopeHmacKey = '',
        private readonly ?\Closure $now = null,
        private readonly ?LoggerInterface $logger = null,
    ) {
        if ($scopeHmacKey === '' && $redis !== null && $cap > 0) {
            throw new \InvalidArgumentException(
                'scopeHmacKey is required when the cap is enabled — the raw scope string must never be a Redis key component; use ScopeIssuanceCap::deriveScopeHmacKey($master)'
            );
        }
    }

    /**
     * The scope-rate HMAC key: `hash_hkdf('sha256', master,
     * 32, 'kiwi/v2/scope-rate')` — derived from the bundle's risk master
     * (risk.master_secret, falling back to the captcha secret_key) with the
     * purpose-separated info tag. The same derivation is used by the risk
     * package's calibration scope keys (both languages), so scope
     * pseudonyms stay consistent across the bundle and the engine.
     */
    public static function deriveScopeHmacKey(string $master): string
    {
        // Salt fixed for cross-language parity with the risk packages.
        return hash_hkdf('sha256', $master, 32, self::SCOPE_RATE_HKDF_INFO, 'kiwicaptcha/deploy-salt/v1');
    }

    /**
     * Whether the scope's window has room for one more issuance.
     * Consuming: an allowed check adds an admission to the window,
     * counting the issuance the caller then performs. Never throws for
     * a disabled cap (null Redis or cap 0) — always allowed.
     *
     * The canonical server-owned scope identity is mandatory: the
     * configured `risk.scopes.<name>.id`, the shared synthetic
     * unknown-scope id, or {@see self::UNKNOWN_QUOTA_ID} for every
     * unresolved scope. There is deliberately no nullable fallback: a
     * per-name HMAC namespace cannot bound attacker-chosen cardinality,
     * so it is unreachable from the security cap. Direct integrators who
     * explicitly want the non-cardinality-safe per-name form must call
     * {@see self::allowSoftLegacy()} by that name.
     *
     * @throws \Throwable when Redis fails (fail closed — the caller refuses
     *                    issuance rather than minting an unbilled challenge)
     */
    public function allow(string $scope, int $canonicalScopeId): bool
    {
        if ($this->redis === null || $this->cap <= 0) {
            return true;
        }

        [$allowed] = $this->admit($this->windowKey($canonicalScopeId), (string) $canonicalScopeId);

        return $allowed === 1;
    }

    /**
     * Legacy per-name soft quota: keys the window on the hex form of
     * hmac_sha256(scope, K_scope), which hides attacker-controlled
     * bytes but does not bound attacker-controlled cardinality — every
     * unique scope name mints a unique counter. This is not a security
     * bound and is not used anywhere in the bundle; it exists only for
     * integrators migrating from the earlier per-name shape and is named
     * to make the distinction impossible to miss.
     */
    public function allowSoftLegacy(string $scope): bool
    {
        if ($this->redis === null || $this->cap <= 0) {
            return true;
        }

        [$allowed] = $this->admit($this->windowKeySoftLegacy($scope), 'pseudonym '.substr($this->scopeKey($scope), 0, 12));

        return $allowed === 1;
    }

    /**
     * The sliding-window key for the security cap:
     * `{kiwi:<ns>}:issuance:<canonicalScopeId>:sw`: the server-owned
     * scope id (decimal) is the quota identity; the raw scope never
     * appears in Redis (the nullable HMAC fallback is confined to the
     * legacy form, see {@see self::windowKeySoftLegacy()}). One ZSET per
     * scope carries the whole window — there is no per-minute suffix to
     * rotate: the window slides by score pruning, not by the minute.
     */
    public function windowKey(int $canonicalScopeId): string
    {
        return sprintf('%s%d:sw', $this->keyPrefix, $canonicalScopeId);
    }

    /**
     * Legacy per-name window key, the hex form of
     * hmac_sha256(scope, K_scope), for {@see self::allowSoftLegacy()} —
     * hides the raw bytes, does not bound cardinality.
     */
    public function windowKeySoftLegacy(string $scope): string
    {
        return sprintf('%s%s:sw', $this->keyPrefix, $this->scopeKey($scope));
    }

    /**
     * The keyed scope pseudonym: hmac_sha256(scope, K_scope) in hex, 64
     * chars, constant-length regardless of the scope, so distinct scopes
     * never collide structurally and the raw string is never a key
     * component.
     */
    public function scopeKey(string $scope): string
    {
        return hash_hmac('sha256', $scope, $this->scopeHmacKey);
    }

    /**
     * Run one sliding-window admission and surface the approach alert:
     * the script's returned live count drives the warning at
     * >= ceil(0.8 x cap), see {@see self::alertOnApproach()}.
     *
     * @param string $windowKey the per-scope window ZSET key (the
     *                          seq counter rides next to it as `:seq`).
     * @param string $scopeLabel the log-safe scope identity (the decimal
     *                           canonical id, or the keyed pseudonym on
     *                           the legacy path; never the raw scope).
     *
     * @return array{0: int, 1: int} [1|0 admitted, the live window count]
     */
    private function admit(string $windowKey, string $scopeLabel): array
    {
        $nowMs = $this->nowMs();
        $result = $this->eval(self::CHECK_SCRIPT, [$windowKey, $windowKey.':seq'], [(string) $nowMs, (string) self::WINDOW_MS, (string) $this->cap]);
        $admitted = \is_array($result) ? (int) ($result[0] ?? 0) : (int) $result;
        $count = \is_array($result) ? (int) ($result[1] ?? 0) : 0;
        $this->alertOnApproach($windowKey, $scopeLabel, $nowMs, $count);

        return [$admitted, $count];
    }

    /**
     * Warn as the cap is approached (the live count at or above
     * ceil(0.8 x cap)), at most once per scope per window. The
     * last-alerted window marker is APCu-backed (shared across the
     * workers of one deployment, 60 s TTL), with the per-instance
     * fallback de-duplicating a single CLI/test process when APCu is
     * absent. The scope label is the server-owned canonical id (or the
     * keyed pseudonym on the legacy path); the raw scope string is
     * never logged.
     */
    private function alertOnApproach(string $windowKey, string $scopeLabel, int $nowMs, int $count): void
    {
        if ($this->logger === null || $count < (int) ceil(self::APPROACH_FACTOR * $this->cap)) {
            return;
        }
        $key = 'kiwicaptcha.scope_cap.alert.'.hash('sha256', $windowKey);
        $window = intdiv($nowMs, self::WINDOW_MS);
        $last = $this->apcuGet($key);
        if (!\is_int($last)) {
            $last = $this->lastAlertWindow[$windowKey] ?? null;
        }
        if ($last === $window) {
            return;
        }
        $this->logger->warning(
            'kiwicaptcha: scope issuance cap approaching: scope {scope} is at {count} of the {cap}-per-minute cap in the current window and the cap is being approached — it will start refusing challenges before the window slides',
            ['scope' => $scopeLabel, 'count' => $count, 'cap' => $this->cap],
        );
        $this->lastAlertWindow[$windowKey] = $window;
        $this->apcuPut($key, $window, self::ALERT_TTL_SECS);
    }

    /** @var array<string, int> the per-instance alert de-dup fallback (window key => window) */
    private array $lastAlertWindow = [];

    /**
     * Run the Lua script against whichever client implementation is in use.
     * The script rides the typed seam's ordinary mutation lane,
     * {@see RedisSecurityCommandExecutor::executeMutation()}: a quota
     * window counter is a non-final mutation. Under ha_authority
     * pinned_primary it therefore serves within the guard's
     * verification window instead of being classified by the
     * plain-EVAL shape as security-final (which would force an INFO +
     * pin revalidation round trip per issuance). Without the wrapper
     * the lane declaration is inert and the packing is byte-identical.
     *
     * @param list<string> $keys
     * @param list<string> $args
     */
    private function eval(string $script, array $keys, array $args): mixed
    {
        return ($this->luaSeam ??= new RedisSecurityCommandExecutor($this->redis))
            ->executeMutation($script, $keys, $args);
    }

    private ?RedisSecurityCommandExecutor $luaSeam = null;

    private function apcuGet(string $key): mixed
    {
        if (!\function_exists('apcu_fetch')) {
            return null;
        }
        $ok = false;
        $value = @apcu_fetch($key, $ok);
        if (!$ok) {
            return null;
        }

        return $value;
    }

    /**
     * Store with the alert's 60 s de-dup window; a disabled or failing
     * APCu (for example a CLI process without apc.enable_cli) degrades
     * to the instance fallback, so the alert still de-duplicates per
     * process.
     */
    private function apcuPut(string $key, mixed $value, int $ttl): void
    {
        if (!\function_exists('apcu_store')) {
            return;
        }
        @apcu_store($key, $value, $ttl);
    }

    private function nowMs(): int
    {
        if ($this->now !== null) {
            return (int) round(((float) ($this->now)()) * 1000);
        }
        // The window clock comes from the Redis server clock (all
        // application workers share one window), and the clock invariant
        // fails closed: a TIME failure raises instead of silently
        // switching to each host's wall clock, which around window
        // boundaries would let skewed hosts use different windows.
        // Redis is the configured security backend here: no Redis TIME
        // proof, no quota proof, no challenge issuance (the controller
        // maps the exception to 503 `SERVICE_UNAVAILABLE`).
        $time = $this->redis->time();
        if (!\is_array($time) || !isset($time[0])) {
            throw new \RuntimeException('Redis TIME returned an invalid response for the scope issuance cap');
        }

        return (int) $time[0] * 1000 + (int) floor(((int) ($time[1] ?? 0)) / 1000);
    }
}
