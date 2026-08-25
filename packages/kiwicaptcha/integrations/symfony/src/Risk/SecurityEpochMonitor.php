<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Risk;

use KiwiCaptcha\Verifier;

/**
 * Bounded-revocation-latency security-epoch monitor.
 *
 * Reads the central security-policy state, the `{kiwi:<ns>}:security-policy`
 * hash's `min_policy_epoch` field, the same key the readiness probe
 * consults, with a short cache (risk.security_epoch_cache_secs, default
 * 1 s). It feeds the {@see Verifier}'s expected policy epoch per
 * verification, so a central policy bump revokes outstanding challenges
 * within one cache window instead of waiting for a redeploy.
 *
 * Four hardening properties:
 *
 *  1. Monotonic max: once this process has observed epoch N it never
 *     accepts a lower epoch, even if the central value regresses (a
 *     misconfigured rollback of the central hash must not silently
 *     re-validate challenges that were revoked).
 *  2. Fail-safe on Redis failure: when the central read fails (Redis down,
 *     timeout), the monitor serves the last observed max — the verifier
 *     keeps enforcing the newest epoch it ever saw, never a weaker one.
 *  3. Bounded latency: the central value is re-read at most once per cache
 *     window, so the revocation latency is one TTL, never unbounded.
 *  4. Max-stale fail-closed: after the last successful central read, once
 *     `now > last_success + risk.security_epoch_max_stale_secs` (default
 *     60 s, min 10 s) the monitor reports {@see isStale()}. A stale monitor
 *     is the deliberate constrained degradation: the cached max may no
 *     longer reflect the central policy, since an emergency revocation
 *     could have landed while the node could not read. The validator
 *     then fails verification closed (temporary_unavailable), and the
 *     challenge controller refuses issuance with 503
 *     `SERVICE_UNAVAILABLE`. Within the
 *     window the cached max keeps serving, so availability is preserved
 *     for a bounded outage. A monitor without a Redis client is never
 *     stale: "no central state by design" is a configured posture, not a
 *     failure.
 *
 * The effective epoch is `max(configuredEpoch, observedMax)`: the local
 * risk.policy_version is the floor, a node never expects less than its own
 * issuance epoch since its own challenges must verify, and the central
 * value only ever raises it. The readiness gate
 * ({@see \BelConsulting\KiwiCaptchaBundle\Controller\KiwiHealthController})
 * keeps a binary whose configured epoch is behind the central epoch out of
 * the pool, so a serving node's configured epoch is always >= the central
 * value.
 *
 * The epoch is applied to the shared {@see Verifier} via its deployment-
 * expectations seam, so every verification on this worker enforces the
 * current epoch, including the post-derive final revalidation.
 */
final class SecurityEpochMonitor
{
    /** The central policy hash key (shared with the readiness probe). */
    private const POLICY_KEY = '{kiwi:%s}:security-policy';

    /** The central hash field carrying the minimum policy epoch. */
    public const MIN_POLICY_EPOCH_FIELD = 'min_policy_epoch';

    private int $observedMax = 0;

    private int $currentEpoch;

    private float $refreshedAtMs = -PHP_FLOAT_MAX;

    /**
     * The wall-clock ms of the last successful central read (the HGET call
     * itself answered — the field may be absent). -PHP_FLOAT_MAX = never
     * succeeded: with a Redis client configured, that state is immediately
     * stale, fail closed, since an unobserved central policy can never be
     * trusted to be current.
     */
    private float $lastSuccessAtMs = -PHP_FLOAT_MAX;

    /**
     * @param \Redis|\Predis\Client|null $redis         the security Redis
     *                                                   (null = central state
     *                                                   unavailable: the
     *                                                   configured epoch is
     *                                                   authoritative and the
     *                                                   monitor is never
     *                                                   stale).
     * @param string                     $namespace     the sanitized risk
     *                                                   namespace ({kiwi:<ns>}).
     * @param int                        $configuredEpoch the local
     *                                                   risk.policy_version
     *                                                   (the floor and the
     *                                                   issuance-side stamp).
     * @param int                        $cacheSecs     short cache window
     *                                                   (risk.security_epoch_cache_secs).
     * @param callable(): float|null     $nowMs         clock override (tests).
     * @param string|null                $region        the verifier's expected
     *                                                   region, re-applied
     *                                                   with every epoch
     *                                                   rotation so the shared
     *                                                   verifier keeps all its
     *                                                   expectations.
     * @param string|null                $issuer        the verifier's expected
     *                                                   deployment issuer,
     *                                                   same re-apply rule.
     * @param int                        $maxStaleSecs  max-stale window
     *                                                   (risk.security_epoch_
     *                                                   max_stale_secs, >= 10):
     *                                                   once now exceeds
     *                                                   last_success +
     *                                                   max_stale, the
     *                                                   monitor reports stale.
     */
    public function __construct(
        private readonly Verifier $verifier,
        private readonly \Redis|\Predis\Client|null $redis,
        private readonly string $namespace,
        private readonly int $configuredEpoch,
        private readonly int $cacheSecs = 1,
        private $nowMs = null,
        private readonly ?string $region = null,
        private readonly ?string $issuer = null,
        private readonly int $maxStaleSecs = 60,
    ) {
        if ($cacheSecs < 1) {
            throw new \InvalidArgumentException('security-epoch cache window must be >= 1 s');
        }
        if ($maxStaleSecs < 10) {
            throw new \InvalidArgumentException('security-epoch max-stale window must be >= 10 s');
        }
        $this->currentEpoch = $configuredEpoch;
    }

    /**
     * Re-read the central epoch when the cache window elapsed, apply the
     * monotonic max to the verifier, and return the current effective epoch.
     *
     * Never throws: a central-read failure serves the last-observed max
     * (fail-safe). The verifier rotation is applied at most once per epoch
     * change, and always carries the configured region/issuer expectations
     * so rotating the epoch can never disable them.
     */
    public function currentEpoch(): int
    {
        $now = $this->nowMs();
        if ($now - $this->refreshedAtMs >= $this->cacheSecs * 1000) {
            $this->refreshedAtMs = $now;
            $central = $this->readCentralEpoch($now);
            if ($central !== null) {
                $this->observedMax = max($this->observedMax, $central);
            }
            $this->apply(max($this->configuredEpoch, $this->observedMax));
        }

        return $this->currentEpoch;
    }

    /**
     * Explicit refresh hook for the verification path: the validator calls
     * this before every verification so the verifier's expected epoch is
     * the current one (bounded by the cache window). No-op semantics
     * identical to {@see currentEpoch()}.
     */
    public function refresh(): int
    {
        return $this->currentEpoch();
    }

    /** The highest central epoch this process ever observed (0 = none yet). */
    public function observedMax(): int
    {
        return $this->observedMax;
    }

    /** The central policy hash key (shared with the readiness probe). */
    public function policyKey(): string
    {
        return sprintf(self::POLICY_KEY, $this->namespace);
    }

    /**
     * Max-stale fail-closed: true when the central policy state has not
     * been confirmed successfully for longer than the max-stale window
     * (risk.security_epoch_max_stale_secs). The cached max may then be
     * outdated, since an emergency revocation could have landed while this
     * node could not read, so the caller must fail closed: the validator
     * returns temporary_unavailable and the challenge controller refuses
     * issuance with 503 `SERVICE_UNAVAILABLE`. Within the window the cached
     * max keeps serving (bounded outage tolerance). A monitor without a
     * Redis client is never stale (no central state by design — the
     * configured epoch is authoritative). A monitor that never succeeded a
     * central read (Redis down from boot) is stale immediately: an
     * unobserved central policy is never trusted to be current.
     */
    public function isStale(): bool
    {
        if ($this->redis === null) {
            return false;
        }

        return $this->nowMs() > $this->lastSuccessAtMs + $this->maxStaleSecs * 1000;
    }

    /**
     * The last-observed central epoch, or null when the read failed or the
     * field is absent. A successful read, the HGET call itself answered
     * even with an absent field (the "no central policy configured" state
     * is legitimate and confirmed), refreshes the max-stale deadline; a
     * thrown read leaves {@see isStale()} to drift toward true.
     */
    private function readCentralEpoch(float $now): ?int
    {
        if ($this->redis === null) {
            return null;
        }
        try {
            $value = $this->redis->hget($this->policyKey(), self::MIN_POLICY_EPOCH_FIELD);
        } catch (\Throwable) {
            // Fail-safe: serve the last-observed max, never a weaker epoch.
            return null;
        }
        if ($value === null || $value === false) {
            // A successful read with no central epoch configured (a fresh
            // deployment): the monitor is healthy and the success mark is
            // refreshed — only the last-observed max keeps serving.
            $this->lastSuccessAtMs = $now;

            return null;
        }
        // Corrupt PRESENT state must never be indistinguishable from
        // absent state: the central policy epoch is a canonical unsigned
        // decimal integer, and a malformed value (abc, -1, 1.5, 1e3,
        // whitespace variants, integer overflow) is NOT a successful
        // read — the stale window is NOT refreshed (the verification
        // fails closed once the max-stale bound passes) and the
        // last-observed max keeps serving.
        if (!\is_string($value) || !preg_match('/^(?:0|[1-9][0-9]*)$/D', $value)) {
            return null;
        }
        $epoch = (int) $value;
        if ((string) $epoch !== $value) {
            // Integer overflow: the value does not fit a PHP int.
            return null;
        }
        $this->lastSuccessAtMs = $now;

        return $epoch;
    }

    private function apply(int $epoch): void
    {
        if ($epoch === $this->currentEpoch) {
            return;
        }
        $this->currentEpoch = $epoch;
        // The rotation carries the current region/issuer expectations so
        // the shared verifier keeps them (the core applies all three
        // together).
        $this->verifier->rotateDeploymentExpectations($epoch, $this->region, $this->issuer);
    }

    private function nowMs(): float
    {
        return $this->nowMs !== null ? (float) ($this->nowMs)() : microtime(true) * 1000;
    }
}
