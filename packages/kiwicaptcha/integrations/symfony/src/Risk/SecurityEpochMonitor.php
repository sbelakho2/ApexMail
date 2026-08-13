<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Risk;

use KiwiCaptcha\Verifier;

/**
 * Bounded-revocation-latency security-epoch monitor (audit #81).
 *
 * Reads the CENTRAL security-policy state — the `{kiwi:<ns>}:security-policy`
 * hash's `min_policy_epoch` field, the same key the readiness probe consults
 * — with a SHORT cache (risk.security_epoch_cache_secs, default 1 s) and
 * feeds the {@see Verifier}'s expected policy epoch per verification, so a
 * central policy bump revokes outstanding challenges within one cache window
 * instead of waiting for a redeploy.
 *
 * Three hardening properties:
 *
 *  1. MONOTONIC max: once this process has OBSERVED epoch N it never accepts
 *     a lower epoch, even if the central value regresses (a misconfigured
 *     rollback of the central hash must not silently re-validate challenges
 *     that were revoked).
 *  2. FAIL-SAFE on Redis failure: when the central read fails (Redis down,
 *     timeout), the monitor serves the LAST OBSERVED max — the verifier
 *     keeps enforcing the newest epoch it ever saw, never a weaker one.
 *  3. BOUNDED latency: the central value is re-read at most once per cache
 *     window, so the revocation latency is one TTL, never unbounded.
 *
 * The effective epoch is `max(configuredEpoch, observedMax)`: the local
 * risk.policy_version is the floor (a node never expects less than its own
 * issuance epoch — its own challenges must verify), and the central value
 * only ever raises it. The readiness gate
 * ({@see \BelConsulting\KiwiCaptchaBundle\Controller\KiwiHealthController})
 * keeps a binary whose configured epoch is BEHIND the central epoch out of
 * the pool, so a serving node's configured epoch is always >= the central
 * value.
 *
 * The epoch is applied to the shared {@see Verifier} via its deployment-
 * expectations seam, so every verification on this worker enforces the
 * CURRENT epoch — including the post-derive final revalidation.
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
     * @param \Redis|\Predis\Client|null $redis         the security Redis
     *                                                   (null = central state
     *                                                   unavailable — the
     *                                                   configured epoch is
     *                                                   authoritative)
     * @param string                     $namespace     the sanitized risk
     *                                                   namespace ({kiwi:<ns>})
     * @param int                        $configuredEpoch the local
     *                                                   risk.policy_version
     *                                                   (the floor + the
     *                                                   issuance-side stamp)
     * @param int                        $cacheSecs     short cache window
     *                                                   (risk.security_epoch_cache_secs)
     * @param callable(): float|null     $nowMs         clock override (tests)
     * @param string|null                $region        the verifier's expected
     *                                                   region — re-applied
     *                                                   with every epoch
     *                                                   rotation so the shared
     *                                                   verifier keeps all its
     *                                                   expectations
     * @param string|null                $issuer        the verifier's expected
     *                                                   deployment issuer
     *                                                   (audit #67) — same
     *                                                   re-apply rule
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
    ) {
        if ($cacheSecs < 1) {
            throw new \InvalidArgumentException('security-epoch cache window must be >= 1 s');
        }
        $this->currentEpoch = $configuredEpoch;
    }

    /**
     * Re-read the central epoch when the cache window elapsed, apply the
     * monotonic max to the verifier, and return the CURRENT effective epoch.
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
            $central = $this->readCentralEpoch();
            if ($central !== null) {
                $this->observedMax = max($this->observedMax, $central);
            }
            $this->apply(max($this->configuredEpoch, $this->observedMax));
        }

        return $this->currentEpoch;
    }

    /**
     * Explicit refresh hook for the verification path: the validator calls
     * this before every verification so the verifier's expected epoch is the
     * CURRENT one (bounded by the cache window). No-op semantics identical
     * to {@see currentEpoch()}.
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
     * The last-observed central epoch, or null when the read failed or the
     * field is absent.
     */
    private function readCentralEpoch(): ?int
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
        if (!\is_numeric($value)) {
            return null;
        }

        return (int) $value;
    }

    private function apply(int $epoch): void
    {
        if ($epoch === $this->currentEpoch) {
            return;
        }
        $this->currentEpoch = $epoch;
        // The rotation carries the CURRENT region/issuer expectations so the
        // shared verifier keeps them (the core applies all three together).
        $this->verifier->rotateDeploymentExpectations($epoch, $this->region, $this->issuer);
    }

    private function nowMs(): float
    {
        return $this->nowMs !== null ? (float) ($this->nowMs)() : microtime(true) * 1000;
    }
}
