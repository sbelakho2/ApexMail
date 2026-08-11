<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Security;

use KiwiCaptcha\Verifier;
use KiwiCaptcha\VerifyOutcome;

/**
 * Verifier wrapper enforcing the aggregate Argon2id verification concurrency
 * cap (`argon2_max_concurrent_verifications`).
 *
 * KiwiCaptcha\Verifier is final and cannot be decorated by inheritance, so
 * this bundle-owned class composes it and re-exposes the same verify()
 * signature. The validator's constructor accepts Verifier|ThrottledVerifier,
 * and the extension wires whichever is appropriate for the configured
 * algorithm — plain pass-through for SHA-256 mode.
 *
 * Two admission backends:
 *
 *  - {@see RedisAdmissionSemaphore}: when the bundle has a Redis client
 *    (RedisStorage as the storage backend, or a `redis_service` config
 *    option), the cap is enforced ACROSS all PHP-FPM workers sharing the
 *    Redis instance — the deployment-wide bound.
 *  - {@see Argon2Semaphore} (in-process, static): fallback when no Redis
 *    client is configured. PHP-FPM workers share no memory, so this bounds
 *    concurrency PER PROCESS only — a documented approximation (see README).
 */
final class ThrottledVerifier
{
    /**
     * @param int                        $maxConcurrent 0 = no cap (pass-through)
     * @param RedisAdmissionSemaphore|null $redisSemaphore when set, admission is
     *                                                  enforced against Redis
     *                                                  (cross-worker); otherwise
     *                                                  the in-process semaphore
     *                                                  is used (per-process)
     */
    public function __construct(
        private readonly Verifier $inner,
        private readonly int $maxConcurrent,
        private readonly ?RedisAdmissionSemaphore $redisSemaphore = null,
    ) {
    }

    public function verify(
        string $rawToken,
        string $secretKey,
        ?string $expectedScope = null,
        ?string $clientIp = null,
        ?int $nowNs = null,
        bool $enforceTelemetry = false,
    ): VerifyOutcome {
        if ($this->maxConcurrent <= 0) {
            return $this->inner->verify($rawToken, $secretKey, $expectedScope, $clientIp, $nowNs, $enforceTelemetry);
        }

        if ($this->redisSemaphore !== null) {
            return $this->verifyWithRedisAdmission($rawToken, $secretKey, $expectedScope, $clientIp, $nowNs, $enforceTelemetry);
        }

        return $this->verifyWithInProcessSemaphore($rawToken, $secretKey, $expectedScope, $clientIp, $nowNs, $enforceTelemetry);
    }

    private function verifyWithInProcessSemaphore(
        string $rawToken,
        string $secretKey,
        ?string $expectedScope,
        ?string $clientIp,
        ?int $nowNs,
        bool $enforceTelemetry,
    ): VerifyOutcome {
        if (!Argon2Semaphore::acquire($this->maxConcurrent)) {
            throw new VerificationCapacityExceededException(sprintf(
                'KiwiCaptcha: %d concurrent Argon2id verifications are already in flight; refused after waiting for a slot (argon2_max_concurrent_verifications=%d).',
                Argon2Semaphore::active(),
                $this->maxConcurrent,
            ));
        }

        try {
            return $this->inner->verify($rawToken, $secretKey, $expectedScope, $clientIp, $nowNs, $enforceTelemetry);
        } finally {
            Argon2Semaphore::release();
        }
    }

    private function verifyWithRedisAdmission(
        string $rawToken,
        string $secretKey,
        ?string $expectedScope,
        ?string $clientIp,
        ?int $nowNs,
        bool $enforceTelemetry,
    ): VerifyOutcome {
        if (!$this->redisSemaphore->acquire()) {
            throw new VerificationCapacityExceededException(sprintf(
                'KiwiCaptcha: %d concurrent Argon2id verifications are already in flight across all workers; refused (argon2_max_concurrent_verifications=%d).',
                $this->maxConcurrent,
                $this->maxConcurrent,
            ));
        }

        try {
            return $this->inner->verify($rawToken, $secretKey, $expectedScope, $clientIp, $nowNs, $enforceTelemetry);
        } finally {
            $this->redisSemaphore->release();
        }
    }
}
