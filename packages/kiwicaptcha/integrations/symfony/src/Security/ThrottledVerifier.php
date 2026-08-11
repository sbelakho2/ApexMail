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
 */
final class ThrottledVerifier
{
    /**
     * @param int $maxConcurrent 0 = no cap (pass-through)
     */
    public function __construct(
        private readonly Verifier $inner,
        private readonly int $maxConcurrent,
    ) {
    }

    public function verify(
        string $rawToken,
        string $secretKey,
        ?string $expectedScope = null,
        ?string $clientIp = null,
        ?int $nowNs = null,
        bool $enforceTelemetry = false,
        ?int $maxAttempts = null,
    ): VerifyOutcome {
        if ($this->maxConcurrent <= 0) {
            return $this->inner->verify($rawToken, $secretKey, $expectedScope, $clientIp, $nowNs, $enforceTelemetry, $maxAttempts);
        }

        if (!Argon2Semaphore::acquire($this->maxConcurrent)) {
            throw new VerificationCapacityExceededException(sprintf(
                'KiwiCaptcha: %d concurrent Argon2id verifications are already in flight; refused after waiting for a slot (argon2_max_concurrent_verifications=%d).',
                Argon2Semaphore::active(),
                $this->maxConcurrent,
            ));
        }

        try {
            return $this->inner->verify($rawToken, $secretKey, $expectedScope, $clientIp, $nowNs, $enforceTelemetry, $maxAttempts);
        } finally {
            Argon2Semaphore::release();
        }
    }
}
