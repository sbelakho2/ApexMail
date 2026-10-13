<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Security\StepUp;

use BelConsulting\KiwiCaptchaBundle\Risk\OutcomeReporterInterface;
use KiwiCaptcha\Risk\Outcomes\Outcome;
use KiwiCaptcha\Risk\Outcomes\OutcomeHandle;

/**
 * The completion effect of the demand finalization: the stepUpCompleted
 * outcome reported for the authorized demand's principal and target
 * pseudonyms through the outcomes seam. A legitimate user is therefore
 * not demanded a second step-up while the credited trust holds, because
 * the risk side subtracts risk on that outcome through its mapping
 * table.
 *
 * This is an internal effect of {@see StepUpDemandFinalizer} and of
 * nothing else: the factor completion answers a proof, the finalizer
 * reassesses and settles the demand terminally, and only an authorized
 * settlement invokes this credit. The factor can never turn its proof
 * into an outcome booking by itself, which is exactly the boundary the
 * demand architecture draws.
 *
 * The idempotency keys derive from the challenge record id under a
 * purpose-separated key, built with the bundle's shared HKDF
 * derivation and this class's own info string. The same challenge can
 * never double-credit, and every caller shares one derivation. Each
 * handle dimension carries its own derived key, so the principal
 * report and the target report stay distinct bookings.
 *
 * A report that fails surfaces as an exception to the caller,
 * fail-closed: the finalizer answers the retryable
 * outcome_unavailable failure and the user repeats the completion,
 * since an authorized demand whose credit never landed would leave the
 * user stepped up again. The terminal settlement keeps the authorized
 * state, so the idempotent retry re-runs the effect without
 * double-booking.
 */
final class StepUpCompletionCredit
{
    private const HKDF_INFO = 'kiwi/v1/stepup-idem';

    private const HKDF_SALT = 'kiwicaptcha/deploy-salt/v1';

    private readonly string $idemKey;

    public function __construct(
        private readonly OutcomeReporterInterface $reporter,
        string $master,
    ) {
        if (\strlen($master) < 32) {
            throw new \InvalidArgumentException('The step-up idempotency master must be at least 32 bytes (the same floor as secret_key)');
        }
        $this->idemKey = hash_hkdf('sha256', $master, 32, self::HKDF_INFO, self::HKDF_SALT);
    }

    /**
     * Report stepUpCompleted for the authorized demand's principal and,
     * when the challenge asserted the principal owns the target, the
     * target pseudonym.
     *
     * The target credit (and the risk-side failure clear) only runs when
     * the challenge asserts the principal owns the target. A challenge
     * that merely *named* a victim target must never clear that
     * target's failure counter or lockout. The handle carries the
     * canonical 64-hex digest the challenge record stores, so the clear
     * lands on exactly the target state keys the engine's consolidated
     * assessment reads (the outcomes layer projects the digest to the
     * mark spelling where marks are written).
     *
     * @throws \Throwable when a report failed; the caller answers the
     *                    retryable failure and the idempotent retry
     *                    re-runs the effect
     */
    public function report(string $challengeId, string $principalPseudonym, ?string $targetPseudonym, bool $targetOwned): void
    {
        $this->reporter->report(
            Outcome::StepUpCompleted,
            OutcomeHandle::principal($principalPseudonym),
            $this->idempotencyKey('principal', $challengeId),
        );
        if ($targetPseudonym !== null && $targetOwned) {
            $this->reporter->report(
                Outcome::StepUpCompleted,
                OutcomeHandle::target($targetPseudonym),
                $this->idempotencyKey('target', $challengeId),
            );
        }
    }

    private function idempotencyKey(string $dimension, string $challengeId): string
    {
        return hash_hmac('sha256', 'step-up-completed:'.$dimension.':'.$challengeId, $this->idemKey);
    }
}
