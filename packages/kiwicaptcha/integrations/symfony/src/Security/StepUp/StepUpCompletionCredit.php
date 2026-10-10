<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Security\StepUp;

use BelConsulting\KiwiCaptchaBundle\Risk\OutcomeReporterInterface;
use BelConsulting\KiwiCaptchaBundle\Risk\TargetMarkKey;
use KiwiCaptcha\Risk\Outcomes\Outcome;
use KiwiCaptcha\Risk\Outcomes\OutcomeHandle;

/**
 * The completion credit of the step-up plane: the stepUpCompleted
 * outcome reported for the challenge's principal and target pseudonyms
 * through the outcomes seam. A legitimate user is therefore not
 * demanded a second step-up while the credited trust holds, because
 * the risk side subtracts risk on that outcome through its mapping
 * table.
 *
 * The idempotency keys derive from the challenge record id under a
 * purpose-separated key, built with the bundle's shared HKDF
 * derivation and this class's own info string. The same challenge can
 * never double-credit, and both handlers share one derivation. Each
 * handle dimension carries its own derived key, so the principal
 * report and the target report stay distinct bookings.
 *
 * The credit runs after the single-use consumption, so exactly one
 * completer of a challenge ever reaches it. A report that fails
 * surfaces as an exception to the caller, fail-closed: the handlers
 * answer the outcome_unavailable failure and the user begins a fresh
 * challenge, since a completion without its credit would leave the
 * user stepped up again.
 */
final class StepUpCompletionCredit
{
    private const HKDF_INFO = 'kiwi/v1/stepup-idem';

    private const HKDF_SALT = 'kiwicaptcha/deploy-salt/v1';

    private readonly string $idemKey;

    public function __construct(
        private readonly OutcomeReporterInterface $reporter,
        string $master,
        private readonly ?SessionRestorer $sessionRestorer = null,
        private readonly ?\Symfony\Component\HttpFoundation\RequestStack $requestStack = null,
    ) {
        if (\strlen($master) < 32) {
            throw new \InvalidArgumentException('The step-up idempotency master must be at least 32 bytes (the same floor as secret_key)');
        }
        $this->idemKey = hash_hkdf('sha256', $master, 32, self::HKDF_INFO, self::HKDF_SALT);
    }

    /**
     * Report stepUpCompleted for the principal and (when the challenge
     * carried one) the target pseudonym, and answer the succeeded
     * verdict naming what was credited.
     *
     * @throws \Throwable when a report failed; the caller answers the
     *                    fail-closed outcome_unavailable verdict
     */
    public function credit(string $challengeId, StepUpChallenge $challenge): StepUpResult
    {
        $this->reporter->report(
            Outcome::StepUpCompleted,
            OutcomeHandle::principal($challenge->principalPseudonym),
            $this->idempotencyKey('principal', $challengeId),
        );
        $creditedTarget = false;
        // Target credit (and the risk-side failure clear) only runs when
        // the challenge asserts the principal owns the target. A
        // challenge that merely *named* a victim target must never
        // clear that target's failure counter or lockout.
        if ($challenge->targetPseudonym !== null && $challenge->targetOwned) {
            $this->reporter->report(
                Outcome::StepUpCompleted,
                OutcomeHandle::target(TargetMarkKey::of($challenge->targetPseudonym)),
                $this->idempotencyKey('target', $challengeId),
            );
            $creditedTarget = true;
        }
        // Restore the wrapped token and record the network bucket so
        // the next login from the same network is no longer novel.
        $this->sessionRestorer?->restore(
            $challenge->principalPseudonym,
            $this->requestStack?->getCurrentRequest(),
        );

        return StepUpResult::succeeded(true, $creditedTarget);
    }

    private function idempotencyKey(string $dimension, string $challengeId): string
    {
        return hash_hmac('sha256', 'step-up-completed:'.$dimension.':'.$challengeId, $this->idemKey);
    }
}
