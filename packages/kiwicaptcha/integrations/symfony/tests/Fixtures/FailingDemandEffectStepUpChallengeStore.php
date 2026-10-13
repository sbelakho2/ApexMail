<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests\Fixtures;

use BelConsulting\KiwiCaptchaBundle\Security\StepUp\ArrayStepUpChallengeStore;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpChallenge;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpChallengeStore;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpDemand;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpDemandSendLease;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpDemandSendSettlement;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpDemandState;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpFactorCompletion;

/**
 * A store decorator whose journal write can be armed to refuse exactly
 * one named effect once, so a test can kill the completion lifecycle
 * at the statement after an effect landed and before its journal
 * entry. Everything else delegates to the live array store.
 */
final class FailingDemandEffectStepUpChallengeStore implements StepUpChallengeStore
{
    /**
     * The armed effect name. The next journal write of this effect
     * throws instead of landing and disarms the fault; every other
     * effect journals normally.
     */
    public ?string $failEffect = null;

    public function __construct(
        private readonly ArrayStepUpChallengeStore $inner,
    ) {
    }

    public function create(StepUpChallenge $challenge, int $ttlSecs): string
    {
        return $this->inner->create($challenge, $ttlSecs);
    }

    public function read(string $challengeId): ?StepUpChallenge
    {
        return $this->inner->read($challengeId);
    }

    public function consume(string $challengeId): ?StepUpChallenge
    {
        return $this->inner->consume($challengeId);
    }

    public function recordFailure(string $challengeId, int $maxAttempts): int
    {
        return $this->inner->recordFailure($challengeId, $maxAttempts);
    }

    public function countBegin(string $principalPseudonym, int $windowSecs): int
    {
        return $this->inner->countBegin($principalPseudonym, $windowSecs);
    }

    public function createDemand(StepUpDemand $demand, int $ttlSecs): string
    {
        return $this->inner->createDemand($demand, $ttlSecs);
    }

    public function readDemand(string $demandId): ?StepUpDemand
    {
        return $this->inner->readDemand($demandId);
    }

    public function consumeDemand(string $demandId): ?StepUpDemand
    {
        return $this->inner->consumeDemand($demandId);
    }

    public function completeDemand(string $demandId, int $now, int $ttlSecs): ?StepUpDemand
    {
        return $this->inner->completeDemand($demandId, $now, $ttlSecs);
    }

    public function completeFactor(string $challengeId, string $demandId, string $presentedBindingHash, int $now, ?string $sessionHash = null): ?StepUpFactorCompletion
    {
        return $this->inner->completeFactor($challengeId, $demandId, $presentedBindingHash, $now, $sessionHash);
    }

    public function completedFactorOf(string $sessionHash, string $scope, int $now): ?string
    {
        return $this->inner->completedFactorOf($sessionHash, $scope, $now);
    }

    public function claimDemandFinalization(string $demandId, int $now, int $claimSecs): ?StepUpDemand
    {
        return $this->inner->claimDemandFinalization($demandId, $now, $claimSecs);
    }

    public function settleDemandFinalization(string $demandId, StepUpDemandState $state, int $now, ?string $factor = null): ?StepUpDemand
    {
        return $this->inner->settleDemandFinalization($demandId, $state, $now, $factor);
    }

    public function recordDemandEffect(string $demandId, string $effect, int $now): ?StepUpDemand
    {
        if ($this->failEffect !== null && $effect === $this->failEffect) {
            $this->failEffect = null;
            throw new \RuntimeException('the journal write of the armed effect died');
        }

        return $this->inner->recordDemandEffect($demandId, $effect, $now);
    }

    public function demandIdForOperation(string $operationDigest): ?string
    {
        return $this->inner->demandIdForOperation($operationDigest);
    }

    public function createRootDemand(StepUpDemand $demand, int $ttlSecs): string
    {
        return $this->inner->createRootDemand($demand, $ttlSecs);
    }

    public function supersedeDemandWithChild(string $parentDemandId, StepUpDemand $child): ?StepUpDemand
    {
        return $this->inner->supersedeDemandWithChild($parentDemandId, $child);
    }

    public function claimDemandSendLease(string $demandId, int $resendAfterSecs, int $leaseSecs): ?StepUpDemandSendLease
    {
        return $this->inner->claimDemandSendLease($demandId, $resendAfterSecs, $leaseSecs);
    }

    public function settleDemandSendLease(StepUpDemandSendSettlement $settlement): bool
    {
        return $this->inner->settleDemandSendLease($settlement);
    }

    public function reserveMailQuota(string $reservationId, array $budgetKeys, array $limits, int $windowSecs, int $leaseSecs): bool
    {
        return $this->inner->reserveMailQuota($reservationId, $budgetKeys, $limits, $windowSecs, $leaseSecs);
    }

    public function commitMailQuota(string $reservationId): void
    {
        $this->inner->commitMailQuota($reservationId);
    }

    public function releaseMailQuota(string $reservationId): bool
    {
        return $this->inner->releaseMailQuota($reservationId);
    }

    public function saveTotpSecret(string $principalPseudonym, string $secretRaw): void
    {
        $this->inner->saveTotpSecret($principalPseudonym, $secretRaw);
    }

    public function findTotpSecret(string $principalPseudonym): ?string
    {
        return $this->inner->findTotpSecret($principalPseudonym);
    }

    public function markTotpStep(string $principalPseudonym, int $step, int $ttlSecs): bool
    {
        return $this->inner->markTotpStep($principalPseudonym, $step, $ttlSecs);
    }

    public function markStepUpSuccess(string $principalPseudonym, int $ttlSecs, int $now): void
    {
        $this->inner->markStepUpSuccess($principalPseudonym, $ttlSecs, $now);
    }

    public function recentStepUpSuccess(string $principalPseudonym, int $withinSecs, int $now): bool
    {
        return $this->inner->recentStepUpSuccess($principalPseudonym, $withinSecs, $now);
    }

    public function markSessionStepUpSuccess(string $sessionId, string $principalPseudonym, string $factor, int $ttlSecs, int $now): void
    {
        $this->inner->markSessionStepUpSuccess($sessionId, $principalPseudonym, $factor, $ttlSecs, $now);
    }

    public function recentSessionStepUpSuccess(string $sessionId, string $principalPseudonym, ?string $minFactor, int $withinSecs, int $now): bool
    {
        return $this->inner->recentSessionStepUpSuccess($sessionId, $principalPseudonym, $minFactor, $withinSecs, $now);
    }

    public function countLockoutFailure(string $dimension, string $pseudonym, int $windowSecs): int
    {
        return $this->inner->countLockoutFailure($dimension, $pseudonym, $windowSecs);
    }

    public function lockoutUntil(string $dimension, string $pseudonym, int $now): int
    {
        return $this->inner->lockoutUntil($dimension, $pseudonym, $now);
    }

    public function armLockout(string $dimension, string $pseudonym, int $now, int $ttlSecs): void
    {
        $this->inner->armLockout($dimension, $pseudonym, $now, $ttlSecs);
    }

    public function clearLockout(string $dimension, string $pseudonym): void
    {
        $this->inner->clearLockout($dimension, $pseudonym);
    }
}
