<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Security\StepUp;

/**
 * The typed verdict of {@see StepUpHandlerInterface::complete()}.
 *
 * A succeeded verdict of a handler is the verified factor proof: it
 * names the challenge that was consumed, the demand the challenge was
 * bound to, the factor and its server-owned assurance rank, and the
 * identities the proof belongs to. It books nothing: the demand
 * finalization decides the authorization and the completion effects
 * ({@see StepUpDemandFinalizer}). A verdict with credited flags true
 * therefore only ever leaves the finalizer's authorization, never a
 * handler.
 */
final class StepUpResult
{
    /**
     * The terminal failure codes of a completion. Stable wire values.
     */
    public const FAIL_UNKNOWN_CHALLENGE = 'unknown_challenge';
    public const FAIL_EXPIRED = 'expired';
    public const FAIL_BAD_CODE = 'bad_code';
    public const FAIL_TOO_MANY_ATTEMPTS = 'too_many_attempts';
    public const FAIL_NOT_ENROLLED = 'not_enrolled';
    /** The stored factor secret cannot be unsealed for its principal (re-enroll required). */
    public const FAIL_SECRET_UNUSABLE = 'secret_unusable';
    public const FAIL_REPLAYED_STEP = 'replayed_step';
    public const FAIL_OUTCOME_UNAVAILABLE = 'outcome_unavailable';
    /** The completing session is not the one that began the challenge. */
    public const FAIL_SESSION_MISMATCH = 'session_mismatch';
    /** The principal or target budget is locked out; retry later. */
    public const FAIL_LOCKED_OUT = 'locked_out';
    /** The challenge named no demand, so its proof finalizes nothing. */
    public const FAIL_DEMAND_UNBOUND = 'demand_unbound';
    /** The demand finalization refused the completion (the reassessment denied it). */
    public const FAIL_DEMAND_REFUSED = 'demand_refused';
    /** The reassessment re-raised the step-up: a strictly stronger child demand took over. */
    public const FAIL_DEMAND_ESCALATED = 'escalated';

    private function __construct(
        public readonly StepUpResultStatus $status,
        public readonly ?string $challengeId,
        public readonly ?string $failureCode,
        public readonly bool $creditedPrincipal,
        public readonly bool $creditedTarget,
        /** The demand the proof answers, null on a failure or an unbound challenge. */
        public readonly ?string $demandId = null,
        /** The factor identity of the proof, null on a failure. */
        public readonly ?string $factor = null,
        /** The server-owned assurance rank of the factor, null on a failure. */
        public readonly ?int $assurance = null,
        /** The principal pseudonym the proof belongs to, server-internal only. */
        public readonly ?string $principalPseudonym = null,
        /** The target pseudonym of the proof, null when the challenge named none. */
        public readonly ?string $targetPseudonym = null,
        /** Whether the proof asserts the principal owns the target. */
        public readonly bool $targetOwned = false,
        /**
         * The structured escalation payload of a step_up_required
         * completion answer (the child demand id, the factor it
         * requires, its assurance rank, the begin path), null on every
         * other verdict. The json wire shape reports it verbatim: the
         * escalation survives the wire boundary instead of collapsing
         * into an opaque failure.
         *
         * @var array<string, mixed>|null
         */
        public readonly ?array $escalation = null,
    ) {
    }

    public static function pending(string $challengeId): self
    {
        return new self(StepUpResultStatus::Pending, $challengeId, null, false, false);
    }

    /**
     * The finalizer's authorized verdict, or an enrollment completion:
     * a succeeded answer whose credit flags name what was booked.
     */
    public static function succeeded(bool $creditedPrincipal, bool $creditedTarget): self
    {
        return new self(StepUpResultStatus::Succeeded, null, null, $creditedPrincipal, $creditedTarget);
    }

    /**
     * The verified factor proof of one consumed challenge: the demand
     * it answers, the factor with its assurance, and the pseudonym
     * identities the finalization books. The credit flags stay false:
     * the proof itself books nothing.
     */
    public static function proved(StepUpChallenge $challenge, StepUpFactorAssurance $assurance): self
    {
        return new self(
            StepUpResultStatus::Succeeded,
            $challenge->id,
            null,
            false,
            false,
            $challenge->demandId,
            $assurance->identity,
            $assurance->rank,
            $challenge->principalSubject() ?? $challenge->principalPseudonym,
            $challenge->targetPseudonym,
            $challenge->targetOwned,
        );
    }

    public static function failed(string $failureCode, ?string $challengeId = null): self
    {
        return new self(StepUpResultStatus::Failed, $challengeId, $failureCode, false, false);
    }

    /**
     * The typed escalation answer of a completed proof: the fresh
     * reassessment re-raised the step-up, a strictly stronger child
     * demand took the family over, and the answer carries the child on
     * the wire. The demand id, the required factor, its assurance rank
     * and the begin path are exactly what a client needs to begin the
     * child; nothing else rides.
     */
    public static function escalated(
        ?string $challengeId,
        string $childDemandId,
        ?string $requiredFactor,
        ?int $requiredRank,
        string $beginPath,
    ): self {
        $payload = [
            'status' => 'step_up_required',
            'reason' => 'escalated',
            'demand' => $childDemandId,
        ];
        if ($requiredFactor !== null) {
            $payload['required_factor'] = $requiredFactor;
        }
        if ($requiredRank !== null) {
            $payload['required_rank'] = $requiredRank;
        }
        $payload['begin_path'] = $beginPath;

        return new self(StepUpResultStatus::Failed, $challengeId, self::FAIL_DEMAND_ESCALATED, false, false, escalation: $payload);
    }

    /**
     * The completion credit of a succeeded verdict, as the json wire
     * shape of a completion answer reports it. The pseudonym identities
     * and the assurance ride no wire: they are the finalizer's input,
     * never a client payload. An escalated answer reports its
     * structured payload verbatim (status step_up_required, the child
     * demand, the required factor and rank, the begin path).
     *
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        if ($this->escalation !== null) {
            return $this->escalation;
        }
        $payload = ['status' => $this->status->value];
        if ($this->challengeId !== null) {
            $payload['challenge_id'] = $this->challengeId;
        }
        if ($this->failureCode !== null) {
            $payload['failure_code'] = $this->failureCode;
        }
        if ($this->status === StepUpResultStatus::Succeeded) {
            $payload['credited'] = ['principal' => $this->creditedPrincipal, 'target' => $this->creditedTarget];
        }

        return $payload;
    }
}
