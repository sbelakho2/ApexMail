<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Security\StepUp;

/**
 * The typed verdict of {@see StepUpHandlerInterface::complete()}.
 *
 * The credited identities answer the completion-credit contract: which
 * of the context's pseudonyms the stepUpCompleted outcome was reported
 * for. A succeeded verdict with both flags false carries no credit and
 * is therefore refused by the handlers (fail-closed: a completion that
 * booked no credit would leave the user stepped up again).
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

    private function __construct(
        public readonly StepUpResultStatus $status,
        public readonly ?string $challengeId,
        public readonly ?string $failureCode,
        public readonly bool $creditedPrincipal,
        public readonly bool $creditedTarget,
    ) {
    }

    public static function pending(string $challengeId): self
    {
        return new self(StepUpResultStatus::Pending, $challengeId, null, false, false);
    }

    public static function succeeded(bool $creditedPrincipal, bool $creditedTarget): self
    {
        return new self(StepUpResultStatus::Succeeded, null, null, $creditedPrincipal, $creditedTarget);
    }

    public static function failed(string $failureCode, ?string $challengeId = null): self
    {
        return new self(StepUpResultStatus::Failed, $challengeId, $failureCode, false, false);
    }

    /**
     * The completion credit of a succeeded verdict, as the json wire
     * shape of a completion answer reports it.
     *
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
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
