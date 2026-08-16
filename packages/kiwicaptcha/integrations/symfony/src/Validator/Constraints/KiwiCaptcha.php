<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Validator\Constraints;

use Symfony\Component\Validator\Constraint;

/**
 * Validates a KiwiCaptcha solution token (the value of the kiwi__token field).
 *
 * Verification is performed locally using the verified kiwicaptcha-php core —
 * no external service, no secret key ever leaves the application.
 *
 * Usage:
 *   #[KiwiCaptcha(scope: 'login')]
 *   private ?string $kiwiToken = null;
 *
 * @Annotation
 * @Target({"PROPERTY", "METHOD", "ANNOTATION"})
 */
#[\Attribute(\Attribute::TARGET_PROPERTY | \Attribute::TARGET_METHOD | \Attribute::IS_REPEATABLE)]
class KiwiCaptcha extends Constraint
{
    /**
     * The token-level verification failure (audit #57): EVERY token-level
     * core error — WrongScope, IpMismatch, Expired, MalformedToken,
     * BadSignature, TooFast, WrongRegion, WrongPolicyVersion,
     * MissingClientIp, CounterTooLarge, InsufficientWork, RecordNotFound,
     * MalformedRecord, a request-binding mismatch (audit #41) — collapses to
     * ONE public code `invalid_or_expired`. The precise internal reason is
     * never exposed to the client (no oracle for which check failed); it
     * stays in the logs. The alias NOT_SOLVED_ERROR keeps the pre-round-9
     * name for BC.
     */
    public const INVALID_OR_EXPIRED_ERROR = 'invalid_or_expired';

    /** @deprecated BC alias for {@see self::INVALID_OR_EXPIRED_ERROR} */
    public const NOT_SOLVED_ERROR = self::INVALID_OR_EXPIRED_ERROR;

    /**
     * The verification was refused because the Argon2id admission budget is
     * saturated (CapacityExceeded — per-scope or global). Distinct from
     * invalid_or_expired so applications can tell a retryable capacity
     * refusal from a burned token.
     */
    public const RATE_LIMITED_ERROR = 'rate_limited';

    /**
     * The verification could not be completed because a security backend
     * (the challenge storage or the admission gate) is unavailable
     * (AdmissionUnavailable / StorageUnavailable), or the consume outcome is
     * unresolvably INDETERMINATE (ConsumeIndeterminate — audit #74: the
     * storage first tries the consumed record's committed result, and only
     * a genuinely unresolvable ambiguity lands here). Distinct so
     * applications can surface a temporary service problem instead of a
     * re-solve loop.
     */
    public const TEMPORARY_UNAVAILABLE_ERROR = 'temporary_unavailable';

    /**
     * The token verified correctly, but the scope's post_solve_check
     * re-assessment returned a Deny: the security context materially changed
     * while the client was solving, so the valid proof does not clear the
     * request. Distinct from INVALID_OR_EXPIRED_ERROR so applications can
     * react (fresh challenge, step-up, human review) instead of forcing a
     * silent re-solve loop.
     */
    public const POST_SOLVE_REJECTED_ERROR = 'kiwi.post_solve_rejected';

    /**
     * The token verified correctly, but the scope's post_solve_check
     * re-assessment returned a StepUp: the adaptive engine considers
     * proof-of-work alone insufficient for this request and demands
     * additional application-level verification (MFA, passkey, email
     * confirmation). Distinct from INVALID_OR_EXPIRED_ERROR and
     * POST_SOLVE_REJECTED_ERROR so applications can route the user to the
     * step-up flow instead of forcing a silent re-solve loop.
     */
    public const POST_SOLVE_STEP_UP_REQUIRED = 'kiwi.post_solve_step_up_required';

    protected const ERROR_NAMES = [
        self::INVALID_OR_EXPIRED_ERROR => 'INVALID_OR_EXPIRED_ERROR',
        self::RATE_LIMITED_ERROR => 'RATE_LIMITED_ERROR',
        self::TEMPORARY_UNAVAILABLE_ERROR => 'TEMPORARY_UNAVAILABLE_ERROR',
        self::POST_SOLVE_REJECTED_ERROR => 'POST_SOLVE_REJECTED_ERROR',
        self::POST_SOLVE_STEP_UP_REQUIRED => 'POST_SOLVE_STEP_UP_REQUIRED',
    ];

    public string $message = 'The security check failed. Please try again.';

    /** Expected challenge scope (null = accept any scope). */
    public ?string $scope = null;

    public function __construct(
        mixed $options = null,
        ?string $scope = null,
        ?string $message = null,
        ?array $groups = null,
        mixed $payload = null,
    ) {
        parent::__construct($options, $groups, $payload);
        // Symfony 8 removed the array-options -> constructor-parameter
        // hydration (deprecated since 7.1), so `new KiwiCaptcha(['scope'
        // => 'login'])` — the documented convention on 6.x/7.x — silently
        // produced a null scope. Accept BOTH forms explicitly: array
        // options (6.x/7.x convention) and named arguments (8.x).
        if (\is_array($options)) {
            $scope = \is_string($options['scope'] ?? null) ? $options['scope'] : $scope;
            $message = \is_string($options['message'] ?? null) ? $options['message'] : $message;
        }
        $this->scope = $scope ?? $this->scope;
        $this->message = $message ?? $this->message;
    }

    public function validatedBy(): string
    {
        return KiwiCaptchaValidator::class;
    }
}
