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
    public const NOT_SOLVED_ERROR = 'kiwicaptcha_not_solved';

    /**
     * The token verified correctly, but the scope's post_solve_check
     * re-assessment returned a Deny: the security context materially changed
     * while the client was solving, so the valid proof does not clear the
     * request. Distinct from NOT_SOLVED_ERROR so applications can react
     * (fresh challenge, step-up, human review) instead of forcing a silent
     * re-solve loop.
     */
    public const POST_SOLVE_REJECTED_ERROR = 'kiwi.post_solve_rejected';

    /**
     * The token verified correctly, but the scope's post_solve_check
     * re-assessment returned a StepUp: the adaptive engine considers
     * proof-of-work alone insufficient for this request and demands
     * additional application-level verification (MFA, passkey, email
     * confirmation). Distinct from NOT_SOLVED_ERROR and
     * POST_SOLVE_REJECTED_ERROR so applications can route the user to the
     * step-up flow instead of forcing a silent re-solve loop.
     */
    public const POST_SOLVE_STEP_UP_REQUIRED = 'kiwi.post_solve_step_up_required';

    protected const ERROR_NAMES = [
        self::NOT_SOLVED_ERROR => 'NOT_SOLVED_ERROR',
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
        $this->scope = $scope ?? $this->scope;
        $this->message = $message ?? $this->message;
    }

    public function validatedBy(): string
    {
        return KiwiCaptchaValidator::class;
    }
}
