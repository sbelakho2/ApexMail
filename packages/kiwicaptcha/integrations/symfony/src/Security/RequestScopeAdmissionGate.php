<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Security;

use KiwiCaptcha\VerificationAdmissionGate;
use Symfony\Component\HttpFoundation\RequestStack;

/**
 * Request-scope-aware admission gate: forwards every acquire()
 * from the core Verifier to the inner {@see RedisAdmissionSemaphore} WITH
 * the current request's captcha scope, so the semaphore's PER-SCOPE budget
 * ({kiwicaptcha:argon2:leases:<ns>}:<scope>, argon2_max_per_tenant)
 * engages on top of the global cap.
 *
 * The scope travels through the request: the validator
 * ({@see \BelConsulting\KiwiCaptchaBundle\Validator\Constraints\KiwiCaptchaValidator})
 * stamps the constraint's scope into the request attribute
 * ({@see self::SCOPE_ATTRIBUTE}) immediately before calling the verifier;
 * this wrapper reads it at acquire() time. When no attribute is set (direct
 * verifier use, non-web contexts, a null constraint scope) the acquire is
 * unscoped — only the global cap applies.
 *
 * The interface contract stays unchanged (acquire(): ?string — the core
 * verifier calls it without arguments); the scope is an implementation
 * detail of the bundle wiring.
 */
final class RequestScopeAdmissionGate implements VerificationAdmissionGate
{
    /**
     * Request attribute holding the captcha scope of the current
     * validation. Set by the validator before verification.
     */
    public const SCOPE_ATTRIBUTE = '_kiwi_captcha_scope';

    public function __construct(
        private readonly RedisAdmissionSemaphore $semaphore,
        private readonly RequestStack $requestStack,
    ) {
    }

    public function acquire(): ?string
    {
        $scope = null;
        $request = $this->requestStack->getMainRequest();
        if ($request !== null && $request->attributes->has(self::SCOPE_ATTRIBUTE)) {
            $scope = (string) $request->attributes->get(self::SCOPE_ATTRIBUTE);
        }

        return $this->semaphore->acquire($scope);
    }

    public function release(string $lease): void
    {
        $this->semaphore->release($lease);
    }
}
