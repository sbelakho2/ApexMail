<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Controller;

use BelConsulting\KiwiCaptchaBundle\Risk\PrincipalResolverInterface;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\KiwiStepUpHandlerRegistry;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpContext;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpHandlerInterface;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpResult;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpResultStatus;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpPendingToken;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpSessionBinding;
use KiwiCaptcha\Risk\RiskIdentityFactory;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * The HTTP surface of the step-up plane: begin() presents the
 * challenge, complete() answers the verdict. The step-up endpoints
 * are application-facing: their chrome, paths and access control
 * belong to the application's own auth flow. This controller is
 * therefore exposed as a service and the application registers its
 * routes; the bundle's route loader keeps its own endpoint set
 * unchanged.
 *
 * Route registration (the application's routes.yaml):
 *
 *   kiwi_step_up_begin:
 *     path: /kiwi/step-up/begin
 *     controller: StepUpController::begin
 *   kiwi_step_up_complete:
 *     path: /kiwi/step-up/complete
 *     controller: StepUpController::complete
 *
 * The paths must equal risk.step_up.begin_path and complete_path, or
 * those knobs must be set to the application's own paths. The reason:
 * the forms the handlers render post to the configured complete path.
 * Both routes belong behind the application's authentication firewall,
 * because the principal is resolved server-side through the wired
 * resolver, never from a client-supplied field.
 *
 * The context inputs are server-owned: the principal pseudonym from
 * the resolver, the target pseudonym and the return path from request
 * attributes the application sets, and the presentation mode from the
 * request's own negotiation. The begin reason defaults to the typed
 * violation name the validator answers, so a step-up begun from the
 * post-solve flow carries its coherent reason. That name is
 * {@see \BelConsulting\KiwiCaptchaBundle\Validator\Constraints\KiwiCaptcha::POST_SOLVE_STEP_UP_REQUIRED}.
 */
final class StepUpController
{
    private const DEFAULT_REASON = 'post_solve_step_up_required';

    public function __construct(
        private readonly KiwiStepUpHandlerRegistry $registry,
        private readonly RiskIdentityFactory $identityFactory,
        private readonly string $scope,
        private readonly ?PrincipalResolverInterface $principalResolver = null,
        private readonly ?\Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface $tokenStorage = null,
    ) {
    }

    public function begin(Request $request): Response
    {
        $rawPrincipal = $this->unwrapPendingToken($request);
        if ($rawPrincipal === null || $rawPrincipal === '') {
            return self::plain('No principal is resolvable for this request; step-up is refused.', Response::HTTP_FORBIDDEN);
        }
        $returnPath = $request->query->get('return_to');
        if (\is_string($returnPath) && $returnPath !== '' && !StepUpContext::isSafeReturnPath($returnPath)) {
            return self::plain('The return path must be an absolute same-site path.', Response::HTTP_UNPROCESSABLE_ENTITY);
        }
        $reason = $request->query->get('reason');
        if (!\is_string($reason) || $reason === '') {
            $reason = self::DEFAULT_REASON;
        }

        try {
            $context = new StepUpContext(
                $this->identityFactory->principalId($rawPrincipal),
                $this->targetPseudonym($request),
                $this->scope,
                \is_string($returnPath) && $returnPath !== '' ? $returnPath : null,
                $reason,
                $this->mode($request),
            );
            $handler = $this->handler($request);
        } catch (\InvalidArgumentException $e) {
            return self::plain($e->getMessage(), Response::HTTP_UNPROCESSABLE_ENTITY);
        }

        return $handler->begin($request, $context);
    }

    public function complete(Request $request): Response
    {
        try {
            $handler = $this->handler($request);
        } catch (\InvalidArgumentException $e) {
            return self::plain($e->getMessage(), Response::HTTP_UNPROCESSABLE_ENTITY);
        }
        // The completion is bound to the session that began the
        // challenge: the principal is re-resolved here, exactly like
        // at begin(), and the handler refuses a challenge that belongs
        // to anyone else. A request with no resolvable principal can
        // complete nothing.
        $rawPrincipal = $this->unwrapPendingToken($request);
        if ($rawPrincipal === null || $rawPrincipal === '') {
            return self::plain('No principal is resolvable for this request; step-up completion is refused.', Response::HTTP_FORBIDDEN);
        }
        try {
            $boundPrincipal = $this->identityFactory->principalId($rawPrincipal);
        } catch (\Throwable) {
            return self::plain('No principal is resolvable for this request; step-up completion is refused.', Response::HTTP_FORBIDDEN);
        }
        StepUpSessionBinding::bind($request, $boundPrincipal);
        $result = $handler->complete($request);

        if ($this->mode($request) === StepUpContext::MODE_JSON) {
            return new Response(
                (string) json_encode($result->toArray(), JSON_UNESCAPED_SLASHES),
                self::statusOf($result),
                ['Content-Type' => 'application/json', 'Cache-Control' => 'no-store'],
            );
        }
        if ($result->status === StepUpResultStatus::Succeeded) {
            $returnPath = $request->query->get('return_to');
            if (\is_string($returnPath) && $returnPath !== '' && StepUpContext::isSafeReturnPath($returnPath)) {
                return new RedirectResponse($returnPath, Response::HTTP_SEE_OTHER);
            }
        }

        return self::plain(match ($result->status) {
            StepUpResultStatus::Succeeded => 'Verification complete.',
            StepUpResultStatus::Pending => 'That code was not accepted; try again with the current code.',
            default => 'This verification can no longer be completed; begin a fresh challenge.',
        }, self::statusOf($result));
    }

    /**
     * The raw principal of the request, resolved through the wired
     * resolver with a pending token temporarily unwrapped.
     *
     * A {@see StepUpPendingToken} deliberately answers null from
     * getUser() (a pending session must never pass IS_AUTHENTICATED_*
     * checks), so the typical application resolver — $security->getUser()
     * — resolves nothing and step-up would be refused to exactly the
     * users who need it. The wrapped token is therefore exposed to the
     * resolver for the duration of this resolution only, then the
     * pending token is put back: a begin, or a failed complete, never
     * upgrades the session. Only a completed factor does, through
     * {@see StepUpSessionBinding} and the session restorer.
     */
    private function unwrapPendingToken(Request $request): ?string
    {
        $token = $this->tokenStorage?->getToken();
        $pending = $token instanceof StepUpPendingToken ? $token : null;
        if ($pending !== null) {
            $this->tokenStorage?->setToken($pending->getWrapped());
        }
        try {
            return $this->principalResolver?->resolve($request, $this->scope);
        } finally {
            if ($pending !== null) {
                $this->tokenStorage?->setToken($pending);
            }
        }
    }

    /**
     * The handler of the request: the explicit handler query name, or
     * the configured default. A malformed or unknown name is refused
     * (fail-closed), never defaulted.
     */
    private function handler(Request $request): StepUpHandlerInterface
    {
        $name = $request->query->get('handler');
        if (\is_string($name) && $name !== '' && preg_match('/^[a-z0-9_]{1,64}$/D', $name) !== 1) {
            throw new \InvalidArgumentException('The handler name must be 1-64 chars of [a-z0-9_]');
        }

        return $this->registry->get(\is_string($name) && $name !== '' ? $name : null);
    }

    /**
     * The presentation mode: the explicit mode query parameter, or the
     * request's own json negotiation, html otherwise.
     */
    private function mode(Request $request): string
    {
        $mode = $request->query->get('mode');
        if (\is_string($mode) && $mode !== '') {
            return $mode === StepUpContext::MODE_JSON ? StepUpContext::MODE_JSON : StepUpContext::MODE_HTML;
        }

        return str_contains((string) $request->headers->get('Accept', ''), 'application/json')
            ? StepUpContext::MODE_JSON
            : StepUpContext::MODE_HTML;
    }

    /**
     * The server-owned target pseudonym: the application sets the
     * request attribute when the flow addresses a target identity (for
     * example the claimed username of a login step-up). Only the exact
     * pseudonym shape is accepted — the canonical 64-char lowercase
     * hex digest the engine derives
     * {@see \KiwiCaptcha\Risk\RiskIdentityFactory::targetId()}. A
     * truncated or raw value is refused.
     */
    private function targetPseudonym(Request $request): ?string
    {
        $target = $request->attributes->get('_kiwi_step_up_target');
        if ($target === null) {
            return null;
        }
        if (!\is_string($target) || preg_match('/^[0-9a-f]{64}$/D', $target) !== 1) {
            throw new \InvalidArgumentException('The _kiwi_step_up_target attribute must be the 64 lowercase hex target pseudonym, never a raw identifier');
        }

        return $target;
    }

    private static function statusOf(StepUpResult $result): int
    {
        return match ($result->status) {
            StepUpResultStatus::Succeeded => Response::HTTP_OK,
            StepUpResultStatus::Pending => Response::HTTP_UNAUTHORIZED,
            default => Response::HTTP_UNPROCESSABLE_ENTITY,
        };
    }

    private static function plain(string $body, int $status): Response
    {
        return new Response($body, $status, ['Content-Type' => 'text/plain; charset=utf-8', 'Cache-Control' => 'no-store']);
    }
}
