<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\EventSubscriber;

use BelConsulting\KiwiCaptchaBundle\Risk\ClientIpResolver;
use BelConsulting\KiwiCaptchaBundle\Risk\LoginDecisionGate;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpPendingToken;
use KiwiCaptcha\Risk\RiskAction;
use KiwiCaptcha\Risk\RiskIdentityFactory;
use Psr\Log\LoggerInterface;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Component\Security\Core\Authentication\Token\RememberMeToken;

/**
 * The post-credential, pre-session first-attempt gate (P0-1).
 *
 * AuthenticationTokenCreatedEvent fires before the token is stored, so
 * this is the only hook that can actually withhold the session. On a
 * StepUp (or stronger) decision the just-created token is replaced with
 * {@see StepUpPendingToken}, which grants only IS_KIWI_STEP_UP_PENDING.
 * The step-up routes accept that role; every other firewall path does
 * not. After the factor completes the step-up credit restores the
 * wrapped token and records the network bucket.
 *
 * The engine pipeline runs here with event=AuthenticationSuccess and
 * the resolved principal id — the only path where firstAttemptEvidence
 * (novel network, breached credential, scope pressure) can fire. The
 * feedback paths never reach that code.
 *
 * Client IP comes from the bundle's own {@see ClientIpResolver} so the
 * novelty decision follows the same trust rules as every other
 * component. An unexpected error fails closed to the pending token:
 * a programming or wiring bug must never silently disable stuffing
 * protection (the store-failure path already degrades to a
 * conservative decision inside the pipeline).
 */
final class FirstAttemptLoginGuard implements EventSubscriberInterface
{
    /** High priority: the token is replaced before the firewall stores it. */
    public const TOKEN_CREATED_PRIORITY = 512;

    public const TOKEN_CREATED_EVENT = 'Symfony\Component\Security\Http\Event\AuthenticationTokenCreatedEvent';

    /**
     * The passport badge that marks an interactive password login (the
     * FormLogin / JsonLogin / HttpBasic shape). A string FQCN so the
     * guard duck-types even when security-http is not on the autoloader
     * at parse time.
     */
    private const PASSWORD_CREDENTIALS = 'Symfony\Component\Security\Http\Authenticator\Passport\Credentials\PasswordCredentials';

    public function __construct(
        private readonly LoginDecisionGate $gateway,
        private readonly RiskIdentityFactory $identityFactory,
        private readonly string $scope,
        private readonly ?ClientIpResolver $clientIpResolver = null,
        private readonly ?LoggerInterface $logger = null,
        private readonly bool $enabled = true,
        private readonly ?RequestStack $requestStack = null,
    ) {
    }

    /**
     * @return array<string, list<string>|string>
     */
    public static function getSubscribedEvents(): array
    {
        return [
            self::TOKEN_CREATED_EVENT => ['onTokenCreated', self::TOKEN_CREATED_PRIORITY],
        ];
    }

    public function onTokenCreated(object $event): void
    {
        if (!$this->enabled) {
            return;
        }
        try {
            $token = $this->tokenOf($event);
            if ($token === null || $token instanceof StepUpPendingToken) {
                return;
            }
            // Scope: only interactive (form/login) authenticators. A
            // remember-me or stateless API token must never be swapped
            // for a pending token the client cannot complete.
            if (!$this->isInteractiveAuthenticator($event, $token)) {
                return;
            }
            $request = $this->requestOf($event);
            if ($request === null) {
                // Fail closed: without a request there is no IP to
                // assess and no way to justify a full session.
                $this->withhold($event, $token, 'no_request');

                return;
            }
            $identifier = $this->tokenIdentifier($token);
            if ($identifier === null || $identifier === '') {
                $this->withhold($event, $token, 'unresolvable_identifier');

                return;
            }
            $principal = $this->identityFactory->principalId($identifier);
            $ip = $this->resolveIp($request);
            if ($ip === '') {
                $this->withhold($event, $token, 'empty_client_ip');

                return;
            }
            $decision = $this->gateway->loginDecision($this->scope, $ip, null, $principal, null);
            if ($decision === null) {
                $this->withhold($event, $token, 'no_decision');

                return;
            }
            if ($decision->action === RiskAction::Deny || $decision->action === RiskAction::StepUp) {
                $this->logger?->info('kiwi first-attempt gate withholds the session (step-up pending)', [
                    'scope' => $this->scope,
                    'decision_id' => $decision->decisionId,
                    'action' => $decision->action->value,
                ]);
                $this->replaceToken($event, new StepUpPendingToken($token));
            }
        } catch (\Throwable $e) {
            // Fail Closed: a gate error must never hand out a full
            // session. The pending token is the conservative outcome.
            $this->logger?->error('kiwi first-attempt gate failed closed on an unexpected error: {message}', [
                'message' => $e->getMessage(),
            ]);
            try {
                $token = $this->tokenOf($event);
                if ($token !== null && !$token instanceof StepUpPendingToken) {
                    $this->replaceToken($event, new StepUpPendingToken($token));
                }
            } catch (\Throwable) {
                // Last resort: the original token stands, but the error
                // is already alerted through the log.
            }
        }
    }

    /** Withhold the session with a named reason (always logged). */
    private function withhold(object $event, object $token, string $reason): void
    {
        $this->logger?->warning('kiwi first-attempt gate withholds the session', [
            'scope' => $this->scope,
            'reason' => $reason,
        ]);
        if ($token instanceof StepUpPendingToken) {
            return;
        }
        $this->replaceToken($event, new StepUpPendingToken($token));
    }

    /**
     * Whether the event's authenticator is an interactive credential
     * login. The gate must only withhold sessions a client can actually
     * win back through the step-up flow: a remember-me cookie or a
     * stateless API token carries no interactive completion path, so a
     * pending token would strand that client forever.
     *
     * The rules, in order:
     *
     * 1. A {@see RememberMeToken} is never interactive (checked on the
     *    token itself: the remember-me authenticator's passport is
     *    self-validating and would otherwise slip through).
     * 2. A real passport counts as interactive only when it carries a
     *    PasswordCredentials badge — the shape FormLogin, JsonLogin and
     *    HttpBasic all build. Passport exposes no getAuthClass() API,
     *    so the credential badge is the only reliable signal of a
     *    password login; a passport without it (remember-me, JWT/Token
     *    authenticators, custom self-validating passports) is not
     *    interactive. Fail closed: an unknown passport shape never
     *    counts, because the harm of a stranded pending token is
     *    permanent lockout while the harm of skipping the gate is the
     *    pre-guard posture.
     * 3. A duck-typed event without getPassport() (tests) is treated as
     *    interactive so the guard still exercises its logic.
     */
    private function isInteractiveAuthenticator(object $event, object $token): bool
    {
        if ($token instanceof RememberMeToken || str_contains($token::class, 'RememberMeToken')) {
            return false;
        }
        if (!method_exists($event, 'getPassport')) {
            // A duck-typed event (tests) is treated as interactive so
            // the guard still exercises its logic.
            return true;
        }
        try {
            $passport = $event->getPassport();
            if ($passport === null) {
                return false;
            }
            if (method_exists($passport, 'hasBadge')) {
                return (bool) $passport->hasBadge(self::PASSWORD_CREDENTIALS);
            }
            if (method_exists($passport, 'getBadges')) {
                foreach ($passport->getBadges() as $badge) {
                    if (is_object($badge) && (is_a($badge, self::PASSWORD_CREDENTIALS)
                        || str_ends_with($badge::class, 'PasswordCredentials'))) {
                        return true;
                    }
                }

                return false;
            }

            return false;
        } catch (\Throwable) {
            // Unknown passport shape: never interactive (fail closed —
            // a stuck pending token is worse than a skipped gate).
            return false;
        }
    }

    /**
     * Restore the wrapped authenticated token after the step-up factor
     * completes. Called by the step-up completion credit.
     */
    public static function unwrapIfPending(object $token): object
    {
        return $token instanceof StepUpPendingToken ? $token->getWrapped() : $token;
    }

    private function replaceToken(object $event, StepUpPendingToken $token): void
    {
        // The real AuthenticationTokenCreatedEvent API.
        if (method_exists($event, 'setAuthenticatedToken')) {
            $event->setAuthenticatedToken($token);

            return;
        }
        if (method_exists($event, 'setToken')) {
            $event->setToken($token);
        }
    }

    private function resolveIp(Request $request): string
    {
        if ($this->clientIpResolver !== null) {
            try {
                return $this->clientIpResolver->resolve($request);
            } catch (\Throwable) {
                return '';
            }
        }

        return (string) ($request->getClientIp() ?? '');
    }

    private function requestOf(object $event): ?Request
    {
        // The real AuthenticationTokenCreatedEvent carries no request;
        // the RequestStack is the source of truth. A duck-typed event
        // (tests) may still expose one.
        if (method_exists($event, 'getRequest')) {
            $request = $event->getRequest();
            if ($request instanceof Request) {
                return $request;
            }
        }

        return $this->requestStack?->getCurrentRequest();
    }

    private function tokenOf(object $event): ?object
    {
        // The real event API is getAuthenticatedToken(); duck-typed
        // test events may expose getToken().
        foreach (['getAuthenticatedToken', 'getToken'] as $method) {
            if (method_exists($event, $method)) {
                $token = $event->{$method}();
                if ($token !== null) {
                    return $token;
                }
            }
        }

        return null;
    }

    private function tokenIdentifier(object $token): ?string
    {
        try {
            if (method_exists($token, 'getUserIdentifier')) {
                $id = (string) $token->getUserIdentifier();

                return $id !== '' ? $id : null;
            }
            if (method_exists($token, 'getUsername')) {
                $id = (string) $token->getUsername();

                return $id !== '' ? $id : null;
            }
            $user = method_exists($token, 'getUser') ? $token->getUser() : null;
            if (\is_string($user) && $user !== '') {
                return $user;
            }
            if (\is_object($user) && method_exists($user, 'getUserIdentifier')) {
                $id = (string) $user->getUserIdentifier();

                return $id !== '' ? $id : null;
            }
        } catch (\Throwable) {
            return null;
        }

        return null;
    }
}
