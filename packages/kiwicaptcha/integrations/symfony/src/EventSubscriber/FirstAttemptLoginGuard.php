<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\EventSubscriber;

use BelConsulting\KiwiCaptchaBundle\Risk\ClientIpResolver;
use BelConsulting\KiwiCaptchaBundle\Risk\ContinuityCookie;
use BelConsulting\KiwiCaptchaBundle\Risk\LoginDecisionGate;
use BelConsulting\KiwiCaptchaBundle\Risk\MetricsCounterStore;
use BelConsulting\KiwiCaptchaBundle\Risk\TrustedDeviceCookie;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpPendingToken;
use KiwiCaptcha\Risk\RiskAction;
use KiwiCaptcha\Risk\RiskIdentityFactory;
use Psr\Log\LoggerInterface;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Component\Security\Core\Authentication\Token\RememberMeToken;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Exception\BadCredentialsException;

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
 * The scope resolves per event: the request's _firewall_context
 * attribute names the firewall (the security.firewall.map.context.
 * prefix stripped off), and the risk.login_scopes map translates the
 * firewall name into the risk scope the guard assesses and books
 * under. One container with a user firewall and an admin firewall
 * therefore carries two independent login policies. An event whose
 * firewall has no entry is out of the guard's mandate: it is skipped
 * and counted under {@see self::UNMAPPED_COUNTER}, so a deployment can
 * see how many logins bypass the gate through a missing mapping.
 *
 * A mapped scope that configures login_step_up always
 * (risk.scopes.<name>.login_step_up) withholds the session on every
 * interactive login, an Allow included. The map $loginStepUpByScope
 * (scope name to the configured mode) is resolved from the same scope
 * table the authenticator wiring reads, and the guard consults the
 * entry of the scope it resolved for the event. The pending path stays
 * completable through the principal factors, so a critical scope never
 * grants a session on credentials alone. The resolved scope rides the
 * pending token, exposed through {@see StepUpPendingToken::scope()},
 * so the step-up flow books its challenge under the same scope the
 * demand was raised in.
 *
 * The browser's continuity identities ride the same decision: the
 * continuity cookie read and the trusted-device cookie read flow into
 * the gate, so a returning browser on a rotated address is recognized.
 * On an Allow the device value is staged on the request under the
 * {@see self::DEVICE_MINT_ATTRIBUTE} attribute and the response
 * subscriber issues the cookie; a fresh mint on a StepUp is simply
 * dropped, the step-up restore mints its own.
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

    /** Request attribute carrying the device value to (re)issue as a cookie. */
    public const DEVICE_MINT_ATTRIBUTE = '_kiwi_device_mint';

    /**
     * The exporter series counting the token-created events the guard
     * skipped because no risk.login_scopes entry covered their
     * firewall. A growing series with an enforcing posture means the
     * map is missing entries.
     */
    public const UNMAPPED_COUNTER = 'kiwi_login_guard_unmapped_total';

    /** The request attribute the firewall listener stamps with the context key. */
    private const FIREWALL_CONTEXT_ATTRIBUTE = '_firewall_context';

    /** The context-key prefix, stripped to recover the bare firewall name. */
    private const FIREWALL_CONTEXT_PREFIX = 'security.firewall.map.context.';

    public function __construct(
        private readonly LoginDecisionGate $gateway,
        private readonly RiskIdentityFactory $identityFactory,
        /**
         * Firewall name to risk scope name (the risk.login_scopes
         * map). The scope of an event resolves here per event; an
         * unmapped firewall skips the gate and counts
         * {@see self::UNMAPPED_COUNTER}.
         *
         * @var array<string, string>
         */
        private readonly array $loginScopes,
        private readonly ?ClientIpResolver $clientIpResolver = null,
        private readonly ?LoggerInterface $logger = null,
        private readonly bool $enabled = true,
        private readonly ?RequestStack $requestStack = null,
        private readonly ?ContinuityCookie $continuity = null,
        private readonly ?TrustedDeviceCookie $device = null,
        /**
         * Scope name to the configured login_step_up mode ('risk' or
         * 'always'). Resolved from the risk.scopes table the extension
         * hands the authenticator wiring; the guard reads the entry of
         * the scope it resolved for the event. 'always' withholds the
         * session on every interactive login under the scope, an Allow
         * included.
         *
         * @var array<string, string>
         */
        private readonly array $loginStepUpByScope = [],
        /**
         * The configured target form field names (F14) per resolved
         * scope name: their submitted values ride the decision, so the
         * engine's target resolver books the target dimension (failure
         * counter and spread) on the first-attempt path, exactly like
         * the outcome bridge does. A scope without an entry (or without
         * a target_field) carries no target.
         *
         * @var array<string, list<string>>
         */
        private readonly array $targetFieldsByScope = [],
        /**
         * The exporter's cross-worker counter store; only the unmapped
         * skip is counted here (the decision paths book through the
         * engine's own metrics).
         */
        private readonly ?MetricsCounterStore $counters = null,
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
        $resolvedScope = null;
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
                // No request means no firewall context either, so the
                // scope cannot resolve and the guard has no mandate.
                $this->skipUnmapped(null, 'no_request');

                return;
            }
            $scope = $this->resolveScope($request);
            if ($scope === null) {
                $this->skipUnmapped($request, 'no_scope_mapping');

                return;
            }
            $resolvedScope = $scope;
            $identifier = $this->tokenIdentifier($token);
            if ($identifier === null || $identifier === '') {
                $this->withhold($event, $token, $scope, 'unresolvable_identifier');

                return;
            }
            $ip = $this->resolveIp($request);
            if ($ip === '') {
                $this->withhold($event, $token, $scope, 'empty_client_ip');

                return;
            }
            // The browser's continuity identities ride the decision: the
            // continuity cookie read and the trusted-device cookie read.
            // Without them the gate would judge every login novel and
            // continuity would never exist in production. When no device
            // cookie was presented, a fresh value is minted before the
            // call: a random mint carries no binding, so it cannot change
            // the decision, and an Allow can bind it and re-issue the
            // cookie in one pass.
            $sessionCookie = $this->continuity?->read($request);
            $presentedDevice = $this->device?->read($request);
            $deviceValue = $presentedDevice ?? $this->device?->mint();
            $decision = $this->gateway->loginDecision(
                $scope,
                $ip,
                $sessionCookie,
                $identifier,
                null,
                $deviceValue,
                $this->targetFieldValues($request, $scope),
            );
            if ($decision === null) {
                $this->withhold($event, $token, $scope, 'no_decision');

                return;
            }
            // A terminal Deny refuses the login outright. It must never
            // mint a step-up: the pending token is the step-up mint, and
            // a Deny that a factor can solve is not a Deny. The refusal
            // runs before the always-policy below so a scope configured
            // for forced step-up still keeps its Denies terminal.
            if ($decision->action === RiskAction::Deny) {
                $this->logger?->info('kiwi first-attempt gate denies the login (terminal)', [
                    'scope' => $scope,
                    'decision_id' => $decision->decisionId,
                    'action' => $decision->action->value,
                ]);
                throw new BadCredentialsException('The login was denied.');
            }
            // The always step-up policy: the decision is recorded (its
            // evidence and reasons still flow) but never grants the
            // session. The pending path is completable through the
            // principal factors, so every login under the scope pays
            // the second factor.
            if (($this->loginStepUpByScope[$scope] ?? 'risk') === 'always') {
                $this->logger?->info('kiwi first-attempt gate withholds the session (login_step_up always)', [
                    'scope' => $scope,
                    'decision_id' => $decision->decisionId,
                    'action' => $decision->action->value,
                ]);
                $this->replaceToken($event, $this->pendingToken($token, $scope));

                return;
            }
            if ($decision->action === RiskAction::StepUp) {
                $this->logger?->info('kiwi first-attempt gate withholds the session (step-up pending)', [
                    'scope' => $scope,
                    'decision_id' => $decision->decisionId,
                    'action' => $decision->action->value,
                ]);
                $this->replaceToken($event, $this->pendingToken($token, $scope));

                return;
            }
            // Allow: issue (or re-issue) the trusted-device cookie. The
            // presented value re-issues verbatim so the Max-Age slides
            // forward; the minted value issues for the first time. The
            // engine's post-Allow binding records the device tag, so the
            // tag's last-use and trust refresh with every Allow.
            if ($deviceValue !== null) {
                $request->attributes->set(self::DEVICE_MINT_ATTRIBUTE, $deviceValue);
            }
        } catch (BadCredentialsException $e) {
            // A terminal deny: never fail closed to a solvable
            // step-up. The refusal surfaces to the authentication
            // failure handler, exactly like a wrong password.
            throw $e;
        } catch (\Throwable $e) {
            // Fail Closed: a gate error must never hand out a full
            // session. The pending token is the conservative outcome,
            // stamped with the scope the event resolved to (when it
            // did) so the completion still books the right scope.
            $this->logger?->error('kiwi first-attempt gate failed closed on an unexpected error: {message}', [
                'message' => $e->getMessage(),
            ]);
            try {
                $token = $this->tokenOf($event);
                if ($token !== null && !$token instanceof StepUpPendingToken) {
                    $this->replaceToken($event, $resolvedScope !== null
                        ? $this->pendingToken($token, $resolvedScope)
                        : new StepUpPendingToken($token));
                }
            } catch (\Throwable $replacementFailure) {
                // The guard could not install the blocked state. The
                // invariant: when the guard cannot determine the
                // outcome, authentication cannot stay authenticated.
                // The authenticated token is cleared where the event
                // allows it and the login is refused outright, so the
                // failure handler answers instead of a granted session.
                $this->logger?->error('kiwi first-attempt gate could not install the pending state; the login is refused: {message}', [
                    'message' => $replacementFailure->getMessage(),
                ]);
                $this->clearToken($event);
                throw new AuthenticationException('The first-attempt gate could not determine the login outcome; the login is refused.', 0, $replacementFailure);
            }
        }
    }

    /**
     * The risk scope of the event's firewall: the request's
     * _firewall_context attribute (the framework stamps it before the
     * authenticator runs) minus the context-key prefix, translated
     * through the risk.login_scopes map. Null when the attribute is
     * absent or the firewall has no entry.
     */
    private function resolveScope(Request $request): ?string
    {
        $context = $request->attributes->get(self::FIREWALL_CONTEXT_ATTRIBUTE);
        if (!\is_string($context) || !str_starts_with($context, self::FIREWALL_CONTEXT_PREFIX)) {
            return null;
        }
        $firewall = substr($context, \strlen(self::FIREWALL_CONTEXT_PREFIX));

        return $this->loginScopes[$firewall] ?? null;
    }

    /** Count and log the unmapped skip; the token stays untouched. */
    private function skipUnmapped(?Request $request, string $reason): void
    {
        $this->counters?->increment(self::UNMAPPED_COUNTER);
        $this->logger?->debug('kiwi first-attempt gate skipped an unmapped firewall', [
            'firewall' => $request === null ? null : self::firewallNameOf($request),
            'reason' => $reason,
        ]);
    }

    /** The bare firewall name behind the request's context attribute. */
    private static function firewallNameOf(Request $request): ?string
    {
        $context = $request->attributes->get(self::FIREWALL_CONTEXT_ATTRIBUTE);
        if (!\is_string($context) || !str_starts_with($context, self::FIREWALL_CONTEXT_PREFIX)) {
            return null;
        }

        return substr($context, \strlen(self::FIREWALL_CONTEXT_PREFIX));
    }

    /** Withhold the session with a named reason (always logged). */
    private function withhold(object $event, object $token, string $scope, string $reason): void
    {
        $this->logger?->warning('kiwi first-attempt gate withholds the session', [
            'scope' => $scope,
            'reason' => $reason,
        ]);
        if ($token instanceof StepUpPendingToken) {
            return;
        }
        $this->replaceToken($event, $this->pendingToken($token, $scope));
    }

    /** The pending token, stamped with the scope the demand was raised under. */
    private function pendingToken(object $token, string $scope): StepUpPendingToken
    {
        $pending = new StepUpPendingToken($token);
        $pending->setAttribute(StepUpPendingToken::SCOPE_ATTRIBUTE, $scope);

        return $pending;
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
                    if (\is_object($badge) && (is_a($badge, self::PASSWORD_CREDENTIALS)
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

    /**
     * The best-effort token clear of the refused-login path: the event
     * is asked to drop its token so no later reader can resurrect the
     * authenticated state. A typed event whose setter refuses null
     * stays untouched (the call is swallowed): the AuthenticationException
     * the caller throws is the real refusal, and the framework answers
     * it on the failure path, never with a stored token.
     */
    private function clearToken(object $event): void
    {
        foreach (['setAuthenticatedToken', 'setToken'] as $method) {
            if (!method_exists($event, $method)) {
                continue;
            }
            try {
                $event->{$method}(null);
            } catch (\Throwable) {
                // The setter's own contract wins; the thrown
                // AuthenticationException carries the refusal.
            }

            return;
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

    /**
     * The submitted values of the resolved scope's configured target
     * fields, keyed by field name: the exact input shape the engine's
     * target resolver reads. The values come from the request's full
     * payload (form bodies and json_login bodies alike), so a JSON
     * login that omits the target field simply carries no target
     * dimension instead of silently losing it. Absent or empty fields
     * are left out, and a non-string value (an array or object under
     * the field name) is skipped: a malformed shape resolves no target
     * instead of throwing inside the guard.
     *
     * @return array<string, string>
     */
    private function targetFieldValues(Request $request, string $scope): array
    {
        // Nesting-aware: a Symfony form nests its data under the form
        // name, so a flat request-key read would miss every nested
        // submission. A non-scalar or ambiguous value resolves no
        // target instead of throwing inside the guard.
        return \BelConsulting\KiwiCaptchaBundle\Http\RequestFieldResolver::targetFields(
            $request,
            $this->targetFieldsByScope[$scope] ?? [],
        );
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
