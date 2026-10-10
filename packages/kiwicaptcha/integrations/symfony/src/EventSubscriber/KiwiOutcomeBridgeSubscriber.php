<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\EventSubscriber;

use BelConsulting\KiwiCaptchaBundle\Risk\AuthOutcomeWindowInterface;
use BelConsulting\KiwiCaptchaBundle\Risk\ClientIpResolver;
use BelConsulting\KiwiCaptchaBundle\Risk\ContinuityCookie;
use BelConsulting\KiwiCaptchaBundle\Risk\MetricsCounterStore;
use BelConsulting\KiwiCaptchaBundle\Risk\OutcomeReporterInterface;
use BelConsulting\KiwiCaptchaBundle\Risk\OutcomeTrustGateInterface;
use BelConsulting\KiwiCaptchaBundle\Risk\TargetMarkKey;
use KiwiCaptcha\Risk\Network\NetworkClassifierInterface;
use KiwiCaptcha\Risk\Outcomes\Outcome;
use KiwiCaptcha\Risk\Outcomes\OutcomeHandle;
use KiwiCaptcha\Risk\ResourcePressure;
use KiwiCaptcha\Risk\RiskContext;
use KiwiCaptcha\Risk\RiskEventKind;
use KiwiCaptcha\Risk\RiskIdentityFactory;
use KiwiCaptcha\Risk\TargetIdentifierNormalizer;
use Psr\Log\LoggerInterface;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpFoundation\Request;

/**
 * The Symfony security auto-bridge of the outcomes plane: framework
 * auth events translated into the typed outcome vocabulary.
 *
 * LoginSuccessEvent reports authenticationSuccess on the principal
 * pseudonym. LoginFailureEvent and observable CheckPassportEvent errors
 * report authenticationFailure on the target pseudonym when the scope's
 * target field is configured. Otherwise they report it on the session
 * pseudonym when a continuity cookie exists, never on the raw claimed
 * identifier.
 *
 * The bridge must never break authentication: every listener body is a
 * try/catch that logs at debug and returns, so a reporting failure is a
 * missing risk signal, never a failed login. Raw identifiers never
 * reach a handle, a context or a counter. The principal is the
 * pseudonym the risk engine derives through RiskIdentityFactory, the
 * same derivation every engine context uses. The target is the
 * normalized identifier's keyed digest, and a handle whose shape the
 * outcomes API rejects is skipped with a debug log, never retried with
 * raw bytes.
 *
 * Idempotency key = HMAC(request id). The request's unique id is the
 * Request getRequestId of newer Symfony, the X-Request-Id header, or
 * the deterministic server fingerprint of time, address and port. It is
 * HMAC'd under a purpose-separated key derived like the bundle's other
 * HKDF derivations, {@see self::deriveIdempotencyKey()}. Replayed
 * events (the same request id) therefore book the same mapped event
 * exactly once through the engine's event-id dedupe, and the two
 * failure lanes of one request (a CheckPassport error followed by the
 * LoginFailureEvent) collapse onto one report.
 *
 * The success-trust rule: authenticationSuccess always credits the
 * principal; the session (and, inside the core's apply-feedback path,
 * the source) is credited only when {@see OutcomeTrustGateInterface}
 * allows it for this identity. The fail-closed default gate carries no
 * session on a success while the windowed failure ratio stays
 * unreadable; see the gate interface for the extension point.
 *
 * Registered by the extension only when the risk engine is on, the
 * outcomes surface exists, the security event classes exist (the
 * security bundle is optional for this bundle) and the outcomes scope
 * is configured; risk.outcomes.auto_bridge false removes the listener
 * entirely.
 */
final class KiwiOutcomeBridgeSubscriber implements EventSubscriberInterface
{
    /** The event names, as class strings: the classes stay unloaded when the security bundle is absent. */
    public const LOGIN_SUCCESS_EVENT = 'Symfony\Component\Security\Http\Event\LoginSuccessEvent';
    public const LOGIN_FAILURE_EVENT = 'Symfony\Component\Security\Http\Event\LoginFailureEvent';
    public const CHECK_PASSPORT_EVENT = 'Symfony\Component\Security\Http\Event\CheckPassportEvent';

    /** The passport badge class the CheckPassport lane reads (duck-typed, never autoloaded here). */
    private const USER_BADGE_CLASS = 'Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge';

    /**
     * The request attribute carrying the claimed identifier the
     * CheckPassport lane observed, handed to the LoginFailure lane of
     * the same request. The framework's own last-username attribute
     * ('_security.last_username') is the fallback.
     */
    private const TARGET_ATTRIBUTE = '_kiwi_outcome_target';

    /** The HKDF info of the purpose-separated idempotency key derivation. */
    private const IDEMPOTENCY_HKDF_INFO = 'kiwi/v5/outcome-bridge-idem';

    /** The shared deployment salt of the bundle's HKDF derivations. */
    private const HKDF_SALT = 'kiwicaptcha/deploy-salt/v1';

    /** The CheckPassport lane runs before the framework's checkers so it observes the resolution error first. */
    private const CHECK_PASSPORT_PRIORITY = 1024;

    private readonly string $idempotencyKey;

    public function __construct(
        private readonly OutcomeReporterInterface $reporter,
        private readonly RiskIdentityFactory $identityFactory,
        private readonly int $scopeId,
        string $idempotencyMaster,
        private readonly ?NetworkClassifierInterface $classifier = null,
        private readonly ?ContinuityCookie $continuityCookie = null,
        private readonly ?ClientIpResolver $clientIpResolver = null,
        private readonly bool $targetFieldConfigured = false,
        private readonly ?OutcomeTrustGateInterface $trustGate = null,
        private readonly ?MetricsCounterStore $counters = null,
        private readonly ?LoggerInterface $logger = null,
        private readonly bool $trustRequestIdHeader = false,
        private readonly ?AuthOutcomeWindowInterface $authWindow = null,
    ) {
        $this->idempotencyKey = self::deriveIdempotencyKey($idempotencyMaster);
    }

    /**
     * @return array<string, list<string>|string>
     */
    public static function getSubscribedEvents(): array
    {
        return [
            self::LOGIN_SUCCESS_EVENT => 'onLoginSuccess',
            self::LOGIN_FAILURE_EVENT => 'onLoginFailure',
            self::CHECK_PASSPORT_EVENT => ['onCheckPassport', self::CHECK_PASSPORT_PRIORITY],
        ];
    }

    /**
     * The purpose-separated idempotency key derivation, mirroring the
     * bundle's other HKDF derivations (for example the scope-rate key):
     * hash_hkdf over the deployment master with this bridge's own info
     * string, so the idempotency HMAC never shares key material with
     * any other purpose.
     */
    public static function deriveIdempotencyKey(string $master): string
    {
        return hash_hkdf('sha256', $master, 32, self::IDEMPOTENCY_HKDF_INFO, self::HKDF_SALT);
    }

    /**
     * authenticationSuccess on the principal pseudonym. The session
     * rides the report context only when the trust gate allows session
     * and source credit for this identity.
     */
    public function onLoginSuccess(object $event): void
    {
        try {
            $request = $this->requestOf($event);
            $identifier = $this->authenticatedIdentifier($event);
            if ($identifier === null) {
                $this->countSkip('no_principal');

                return;
            }
            $principalPseudonym = $this->identityFactory->principalId($identifier);
            $handle = $this->principalHandle($principalPseudonym);
            if ($handle === null) {
                return;
            }
            $targetPseudonym = $this->targetPseudonymOf($request);
            $sessionRaw = $request !== null && $this->continuityCookie !== null
                ? $this->continuityCookie->read($request)
                : null;
            $sessionPseudonym = $sessionRaw !== null ? $this->identityFactory->sessionId($sessionRaw) : null;
            // Evaluate the gate before recording this success: a
            // record-then-check order hands every fresh session a clean
            // ratio and lets a stuffer mint session/source trust on
            // every stolen login. The gate reads the same normalized
            // window key the writes use (never the un-normalized
            // principalId), so the lanes cannot diverge.
            $windowKey = $this->principalWindowKey($identifier) ?? $principalPseudonym;
            $credit = $this->trustGate?->allowsSessionSourceCredit($windowKey, $sessionPseudonym, $targetPseudonym) === true;
            if ($sessionPseudonym !== null) {
                $this->authWindow?->recordSuccess($sessionPseudonym);
            }
            if ($this->authWindow !== null) {
                // The principal window accumulates across sessions so a
                // cross-session stuffer cannot reset the ratio.
                $this->authWindow->recordSuccess($windowKey);
            }
            if ($credit) {
                // keep $sessionRaw: the gate approved session/source credit
            } else {
                $sessionRaw = null;
            }
            $context = $this->context(RiskEventKind::AuthenticationSuccess, $request, $sessionRaw);
            $this->report(Outcome::AuthenticationSuccess, $handle, $this->idempotencyKeyOf($request), $context);
        } catch (\Throwable $e) {
            $this->fail($e, 'login success');
        }
    }

    /**
     * authenticationFailure. The target pseudonym carries the report
     * when the scope's target field is configured; otherwise the
     * session pseudonym does when a continuity cookie exists. A failure
     * with no attributable identity handle is skipped with a debug log
     * (the raw claimed identifier is never a handle).
     */
    public function onLoginFailure(object $event): void
    {
        try {
            $request = $this->requestOf($event);
            $username = $this->claimedIdentifier($request);
            $sessionRaw = $this->sessionRaw($request);
            if ($sessionRaw !== null) {
                $this->authWindow?->recordFailure($this->identityFactory->sessionId($sessionRaw));
            }
            if ($username !== null && $username !== '') {
                $windowKey = $this->principalWindowKey($username);
                if ($windowKey !== null) {
                    $this->authWindow?->recordFailure($windowKey);
                }
            }
            $context = $this->context(RiskEventKind::AuthenticationFailure, $request, $sessionRaw);
            $idempotencyKey = $this->idempotencyKeyOf($request);

            if ($this->targetFieldConfigured && $username !== null) {
                $handle = $this->targetHandle($username);
                if ($handle !== null) {
                    $this->report(Outcome::AuthenticationFailure, $handle, $idempotencyKey, $context);
                }

                return;
            }
            $handle = $this->sessionHandle($request);
            if ($handle !== null) {
                $this->report(Outcome::AuthenticationFailure, $handle, $idempotencyKey, $context);

                return;
            }
            $this->countSkip('no_attributable_handle');
        } catch (\Throwable $e) {
            $this->fail($e, 'login failure');
        }
    }

    /**
     * The CheckPassport lane: it observes the claimed identifier for
     * the request's later failure lane, and it reports
     * authenticationFailure when the passport's user badge resolution
     * errors. The probe is swallowed, so the framework's own error
     * handling is unchanged and the LoginFailure lane of the same
     * request dedupes onto the same report.
     */
    public function onCheckPassport(object $event): void
    {
        try {
            $request = $this->requestOf($event);
            $identifier = $this->passportBadgeIdentifier($event);
            if ($identifier !== null && $request !== null) {
                $request->attributes->set(self::TARGET_ATTRIBUTE, $identifier);
            }
            if (!$this->passportBadgeResolves($event)) {
                $username = $identifier;
                $sessionRaw = $this->sessionRaw($request);
                if ($sessionRaw !== null) {
                    $this->authWindow?->recordFailure($this->identityFactory->sessionId($sessionRaw));
                }
                $context = $this->context(RiskEventKind::AuthenticationFailure, $request, $sessionRaw);
                $handle = $username !== null && $this->targetFieldConfigured
                    ? $this->targetHandle($username)
                    : $this->sessionHandle($request);
                if ($handle !== null) {
                    $this->report(Outcome::AuthenticationFailure, $handle, $this->idempotencyKeyOf($request), $context);
                } else {
                    $this->countSkip('no_attributable_handle');
                }
            }
        } catch (\Throwable $e) {
            $this->fail($e, 'check passport');
        }
    }

    /**
     * The principal handle: the pseudonym is always the engine's own
     * 128-bit derivation, and a construction rejection is a skip, never
     * a raw-identifier retry.
     */
    private function principalHandle(string $pseudonym): ?OutcomeHandle
    {
        try {
            return OutcomeHandle::principal($pseudonym);
        } catch (\Throwable $e) {
            $this->debug('principal handle rejected the pseudonym shape: {reason}', ['reason' => $e->getMessage()]);
            $this->countSkip('raw_identifier_rejected');

            return null;
        }
    }

    /**
     * The target handle. The engine derives the full 32-byte digest of
     * the normalized identifier (the canonical 64-hex target
     * pseudonym). The outcomes API addresses target marks under the
     * 128-bit handle spelling, so the one projection lives in
     * {@see TargetMarkKey::of()}. Never a try-both fallback here.
     * Authentication outcomes write no target marks of their own, so
     * the projection cannot split a mark key; anything else is a skip
     * with a debug log.
     */
    private function targetHandle(string $rawUsername): ?OutcomeHandle
    {
        $digest = $this->targetPseudonymOfRaw($rawUsername);
        if ($digest === null) {
            $this->countSkip('no_attributable_handle');

            return null;
        }
        try {
            return OutcomeHandle::target(TargetMarkKey::of($digest));
        } catch (\Throwable) {
            // The projection refused a non-canonical digest (or the
            // handle gate refused the derived key): the report is
            // skipped, never sent under a raw identifier.
        }
        $this->debug('target handle rejected the derived pseudonym shape; the report is skipped, never raw');
        $this->countSkip('raw_identifier_rejected');

        return null;
    }

    /**
     * The session handle: the continuity cookie's validated value is
     * pseudonymized by the same derivation every engine context uses.
     */
    private function sessionHandle(?Request $request): ?OutcomeHandle
    {
        $sessionRaw = $this->sessionRaw($request);
        if ($sessionRaw === null) {
            return null;
        }
        try {
            return OutcomeHandle::session($this->identityFactory->sessionId($sessionRaw));
        } catch (\Throwable) {
            return null;
        }
    }

    /**
     * The report context of one lane: the configured scope, the
     * canonical client IP, the (gate-gated) session raw value and no
     * principal (a failure asserts no authenticated principal, and a
     * success's principal rides the handle pseudonym). Null when the
     * request or its IP cannot anchor an observation.
     */
    private function context(RiskEventKind $event, ?Request $request, ?string $sessionRaw): ?RiskContext
    {
        if ($request === null || $this->clientIpResolver === null) {
            return null;
        }
        $ip = $this->clientIpResolver->resolve($request);
        if ($ip === '' || filter_var($ip, FILTER_VALIDATE_IP) === false) {
            return null;
        }

        return new RiskContext(
            scope: $this->scopeId,
            sourceIp: $ip,
            sessionId: $sessionRaw,
            principalId: null,
            event: $event,
            networkFlags: $this->classifier?->classify($ip) ?? new \KiwiCaptcha\Risk\Network\NetworkFlags(),
            resources: new ResourcePressure(1000, 1000),
        );
    }

    /**
     * One typed report through the seam, with the outcome counter and
     * the never-break guarantee: a throwing reporter is logged at
     * debug and the listener returns normally.
     */
    private function report(Outcome $outcome, OutcomeHandle $handle, ?string $idempotencyKey, ?RiskContext $context): void
    {
        try {
            $this->reporter->report($outcome, $handle, $idempotencyKey, $context);
            $this->counters?->increment('outcome_reports:'.$outcome->value);
        } catch (\Throwable $e) {
            $this->debug('outcome report failed (authentication continues): {reason}', ['reason' => $e->getMessage()]);
            $this->countSkip('report_failed');
        }
    }

    /**
     * The idempotency key: HMAC of the request id under the derived
     * purpose key. A request with no derivable id material books with a
     * null key (the engine then mints a fresh event id); the security
     * events always carry a request, so the lane is a defensive one.
     */
    private function idempotencyKeyOf(?Request $request): ?string
    {
        $requestId = $this->requestId($request);
        if ($requestId === null) {
            return null;
        }

        return hash_hmac('sha256', $requestId, $this->idempotencyKey);
    }

    /**
     * The request's unique id, derived server-side: Request::getRequestId()
     * on newer Symfony, or the fingerprint of the request's server
     * material (time, address, port). The client-controlled X-Request-Id
     * header is consulted only when the deployment declares a fronting
     * edge that overwrites it (risk.outcomes.trust_request_id_header);
     * otherwise a caller could replay one header value across attempts
     * and collapse every failure into one deduplicated event. The
     * fingerprint distinguishes distinct connections while collapsing
     * in-process replays of one request.
     */
    private function requestId(?Request $request): ?string
    {
        if ($request === null) {
            return null;
        }
        if (method_exists($request, 'getRequestId')) {
            $id = $request->getRequestId();
            if (\is_string($id) && $id !== '') {
                return $id;
            }
        }
        if ($this->trustRequestIdHeader) {
            $header = $request->headers->get('X-Request-Id');
            if (\is_string($header) && preg_match('/^[A-Za-z0-9._:-]{1,128}$/D', $header) === 1) {
                return $header;
            }
        }
        $parts = [
            $request->server->get('REQUEST_TIME_FLOAT'),
            $request->server->get('REMOTE_ADDR'),
            $request->server->get('REMOTE_PORT'),
        ];
        $fingerprint = implode('|', array_filter($parts, static fn (mixed $p): bool => $p !== null && $p !== ''));
        if ($fingerprint === '' || $fingerprint === '|') {
            return null;
        }

        return $fingerprint;
    }

    /**
     * The authenticated principal's raw identifier (the app-supplied
     * user identifier of the event's user or token), the exact value
     * whose engine pseudonymization every risk context already uses.
     */
    private function authenticatedIdentifier(object $event): ?string
    {
        $user = null;
        if (method_exists($event, 'getUser')) {
            $user = $event->getUser();
        } elseif (method_exists($event, 'getToken')) {
            $token = $event->getToken();
            $user = \is_object($token) && method_exists($token, 'getUser') ? $token->getUser() : null;
        }
        if (!\is_object($user) || !method_exists($user, 'getUserIdentifier')) {
            return null;
        }
        $identifier = $user->getUserIdentifier();
        if (!\is_string($identifier) || $identifier === '') {
            return null;
        }

        return $identifier;
    }

    /**
     * The claimed identifier of a failure: the CheckPassport lane's
     * observation of the same request first, the framework's
     * last-username attribute second.
     */
    private function claimedIdentifier(?Request $request): ?string
    {
        if ($request === null) {
            return null;
        }
        foreach ([self::TARGET_ATTRIBUTE, '_security.last_username'] as $attribute) {
            $value = $request->attributes->get($attribute);
            if (\is_string($value) && $value !== '') {
                return $value;
            }
        }

        return null;
    }

    /**
     * The passport badge identifier of a CheckPassport event, or null
     * when the event exposes no passport or no user badge.
     */
    private function passportBadgeIdentifier(object $event): ?string
    {
        $badge = $this->passportBadge($event);
        if ($badge === null || !method_exists($badge, 'getUserIdentifier')) {
            return null;
        }
        $identifier = $badge->getUserIdentifier();
        if (!\is_string($identifier) || $identifier === '') {
            return null;
        }

        return $identifier;
    }

    /**
     * True when the passport's user badge resolves its user without
     * error (an absent badge resolves vacuously: the passport carries
     * no user lane to observe).
     */
    private function passportBadgeResolves(object $event): bool
    {
        $badge = $this->passportBadge($event);
        if ($badge === null || !method_exists($badge, 'getUser')) {
            return true;
        }
        try {
            $badge->getUser();
        } catch (\Throwable) {
            return false;
        }

        return true;
    }

    /**
     * The passport's user badge, read duck-typed (the badge class is a
     * security-bundle class that stays unloaded when the bundle is
     * absent).
     */
    private function passportBadge(object $event): ?object
    {
        if (!method_exists($event, 'getPassport')) {
            return null;
        }
        $passport = $event->getPassport();
        if (!\is_object($passport) || !method_exists($passport, 'getBadge')) {
            return null;
        }
        $badge = $passport->getBadge(self::USER_BADGE_CLASS);

        return \is_object($badge) ? $badge : null;
    }

    /**
     * The target pseudonym of the request's claimed identifier (the
     * trust gate's spread input); null when none is derivable.
     */
    /**
     * The window key of an identity: the normalized target pseudonym
     * under the principal purpose. Both the success and the failure
     * lanes key on this, so the login field and the user identifier
     * never diverge into two windows.
     */
    private function principalWindowKey(string $raw): ?string
    {
        try {
            $normalized = TargetIdentifierNormalizer::normalize($raw);

            return $this->identityFactory->principalId($normalized);
        } catch (\Throwable) {
            return null;
        }
    }

    private function targetPseudonymOf(?Request $request): ?string
    {
        $username = $this->claimedIdentifier($request);

        return $username === null ? null : $this->targetPseudonymOfRaw($username);
    }

    /**
     * The keyed digest of a raw claimed identifier: the versioned
     * normalization pipeline then the engine's target derivation. The
     * normalized value never leaves this boundary.
     */
    private function targetPseudonymOfRaw(string $raw): ?string
    {
        try {
            $normalized = TargetIdentifierNormalizer::normalize($raw);
        } catch (\Throwable) {
            return null;
        }
        if ($normalized === '') {
            return null;
        }

        return $this->identityFactory->targetId($normalized);
    }

    /**
     * The validated continuity cookie value of the request (the raw
     * 16-byte session identity the engine pseudonymizes itself).
     */
    private function sessionRaw(?Request $request): ?string
    {
        if ($request === null || $this->continuityCookie === null) {
            return null;
        }

        return $this->continuityCookie->read($request);
    }

    private function requestOf(object $event): ?Request
    {
        if (!method_exists($event, 'getRequest')) {
            return null;
        }
        $request = $event->getRequest();

        return $request instanceof Request ? $request : null;
    }

    private function countSkip(string $reason): void
    {
        $this->counters?->increment('outcome_skips:'.$reason);
    }

    private function debug(string $message, array $context = []): void
    {
        $this->logger?->debug('KiwiCaptcha outcome bridge: '.$message, $context);
    }

    /**
     * The never-break lane of every listener: the exception is logged
     * at debug with the lane's name and the authentication flow
     * continues untouched.
     */
    private function fail(\Throwable $e, string $lane): void
    {
        $this->debug('the {lane} lane skipped its report (authentication continues): {reason}', [
            'lane' => $lane,
            'reason' => $e->getMessage(),
        ]);
        $this->countSkip('listener_failed');
    }
}
