<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Security\StepUp;

use Symfony\Component\HttpFoundation\Request;

/**
 * The session binding of step-up completion. The completion of a
 * challenge is only accepted for the same principal that began it.
 * It is also bound to the same PHP session. The controller
 * re-resolves the principal and binds it before dispatching. Every
 * handler requires the bound principal and session to match. A stolen
 * ticket from another session is refused. A request with no binding
 * matches nothing. That is fail closed.
 */
final class StepUpSessionBinding
{
    /** The request attribute carrying the resolved principal pseudonym. */
    public const ATTRIBUTE = '_kiwi_step_up_principal';

    /** The request attribute carrying the session id of this request. */
    public const SESSION_ATTRIBUTE = '_kiwi_step_up_session';

    /** The POST field a stateless client carries the per-challenge secret in. */
    public const CLIENT_SECRET_FIELD = 'kiwi_step_up_client_secret';

    private function __construct()
    {
    }

    /**
     * Bind the resolved principal pseudonym and the current session id
     * onto the request. The session id is read from the Symfony session
     * bag when one is started. Without a started session the binding
     * carries an empty session. A session-bound challenge then matches
     * nothing. That is fail closed. Only a stateless challenge may then
     * be completed. It must present its client secret.
     */
    public static function bind(Request $request, string $principalPseudonym): void
    {
        $request->attributes->set(self::ATTRIBUTE, $principalPseudonym);
        $request->attributes->set(self::SESSION_ATTRIBUTE, self::sessionId($request));
    }

    /**
     * The session id of the request: the started Symfony session's id,
     * else the empty string. Never a client-supplied header.
     */
    public static function sessionId(Request $request): string
    {
        $session = $request->hasSession() ? $request->getSession() : null;
        if ($session === null || !$session->isStarted()) {
            return '';
        }

        return (string) $session->getId();
    }

    /**
     * Whether the request's bound principal and session match the
     * challenge. Absent or malformed bindings do not match. The
     * challenge's own recorded session hash is the authority: a
     * completion presented under a different session than the one that
     * began the challenge is refused, even for the same principal
     * (cross-session ticket replay / session fixation).
     *
     * Exactly one binding per challenge, both fail-closed:
     *
     * 1. Session binding (the normal browser case): the challenge was
     *    begun with a started session, records that session's hash, and
     *    only that session may complete it. A presented client secret
     *    is meaningless here, the challenge never minted one.
     * 2. Stateless binding (API / SPA): the challenge was begun with no
     *    session, mints a one-time client secret (returned once at
     *    begin, stored only as a SHA-256 hash), and only a request
     *    presenting that secret may complete it.
     */
    public static function matches(Request $request, StepUpChallenge $challenge): bool
    {
        $bound = $request->attributes->get(self::ATTRIBUTE);
        if (!\is_string($bound) || $bound === '') {
            return false;
        }
        if (!hash_equals($challenge->principalPseudonym, $bound)) {
            return false;
        }
        // Session-bound challenge: only the recorded session may
        // complete it. A client secret is not minted for these, so a
        // stolen ticket from one session can never be finished in
        // another (the whole point of the session binding).
        $requestSession = self::sessionId($request);
        $boundHash = $challenge->sessionHash;
        if ($boundHash !== null && $boundHash !== '') {
            if ($requestSession === '') {
                return false;
            }
            $requestHash = StepUpChallenge::sessionHash($requestSession);

            return $requestHash !== null && hash_equals($boundHash, $requestHash);
        }
        // Stateless challenge: the per-challenge client secret, compared
        // against the stored hash (never a plaintext secret).
        if ($challenge->clientSecretHash !== null && $challenge->clientSecretHash !== '') {
            $presented = (string) $request->request->get(self::CLIENT_SECRET_FIELD, '');

            return $presented !== '' && $challenge->clientSecretMatches($presented);
        }

        return false;
    }

    /**
     * The presented binding hash of a completion: the SHA-256 of the
     * bound session id for a session-bound challenge, of the presented
     * client secret for a stateless one. This is the material the
     * store's atomic factor completion compares against the stored
     * hashes, so the binding check runs inside the script and never
     * from a caller's word. Null when the request presents nothing the
     * challenge could be bound to, fail closed.
     */
    public static function presentedBindingHash(Request $request, StepUpChallenge $challenge): ?string
    {
        if ($challenge->sessionHash !== null && $challenge->sessionHash !== '') {
            $requestSession = self::sessionId($request);
            if ($requestSession === '') {
                return null;
            }

            return StepUpChallenge::sessionHash($requestSession);
        }
        if ($challenge->clientSecretHash !== null && $challenge->clientSecretHash !== '') {
            $presented = (string) $request->request->get(self::CLIENT_SECRET_FIELD, '');

            return $presented === '' ? null : StepUpChallenge::clientSecretHash($presented);
        }

        return null;
    }
}
