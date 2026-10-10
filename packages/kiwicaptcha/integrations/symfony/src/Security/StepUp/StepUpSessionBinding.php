<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Security\StepUp;

use Symfony\Component\HttpFoundation\Request;

/**
 * The session binding of step-up completion: the completion of a
 * challenge is only ever accepted for the same principal that began it
 * AND under exactly one per-challenge binding. {@see \BelConsulting\KiwiCaptchaBundle\Controller\StepUpController::complete()}
 * re-resolves the principal of the current request and binds it (plus
 * the session id) here before dispatching to a handler. Every handler
 * then requires the bound principal and the challenge's own binding to
 * hold. A stolen ticket presented under another session is refused and
 * never completed. A principal-level success marker alone never
 * authorizes enrollment: that proof is session-scoped.
 *
 * Exactly one binding per challenge, both fail-closed:
 *
 * 1. Session binding (the normal browser case): a challenge begun with
 *    a started session records that session's hash and mints no client
 *    secret, only that session may complete it.
 * 2. Stateless binding (API / SPA): a challenge begun with no session
 *    mints a one-time client secret (returned once at begin, stored
 *    only as its SHA-256 hash), only a request presenting that secret
 *    may complete it.
 *
 * A request that carries no binding (a handler reached without the
 * controller) matches nothing: fail closed, never open.
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
     * bag when one is started; without a started session the binding
     * carries an empty session and a session-bound challenge matches
     * nothing (fail closed), only a stateless challenge may then be
     * completed, and only with its client secret.
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
}
