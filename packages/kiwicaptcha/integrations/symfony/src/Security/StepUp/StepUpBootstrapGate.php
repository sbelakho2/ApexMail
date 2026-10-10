<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Security\StepUp;

use KiwiCaptcha\Risk\RiskIdentityFactory;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\RequestStack;

/**
 * The first-factor bootstrap gate. Applications without email OTP have
 * no prior factor to complete a step-up with. A first enrollment would
 * then be a dead end. When enabled, a freshly verified signup or
 * recovery session may enroll a first factor.
 *
 * The grant is never a request attribute (any client could set one).
 * The application calls {@see self::grant()} with the RAW identifier
 * (email, username) it verified out of band; the gate pseudonymizes it
 * internally, so the enrollment path's 32-hex principal pseudonym and
 * the application's raw spelling can never disagree (the same class of
 * bug that broke the session restorer). The grant is single-use,
 * session-scoped, bound to that principal, and expires after
 * {@see self::TTL_SECS}. The gate is off by default; the doctor warns
 * when step-up is enabled without either email OTP or this bootstrap.
 */
final class StepUpBootstrapGate
{
    /** The session key of the single-use, principal-bound grant. */
    private const SESSION_KEY = '_kiwi_signup_bootstrap_grant';

    /** The grant lifetime: a signup/recovery window, not a session-long permission. */
    public const TTL_SECS = 900;

    public function __construct(
        private readonly bool $enabled = false,
        private readonly ?RequestStack $requestStack = null,
        private readonly ?RiskIdentityFactory $identityFactory = null,
    ) {
    }

    /**
     * Grant a one-time first-enrollment bootstrap to the session of
     * this request, bound to the given principal. $rawIdentifier is the
     * RAW user identifier (email, username) the signup/recovery flow
     * verified out of band; the gate pseudonymizes it internally so the
     * enrollment path and the grant can never disagree on the spelling.
     * A disabled gate or a request without a session grants nothing
     * (fail closed).
     */
    public function grant(Request $request, string $rawIdentifier): void
    {
        if (!$this->enabled || $rawIdentifier === '') {
            return;
        }
        $session = $request->hasSession() ? $request->getSession() : null;
        if ($session === null) {
            return;
        }
        $pseudonym = $this->pseudonymize($rawIdentifier);
        if ($pseudonym === null) {
            return;
        }
        $session->set(self::SESSION_KEY, [
            'principal' => hash('sha256', $pseudonym),
            'expires' => time() + self::TTL_SECS,
        ]);
    }

    /**
     * Whether this request may proceed to a first factor enrollment.
     * $principalPseudonym is the engine's 32-hex principal pseudonym
     * (the spelling the handlers carry). The gate pseudonymizes nothing
     * here, it compares against the already-pseudonymized grant.
     * Consumes the session's grant on success (single-use); a missing
     * or expired grant, a disabled gate, or a principal other than the
     * granted one answers false and leaves the marker for the principal
     * it was granted to.
     */
    public function allowsFirstEnrollment(?Request $request = null, ?string $principalPseudonym = null): bool
    {
        if (!$this->enabled) {
            return false;
        }
        $request ??= $this->requestStack?->getCurrentRequest();
        if ($request === null || $principalPseudonym === null || $principalPseudonym === '') {
            return false;
        }
        $session = $request->hasSession() ? $request->getSession() : null;
        if ($session === null) {
            return false;
        }
        $grant = $session->get(self::SESSION_KEY);
        if (!\is_array($grant) || !\is_string($grant['principal'] ?? null)) {
            return false;
        }
        if ((int) ($grant['expires'] ?? 0) < time()) {
            $session->remove(self::SESSION_KEY);

            return false;
        }
        if (!hash_equals($grant['principal'], hash('sha256', $principalPseudonym))) {
            return false;
        }
        $session->remove(self::SESSION_KEY);

        return true;
    }

    /**
     * The engine pseudonym of a raw identifier. Returns null when the
     * identity factory is not wired (fail closed, no grant is minted).
     */
    private function pseudonymize(string $rawIdentifier): ?string
    {
        if ($this->identityFactory === null) {
            return null;
        }
        try {
            return $this->identityFactory->principalId($rawIdentifier);
        } catch (\Throwable) {
            return null;
        }
    }
}
