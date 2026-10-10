<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests;

use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpBootstrapGate;
use KiwiCaptcha\Risk\RiskIdentityFactory;
use KiwiCaptcha\Risk\RiskKeys;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;

/**
 * The first-factor bootstrap gate (finding 5): a single-use,
 * session-scoped grant bound to the principal the application verified
 * out of band. Never a bare request attribute — anyone can set one of
 * those. The marker is consumed on the first matching enrollment; a
 * wrong principal or a replay answers false.
 */
final class StepUpBootstrapGateTest extends TestCase
{
    private const PRINCIPAL = '00112233445566778899aabbccddeeff';
    private const RAW_IDENTIFIER = 'user@example.com';

    private function identity(): RiskIdentityFactory
    {
        return new RiskIdentityFactory(RiskKeys::fromMaster(str_repeat("\x42", 32)));
    }

    private function gate(): StepUpBootstrapGate
    {
        return new StepUpBootstrapGate(true, null, $this->identity());
    }

    /** The engine pseudonym of the raw identifier (the spelling the handlers carry). */
    private function pseudonym(): string
    {
        return $this->identity()->principalId(self::RAW_IDENTIFIER);
    }

    public function testTheGrantIsSingleUseAndSessionScoped(): void
    {
        $gate = $this->gate();
        $request = $this->request('grant-session-00000000000000001');
        $gate->grant($request, self::RAW_IDENTIFIER);

        self::assertTrue($gate->allowsFirstEnrollment($request, $this->pseudonym()), 'the granted session may enroll');
        self::assertFalse($gate->allowsFirstEnrollment($request, $this->pseudonym()), 'the grant is one-time: a second attempt is refused');

        // Another session of the same principal: never (session-scoped).
        $other = $this->request('grant-session-00000000000000002');
        self::assertFalse($gate->allowsFirstEnrollment($other, $this->pseudonym()));
    }

    public function testTheGrantIsBoundToThePrincipal(): void
    {
        $gate = $this->gate();
        $request = $this->request('grant-session-00000000000000001');
        $gate->grant($request, self::RAW_IDENTIFIER);

        self::assertFalse(
            $gate->allowsFirstEnrollment($request, 'ffeeddccbbaa99887766554433221100'),
            'a grant for one principal never authorizes another',
        );
        // The refusal does not consume the grant: the right principal
        // can still use it.
        self::assertTrue($gate->allowsFirstEnrollment($request, $this->pseudonym()));
    }

    /**
     * The old free-form marker (a request attribute anyone could set)
     * is never accepted, with or without a grant().
     */
    public function testABareRequestAttributeIsNeverAccepted(): void
    {
        $gate = new StepUpBootstrapGate(true);
        $request = $this->request('grant-session-00000000000000001');
        $request->attributes->set('_kiwi_signup_bootstrap', true);

        self::assertFalse($gate->allowsFirstEnrollment($request, self::PRINCIPAL));
    }

    public function testADisabledGateGrantsAndAllowsNothing(): void
    {
        $gate = new StepUpBootstrapGate(false);
        $request = $this->request('grant-session-00000000000000001');
        $gate->grant($request, self::PRINCIPAL);

        self::assertFalse($gate->allowsFirstEnrollment($request, self::PRINCIPAL));
    }

    public function testAGrantWithoutASessionSticksToNothing(): void
    {
        $gate = new StepUpBootstrapGate(true);
        $request = Request::create('https://example.com/signup');
        $gate->grant($request, self::PRINCIPAL);

        self::assertFalse($gate->allowsFirstEnrollment($request, self::PRINCIPAL));
    }

    public function testAnUngrantedOrUnstatedPrincipalIsRefused(): void
    {
        $gate = new StepUpBootstrapGate(true);
        $request = $this->request('grant-session-00000000000000001');
        $gate->grant($request, self::PRINCIPAL);

        self::assertFalse($gate->allowsFirstEnrollment($request), 'no principal presented: refused');
        self::assertFalse($gate->allowsFirstEnrollment($request, ''), 'an empty principal presented: refused');
    }

    private function request(string $sessionId): Request
    {
        $request = Request::create('https://example.com/signup', 'POST');
        $storage = new \Symfony\Component\HttpFoundation\Session\Storage\MockArraySessionStorage();
        $storage->setId($sessionId);
        $session = new \Symfony\Component\HttpFoundation\Session\Session($storage);
        $session->start();
        $request->setSession($session);

        return $request;
    }

    public function testTheRawIdentifierAndThePseudonymMayDiffer(): void
    {
        // The bug class: grant() takes the raw identifier (an email the
        // signup flow verified), while the enrollment path carries the
        // engine's 32-hex pseudonym. The gate pseudonymizes internally
        // so the two spellings can never disagree.
        $gate = $this->gate();
        $request = $this->request('grant-session-00000000000000003');
        $gate->grant($request, self::RAW_IDENTIFIER);
        $pseudonym = $this->pseudonym();
        self::assertNotSame(self::RAW_IDENTIFIER, $pseudonym, 'the test premise: raw and pseudonym differ');
        self::assertTrue(
            $gate->allowsFirstEnrollment($request, $pseudonym),
            'grant(raw) must authorize the matching pseudonym',
        );
    }

    public function testTheGrantExpiresAfterFifteenMinutes(): void
    {
        $gate = $this->gate();
        $request = $this->request('grant-session-00000000000000004');
        $gate->grant($request, self::RAW_IDENTIFIER);
        // Age the grant past the TTL.
        $session = $request->getSession();
        $grant = $session->get('_kiwi_signup_bootstrap_grant');
        $grant['expires'] = time() - 1;
        $session->set('_kiwi_signup_bootstrap_grant', $grant);
        self::assertFalse($gate->allowsFirstEnrollment($request, $this->pseudonym()), 'an expired grant is refused');
    }
}
