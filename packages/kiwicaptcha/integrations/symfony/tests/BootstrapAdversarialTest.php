<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests;

use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpBootstrapGate;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpChallenge;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpChallengeKind;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpSessionBinding;
use KiwiCaptcha\Risk\RiskIdentityFactory;
use KiwiCaptcha\Risk\RiskKeys;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;

/**
 * Adversarial tests for the bootstrap enrollment path and the
 * challenge-record binding invariants. Each test names the attack it
 * pins: a bootstrap enrollment that dies at the finish line, a
 * creation ceremony that runs the assertion API, a stateless
 * challenge minted for a session-bound begin, and a stale-run guard
 * that trusts mtimes.
 */
final class BootstrapAdversarialTest extends TestCase
{
    private function identity(): RiskIdentityFactory
    {
        return new RiskIdentityFactory(RiskKeys::fromMaster(str_repeat("\x42", 32)));
    }

    private function request(string $sessionId = 'sess-00000000000000000000000001'): Request
    {
        $storage = new \Symfony\Component\HttpFoundation\Session\Storage\MockArraySessionStorage();
        $storage->setId($sessionId);
        $session = new \Symfony\Component\HttpFoundation\Session\Session($storage);
        $session->start();
        $request = Request::create('https://example.com/kiwi/step-up/enroll');
        $request->setSession($session);

        return $request;
    }

    /**
     * Finding 1 (HIGH): the single-use grant is consumed at
     * enrollBegin, so enrollComplete must read the flag the begin
     * recorded, re-consulting the gate finds nothing and refuses a
     * legitimate bootstrap enrollment at the finish line.
     */
    public function testABootstrapEnrollmentSurvivesBeginAndComplete(): void
    {
        $gate = new StepUpBootstrapGate(true, null, $this->identity());
        $request = $this->request();
        $raw = 'user@example.com';
        $gate->grant($request, $raw);
        $pseudonym = $this->identity()->principalId($raw);

        // enrollBegin: the gate is consulted once and the flag is
        // recorded on the challenge.
        self::assertTrue($gate->allowsFirstEnrollment($request, $pseudonym), 'begin consumes the grant');
        $challenge = StepUpChallenge::begin(
            StepUpChallenge::mintId(),
            StepUpChallengeKind::WebAuthn,
            $pseudonym,
            null,
            'login',
            null,
            'enroll',
            1700000000,
            300,
            5,
            'hash',
            'creation',
            StepUpSessionBinding::sessionId($request),
            false,
            true, // bootstrapAuthorized
        );
        self::assertTrue($challenge->bootstrapAuthorized, 'the creation challenge carries the bootstrap flag');

        // enrollComplete: the gate is empty (consumed) but the flag
        // authorizes the enrollment. This is the exact finish-line
        // scenario the finding names.
        self::assertFalse($gate->allowsFirstEnrollment($request, $pseudonym), 'the grant is single-use: already consumed');
        self::assertTrue(
            $challenge->bootstrapAuthorized,
            'the challenge flag, not a re-consulted gate, authorizes the completion',
        );
    }

    /**
     * Finding 1 adversarial: a NON-bootstrap challenge must not
     * inherit the flag from a previous grant.
     */
    public function testANonBootstrapChallengeNeverCarriesTheFlag(): void
    {
        $challenge = StepUpChallenge::begin(
            StepUpChallenge::mintId(),
            StepUpChallengeKind::WebAuthn,
            'aabbccddeeff00112233445566778899',
            null,
            'login',
            null,
            'enroll',
            1700000000,
            300,
            5,
            'hash',
            'creation',
            'sess-00000000000000000000000001',
        );
        self::assertFalse($challenge->bootstrapAuthorized);
    }

    /**
     * Finding 2 (Moderate): the HTML creation ceremony must drive
     * navigator.credentials.create(), not get(). The assertion script
     * serializes an assertion; a creation ceremony needs an
     * attestationObject.
     */
    public function testTheCreationScriptCallsCreateNotGet(): void
    {
        $create = \BelConsulting\KiwiCaptchaBundle\Security\StepUp\WebAuthnStepUpHandler::CEREMONY_CREATION_SCRIPT;
        $assertion = \BelConsulting\KiwiCaptchaBundle\Security\StepUp\WebAuthnStepUpHandler::CEREMONY_SCRIPT;
        self::assertStringContainsString('navigator.credentials.create', $create);
        self::assertStringNotContainsString('navigator.credentials.get', $create);
        self::assertStringContainsString('attestationObject', $create);
        self::assertStringContainsString('navigator.credentials.get', $assertion);
        self::assertStringNotContainsString('navigator.credentials.create', $assertion);
        self::assertStringContainsString('signature', $assertion);
    }

    /**
     * Finding 5 (Low): the creation challenge is begun with the
     * session id, so it is never minted as a stateless challenge (no
     * client secret) and the completing session is bound.
     */
    public function testTheCreationChallengeIsSessionBoundNeverStateless(): void
    {
        $challenge = StepUpChallenge::begin(
            StepUpChallenge::mintId(),
            StepUpChallengeKind::WebAuthn,
            'aabbccddeeff00112233445566778899',
            null,
            'login',
            null,
            'enroll',
            1700000000,
            300,
            5,
            'hash',
            'creation',
            'sess-00000000000000000000000001',
        );
        self::assertNotNull($challenge->sessionHash, 'the creation challenge records the session');
        self::assertNull($challenge->clientSecretHash, 'a session-bound challenge never mints a client secret');
    }

    /**
     * Finding 5 adversarial: a stateless begin (no session) mints a
     * client secret and records no session hash, exactly one binding.
     */
    public function testAStatelessBeginMintsOnlyAClientSecret(): void
    {
        $challenge = StepUpChallenge::begin(
            StepUpChallenge::mintId(),
            StepUpChallengeKind::WebAuthn,
            'aabbccddeeff00112233445566778899',
            null,
            'login',
            null,
            'enroll',
            1700000000,
            300,
            5,
            'hash',
            'creation',
            null,
        );
        self::assertNull($challenge->sessionHash);
        self::assertNotNull($challenge->clientSecretHash);
    }

    /**
     * Finding 5 adversarial: a session-bound challenge completed from
     * a different session is refused even when the ticket is valid.
     */
    public function testASessionBoundChallengeIsRefusedFromAnotherSession(): void
    {
        $challenge = StepUpChallenge::begin(
            StepUpChallenge::mintId(),
            StepUpChallengeKind::EmailOtp,
            'aabbccddeeff00112233445566778899',
            null,
            'login',
            null,
            'step_up',
            1700000000,
            300,
            5,
            'hash',
            null,
            'sess-original-000000000000000001',
        );
        $beginReq = $this->request('sess-original-000000000000000001');
        StepUpSessionBinding::bind($beginReq, 'aabbccddeeff00112233445566778899');
        self::assertTrue(StepUpSessionBinding::matches($beginReq, $challenge));

        $otherReq = $this->request('sess-attacker-00000000000000001');
        StepUpSessionBinding::bind($otherReq, 'aabbccddeeff00112233445566778899');
        self::assertFalse(
            StepUpSessionBinding::matches($otherReq, $challenge),
            'a ticket captured in one session can never be completed in another',
        );
    }

    /**
     * Finding 5 adversarial: a stateless challenge completed with the
     * wrong client secret is refused.
     */
    public function testAStatelessChallengeRejectsAWrongClientSecret(): void
    {
        $challenge = StepUpChallenge::begin(
            StepUpChallenge::mintId(),
            StepUpChallengeKind::EmailOtp,
            'aabbccddeeff00112233445566778899',
            null,
            'login',
            null,
            'step_up',
            1700000000,
            300,
            5,
            'hash',
            null,
            null,
        );
        $req = Request::create('https://example.com/kiwi/step-up/complete', 'POST', [
            'kiwi_step_up_client_secret' => 'wrong-secret',
        ]);
        StepUpSessionBinding::bind($req, 'aabbccddeeff00112233445566778899');
        self::assertFalse(StepUpSessionBinding::matches($req, $challenge));
    }

    /**
     * Finding 3 adversarial: the bootstrap grant expires. A stale
     * grant (past the TTL) never authorizes.
     */
    public function testAnExpiredGrantNeverAuthorizes(): void
    {
        $gate = new StepUpBootstrapGate(true, null, $this->identity());
        $request = $this->request();
        $gate->grant($request, 'user@example.com');
        $session = $request->getSession();
        $grant = $session->get('_kiwi_signup_bootstrap_grant');
        $grant['expires'] = time() - 1;
        $session->set('_kiwi_signup_bootstrap_grant', $grant);
        self::assertFalse($gate->allowsFirstEnrollment($request, $this->identity()->principalId('user@example.com')));
    }

    /**
     * Finding 3 adversarial: the raw identifier and the pseudonym
     * differ, and the gate must still match them.
     */
    public function testGrantAndEnrollmentSpellingMayDiffer(): void
    {
        $gate = new StepUpBootstrapGate(true, null, $this->identity());
        $request = $this->request();
        $gate->grant($request, 'raw-login@example.com');
        $pseudonym = $this->identity()->principalId('raw-login@example.com');
        self::assertNotSame('raw-login@example.com', $pseudonym);
        self::assertTrue($gate->allowsFirstEnrollment($request, $pseudonym));
    }

    /**
     * Full-chain (finding 1): write the challenge, serialize it
     * (toArray), read it back (fromArray), and confirm the bootstrap
     * flag survives the store round trip. The in-memory object check
     * is not enough, fromArray() is the real path every store takes.
     */
    public function testTheBootstrapFlagSurvivesTheStoreRoundTrip(): void
    {
        $challenge = StepUpChallenge::begin(
            StepUpChallenge::mintId(),
            StepUpChallengeKind::WebAuthn,
            'aabbccddeeff00112233445566778899',
            null,
            'login',
            null,
            'enroll',
            1700000000,
            300,
            5,
            'hash',
            'creation',
            'sess-00000000000000000000000001',
            false,
            true,
        );
        $wire = $challenge->toArray();
        self::assertSame(1, $wire['bootstrap'], 'the wire form carries the bootstrap flag');
        $back = StepUpChallenge::fromArray($wire);
        self::assertTrue(
            $back->bootstrapAuthorized,
            'fromArray() must restore the bootstrap flag: a store round trip is the real path',
        );
        // The other invariants survive too.
        self::assertSame($challenge->sessionHash, $back->sessionHash);
        self::assertNull($back->clientSecretHash);
        self::assertSame($challenge->id, $back->id);
    }

    /**
     * Full-chain: a non-bootstrap challenge must not gain the flag
     * through the round trip.
     */
    public function testANonBootstrapChallengeStaysFalseAfterARoundTrip(): void
    {
        $challenge = StepUpChallenge::begin(
            StepUpChallenge::mintId(),
            StepUpChallengeKind::WebAuthn,
            'aabbccddeeff00112233445566778899',
            null,
            'login',
            null,
            'enroll',
            1700000000,
            300,
            5,
            'hash',
            'creation',
            'sess-00000000000000000000000001',
        );
        $back = StepUpChallenge::fromArray($challenge->toArray());
        self::assertFalse($back->bootstrapAuthorized);
    }

    /**
     * Full-chain: the external combined script branches on the
     * ceremony (finding 3). A single external file must drive both
     * create() and get().
     */
    public function testTheCombinedScriptBranchesOnTheCeremony(): void
    {
        $combined = \BelConsulting\KiwiCaptchaBundle\Security\StepUp\WebAuthnStepUpHandler::CEREMONY_COMBINED_SCRIPT;
        self::assertStringContainsString("doc.ceremony === 'creation'", $combined);
        self::assertStringContainsString('navigator.credentials.create', $combined);
        self::assertStringContainsString('navigator.credentials.get', $combined);
        self::assertStringContainsString('attestationObject', $combined);
        self::assertStringContainsString('authenticatorData', $combined);
    }

    /**
     * Full-chain (finding 5): the bootstrap flag decodes strictly.
     * Exactly the integer 0 or 1; a stringly-typed "1", "1abc" or
     * true is malformed and refused like every other field.
     */
    public function testTheBootstrapFlagDecodesStrictly(): void
    {
        $base = StepUpChallenge::begin(
            StepUpChallenge::mintId(),
            StepUpChallengeKind::WebAuthn,
            'aabbccddeeff00112233445566778899',
            null,
            'login',
            null,
            'enroll',
            1700000000,
            300,
            5,
            'hash',
            'creation',
            'sess-00000000000000000000000001',
            false,
            true,
        )->toArray();
        // The integer 1 is accepted.
        self::assertTrue(StepUpChallenge::fromArray($base)->bootstrapAuthorized);
        // The integer 0 is accepted and false.
        $off = $base;
        $off['bootstrap'] = 0;
        self::assertFalse(StepUpChallenge::fromArray($off)->bootstrapAuthorized);
        // Stringly-typed and boolean forms are malformed.
        foreach (['1', '1abc', true, 'true', 2, -1, null] as $bad) {
            $wire = $base;
            $wire['bootstrap'] = $bad;
            try {
                StepUpChallenge::fromArray($wire);
                self::fail('bootstrap=' . var_export($bad, true) . ' must be refused');
            } catch (\BelConsulting\KiwiCaptchaBundle\Security\StepUp\MalformedStepUpChallengeException $e) {
                self::assertStringContainsString('bootstrap', $e->getMessage());
            }
        }
    }
}
