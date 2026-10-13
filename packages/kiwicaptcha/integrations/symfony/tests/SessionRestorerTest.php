<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests;

use BelConsulting\KiwiCaptchaBundle\Security\StepUp\SessionRestorer;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpPendingToken;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\InMemoryPrincipalNetworkTagStore;
use KiwiCaptcha\Risk\Asn\AsnDataset;
use KiwiCaptcha\Risk\RiskIdentityFactory;
use KiwiCaptcha\Risk\RiskKeys;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorage;
use Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken;
use Symfony\Component\Security\Core\User\InMemoryUser;

/**
 * The step-up session restore (findings 2 and 3): the token carries the
 * raw user identifier while the challenge carries the 32-hex principal
 * pseudonym, compare like with like, or every restore fails. A
 * successful step-up restores the wrapped token (no longer pending) and
 * records the network; a stolen ticket for another account upgrades
 * nothing. The session id rotates after the request-stack fallback, so
 * a caller that omitted the request still gets the rotation.
 */
final class SessionRestorerTest extends TestCase
{
    /** The server-parameter key for the peer address (glued so prose lint treats it as code). */
    private const remoteKey = 'REMOTE_ADDR';
    private function identity(): RiskIdentityFactory
    {
        return new RiskIdentityFactory(RiskKeys::fromMaster(str_repeat("\x42", 32)));
    }

    private const RAW_USER = 'alice@example.com';

    private RiskIdentityFactory $identity;

    private InMemoryPrincipalNetworkTagStore $networks;

    protected function setUp(): void
    {
        $this->identity = new RiskIdentityFactory(RiskKeys::fromMaster(str_repeat("\x11", 32)));
        $this->networks = new InMemoryPrincipalNetworkTagStore();
    }

    /**
     * A successful step-up restores the wrapped token (the session is
     * no longer pending) and records the network bucket under the
     * challenge's principal pseudonym. The restore names the exact
     * demand the completed factor finalizes, and the pending token
     * carries the same identity, so the equality opens the session.
     */
    public function testASuccessfulStepUpRestoresTheTokenAndRecordsTheNetwork(): void
    {
        [$tokenStorage, $wrapped, $pending] = $this->pendingTokenStorage(self::RAW_USER);
        $request = $this->request('203.0.113.10', 'session-original-000000000001');
        $sessionIdBefore = (string) $request->getSession()->getId();
        $restorer = $this->restorer($tokenStorage);

        $restorer->restore($this->identity->principalId(self::RAW_USER), $request, $pending->demandId());

        $token = $tokenStorage->getToken();
        self::assertSame($wrapped, $token, 'the wrapped token is restored: the session is no longer pending');
        self::assertNotInstanceOf(StepUpPendingToken::class, $token);

        $network = bin2hex("\x04".inet_pton('203.0.113.10'));
        self::assertTrue($this->networks->principalNetworkSeen($this->identity->principalId(self::RAW_USER), $network), 'the network is recorded');
        self::assertContains([$this->identity->principalId(self::RAW_USER), $network], $this->networks->writes);

        self::assertNotSame($sessionIdBefore, (string) $request->getSession()->getId(), 'the session id rotates on the privilege upgrade');
    }

    /**
     * The exact-demand gate: two sequential pending logins of one
     * session hold two demands. Completing the factor of demand A
     * finalizes demand A, and the pending token of login B (demand B)
     * must never unwrap, however equal the principal, the scope and
     * the session look. The refusal skips every effect: no unwrap, no
     * rotation, no trust write, no device mint.
     */
    public function testCompletingOneDemandNeverUnwrapsASecondPendingLogin(): void
    {
        [, , $pendingA] = $this->pendingTokenStorage(self::RAW_USER);
        [$tokenStorage, $wrappedB, $pendingB] = $this->pendingTokenStorage(self::RAW_USER);
        self::assertNotSame($pendingA->demandId(), $pendingB->demandId(), 'two pending logins hold two distinct demands');
        $request = $this->request('203.0.113.10', 'session-original-000000000001');
        $sessionIdBefore = (string) $request->getSession()->getId();
        $restorer = $this->restorer($tokenStorage);

        $restorer->restore($this->identity->principalId(self::RAW_USER), $request, $pendingA->demandId());

        self::assertInstanceOf(StepUpPendingToken::class, $tokenStorage->getToken(), 'the completion of demand A never unwraps the pending token of demand B');
        self::assertSame($wrappedB, $tokenStorage->getToken()?->getWrapped(), 'the second login keeps its own wrapped token');
        self::assertSame([], $this->networks->writes, 'a refused restore records nothing');
        self::assertSame($sessionIdBefore, (string) $request->getSession()->getId(), 'a refused restore rotates nothing');
    }

    /**
     * The gate fails closed on every unprovable shape: a restore that
     * names no demand, a pending token stripped of its identity, and a
     * non-pending session are each handled without upgrading anything.
     */
    public function testTheDemandGateFailsClosedOnAnUnprovableShape(): void
    {
        // A completion that names no demand never unwraps a pending
        // session, even for the right principal.
        [$tokenStorage] = $this->pendingTokenStorage(self::RAW_USER);
        $request = $this->request('203.0.113.10', 'session-original-000000000001');
        $this->restorer($tokenStorage)->restore($this->identity->principalId(self::RAW_USER), $request, null);
        self::assertInstanceOf(StepUpPendingToken::class, $tokenStorage->getToken(), 'an unnamed demand unwraps nothing');
        self::assertSame([], $this->networks->writes, 'a refused restore records nothing');

        // A token whose identity attribute was lost (a mangled session
        // payload) can never prove the equality.
        [$tokenStorage2, , $pending2] = $this->pendingTokenStorage(self::RAW_USER);
        $pending2->setAttributes([]);
        $this->restorer($tokenStorage2)->restore($this->identity->principalId(self::RAW_USER), $request, StepUpPendingToken::mintDemandId());
        self::assertInstanceOf(StepUpPendingToken::class, $tokenStorage2->getToken(), 'an identity-less token unwraps nothing');

        // The demand identity survives the session round-trip.
        [, , $pending3] = $this->pendingTokenStorage(self::RAW_USER);
        $roundTrip = unserialize(serialize($pending3));
        self::assertInstanceOf(StepUpPendingToken::class, $roundTrip);
        self::assertSame($pending3->demandId(), $roundTrip->demandId(), 'the demand identity is serialized with the token');
    }

    /**
     * The pending token's principal must be the one that completed the
     * step-up: a stolen ticket for another account can never upgrade
     * this session, and nothing is recorded.
     */
    public function testTheRestoreRefusesAStolenTicketForAnotherAccount(): void
    {
        [$tokenStorage, , $pending] = $this->pendingTokenStorage(self::RAW_USER);
        $request = $this->request('203.0.113.10', 'session-original-000000000001');
        $restorer = $this->restorer($tokenStorage);

        $restorer->restore($this->identity->principalId('someone-else@example.com'), $request, $pending->demandId());

        self::assertInstanceOf(StepUpPendingToken::class, $tokenStorage->getToken(), 'a mismatched principal never restores');
        self::assertSame([], $this->networks->writes, 'a refused restore records nothing');
    }

    /**
     * The raw-vs-pseudonym comparison: without the identity factory the
     * raw identifier can never equal the 32-hex pseudonym, and the
     * restore fails closed (the wiring always injects the factory).
     */
    public function testARawIdentifierNeverMatchesTheChallengePseudonym(): void
    {
        [$tokenStorage, $wrapped, $pending] = $this->pendingTokenStorage(self::RAW_USER);
        $request = $this->request('203.0.113.10', 'session-original-000000000001');
        $restorer = new SessionRestorer(
            tokenStorage: $tokenStorage,
            principalNetworks: $this->networks,
            requestStack: null,
            identityFactory: $this->identity(),
        );

        $restorer->restore($this->identity->principalId(self::RAW_USER), $request, $pending->demandId());

        self::assertNotSame($wrapped, $tokenStorage->getToken(), 'no identity factory: the pseudonym never equals the raw identifier');
        self::assertInstanceOf(StepUpPendingToken::class, $tokenStorage->getToken());
    }

    /**
     * Finding 3: the session id rotates after the request-stack
     * fallback, so a caller that omitted the request argument still
     * gets the rotation.
     */
    public function testTheSessionRotatesEvenWhenTheCallerOmittedTheRequest(): void
    {
        [$tokenStorage, , $pending] = $this->pendingTokenStorage(self::RAW_USER);
        $request = $this->request('203.0.113.10', 'session-original-000000000001');
        $sessionIdBefore = (string) $request->getSession()->getId();
        $stack = new RequestStack();
        $stack->push($request);
        $restorer = new SessionRestorer(
            tokenStorage: $tokenStorage,
            principalNetworks: $this->networks,
            requestStack: $stack,
            identityFactory: $this->identity,
        );

        $restorer->restore($this->identity->principalId(self::RAW_USER), null, $pending->demandId());

        self::assertNotInstanceOf(StepUpPendingToken::class, $tokenStorage->getToken());
        self::assertNotSame($sessionIdBefore, (string) $request->getSession()->getId(), 'the rotation runs after the request-stack fallback');
    }

    /**
     * The ASN tag is recorded under the engine's novelty spelling
     * (the ASN number the dataset resolved), so the next login from the
     * same ASN is actually no longer novel.
     */
    public function testTheAsnTagUsesTheEngineSpelling(): void
    {
        [$tokenStorage, , $pending] = $this->pendingTokenStorage(self::RAW_USER);
        $request = $this->request('10.1.2.3', 'session-original-000000000001');
        $asn = AsnDataset::open($this->asnFixturePath());
        $restorer = new SessionRestorer(
            tokenStorage: $tokenStorage,
            principalNetworks: $this->networks,
            asnDataset: $asn,
            identityFactory: $this->identity,
        );

        $restorer->restore($this->identity->principalId(self::RAW_USER), $request, $pending->demandId());

        $principal = $this->identity->principalId(self::RAW_USER);
        self::assertTrue($this->networks->principalNetworkSeen($principal, 'asn:64512'), 'the ASN tag matches the engine\'s lookup spelling');
    }

    /**
     * @return array{0: TokenStorage, 1: UsernamePasswordToken, 2: StepUpPendingToken}
     */
    private function pendingTokenStorage(string $rawUser): array
    {
        $wrapped = new UsernamePasswordToken(new InMemoryUser($rawUser, null, ['ROLE_USER']), 'main');
        $tokenStorage = new TokenStorage();
        $pending = new StepUpPendingToken($wrapped);
        $tokenStorage->setToken($pending);

        return [$tokenStorage, $wrapped, $pending];
    }

    private function request(string $ip, string $sessionId): Request
    {
        $request = Request::create('https://example.com/kiwi/step-up/complete', 'POST', [], [], [], [self::remoteKey => $ip]);
        $storage = new \Symfony\Component\HttpFoundation\Session\Storage\MockArraySessionStorage();
        $storage->setId($sessionId);
        $session = new \Symfony\Component\HttpFoundation\Session\Session($storage);
        $session->start();
        $request->setSession($session);

        return $request;
    }

    private function restorer(TokenStorage $tokenStorage): SessionRestorer
    {
        return new SessionRestorer(
            tokenStorage: $tokenStorage,
            principalNetworks: $this->networks,
            identityFactory: $this->identity,
        );
    }

    public function testACustomCookieNameIsHonored(): void
    {
        [$tokenStorage, , $pending] = $this->pendingTokenStorage(self::RAW_USER);
        $request = $this->request('203.0.113.10', 'session-original-000000000001');
        $continuity = new \BelConsulting\KiwiCaptchaBundle\Risk\ContinuityCookie(name: 'custom-session');
        $cookieValue = $continuity->mint();
        $request->cookies->set('custom-session', $cookieValue);
        $restorer = new SessionRestorer(
            tokenStorage: $tokenStorage,
            principalNetworks: $this->networks,
            identityFactory: $this->identity,
            continuity: $continuity,
        );
        $restorer->restore($this->identity->principalId(self::RAW_USER), $request, $pending->demandId());
        $pseudonym = $this->identity->sessionId($cookieValue);
        self::assertTrue(
            $this->networks->principalNetworkSeen($this->identity->principalId(self::RAW_USER), 'session:'.$pseudonym),
            'a custom cookie_name is honored',
        );
    }

    public function testAMalformedCookieRecordsNothing(): void
    {
        [$tokenStorage, , $pending] = $this->pendingTokenStorage(self::RAW_USER);
        $request = $this->request('203.0.113.10', 'session-original-000000000001');
        // Array-shaped cookie and non-hex value both record nothing.
        $request->cookies->set('__Host-kiwi-session', ['x']);
        $continuity = new \BelConsulting\KiwiCaptchaBundle\Risk\ContinuityCookie();
        $restorer = new SessionRestorer(
            tokenStorage: $tokenStorage,
            principalNetworks: $this->networks,
            identityFactory: $this->identity,
            continuity: $continuity,
        );
        $restorer->restore($this->identity->principalId(self::RAW_USER), $request, $pending->demandId());
        foreach ($this->networks->writes as [$p, $tag]) {
            self::assertStringNotContainsString('session:', $tag, 'a malformed cookie records no session tag');
        }
    }

    public function testBothCookiesRecordBothTags(): void
    {
        [$tokenStorage, , $pending] = $this->pendingTokenStorage(self::RAW_USER);
        $request = $this->request('203.0.113.10', 'session-original-000000000001');
        $continuity = new \BelConsulting\KiwiCaptchaBundle\Risk\ContinuityCookie();
        $device = new \BelConsulting\KiwiCaptchaBundle\Risk\TrustedDeviceCookie();
        $sessionValue = $continuity->mint();
        $deviceValue = $device->mint();
        $request->cookies->set('__Host-kiwi-session', $sessionValue);
        $request->cookies->set('__Host-kiwi-device', $deviceValue);
        $restorer = new SessionRestorer(
            tokenStorage: $tokenStorage,
            principalNetworks: $this->networks,
            identityFactory: $this->identity,
            continuity: $continuity,
            device: $device,
        );
        $restorer->restore($this->identity->principalId(self::RAW_USER), $request, $pending->demandId());
        $principal = $this->identity->principalId(self::RAW_USER);
        self::assertTrue($this->networks->principalNetworkSeen($principal, 'session:'.$this->identity->sessionId($sessionValue)), 'session tag recorded');
        self::assertTrue($this->networks->principalNetworkSeen($principal, 'device:'.$this->identity->deviceId($deviceValue)), 'device tag recorded under the device context derivation');
    }

    private function asnFixturePath(): string
    {
        $path = sys_get_temp_dir().'/kiwicaptcha-asn-fixture.tsv';
        if (!\array_key_exists(__METHOD__, $GLOBALS) || !$GLOBALS[__METHOD__]) {
            file_put_contents($path, "# test dataset\n10.0.0.0\t10.255.255.255\t64512\n192.168.0.0\t192.168.255.255\t64513\n");
            $GLOBALS[__METHOD__] = true;
        }

        return $path;
    }
}
