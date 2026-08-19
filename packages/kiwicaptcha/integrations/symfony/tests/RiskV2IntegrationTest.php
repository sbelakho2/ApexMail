<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests\Risk;

use BelConsulting\KiwiCaptchaBundle\Controller\ChallengeController;
use BelConsulting\KiwiCaptchaBundle\Risk\ContinuityCookie;
use BelConsulting\KiwiCaptchaBundle\Risk\RiskGateway;
use BelConsulting\KiwiCaptchaBundle\Risk\RiskProfileResolver;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\FakeRiskStateStore;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\JsonRequest;
use KiwiCaptcha\Config;
use KiwiCaptcha\Issuer;
use KiwiCaptcha\PoWAlgorithm;
use KiwiCaptcha\Risk\AdaptiveRiskEngine;
use KiwiCaptcha\Risk\Network\CidrNetworkClassifier;
use KiwiCaptcha\Risk\RiskEventKind;
use KiwiCaptcha\Risk\RiskIdentityFactory;
use KiwiCaptcha\Risk\RiskKeys;
use KiwiCaptcha\Risk\RiskPolicy;
use KiwiCaptcha\Risk\RiskScorer;
use KiwiCaptcha\Storage\ArrayStorage;
use PHPUnit\Framework\TestCase;

/**
 * Risk-v2 bundle wiring: decoy-marked challenge requests feed honeypot
 * evidence into the risk gateway WITHOUT gating issuance, and the
 * session client-context tag drives the session-consistency signal through
 * the full stack (controller -> gateway -> engine -> store).
 */
final class RiskV2IntegrationTest extends TestCase
{
    private const SECRET = '0123456789abcdef0123456789abcdef';

    /**
     * @return array{controller: ChallengeController, gateway: RiskGateway, store: FakeRiskStateStore}
     */
    private function stack(): array
    {
        $issuer = new Issuer(new Config(secretKey: self::SECRET, targetBits: 8, ttlSecs: 120), new ArrayStorage());
        $keys = RiskKeys::fromMaster(self::SECRET);
        $classifier = new CidrNetworkClassifier([]);
        $policy = RiskPolicy::fromConfig([
            'version' => RiskPolicy::CONTRACT_VERSION,
            'weights' => [],
            'scopes' => [
                1 => ['base_risk' => 100, 'minimum' => 'allow', 'post_solve_check' => false, 'degraded' => 'allow'],
            ],
        ]);
        $store = new FakeRiskStateStore();
        $engine = new AdaptiveRiskEngine($store, $classifier, new RiskIdentityFactory($keys), new RiskScorer(), $policy, $keys);
        $gateway = new RiskGateway($engine, $classifier, new RiskProfileResolver(PoWAlgorithm::Sha256, 8), ['login' => 1], policy: $policy);
        $controller = new ChallengeController($issuer, null, true, $gateway, new ContinuityCookie());

        return ['controller' => $controller, 'gateway' => $gateway, 'store' => $store];
    }

    private function challengeRequest(string $body, ?string $session = null): \Symfony\Component\HttpFoundation\Request
    {
        return JsonRequest::create(
            '/kiwi-captcha/challenge',
            'POST',
            [],
            $session !== null ? ['__Host-kiwi-session' => $session] : [],
            [],
            ['REMOTE_ADDR' => '198.51.100.7'],
            $body,
        );
    }

    public function testDecoyMarkedRequestFeedsTheEventWithoutGatingIssuance(): void
    {
        $stack = $this->stack();
        $response = $stack['controller']->challenge($this->challengeRequest(
            '{"scope":"login","decoy_field":"decoy_12345678","honeypot":"bot@example.com"}'
        ));

        // Issuance proceeds normally: the markers are evidence, never a gate.
        self::assertSame(200, $response->getStatusCode());
        $data = json_decode((string) $response->getContent(), true);
        self::assertSame('sha256', $data['algorithm']);

        // The server-issued decoy field name rides the issuance response.
        self::assertMatchesRegularExpression('/^decoy_[0-9a-f]{8}$/D', (string) $data['decoy_field']);

        // The decoy marker fed the risk gateway as the DecoyFieldSubmitted
        // event (evidence), alongside the pre-issue assessment.
        $events = array_map(static fn ($o): RiskEventKind => $o->event, $stack['store']->observations);
        self::assertContains(RiskEventKind::PreIssue, $events);
        self::assertContains(RiskEventKind::DecoyFieldSubmitted, $events);
    }

    public function testHoneypotOnlyRequestFeedsHoneypotTriggeredWithoutGating(): void
    {
        $stack = $this->stack();
        $response = $stack['controller']->challenge($this->challengeRequest('{"scope":"login","honeypot":"filled"}'));
        self::assertSame(200, $response->getStatusCode());

        $events = array_map(static fn ($o): RiskEventKind => $o->event, $stack['store']->observations);
        self::assertContains(RiskEventKind::HoneypotTriggered, $events);
    }

    public function testDecoyMarkersWithoutRiskStayAcceptedAndIgnored(): void
    {
        $issuer = new Issuer(new Config(secretKey: self::SECRET, targetBits: 8, ttlSecs: 120), new ArrayStorage());
        $controller = new ChallengeController($issuer);
        $response = $controller->challenge($this->challengeRequest(
            '{"scope":"login","decoy_field":"decoy_12345678","honeypot":"x","client_context":"vp=1,t=0,l=en,z=1"}'
        ));
        self::assertSame(200, $response->getStatusCode());
        $data = json_decode((string) $response->getContent(), true);
        self::assertArrayNotHasKey('decoy_field', $data, 'the decoy field is server-issued by the risk program only');
    }

    public function testMalformedDecoyMarkersAreRejectedLikeAnyMalformedField(): void
    {
        $stack = $this->stack();
        foreach (['{"scope":"login","decoy_field":"bad name"}', '{"scope":"login","client_context":"VP=1"}', '{"scope":"login","honeypot":"'.str_repeat('x', 300).'"}'] as $body) {
            $response = $stack['controller']->challenge($this->challengeRequest($body));
            self::assertSame(422, $response->getStatusCode(), sprintf('malformed marker body %s must be refused', $body));
        }
    }

    public function testSameSessionWithChangedClientContextCarriesTheInconsistencySignal(): void
    {
        $stack = $this->stack();
        $session = str_repeat('ab', 16);

        // First tag-bearing request: the tag is recorded; the consistency
        // signal is neutral (score 100, Allow).
        $first = $stack['gateway']->clientContextV2(false, $session, 'vp=1,t=0,l=en,z=1');
        self::assertNotNull($first);
        $decision1 = $stack['gateway']->preIssue('login', '198.51.100.7', $session, null, $first);
        self::assertSame(100, $decision1->score);

        // Same session, CHANGED coarse capabilities: a different tag -> the
        // session-consistency signal raises the aggregate (100 + 120 = 220).
        $second = $stack['gateway']->clientContextV2(false, $session, 'vp=3,t=1,l=zh,z=2');
        self::assertNotNull($second);
        self::assertNotSame($first->clientContextTag, $second->clientContextTag, 'changed capabilities must change the tag');
        $decision2 = $stack['gateway']->preIssue('login', '198.51.100.7', $session, null, $second);
        self::assertSame(220, $decision2->score, 'a changed client-context tag must raise the aggregate');
    }

    public function testSameSessionWithConsistentClientContextStaysNeutral(): void
    {
        $stack = $this->stack();
        $session = str_repeat('cd', 16);

        $v2 = $stack['gateway']->clientContextV2(false, $session, 'vp=1,t=0,l=en,z=1');
        $decision1 = $stack['gateway']->preIssue('login', '198.51.100.7', $session, null, $v2);
        $decision2 = $stack['gateway']->preIssue('login', '198.51.100.7', $session, null, $v2);
        self::assertSame(100, $decision1->score);
        self::assertSame(100, $decision2->score, 'an unchanged tag stays neutral');
    }

    public function testNoSessionOrNoDescriptorCarriesNoV2Context(): void
    {
        $stack = $this->stack();
        self::assertNull($stack['gateway']->clientContextV2(false, null, 'vp=1,t=0,l=en,z=1'), 'no session -> no v2 context');
        self::assertNull($stack['gateway']->clientContextV2(false, 'session', null), 'no descriptor -> no v2 context');
        self::assertNull($stack['gateway']->clientContextV2(false, null, null), 'no evidence at all -> no v2 context');

        $honeypotOnly = $stack['gateway']->clientContextV2(true, null, null);
        self::assertNotNull($honeypotOnly, 'a honeypot hit alone still carries the v2 context');
        self::assertTrue($honeypotOnly->honeypotHit);
        self::assertNull($honeypotOnly->clientContextTag);
    }

    public function testHoneypotEvidenceRejectsNonHoneypotKinds(): void
    {
        $stack = $this->stack();
        $this->expectException(\InvalidArgumentException::class);
        $stack['gateway']->honeypotEvidence(RiskEventKind::PreIssue, 'login', '198.51.100.7');
    }

    public function testHoneypotEvidenceRecordsEachKind(): void
    {
        $stack = $this->stack();
        foreach ([RiskEventKind::HoneypotTriggered, RiskEventKind::DecoyEndpointTouched, RiskEventKind::DecoyFieldSubmitted] as $kind) {
            $receipt = $stack['gateway']->honeypotEvidence($kind, 'login', '198.51.100.7');
            self::assertNotNull($receipt);
            $events = array_map(static fn ($o): RiskEventKind => $o->event, $stack['store']->observations);
            self::assertContains($kind, $events);
        }
    }
}
