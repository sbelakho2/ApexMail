<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests\Risk;

use BelConsulting\KiwiCaptchaBundle\Controller\ChallengeController;
use BelConsulting\KiwiCaptchaBundle\Risk\ContinuityCookie;
use BelConsulting\KiwiCaptchaBundle\Risk\RiskGateway;
use BelConsulting\KiwiCaptchaBundle\Risk\RiskProfileResolver;
use BelConsulting\KiwiCaptchaBundle\Risk\SecurityEpochMonitor;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\FakePredisClient;
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
use KiwiCaptcha\Verifier;
use PHPUnit\Framework\TestCase;

/**
 * Risk-v2 bundle wiring: decoy-marked challenge requests feed honeypot
 * evidence into the risk gateway without gating issuance. The session
 * client-context tag drives the session-consistency signal through the
 * full stack (controller -> gateway -> engine -> store), and the trusted
 * proxy-supplied TLS classification tag drives the TLS-consistency
 * signal through the same stack.
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
        // Protocol-v3 emission is gated by the two-phase rollout
        // invariant: risk.decoy_v3_enabled true AND the central
        // security-policy floor min_protocol_version >= 3. The fake
        // security Redis below reports floor 3, so this stack exercises
        // the armed-issuance surface (protocol v3 + authenticated decoy).
        $redis = new FakePredisClient();
        $redis->hset('{kiwi:test-ns}:security-policy', SecurityEpochMonitor::MIN_PROTOCOL_VERSION_FIELD, '3');
        $redis->hset('{kiwi:test-ns}:security-policy', SecurityEpochMonitor::MIN_POLICY_EPOCH_FIELD, '1');
        $monitor = new SecurityEpochMonitor(new Verifier(new ArrayStorage()), $redis, 'test-ns', 1, 1);
        $controller = new ChallengeController($issuer, null, true, $gateway, new ContinuityCookie(), epochMonitor: $monitor, decoyV3Enabled: true);

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

        // The authenticated decoy field name rides the issuance response:
        // the issuer's per-issuance pool pick (armed issuance, protocol
        // v3) — never a decoy_<hash> nonce-hash reconstruction.
        self::assertIsString($data['decoy_field'] ?? null);
        self::assertTrue(Issuer::isGrammarDecoyName((string) $data['decoy_field']), 'the issuance response carries the issuer\'s combinatorial grammar name');
        self::assertNotSame(
            'decoy_'.substr(hash('sha256', (string) $data['nonce']), 0, 8),
            $data['decoy_field'],
            'the decoy name must not be a nonce-hash reconstruction (the audit\'s "no second nonce-hash scheme")',
        );

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

        // Same session, changed coarse capabilities: a different tag -> the
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
        self::assertNull($honeypotOnly->tlsTag);
    }

    public function testTrustedTlsTagConsistencyThroughTheGateway(): void
    {
        $stack = $this->stack();
        $session = str_repeat('3a', 16);
        $descriptor = 'vp=1,t=0,l=en,z=1';

        // The gateway accepts the coarse, server-attested TLS classification
        // tag from trusted proxy infrastructure as the 4th argument.
        $first = $stack['gateway']->clientContextV2(false, $session, $descriptor, 'tls13|http2');
        self::assertNotNull($first);
        self::assertSame('tls13|http2', $first->tlsTag, 'the trusted TLS tag must ride the v2 context');
        self::assertNotNull($first->clientContextTag, 'the descriptor-derived tag is built as today');
        $decision1 = $stack['gateway']->preIssue('login', '198.51.100.7', $session, null, $first);
        self::assertSame(100, $decision1->score, 'the first TLS tag-bearing request is neutral');

        // Same session, same TLS tag: neutral.
        $again = $stack['gateway']->clientContextV2(false, $session, $descriptor, 'tls13|http2');
        $decision2 = $stack['gateway']->preIssue('login', '198.51.100.7', $session, null, $again);
        self::assertSame(100, $decision2->score, 'an unchanged TLS tag stays neutral');

        // Same session, changed TLS tag: the tls_inconsistency signal
        // raises the aggregate (100 + 80 = 180).
        $changed = $stack['gateway']->clientContextV2(false, $session, $descriptor, 'tls12|http1');
        $decision3 = $stack['gateway']->preIssue('login', '198.51.100.7', $session, null, $changed);
        self::assertSame(180, $decision3->score, 'a changed trusted TLS tag must raise the aggregate');
    }

    public function testTlsTagWithoutSessionOrDescriptorIsNeutral(): void
    {
        $stack = $this->stack();

        // A TLS tag alone (no session) still yields a v2 context, but the
        // engine has no session record to compare against: neutral.
        $onlyTls = $stack['gateway']->clientContextV2(false, null, null, 'tls13|http2');
        self::assertNotNull($onlyTls, 'a trusted TLS tag alone is still risk-v2 evidence');
        self::assertSame('tls13|http2', $onlyTls->tlsTag);
        self::assertNull($onlyTls->clientContextTag);
        $decision = $stack['gateway']->preIssue('login', '198.51.100.7', null, null, $onlyTls);
        self::assertSame(100, $decision->score, 'a TLS tag without a session is neutral');

        // An empty TLS tag is treated as absent: no v2 context at all.
        self::assertNull($stack['gateway']->clientContextV2(false, null, null, ''), 'an empty TLS tag is no evidence');
    }

    public function testV2WeightsOverrideThroughTheGateway(): void
    {
        $stack = $this->stack();
        $session = str_repeat('3b', 16);
        $descriptor = 'vp=1,t=0,l=en,z=1';

        // Null override: the default weights apply (100 + 1000*200/1000 = 300).
        $default = $stack['gateway']->clientContextV2(true, $session, $descriptor);
        self::assertNotNull($default);
        $decisionDefault = $stack['gateway']->preIssue('login', '198.51.100.7', $session, null, $default, null);
        self::assertSame(300, $decisionDefault->score, 'a null weights override must produce the default score');

        // Operator-tuned weights: honeypot weight 100 -> 100 + 1000*100/1000 = 200.
        $tuned = $stack['gateway']->preIssue('login', '198.51.100.7', $session, null, $default, new \KiwiCaptcha\Risk\RiskV2Weights(honeypot: 100));
        self::assertSame(200, $tuned->score, 'the v2 weights override must reach the engine through the gateway');
    }

    public function testConfiguredV2WeightsReachTheEngineThroughTheGateway(): void
    {
        // The gateway's constructor weights are the operator-configured
        // risk.v2.* values: a honeypot hit scores with the configured
        // weight when no per-call override is given.
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
        $gateway = new RiskGateway(
            $engine,
            $classifier,
            new RiskProfileResolver(PoWAlgorithm::Sha256, 8),
            ['login' => 1],
            policy: $policy,
            v2Weights: new \KiwiCaptcha\Risk\RiskV2Weights(honeypot: 100, sessionInconsistency: 60, tls: 30),
        );

        $v2 = $gateway->clientContextV2(true, null, null);
        self::assertNotNull($v2);
        $decision = $gateway->preIssue('login', '198.51.100.7', null, null, $v2);
        self::assertSame(200, $decision->score, 'the configured honeypot weight (100) must score the hit (100 + 1000*100/1000)');
    }

    public function testPostSolveDecisionV2ScoresTheHoneypotHitHigherThanV1(): void
    {
        $stack = $this->stack();

        // The v1 post-solve assessment with a clean context scores the
        // base risk (100, allow).
        $v1 = $stack['gateway']->postSolveDecision('login', '198.51.100.7');
        self::assertNotNull($v1);
        self::assertSame(100, $v1->score);

        // The v2 post-solve assessment with the honeypot hit scores
        // strictly higher (100 + 200 = 300) — the honeypot evidence now
        // actually moves the post-solve score.
        $honeypot = $stack['gateway']->clientContextV2(true, null, null);
        self::assertNotNull($honeypot);
        $v2 = $stack['gateway']->postSolveDecisionV2('login', '198.51.100.7', null, null, null, $honeypot);
        self::assertNotNull($v2);
        self::assertGreaterThan($v1->score, $v2->score, 'a filled exact decoy field must raise the post-solve score');
        self::assertSame(300, $v2->score);

        // A context without the hit scores identically to the v1 path.
        $empty = $stack['gateway']->postSolveDecisionV2('login', '198.51.100.7');
        self::assertNotNull($empty);
        self::assertSame($v1->score, $empty->score, 'postSolveDecisionV2 without evidence is the v1 score');
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
