<?php

declare(strict_types=1);

namespace BelConsulting\Kernel;

use BelConsulting\KiwiCaptchaBundle\Controller\ChallengeController;
use BelConsulting\KiwiCaptchaBundle\Controller\KiwiMetricsController;
use BelConsulting\KiwiCaptchaBundle\Risk\BucketTrustPriceContext;
use BelConsulting\KiwiCaptchaBundle\Risk\RiskGateway;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\JsonRequest;
use BelConsulting\KiwiCaptchaBundle\Tests\Kernel\AbuseFirstCompositionTestKernel;
use KiwiCaptcha\Risk\AdaptiveRiskEngine;
use KiwiCaptcha\Risk\Marks\StoreMarksReader;
use KiwiCaptcha\Risk\Outcomes\KiwiOutcomes;
use KiwiCaptcha\Risk\Outcomes\Outcome;
use KiwiCaptcha\Risk\Outcomes\OutcomeHandle;
use KiwiCaptcha\Risk\Pricing\PriceRequest;
use KiwiCaptcha\Risk\ResourcePressure;
use KiwiCaptcha\Risk\RiskAction;
use KiwiCaptcha\Risk\RiskContext;
use KiwiCaptcha\Risk\RiskEventKind;
use KiwiCaptcha\Risk\Trust\ContextBoundTrust;
use KiwiCaptcha\VerifyError;
use PHPUnit\Framework\TestCase;
use Symfony\Component\DependencyInjection\ContainerInterface;
use Symfony\Component\HttpFoundation\Request;

/**
 * The full abuse_first composition, live: one kernel, the profile's
 * every Part 3 stage composed by the extension, and the whole pipeline
 * exercised through the real issued-challenge surface against the real
 * risk Lua (risk-v1, marks, trust, outcome ledger). The sequence is the
 * change.md Part 5 contract end to end:
 *
 *  1. the target dimension: a target_field request derives the target
 *     pseudonym and a confirmed abuse outcome on it writes the target
 *     mark (read back from the store),
 *  2. a confirmed abuse outcome on a session writes the session mark,
 *  3. the marked identity's next challenge is escalated to Argon64, and
 *     with corroborating attacker evidence denied outright,
 *  4. the explanation surface carries dimension names only, never a hex
 *     pseudonym,
 *  5. the price model is live: at the same score, a trusted context and
 *     an untrusted context price onto different rungs (observable in the
 *     issued challenge difficulty),
 *  6. the metrics exporter counts the decisions.
 *
 * Gated on KC_REDIS_URL like every real-Redis test (the fake client
 * cannot serve the canonical risk Lua, and a degraded engine proves
 * nothing about the composition).
 */
final class AbuseFirstCompositionKernelTest extends TestCase
{
    private static ?AbuseFirstCompositionTestKernel $kernel = null;
    private static ContainerInterface $container;

    private const COOKIE = '__Host-kiwi-session';

    public static function setUpBeforeClass(): void
    {
        if (AbuseFirstCompositionTestKernel::redisUrl() === null) {
            self::markTestSkipped('KC_REDIS_URL not set — the abuse_first composition proof needs the real risk Lua');
        }
        self::$kernel = new AbuseFirstCompositionTestKernel('test', true);
        self::$kernel->boot();
        self::$container = self::$kernel->getContainer()->get('test.service_container');
        self::redis()->flushdb();
    }

    public function setUp(): void
    {
        if (AbuseFirstCompositionTestKernel::redisUrl() === null) {
            self::markTestSkipped('KC_REDIS_URL not set');
        }
    }

    private static function redis(): \Predis\Client
    {
        return self::$container->get('kiwi_e2e_redis');
    }

    private static function gateway(): RiskGateway
    {
        return self::$container->get(RiskGateway::class);
    }

    private static function identityFactory(): \KiwiCaptcha\Risk\RiskIdentityFactory
    {
        return self::$container->get('kiwi_captcha.risk.identity_factory');
    }

    private static function outcomes(): KiwiOutcomes
    {
        return self::$container->get('kiwi_captcha.risk.outcomes');
    }

    /** One issued challenge through the real controller. */
    private static function challenge(Request $request): array
    {
        self::$container->get('request_stack')->push($request);
        $response = self::$container->get(ChallengeController::class)->challenge($request);
        self::$container->get('request_stack')->pop();

        return [json_decode((string) $response->getContent(), true), $response->getStatusCode()];
    }

    private static function challengeRequest(string $scope, string $ip, ?string $session): Request
    {
        return JsonRequest::create(
            '/kiwi-captcha/challenge',
            'POST',
            [],
            $session !== null ? [self::COOKIE => $session] : [],
            [],
            ['REMOTE_ADDR' => $ip],
            '{"scope":"'.$scope.'"}',
        );
    }

    private static function freshSession(): string
    {
        return bin2hex(random_bytes(16));
    }

    private static function reportAbuse(OutcomeHandle $handle, string $ip, ?string $session): void
    {
        self::outcomes()->report(
            Outcome::FraudConfirmed,
            $handle,
            null,
            new RiskContext(
                scope: 10,
                sourceIp: $ip,
                sessionId: $session,
                principalId: null,
                event: RiskEventKind::PreIssue,
                networkFlags: self::$container->get('kiwi_captcha.risk.classifier')->classify($ip),
                resources: new ResourcePressure(1000, 1000),
            ),
        );
    }

    public function testTheFullAbuseFirstCompositionIsWired(): void
    {
        $engine = self::$container->get('kiwi_captcha.risk.engine');
        $reader = (new \ReflectionProperty(AdaptiveRiskEngine::class, 'marksReader'))->getValue($engine);
        $price = (new \ReflectionProperty(AdaptiveRiskEngine::class, 'priceContext'))->getValue($engine);
        $target = (new \ReflectionProperty(AdaptiveRiskEngine::class, 'targetResolver'))->getValue($engine);
        self::assertInstanceOf(StoreMarksReader::class, $reader);
        self::assertInstanceOf(BucketTrustPriceContext::class, $price);
        self::assertNotNull($target);
        self::assertTrue(self::$container->has('kiwi_captcha.risk.asn'));
        self::assertInstanceOf(ContextBoundTrust::class, self::$container->get('kiwi_captcha.risk.trust'));

        // The dataset resolves the listed /8 into one ASN bucket, the
        // trust plane earns and reads bucket-local credit over trust.lua.
        $asn = self::$container->get('kiwi_captcha.risk.asn');
        self::assertSame($asn->bucketId('10.44.0.1'), $asn->bucketId('10.9.9.9'));
    }

    /**
     * Stage 1: the target dimension derives the pseudonym and the mark
     * plane addresses it.
     */
    public function testTargetDimensionDerivesPseudonymAndCarriesTheMark(): void
    {
        $target = self::gateway()->targetPseudonym('login', ['username' => 'victim@example.com']);
        self::assertMatchesRegularExpression('/^[0-9a-f]{64}$/', $target, 'the target dimension is the keyed digest of the normalized identifier');
        // The same claimed identifier always folds onto the same
        // pseudonym (normalization folds case, whitespace and the
        // provider email rules); a different identifier never does.
        self::assertSame($target, self::gateway()->targetPseudonym('login', ['username' => '  VICTIM@Example.com ']));
        self::assertNotSame($target, self::gateway()->targetPseudonym('login', ['username' => 'other@example.com']));

        // The confirmed abuse outcome writes the long-memory target mark
        // under the one derived mark-key spelling (the leading 128 bits
        // of the canonical 64-hex pseudonym, exactly the projection the
        // outcome bridge and the mark probe share).
        $markKey = \BelConsulting\KiwiCaptchaBundle\Risk\TargetMarkKey::of($target);
        self::assertSame(substr($target, 0, 32), $markKey);
        self::reportAbuse(OutcomeHandle::target($markKey), '10.1.0.1', null);

        $store = self::$container->get('kiwi_captcha.risk.store');
        $mark = $store->readMark('target', $markKey);
        self::assertNotNull($mark, 'the confirmed abuse outcome wrote the long-memory target mark');
        self::assertSame(Outcome::FraudConfirmed->value, $mark['kind']);

        // A scope without a target field derives no target dimension.
        self::assertNull(self::gateway()->targetPseudonym('pricing_probe', ['username' => 'victim@example.com']));
    }

    /**
     * Stage 2 and 3, first flavor: the spam mark is the quarantine
     * plane's subject (change.md 1.3 and 3.3.4), so it never adds a rung
     * of its own. On a request whose plain action already sits above the
     * Allow band the plain action wins and the issued challenge stays
     * the plain band's sha rung (this composition kernel carries live
     * aggregate pressure, so the global floor holds the band). On a
     * clean Allow-band request the decision quarantines instead of
     * escalating, proven byte-for-byte against a clean reference by the
     * bundle's wire-diff harness. The non-spam contrast keeps the
     * legacy maximum-rung floor.
     */
    public function testSpamMarkAddsNoRungAndNonSpamKeepsTheFloor(): void
    {
        $session = self::freshSession();
        [$baseline, $status] = self::challenge(self::challengeRequest('login', '10.2.0.1', $session));
        self::assertSame(200, $status);
        self::assertSame('sha256', $baseline['algorithm'], 'an unmarked session issues the plain sha rung');

        $pseudonym = self::identityFactory()->sessionId($session);
        $store = self::$container->get('kiwi_captcha.risk.store');
        $store->writeMark('session', $pseudonym, 'spamReported', (int) floor(microtime(true) * 1000));
        self::assertNotNull($store->readMark('session', $pseudonym), 'the spam mark rides the marks surface');

        // This composition kernel carries live aggregate pressure, so
        // the plain band of the request sits wherever the aggregate puts
        // it; the invariant under test is the rung arithmetic, which is
        // band-independent.
        $decision = self::gateway()->preIssue('login', '10.2.1.3', $session);
        self::assertContains(\KiwiCaptcha\Risk\RiskReason::MarkedIdentity->value, array_map(static fn ($r): string => $r->value, $decision->reasons));
        self::assertFalse($decision->quarantined, 'above the Allow band the plain action outranks the quarantine disposition');
        self::assertLessThan(RiskAction::Argon64->rank(), $decision->action->rank(), 'the spam mark adds no rung: the plain band stands');

        [$held, $status] = self::challenge(self::challengeRequest('login', '10.2.1.4', $session));
        self::assertSame(200, $status);
        self::assertSame('sha256', $held['algorithm'], 'the issued challenge stays the sha family, never argon');

        // The contrast: a non-spam mark keeps the legacy maximum-rung
        // floor. The quarantine selection is the spam kind's treatment,
        // never a general mark softening.
        $other = self::freshSession();
        $otherPseudonym = self::identityFactory()->sessionId($other);
        $store->writeMark('session', $otherPseudonym, 'fraudConfirmed', (int) floor(microtime(true) * 1000));
        $floored = self::gateway()->preIssue('login', '10.2.2.3', $other);
        self::assertFalse($floored->quarantined);
        self::assertSame(RiskAction::Argon64, $floored->action, 'a non-spam mark keeps the maximum-rung floor');
        self::assertContains(\KiwiCaptcha\Risk\RiskReason::MarkedIdentity->value, array_map(static fn ($r): string => $r->value, $floored->reasons));
    }

    /**
     * Stage 3, second flavor: the mark plus corroborating attacker
     * evidence denies the next request outright, with the saturated
     * retry hint of the deny window. The confirmed-abuse feedback
     * itself books bad and malformed pressure on the marked identity,
     * and the failed proof adds the invalid-proof channel on top.
     */
    public function testMarkedSessionWithCorroboratedEvidenceIsDenied(): void
    {
        $session = self::freshSession();
        self::reportAbuse(OutcomeHandle::session(self::identityFactory()->sessionId($session)), '10.3.0.1', $session);

        // Corroborating evidence: the marked identity submits a proof
        // with insufficient work (the invalid-proof feedback channel).
        self::gateway()->solveOutcome('login', '10.3.0.2', $session, VerifyError::InsufficientWork);

        $decision = self::gateway()->preIssue('login', '10.3.0.3', $session);
        self::assertSame(RiskAction::Deny, $decision->action, 'the corroborated mark denies the request');
        self::assertContains(\KiwiCaptcha\Risk\RiskReason::CorroboratedAbuse->value, array_map(static fn ($r): string => $r->value, $decision->reasons));
        self::assertGreaterThan(0, $decision->retryAfterMs);

        [$body, $status] = self::challenge(self::challengeRequest('login', '10.3.0.4', $session));
        self::assertSame(429, $status);
        self::assertSame('RISK_DENIED', $body['error']['code'] ?? null, 'the corroborated denial holds at the issuance boundary');
    }

    /**
     * Stage 4 (explanation): the surfaced explanation carries dimension
     * names only, never a pseudonym value. The read happens inside the
     * request window, exactly where the gateway attaches the attribute.
     */
    public function testExplanationCarriesDimensionNamesOnly(): void
    {
        $request = self::challengeRequest('login', '10.5.0.1', self::freshSession());
        $stack = self::$container->get('request_stack');
        $stack->push($request);
        $response = self::$container->get(ChallengeController::class)->challenge($request);
        $explanation = self::gateway()->currentDecisionExplanation();
        $stack->pop();

        self::assertSame(200, $response->getStatusCode(), 'precondition: the challenge was issued');
        self::assertArrayHasKey('nonce', json_decode((string) $response->getContent(), true));

        self::assertNotNull($explanation, 'abuse_first surfaces the decision explanation');
        self::assertContains('target', $explanation['dimensions'], 'the target dimension is named (the scope configures a target field)');
        foreach ($explanation['dimensions'] as $dimension) {
            self::assertContains($dimension, ['source', 'subnet', 'asn', 'session', 'principal', 'target', 'agent'], 'explanation dimensions are contract names only');
        }
        self::assertDoesNotMatchRegularExpression('/[0-9a-f]{16,}/', (string) json_encode($explanation), 'no pseudonym value ever enters the explanation');
        self::assertArrayHasKey('action', $explanation);
        self::assertIsString($explanation['action']);
        self::assertArrayHasKey('reasons', $explanation);
    }

    /**
     * Stage 5: the price model at work. The storm kernel below runs the
     * identical abuse_first composition over a dedicated namespace, a
     * quiet aggregate store. The global pressure ramp is driven into
     * the deep-but-not-emergency window. A trusted context (full bucket
     * credit) and an untrusted context (zero credit) then price onto
     * different rungs at the same score, observable in the issued
     * challenges.
     */
    public function testTrustedAndUntrustedContextsPriceDifferentlyAtTheSameScore(): void
    {
        // The storm kernel: the same abuse_first composition over its
        // own risk namespace, so the global pressure window is reached
        // from zero regardless of the identity legs before this test.
        $stormKernel = new AbuseFirstCompositionTestKernel('test', true, 'e2e-pricing-storm');
        $stormKernel->boot();
        $container = $stormKernel->getContainer()->get('test.service_container');
        $redis = $container->get('kiwi_e2e_redis');
        $redis->flushdb();
        $gateway = $container->get(RiskGateway::class);
        $trust = $container->get('kiwi_captcha.risk.trust');
        $identityFactory = $container->get('kiwi_captcha.risk.identity_factory');

        // The trust plane earns full bucket-local credit for the trusted
        // session in its current ASN bucket (trust.lua, the 10/8 bucket
        // of the fixture dataset), and the price context reads it back.
        $trustedSession = bin2hex(random_bytes(16));
        $trustedPseudonym = $identityFactory->sessionId($trustedSession);
        $credit = $trust->earn($trustedPseudonym, '10.44.0.1', 10000);
        self::assertSame(10000, $credit->rawTrust);
        self::assertSame(10000, $container->get('kiwi_captcha.risk.price_context')
            ->priceInputs(new PriceRequest(scope: 20, sourceIp: '10.44.0.1', session: $trustedPseudonym, principal: null))
            ->bucketTrust, 'the price context reads the earned bucket credit');

        // The pressure storm: identity-neutral deployment-overload events
        // drive the aggregate global pressure into the level-2/3 window,
        // deep enough that the pricing stage's pressure ramp bites. The
        // global hash exists after the first observation.
        $gateway->globalCapacityHit(20);
        $keys = $redis->keys('{kiwi:*}:risk:global');
        self::assertNotEmpty($keys, 'the risk-v1 global state hash exists');
        $globalKey = (string) $keys[0];
        $gnorm = function () use ($redis, $globalKey): int {
            $state = $redis->hgetall($globalKey);
            $sum = 0;
            foreach (['rf', 'rs', 'iss', 'bad', 'mal', 'rep', 'af'] as $channel) {
                $sum += (int) ($state[$channel] ?? 0);
            }

            return min(1000, intdiv($sum * 1000, 70000));
        };
        for ($i = 0; $i < 60 && $gnorm() < 640; $i++) {
            $gateway->globalCapacityHit(20);
        }
        $pressure = $gnorm();
        self::assertGreaterThanOrEqual(580, $pressure, 'the storm reached the pricing window');
        self::assertLessThan(900, $pressure, 'the storm stayed below the emergency cooldown level');

        $trusted = $gateway->preIssue('pricing_probe', '10.44.0.1', $trustedSession);
        $untrustedSession = bin2hex(random_bytes(16));
        $untrusted = $gateway->preIssue('pricing_probe', '10.44.0.2', $untrustedSession);

        // The same score: the two contexts differ only in bucket trust.
        self::assertLessThanOrEqual(30, abs($trusted->score - $untrusted->score), sprintf('scores must match for the pricing comparison (%d vs %d)', $trusted->score, $untrusted->score));
        self::assertGreaterThan(
            $trusted->action->rank(),
            $untrusted->action->rank(),
            sprintf('the untrusted context must price onto a stronger rung (trusted %s vs untrusted %s at score %d, gnorm %d)', $trusted->action->value, $untrusted->action->value, $untrusted->score, $pressure),
        );

        // The priced difference is observable in the issued challenges:
        // the trusted context keeps the sha rung, the untrusted one pays
        // a memory-hard rung.
        $issue = function (string $ip, string $session) use ($container): array {
            $request = JsonRequest::create(
                '/kiwi-captcha/challenge',
                'POST',
                [],
                [self::COOKIE => $session],
                [],
                ['REMOTE_ADDR' => $ip],
                '{"scope":"pricing_probe"}',
            );
            $stack = $container->get('request_stack');
            $stack->push($request);
            $response = $container->get(ChallengeController::class)->challenge($request);
            $stack->pop();

            return [json_decode((string) $response->getContent(), true), $response->getStatusCode()];
        };
        [$trustedChallenge, $trustedStatus] = $issue('10.44.0.3', $trustedSession);
        [$untrustedChallenge, $untrustedStatus] = $issue('10.44.0.4', $untrustedSession);
        self::assertSame(200, $trustedStatus, json_encode($trustedChallenge));
        self::assertSame(200, $untrustedStatus, json_encode($untrustedChallenge));
        self::assertSame('sha256', $trustedChallenge['algorithm'], sprintf('the trusted context keeps the sha rung (%s)', $trusted->action->value));
        self::assertSame('argon2id', $untrustedChallenge['algorithm'], 'the untrusted context pays a strictly stronger challenge');

        // The storm exporter counts both priced contexts: the sha rung of
        // the trusted context and the argon rung of the untrusted one.
        $metricsRequest = Request::create('https://captcha.example.com/metrics', 'GET');
        $metricsRequest->headers->set('Authorization', 'Bearer '.AbuseFirstCompositionTestKernel::METRICS_SECRET);
        $metricsBody = (string) $container->get(KiwiMetricsController::class)->metrics($metricsRequest)->getContent();
        self::assertMatchesRegularExpression('/kiwicaptcha_risk_decisions_total\{scope="20",action="sha[0-9]+",band="\d+"\} [1-9]/', $metricsBody, 'the trusted context\'s priced sha decision is counted');
        self::assertMatchesRegularExpression('/kiwicaptcha_risk_decisions_total\{scope="20",action="argon[0-9]+",band="\d+"\} [1-9]/', $metricsBody, 'the untrusted context\'s priced argon decision is counted');
    }

    /**
     * Stage 6: the metrics exporter counts the decisions of this whole
     * sequence (the redacted per-scope/action/band series).
     */
    public function testMetricsExporterCountsTheDecisions(): void
    {
        $request = Request::create('https://captcha.example.com/metrics', 'GET');
        $request->headers->set('Authorization', 'Bearer '.AbuseFirstCompositionTestKernel::METRICS_SECRET);
        $response = self::$container->get(KiwiMetricsController::class)->metrics($request);

        self::assertSame(200, $response->getStatusCode());
        $body = (string) $response->getContent();
        self::assertStringContainsString('kiwicaptcha_risk_decisions_total', $body);
        // The quarantine disposition of the marked identity and the
        // corroborated denial are both in the exporter's counters, by
        // canonical scope and action label.
        self::assertMatchesRegularExpression('/kiwicaptcha_risk_decisions_total\{scope="10",action="argon64",band="\d+"\} [1-9]/', $body, 'the non-spam mark floor is counted');
        self::assertMatchesRegularExpression('/kiwicaptcha_risk_decisions_total\{scope="10",action="deny",band="\d+"\} [1-9]/', $body, 'the corroborated denial is counted');
        // The priced probe decisions of the storm leg live in that
        // kernel's own exporter (asserted there); this exporter counts
        // this namespace's legs.
        self::assertMatchesRegularExpression('/kiwicaptcha_risk_decisions_total\{scope="10",action="sha[0-9]+",band="\d+"\} [1-9]/', $body, 'the plain pre-issue decisions are counted');
    }
}
