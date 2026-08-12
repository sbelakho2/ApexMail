<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests;

use BelConsulting\KiwiCaptchaBundle\Controller\ChallengeController;
use BelConsulting\KiwiCaptchaBundle\DependencyInjection\Configuration;
use BelConsulting\KiwiCaptchaBundle\Risk\ContinuityCookie;
use BelConsulting\KiwiCaptchaBundle\Risk\RiskFeedback;
use BelConsulting\KiwiCaptchaBundle\Risk\RiskGateway;
use BelConsulting\KiwiCaptchaBundle\Risk\RiskProfileResolver;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\FakeRiskStateStore;
use BelConsulting\KiwiCaptchaBundle\Tests\Kernel\RiskNoRedisTestKernel;
use BelConsulting\KiwiCaptchaBundle\Tests\Kernel\RiskTestKernel;
use BelConsulting\KiwiCaptchaBundle\Validator\Constraints\KiwiCaptchaValidator;
use KiwiCaptcha\Config;
use KiwiCaptcha\Issuer;
use KiwiCaptcha\PoWAlgorithm;
use KiwiCaptcha\Risk\AdaptiveRiskEngine;
use KiwiCaptcha\Risk\Network\CidrNetworkClassifier;
use KiwiCaptcha\Risk\RiskAction;
use KiwiCaptcha\Risk\RiskEventKind;
use KiwiCaptcha\Risk\RiskIdentityFactory;
use KiwiCaptcha\Risk\RiskKeys;
use KiwiCaptcha\Risk\RiskPolicy;
use KiwiCaptcha\Risk\RiskScorer;
use KiwiCaptcha\Risk\SignalVector;
use KiwiCaptcha\Risk\Storage\RedisRiskStateStore;
use KiwiCaptcha\Storage\ArrayStorage;
use KiwiCaptcha\VerifyError;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Config\Definition\Processor;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\KernelInterface;

/**
 * Adaptive risk engine integration: full-stack (engine + gateway + resolver +
 * continuity cookie + controller) driven by a fake risk state store, plus the
 * kernel wiring contract (risk-enabled boots and degrades, risk-without-redis
 * fails fast).
 */
final class RiskIntegrationTest extends TestCase
{
    private const SECRET = '0123456789abcdef0123456789abcdef';

    /**
     * The full bundle risk stack with an in-memory fake store.
     *
     * @return array{controller: ChallengeController, gateway: RiskGateway, store: \KiwiCaptcha\Risk\Storage\RiskStateStoreInterface, resolver: RiskProfileResolver}
     */
    private function stack(\KiwiCaptcha\Risk\Storage\RiskStateStoreInterface $store, array $scopeIds = ['login' => 1, 'signup' => 2]): array
    {
        $issuer = new Issuer(new Config(secretKey: self::SECRET, targetBits: 8, ttlSecs: 120), new ArrayStorage());
        $keys = RiskKeys::fromMaster(self::SECRET);
        $identityFactory = new RiskIdentityFactory($keys);
        $classifier = new CidrNetworkClassifier([]);
        $scorer = new RiskScorer();
        $policy = RiskPolicy::fromConfig([
            'version' => 1,
            'weights' => [],
            'scopes' => [
                1 => ['base_risk' => 100, 'minimum' => 'allow', 'post_solve_check' => false, 'degraded' => 'allow'],
                2 => ['base_risk' => 100, 'minimum' => 'allow', 'post_solve_check' => false, 'degraded' => 'allow'],
            ],
        ]);
        $engine = new AdaptiveRiskEngine($store, $classifier, $identityFactory, $scorer, $policy, $keys);
        $resolver = new RiskProfileResolver(PoWAlgorithm::Sha256, 8, 8);
        $gateway = new RiskGateway($engine, $classifier, $resolver, $scopeIds);
        $controller = new ChallengeController($issuer, null, true, $gateway, new ContinuityCookie());

        return ['controller' => $controller, 'gateway' => $gateway, 'store' => $store, 'resolver' => $resolver];
    }

    private function challengeRequest(): Request
    {
        return Request::create('/kiwi-captcha/challenge', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7'], '{"scope":"login"}');
    }

    public function testAllowIssuesConfiguredDifficultyAndContinuityCookie(): void
    {
        $stack = $this->stack(new FakeRiskStateStore());

        $response = $stack['controller']->challenge($this->challengeRequest());
        self::assertSame(200, $response->getStatusCode());

        $data = json_decode((string) $response->getContent(), true);
        self::assertSame('sha256', $data['algorithm']);
        self::assertSame(8, $data['targetBits']);

        // A NEW continuity session was minted and attached as a first-party
        // HttpOnly cookie (32 lowercase hex chars = 16 random bytes).
        $cookies = $response->headers->getCookies();
        self::assertCount(1, $cookies);
        self::assertSame('__Host-kiwi-session', $cookies[0]->getName());
        self::assertMatchesRegularExpression('/^[0-9a-f]{32}$/D', $cookies[0]->getValue());
        self::assertTrue($cookies[0]->isHttpOnly());
        self::assertSame('strict', $cookies[0]->getSameSite());
        self::assertFalse($cookies[0]->isSecure(), 'secure=null must follow the (http) request scheme');

        // The engine saw the pre-issue assessment and the post-issue signal.
        $events = array_map(static fn ($o): RiskEventKind => $o->event, $stack['store']->observations);
        self::assertSame([RiskEventKind::PreIssue, RiskEventKind::ChallengeIssued], $events);
    }

    public function testExistingContinuityCookieIsReused(): void
    {
        $stack = $this->stack(new FakeRiskStateStore());
        $session = bin2hex(random_bytes(16));
        $request = Request::create('/kiwi-captcha/challenge', 'POST', [], ['__Host-kiwi-session' => $session], [], ['REMOTE_ADDR' => '198.51.100.7'], '{"scope":"login"}');

        $response = $stack['controller']->challenge($request);
        self::assertSame(200, $response->getStatusCode());
        self::assertCount(0, $response->headers->getCookies(), 'an existing valid cookie must not be re-minted');

        // The engine derives the keyed session pseudonym from the raw cookie
        // value — the assessment must carry exactly that pseudonym.
        $observations = $stack['store']->observations;
        self::assertCount(2, $observations);
        $expected = (new RiskIdentityFactory(RiskKeys::fromMaster(self::SECRET)))->sessionId($session);
        self::assertSame($expected, $observations[0]->sessionId, 'the session signal must be fed into the assessment');
    }

    public function testDenyReturns429AndStoresNoChallenge(): void
    {
        // replay >= 700 is a hard deny with the ReplayTraffic reason.
        $stack = $this->stack(new FakeRiskStateStore(SignalVector::fromArray(['replay' => 700])));

        $response = $stack['controller']->challenge($this->challengeRequest());
        self::assertSame(429, $response->getStatusCode());
        $body = json_decode((string) $response->getContent(), true);
        self::assertSame('RISK_DENIED', $body['error']['code']);

        $events = array_map(static fn ($o): RiskEventKind => $o->event, $stack['store']->observations);
        self::assertSame([RiskEventKind::PreIssue], $events, 'a denied request must never mint a challenge');
    }

    public function testEscalatedActionRaisesShaDifficulty(): void
    {
        // source_fast 900 (+171), subnet_fast 1000 (+80), issue_debt 1000
        // (+150) on base 100 = 501 -> Sha20 band (450-599), no hard denies.
        $vector = SignalVector::fromArray(['source_fast' => 900, 'subnet_fast' => 1000, 'issue_debt' => 1000]);
        $stack = $this->stack(new FakeRiskStateStore($vector));

        $response = $stack['controller']->challenge($this->challengeRequest());
        self::assertSame(200, $response->getStatusCode());
        $data = json_decode((string) $response->getContent(), true);
        self::assertSame(20, $data['targetBits'], 'a Sha20 decision must escalate the challenge difficulty');
        self::assertSame('sha256', $data['algorithm']);
    }

    public function testStoreOutageDegradesToAllowAndStillIssues(): void
    {
        $store = new FakeRiskStateStore();
        $stack = $this->stack($store);
        $store->throwing = true;

        $response = $stack['controller']->challenge($this->challengeRequest());
        self::assertSame(200, $response->getStatusCode(), 'a risk backend outage must never break issuance (degraded allow)');

        // Two failed observations (pre-issue assessment + post-issue signal),
        // both degraded.
        $metrics = $stack['gateway']->metricsSnapshot();
        self::assertSame(2, $metrics['counters']['degraded:store'] ?? 0);
    }

    public function testInvalidClientIpSkipsRiskWithoutErroring(): void
    {
        $stack = $this->stack(new FakeRiskStateStore());
        $request = Request::create('/kiwi-captcha/challenge', 'POST', [], [], [], ['REMOTE_ADDR' => 'not-an-ip'], '{"scope":"login"}');

        // The risk assessment is skipped (invalid IP), and issuance itself
        // fails closed on the invalid binding IP with the existing 422.
        $response = $stack['controller']->challenge($request);
        self::assertSame(422, $response->getStatusCode());
        self::assertSame([], $stack['store']->observations, 'no risk observation may be recorded for an unparseable IP');
    }

    public function testSolveOutcomeFeedsPostSolveEvents(): void
    {
        $stack = $this->stack(new FakeRiskStateStore());
        $gateway = $stack['gateway'];

        $gateway->solveOutcome('login', '198.51.100.7', null, null);
        $gateway->solveOutcome('login', '198.51.100.7', null, VerifyError::InsufficientWork);
        $gateway->solveOutcome('login', '198.51.100.7', null, VerifyError::BadSignature);
        $gateway->solveOutcome('login', '198.51.100.7', null, VerifyError::Expired);
        $gateway->solveOutcome('login', '198.51.100.7', null, VerifyError::RecordNotFound);
        $gateway->solveOutcome('login', '198.51.100.7', null, VerifyError::CapacityExceeded);

        $events = array_map(static fn ($o): RiskEventKind => $o->event, $stack['store']->observations);
        self::assertSame([
            RiskEventKind::SolveSuccess,
            RiskEventKind::InvalidProof,
            RiskEventKind::MalformedToken,
            RiskEventKind::ExpiredChallenge,
            RiskEventKind::ReplayAttempt,
        ], $events, 'infrastructure failures (CapacityExceeded) must not be recorded as client abuse');
    }

    public function testRiskFeedbackMapsEveryCoreError(): void
    {
        $expectations = [
            [null, RiskEventKind::SolveSuccess],
            [VerifyError::Expired, RiskEventKind::ExpiredChallenge],
            [VerifyError::RecordNotFound, RiskEventKind::ReplayAttempt],
            [VerifyError::MalformedToken, RiskEventKind::MalformedToken],
            [VerifyError::MalformedRecord, RiskEventKind::MalformedToken],
            [VerifyError::BadSignature, RiskEventKind::MalformedToken],
            [VerifyError::CapacityExceeded, null],
            [VerifyError::WrongScope, RiskEventKind::InvalidProof],
            [VerifyError::IpMismatch, RiskEventKind::InvalidProof],
            [VerifyError::MissingClientIp, RiskEventKind::InvalidProof],
            [VerifyError::TooFast, RiskEventKind::InvalidProof],
            [VerifyError::InsufficientWork, RiskEventKind::InvalidProof],
            [VerifyError::UnsupportedArgon2Params, RiskEventKind::InvalidProof],
            [VerifyError::TooManyAttempts, RiskEventKind::InvalidProof],
            [VerifyError::TelemetryRejected, RiskEventKind::InvalidProof],
        ];
        foreach ($expectations as [$error, $event]) {
            self::assertSame($event, RiskFeedback::eventFor($error), sprintf('eventFor(%s)', $error?->value ?? 'null'));
        }
    }

    public function testProfileResolverEscalatesWithinAlgorithmFamily(): void
    {
        // SHA app, floor 8: sha actions escalate, argon actions approximate
        // with the strongest SHA profile, step_up = sha20.
        $resolver = new RiskProfileResolver(PoWAlgorithm::Sha256, 8, 8);
        self::assertNull($resolver->profileFor(RiskAction::Allow));
        self::assertSame(16, $resolver->profileFor(RiskAction::Sha16)?->targetBits);
        self::assertSame(18, $resolver->profileFor(RiskAction::Sha18)?->targetBits);
        self::assertSame(20, $resolver->profileFor(RiskAction::Sha20)?->targetBits);
        self::assertSame(20, $resolver->profileFor(RiskAction::Argon32)?->targetBits, 'argon action on a sha app = sha20');
        self::assertSame(PoWAlgorithm::Sha256, $resolver->profileFor(RiskAction::Argon32)?->algorithm);
        // StepUp is application-defined and handled by the controller
        // (403 STEP_UP_REQUIRED) — it must NEVER map to a challenge profile.
        try {
            $resolver->profileFor(RiskAction::StepUp);
            self::fail('StepUp must not map to a profile');
        } catch (\LogicException) {
            self::assertTrue(true);
        }

        // Escalation-only: a floor already at 20 never weakens or repeats.
        $maxed = new RiskProfileResolver(PoWAlgorithm::Sha256, 20, 8);
        self::assertNull($maxed->profileFor(RiskAction::Sha20));
        self::assertNull($maxed->profileFor(RiskAction::Argon64));
        // StepUp always throws (controller-handled), even at the max floor.

        // Argon app: argon actions map to real memory-hard profiles carrying
        // the app's argon2 difficulty; sha actions are no-ops (argon is
        // already at least as strong).
        $argon = new RiskProfileResolver(PoWAlgorithm::Argon2id, 20, 6);
        $argon32 = $argon->profileFor(RiskAction::Argon32);
        self::assertSame(PoWAlgorithm::Argon2id, $argon32?->algorithm);
        self::assertSame(32768, $argon32?->mKib);
        self::assertSame(6, $argon32?->targetBits);
        self::assertNull($argon->profileFor(RiskAction::Sha16));
        self::assertSame(65536, $argon->profileFor(RiskAction::Argon64)?->mKib);
        // StepUp always throws (controller-handled).
        try {
            $argon->profileFor(RiskAction::StepUp);
            self::fail('StepUp must not map to a profile');
        } catch (\LogicException) {
            self::assertTrue(true);
        }
    }

    public function testContinuityCookieValidatesAndMints(): void
    {
        $cookie = new ContinuityCookie();
        $request = Request::create('/challenge', 'POST');

        self::assertNull($cookie->read($request), 'absent cookie reads null');
        $request->cookies->set('__Host-kiwi-session', 'zzzz');
        self::assertNull($cookie->read($request), 'non-hex value reads null');
        $request->cookies->set('__Host-kiwi-session', 'abc');
        self::assertNull($cookie->read($request), 'short value reads null');

        $minted = $cookie->mint();
        self::assertMatchesRegularExpression('/^[0-9a-f]{32}$/D', $minted);
        $request->cookies->set('__Host-kiwi-session', $minted);
        self::assertSame($minted, $cookie->read($request));

        $http = $cookie->cookie($request, $minted);
        self::assertSame('__Host-kiwi-session', $http->getName());
        self::assertSame('strict', $http->getSameSite());
        self::assertSame(1800, $http->getExpiresTime() - time(), 'spec: 15-30 minute expiry');
        self::assertTrue($http->isHttpOnly());
        self::assertTrue($http->isHttpOnly());
        self::assertFalse($http->isSecure(), 'secure=null follows the http request');
        $https = Request::create('https://example.com/challenge', 'POST');
        self::assertTrue($cookie->cookie($https, $minted)->isSecure(), 'secure=null follows the https request');
    }

    public function testConfigTreeRiskDefaults(): void
    {
        $processed = (new Processor())->processConfiguration(new Configuration(), [['secret_key' => str_repeat('a', 32)]]);
        $risk = $processed['risk'];

        self::assertFalse($risk['enabled'], 'risk must be OFF by default (privacy posture, opt-in)');
        self::assertSame('%kernel.project_dir%', $risk['namespace']);
        self::assertNull($risk['redis_service']);
        self::assertSame(900, $risk['source_epoch_secs']);
        self::assertSame(1800, $risk['state_ttl_secs']);
        self::assertSame(60, $risk['dedupe_ttl_secs']);
        self::assertSame(1, $risk['policy_version']);
        self::assertSame(8000, $risk['saturations']['src_fast']);
        self::assertSame(70000, $risk['saturations']['global']);
        self::assertSame(190, $risk['weights']['source_fast']);
        self::assertSame([1 => 'sha16', 2 => 'sha18', 3 => 'sha20', 4 => 'sha20'], $risk['global_floors']);
        // Spec section 31 defaults.
        self::assertSame('sha16', $risk['scopes']['signup']['minimum']);
        self::assertSame('sha18', $risk['scopes']['login']['minimum']);
        self::assertSame('sha18', $risk['scopes']['password_reset']['minimum']);
        self::assertSame('sha20', $risk['scopes']['admin_login']['minimum']);
        self::assertSame('sha20', $risk['scopes']['financial_action']['minimum']);
        self::assertSame(120, $risk['scopes']['login']['base_risk']);
        self::assertTrue($risk['scopes']['login']['post_solve_check']);
        self::assertNull($risk['scopes']['login']['id']);
        self::assertNull($risk['master_secret']);
        self::assertTrue($risk['global_pressure']['enabled']);
        self::assertTrue($risk['argon_capacity']['enabled']);
        self::assertSame(100, $risk['hard_limits']['source_per_second']);
        self::assertFalse($risk['calibration']['enabled']);
        self::assertNull($risk['network_classifier_file']);
        self::assertSame('__Host-kiwi-session', $risk['continuity_cookie']['name']);
        self::assertSame(1800, $risk['continuity_cookie']['ttl_secs']);
        self::assertNull($risk['continuity_cookie']['secure']);
        self::assertNull($risk['network_classifier_file']);
    }

    public function testRiskEnabledKernelBootsIssuesAndDegrades(): void
    {
        $kernel = new RiskTestKernel('test', true);
        $kernel->boot();
        $container = $kernel->getContainer();

        // Wiring contract: the engine and gateway are public services, the
        // controller and validator are wired with them.
        self::assertTrue($container->has('kiwi_captcha.risk.engine'));
        self::assertInstanceOf(AdaptiveRiskEngine::class, $container->get('kiwi_captcha.risk.engine'));
        self::assertInstanceOf(RiskGateway::class, $container->get(RiskGateway::class));
        self::assertInstanceOf(ContinuityCookie::class, $container->get(ContinuityCookie::class));
        self::assertInstanceOf(KiwiCaptchaValidator::class, $container->get(KiwiCaptchaValidator::class));
        $controller = $container->get(ChallengeController::class);
        self::assertInstanceOf(ChallengeController::class, $controller);

        // The fake Redis does not speak the risk-v1 EVALSHA protocol -> the
        // engine degrades (store failure -> degraded allow) and issuance
        // still succeeds, cookie included.
        $request = Request::create('/kiwi-captcha/challenge', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7'], '{"scope":"login"}');
        $response = $controller->challenge($request);
        self::assertSame(200, $response->getStatusCode());
        self::assertCount(1, $response->headers->getCookies());

        $gateway = $container->get(RiskGateway::class);
        $metrics = $gateway->metricsSnapshot();
        self::assertSame(2, $metrics['counters']['degraded:store'] ?? 0, 'the fake backend must trigger the degraded path');
        $kernel->shutdown();
    }

    public function testRiskEnabledWithoutRedisFailsFast(): void
    {
        $this->expectException(\LogicException::class);
        $this->expectExceptionMessageMatches('/risk\.enabled requires a Redis client/');

        $kernel = new RiskNoRedisTestKernel('test', true);
        $kernel->boot();
        $kernel->shutdown();
    }

    public function testRealRedisFullStackAllowPath(): void
    {
        $url = getenv('KC_REDIS_URL');
        if ($url === false || $url === '') {
            self::markTestSkipped('KC_REDIS_URL not set — real-Redis risk integration test skipped');
        }
        $client = RedisRiskStateStore::createClient($url);
        try {
            $client->ping();
        } catch (\Throwable $e) {
            self::markTestSkipped('Redis unreachable: '.$e->getMessage());
        }
        $client->flushdb();

        // Real RedisRiskStateStore + full bundle stack: an idle source stays
        // on the allow path across repeated issuances, and every request is
        // actually observed in Redis (source/debt counters).
        $store = new RedisRiskStateStore($client, 'ci-risk-bundle', 900, 900, 1800, 86400, 60, 60000);
        $stack = $this->stack($store);
        $controller = $stack['controller'];

        $targets = [];
        for ($i = 0; $i < 3; $i++) {
            $response = $controller->challenge($this->challengeRequest());
            self::assertSame(200, $response->getStatusCode(), sprintf('issuance %d must stay allowed', $i + 1));
            $data = json_decode((string) $response->getContent(), true);
            self::assertSame('sha256', $data['algorithm']);
            $targets[] = $data['targetBits'];
        }
        // Repeated issuance must NEVER weaken below the issued floor: the
        // first request is idle (default 8), subsequent requests escalate
        // monotonically (never below 8, never above the sha ceiling 20).
        self::assertGreaterThanOrEqual(8, $targets[0]);
        for ($i = 1; $i < 3; $i++) {
            self::assertGreaterThanOrEqual($targets[$i - 1], $targets[$i], sprintf('issuance %d must not weaken below the previous floor', $i + 1));
            self::assertLessThanOrEqual(20, $targets[$i]);
        }

        // The real store ran the canonical risk-v1 Lua: decision counters
        // exist, one decision per request was recorded, and the first
        // (idle) request was an allow.
        $metrics = $stack['gateway']->metricsSnapshot();
        self::assertArrayHasKey('decisions:1:allow:1', $metrics['counters']);
        self::assertSame(1, $metrics['counters']['decisions:1:allow:1']);
        $totalDecisions = 0;
        foreach ($metrics['counters'] as $key => $count) {
            if (str_starts_with((string) $key, 'decisions:1:')) {
                $totalDecisions += $count;
            }
        }
        self::assertGreaterThanOrEqual(3, $totalDecisions, 'at least one decision per request');

        // Cleanup the test namespace.
        foreach ($client->keys('{kiwi:ci-risk-bundle}:*') ?: [] as $key) {
            $client->del($key);
        }
        $client->disconnect();
    }
}
