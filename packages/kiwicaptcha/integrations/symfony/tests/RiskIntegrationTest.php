<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests;

use BelConsulting\KiwiCaptchaBundle\Controller\ChallengeController;
use BelConsulting\KiwiCaptchaBundle\DependencyInjection\Configuration;
use BelConsulting\KiwiCaptchaBundle\Risk\ContinuityCookie;
use BelConsulting\KiwiCaptchaBundle\Risk\ResourcePressureProviderInterface;
use BelConsulting\KiwiCaptchaBundle\Risk\RiskFeedback;
use BelConsulting\KiwiCaptchaBundle\Risk\RiskGateway;
use BelConsulting\KiwiCaptchaBundle\Risk\RiskProfileResolver;
use BelConsulting\KiwiCaptchaBundle\Security\IssuanceCounter;
use BelConsulting\KiwiCaptchaBundle\Security\IssuanceRateLimiter;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\FakePredisClient;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\FakePrincipalResolver;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\FakeRiskStateStore;
use BelConsulting\KiwiCaptchaBundle\Tests\Kernel\RiskNoRedisTestKernel;
use BelConsulting\KiwiCaptchaBundle\Tests\Kernel\RiskTestKernel;
use BelConsulting\KiwiCaptchaBundle\Validator\Constraints\KiwiCaptcha;
use BelConsulting\KiwiCaptchaBundle\Validator\Constraints\KiwiCaptchaValidator;
use KiwiCaptcha\Config;
use KiwiCaptcha\Issuer;
use KiwiCaptcha\PoWAlgorithm;
use KiwiCaptcha\Risk\AdaptiveRiskEngine;
use KiwiCaptcha\Risk\Calibration\AggregateCalibrator;
use KiwiCaptcha\Risk\EventReceipt;
use KiwiCaptcha\Risk\Network\CidrNetworkClassifier;
use KiwiCaptcha\Risk\ResourcePressure;
use KiwiCaptcha\Risk\RiskAction;
use KiwiCaptcha\Risk\RiskEventKind;
use KiwiCaptcha\Risk\RiskIdentityFactory;
use KiwiCaptcha\Risk\RiskKeys;
use KiwiCaptcha\Risk\RiskPolicy;
use KiwiCaptcha\Risk\RiskReason;
use KiwiCaptcha\Risk\RiskScorer;
use KiwiCaptcha\Risk\SignalVector;
use KiwiCaptcha\Risk\Storage\ProcessEmergencyCap;
use KiwiCaptcha\Risk\Storage\RedisRiskStateStore;
use KiwiCaptcha\Storage\ArrayStorage;
use KiwiCaptcha\Verifier;
use KiwiCaptcha\VerifyError;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Config\Definition\Processor;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\JsonRequest;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Component\HttpKernel\KernelInterface;
use Symfony\Component\Validator\ConstraintValidatorFactory;
use Symfony\Component\Validator\Validation;

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
            'version' => RiskPolicy::CONTRACT_VERSION,
            'weights' => [],
            'scopes' => [
                1 => ['base_risk' => 100, 'minimum' => 'allow', 'post_solve_check' => false, 'degraded' => 'allow'],
                2 => ['base_risk' => 100, 'minimum' => 'allow', 'post_solve_check' => false, 'degraded' => 'allow'],
            ],
        ]);
        $engine = new AdaptiveRiskEngine($store, $classifier, $identityFactory, $scorer, $policy, $keys);
        $resolver = new RiskProfileResolver(PoWAlgorithm::Sha256, 8);
        $gateway = new RiskGateway($engine, $classifier, $resolver, $scopeIds, policy: $policy);
        $controller = new ChallengeController($issuer, null, true, $gateway, new ContinuityCookie());

        return ['controller' => $controller, 'gateway' => $gateway, 'store' => $store, 'resolver' => $resolver];
    }

    private function challengeRequest(): Request
    {
        return JsonRequest::create('/kiwi-captcha/challenge', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7'], '{"scope":"login"}');
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
        $request = JsonRequest::create('/kiwi-captcha/challenge', 'POST', [], ['__Host-kiwi-session' => $session], [], ['REMOTE_ADDR' => '198.51.100.7'], '{"scope":"login"}');

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

        // The denial already scored the evidence (the PreIssue assessment +
        // decision) — NO extra rate-limit event is recorded (double-counting
        // removed); no challenge is ever minted.
        $events = array_map(static fn ($o): RiskEventKind => $o->event, $stack['store']->observations);
        self::assertSame([RiskEventKind::PreIssue], $events, 'a denied request must never mint a challenge nor double-count the denial');
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

        // The pre-issue assessment degraded (store failure -> degraded
        // allow); the post-issue feedback (record_feedback) degrades
        // silently (zero signals, no decision, no metric) — one degraded
        // decision per request.
        $metrics = $stack['gateway']->metricsSnapshot();
        self::assertSame(1, $metrics['counters']['degraded:store'] ?? 0);
    }

    public function testInvalidClientIpSkipsRiskWithoutErroring(): void
    {
        $stack = $this->stack(new FakeRiskStateStore());
        $request = JsonRequest::create('/kiwi-captcha/challenge', 'POST', [], [], [], ['REMOTE_ADDR' => 'not-an-ip'], '{"scope":"login"}');

        // The risk assessment is skipped (invalid IP -> the scope's degraded
        // decision applies instead of a live assessment; degraded=allow here
        // so issuance proceeds), and issuance itself fails closed on the
        // invalid binding IP with the existing 422.
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
            [VerifyError::AlreadyConsumed, RiskEventKind::ReplayAttempt],
            [VerifyError::MalformedToken, RiskEventKind::MalformedToken],
            [VerifyError::MalformedRecord, RiskEventKind::MalformedToken],
            [VerifyError::BadSignature, RiskEventKind::MalformedToken],
            [VerifyError::CapacityExceeded, null],
            [VerifyError::AdmissionUnavailable, null],
            [VerifyError::StorageUnavailable, null],
            [VerifyError::ConsumeIndeterminate, null],
            [VerifyError::WrongPolicyVersion, null],
            [VerifyError::WrongIssuer, null],
            [VerifyError::WrongRegion, null],
            [VerifyError::UnknownKid, null],
            [VerifyError::UnsupportedArgon2Params, null],
            [VerifyError::WrongScope, RiskEventKind::InvalidProof],
            [VerifyError::RequestBindingMismatch, RiskEventKind::InvalidProof],
            [VerifyError::IpMismatch, RiskEventKind::InvalidProof],
            [VerifyError::MissingClientIp, RiskEventKind::InvalidProof],
            [VerifyError::TooFast, RiskEventKind::InvalidProof],
            [VerifyError::InsufficientWork, RiskEventKind::InvalidProof],
            [VerifyError::TooManyAttempts, RiskEventKind::InvalidProof],
            [VerifyError::TelemetryRejected, RiskEventKind::InvalidProof],
        ];
        foreach ($expectations as [$error, $event]) {
            self::assertSame($event, RiskFeedback::eventFor($error), sprintf('eventFor(%s)', $error?->value ?? 'null'));
        }
    }

    public function testProfileResolverEscalatesWithinAlgorithmFamily(): void
    {
        // SHA app, floor 8: sha actions escalate; argon actions map to the
        // fixed-envelope ladder: ALL three share the
        // server-controlled memory envelope (default 16384 KiB, t=3, p=1) —
        // risk escalates the target difficulty (expected nonce search space
        // 1/4/8), never the server verification cost — regardless of the
        // app algorithm: the core's issueWithProfile accepts a profile
        // directly.
        $resolver = new RiskProfileResolver(PoWAlgorithm::Sha256, 8);
        self::assertNull($resolver->profileFor(RiskAction::Allow));
        self::assertSame(16, $resolver->profileFor(RiskAction::Sha16)?->targetBits);
        self::assertSame(18, $resolver->profileFor(RiskAction::Sha18)?->targetBits);
        self::assertSame(20, $resolver->profileFor(RiskAction::Sha20)?->targetBits);
        $argon16 = $resolver->profileFor(RiskAction::Argon16);
        self::assertSame(PoWAlgorithm::Argon2id, $argon16?->algorithm);
        self::assertSame(1, $argon16?->targetBits, 'Argon16 escalates to the ladder rung 1');
        self::assertSame(16384, $argon16?->mKib, 'argon profiles share the FIXED verification envelope');
        self::assertSame(3, $argon16?->t);
        self::assertSame(1, $argon16?->p);
        $argon32 = $resolver->profileFor(RiskAction::Argon32);
        self::assertSame(PoWAlgorithm::Argon2id, $argon32?->algorithm);
        self::assertSame(16384, $argon32?->mKib, 'Argon32 must NOT raise the memory (fixed envelope)');
        self::assertSame(4, $argon32?->targetBits, 'Argon32 escalates the target difficulty to 4');
        $argon64 = $resolver->profileFor(RiskAction::Argon64);
        self::assertSame(16384, $argon64?->mKib, 'Argon64 must NOT raise the memory (fixed envelope)');
        self::assertSame(8, $argon64?->targetBits, 'Argon64 escalates the target difficulty to 8');
        // StepUp is application-defined and handled by the controller
        // (403 step_UP_required) — it must never map to a challenge profile.
        try {
            $resolver->profileFor(RiskAction::StepUp);
            self::fail('StepUp must not map to a profile');
        } catch (\LogicException) {
            self::assertTrue(true);
        }

        // Escalation-only: a floor already at 20 never weakens or repeats,
        // but an argon action still maps to a real argon profile (a sha-only
        // deployment can still issue argon work via the risk ladder).
        $maxed = new RiskProfileResolver(PoWAlgorithm::Sha256, 20);
        self::assertNull($maxed->profileFor(RiskAction::Sha20));
        self::assertSame(PoWAlgorithm::Argon2id, $maxed->profileFor(RiskAction::Argon64)?->algorithm);

        // Argon app: argon actions map to the fixed-envelope profiles; sha
        // actions are no-ops (argon is already at least as strong).
        $argon = new RiskProfileResolver(PoWAlgorithm::Argon2id, 20);
        self::assertSame(4, $argon->profileFor(RiskAction::Argon32)?->targetBits, 'the app argon2 difficulty must NOT leak into risk profiles');
        self::assertNull($argon->profileFor(RiskAction::Sha16));
        self::assertSame(16384, $argon->profileFor(RiskAction::Argon64)?->mKib, 'the envelope applies to an argon2id deployment too');
        // StepUp always throws (controller-handled).
        try {
            $argon->profileFor(RiskAction::StepUp);
            self::fail('StepUp must not map to a profile');
        } catch (\LogicException) {
            self::assertTrue(true);
        }
    }

    /**
     * Core invariant: the server verification cost ceiling is
     * risk-independent. Even the maximum adaptive escalation (Argon64) keeps
     * the memory at the fixed envelope — risk only raises the expected nonce
     * search space, which stays within the widget-solvable ceiling (target
     * bits <= 20).
     */
    public function testMaximumAdaptiveEscalationKeepsMemoryAtTheEnvelope(): void
    {
        $resolver = new RiskProfileResolver(PoWAlgorithm::Sha256, 8, 16384, [1, 4, 8]);
        $max = $resolver->profileFor(RiskAction::Argon64);
        self::assertNotNull($max);
        self::assertSame(16384, $max->mKib, 'the server verification memory must stay at the envelope under maximum escalation');
        self::assertSame(3, $max->t);
        self::assertSame(1, $max->p);
        self::assertLessThanOrEqual(20, $max->targetBits, 'the challenge target difficulty stays within the widget-solvable ceiling');
        self::assertSame(8, $max->targetBits);

        // A custom envelope is honored across ALL rungs — the ceiling is the
        // configured envelope, never the action.
        $custom = new RiskProfileResolver(PoWAlgorithm::Sha256, 8, 32768, [2, 6, 10]);
        foreach ([RiskAction::Argon16, RiskAction::Argon32, RiskAction::Argon64] as $action) {
            $profile = $custom->profileFor($action);
            self::assertSame(32768, $profile?->mKib, sprintf('%s must stay on the custom envelope', $action->value));
            self::assertLessThanOrEqual(20, $profile?->targetBits ?? 0);
        }

        // The ladder needs exactly 3 rungs.
        try {
            new RiskProfileResolver(PoWAlgorithm::Sha256, 8, 16384, [1, 4]);
            self::fail('a 2-entry ladder must be refused');
        } catch (\InvalidArgumentException) {
            self::assertTrue(true);
        }
        try {
            new RiskProfileResolver(PoWAlgorithm::Sha256, 8, 16384, [1, 4, 8, 12]);
            self::fail('a 4-entry ladder must be refused');
        } catch (\InvalidArgumentException) {
            self::assertTrue(true);
        }
    }

    public function testContinuityCookieValidatesAndMints(): void
    {
        $cookie = new ContinuityCookie();
        $request = JsonRequest::create('/challenge', 'POST');

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
        $https = JsonRequest::create('https://example.com/challenge', 'POST');
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
        self::assertSame(1, $risk['policy_version'], 'policy_version is the CHALLENGE security-policy epoch — default 1, independent of the risk-v1 contract version ('.RiskPolicy::CONTRACT_VERSION.')');
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
        self::assertSame(10000, $risk['hard_limits']['process_per_second']);
        self::assertArrayNotHasKey('source_per_second', $risk['hard_limits']);
        self::assertArrayNotHasKey('global_per_second', $risk['hard_limits']);
        self::assertFalse($risk['calibration']['enabled']);
        self::assertSame(86400, $risk['calibration']['outcome_receipt_ttl_secs'], 'the outcome/calibration receipt + outcome-ledger lifetime defaults to 86400 (24 h — long enough for fraud review / moderation / chargeback labels)');
        self::assertSame(300, $risk['nonce_to_decision_ttl_secs'], 'the nonce->decision handle TTL defaults to 300 (risk.nonce_to_decision_ttl_secs, independent of the outcome lifetime)');
        self::assertSame('random_sample', $risk['calibration']['mode'], 'the label-selection contract defaults to random_sample');
        self::assertSame(100000, $risk['calibration']['sampling_probability_ppm'], 'sampling_probability_ppm defaults to 100000 (10%)');
        self::assertNull($risk['network_classifier_file']);
        self::assertSame('__Host-kiwi-session', $risk['continuity_cookie']['name']);
        self::assertSame(1800, $risk['continuity_cookie']['ttl_secs']);
        self::assertNull($risk['continuity_cookie']['secure']);
        self::assertNull($risk['network_classifier_file']);
        self::assertSame('minimum', $risk['unknown_scope']['mode']);
        self::assertSame('strict', $risk['continuity_cookie']['samesite'], 'samesite is defined exactly once, default strict');
        self::assertTrue($risk['continuity_cookie']['http_only']);
        // The fixed Argon2id verification-memory envelope and the
        // target-difficulty escalation ladder.
        self::assertSame(16384, $risk['argon_verification_memory_kib'], 'the adaptive Argon memory envelope defaults to 16384 KiB');
        self::assertSame([1, 4, 8], $risk['argon_escalation_target_bits'], 'the default Argon target-bits ladder is [1, 4, 8]');
        // The security-epoch monitor's short cache window.
        self::assertSame(1, $risk['security_epoch_cache_secs'], 'the central security-epoch read is cached 1 s by default');
        // The Ed25519 receipt signer is OFF by default.
        self::assertNull($risk['result_receipt_signing_key']);
        // The per-scope issuance cap is OFF by default.
        self::assertSame(0, $risk['max_challenges_per_scope_per_minute'], 'the per-scope issuance cap defaults to unlimited');
    }

    public function testArgonVerificationMemoryKibBounds(): void
    {
        $process = static fn (array $risk): array => (new Processor())->processConfiguration(new Configuration(), [[
            'secret_key' => str_repeat('a', 32),
            'risk' => $risk,
        ]])['risk'];

        self::assertSame(1024, $process(['argon_verification_memory_kib' => 1024])['argon_verification_memory_kib']);
        self::assertSame(65536, $process(['argon_verification_memory_kib' => 65536])['argon_verification_memory_kib']);
        foreach ([1023, 65537, 0] as $bad) {
            try {
                $process(['argon_verification_memory_kib' => $bad]);
                self::fail("envelope $bad must be rejected");
            } catch (\Symfony\Component\Config\Definition\Exception\InvalidConfigurationException) {
                self::assertTrue(true);
            }
        }
    }

    public function testArgonEscalationTargetBitsValidation(): void
    {
        $process = static fn (array $risk): array => (new Processor())->processConfiguration(new Configuration(), [[
            'secret_key' => str_repeat('a', 32),
            'risk' => $risk,
        ]])['risk'];

        self::assertSame([2, 6, 10], $process(['argon_escalation_target_bits' => [2, 6, 10]])['argon_escalation_target_bits']);
        // compile-time ladder validation: the rungs must satisfy
        // 1 <= rung1 < rung2 < rung3 <= Config::MAX_argon2_target_bits —
        // a non-monotone ladder or a rung above the core's Argon2id
        // widget ceiling is refused at configuration time (never deferred
        // to an issuance-time profile refusal).
        self::assertSame([1, 4, Config::MAX_ARGON2_TARGET_BITS], $process(['argon_escalation_target_bits' => [1, 4, Config::MAX_ARGON2_TARGET_BITS]])['argon_escalation_target_bits']);
        // Exactly 3 entries.
        foreach ([[1, 4], [1, 4, 8, 12], []] as $bad) {
            try {
                $process(['argon_escalation_target_bits' => $bad]);
                self::fail('a ladder that is not exactly 3 entries must be rejected');
            } catch (\Symfony\Component\Config\Definition\Exception\InvalidConfigurationException) {
                self::assertTrue(true);
            }
        }
        // Each rung within 1..Config::MAX_argon2_target_bits, strictly
        // increasing.
        foreach ([[0, 4, 8], [1, 4, Config::MAX_ARGON2_TARGET_BITS + 1], [20, 20, 20], [1, 4, 4], [5, 5, 10]] as $bad) {
            try {
                $process(['argon_escalation_target_bits' => $bad]);
                self::fail('a rung outside 1..'.Config::MAX_ARGON2_TARGET_BITS.' or a non-monotone ladder must be rejected: '.json_encode($bad));
            } catch (\Symfony\Component\Config\Definition\Exception\InvalidConfigurationException) {
                self::assertTrue(true);
            }
        }
    }

    public function testSecurityEpochCacheSecsBounds(): void
    {
        $process = static fn (array $risk): array => (new Processor())->processConfiguration(new Configuration(), [[
            'secret_key' => str_repeat('a', 32),
            'risk' => $risk,
        ]])['risk'];

        self::assertSame(30, $process(['security_epoch_cache_secs' => 30])['security_epoch_cache_secs']);
        foreach ([0, 31] as $bad) {
            try {
                $process(['security_epoch_cache_secs' => $bad]);
                self::fail("cache window $bad must be rejected");
            } catch (\Symfony\Component\Config\Definition\Exception\InvalidConfigurationException) {
                self::assertTrue(true);
            }
        }
    }

    public function testResultReceiptSigningKeyAcceptsAValidSeed(): void
    {
        $seed = base64_encode(random_bytes(32));
        $processed = (new Processor())->processConfiguration(new Configuration(), [[
            'secret_key' => str_repeat('a', 32),
            'risk' => ['result_receipt_signing_key' => $seed],
        ]]);

        self::assertSame($seed, $processed['risk']['result_receipt_signing_key']);
    }

    public function testMaxChallengesPerScopePerMinuteBounds(): void
    {
        $process = static fn (array $risk): array => (new Processor())->processConfiguration(new Configuration(), [[
            'secret_key' => str_repeat('a', 32),
            'risk' => $risk,
        ]])['risk'];

        self::assertSame(60, $process(['max_challenges_per_scope_per_minute' => 60])['max_challenges_per_scope_per_minute']);
        try {
            $process(['max_challenges_per_scope_per_minute' => -1]);
            self::fail('a negative per-scope cap must be rejected');
        } catch (\Symfony\Component\Config\Definition\Exception\InvalidConfigurationException) {
            self::assertTrue(true);
        }
    }

    public function testUnknownScopeModeMinimumIsTheDefault(): void
    {
        $processed = (new Processor())->processConfiguration(new Configuration(), [[
            'secret_key' => str_repeat('a', 32),
        ]]);

        self::assertSame('minimum', $processed['risk']['unknown_scope']['mode']);
    }

    public function testUnknownScopeModeBaselineIsAccepted(): void
    {
        $processed = (new Processor())->processConfiguration(new Configuration(), [[
            'secret_key' => str_repeat('a', 32),
            'risk' => ['unknown_scope' => ['mode' => 'baseline']],
        ]]);

        self::assertSame('baseline', $processed['risk']['unknown_scope']['mode']);
    }

    public function testUnknownScopeModeRejectIsAccepted(): void
    {
        $processed = (new Processor())->processConfiguration(new Configuration(), [[
            'secret_key' => str_repeat('a', 32),
            'risk' => ['unknown_scope' => ['mode' => 'reject']],
        ]]);

        self::assertSame('reject', $processed['risk']['unknown_scope']['mode']);
    }

    public function testUnknownScopeModeMinimumIsAccepted(): void
    {
        $processed = (new Processor())->processConfiguration(new Configuration(), [[
            'secret_key' => str_repeat('a', 32),
            'risk' => ['unknown_scope' => ['mode' => 'minimum']],
        ]]);

        self::assertSame('minimum', $processed['risk']['unknown_scope']['mode']);
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

        // The fake Redis does not speak the risk-v1 evalsha protocol -> the
        // engine degrades (store failure -> degraded allow) and issuance
        // still succeeds, cookie included.
        $request = JsonRequest::create('/kiwi-captcha/challenge', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7'], '{"scope":"login"}');
        $response = $controller->challenge($request);
        self::assertSame(200, $response->getStatusCode());
        self::assertCount(1, $response->headers->getCookies());

        $gateway = $container->get(RiskGateway::class);
        $metrics = $gateway->metricsSnapshot();
        self::assertSame(1, $metrics['counters']['degraded:store'] ?? 0, 'the fake backend must trigger the degraded path (the feedback path degrades silently)');
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
        // actually observed in Redis (source/debt counters). Named arguments
        // after stateTtlSecs so the sessionTtlSecs position in the package
        // constructor cannot drift from this construction.
        $store = new RedisRiskStateStore(
            $client,
            'ci-risk-bundle',
            900,
            900,
            1800,
            principalTtlSecs: 86400,
            sessionTtlSecs: 1800,
            dedupeTtlSecs: 60,
            hysteresisMs: 60000,
        );
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
        // Repeated issuance must never weaken below the issued floor: the
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

    public function testUnknownScopeRejectModeDeniesWithoutIssuing(): void
    {
        // unknown_scope.mode=reject: true rejection — the controller returns
        // the risk-denied 429 (same as a Deny decision) without issuing any
        // challenge and without falling back to a baseline profile. The
        // rateLimitHit feedback for the refusal is skipped inside the
        // gateway (unknown scope — never an exception).
        $issuer = new Issuer(new Config(secretKey: self::SECRET, targetBits: 8, ttlSecs: 120), new ArrayStorage());
        $keys = RiskKeys::fromMaster(self::SECRET);
        $identityFactory = new RiskIdentityFactory($keys);
        $classifier = new CidrNetworkClassifier([]);
        $policy = RiskPolicy::fromConfig([
            'version' => RiskPolicy::CONTRACT_VERSION,
            'weights' => [],
            'scopes' => [
                1 => ['base_risk' => 100, 'minimum' => 'allow', 'post_solve_check' => false, 'degraded' => 'allow'],
            ],
        ]);
        $store = new FakeRiskStateStore();
        $engine = new AdaptiveRiskEngine($store, $classifier, $identityFactory, new RiskScorer(), $policy, $keys);
        $resolver = new RiskProfileResolver(PoWAlgorithm::Sha256, 8);
        $gateway = new RiskGateway($engine, $classifier, $resolver, ['login' => 1], null, null, [], 'reject');
        $controller = new ChallengeController($issuer, null, true, $gateway, new ContinuityCookie());

        $request = JsonRequest::create('/kiwi-captcha/challenge', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7'], '{"scope":"weird_unconfigured_scope"}');
        $response = $controller->challenge($request);
        self::assertSame(429, $response->getStatusCode());
        $data = json_decode((string) $response->getContent(), true);
        self::assertSame('RISK_DENIED', $data['error']['code']);
        self::assertSame([], $store->observations, 'an unknown scope in reject mode must never touch the adaptive engine');
    }

    public function testUnknownScopeBaselineModeIssuesDefaultProfileWithoutRisk(): void
    {
        // unknown_scope.mode=baseline (the default): the gateway throws
        // UnknownScopeException, the controller catches it and issues the
        // default challenge profile — the adaptive engine is never touched.
        $issuer = new Issuer(new Config(secretKey: self::SECRET, targetBits: 8, ttlSecs: 120), new ArrayStorage());
        $keys = RiskKeys::fromMaster(self::SECRET);
        $identityFactory = new RiskIdentityFactory($keys);
        $classifier = new CidrNetworkClassifier([]);
        $policy = RiskPolicy::fromConfig([
            'version' => RiskPolicy::CONTRACT_VERSION,
            'weights' => [],
            'scopes' => [
                1 => ['base_risk' => 100, 'minimum' => 'allow', 'post_solve_check' => false, 'degraded' => 'allow'],
            ],
        ]);
        $store = new FakeRiskStateStore();
        $engine = new AdaptiveRiskEngine($store, $classifier, $identityFactory, new RiskScorer(), $policy, $keys);
        $resolver = new RiskProfileResolver(PoWAlgorithm::Sha256, 8);
        $gateway = new RiskGateway($engine, $classifier, $resolver, ['login' => 1], null, null, [], 'baseline');
        $controller = new ChallengeController($issuer, null, true, $gateway, new ContinuityCookie());

        $request = JsonRequest::create('/kiwi-captcha/challenge', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7'], '{"scope":"weird_unconfigured_scope"}');
        $response = $controller->challenge($request);
        self::assertSame(200, $response->getStatusCode());
        $data = json_decode((string) $response->getContent(), true);
        self::assertSame(8, $data['targetBits'], 'an unknown scope in baseline mode must issue the default profile');
        self::assertSame([], $store->observations, 'the adaptive engine must never be consulted for an unknown scope in baseline mode');
    }

    public function testUnknownScopeMinimumModeUsesSyntheticPolicy(): void
    {
        // unknown_scope.mode=minimum: unknown scopes are assessed under the
        // synthetic policy (base_risk 100, minimum sha20, degraded sha20)
        // via a reserved scope id.
        $issuer = new Issuer(new Config(secretKey: self::SECRET, targetBits: 8, ttlSecs: 120), new ArrayStorage());
        $keys = RiskKeys::fromMaster(self::SECRET);
        $identityFactory = new RiskIdentityFactory($keys);
        $classifier = new CidrNetworkClassifier([]);
        $policy = RiskPolicy::fromConfig([
            'version' => RiskPolicy::CONTRACT_VERSION,
            'weights' => [],
            'scopes' => [
                1 => ['base_risk' => 100, 'minimum' => 'allow', 'post_solve_check' => false, 'degraded' => 'allow'],
                // The synthetic unknown-scope entry the extension reserves.
                42 => ['base_risk' => 100, 'minimum' => 'sha20', 'post_solve_check' => false, 'degraded' => 'sha20'],
            ],
        ]);
        $store = new FakeRiskStateStore();
        $engine = new AdaptiveRiskEngine($store, $classifier, $identityFactory, new RiskScorer(), $policy, $keys);
        $resolver = new RiskProfileResolver(PoWAlgorithm::Sha256, 8);
        $gateway = new RiskGateway($engine, $classifier, $resolver, ['login' => 1], null, null, [], 'minimum', 42);
        $controller = new ChallengeController($issuer, null, true, $gateway, new ContinuityCookie());

        $request = JsonRequest::create('/kiwi-captcha/challenge', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7'], '{"scope":"weird_unconfigured_scope"}');
        $response = $controller->challenge($request);
        self::assertSame(200, $response->getStatusCode());
        $data = json_decode((string) $response->getContent(), true);
        self::assertSame(20, $data['targetBits'], 'the synthetic minimum sha20 must escalate the issued challenge');
        self::assertSame([42, 42], array_map(static fn ($o): int => $o->scope, $store->observations ?? []), 'unknown scopes must be observed under the synthetic scope id');
    }

    /**
     * The gateway's decision ids must flow into the post-issue feedback:
     * preIssue returns a decisionId, challengeIssued passes it on.
     */
    public function testDecisionIdFlowsFromAssessToFeedback(): void
    {
        $stack = $this->stack(new FakeRiskStateStore());
        $response = $stack['controller']->challenge($this->challengeRequest());
        self::assertSame(200, $response->getStatusCode());
        // The gateway ran assessPreIssue (PreIssue) then record_feedback
        // (ChallengeIssued) — both against the fake store.
        self::assertCount(2, $stack['store']->observations);
        $events = array_map(static fn ($o): RiskEventKind => $o->event, $stack['store']->observations);
        self::assertSame([RiskEventKind::PreIssue, RiskEventKind::ChallengeIssued], $events);
    }

    /**
     * A misconfigured proxy (unparseable client IP = no usable risk signal)
     * must apply the scope's configured degraded action — a degraded=deny
     * scope still returns 429 risk_denied, never a silent baseline drop.
     */
    public function testInvalidClientIpAppliesConfiguredDegradedAction(): void
    {
        $issuer = new Issuer(new Config(secretKey: self::SECRET, targetBits: 8, ttlSecs: 120), new ArrayStorage());
        $keys = RiskKeys::fromMaster(self::SECRET);
        $classifier = new CidrNetworkClassifier([]);
        $policy = RiskPolicy::fromConfig([
            'version' => RiskPolicy::CONTRACT_VERSION,
            'weights' => [],
            'scopes' => [
                1 => ['base_risk' => 300, 'minimum' => 'allow', 'post_solve_check' => false, 'degraded' => 'deny'],
            ],
        ]);
        $store = new FakeRiskStateStore();
        $engine = new AdaptiveRiskEngine($store, $classifier, new RiskIdentityFactory($keys), new RiskScorer(), $policy, $keys);
        $gateway = new RiskGateway($engine, $classifier, new RiskProfileResolver(PoWAlgorithm::Sha256, 8), ['financial_action' => 1], policy: $policy);
        $controller = new ChallengeController($issuer, null, true, $gateway, new ContinuityCookie());

        $request = JsonRequest::create('/kiwi-captcha/challenge', 'POST', [], [], [], ['REMOTE_ADDR' => 'not-an-ip'], '{"scope":"financial_action"}');
        $response = $controller->challenge($request);
        self::assertSame(429, $response->getStatusCode(), 'the degraded=deny floor must hold even without a usable IP');
        $data = json_decode((string) $response->getContent(), true);
        self::assertSame('RISK_DENIED', $data['error']['code']);
        self::assertSame([], $store->observations, 'the degraded fallback must never touch the state store');
    }

    /**
     * The degraded decision for a scope must come from the policy only —
     * neither the state store nor the emergency limiter may be touched, so a
     * saturated process window or a backend outage can never distort the
     * configured degraded floor.
     */
    public function testDegradedDecisionForScopeTouchesNeitherStoreNorLimiter(): void
    {
        $keys = RiskKeys::fromMaster(self::SECRET);
        $classifier = new CidrNetworkClassifier([]);
        $policy = RiskPolicy::fromConfig([
            'version' => RiskPolicy::CONTRACT_VERSION,
            'weights' => [],
            'scopes' => [
                1 => ['base_risk' => 100, 'minimum' => 'allow', 'post_solve_check' => false, 'degraded' => 'sha20'],
            ],
        ]);
        $store = new FakeRiskStateStore();
        $store->throwing = true;

        // Saturate the single limiter window: any live assess() would now be
        // a HardRateLimit deny.
        $limiter = new ProcessEmergencyCap(1);
        self::assertTrue($limiter->allow(), 'window consumed');
        $engine = new AdaptiveRiskEngine($store, $classifier, new RiskIdentityFactory($keys), new RiskScorer(), $policy, $keys, limiter: $limiter);
        $gateway = new RiskGateway($engine, $classifier, new RiskProfileResolver(PoWAlgorithm::Sha256, 8), ['login' => 1], policy: $policy);

        $decision = $gateway->degradedDecisionForScope(1);
        self::assertSame(RiskAction::Sha20, $decision->action, 'the degraded decision is the policy action, not a limiter deny');
        self::assertSame([], $store->observations, 'the degraded decision must never observe the store');
        self::assertSame(RiskReason::CapacityPressure, $decision->reasons[0]);

        // Without a wired policy the helper must fail loudly, never guess.
        $bare = new RiskGateway($engine, $classifier, new RiskProfileResolver(PoWAlgorithm::Sha256, 8), ['login' => 1]);
        try {
            $bare->degradedDecisionForScope(1);
            self::fail('degradedDecisionForScope without a wired policy must throw LogicException');
        } catch (\LogicException) {
            self::assertTrue(true);
        }
    }

    /**
     * preIssue and postSolveDecision record their decision id on the
     * request-local decision context (RequestStack attribute).
     */
    public function testPreIssueAndPostSolvePopulateDecisionContext(): void
    {
        $stack = $this->stack(new FakeRiskStateStore());
        $gateway = $stack['gateway'];

        // No request in scope -> no decision context anywhere.
        self::assertNull($gateway->currentDecisionId(), 'no decision yet');

        $requests = new RequestStack();
        $requests->push(JsonRequest::create('/challenge', 'POST'));
        $decision = $gateway->preIssue('login', '198.51.100.7', null);
        self::assertNull($gateway->currentDecisionId(), 'without a RequestStack the gateway cannot hold a request-local id');
        self::assertNotNull($decision->decisionId);

        $gateway->setCurrentDecisionId('manual-id');
        self::assertNull($gateway->currentDecisionId(), 'setCurrentDecisionId without a RequestStack is a no-op');
    }

    /**
     * The decision context is request-local: a long-running worker serving
     * two sequential requests must never leak request 1's decision id into
     * request 2 (a fresh Request with empty attributes, the way the kernel
     * pushes one per request, reads back null).
     */
    public function testDecisionContextIsIsolatedAcrossSequentialRequests(): void
    {
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
        $stack = new RequestStack();
        $gateway = new RiskGateway($engine, $classifier, new RiskProfileResolver(PoWAlgorithm::Sha256, 8), ['login' => 1], requestStack: $stack);

        // Request 1: pre-issue decision id visible only on request 1.
        $first = JsonRequest::create('/challenge', 'POST');
        $stack->push($first);
        $decision1 = $gateway->preIssue('login', '198.51.100.7', null);
        self::assertSame($decision1->decisionId, $gateway->currentDecisionId(), 'request 1 sees its own decision id');

        // The kernel swaps the main request: request 2 is a fresh Request
        // with empty attributes — request 1's id must be invisible.
        $stack->pop();
        $second = JsonRequest::create('/challenge', 'POST');
        $stack->push($second);
        self::assertNull($gateway->currentDecisionId(), 'request 2 must not see request 1\'s decision id');

        $decision2 = $gateway->postSolveDecision('login', '198.51.100.7');
        self::assertNotNull($decision2);
        self::assertSame($decision2->decisionId, $gateway->currentDecisionId(), 'request 2 sees only its own decision id');
        self::assertNotSame($decision1->decisionId, $decision2->decisionId);

        // And request 1's Request still holds ITS id (immutable history),
        // while request 2's Request holds only ITS OWN id.
        self::assertSame($decision1->decisionId, $first->attributes->get('_kiwi_risk_decision_id'));
        self::assertSame($decision2->decisionId, $second->attributes->get('_kiwi_risk_decision_id'), 'request 2 holds only its own decision id');
    }

    /**
     * The nonce -> decision mapping: JSON {"decision_id": ...} at
     * {kiwi:<ns>}:decision:<nonce> with the risk.nonce_to_decision_ttl_secs
     * TTL (default 300), consumed once via getdel (at most one winner).
     */
    public function testNonceToDecisionMappingRoundTripsWithTtlAndConsumesOnce(): void
    {
        $client = new FakePredisClient();
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
            null,
            null,
            [],
            'reject',
            null,
            null,
            null,
            $client,
            '{kiwi:t}:decision:',
            300,
        );

        $gateway->attachDecisionForNonce('nonce-1', 'dec-1');
        $key = '{kiwi:t}:decision:nonce-1';
        self::assertSame('{"decision_id":"dec-1"}', $client->strings[$key], 'the handle holds the JSON decision id only (no IP, no identity)');
        self::assertSame(300_000, $client->expirations[$key], 'the handle TTL must be risk.nonce_to_decision_ttl_secs in ms (independent of the outcome lifetime)');

        self::assertSame('dec-1', $gateway->resolveDecisionForNonce('nonce-1'), 'GETDEL must return the paired decision id');
        self::assertNull($gateway->resolveDecisionForNonce('nonce-1'), 'the handle is consumed once — a second resolve gets nothing');
        self::assertArrayNotHasKey($key, $client->strings, 'the consumed handle must be gone');
        self::assertNull($gateway->resolveDecisionForNonce('never-attached'));
    }

    /**
     * The controller pairs the minted challenge nonce to the pre-issue
     * decision id right after a successful preIssue, so a later solve can be
     * confirmed back to the original decision.
     */
    public function testControllerAttachesNonceToDecisionMappingAfterPreIssue(): void
    {
        $client = new FakePredisClient();
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
        $stack = new RequestStack();
        $gateway = new RiskGateway(
            $engine,
            $classifier,
            new RiskProfileResolver(PoWAlgorithm::Sha256, 8),
            ['login' => 1],
            null,
            null,
            [],
            'reject',
            null,
            null,
            $stack,
            $client,
            '{kiwi:t}:decision:',
            300,
        );
        $controller = new ChallengeController($issuer, null, true, $gateway, new ContinuityCookie());

        $request = $this->challengeRequest();
        $stack->push($request);
        $response = $controller->challenge($request);
        self::assertSame(200, $response->getStatusCode());
        $data = json_decode((string) $response->getContent(), true);

        $key = '{kiwi:t}:decision:'.$data['nonce'];
        self::assertArrayHasKey($key, $client->strings, 'the controller must pair the minted nonce to the decision id');
        $mapped = json_decode($client->strings[$key], true);
        self::assertSame($gateway->currentDecisionId(), $mapped['decision_id'], 'the mapped id is the pre-issue decision id');
    }

    /**
     * A wired principal resolver must flow the RAW principal into every
     * engine context (pre-issue AND feedback signals); the engine
     * HMAC-pseudonymizes it, so the recorded observation carries the derived
     * pseudonym, never the raw value.
     */
    public function testPrincipalResolverFlowsIntoEveryContext(): void
    {
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

        $stack = new RequestStack();
        $stack->push(JsonRequest::create('/', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7']));
        $gateway = new RiskGateway(
            $engine,
            $classifier,
            new RiskProfileResolver(PoWAlgorithm::Sha256, 8),
            ['login' => 1],
            null,
            null,
            [],
            'reject',
            null,
            new FakePrincipalResolver('user-42'),
            $stack,
        );

        $gateway->preIssue('login', '198.51.100.7', null);
        $gateway->authenticationSuccess('login', '198.51.100.7', null);
        $gateway->rateLimitHit('login', '198.51.100.7', null);

        $expected = (new RiskIdentityFactory($keys))->principalId('user-42');
        self::assertSame([$expected, $expected, $expected], array_map(static fn ($o): ?string => $o->principalId, $store->observations), 'every context must carry the HMAC-pseudonymized principal');

        // Without a resolver (or without a request) the principal stays null.
        $store->observations = [];
        $bare = new RiskGateway($engine, $classifier, new RiskProfileResolver(PoWAlgorithm::Sha256, 8), ['login' => 1]);
        $bare->authenticationSuccess('login', '198.51.100.7', null);
        self::assertSame([null], array_map(static fn ($o): ?string => $o->principalId, $store->observations), 'no resolver -> no principal signal');
    }

    /**
     * reassess() must NOT consume the emergency admission budget: a
     * saturated process window denies pre-issue assessments but can never
     * deny a valid post-solve re-assessment.
     */
    public function testLowLimiterCapNeverDeniesPostSolve(): void
    {
        $keys = RiskKeys::fromMaster(self::SECRET);
        $classifier = new CidrNetworkClassifier([]);
        $policy = RiskPolicy::fromConfig([
            'version' => RiskPolicy::CONTRACT_VERSION,
            'weights' => [],
            'scopes' => [
                1 => ['base_risk' => 100, 'minimum' => 'allow', 'post_solve_check' => true, 'degraded' => 'allow'],
            ],
        ]);
        $store = new FakeRiskStateStore();
        $limiter = new ProcessEmergencyCap(1, 1);
        $engine = new AdaptiveRiskEngine($store, $classifier, new RiskIdentityFactory($keys), new RiskScorer(), $policy, $keys, limiter: $limiter);
        $gateway = new RiskGateway($engine, $classifier, new RiskProfileResolver(PoWAlgorithm::Sha256, 8), ['login' => 1], null, null, ['login' => true]);

        $first = $gateway->preIssue('login', '198.51.100.7', null);
        self::assertSame(RiskAction::Allow, $first->action, 'the first pre-issue consumes the only limiter slot');

        $saturated = $gateway->preIssue('login', '198.51.100.7', null);
        self::assertSame(RiskAction::Deny, $saturated->action, 'a second pre-issue is denied by the saturated limiter');
        self::assertTrue($saturated->hasReason(RiskReason::HardRateLimit));

        $postSolve = $gateway->postSolveDecision('login', '198.51.100.7');
        self::assertNotNull($postSolve);
        self::assertSame(RiskAction::Allow, $postSolve->action, 'a valid solve must never be denied by the emergency limiter');
        self::assertSame([RiskEventKind::PreIssue, RiskEventKind::SolveSuccess], array_map(static fn ($o): RiskEventKind => $o->event, $store->observations), 'the limiter-denied pre-issue records no observation; the post-solve reassessment does');
    }

    public function testPostSolveCheckDenyRejectsValidSolve(): void
    {
        // post_solve_check scope: a valid solve whose SolveSuccess
        // re-assessment denies must fail the validation with the distinct
        // POST_solve_rejected_error. The gateway does NOT self-train: the
        // post-solve outcome is NOT recorded as ConfirmedAbuse by the
        // bundle (confirmation is an application-only signal that requires
        // a decision id), so the only observation is the SolveSuccess
        // assessment itself.
        $store = new FakeRiskStateStore(SignalVector::fromArray(['replay' => 700]));
        $storage = new ArrayStorage();
        $issuer = new Issuer(new Config(secretKey: self::SECRET, targetBits: 8, ttlSecs: 120), $storage);
        $verifier = new Verifier($storage);
        $keys = RiskKeys::fromMaster(self::SECRET);
        $identityFactory = new RiskIdentityFactory($keys);
        $classifier = new CidrNetworkClassifier([]);
        $policy = RiskPolicy::fromConfig([
            'version' => RiskPolicy::CONTRACT_VERSION,
            'weights' => [],
            'scopes' => [
                1 => ['base_risk' => 100, 'minimum' => 'allow', 'post_solve_check' => true, 'degraded' => 'allow'],
            ],
        ]);
        $engine = new AdaptiveRiskEngine($store, $classifier, $identityFactory, new RiskScorer(), $policy, $keys);
        $resolver = new RiskProfileResolver(PoWAlgorithm::Sha256, 8);
        $gateway = new RiskGateway($engine, $classifier, $resolver, ['login' => 1], null, null, ['login' => true]);

        $challenge = $issuer->issue('login', '198.51.100.7');
        usleep(((int) $challenge->minDurationMs + 10) * 1000);
        $token = $this->solve($challenge->prefix, $challenge->salt, $challenge->targetBits, $challenge->nonce);

        $stack = new RequestStack();
        $stack->push(JsonRequest::create('/', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7']));
        $validator = new KiwiCaptchaValidator($verifier, $stack, self::SECRET, false, $gateway);
        $factory = new ConstraintValidatorFactory([KiwiCaptchaValidator::class => $validator]);
        $engineValidator = Validation::createValidatorBuilder()->setConstraintValidatorFactory($factory)->getValidator();

        $dto = new class {
            public ?string $captcha = null;
        };
        $dto->captcha = $token;
        $meta = $engineValidator->getMetadataFor($dto::class);
        $meta->addPropertyConstraint('captcha', new KiwiCaptcha(['scope' => 'login']));

        $violations = $engineValidator->validate($dto);
        self::assertCount(1, $violations);
        self::assertSame(KiwiCaptcha::POST_SOLVE_REJECTED_ERROR, $violations[0]->getCode());

        // Only the SolveSuccess assessment itself — no self-confirmation.
        $events = array_map(static fn ($o): RiskEventKind => $o->event, $store->observations);
        self::assertSame([RiskEventKind::SolveSuccess], $events);
    }

    public function testPostSolveCheckPassRecordsPlainSolveSuccess(): void
    {
        // A valid solve on a post_solve_check scope whose re-assessment
        // allows must pass validation. The outcome is recorded as the plain
        // SolveSuccess signal — the gateway no longer self-confirms as
        // ConfirmedLegitimate (application-only signal, requires a decision
        // id).
        $store = new FakeRiskStateStore();
        $storage = new ArrayStorage();
        $issuer = new Issuer(new Config(secretKey: self::SECRET, targetBits: 8, ttlSecs: 120), $storage);
        $verifier = new Verifier($storage);
        $keys = RiskKeys::fromMaster(self::SECRET);
        $identityFactory = new RiskIdentityFactory($keys);
        $classifier = new CidrNetworkClassifier([]);
        $policy = RiskPolicy::fromConfig([
            'version' => RiskPolicy::CONTRACT_VERSION,
            'weights' => [],
            'scopes' => [
                1 => ['base_risk' => 100, 'minimum' => 'allow', 'post_solve_check' => true, 'degraded' => 'allow'],
            ],
        ]);
        $engine = new AdaptiveRiskEngine($store, $classifier, $identityFactory, new RiskScorer(), $policy, $keys);
        $gateway = new RiskGateway($engine, $classifier, new RiskProfileResolver(PoWAlgorithm::Sha256, 8), ['login' => 1], null, null, ['login' => true]);

        $challenge = $issuer->issue('login', '198.51.100.7');
        usleep(((int) $challenge->minDurationMs + 10) * 1000);
        $token = $this->solve($challenge->prefix, $challenge->salt, $challenge->targetBits, $challenge->nonce);

        $stack = new RequestStack();
        $stack->push(JsonRequest::create('/', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7']));
        $validator = new KiwiCaptchaValidator($verifier, $stack, self::SECRET, false, $gateway);
        $factory = new ConstraintValidatorFactory([KiwiCaptchaValidator::class => $validator]);
        $engineValidator = Validation::createValidatorBuilder()->setConstraintValidatorFactory($factory)->getValidator();

        $dto = new class {
            public ?string $captcha = null;
        };
        $dto->captcha = $token;
        $meta = $engineValidator->getMetadataFor($dto::class);
        $meta->addPropertyConstraint('captcha', new KiwiCaptcha(['scope' => 'login']));

        $violations = $engineValidator->validate($dto);
        self::assertCount(0, $violations);
        $events = array_map(static fn ($o): RiskEventKind => $o->event, $store->observations);
        self::assertSame([RiskEventKind::SolveSuccess], $events);
    }

    public function testPostSolveDecisionDoesNotSelfTrain(): void
    {
        // The gateway's own post-solve decision must NOT be converted into
        // ConfirmedLegitimate / ConfirmedAbuse feedback (those are
        // application-only signals requiring a decision id) — even for a
        // denying re-assessment. The only observation is the SolveSuccess
        // assessment.
        $store = new FakeRiskStateStore(SignalVector::fromArray(['replay' => 700]));
        $keys = RiskKeys::fromMaster(self::SECRET);
        $classifier = new CidrNetworkClassifier([]);
        $policy = RiskPolicy::fromConfig([
            'version' => RiskPolicy::CONTRACT_VERSION,
            'weights' => [],
            'scopes' => [
                1 => ['base_risk' => 100, 'minimum' => 'allow', 'post_solve_check' => true, 'degraded' => 'allow'],
            ],
        ]);
        $engine = new AdaptiveRiskEngine($store, $classifier, new RiskIdentityFactory($keys), new RiskScorer(), $policy, $keys);
        $gateway = new RiskGateway($engine, $classifier, new RiskProfileResolver(PoWAlgorithm::Sha256, 8), ['login' => 1], null, null, ['login' => true]);

        $decision = $gateway->postSolveDecision('login', '198.51.100.7', null);
        self::assertNotNull($decision);
        self::assertSame(RiskAction::Deny, $decision->action);

        $events = array_map(static fn ($o): RiskEventKind => $o->event, $store->observations);
        self::assertSame([RiskEventKind::SolveSuccess], $events, 'postSolveDecision must not record its own confirmation');
        self::assertCount(1, $store->observations);
    }

    public function testPostSolveStepUpFailsValidationWithStepUpError(): void
    {
        // post_solve_check scope: a valid solve whose SolveSuccess
        // re-assessment escalates to StepUp (an Argon band action while
        // Argon capacity is saturated) must fail the validation with the
        // distinct POST_solve_step_UP_required error — the application
        // routes the user to MFA/passkey/email confirmation instead of a
        // silent re-solve loop.
        // Score: base 100 + source_fast 900 (171) + subnet_fast 1000 (80) +
        // issue_debt 1000 (150) + bad_proof 1000 (220) = 721 -> Argon16
        // band (600-749); argonCapacity 0 (< 300) escalates Argon to StepUp.
        $store = new FakeRiskStateStore(SignalVector::fromArray(['source_fast' => 900, 'subnet_fast' => 1000, 'issue_debt' => 1000, 'bad_proof' => 1000]));
        $storage = new ArrayStorage();
        $issuer = new Issuer(new Config(secretKey: self::SECRET, targetBits: 8, ttlSecs: 120), $storage);
        $verifier = new Verifier($storage);
        $keys = RiskKeys::fromMaster(self::SECRET);
        $identityFactory = new RiskIdentityFactory($keys);
        $classifier = new CidrNetworkClassifier([]);
        $policy = RiskPolicy::fromConfig([
            'version' => RiskPolicy::CONTRACT_VERSION,
            'weights' => [],
            'scopes' => [
                1 => ['base_risk' => 100, 'minimum' => 'allow', 'post_solve_check' => true, 'degraded' => 'allow'],
            ],
        ]);
        $engine = new AdaptiveRiskEngine($store, $classifier, $identityFactory, new RiskScorer(), $policy, $keys);
        $saturatedArgon = new class implements ResourcePressureProviderInterface {
            public function snapshot(): ResourcePressure
            {
                return new ResourcePressure(0, 1000, 1000);
            }
        };
        $gateway = new RiskGateway($engine, $classifier, new RiskProfileResolver(PoWAlgorithm::Sha256, 8), ['login' => 1], null, $saturatedArgon, ['login' => true]);

        $challenge = $issuer->issue('login', '198.51.100.7');
        usleep(((int) $challenge->minDurationMs + 10) * 1000);
        $token = $this->solve($challenge->prefix, $challenge->salt, $challenge->targetBits, $challenge->nonce);

        $stack = new RequestStack();
        $stack->push(JsonRequest::create('/', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7']));
        $validator = new KiwiCaptchaValidator($verifier, $stack, self::SECRET, false, $gateway);
        $factory = new ConstraintValidatorFactory([KiwiCaptchaValidator::class => $validator]);
        $engineValidator = Validation::createValidatorBuilder()->setConstraintValidatorFactory($factory)->getValidator();

        $dto = new class {
            public ?string $captcha = null;
        };
        $dto->captcha = $token;
        $meta = $engineValidator->getMetadataFor($dto::class);
        $meta->addPropertyConstraint('captcha', new KiwiCaptcha(['scope' => 'login']));

        $violations = $engineValidator->validate($dto);
        self::assertCount(1, $violations);
        self::assertSame(KiwiCaptcha::POST_SOLVE_STEP_UP_REQUIRED, $violations[0]->getCode());
    }

    /**
     * confirmedLegitimate / confirmedAbuse require the decisionId: the
     * engine enforces it with InvalidArgumentException and the gateway lets
     * that enforcement surface (application-only signals, never inferred by
     * the bundle). With a decisionId the first confirmation (status 1)
     * books the reputation event exactly once.
     */
    public function testConfirmedSignalsRequireDecisionId(): void
    {
        $stack = $this->stack(new FakeRiskStateStore());
        $gateway = $stack['gateway'];

        try {
            $gateway->confirmedLegitimate('login', '198.51.100.7');
            self::fail('confirmedLegitimate without a decisionId must throw InvalidArgumentException');
        } catch (\InvalidArgumentException) {
            self::assertTrue(true);
        }
        try {
            $gateway->confirmedAbuse('login', '198.51.100.7');
            self::fail('confirmedAbuse without a decisionId must throw InvalidArgumentException');
        } catch (\InvalidArgumentException) {
            self::assertTrue(true);
        }
        try {
            $gateway->recordConfirmedReputation(true, 'login', '198.51.100.7');
            self::fail('recordConfirmedReputation without a decisionId must throw InvalidArgumentException');
        } catch (\InvalidArgumentException) {
            self::assertTrue(true);
        }

        // With a decisionId AND a calibration store the first confirmation
        // (status 1) records the reputation event.
        $store = new FakeRiskStateStore();
        $client = new FakePredisClient();
        $keys = RiskKeys::fromMaster(self::SECRET);
        $classifier = new CidrNetworkClassifier([]);
        $policy = RiskPolicy::fromConfig([
            'version' => RiskPolicy::CONTRACT_VERSION,
            'weights' => [],
            'scopes' => [
                1 => ['base_risk' => 100, 'minimum' => 'allow', 'post_solve_check' => false, 'degraded' => 'allow'],
            ],
        ]);
        $calibrator = new AggregateCalibrator($client, 'cal-reqid', samplingMode: 'complete');
        $engine = new AdaptiveRiskEngine(
            $store,
            $classifier,
            new RiskIdentityFactory($keys),
            new RiskScorer(),
            $policy,
            $keys,
            calibration: $calibrator,
        );
        $calibrator->recordReceipt('dec-1', 1, 0, RiskAction::Allow, 100, 1, 172800, 1.0);
        $gateway = new RiskGateway($engine, $classifier, new RiskProfileResolver(PoWAlgorithm::Sha256, 8), ['login' => 1]);

        $receipt = $gateway->confirmedAbuse('login', '198.51.100.7', null, null, 'dec-1');
        self::assertInstanceOf(EventReceipt::class, $receipt);
        self::assertFalse($receipt->isDuplicate);
        $events = array_map(static fn ($o): RiskEventKind => $o->event, $store->observations);
        self::assertSame([RiskEventKind::ConfirmedAbuse], $events);
    }

    /**
     * recordConfirmedReputation is the context-ful path: with a valid
     * source/session context the engine confirms the decision atomically
     * (status 1/2 — the first confirmation) and records the reputation
     * event carrying the source/session/principal signals. Without a
     * usable client IP the signal is skipped (null) — never an exception.
     */
    public function testRecordConfirmedReputationStillUpdatesReputation(): void
    {
        $store = new FakeRiskStateStore();
        $client = new FakePredisClient();
        $keys = RiskKeys::fromMaster(self::SECRET);
        $classifier = new CidrNetworkClassifier([]);
        $policy = RiskPolicy::fromConfig([
            'version' => RiskPolicy::CONTRACT_VERSION,
            'weights' => [],
            'scopes' => [
                1 => ['base_risk' => 100, 'minimum' => 'allow', 'post_solve_check' => false, 'degraded' => 'allow'],
            ],
        ]);
        $calibrator = new AggregateCalibrator($client, 'cal-rep-ctx', samplingMode: 'complete');
        $engine = new AdaptiveRiskEngine(
            $store,
            $classifier,
            new RiskIdentityFactory($keys),
            new RiskScorer(),
            $policy,
            $keys,
            calibration: $calibrator,
        );
        $gateway = new RiskGateway($engine, $classifier, new RiskProfileResolver(PoWAlgorithm::Sha256, 8), ['login' => 1]);

        $calibrator->recordReceipt('dec-1', 1, 0, RiskAction::Allow, 100, 1, 172800, 1.0);
        $receipt = $gateway->recordConfirmedReputation(true, 'login', '198.51.100.7', null, null, 'dec-1');
        self::assertInstanceOf(EventReceipt::class, $receipt, 'the context-ful confirmation must return the engine EventReceipt');
        $events = array_map(static fn ($o): RiskEventKind => $o->event, $store->observations);
        self::assertSame([RiskEventKind::ConfirmedLegitimate], $events, 'the reputation event is recorded via the engine');

        // The reputation event is attributed to the request context: the
        // observation carries the derived source pseudonym.
        $identityFactory = new RiskIdentityFactory(RiskKeys::fromMaster(self::SECRET));
        self::assertSame($identityFactory->sourceId('198.51.100.7', time()), $store->observations[0]->sourceId);

        // Legitimate vs abuse flag selects the event kind.
        $calibrator->recordReceipt('dec-2', 1, 0, RiskAction::Allow, 100, 1, 172800, 1.0);
        $gateway->recordConfirmedReputation(false, 'login', '198.51.100.7', null, null, 'dec-2');
        $events = array_map(static fn ($o): RiskEventKind => $o->event, $store->observations);
        self::assertSame([RiskEventKind::ConfirmedLegitimate, RiskEventKind::ConfirmedAbuse], $events);

        // Invalid client IP: nothing to attribute the reputation event to.
        self::assertNull($gateway->recordConfirmedReputation(true, 'login', 'not-an-ip', null, null, 'dec-3'), 'an unparseable IP skips the reputation signal (null), never an exception');
        self::assertCount(2, $store->observations, 'the skipped signal must not reach the engine');
    }

    /**
     * confirmDecisionOutcome is the calibration-only path: a decision id +
     * outcome is enough — no scope, no session and NO network identity.
     * The engine's atomic confirm consumes the receipt and records the
     * score-weighted outcome in one canonical confirm.lua script.
     */
    public function testConfirmDecisionOutcomeWorksWithoutNetworkIdentity(): void
    {
        $client = new FakePredisClient();
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
        $calibrator = new AggregateCalibrator($client, 'cal-test', samplingMode: 'complete');
        $engine = new AdaptiveRiskEngine(
            $store,
            $classifier,
            new RiskIdentityFactory($keys),
            new RiskScorer(),
            $policy,
            $keys,
            calibration: $calibrator,
        );
        $gateway = new RiskGateway($engine, $classifier, new RiskProfileResolver(PoWAlgorithm::Sha256, 8), ['login' => 1]);

        // A decision's receipt exists (score 100, sampled) — written the
        // way the engine registers it at assessment time.
        $calibrator->recordReceipt('dec-1', 1, 0, RiskAction::Allow, 100, 1, 172800, 1.0);

        // No IP, no scope, no session: the delayed confirmation records the
        // outcome purely against the calibration aggregates.
        $result = $gateway->confirmDecisionOutcome('dec-1', true);
        self::assertSame(1, $result, 'first confirmation returns status 1 (outcome recorded)');
        self::assertArrayNotHasKey('{kiwi:cal-test}:cal:receipt:dec-1', $client->strings, 'the receipt is consumed atomically by the confirm script');
        $hour = 172800;
        $bucket = "{kiwi:cal-test}:cal:1:{$hour}";
        self::assertSame(1.0, $client->hashes[$bucket]['legit_count'] ?? null, 'the legit outcome is counted');
        self::assertSame(100.0, $client->hashes[$bucket]['legit_score_sum'] ?? null, 'the exact score is summed');
        self::assertArrayNotHasKey('abuse_count', $client->hashes[$bucket], 'no abuse side may be touched');

        // A missing / already-consumed receipt confirms to status 0 — the
        // application treats it as a no-op (a webhook retry of an
        // already-confirmed decision is harmless; at most ONE reputation
        // mutation per decision). The reputation event is NOT part of this
        // path.
        self::assertSame(0, $gateway->confirmDecisionOutcome('dec-1', true), 'an already-consumed receipt confirms to status 0 (no-op, no double-record)');
        self::assertSame(0, $gateway->confirmDecisionOutcome('never-registered', false), 'a missing receipt confirms to status 0');
        self::assertSame([], $store->observations, 'the calibration-only path never records a reputation event');
    }

    /**
     * confirmDecisionOutcome with $samplingProbabilityPpm supplies the
     * inverse sampling probability (weighted mode): weight = 1_000_000/ppm,
     * so a label known to be 50% likely to be reported is weighted 2.0.
     */
    public function testConfirmDecisionOutcomeWeightedModeConvertsPpmToWeight(): void
    {
        $client = new FakePredisClient();
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
        $calibrator = new AggregateCalibrator($client, 'cal-weighted', samplingMode: 'weighted');
        $engine = new AdaptiveRiskEngine(
            $store,
            $classifier,
            new RiskIdentityFactory($keys),
            new RiskScorer(),
            $policy,
            $keys,
            calibration: $calibrator,
        );
        $gateway = new RiskGateway($engine, $classifier, new RiskProfileResolver(PoWAlgorithm::Sha256, 8), ['login' => 1]);

        $calibrator->recordReceipt('dec-1', 1, 10, RiskAction::Deny, 700, 1, 172800, 1.0);
        $result = $gateway->confirmDecisionOutcome('dec-1', false, 500_000);
        self::assertSame(1, $result, 'weighted confirmation records the outcome');
        $hour = 172800;
        $bucket = "{kiwi:cal-weighted}:cal:1:{$hour}";
        self::assertSame(2.0, $client->hashes[$bucket]['abuse_count'] ?? null, 'weight = 1_000_000/500000 = 2.0');
        self::assertSame(1400.0, $client->hashes[$bucket]['abuse_score_sum'] ?? null, 'score * weight = 700 * 2.0');

        // ppm without an explicit weighted calibrator mode is still passed
        // through as the weight (the calibrator governs the mode contract).
        $calibrator->recordReceipt('dec-2', 1, 0, RiskAction::Allow, 50, 1, 172800, 1.0);
        $result = $gateway->confirmDecisionOutcome('dec-2', true, 1_000_000);
        self::assertSame(1, $result, 'ppm = 1000000 is the identity weight');
        self::assertSame(1.0, $client->hashes[$bucket]['legit_count'] ?? null);
        self::assertSame(50.0, $client->hashes[$bucket]['legit_score_sum'] ?? null);

        // Out-of-range ppm is refused loudly.
        try {
            $gateway->confirmDecisionOutcome('dec-3', true, 0);
            self::fail('ppm 0 must be rejected');
        } catch (\InvalidArgumentException) {
            self::assertTrue(true);
        }
        try {
            $gateway->confirmDecisionOutcome('dec-4', true, 1_000_001);
            self::fail('ppm above 1_000_000 must be rejected');
        } catch (\InvalidArgumentException) {
            self::assertTrue(true);
        }
    }

    /**
     * Weighted mode through the context-ful API: confirmedLegitimate /
     * confirmedAbuse / recordConfirmedReputation accept the same optional
     * $samplingProbabilityPpm (inverse sampling probability, 1..1_000_000)
     * and pass it to the engine's confirmed* methods, which convert it to
     * weight = 1_000_000/ppm. A context-ful confirmation thus re-weights
     * the label into the calibration population exactly like
     * confirmDecisionOutcome. A null ppm in weighted mode makes the
     * engine throw InvalidArgumentException (the label cannot be
     * re-weighted without its inverse probability) — the gateway lets it
     * propagate.
     */
    public function testConfirmedContextfulApiWeightedModeMapsPpmAndPropagatesNullPpm(): void
    {
        $client = new FakePredisClient();
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
        $calibrator = new AggregateCalibrator($client, 'cal-ctx-weighted', samplingMode: 'weighted');
        $engine = new AdaptiveRiskEngine(
            $store,
            $classifier,
            new RiskIdentityFactory($keys),
            new RiskScorer(),
            $policy,
            $keys,
            calibration: $calibrator,
        );
        $gateway = new RiskGateway($engine, $classifier, new RiskProfileResolver(PoWAlgorithm::Sha256, 8), ['login' => 1]);

        // ppm -> weight through confirmedAbuse: weight = 1_000_000/500000
        // = 2.0 -> the abuse bucket is incremented by the weighted deltas
        // AND the reputation event is recorded once.
        $calibrator->recordReceipt('dec-ctx-1', 1, 0, RiskAction::Allow, 100, 1, 172800, 1.0);
        $receipt = $gateway->confirmedAbuse('login', '198.51.100.7', null, null, 'dec-ctx-1', 500_000);
        self::assertInstanceOf(EventReceipt::class, $receipt);
        self::assertFalse($receipt->isDuplicate, 'the weighted context-ful confirmation is a first (non-duplicate) confirmation');
        $hour = 172800;
        $bucket = "{kiwi:cal-ctx-weighted}:cal:1:{$hour}";
        self::assertSame(2.0, $client->hashes[$bucket]['abuse_count'] ?? null, 'weight = 1_000_000/500000 = 2.0 (weighted bucket increment)');
        self::assertSame(200.0, $client->hashes[$bucket]['abuse_score_sum'] ?? null, 'score * weight = 100 * 2.0');
        self::assertSame([RiskEventKind::ConfirmedAbuse], array_map(static fn ($o): RiskEventKind => $o->event, $store->observations), 'the reputation event follows the atomic weighted confirmation');

        // ppm = 1_000_000 is the identity weight through confirmedLegitimate.
        $calibrator->recordReceipt('dec-ctx-2', 1, 0, RiskAction::Allow, 50, 1, 172800, 1.0);
        $gateway->confirmedLegitimate('login', '198.51.100.7', null, null, 'dec-ctx-2', 1_000_000);
        self::assertSame(1.0, $client->hashes[$bucket]['legit_count'] ?? null, 'ppm = 1000000 is the identity weight');
        self::assertSame(50.0, $client->hashes[$bucket]['legit_score_sum'] ?? null);

        // recordConfirmedReputation passes the ppm through as well
        $calibrator->recordReceipt('dec-ctx-3', 1, 0, RiskAction::Allow, 100, 1, 172800, 1.0);
        $gateway->recordConfirmedReputation(false, 'login', '198.51.100.7', null, null, 'dec-ctx-3', 250_000);
        self::assertSame(6.0, $client->hashes[$bucket]['abuse_count'] ?? null, 'weight = 2.0 (500000 ppm) + 4.0 (250000 ppm) — every context-ful confirmation re-weights its label');

        // null ppm in weighted mode: the engine's confirmOutcome refuses a
        // null weight with InvalidArgumentException — the gateway lets it
        // propagate (documented behavior).
        $calibrator->recordReceipt('dec-ctx-null', 1, 0, RiskAction::Allow, 100, 1, 172800, 1.0);
        try {
            $gateway->confirmedAbuse('login', '198.51.100.7', null, null, 'dec-ctx-null');
            self::fail('null ppm in weighted mode must throw InvalidArgumentException (propagated from the engine)');
        } catch (\InvalidArgumentException $e) {
            self::assertStringContainsString('weighted', strtolower($e->getMessage()), 'the refusal names the weighted mode');
        }
        try {
            $gateway->recordConfirmedReputation(true, 'login', '198.51.100.7', null, null, 'dec-ctx-null');
            self::fail('null ppm in weighted mode must throw through recordConfirmedReputation too');
        } catch (\InvalidArgumentException) {
            self::assertTrue(true);
        }
        self::assertArrayHasKey('{kiwi:cal-ctx-weighted}:cal:receipt:dec-ctx-null', $client->strings, 'a refused weighted confirmation leaves the receipt intact (argument validation before consumption)');

        // Out-of-range ppm is refused by the gateway itself.
        try {
            $gateway->confirmedLegitimate('login', '198.51.100.7', null, null, 'dec-ctx-x', 0);
            self::fail('ppm 0 must be rejected');
        } catch (\InvalidArgumentException) {
            self::assertTrue(true);
        }
        try {
            $gateway->confirmedAbuse('login', '198.51.100.7', null, null, 'dec-ctx-x', 1_000_001);
            self::fail('ppm above 1_000_000 must be rejected');
        } catch (\InvalidArgumentException) {
            self::assertTrue(true);
        }
    }

    /**
     * samplingMetrics: the calibrator's sampling-resolution counters
     * (random_sample gate) exposed through the gateway — sampledTotal /
     * sampledResolved / resolutionRatio / sampledExpired. Without a wired
     * calibration store every value is zero.
     */
    public function testSamplingMetricsExposeResolutionGateCounters(): void
    {
        $client = new FakePredisClient();
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
        $calibrator = new AggregateCalibrator($client, 'cal-metrics', samplingMode: 'random_sample', samplingProbabilityPpm: 100_000);
        $engine = new AdaptiveRiskEngine(
            $store,
            $classifier,
            new RiskIdentityFactory($keys),
            new RiskScorer(),
            $policy,
            $keys,
            calibration: $calibrator,
        );
        $gateway = new RiskGateway($engine, $classifier, new RiskProfileResolver(PoWAlgorithm::Sha256, 8), ['login' => 1], calibration: $calibrator);

        self::assertSame(
            ['sampledTotal' => 0, 'sampledResolved' => 0, 'resolutionRatio' => 0.0, 'sampledExpired' => 0],
            $gateway->samplingMetrics(1),
            'an empty sample reads zeros',
        );

        // Two decisions were sampled at assessment time (the calibrator's
        // sample call books the total counter — one incr per sampled
        // decision); one of them was confirmed. The counters are booked
        // deterministically here (sample itself is probabilistic). The
        // counters live in the scope/hour buckets, so the sample
        // receipts are registered at the current hour to sit inside the
        // 24-hour metrics window.
        $currentHour = intdiv((int) floor(microtime(true) * 1000), 3_600_000);
        $calibrator->recordReceipt('met-1', 1, 0, RiskAction::Allow, 100, 1, $currentHour, 1.0);
        $calibrator->recordReceipt('met-2', 1, 0, RiskAction::Allow, 100, 1, $currentHour, 1.0);
        self::assertSame(1, $gateway->confirmDecisionOutcome('met-1', true), 'the sampled decision is confirmed (status 1)');

        self::assertSame(2.0, $client->hashes["{kiwi:cal-metrics}:cal:1:{$currentHour}"]['sample_total'] ?? null, 'two sampled decisions booked the bucket TOTAL counter');
        $metrics = $gateway->samplingMetrics(1);
        self::assertSame(2, $metrics['sampledTotal']);
        self::assertSame(1, $metrics['sampledResolved']);
        self::assertSame(0.5, $metrics['resolutionRatio'], 'resolution = resolved/total = 1/2');
        self::assertSame(1, $metrics['sampledExpired'], 'sampledExpired = total - resolved');

        // complete/weighted modes never touch the counters -> zeros
        $complete = new AggregateCalibrator(new FakePredisClient(), 'cal-metrics-complete', samplingMode: 'complete');
        $engineComplete = new AdaptiveRiskEngine(
            new FakeRiskStateStore(),
            $classifier,
            new RiskIdentityFactory($keys),
            new RiskScorer(),
            $policy,
            $keys,
            calibration: $complete,
        );
        $gatewayComplete = new RiskGateway($engineComplete, $classifier, new RiskProfileResolver(PoWAlgorithm::Sha256, 8), ['login' => 1], calibration: $complete);
        self::assertSame(0, $gatewayComplete->samplingMetrics(1)['sampledTotal'], 'complete mode reports zero sampled totals');

        // Without a calibration store the gateway guards with zeros.
        $bareEngine = new AdaptiveRiskEngine(new FakeRiskStateStore(), $classifier, new RiskIdentityFactory($keys), new RiskScorer(), $policy, $keys);
        $bare = new RiskGateway($bareEngine, $classifier, new RiskProfileResolver(PoWAlgorithm::Sha256, 8), ['login' => 1]);
        self::assertSame(
            ['sampledTotal' => 0, 'sampledResolved' => 0, 'resolutionRatio' => 0.0, 'sampledExpired' => 0],
            $bare->samplingMetrics(1),
            'calibration disabled -> zeros',
        );
    }

    /**
     * random_sample calibration: an unsampled confirmation is consumed
     * with status 2, deliberately not recorded — the label can never
     * select itself into the calibration population, and the caller may
     * still apply first-party reputation exactly once. A sampled
     * confirmation is recorded with status 1, keyed by the receipt's
     * assessment-time "sampled" flag.
     */
    public function testConfirmDecisionOutcomeRandomSampleDiscardsUnsampledReceipts(): void
    {
        $client = new FakePredisClient();
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
        $calibrator = new AggregateCalibrator($client, 'cal-sample', samplingMode: 'random_sample', samplingProbabilityPpm: 100_000);
        $engine = new AdaptiveRiskEngine(
            $store,
            $classifier,
            new RiskIdentityFactory($keys),
            new RiskScorer(),
            $policy,
            $keys,
            calibration: $calibrator,
        );
        $gateway = new RiskGateway($engine, $classifier, new RiskProfileResolver(PoWAlgorithm::Sha256, 8), ['login' => 1]);

        // Unsampled receipt (Kiwi did not sample this decision): the
        // confirmation is consumed with status 2 — receipt gone, NO bucket
        // write.
        $calibrator->recordReceipt('unsampled', 1, 0, RiskAction::Allow, 100, 0, 172800, 1.0);
        self::assertSame(2, $gateway->confirmDecisionOutcome('unsampled', true), 'an unsampled confirmation is consumed with status 2 (deliberately not recorded)');
        self::assertArrayNotHasKey('{kiwi:cal-sample}:cal:receipt:unsampled', $client->strings, 'the unsampled receipt is consumed (deleted), never left to be confirmed twice');
        $hour = 172800;
        self::assertArrayNotHasKey("{kiwi:cal-sample}:cal:1:{$hour}", $client->hashes, 'an unsampled outcome must never reach the aggregates');

        // Sampled receipt: recorded with status 1 (and the sampled-decision
        // resolved counter of the resolution gate is INCRed exactly once).
        $calibrator->recordReceipt('sampled', 1, 0, RiskAction::Allow, 100, 1, 172800, 1.0);
        self::assertSame(1, $gateway->confirmDecisionOutcome('sampled', true), 'a sampled confirmation is recorded with status 1');
        self::assertSame(1.0, $client->hashes["{kiwi:cal-sample}:cal:1:{$hour}"]['legit_count'] ?? null);
        self::assertSame(1.0, $client->hashes["{kiwi:cal-sample}:cal:1:172800"]['sample_resolved'] ?? null, 'the sampled confirmation increments the bucket RESOLVED counter exactly once');
    }

    /**
     * confirmCorrection: an application-level label correction of a
     * decision (e.g. a fraud-review appeal or chargeback verdict flipped
     * the class). Maps $samplingProbabilityPpm to the engine weight
     * exactly like confirmDecisionOutcome (weight = 1_000_000/ppm). The
     * outcome ledger guards the compensating-state API: the first
     * correction flips the ledger (1 -> 2) and reverses the recorded
     * bucket counts. The second correction of the same decision is a
     * no-op — retries can never double-compensate, and the calibration
     * aggregates return to the pre-confirmation state.
     */
    public function testConfirmCorrectionIsOnceOnlyAndReversesBuckets(): void
    {
        $client = new FakePredisClient();
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
        $calibrator = new AggregateCalibrator($client, 'cal-corr', samplingMode: 'complete');
        $engine = new AdaptiveRiskEngine(
            $store,
            $classifier,
            new RiskIdentityFactory($keys),
            new RiskScorer(),
            $policy,
            $keys,
            calibration: $calibrator,
        );
        $gateway = new RiskGateway($engine, $classifier, new RiskProfileResolver(PoWAlgorithm::Sha256, 8), ['login' => 1]);

        // A decision was assessed and confirmed (score 100, legit) — the
        // buckets hold the recorded outcome.
        $calibrator->recordReceipt('corr-1', 1, 0, RiskAction::Allow, 100, 1, 172800, 1.0);
        self::assertSame(1, $gateway->confirmDecisionOutcome('corr-1', true), 'the first confirmation records the outcome');
        $hour = 172800;
        $bucket = "{kiwi:cal-corr}:cal:1:{$hour}";
        self::assertSame(1.0, $client->hashes[$bucket]['legit_count'] ?? null);
        self::assertSame(100.0, $client->hashes[$bucket]['legit_score_sum'] ?? null);

        // First correction: the ledger flips to 2 and the recorded bucket
        // deltas are reversed exactly.
        self::assertTrue($gateway->confirmCorrection('corr-1', false), 'the first correction applies the compensation');
        $ledger = json_decode($client->strings['{kiwi:cal-corr}:outcome:corr-1'], true);
        self::assertSame('A', $ledger['o'], 'the outcome ledger is flipped to the corrected outcome (abuse)');
        self::assertSame(0.0, $client->hashes[$bucket]['legit_count'] ?? null, 'the reversal returns legit_count to 0');
        self::assertSame(0.0, $client->hashes[$bucket]['legit_score_sum'] ?? null, 'the reversal returns legit_score_sum to 0');

        // Same-target corrections are no-ops (the ledger already carries
        // the corrected outcome); a correction back to the opposite
        // outcome is a new explicit correction (each flip reverses the
        // bucket deltas again).
        self::assertFalse($gateway->confirmCorrection('corr-1', false), 'a correction to the current outcome is a no-op (false)');
        self::assertSame('A', json_decode($client->strings['{kiwi:cal-corr}:outcome:corr-1'], true)['o'], 'the flipped ledger stays flipped');
        self::assertTrue($gateway->confirmCorrection('corr-1', true), 'an explicit correction back to legitimate flips the ledger again');

        // Weighted-mode parity: a weighted confirmation is reversed by the
        // exact weighted deltas (weight = 1_000_000/500000 = 2.0).
        $calibrator->recordReceipt('corr-2', 1, 0, RiskAction::Allow, 100, 1, 172800, 1.0);
        self::assertSame(1, $gateway->confirmDecisionOutcome('corr-2', false, 500_000), 'a weighted confirmation records the outcome');
        self::assertSame(2.0, $client->hashes[$bucket]['abuse_count'] ?? null);
        self::assertTrue($gateway->confirmCorrection('corr-2', true, 500_000), 'weight = 1_000_000/500000 = 2.0 is passed to the engine');
        self::assertSame(0.0, $client->hashes[$bucket]['abuse_count'] ?? null, 'the weighted reversal returns abuse_count to 0');
        self::assertSame(0.0, $client->hashes[$bucket]['abuse_score_sum'] ?? null, 'the weighted reversal returns abuse_score_sum to 0');
        self::assertFalse($gateway->confirmCorrection('corr-2', true, 500_000), 'a retried correction of corr-2 is also once-only');

        // Out-of-range ppm is refused loudly.
        try {
            $gateway->confirmCorrection('corr-3', true, 0);
            self::fail('ppm 0 must be rejected');
        } catch (\InvalidArgumentException) {
            self::assertTrue(true);
        }
        try {
            $gateway->confirmCorrection('corr-4', true, 1_000_001);
            self::fail('ppm above 1_000_000 must be rejected');
        } catch (\InvalidArgumentException) {
            self::assertTrue(true);
        }
    }

    /**
     * confirmCorrection works without calibration: the once-only guard is
     * the state store's outcome ledger (registered at assessment time), so
     * a correction of a decision is applied at most once even when no
     * calibration store is attached.
     */
    public function testConfirmCorrectionWorksWithoutCalibration(): void
    {
        $store = new FakeRiskStateStore();
        $keys = RiskKeys::fromMaster(self::SECRET);
        $classifier = new CidrNetworkClassifier([]);
        $policy = RiskPolicy::fromConfig([
            'version' => RiskPolicy::CONTRACT_VERSION,
            'weights' => [],
            'scopes' => [
                1 => ['base_risk' => 100, 'minimum' => 'allow', 'post_solve_check' => false, 'degraded' => 'allow'],
            ],
        ]);
        $engine = new AdaptiveRiskEngine($store, $classifier, new RiskIdentityFactory($keys), new RiskScorer(), $policy, $keys);
        $gateway = new RiskGateway($engine, $classifier, new RiskProfileResolver(PoWAlgorithm::Sha256, 8), ['login' => 1]);

        // The engine registered the ledger when the decision was assessed.
        $decision = $gateway->preIssue('login', '198.51.100.7', null);
        self::assertSame(0, $store->ledger[$decision->decisionId]['status'], 'the assessment registers the outcome ledger (status 0)');

        // First correction: the ledger flips (the corrected outcome is
        // authoritative for future events). No synthetic
        // opposite-event compensation — the ephemeral reputation pressure
        // is left to decay naturally (Kiwi does not pretend to reverse
        // already-decayed leaky counters).
        self::assertTrue($gateway->confirmCorrection($decision->decisionId, true), 'a correction works without a calibration store');
        self::assertSame(2, $store->ledger[$decision->decisionId]['status'], 'the store ledger flips to corrected (status 2)');
        $events = array_map(static fn ($o): RiskEventKind => $o->event, $store->observations);
        self::assertSame([RiskEventKind::PreIssue], $events, 'a correction does not fabricate a synthetic reputation event');

        // Once-only: a second correction of the same decision is a no-op.
        self::assertFalse($gateway->confirmCorrection($decision->decisionId, true), 'a retried correction of the same decision is a no-op');
        self::assertCount(1, $store->observations, 'the retried correction records no additional observation');
    }

    /**
     * The context-ful reputation path and the calibration-only path compose:
     * recordConfirmedReputation confirms the receipt atomically (same
     * confirm.lua) and then records the reputation event.
     */
    public function testRecordConfirmedReputationConfirmsAndRecordsReputation(): void
    {
        $client = new FakePredisClient();
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
        $calibrator = new AggregateCalibrator($client, 'cal-rep', samplingMode: 'complete');
        $engine = new AdaptiveRiskEngine(
            $store,
            $classifier,
            new RiskIdentityFactory($keys),
            new RiskScorer(),
            $policy,
            $keys,
            calibration: $calibrator,
        );
        $gateway = new RiskGateway($engine, $classifier, new RiskProfileResolver(PoWAlgorithm::Sha256, 8), ['login' => 1]);

        $calibrator->recordReceipt('dec-1', 1, 0, RiskAction::Allow, 100, 1, 172800, 1.0);
        $receipt = $gateway->recordConfirmedReputation(true, 'login', '198.51.100.7', null, null, 'dec-1');

        self::assertInstanceOf(EventReceipt::class, $receipt);
        self::assertArrayNotHasKey('{kiwi:cal-rep}:cal:receipt:dec-1', $client->strings, 'the confirmation consumed the receipt atomically');
        $hour = 172800;
        self::assertSame(100.0, $client->hashes["{kiwi:cal-rep}:cal:1:{$hour}"]['legit_score_sum'] ?? null, 'the calibration side recorded the outcome');
        $events = array_map(static fn ($o): RiskEventKind => $o->event, $store->observations);
        self::assertSame([RiskEventKind::ConfirmedLegitimate], $events, 'the reputation event follows the atomic confirmation');
    }

    /**
     * Webhook retries must not amplify reputation: the engine gates the
     * reputation event on the confirm status (1/2 -> event; 0 -> none).
     * Re-delivering the same confirmation of the same decision records
     * the event at most once — a retried ConfirmedAbuse can never
     * re-penalize the source.
     */
    public function testConfirmedReputationRetryDoesNotAmplify(): void
    {
        $client = new FakePredisClient();
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
        $calibrator = new AggregateCalibrator($client, 'cal-rep-retry', samplingMode: 'complete');
        $engine = new AdaptiveRiskEngine(
            $store,
            $classifier,
            new RiskIdentityFactory($keys),
            new RiskScorer(),
            $policy,
            $keys,
            calibration: $calibrator,
        );
        $gateway = new RiskGateway($engine, $classifier, new RiskProfileResolver(PoWAlgorithm::Sha256, 8), ['login' => 1]);

        $calibrator->recordReceipt('dec-retry', 1, 0, RiskAction::Allow, 100, 1, 172800, 1.0);
        $first = $gateway->recordConfirmedReputation(false, 'login', '198.51.100.7', null, 'key-1', 'dec-retry');
        $retry = $gateway->recordConfirmedReputation(false, 'login', '198.51.100.7', null, 'key-2', 'dec-retry');

        self::assertInstanceOf(EventReceipt::class, $first, 'the first confirmation records the reputation event');
        self::assertFalse($first->isDuplicate, 'the first confirmation is a real (non-duplicate) event');
        self::assertInstanceOf(EventReceipt::class, $retry, 'a retried confirmation returns the duplicate-marked receipt');
        self::assertTrue($retry->isDuplicate, 'a retried confirmation of the same decision is marked duplicate (status 0 -> no reputation mutation)');
        $events = array_map(static fn ($o): RiskEventKind => $o->event, $store->observations);
        self::assertSame([RiskEventKind::ConfirmedAbuse], $events, 'at most ONE reputation mutation per decision — retries cannot amplify ConfirmedAbuse');
    }

    /**
     * The gateway's server-derived event methods must record their
     * corresponding RiskEventKind through record_feedback and return the
     * EventReceipt.
     */
    public function testServerDerivedEventMethodsRecordTheRightEvents(): void
    {
        $stack = $this->stack(new FakeRiskStateStore());
        $gateway = $stack['gateway'];

        $receipts = [
            $gateway->protectedActionSuccess('login', '198.51.100.7', null),
            $gateway->protectedActionFailure('login', '198.51.100.7', null),
            $gateway->authenticationSuccess('login', '198.51.100.7', null),
            $gateway->authenticationFailure('login', '198.51.100.7', null),
            $gateway->rateLimitHit('login', '198.51.100.7', null),
            $gateway->expiredChallenge('login', '198.51.100.7', null),
        ];
        foreach ($receipts as $receipt) {
            self::assertInstanceOf(EventReceipt::class, $receipt, 'each event method must return the engine EventReceipt');
        }

        $events = array_map(static fn ($o): RiskEventKind => $o->event, $stack['store']->observations);
        self::assertSame([
            RiskEventKind::ProtectedActionSuccess,
            RiskEventKind::ProtectedActionFailure,
            RiskEventKind::AuthenticationSuccess,
            RiskEventKind::AuthenticationFailure,
            RiskEventKind::RateLimitHit,
            RiskEventKind::ExpiredChallenge,
        ], $events);
    }

    /**
     * Every feedback path must survive an unknown scope in baseline/reject
     * modes (the engine declines to evaluate): the signal is skipped with a
     * debug log, never an exception, and the engine is never touched.
     */
    public function testFeedbackPathsSkipUnknownScopesWithoutThrowing(): void
    {
        $store = new FakeRiskStateStore();
        $keys = RiskKeys::fromMaster(self::SECRET);
        $classifier = new CidrNetworkClassifier([]);
        $policy = RiskPolicy::fromConfig([
            'version' => RiskPolicy::CONTRACT_VERSION,
            'weights' => [],
            'scopes' => [
                1 => ['base_risk' => 100, 'minimum' => 'allow', 'post_solve_check' => false, 'degraded' => 'allow'],
            ],
        ]);
        $engine = new AdaptiveRiskEngine($store, $classifier, new RiskIdentityFactory($keys), new RiskScorer(), $policy, $keys);
        $gateway = new RiskGateway($engine, $classifier, new RiskProfileResolver(PoWAlgorithm::Sha256, 8), ['login' => 1], null, null, [], 'baseline');

        self::assertNull($gateway->postSolveDecision('weird_unconfigured_scope', '198.51.100.7'));
        $gateway->challengeIssued('weird_unconfigured_scope', '198.51.100.7', null, 'did-x');
        $gateway->solveOutcome('weird_unconfigured_scope', '198.51.100.7', null, VerifyError::Expired);
        self::assertNull($gateway->confirmedLegitimate('weird_unconfigured_scope', '198.51.100.7', null, null, 'did-x'));
        self::assertNull($gateway->confirmedAbuse('weird_unconfigured_scope', '198.51.100.7', null, null, 'did-x'));
        self::assertNull($gateway->recordConfirmedReputation(true, 'weird_unconfigured_scope', '198.51.100.7', null, null, 'did-x'));
        self::assertNull($gateway->protectedActionSuccess('weird_unconfigured_scope', '198.51.100.7'));
        self::assertNull($gateway->protectedActionFailure('weird_unconfigured_scope', '198.51.100.7'));
        self::assertNull($gateway->authenticationSuccess('weird_unconfigured_scope', '198.51.100.7'));
        self::assertNull($gateway->authenticationFailure('weird_unconfigured_scope', '198.51.100.7'));
        self::assertNull($gateway->rateLimitHit('weird_unconfigured_scope', '198.51.100.7'));
        self::assertNull($gateway->expiredChallenge('weird_unconfigured_scope', '198.51.100.7'));

        self::assertSame([], $store->observations, 'no feedback may reach the engine for an unknown scope');
    }

    public function testRiskDenied429DoesNotDoubleCount(): void
    {
        // A Deny decision returns 429 risk_denied. The denial already scored
        // the evidence (PreIssue assessment + decision), so NO further
        // rate-limit event may be recorded — double-counting removed.
        $stack = $this->stack(new FakeRiskStateStore(SignalVector::fromArray(['replay' => 700])));

        $response = $stack['controller']->challenge($this->challengeRequest());
        self::assertSame(429, $response->getStatusCode());

        $events = array_map(static fn ($o): RiskEventKind => $o->event, $stack['store']->observations);
        self::assertSame([RiskEventKind::PreIssue], $events, 'the denial must not be double-counted with a rate-limit event');
    }

    public function testSourceRateLimitHitRecordedOnIssuerRateLimit429(): void
    {
        // The issuer's hard rate limit (per-client) returns 429 and the
        // refusal is recorded as SourceRateLimitHit feedback before the
        // response (per-source attribution; the global 429 uses
        // GlobalCapacityHit instead).
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
        $gateway = new RiskGateway($engine, $classifier, new RiskProfileResolver(PoWAlgorithm::Sha256, 8), ['login' => 1]);
        $limiter = new IssuanceRateLimiter(1, 60, null, null, 'test-pepper', null, 100, 'test-ns', 0);
        $controller = new ChallengeController($issuer, $limiter, true, $gateway, new ContinuityCookie());

        $request = JsonRequest::create('/kiwi-captcha/challenge', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7'], '{"scope":"login"}');
        self::assertSame(200, $controller->challenge($request)->getStatusCode());

        $response = $controller->challenge($request);
        self::assertSame(429, $response->getStatusCode());
        $body = json_decode((string) $response->getContent(), true);
        self::assertSame('RATE_LIMITED', $body['error']['code']);

        $events = array_map(static fn ($o): RiskEventKind => $o->event, $store->observations);
        self::assertSame([RiskEventKind::PreIssue, RiskEventKind::ChallengeIssued, RiskEventKind::SourceRateLimitHit], $events, 'the per-client rate-limit 429 must record SourceRateLimitHit before responding');
    }

    public function testGlobalCapacityHitRecordedOnGlobalRateLimit429(): void
    {
        // The deployment-global cap returns 429 global_rate_limited and the
        // refusal is recorded as GlobalCapacityHit — identity-neutral: the
        // canonical risk-v1 Lua adds global-only bad pressure and never
        // contaminates the visitor's source/session reputation.
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
        $gateway = new RiskGateway($engine, $classifier, new RiskProfileResolver(PoWAlgorithm::Sha256, 8), ['login' => 1]);
        // Global cap 1: the second request is refused by the deployment-wide
        // window, not the per-client one (Redis backend — the global cap is
        // only enforced atomically against Redis).
        $limiter = new IssuanceRateLimiter(100, 60, null, null, 'test-pepper', new FakePredisClient(), 1, 'test-ns', 0);
        $controller = new ChallengeController($issuer, $limiter, true, $gateway, new ContinuityCookie());

        $request = JsonRequest::create('/kiwi-captcha/challenge', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7'], '{"scope":"login"}');
        self::assertSame(200, $controller->challenge($request)->getStatusCode());

        $response = $controller->challenge($request);
        self::assertSame(429, $response->getStatusCode());
        $body = json_decode((string) $response->getContent(), true);
        self::assertSame('GLOBAL_RATE_LIMITED', $body['error']['code']);

        $events = array_map(static fn ($o): RiskEventKind => $o->event, $store->observations);
        self::assertSame([RiskEventKind::PreIssue, RiskEventKind::ChallengeIssued, RiskEventKind::GlobalCapacityHit], $events, 'the global rate-limit 429 must record GlobalCapacityHit before responding');
    }

    public function testIssuanceCounterIncrementsOnEveryIssuedChallenge(): void
    {
        // Every minted challenge increments the atomic per-second issuance
        // counter (one Lua script: incr + expire 1 — the TTL can never be
        // lost, so the signal always reflects the live second) that the
        // resource-pressure provider reads for issuanceCapacity.
        $client = new FakePredisClient();
        $counter = new IssuanceCounter($client, '{kiwi:test}:issuance:');
        $issuer = new Issuer(new Config(secretKey: self::SECRET, targetBits: 8, ttlSecs: 120), new ArrayStorage());
        $controller = new ChallengeController($issuer, null, true, null, null, $counter);

        $response = $controller->challenge($this->challengeRequest());
        self::assertSame(200, $response->getStatusCode());
        $controller->challenge($this->challengeRequest());

        $key = IssuanceCounter::rateKey('{kiwi:test}:issuance:');
        $evals = array_filter($client->calls, static fn (array $call): bool => $call[0] === 'EVAL' && ($call[1][1] ?? null) === 1 && $call[1][2] === $key);
        self::assertCount(2, $evals, 'one atomic INCR+EXPIRE EVAL per issued challenge');
        self::assertSame(2, $client->counters[$key], 'the counter must reflect both issuances');
        self::assertSame(1000, $client->expirations[$key], 'the atomic script must set EXPIRE 1 (1000 ms) so the signal reflects the live second');
    }

    /**
     * The gateway's rate-attribution methods record the exact new event
     * kinds: SourceRateLimitHit (15) with the source, GlobalCapacityHit
     * (16) identity-neutral (0.0.0.0 — the canonical Lua only raises the
     * global pressure for it), RiskDenied (17) with the source. An
     * unparseable IP skips the attributed source signals.
     */
    public function testRateAttributionGatewayMethodsRecordTheRightEvents(): void
    {
        $stack = $this->stack(new FakeRiskStateStore());
        $gateway = $stack['gateway'];

        $receipt = $gateway->sourceRateLimitHit(1, '198.51.100.7', 'sess-1');
        self::assertInstanceOf(EventReceipt::class, $receipt);
        $receipt = $gateway->globalCapacityHit(1, 'sess-1');
        self::assertInstanceOf(EventReceipt::class, $receipt);
        $receipt = $gateway->riskDenied(1, '198.51.100.7', 'sess-1');
        self::assertInstanceOf(EventReceipt::class, $receipt);

        $events = array_map(static fn ($o): RiskEventKind => $o->event, $stack['store']->observations);
        self::assertSame([
            RiskEventKind::SourceRateLimitHit,
            RiskEventKind::GlobalCapacityHit,
            RiskEventKind::RiskDenied,
        ], $events);

        // The GlobalCapacityHit observation is identity-neutral: its source
        // pseudonym is derived from the unspecified-address sentinel (the
        // canonical Lua mutates only the global state for event 16).
        $identityFactory = new RiskIdentityFactory(RiskKeys::fromMaster(self::SECRET));
        self::assertSame(1, $stack['store']->observations[1]->scope);
        self::assertSame($identityFactory->sessionId('sess-1'), $stack['store']->observations[1]->sessionId, 'the session signal is still carried');
        $neutralSource = $identityFactory->sourceId('0.0.0.0', time());
        self::assertSame($neutralSource, $stack['store']->observations[1]->sourceId, 'GlobalCapacityHit must not be attributed to a visitor source');

        // The attributed signals carry the real source pseudonym + session.
        $visitorSource = $identityFactory->sourceId('198.51.100.7', time());
        self::assertSame($visitorSource, $stack['store']->observations[0]->sourceId);
        self::assertSame($identityFactory->sessionId('sess-1'), $stack['store']->observations[0]->sessionId);
        self::assertSame($visitorSource, $stack['store']->observations[2]->sourceId);

        // Invalid client IP: nothing to attribute the source signals to.
        $store2 = new FakeRiskStateStore();
        $keys = RiskKeys::fromMaster(self::SECRET);
        $classifier = new CidrNetworkClassifier([]);
        $policy = RiskPolicy::fromConfig([
            'version' => RiskPolicy::CONTRACT_VERSION,
            'weights' => [],
            'scopes' => [
                1 => ['base_risk' => 100, 'minimum' => 'allow', 'post_solve_check' => false, 'degraded' => 'allow'],
            ],
        ]);
        $engine = new AdaptiveRiskEngine($store2, $classifier, new RiskIdentityFactory($keys), new RiskScorer(), $policy, $keys);
        $bare = new RiskGateway($engine, $classifier, new RiskProfileResolver(PoWAlgorithm::Sha256, 8), ['login' => 1]);
        self::assertNull($bare->sourceRateLimitHit(1, 'not-an-ip'));
        self::assertNull($bare->riskDenied(1, 'not-an-ip'));
        self::assertInstanceOf(EventReceipt::class, $bare->globalCapacityHit(1), 'global capacity needs no client IP');
        self::assertSame([RiskEventKind::GlobalCapacityHit], array_map(static fn ($o): RiskEventKind => $o->event, $store2->observations));
    }

    /**
     * nonce -> decision consumption (no post_solve_check): after a valid
     * solve the validator decodes the bounded solution token and consumes
     * the nonce -> decision handle (getdel). It sets the original
     * pre-issue decision id as the request's current decision id, so the
     * application can confirm this challenge's original decision.
     */
    public function testValidatorConsumesNonceMappingAndConfirmsPreIssueDecision(): void
    {
        $client = new FakePredisClient();
        $store = new FakeRiskStateStore();
        $storage = new ArrayStorage();
        $issuer = new Issuer(new Config(secretKey: self::SECRET, targetBits: 8, ttlSecs: 120), $storage);
        $verifier = new Verifier($storage);
        $keys = RiskKeys::fromMaster(self::SECRET);
        $identityFactory = new RiskIdentityFactory($keys);
        $classifier = new CidrNetworkClassifier([]);
        $policy = RiskPolicy::fromConfig([
            'version' => RiskPolicy::CONTRACT_VERSION,
            'weights' => [],
            'scopes' => [
                1 => ['base_risk' => 100, 'minimum' => 'allow', 'post_solve_check' => false, 'degraded' => 'allow'],
            ],
        ]);
        $engine = new AdaptiveRiskEngine($store, $classifier, $identityFactory, new RiskScorer(), $policy, $keys);
        $stack = new RequestStack();
        $gateway = new RiskGateway(
            $engine,
            $classifier,
            new RiskProfileResolver(PoWAlgorithm::Sha256, 8),
            ['login' => 1],
            requestStack: $stack,
            decisionRedis: $client,
            decisionKeyPrefix: '{kiwi:t}:decision:',
        );

        // The challenge request pairs the minted nonce to the pre-issue
        // decision id (as the controller does).
        $challenge = $issuer->issue('login', '198.51.100.7');
        $preIssue = $gateway->preIssue('login', '198.51.100.7', null);
        $gateway->attachDecisionForNonce($challenge->nonce, $preIssue->decisionId);

        // The verification request is a fresh request (empty attributes).
        $request = JsonRequest::create('/', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7']);
        $stack->push($request);
        $validator = new KiwiCaptchaValidator($verifier, $stack, self::SECRET, false, $gateway);
        $factory = new ConstraintValidatorFactory([KiwiCaptchaValidator::class => $validator]);
        $engineValidator = Validation::createValidatorBuilder()->setConstraintValidatorFactory($factory)->getValidator();

        usleep(((int) $challenge->minDurationMs + 10) * 1000);
        $dto = new class {
            public ?string $captcha = null;
        };
        $dto->captcha = $this->solve($challenge->prefix, $challenge->salt, $challenge->targetBits, $challenge->nonce);
        $meta = $engineValidator->getMetadataFor($dto::class);
        $meta->addPropertyConstraint('captcha', new KiwiCaptcha(['scope' => 'login']));

        $violations = $engineValidator->validate($dto);
        self::assertCount(0, $violations);

        self::assertSame($preIssue->decisionId, $gateway->currentDecisionId(), 'the ORIGINAL pre-issue decision becomes the request\'s current confirmation target');
        self::assertArrayNotHasKey('{kiwi:t}:decision:'.$challenge->nonce, $client->strings, 'the nonce -> decision handle was consumed (GETDEL)');
        self::assertNull($gateway->resolveDecisionForNonce($challenge->nonce), 'the handle is consumed once');
    }

    /**
     * nonce -> decision consumption (post_solve_check scope): the stale
     * mapping is still consumed as cleanup — it can never confirm against
     * a stale decision — and the fresh post-solve decision becomes the
     * current confirmation target.
     */
    public function testValidatorPostSolveScopeConsumesOldMappingAndTargetsPostSolveDecision(): void
    {
        $client = new FakePredisClient();
        $store = new FakeRiskStateStore();
        $storage = new ArrayStorage();
        $issuer = new Issuer(new Config(secretKey: self::SECRET, targetBits: 8, ttlSecs: 120), $storage);
        $verifier = new Verifier($storage);
        $keys = RiskKeys::fromMaster(self::SECRET);
        $identityFactory = new RiskIdentityFactory($keys);
        $classifier = new CidrNetworkClassifier([]);
        $policy = RiskPolicy::fromConfig([
            'version' => RiskPolicy::CONTRACT_VERSION,
            'weights' => [],
            'scopes' => [
                1 => ['base_risk' => 100, 'minimum' => 'allow', 'post_solve_check' => true, 'degraded' => 'allow'],
            ],
        ]);
        $engine = new AdaptiveRiskEngine($store, $classifier, $identityFactory, new RiskScorer(), $policy, $keys);
        $stack = new RequestStack();
        $gateway = new RiskGateway(
            $engine,
            $classifier,
            new RiskProfileResolver(PoWAlgorithm::Sha256, 8),
            ['login' => 1],
            null,
            null,
            ['login' => true],
            'reject',
            null,
            null,
            $stack,
            $client,
            '{kiwi:t}:decision:',
        );

        $challenge = $issuer->issue('login', '198.51.100.7');
        $preIssue = $gateway->preIssue('login', '198.51.100.7', null);
        $gateway->attachDecisionForNonce($challenge->nonce, $preIssue->decisionId);
        $gateway->setCurrentDecisionId('stale-target');
        $stack->push(JsonRequest::create('/', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7']));
        $validator = new KiwiCaptchaValidator($verifier, $stack, self::SECRET, false, $gateway);
        $factory = new ConstraintValidatorFactory([KiwiCaptchaValidator::class => $validator]);
        $engineValidator = Validation::createValidatorBuilder()->setConstraintValidatorFactory($factory)->getValidator();

        usleep(((int) $challenge->minDurationMs + 10) * 1000);
        $dto = new class {
            public ?string $captcha = null;
        };
        $dto->captcha = $this->solve($challenge->prefix, $challenge->salt, $challenge->targetBits, $challenge->nonce);
        $meta = $engineValidator->getMetadataFor($dto::class);
        $meta->addPropertyConstraint('captcha', new KiwiCaptcha(['scope' => 'login']));

        $violations = $engineValidator->validate($dto);
        self::assertCount(0, $violations);

        // The stale mapping was consumed for cleanup and discarded.
        self::assertArrayNotHasKey('{kiwi:t}:decision:'.$challenge->nonce, $client->strings, 'the stale mapping must be consumed even on post_solve_check scopes');
        // The fresh post-solve decision is the current confirmation target —
        // never the stale pre-issue decision.
        $confirmationTarget = $gateway->currentDecisionId();
        self::assertNotNull($confirmationTarget, 'the post-solve decision must become the confirmation target');
        self::assertNotSame($preIssue->decisionId, $confirmationTarget, 'the stale pre-issue decision must NOT be the confirmation target');
        $events = array_map(static fn ($o): RiskEventKind => $o->event, $store->observations);
        self::assertSame([RiskEventKind::PreIssue, RiskEventKind::SolveSuccess], $events, 'the valid solve runs exactly one post-solve reassessment');
    }

    /**
     * Real-Redis verification of the canonical risk-v1 Lua semantics for
     * GlobalCapacityHit: the global-only bad pressure raises the global
     * state and never touches the visitor's source reputation.
     */
    public function testRealRedisGlobalCapacityHitIsIdentityNeutral(): void
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

        $store = new RedisRiskStateStore(
            $client,
            'ci-risk-global-only',
            900,
            900,
            1800,
            principalTtlSecs: 86400,
            sessionTtlSecs: 1800,
            dedupeTtlSecs: 60,
            hysteresisMs: 60000,
        );
        $stack = $this->stack($store);
        $gateway = $stack['gateway'];

        // Attribute a per-source refusal first (SourceRateLimitHit adds
        // bad+3000 on the source)...
        $gateway->sourceRateLimitHit(1, '198.51.100.7', null);
        $identityFactory = new RiskIdentityFactory(RiskKeys::fromMaster(self::SECRET));
        $nowSecs = time();
        $epoch = intdiv($nowSecs, 900);
        $sourceKey = sprintf('{kiwi:ci-risk-global-only}:risk:src:%d:%s', $epoch, $identityFactory->sourceId('198.51.100.7', $nowSecs));
        $globalKey = '{kiwi:ci-risk-global-only}:risk:global';
        $sourceBadBefore = (int) ($client->hget($sourceKey, 'bad') ?? 0);
        $globalBadBefore = (int) ($client->hget($globalKey, 'bad') ?? 0);
        self::assertGreaterThanOrEqual(3000, $sourceBadBefore, 'the per-source refusal must have raised the source bad pressure');

        // ...then a deployment-capacity refusal (GlobalCapacityHit).
        $gateway->globalCapacityHit(1, null);

        $sourceBadAfter = (int) ($client->hget($sourceKey, 'bad') ?? 0);
        $globalBadAfter = (int) ($client->hget($globalKey, 'bad') ?? 0);
        self::assertSame($sourceBadBefore, $sourceBadAfter, 'GlobalCapacityHit must never contaminate the visitor\'s source reputation');
        self::assertGreaterThan($globalBadBefore, $globalBadAfter, 'GlobalCapacityHit must raise the global attack/resource pressure');

        // Cleanup the test namespace.
        foreach ($client->keys('{kiwi:ci-risk-global-only}:*') ?: [] as $key) {
            $client->del($key);
        }
        $client->disconnect();
    }

    /**
     * Solve a sha256 challenge in pure PHP (fast 8-bit difficulty).
     */
    private function solve(string $prefix, string $salt, int $targetBits, string $nonce): string
    {
        $saltBytes = base64_decode($salt, true);
        $counter = 0;
        do {
            $hash = hash('sha256', $prefix.$counter.$saltBytes, true);
            $counter++;
        } while (Verifier::leadingZeroBits($hash) < $targetBits);
        --$counter;

        return \KiwiCaptcha\SolutionToken::create($nonce, $counter, 5000, [])->encode();
    }
}
