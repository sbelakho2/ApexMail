<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests\Kernel;

use BelConsulting\KiwiCaptchaBundle\Risk\DecoyEscalationScriptRunner;
use BelConsulting\KiwiCaptchaBundle\Risk\RiskGateway;
use BelConsulting\KiwiCaptchaBundle\Risk\RiskProfileResolver;
use KiwiCaptcha\PoWAlgorithm;
use KiwiCaptcha\Risk\AdaptiveRiskEngine;
use KiwiCaptcha\Risk\Evidence\AutofillQualificationGate;
use KiwiCaptcha\Risk\Evidence\DecoyEscalationStore;
use KiwiCaptcha\Risk\Network\CidrNetworkClassifier;
use KiwiCaptcha\Risk\RiskAction;
use KiwiCaptcha\Risk\RiskIdentityFactory;
use KiwiCaptcha\Risk\RiskKeys;
use KiwiCaptcha\Risk\RiskPolicy;
use KiwiCaptcha\Risk\RiskReason;
use KiwiCaptcha\Risk\RiskScorer;
use KiwiCaptcha\Risk\Storage\RedisRiskStateStore;
use PHPUnit\Framework\TestCase;
use Symfony\Component\DependencyInjection\ContainerInterface;
use Symfony\Component\HttpFoundation\Request;

/**
 * The decoy escalation of change.md 3.2.2 over the full bundle. The
 * engine composes the escalation stage through the wired store: the
 * container's engine reader is the extension-built DecoyEscalationStore
 * over the bundle's script runner, the committed qualification gate and
 * the deployment namespace. The gateway's server-confirmed-hit record
 * call writes through the same identity the engine's read consults. The
 * canonical 10-minute record raises the session's next assessment by
 * exactly one rung.
 *
 * The committed matrix stands fail-closed, so the container-level
 * record path writes nothing. The open-gate leg runs the identical
 * store and reader over a qualified fixture matrix.
 *
 * Gated on KC_REDIS_URL like every real-Redis test (the escalation
 * record and the engine pipeline run the canonical Lua).
 */
final class DecoyEscalationKernelTest extends TestCase
{
    private static ?EvidenceCompositionTestKernel $kernel = null;
    private static ContainerInterface $container;

    private const COOKIE = '__Host-kiwi-session';
    private const NAMESPACE_SEGMENT = 'e2e-evidence';

    public static function setUpBeforeClass(): void
    {
        if (EvidenceCompositionTestKernel::redisUrl() === null) {
            self::markTestSkipped('KC_REDIS_URL not set — the decoy-escalation proof needs the real risk Lua');
        }
        self::$kernel = new EvidenceCompositionTestKernel('test', true);
        self::$kernel->boot();
        self::$container = self::$kernel->getContainer()->get('test.service_container');
    }

    protected function setUp(): void
    {
        if (EvidenceCompositionTestKernel::redisUrl() === null) {
            self::markTestSkipped('KC_REDIS_URL not set');
        }
        // Each leg starts from a quiet store: the aggregate channels are
        // namespace-global, so a previous leg's pressure and records must
        // never leak into the next leg's assertions.
        self::redis()->flushdb();
    }

    private static function redis(): \Predis\Client
    {
        return self::$container->get('kiwi_e2e_redis');
    }

    private static function freshSession(): string
    {
        return bin2hex(random_bytes(16));
    }

    public function testTheEngineReaderIsTheExtensionBuiltStore(): void
    {
        $engine = self::$container->get('kiwi_captcha.risk.engine');
        $reader = (new \ReflectionProperty(AdaptiveRiskEngine::class, 'decoyEscalationReader'))->getValue($engine);
        self::assertInstanceOf(DecoyEscalationStore::class, $reader);
        self::assertSame(self::$container->get('kiwi_captcha.risk.decoy_escalation'), $reader);

        // The committed matrix stands fail-closed on purpose: no real
        // qualification has happened, so the wired gate must refuse.
        $gate = self::$container->get('kiwi_captcha.risk.autofill_gate');
        self::assertInstanceOf(AutofillQualificationGate::class, $gate);
        self::assertFalse($gate->isOpen());
    }

    public function testTheClosedGateMakesTheConfirmedHitAWriteNothingNoOp(): void
    {
        $session = self::freshSession();
        self::$container->get('request_stack')->push(
            Request::create('https://captcha.example.com/login', 'POST', [], [self::COOKIE => $session])
        );
        self::$container->get(RiskGateway::class)->recordConfirmedDecoyHit($session);
        self::$container->get('request_stack')->pop();

        $keys = self::redis()->keys('decoy_esc:'.self::NAMESPACE_SEGMENT.':*');
        self::assertSame([], $keys, 'the closed qualification gate must write nothing');
    }

    public function testTheGatewayRecordCallDegradesSilentlyWithoutASession(): void
    {
        // No cookie in scope, and a malformed session value: both legs
        // are silent no-ops (evidence only, never a form breaker).
        self::$container->get(RiskGateway::class)->recordConfirmedDecoyHit(null);
        self::$container->get(RiskGateway::class)->recordConfirmedDecoyHit('not-a-cookie-value');
        self::assertSame([], self::redis()->keys('decoy_esc:'.self::NAMESPACE_SEGMENT.':*'));
    }

    public function testTheTenMinuteRecordRaisesTheNextAssessmentByOneRung(): void
    {
        $identityFactory = self::$container->get('kiwi_captcha.risk.identity_factory');
        $keys = RiskKeys::fromMaster(EvidenceCompositionTestKernel::SECRET);

        // The open-gate leg: the identical store and runner surface over
        // a qualified fixture matrix (the committed registry's surfaces
        // with passing rows), the exact runtime shape an operator gets
        // once the manual qualification rows land.
        $store = new DecoyEscalationStore(
            new DecoyEscalationScriptRunner(self::redis()),
            self::openGate(),
            self::NAMESPACE_SEGMENT,
        );

        $plainSession = self::freshSession();
        $escalatedSession = self::freshSession();

        // The record write: the server-confirmed hit books the 10-minute
        // escalation record under the session's keyed pseudonym, the
        // identity the engine's own read consults.
        $pseudonym = $identityFactory->sessionId($escalatedSession);
        self::assertSame(1, $store->recordConfirmedHit($pseudonym), 'the open gate lets the confirmed hit write');
        self::assertTrue($store->escalationLive($pseudonym), 'the record is live inside its window');
        $recordKey = 'decoy_esc:'.self::NAMESPACE_SEGMENT.':'.$pseudonym;
        self::assertSame(1, (int) self::redis()->exists($recordKey), 'the canonical record key exists');
        $ttlMs = (int) self::redis()->pttl($recordKey);
        self::assertGreaterThan(0, $ttlMs, 'the record carries a live TTL');
        self::assertLessThanOrEqual(600000, $ttlMs, 'the window is the canonical ten minutes');

        // The next session assessment: the identical engine pipeline with
        // and without the escalation reader, each leg over its own fresh
        // risk namespace and distinct sessions and sources, so the single
        // difference is the live record.
        $engineWith = self::engine($keys, $store, 'e2e-evidence-decoy-with');
        $engineWithout = self::engine($keys, null, 'e2e-evidence-decoy-without');
        $base = self::gateway($engineWithout)->preIssue('login', '10.70.0.1', $plainSession);
        $escalated = self::gateway($engineWith)->preIssue('login', '10.70.0.2', $escalatedSession);

        self::assertSame(RiskAction::Allow, $base->action, 'the session without a record keeps the plain rung');
        self::assertSame(
            $base->action->rank() + 1,
            $escalated->action->rank(),
            sprintf('the live record raises the next assessment by exactly one rung (%s -> %s)', $base->action->value, $escalated->action->value),
        );
        self::assertTrue($escalated->hasReason(RiskReason::DecoyEscalation), 'the stage reason names the escalation');
    }

    public function testTheGatewayRecordCallWritesThroughTheOpenStore(): void
    {
        $identityFactory = self::$container->get('kiwi_captcha.risk.identity_factory');
        $openStore = new DecoyEscalationStore(
            new DecoyEscalationScriptRunner(self::redis()),
            self::openGate(),
            self::NAMESPACE_SEGMENT,
        );
        // The gateway shape the extension builds, with the qualification
        // gate open: the record call derives the keyed pseudonym and
        // writes through the store.
        $gateway = new RiskGateway(
            self::engine(RiskKeys::fromMaster(EvidenceCompositionTestKernel::SECRET), $openStore),
            new CidrNetworkClassifier([]),
            new RiskProfileResolver(PoWAlgorithm::Sha256, 8),
            ['login' => 1],
            decoyEscalation: $openStore,
            identityFactory: $identityFactory,
        );

        $session = self::freshSession();
        self::$container->get('request_stack')->push(
            Request::create('https://captcha.example.com/login', 'POST', [], [self::COOKIE => $session])
        );
        $gateway->recordConfirmedDecoyHit($session);
        self::$container->get('request_stack')->pop();

        self::assertTrue($openStore->escalationLive($identityFactory->sessionId($session)), 'the gateway record call armed the session escalation');
        $keys = self::redis()->keys('decoy_esc:'.self::NAMESPACE_SEGMENT.':*');
        self::assertCount(1, $keys, 'exactly the new session record exists');
    }

    /** One engine over the real risk state store, with the given reader. */
    private static function engine(RiskKeys $keys, ?DecoyEscalationStore $reader, string $riskNamespace = self::NAMESPACE_SEGMENT): AdaptiveRiskEngine
    {
        $policy = RiskPolicy::fromConfig([
            'version' => RiskPolicy::CONTRACT_VERSION,
            'global_floors' => [0 => 'allow', 1 => 'sha16', 2 => 'sha18', 3 => 'sha20', 4 => 'sha20'],
            'weights' => [],
            'scopes' => [
                1 => ['base_risk' => 100, 'minimum' => 'allow', 'post_solve_check' => false, 'degraded' => 'allow'],
            ],
        ]);

        return new AdaptiveRiskEngine(
            new RedisRiskStateStore(self::redis(), $riskNamespace),
            new CidrNetworkClassifier([]),
            new RiskIdentityFactory($keys),
            new RiskScorer(),
            $policy,
            $keys,
            decoyEscalationReader: $reader,
        );
    }

    private static function gateway(AdaptiveRiskEngine $engine): RiskGateway
    {
        return new RiskGateway(
            $engine,
            new CidrNetworkClassifier([]),
            new RiskProfileResolver(PoWAlgorithm::Sha256, 8),
            ['login' => 1],
        );
    }

    /** The qualified fixture gate over the committed registry surfaces. */
    private static function openGate(): AutofillQualificationGate
    {
        $registryPath = dirname(__DIR__, 6).'/tests/browser/qualification/surfaces.json';
        self::assertFileExists($registryPath, 'the committed surface registry must ship with the repository');
        $registry = json_decode((string) file_get_contents($registryPath), true, 16, JSON_THROW_ON_ERROR);
        $rows = [];
        foreach ($registry['surfaces'] as $surface) {
            $rows[] = [
                'surface' => $surface['id'],
                'product' => $surface['product'] ?? 'test',
                'version' => '1.2.3',
                'platform' => $surface['platform'] ?? 'test',
                'status' => 'pass',
                'tested_at' => gmdate('Y-m-d\TH:i:s.v\Z'),
                'controls' => [
                    'negative' => ['result' => 'pass', 'note' => 'decoy stayed empty, honeypot_hit false'],
                    'positive' => ['result' => 'pass', 'note' => 'deliberate fill reported the hit'],
                ],
            ];
        }
        $path = tempnam(sys_get_temp_dir(), 'kiwi-matrix-');
        self::assertIsString($path);
        file_put_contents($path, json_encode([
            'schema' => 'kiwicaptcha.autofill-qualification/1',
            'rows' => $rows,
        ], JSON_THROW_ON_ERROR));

        return new AutofillQualificationGate($path, $registryPath, 90);
    }
}
