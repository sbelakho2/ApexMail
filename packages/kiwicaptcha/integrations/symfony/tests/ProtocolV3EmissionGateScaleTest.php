<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests;

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
use KiwiCaptcha\Risk\RiskIdentityFactory;
use KiwiCaptcha\Risk\RiskKeys;
use KiwiCaptcha\Risk\RiskPolicy;
use KiwiCaptcha\Risk\RiskScorer;
use KiwiCaptcha\Storage\ArrayStorage;
use KiwiCaptcha\Verifier;
use PHPUnit\Framework\TestCase;
use Psr\Log\LoggerInterface;
use Symfony\Component\HttpFoundation\Request;

/**
 * The protocol-v3 emission gate matrix at scale.
 *
 * The single-issuance cells of ProtocolV3EmissionGateTest are extended
 * here to whole-batch assertions. Every issuance under a gate
 * configuration must agree with the matrix, and the documented
 * two-phase rollout must move a live issuance fleet through the
 * transitions: v2-only, mixed, v3-enabled with the central floor
 * raised, then the rollback.
 *
 * The gate rule is total across the batch. A disabled writer switch
 * emits v2 even with the floor at 3. An enabled switch with the floor
 * at 3 arms every issuance. An enabled switch with the floor at 2
 * stays at v2 with a single once-per-process warning.
 */
final class ProtocolV3EmissionGateScaleTest extends TestCase
{
    private const SECRET = '0123456789abcdef0123456789abcdef';

    private const POLICY_KEY = '{kiwi:test-ns}:security-policy';

    private const BATCH = 30;

    /**
     * A risk-wired controller over one ArrayStorage, with the v3 gate
     * parameters injected: the risk.decoy_v3_enabled writer switch and
     * the central floor reported by the fake security Redis. The
     * optional monitor clock (a callable returning float ms) lets tests
     * cross the cache window.
     *
     * @param callable(): float|null $nowMs
     *
     * @return array{controller: ChallengeController, storage: ArrayStorage, redis: FakePredisClient, monitor: SecurityEpochMonitor, gateway: RiskGateway, logger: EmissionGateScaleLoggerSpy}
     */
    private function stack(bool $decoyV3Enabled, ?int $floor, $nowMs = null): array
    {
        $storage = new ArrayStorage();
        $issuer = new Issuer(new Config(secretKey: self::SECRET, targetBits: 8, ttlSecs: 120), $storage);
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

        $redis = new FakePredisClient();
        if ($floor !== null) {
            $redis->hset(self::POLICY_KEY, SecurityEpochMonitor::MIN_PROTOCOL_VERSION_FIELD, (string) $floor);
            $redis->hset(self::POLICY_KEY, SecurityEpochMonitor::MIN_POLICY_EPOCH_FIELD, '1');
        }
        $monitor = new SecurityEpochMonitor(new Verifier(new ArrayStorage()), $redis, 'test-ns', 1, 1, $nowMs);
        $logger = new EmissionGateScaleLoggerSpy();
        $controller = $this->controllerFor($issuer, $storage, $gateway, $monitor, $decoyV3Enabled, $logger);

        return ['controller' => $controller, 'storage' => $storage, 'redis' => $redis, 'monitor' => $monitor, 'gateway' => $gateway, 'logger' => $logger];
    }

    private function controllerFor(
        Issuer $issuer,
        ArrayStorage $storage,
        RiskGateway $gateway,
        SecurityEpochMonitor $monitor,
        bool $decoyV3Enabled,
        EmissionGateScaleLoggerSpy $logger,
    ): ChallengeController {
        return new ChallengeController(
            $issuer,
            null,
            true,
            $gateway,
            new ContinuityCookie(),
            epochMonitor: $monitor,
            decoyV3Enabled: $decoyV3Enabled,
            logger: $logger,
        );
    }

    private function challengeRequest(): Request
    {
        return JsonRequest::create(
            '/kiwi-captcha/challenge',
            'POST',
            [],
            [],
            [],
            ['REMOTE_ADDR' => '198.51.100.7'],
            '{"scope":"login"}',
        );
    }

    /**
     * @return array{0: int, 1: array<string, mixed>}
     */
    private function issue(ChallengeController $controller): array
    {
        $response = $controller->challenge($this->challengeRequest());

        return [$response->getStatusCode(), json_decode((string) $response->getContent(), true)];
    }

    /**
     * Issue a batch and assert every record of the batch observes the
     * expected protocol, the decoy response surface, and the authenticated
     * decoy name when armed.
     *
     * @param list<array{0: int, 1: array<string, mixed>}> $responses
     */
    private function assertBatchProtocol(ArrayStorage $storage, array $responses, int $expectedProtocol, bool $armed, int $expectedCount = self::BATCH): void
    {
        self::assertCount($expectedCount, $responses, 'the batch must be complete');
        $decoyNames = [];
        foreach ($responses as [$status, $data]) {
            self::assertSame(200, $status);
            $record = $storage->find($data['nonce']);
            self::assertNotNull($record);
            self::assertSame($expectedProtocol, $record->protocolVersion, 'every record of the batch must observe the gate protocol');
            if ($armed) {
                self::assertIsString($data['decoy_field'] ?? null, 'an armed batch carries the authenticated decoy name on every response');
                self::assertTrue(Issuer::isGrammarDecoyName((string) $data['decoy_field']), 'the armed name must come from the combinatorial grammar');
                self::assertSame($data['decoy_field'], $record->decoyField, 'the response name equals the stored authenticated name');
                $decoyNames[] = $data['decoy_field'];
            } else {
                self::assertArrayNotHasKey('decoy_field', $data, 'an unarmed batch never exposes the decoy key');
                self::assertNull($record->decoyField);
            }
        }
        if ($armed) {
            self::assertCount($expectedCount, array_unique($decoyNames), 'every armed issuance draws a fresh name, never a repeat');
        }
    }

    public function testDisabledGateEmitsV2AtScaleEvenWithFloorThree(): void
    {
        // The default writer switch stays at v2 across the whole batch
        // even when the central floor is already 3: a new binary never
        // emits a challenge a parent-revision verifier rejects.
        $stack = $this->stack(false, 3);
        $responses = [];
        for ($i = 0; $i < self::BATCH; $i++) {
            $responses[] = $this->issue($stack['controller']);
        }
        $this->assertBatchProtocol($stack['storage'], $responses, 2, false);
        self::assertSame([], $stack['logger']->warnings, 'a disabled gate logs no warning at any volume');
        self::assertSame([], $stack['logger']->infos, 'no info-level noise either');
    }

    public function testEnabledWithFloorThreeArmsEveryIssuanceAtScale(): void
    {
        // The operator completed the two-phase rollout: writer switch on
        // and the central floor at 3. The entire batch is armed protocol
        // v3 with a fresh grammar name per issuance.
        $stack = $this->stack(true, 3);
        $responses = [];
        for ($i = 0; $i < self::BATCH; $i++) {
            $responses[] = $this->issue($stack['controller']);
        }
        $this->assertBatchProtocol($stack['storage'], $responses, 3, true);
        self::assertSame([], $stack['logger']->warnings, 'a fully rolled-out v3 fleet logs no warning at any volume');
    }

    public function testEnabledWithFloorTwoEmitsV2AtScaleWithOneWarning(): void
    {
        // The writer switch is on but the central floor still says 2:
        // the whole batch stays at protocol v2 (availability preserved)
        // and the actionable warning fires once for the process, never
        // once per issuance.
        $stack = $this->stack(true, 2);
        $responses = [];
        for ($i = 0; $i < self::BATCH; $i++) {
            $responses[] = $this->issue($stack['controller']);
        }
        $this->assertBatchProtocol($stack['storage'], $responses, 2, false);
        self::assertCount(1, $stack['logger']->warnings, 'the gate warning fires once per process, never per issuance');
        self::assertStringContainsString('min_protocol_version', $stack['logger']->warnings[0], 'the warning names the central floor field');
        self::assertStringContainsString('is 2', $stack['logger']->warnings[0], 'the warning names the lowered floor');
        self::assertSame([], $stack['logger']->infos, 'no info-level noise either');
    }

    public function testTwoPhaseRolloutTransitionsAtScale(): void
    {
        // Phase one, the v2-only fleet: the new binaries ship with the
        // writer switch off, so every issuance is protocol v2 even under
        // a floor that could never arm anything.
        $clock = [0.0];
        $stack = $this->stack(false, 2, static function () use (&$clock): float {
            return $clock[0];
        });
        $phaseOne = [];
        for ($i = 0; $i < 10; $i++) {
            $phaseOne[] = $this->issue($stack['controller']);
        }
        $this->assertBatchProtocol($stack['storage'], $phaseOne, 2, false, 10);
        self::assertSame([], $stack['logger']->warnings, 'the v2-only fleet is silent');

        // Phase two, the mixed fleet: the operator flips the writer
        // switch while the central floor is still 2. The gate must keep
        // the whole batch at v2, with the once-per-process warning.
        $mixedController = $this->controllerFor(
            new Issuer(new Config(secretKey: self::SECRET, targetBits: 8, ttlSecs: 120), $stack['storage']),
            $stack['storage'],
            $stack['gateway'],
            $stack['monitor'],
            true,
            $stack['logger'],
        );
        $phaseTwo = [];
        for ($i = 0; $i < 10; $i++) {
            $phaseTwo[] = $this->issue($mixedController);
        }
        $this->assertBatchProtocol($stack['storage'], $phaseTwo, 2, false, 10);
        self::assertCount(1, $stack['logger']->warnings, 'the mixed fleet fires the floor warning exactly once');

        // Phase three, v3-enabled: the central floor is raised to 3 and
        // the next cache-window re-read confirms it. The whole batch arms.
        $stack['redis']->hset(self::POLICY_KEY, SecurityEpochMonitor::MIN_PROTOCOL_VERSION_FIELD, '3');
        $clock[0] = 2000.0;
        $phaseThree = [];
        for ($i = 0; $i < 10; $i++) {
            $phaseThree[] = $this->issue($mixedController);
        }
        $this->assertBatchProtocol($stack['storage'], $phaseThree, 3, true, 10);

        // Phase four, the rollback: the floor drops back to 2, the next
        // re-read observes it, and the fleet emits v2 again. The floor is
        // a non-monotonic capability signal, never a sticky 3.
        $stack['redis']->hset(self::POLICY_KEY, SecurityEpochMonitor::MIN_PROTOCOL_VERSION_FIELD, '2');
        $clock[0] = 4000.0;
        $phaseFour = [];
        for ($i = 0; $i < 10; $i++) {
            $phaseFour[] = $this->issue($mixedController);
        }
        $this->assertBatchProtocol($stack['storage'], $phaseFour, 2, false, 10);
        self::assertCount(1, $stack['logger']->warnings, 'the rollback logs no second warning, the once-per-process contract holds');
    }
}

/**
 * Minimal PSR-3 logger spy for the scale matrix: records warnings and
 * infos in-process so the gate tests can assert the once-per-process
 * warning without a real logger backend.
 */
final class EmissionGateScaleLoggerSpy implements LoggerInterface
{
    /** @var list<string> */
    public array $warnings = [];

    /** @var list<string> */
    public array $infos = [];

    public function warning(string|\Stringable $message, array $context = []): void
    {
        $this->warnings[] = (string) $message;
    }

    public function info(string|\Stringable $message, array $context = []): void
    {
        $this->infos[] = (string) $message;
    }

    public function emergency(string|\Stringable $message, array $context = []): void
    {
    }

    public function alert(string|\Stringable $message, array $context = []): void
    {
    }

    public function critical(string|\Stringable $message, array $context = []): void
    {
    }

    public function error(string|\Stringable $message, array $context = []): void
    {
    }

    public function notice(string|\Stringable $message, array $context = []): void
    {
    }

    public function debug(string|\Stringable $message, array $context = []): void
    {
    }

    public function log($level, string|\Stringable $message, array $context = []): void
    {
    }
}
