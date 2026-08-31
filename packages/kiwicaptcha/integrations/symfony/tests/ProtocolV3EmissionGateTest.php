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

/**
 * The protocol-v3 two-phase rollout gate: the challenge
 * controller arms the authenticated decoy (protocol v3 emission) only
 * when risk.decoy_v3_enabled is true AND the central security-policy
 * floor ({kiwi:<ns>}:security-policy min_protocol_version, read through
 * the SecurityEpochMonitor's cached central read) is confirmed >= 3.
 * The default (decoy_v3_enabled false) emits protocol v2 even with the
 * risk engine wired, so a new binary never emits a challenge a
 * parent-revision verifier rejects. Every uncertainty (floor 2,
 * absent/corrupt/unreadable central policy) fails safe to v2 with a
 * once-per-process actionable warning.
 */
final class ProtocolV3EmissionGateTest extends TestCase
{
    private const SECRET = '0123456789abcdef0123456789abcdef';

    private const POLICY_KEY = '{kiwi:test-ns}:security-policy';

    /**
     * A risk-wired controller over one ArrayStorage, with the v3 gate
     * parameters injected: the risk.decoy_v3_enabled writer switch, the
     * central floor reported by the fake security Redis, and an optional
     * monitor clock (a callable returning float ms). The clock lets
     * tests cross the cache window. A null floor leaves the fake policy
     * hash empty; a test can then hset the epoch field alone (the
     * absent-floor matrix cell) or a corrupt floor value. With
     * $wireEpochMonitor false no SecurityEpochMonitor is injected at all
     * (the no-security-Redis matrix cell: the floor can never be
     * confirmed).
     *
     * @param callable(): float|null $nowMs
     *
     * @return array{controller: ChallengeController, storage: ArrayStorage, redis: FakePredisClient, monitor: SecurityEpochMonitor, logger: LoggerSpy}
     */
    private function stack(bool $decoyV3Enabled, ?int $floor, $nowMs = null, bool $wireEpochMonitor = true): array
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
        $logger = new LoggerSpy();
        $controller = new ChallengeController(
            $issuer,
            null,
            true,
            $gateway,
            new ContinuityCookie(),
            epochMonitor: $wireEpochMonitor ? $monitor : null,
            decoyV3Enabled: $decoyV3Enabled,
            logger: $logger,
        );

        return ['controller' => $controller, 'storage' => $storage, 'redis' => $redis, 'monitor' => $monitor, 'logger' => $logger];
    }

    private function challengeRequest(): \Symfony\Component\HttpFoundation\Request
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
     * @return array{status: int, data: array<string, mixed>}
     */
    private function issue(ChallengeController $controller): array
    {
        $response = $controller->challenge($this->challengeRequest());

        return [$response->getStatusCode(), json_decode((string) $response->getContent(), true)];
    }

    public function testDefaultConfigEmitsV2EvenWithRiskWired(): void
    {
        // A new node used to arm the decoy whenever
        // risk was wired, immediately emitting protocol v3 challenges the
        // parent revision's verifiers reject as malformed. The default
        // (decoy_v3_enabled false) must keep emission at protocol v2 —
        // byte-compatible with every serving binary.
        $stack = $this->stack(false, 3);
        [$status, $data] = $this->issue($stack['controller']);
        self::assertSame(200, $status);
        self::assertArrayNotHasKey('decoy_field', $data, 'the default config never arms the decoy, even with risk wired and a floor of 3');

        $record = $stack['storage']->find($data['nonce']);
        self::assertNotNull($record);
        self::assertSame(2, $record->protocolVersion, 'the default config emits protocol v2');
        self::assertNull($record->decoyField);
        self::assertSame([], $stack['logger']->warnings, 'the default config is silent: v2 emission needs no warning');
    }

    public function testEnabledWithFloorThreeArmsProtocolV3(): void
    {
        // The operator completed the two-phase rollout: decoy_v3_enabled
        // true AND the central floor confirms 3. Issuance may arm the
        // decoy: the response carries the authenticated pool name and the
        // stored record is protocol v3.
        $stack = $this->stack(true, 3);
        [$status, $data] = $this->issue($stack['controller']);
        self::assertSame(200, $status);
        self::assertIsString($data['decoy_field'] ?? null, 'the armed issuance carries the authenticated decoy name');
        self::assertTrue(Issuer::isGrammarDecoyName((string) $data['decoy_field']), 'the armed name must come from the combinatorial grammar');

        $record = $stack['storage']->find($data['nonce']);
        self::assertNotNull($record);
        self::assertSame(3, $record->protocolVersion, 'an armed issuance writes protocol v3');
        self::assertSame($data['decoy_field'], $record->decoyField);
        self::assertSame([], $stack['logger']->warnings, 'a fully rolled-out v3 emission logs no warning');
    }

    public function testEnabledWithFloorTwoEmitsV2AndLogsTheWarningOnce(): void
    {
        // decoy_v3_enabled true but the central floor is still 2: the
        // fleet has not established that every serving binary supports
        // protocol 3, so issuance stays at v2 (availability preserved)
        // and the actionable warning fires exactly once per process.
        $stack = $this->stack(true, 2);
        [$status, $data] = $this->issue($stack['controller']);
        self::assertSame(200, $status);
        self::assertArrayNotHasKey('decoy_field', $data, 'a floor below 3 must keep emission at v2');

        $record = $stack['storage']->find($data['nonce']);
        self::assertNotNull($record);
        self::assertSame(2, $record->protocolVersion, 'a floor below 3 must emit protocol v2');

        // A second issuance in the same process must not re-log.
        [$status2, $data2] = $this->issue($stack['controller']);
        self::assertSame(200, $status2);
        self::assertArrayNotHasKey('decoy_field', $data2);
        self::assertSame([], $stack['logger']->infos, 'no info-level noise either');
        self::assertCount(1, $stack['logger']->warnings, 'the gate warning fires once per process, never per issuance');
        self::assertStringContainsString('min_protocol_version', $stack['logger']->warnings[0], 'the warning names the central floor field');
        self::assertStringContainsString('protocol v2', $stack['logger']->warnings[0], 'the warning states the fail-safe behavior');
    }

    public function testEnabledWithUnreadablePolicyFailsSafeToV2(): void
    {
        // Within the max-stale window the central read failing is NOT a
        // stale failure (issuance keeps serving) — but the last re-read
        // failed, so the floor is unconfirmed: fail safe to protocol v2,
        // never arm on uncertainty.
        $clock = [0.0];
        $stack = $this->stack(true, 3, static function () use (&$clock): float {
            return $clock[0];
        });
        [$status, $data] = $this->issue($stack['controller']);
        self::assertSame(200, $status);
        self::assertIsString($data['decoy_field'] ?? null, 'the first read confirms floor 3, so the issuance is armed');

        // Redis goes down; the monitor's cache window (1 s) elapses but
        // the max-stale window (60 s) has not: the controller keeps
        // serving, and the failed re-read leaves the floor unconfirmed.
        $stack['redis']->failCommand = '*';
        $clock[0] = 2000.0;
        [$status2, $data2] = $this->issue($stack['controller']);
        self::assertSame(200, $status2, 'within the max-stale window issuance keeps serving');
        self::assertArrayNotHasKey('decoy_field', $data2, 'an unconfirmed floor must never arm v3');
        $record = $stack['storage']->find($data2['nonce']);
        self::assertNotNull($record);
        self::assertSame(2, $record->protocolVersion, 'an unconfirmed floor fails safe to protocol v2');
        self::assertCount(1, $stack['logger']->warnings, 'the unreadable-floor warning fires once');
    }

    public function testEnabledWithUnreadablePolicyFromBootIsNeverArmed(): void
    {
        // A monitor that has never succeeded a central read is stale
        // immediately: the controller refuses issuance with 503
        // The service-unavailable code (the max-stale fail-closed gate),
        // so a node that cannot confirm the central policy can never
        // emit anything, in particular never an unconfirmed v3.
        $clock = [0.0];
        $stack = $this->stack(true, 3, static function () use (&$clock): float {
            return $clock[0];
        });
        $stack['redis']->failCommand = '*';
        [$status, $data] = $this->issue($stack['controller']);
        self::assertSame(503, $status);
        self::assertSame('SERVICE_UNAVAILABLE', $data['error']['code']);
        self::assertSame([], $stack['logger']->warnings, 'issuance was refused, not silently downgraded — no warning needed');
    }

    public function testRollbackLoweredFloorStopsV3EmissionOnTheNextRead(): void
    {
        // The non-monotonic property pinned at the controller level: the
        // central floor is a fleet-capability coordination signal, not a
        // revocation max. A rollback lowers the floor from 3 back to 2
        // (older binaries are re-admitted to the pool through the
        // readiness gate), and the next issuance — after the monitor's
        // cache window elapses — must emit protocol v2 again. A
        // sticky/monotonic floor would keep emitting v3 records those
        // binaries reject as malformed.
        $clock = [0.0];
        $stack = $this->stack(true, 3, static function () use (&$clock): float {
            return $clock[0];
        });
        [$status, $data] = $this->issue($stack['controller']);
        self::assertSame(200, $status);
        self::assertIsString($data['decoy_field'] ?? null, 'floor 3 plus the writer switch: the first issuance is armed');
        $first = $stack['storage']->find($data['nonce']);
        self::assertNotNull($first);
        self::assertSame(3, $first->protocolVersion);

        // Rollback: the central floor drops to 2. The next cache-window
        // re-read must observe the lowered floor, and the next issuance
        // must fall back to v2.
        $stack['redis']->hset(self::POLICY_KEY, SecurityEpochMonitor::MIN_PROTOCOL_VERSION_FIELD, '2');
        $clock[0] = 2000.0; // past the 1 s cache window -> a re-read happens
        [$status2, $data2] = $this->issue($stack['controller']);
        self::assertSame(200, $status2);
        self::assertArrayNotHasKey('decoy_field', $data2, 'a lowered floor must stop v3 emission on the next issuance');
        $second = $stack['storage']->find($data2['nonce']);
        self::assertNotNull($second);
        self::assertSame(2, $second->protocolVersion, 'a lowered floor emits protocol v2 again — never a sticky 3');
        self::assertCount(1, $stack['logger']->warnings, 'the rollback fires the floor warning exactly once per process');
        self::assertStringContainsString('min_protocol_version is 2', $stack['logger']->warnings[0], 'the warning names the lowered floor');

        // The floor is re-read every window in both directions: raised
        // back to 3, the next issuance arms the decoy again.
        $stack['redis']->hset(self::POLICY_KEY, SecurityEpochMonitor::MIN_PROTOCOL_VERSION_FIELD, '3');
        $clock[0] = 4000.0;
        [$status3, $data3] = $this->issue($stack['controller']);
        self::assertSame(200, $status3);
        self::assertIsString($data3['decoy_field'] ?? null, 'a re-raised floor re-arms v3 on the next re-read');
        $third = $stack['storage']->find($data3['nonce']);
        self::assertNotNull($third);
        self::assertSame(3, $third->protocolVersion);
        self::assertCount(1, $stack['logger']->warnings, 'a re-raised floor logs no second warning');
    }

    public function testEnabledWithoutSecurityRedisFailsSafeToV2(): void
    {
        // The no-security-Redis matrix cell: no SecurityEpochMonitor is
        // wired at all, so the central floor can never be confirmed. A
        // willing writer switch still cannot arm v3 — the emission stays
        // at v2 with the unconfirmed-floor warning.
        $stack = $this->stack(true, null, null, false);
        [$status, $data] = $this->issue($stack['controller']);
        self::assertSame(200, $status);
        self::assertArrayNotHasKey('decoy_field', $data, 'no security Redis means no confirmed floor — v2 emission');

        $record = $stack['storage']->find($data['nonce']);
        self::assertNotNull($record);
        self::assertSame(2, $record->protocolVersion);
        self::assertCount(1, $stack['logger']->warnings, 'the unconfirmed-floor warning fires once');
        self::assertStringContainsString('no confirmed central min_protocol_version', $stack['logger']->warnings[0], 'the warning names the unconfirmed floor');
    }

    public function testEnabledWithAbsentFloorFieldFailsSafeToV2(): void
    {
        // The absent-floor matrix cell: the central policy hash exists
        // (the epoch field is confirmed) but carries no
        // min_protocol_version field. The floor is unconfirmed — v2
        // emission, never an armed guess.
        $stack = $this->stack(true, null);
        $stack['redis']->hset(self::POLICY_KEY, SecurityEpochMonitor::MIN_POLICY_EPOCH_FIELD, '1');
        [$status, $data] = $this->issue($stack['controller']);
        self::assertSame(200, $status);
        self::assertArrayNotHasKey('decoy_field', $data, 'a present policy without the floor field must emit v2');

        $record = $stack['storage']->find($data['nonce']);
        self::assertNotNull($record);
        self::assertSame(2, $record->protocolVersion);
        self::assertCount(1, $stack['logger']->warnings, 'the absent-floor warning fires once');
        self::assertStringContainsString('no confirmed central min_protocol_version', $stack['logger']->warnings[0]);
    }

    public function testEnabledWithCorruptFloorFailsSafeToV2(): void
    {
        // The corrupt-floor matrix cell: a non-canonical
        // min_protocol_version value (abc, -1, 1e3, an overflow) is an
        // unconfirmed floor — v2 emission, never a parsed guess.
        $stack = $this->stack(true, null);
        $stack['redis']->hset(self::POLICY_KEY, SecurityEpochMonitor::MIN_POLICY_EPOCH_FIELD, '1');
        $stack['redis']->hset(self::POLICY_KEY, SecurityEpochMonitor::MIN_PROTOCOL_VERSION_FIELD, 'abc');
        [$status, $data] = $this->issue($stack['controller']);
        self::assertSame(200, $status);
        self::assertArrayNotHasKey('decoy_field', $data, 'a corrupt floor value must emit v2');

        $record = $stack['storage']->find($data['nonce']);
        self::assertNotNull($record);
        self::assertSame(2, $record->protocolVersion);
        self::assertCount(1, $stack['logger']->warnings, 'the corrupt-floor warning fires once');
        self::assertStringContainsString('no confirmed central min_protocol_version', $stack['logger']->warnings[0]);
    }
}

/**
 * Minimal PSR-3 logger spy: records warnings and infos in-process so the
 * gate tests can assert the once-per-process warning without a real
 * logger backend.
 */
final class LoggerSpy implements LoggerInterface
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
