<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests;

use BelConsulting\KiwiCaptchaBundle\Controller\ChallengeController;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\LoggerSpy;
use BelConsulting\KiwiCaptchaBundle\Risk\SecurityEpochMonitor;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\FakePredisClient;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\JsonRequest;
use KiwiCaptcha\Config;
use KiwiCaptcha\Issuer;
use KiwiCaptcha\PoWAlgorithm;
use KiwiCaptcha\RswModulusIdentity;
use KiwiCaptcha\Storage\ArrayStorage;
use KiwiCaptcha\Tests\Support\RswFixture;
use KiwiCaptcha\Verifier;
use PHPUnit\Framework\TestCase;

/**
 * The protocol-v5 two-phase rollout gate: an rsw issuance arms the
 * authenticated modulus identity (kiwi_captcha.rsw_identity) only when
 * the central security-policy floor
 * ({kiwi:<ns>}:security-policy min_protocol_version, read through the
 * SecurityEpochMonitor's cached central read) is confirmed >= 5, the
 * binary's own maximum. An identity-armed record is protocol v5 — a
 * pre-v5 verifier rejects the unknown version instead of silently
 * ignoring the identity — so the floor must prove every serving binary
 * reads v5 before any node writes it.
 *
 * Every uncertainty (floor 4, absent/corrupt/unreadable central policy,
 * no security Redis, the switch off) fails safe to the legacy
 * identityless protocol v2 shape with a once-per-process actionable
 * warning, byte-compatible with every serving binary.
 */
final class RswIdentityEmissionGateTest extends TestCase
{
    private const SECRET = '0123456789abcdef0123456789abcdef';

    private const POLICY_KEY = '{kiwi:test-ns}:security-policy';

    /**
     * An rsw controller over one ArrayStorage with the gate parameters
     * injected: the writer switch and the central floor reported by the
     * fake security Redis. A null floor leaves the fake policy hash
     * empty; $wireEpochMonitor false injects no monitor at all (the
     * no-security-Redis matrix cell).
     *
     * @return array{controller: ChallengeController, storage: ArrayStorage, logger: LoggerSpy}
     */
    private function stack(bool $rswIdentityEnabled, ?int $floor, bool $wireEpochMonitor = true): array
    {
        $storage = new ArrayStorage();
        $issuer = new Issuer(new Config(
            secretKey: self::SECRET,
            algorithm: PoWAlgorithm::Rsw,
            targetBits: 8,
            ttlSecs: 120,
            rswModulusN: RswFixture::MODULUS_N_B64,
            rswLambda: RswFixture::LAMBDA_B64,
            rswT: 10_000,
        ), $storage);

        $redis = new FakePredisClient();
        if ($floor !== null) {
            $redis->hset(self::POLICY_KEY, SecurityEpochMonitor::MIN_PROTOCOL_VERSION_FIELD, (string) $floor);
            $redis->hset(self::POLICY_KEY, SecurityEpochMonitor::MIN_POLICY_EPOCH_FIELD, '1');
        }
        $monitor = new SecurityEpochMonitor(new Verifier(new ArrayStorage()), $redis, 'test-ns', 1, 1);
        $logger = new LoggerSpy();
        $controller = new ChallengeController(
            $issuer,
            null,
            true,
            null,
            null,
            storage: $storage,
            epochMonitor: $wireEpochMonitor ? $monitor : null,
            rswIdentityEnabled: $rswIdentityEnabled,
            logger: $logger,
        );

        return ['controller' => $controller, 'storage' => $storage, 'logger' => $logger];
    }

    /**
     * @return array{0: int, 1: array<string, mixed>}
     */
    private function issue(ChallengeController $controller): array
    {
        $response = $controller->challenge(JsonRequest::create(
            '/kiwi-captcha/challenge',
            'POST',
            [],
            [],
            [],
            ['REMOTE_ADDR' => '198.51.100.7'],
            '{"scope":"login"}',
        ));

        return [$response->getStatusCode(), json_decode((string) $response->getContent(), true, flags: JSON_THROW_ON_ERROR)];
    }

    public function testTheDefaultSwitchKeepsLegacyIdentitylessV2(): void
    {
        // The default (rsw_identity false) keeps rsw issuance on the
        // legacy identityless v2 shape even with the floor confirmed at
        // 5 — an operator opts in explicitly.
        $stack = $this->stack(false, 5);
        [$status, $data] = $this->issue($stack['controller']);
        self::assertSame(200, $status);
        $record = $stack['storage']->find((string) $data['nonce']);
        self::assertNotNull($record);
        self::assertSame(2, $record->protocolVersion);
        self::assertNull($record->rswModulusSha256);
        self::assertSame([], $stack['logger']->warnings, 'the switch being off is not a warning condition');
    }

    public function testEnabledWithFloorFiveArmsProtocolV5(): void
    {
        // The operator completed the two-phase rollout: rsw_identity on
        // AND the central floor confirms the feature version. Issuance
        // signs the canonical identity as the tagged `r=` segment and
        // stamps protocol v5. A later global maximum (6) must not shut the
        // feature off: the gate compares against the feature constant,
        // never the binary's global maximum.
        foreach ([5, 6] as $floor) {
            $stack = $this->stack(true, $floor);
            [$status, $data] = $this->issue($stack['controller']);
            self::assertSame(200, $status);
            $record = $stack['storage']->find((string) $data['nonce']);
            self::assertNotNull($record);
            self::assertSame(5, $record->protocolVersion, "floor {$floor}: the identity-armed record is protocol v5");
            self::assertSame(
                RswModulusIdentity::fingerprint(RswFixture::MODULUS_N_B64),
                $record->rswModulusSha256,
                'the record carries the canonical-byte modulus identity (the keygen fingerprint)',
            );
            self::assertSame([], $stack['logger']->warnings);
        }
    }

    public function testEnabledWithFloorFourStaysV2AndWarnsOnce(): void
    {
        // A floor below 5 cannot prove every serving binary reads v5:
        // the writer stays on the legacy shape and warns once per
        // process.
        $stack = $this->stack(true, 4);
        [$status, $data] = $this->issue($stack['controller']);
        self::assertSame(200, $status);
        $record = $stack['storage']->find((string) $data['nonce']);
        self::assertNotNull($record);
        self::assertSame(2, $record->protocolVersion, 'a floor below 5 keeps the legacy identityless shape');
        self::assertNull($record->rswModulusSha256);

        [$status] = $this->issue($stack['controller']);
        self::assertSame(200, $status);
        self::assertCount(1, $stack['logger']->warnings, 'the warning fires once per process, not per issuance');
        self::assertStringContainsString('rsw_identity', $stack['logger']->warnings[0]);
        self::assertStringContainsString('min_protocol_version is 4', $stack['logger']->warnings[0]);
    }

    public function testAnAbsentFloorStaysV2(): void
    {
        $stack = $this->stack(true, null);
        [$status, $data] = $this->issue($stack['controller']);
        self::assertSame(200, $status);
        self::assertSame(2, $stack['storage']->find((string) $data['nonce'])?->protocolVersion);
        self::assertCount(1, $stack['logger']->warnings);
        self::assertStringContainsString('no confirmed central min_protocol_version', $stack['logger']->warnings[0]);
    }

    public function testNoSecurityRedisStaysV2(): void
    {
        $stack = $this->stack(true, 5, wireEpochMonitor: false);
        [$status, $data] = $this->issue($stack['controller']);
        self::assertSame(200, $status);
        self::assertSame(2, $stack['storage']->find((string) $data['nonce'])?->protocolVersion);
        self::assertCount(1, $stack['logger']->warnings);
    }

    public function testARecoveredFloorAtFiveReArmsV5(): void
    {
        // A partitioned-then-recovered policy server: the floor settles
        // at 5 and the writer re-arms. The monitor's cache window is
        // crossed through its clock.
        $nowMs = 1_000_000.0;
        $storage = new ArrayStorage();
        $issuer = new Issuer(new Config(
            secretKey: self::SECRET,
            algorithm: PoWAlgorithm::Rsw,
            targetBits: 8,
            ttlSecs: 120,
            rswModulusN: RswFixture::MODULUS_N_B64,
            rswLambda: RswFixture::LAMBDA_B64,
            rswT: 10_000,
        ), $storage);
        $redis = new FakePredisClient();
        $clock = static function () use (&$nowMs): float {
            return $nowMs;
        };
        $monitor = new SecurityEpochMonitor(new Verifier(new ArrayStorage()), $redis, 'test-ns', 1, 1, $clock);
        $logger = new LoggerSpy();
        $controller = new ChallengeController(
            $issuer,
            null,
            true,
            null,
            null,
            storage: $storage,
            epochMonitor: $monitor,
            rswIdentityEnabled: true,
            logger: $logger,
        );

        [$status, $data] = $this->issue($controller);
        self::assertSame(200, $status);
        self::assertSame(2, $storage->find((string) $data['nonce'])?->protocolVersion, 'no confirmed floor yet');

        // The policy server recovers with the completed rollout floor.
        $redis->hset(self::POLICY_KEY, SecurityEpochMonitor::MIN_PROTOCOL_VERSION_FIELD, '5');
        $redis->hset(self::POLICY_KEY, SecurityEpochMonitor::MIN_POLICY_EPOCH_FIELD, '1');
        $nowMs += 10_000.0; // past the cached-read window
        [$status, $data] = $this->issue($controller);
        self::assertSame(200, $status);
        $record = $storage->find((string) $data['nonce']);
        self::assertNotNull($record);
        self::assertSame(5, $record->protocolVersion, 'the recovered floor re-arms v5');
        self::assertSame(RswModulusIdentity::fingerprint(RswFixture::MODULUS_N_B64), $record->rswModulusSha256);
    }
}
