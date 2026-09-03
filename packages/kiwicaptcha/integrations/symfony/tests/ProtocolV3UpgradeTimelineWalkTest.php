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
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\ProtocolV2OnlyVerifier;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\RedisTestUrl;
use KiwiCaptcha\ChallengeRecord;
use KiwiCaptcha\Config;
use KiwiCaptcha\ExecutionChallengeGenerator;
use KiwiCaptcha\TestSupport\ExecutionTraceFixture;
use KiwiCaptcha\Issuer;
use KiwiCaptcha\PoWAlgorithm;
use KiwiCaptcha\Risk\AdaptiveRiskEngine;
use KiwiCaptcha\Risk\Network\CidrNetworkClassifier;
use KiwiCaptcha\Risk\RiskIdentityFactory;
use KiwiCaptcha\Risk\RiskKeys;
use KiwiCaptcha\Risk\RiskPolicy;
use KiwiCaptcha\Risk\RiskScorer;
use KiwiCaptcha\SolutionToken;
use KiwiCaptcha\Storage\ArrayStorage;
use KiwiCaptcha\Storage\RedisStorage;
use KiwiCaptcha\Verifier;
use KiwiCaptcha\VerifyError;
use PHPUnit\Framework\TestCase;
use Psr\Log\LoggerInterface;
use Symfony\Component\HttpFoundation\Request;

/**
 * The long-horizon stateful walk over the documented two-phase
 * protocol upgrade timeline (operations.md, "Protocol v3 two-phase
 * rollout" and "Protocol v4 execution rollout").
 *
 * The walk advances a simulated clock through the phases.
 * The phases are a v2-only fleet, a mixed fleet of new binaries still
 * emitting v2, the central floor raised to 3 with the writer switch
 * still disabled, the writer enabled, a rollback mid-upgrade, and the
 * retirement of the residual records.
 * The v4 execution phase follows: the central floor raised to 4
 * with the execution gate on, emitting protocol v4 records the v2-only
 * and v3-only simulators reject.
 * Every issuance enters a ledger tracking its simulated TTL, and every
 * phase boundary asserts the documented invariants.
 * v2 emission serves both verifier generations.
 * v3 emission needs the confirmed floor plus the writer switch.
 * v4 emission needs the v4 floor plus the execution gate.
 * The operator's drain window is at least the maximum challenge TTL.
 * A rollback re-admits v2 emission while v3 records keep verifying on
 * the new generation for the remainder of their TTL.
 *
 * The gate side (the writer switch and the central floor) uses the
 * FakePredisClient stack with a fake monitor clock, exactly like the
 * emission-gate tests. Issuance and verification run against real
 * Redis with real second-bounded TTLs. The two clocks are separate by
 * design: the fake monitor clock only crosses the cache window, while
 * the simulated walk clock drives the ledger expiry math and the
 * phase boundaries.
 *
 * Runs in the dedicated "Real-Redis concurrency" CI lane, which
 * publishes `KC_REDIS_URL` / `TEST_REDIS_URL` and sets
 * `KIWI_REQUIRE_REAL_REDIS_TESTS=1`; with the flag on, a missing or
 * unreachable Redis fails the walk instead of skipping. The walk is
 * fully deterministic.
 */
final class ProtocolV3UpgradeTimelineWalkTest extends TestCase
{
    private const SECRET = '0123456789abcdef0123456789abcdef';

    private const POLICY_KEY = '{kiwi:test-ns}:security-policy';

    private const NAMESPACE = 'test-ns';

    private const PREFIX = 'ci:upgrade-walk:';

    /** The documented default challenge TTL, simulated in the ledger. */
    private const DEFAULT_TTL = 120;

    /** The documented maximum challenge TTL (Config::MAX_TTL_SECS). */
    private const MAX_TTL = 300;

    /** Fake-clock step crossing the monitor's 1 s cache window. */
    private const WALK_CACHE_MS = 2000.0;

    // The simulated walk clock, in seconds. The drain windows between
    // the boundary events are the timeline enforcement of the
    // documented "at least the maximum challenge TTL" waits.
    private const T_A = 0;

    private const T_B = 100;

    private const T_FLOOR_RAISED = 200;

    private const T_C = 250;

    private const T_D = 500;

    private const T_PRE_ROLLBACK = 580;

    private const T_ROLLBACK = 600;

    private const T_F = 900;

    // The execution phase : the v4 floor is raised only
    // after the documented wait since the v3 retirement.
    private const T_V4_FLOOR_RAISED = 1200;

    private const T_G = 1300;

    private const T_H = 1650;

    private \Predis\Client $client;

    private RedisStorage $storage;

    private Verifier $verifier;

    private ProtocolV2OnlyVerifier $simulator;

    /** @var list<array<string, mixed>> */
    private array $ledger = [];

    protected function setUp(): void
    {
        $url = RedisTestUrl::resolve();
        if ($url === null) {
            $this->failIfRealRedisRequired('no Redis test URL (KC_REDIS_URL / TEST_REDIS_URL) is set');
            self::markTestSkipped('no Redis test URL (KC_REDIS_URL / TEST_REDIS_URL) — real-Redis upgrade walk skipped');
        }
        if (!class_exists(\Predis\Client::class)) {
            $this->failIfRealRedisRequired('predis/predis is not installed');
            self::markTestSkipped('predis/predis not installed');
        }
        $this->client = new \Predis\Client($url);
        try {
            $this->client->ping();
        } catch (\Throwable $e) {
            $this->failIfRealRedisRequired('Redis is unreachable at the configured URL');
            self::markTestSkipped('Redis unreachable: '.$e->getMessage());
        }
        $this->client->flushdb();
        $this->storage = new RedisStorage($this->client, self::PREFIX);
        $this->verifier = new Verifier($this->storage);
        $this->simulator = new ProtocolV2OnlyVerifier($this->verifier, $this->storage);
        $this->ledger = [];
    }

    /**
     * Fail the walk instead of skipping when the real-Redis CI lane
     * loses its environment: the lane sets
     * KIWI_REQUIRE_REAL_REDIS_TESTS=1 together with `KC_REDIS_URL` /
     * `TEST_REDIS_URL`, so a missing or unreachable Redis there is a
     * broken lane, not a legitimate skip.
     */
    private function failIfRealRedisRequired(string $why): void
    {
        $flag = getenv('KIWI_REQUIRE_REAL_REDIS_TESTS');
        if (\is_string($flag) && $flag !== '' && $flag !== '0') {
            self::fail('KIWI_REQUIRE_REAL_REDIS_TESTS is set but '.$why.' — the two-phase protocol-v3 upgrade walk must run in the real-Redis CI lane');
        }
    }

    /**
     * The emission-gate stack over the fake security Redis: the writer
     * switch, the central floor, the execution gate and the fake
     * monitor clock. The issuer serves the real Redis storage, so
     * issuance and verification phases run against real Redis while the
     * gate stays fully deterministic.
     *
     * @param callable(): float $nowMs the fake monitor clock
     *
     * @return array{controller: ChallengeController, monitor: SecurityEpochMonitor, redis: FakePredisClient, gateway: RiskGateway, logger: UpgradeWalkLoggerSpy}
     */
    private function gateStack(bool $decoyV3Enabled, int $floor, $nowMs, bool $executionGate = false, string $minimum = 'allow'): array
    {
        $keys = RiskKeys::fromMaster(self::SECRET);
        $classifier = new CidrNetworkClassifier([]);
        $policy = RiskPolicy::fromConfig([
            'version' => RiskPolicy::CONTRACT_VERSION,
            'weights' => [],
            'scopes' => [
                1 => ['base_risk' => 100, 'minimum' => $minimum, 'post_solve_check' => false, 'degraded' => 'allow'],
            ],
        ]);
        $store = new FakeRiskStateStore();
        $engine = new AdaptiveRiskEngine($store, $classifier, new RiskIdentityFactory($keys), new RiskScorer(), $policy, $keys);
        $gateway = new RiskGateway($engine, $classifier, new RiskProfileResolver(PoWAlgorithm::Sha256, 8), ['login' => 1], policy: $policy);

        $redis = new FakePredisClient();
        $redis->hset(self::POLICY_KEY, SecurityEpochMonitor::MIN_PROTOCOL_VERSION_FIELD, (string) $floor);
        $redis->hset(self::POLICY_KEY, SecurityEpochMonitor::MIN_POLICY_EPOCH_FIELD, '1');
        $monitor = new SecurityEpochMonitor(new Verifier(new ArrayStorage()), $redis, self::NAMESPACE, 1, 1, $nowMs);
        $logger = new UpgradeWalkLoggerSpy();
        $controller = $this->controllerFor($this->issuer(), $monitor, $gateway, $decoyV3Enabled, $logger, $executionGate);

        return ['controller' => $controller, 'monitor' => $monitor, 'redis' => $redis, 'gateway' => $gateway, 'logger' => $logger];
    }

    /**
     * One issuer over the real Redis storage serves the whole walk.
     * The records carry the documented maximum TTL (300 s), so every
     * real Redis TTL is a bounded number of seconds and every real
     * verification within the walk happens inside a live record. The
     * execution key is configured from the start so the execution phase
     * can arm (the gate decides, never the key).
     */
    private function issuer(): Issuer
    {
        return new Issuer(new Config(secretKey: self::SECRET, targetBits: 8, ttlSecs: self::MAX_TTL, minDurationMs: 0, executionKey: self::SECRET), $this->storage);
    }

    /**
     * The real-expiry probe issuer: a 1 s real TTL, so the final probe
     * of the walk observes an actual Redis key expiry within seconds.
     */
    private function probeIssuer(): Issuer
    {
        return new Issuer(new Config(secretKey: self::SECRET, targetBits: 8, ttlSecs: 1, minDurationMs: 0), $this->storage);
    }

    private function controllerFor(
        Issuer $issuer,
        SecurityEpochMonitor $monitor,
        RiskGateway $gateway,
        bool $decoyV3Enabled,
        UpgradeWalkLoggerSpy $logger,
        bool $executionGate = false,
    ): ChallengeController {
        return new ChallengeController(
            $issuer,
            null,
            true,
            $gateway,
            new ContinuityCookie(),
            epochMonitor: $monitor,
            decoyV3Enabled: $decoyV3Enabled,
            executionGate: $executionGate,
            storage: $this->storage,
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
     * Issue one challenge, solve it, assert the real-Redis side (the
     * record is readable back and its real TTL is a bounded number of
     * seconds), and push the ledger entry. The simulated TTL is the
     * ledger's expiry model; the real record always mints with the
     * documented maximum TTL.
     */
    private function issue(ChallengeController $controller, int $walkAt, int $ttlSecs, string $phase): void
    {
        $response = $controller->challenge($this->challengeRequest());
        self::assertSame(200, $response->getStatusCode(), 'issuance in phase '.$phase.' must succeed');
        $data = json_decode((string) $response->getContent(), true);
        self::assertIsArray($data);
        self::assertIsString($data['nonce']);
        $record = $this->storage->find($data['nonce']);
        self::assertNotNull($record, 'the issued record must be readable back from real Redis');
        $realTtl = $this->client->ttl(self::PREFIX.$data['nonce']);
        self::assertGreaterThanOrEqual(1, $realTtl, 'the real record must carry a live second-bounded TTL');
        self::assertLessThanOrEqual(self::MAX_TTL, $realTtl, 'the real TTL must stay within the documented maximum');
        $this->ledger[] = [
            'phase' => $phase,
            'virtualAt' => $walkAt,
            'ttlSecs' => $ttlSecs,
            'virtualExpiresAt' => $walkAt + $ttlSecs,
            'protocol' => $record->protocolVersion,
            'nonce' => $data['nonce'],
            'token' => $this->solve($record),
            'decoyField' => $data['decoy_field'] ?? null,
            'executionProgram' => $data['execution_program'] ?? null,
            'currentOk' => null,
            'v2onlyOk' => null,
            'v3onlyOk' => null,
        ];
    }

    private function solve(ChallengeRecord $record): string
    {
        $saltBytes = base64_decode($record->salt, true);
        $counter = 0;
        do {
            $hash = hash('sha256', $record->prefix.$counter.$saltBytes, true);
            $counter++;
        } while (Verifier::leadingZeroBits($hash) < $record->targetBits);
        --$counter;

        // An execution-armed (protocol v4) record demands the execution
        // digest and trace with the token; the digest is a pure
        // function of the stored program and the nonce over the
        // executed trace, recomputed here exactly like the driver
        // computes it.
        $digest = null;
        $traceB64 = null;
        if ($record->executionProgram !== null) {
            $program = ExecutionChallengeGenerator::decode($record->executionProgram);
            self::assertNotNull($program, 'the walk-issued execution program must be parseable');
            $trace = ExecutionTraceFixture::executedTraceFor($program);
            $traceB64 = base64_encode($trace);
            $digest = ExecutionChallengeGenerator::digestOverTrace($record->executionProgram, $record->nonce, $trace);
            self::assertNotNull($digest, 'the walk-issued execution digest must compute');
        }

        return SolutionToken::create($record->nonce, $counter, 5000, [], $digest, $traceB64)->encode();
    }

    /**
     * @return array<string, mixed>
     */
    private function entry(string $nonce): array
    {
        foreach ($this->ledger as $entry) {
            if ($entry['nonce'] === $nonce) {
                return $entry;
            }
        }
        self::fail('no ledger entry for nonce '.$nonce);
    }

    private function markCurrent(string $nonce, bool $ok): void
    {
        foreach ($this->ledger as $i => $entry) {
            if ($entry['nonce'] === $nonce) {
                $this->ledger[$i]['currentOk'] = $ok;

                return;
            }
        }
        self::fail('no ledger entry for nonce '.$nonce);
    }

    private function markV2Only(string $nonce, bool $ok): void
    {
        foreach ($this->ledger as $i => $entry) {
            if ($entry['nonce'] === $nonce) {
                $this->ledger[$i]['v2onlyOk'] = $ok;

                return;
            }
        }
        self::fail('no ledger entry for nonce '.$nonce);
    }

    private function markV3Only(string $nonce, bool $ok): void
    {
        foreach ($this->ledger as $i => $entry) {
            if ($entry['nonce'] === $nonce) {
                $this->ledger[$i]['v3onlyOk'] = $ok;

                return;
            }
        }
        self::fail('no ledger entry for nonce '.$nonce);
    }

    /**
     * The new-generation verification probe: the current verifier over
     * the real Redis storage. The outcome is recorded on the ledger and
     * asserted valid, since a v4-capable binary accepts every
     * generation.
     */
    private function probeCurrent(string $nonce, string $what): void
    {
        $entry = $this->entry($nonce);
        $outcome = $this->verifier->verify($entry['token'], self::SECRET, 'login', '198.51.100.7');
        self::assertTrue($outcome->isOk(), $what.' must verify on the current verifier, got '.$outcome->code());
        $this->markCurrent($nonce, true);
    }

    /**
     * The parent-revision probe: the simulated v2-only binary over the
     * same real storage. The outcome is recorded and asserted to be the
     * deterministic MalformedRecord for protocol v3/v4 (the gate fires
     * before any consume, so the record stays pending).
     */
    private function probeV2Only(string $nonce, string $what): void
    {
        $entry = $this->entry($nonce);
        $outcome = $this->simulator->verify($entry['token'], self::SECRET, 'login', '198.51.100.7');
        self::assertSame(VerifyError::MalformedRecord, $outcome->error, $what.' must be rejected by a v2-only binary');
        $this->markV2Only($nonce, false);
        self::assertNull($this->storage->consumedState($nonce), $what.' must stay pending: the version gate fires before any consume');
    }

    /**
     * The decoy-generation probe: the simulated v3-only binary (max
     * protocol 3) over the same real storage. A v3 record verifies; a
     * v4 record is rejected as MalformedRecord — the explicit
     * capability rule the v4 rollout protects against.
     */
    private function probeV3Only(string $nonce, string $what): void
    {
        $entry = $this->entry($nonce);
        $outcome = $this->simulator->verify($entry['token'], self::SECRET, 'login', '198.51.100.7', null, 3);
        if ($entry['protocol'] === 4) {
            self::assertSame(VerifyError::MalformedRecord, $outcome->error, $what.' must be rejected by a v3-only binary');
            $this->markV3Only($nonce, false);
        } else {
            self::assertTrue($outcome->isOk(), $what.' must verify on a v3-only binary, got '.$outcome->code());
            $this->markV3Only($nonce, true);
        }
        self::assertNull($this->storage->consumedState($nonce), $what.' must stay pending after the rejection probe');
    }

    private function probeV2OnlyAcceptingV2(string $nonce, string $what): void
    {
        $entry = $this->entry($nonce);
        self::assertSame(2, $entry['protocol'], 'a v2-acceptance probe requires a v2 record');
        $outcome = $this->simulator->verify($entry['token'], self::SECRET, 'login', '198.51.100.7');
        self::assertTrue($outcome->isOk(), $what.' must verify on a v2-only binary, got '.$outcome->code());
        $this->markV2Only($nonce, true);
    }

    /**
     * The current-generation probe for v2 records: identical to
     * {@see self::probeCurrent()}, kept as the named counterpart of
     * {@see self::probeV2OnlyAcceptingV2()} at the v2 phase boundaries.
     */
    private function probeCurrentAcceptingV2(string $nonce, string $what): void
    {
        $this->probeCurrent($nonce, $what);
    }

    /**
     * @return list<array<string, mixed>> the ledger entries still
     *                                    outstanding at $walkAt, meaning
     *                                    their simulated expiry is
     *                                    strictly after $walkAt, filtered
     *                                    by protocol when requested
     */
    private function outstanding(int $walkAt, ?int $protocol = null): array
    {
        return array_values(array_filter(
            $this->ledger,
            static fn (array $entry): bool => $entry['virtualExpiresAt'] > $walkAt
                && ($protocol === null || $entry['protocol'] === $protocol),
        ));
    }

    /**
     * @return list<array<string, mixed>>
     */
    private function phaseRecords(string $phase): array
    {
        return array_values(array_filter($this->ledger, static fn (array $entry): bool => $entry['phase'] === $phase));
    }

    /**
     * The global ledger invariants are asserted at every phase
     * boundary. The simulated expiry is the issuance time plus the
     * TTL. A v2 record carries no decoy and no execution surface while
     * a v3 record carries the grammar-valid authenticated name; a v4
     * record carries the authenticated execution program and commitment
     * (the exact armed/unarmed equivalence). Every recorded generation
     * observation matches the protocol: both older generations accept
     * v2, the current verifier accepts every generation, a v2-only
     * binary rejects v3/v4, and a v3-only binary rejects v4.
     */
    private function assertLedgerConsistency(): void
    {
        foreach ($this->ledger as $entry) {
            self::assertSame(
                $entry['virtualAt'] + $entry['ttlSecs'],
                $entry['virtualExpiresAt'],
                'the simulated expiry must be the issuance time plus the TTL',
            );
            if ($entry['protocol'] === 2) {
                self::assertNull($entry['decoyField'], 'a v2 record never carries the decoy');
                self::assertNull($entry['executionProgram'], 'a v2 record never carries the execution program');
                self::assertNotFalse($entry['currentOk'], 'a v2 record is never refused by the current verifier');
                self::assertNotFalse($entry['v2onlyOk'], 'a v2 record is never refused by a v2-only binary');
            } elseif ($entry['protocol'] === 3) {
                self::assertIsString($entry['decoyField'], 'a v3 record always carries the authenticated decoy');
                self::assertTrue(Issuer::isGrammarDecoyName($entry['decoyField']), 'the armed name comes from the combinatorial grammar');
                self::assertNull($entry['executionProgram'], 'a v3 record never carries the execution program');
                self::assertNotFalse($entry['currentOk'], 'the current verifier always accepts its own v3 records');
                self::assertNotTrue($entry['v2onlyOk'], 'a v2-only binary always rejects v3 records');
            } else {
                self::assertSame(4, $entry['protocol'], 'the walk only ever emits protocol v2, v3 or v4');
                self::assertIsString($entry['executionProgram'], 'a v4 record always carries the execution program');
                self::assertNotFalse($entry['currentOk'], 'the current verifier always accepts its own v4 records');
                self::assertNotTrue($entry['v2onlyOk'], 'a v2-only binary always rejects v4 records');
                self::assertNotTrue($entry['v3onlyOk'], 'a v3-only binary always rejects v4 records');
            }
        }
    }

    /**
     * The timeline enforcement of the documented drain windows: the
     * walk only advances past a boundary once at least the maximum
     * challenge TTL has elapsed since the reference event.
     */
    private function assertDrainWindowComplete(int $walkAt, int $since, string $what): void
    {
        self::assertGreaterThanOrEqual(
            self::MAX_TTL,
            $walkAt - $since,
            $what.' (elapsed '.($walkAt - $since).' s of '.self::MAX_TTL.' s required)',
        );
    }

    private function assertNoWarnings(UpgradeWalkLoggerSpy $logger, string $phase): void
    {
        self::assertSame([], $logger->warnings, 'phase '.$phase.' must log no gate warning');
        self::assertSame([], $logger->infos, 'phase '.$phase.' must log no info noise');
    }

    public function testTwoPhaseUpgradeTimelineWalkWithRollbackAndRetirement(): void
    {
        $clock = [0.0];
        $nowMs = static function () use (&$clock): float {
            return $clock[0];
        };

        // Phase a: the v2-only fleet. The default writer switch is
        // disabled and the central floor is 2. Every issuance is
        // protocol v2 and both verifier generations accept it.
        $stack = $this->gateStack(false, 2, $nowMs);
        $this->issue($stack['controller'], self::T_A, self::DEFAULT_TTL, 'a');
        $this->issue($stack['controller'], self::T_A, self::MAX_TTL, 'a');
        $this->issue($stack['controller'], self::T_A, self::DEFAULT_TTL, 'a');
        [$a1, $a2, $a3] = $this->phaseRecords('a');
        $this->probeCurrent($a1['nonce'], 'a v2-only-fleet record');
        $this->probeV2OnlyAcceptingV2($a2['nonce'], 'a v2-only-fleet record');
        foreach ([$a1, $a2, $a3] as $record) {
            self::assertSame(2, $record['protocol'], 'the v2-only fleet emits protocol v2 only');
        }
        self::assertSame([], $this->outstanding(self::T_A, 3), 'no v3 record can exist in the v2-only fleet');
        self::assertSame(2, $stack['monitor']->minProtocolVersion(), 'the floor is 2');
        $this->assertNoWarnings($stack['logger'], 'a');

        // Phase b: the mixed fleet. New binaries are deployed but still
        // emit v2, and the central floor is still 2.
        $clock[0] += self::WALK_CACHE_MS;
        $this->issue($stack['controller'], self::T_B, self::MAX_TTL, 'b');
        $this->issue($stack['controller'], self::T_B, self::DEFAULT_TTL, 'b');
        [$b1, $b2] = $this->phaseRecords('b');
        $this->probeCurrent($b1['nonce'], 'a mixed-fleet record');
        $this->probeV2OnlyAcceptingV2($b2['nonce'], 'a mixed-fleet record');
        foreach ([$b1, $b2] as $record) {
            self::assertSame(2, $record['protocol'], 'the mixed fleet still emits protocol v2');
        }
        self::assertSame(2, $stack['monitor']->minProtocolVersion(), 'the floor is still 2 during the mixed phase');
        $this->assertLedgerConsistency();
        $this->assertNoWarnings($stack['logger'], 'b');

        // The central floor is raised to 3. The drain happened through
        // the readiness gate before this step; the walk enforces the
        // drain window on the simulated timeline.
        $stack['redis']->hset(self::POLICY_KEY, SecurityEpochMonitor::MIN_PROTOCOL_VERSION_FIELD, '3');
        $clock[0] += self::WALK_CACHE_MS;

        // Phase c: floor 3 with the writer switch still disabled. The
        // two switches are independent: the raised floor permits v3
        // emission, but the disabled writer keeps the fleet at v2.
        $this->issue($stack['controller'], self::T_C, self::MAX_TTL, 'c');
        $this->issue($stack['controller'], self::T_C, self::DEFAULT_TTL, 'c');
        [$c1, $c2] = $this->phaseRecords('c');
        $this->probeCurrent($c1['nonce'], 'a floor-3 record emitted with the writer disabled');
        $this->probeV2OnlyAcceptingV2($c2['nonce'], 'a floor-3 record emitted with the writer disabled');
        foreach ([$c1, $c2] as $record) {
            self::assertSame(2, $record['protocol'], 'a raised floor alone never arms v3 emission');
            self::assertNull($record['decoyField'], 'the writer switch is the independent emission gate');
        }
        self::assertSame(3, $stack['monitor']->minProtocolVersion(), 'the confirmed floor is now 3');
        $this->assertLedgerConsistency();
        $this->assertNoWarnings($stack['logger'], 'c');

        // The operator's drain window: the writer is enabled only after
        // at least the maximum challenge TTL has elapsed since the floor
        // was raised and since the last mixed-fleet issuance, and every
        // pre-drain record has lapsed in the ledger.
        $this->assertDrainWindowComplete(self::T_D, self::T_FLOOR_RAISED, 'the writer must not enable before the drain window since the floor raise');
        $this->assertDrainWindowComplete(self::T_D, self::T_B, 'the writer must not enable before the drain window since the mixed phase');
        $preDrain = array_values(array_filter($this->ledger, static fn (array $entry): bool => $entry['virtualAt'] <= self::T_B));
        self::assertSame([], array_values(array_filter($preDrain, static fn (array $entry): bool => $entry['virtualExpiresAt'] > self::T_D)), 'no pre-drain record may outlive the drain window');

        // Phase d: writer enabled with the confirmed floor 3. Issuance
        // arms the authenticated decoy and writes protocol v3. The
        // current verifier accepts these records; a v2-only binary
        // rejects them deterministically, which is exactly why the
        // drained binaries must be gone before this phase.
        $armedController = $this->controllerFor($this->issuer(), $stack['monitor'], $stack['gateway'], true, $stack['logger']);
        $clock[0] += self::WALK_CACHE_MS;
        $this->issue($armedController, self::T_D, self::DEFAULT_TTL, 'd');
        $this->issue($armedController, self::T_D, self::MAX_TTL, 'd');
        $this->issue($armedController, self::T_D, self::DEFAULT_TTL, 'd');
        [$d1, $d2, $d3] = $this->phaseRecords('d');
        foreach ([$d1, $d2, $d3] as $record) {
            self::assertSame(3, $record['protocol'], 'the armed fleet writes protocol v3');
        }
        $names = array_map(static fn (array $entry): string => $entry['decoyField'], [$d1, $d2, $d3]);
        self::assertCount(3, array_unique($names), 'every armed issuance draws a fresh decoy name');
        $this->probeCurrent($d1['nonce'], 'a v3 record issued with the writer enabled');
        self::assertNotNull($this->storage->consumedState($d1['nonce']), 'a valid current-generation verification consumes the record');
        $this->probeV2Only($d2['nonce'], 'a v3 record presented to a v2-only binary');
        $this->assertLedgerConsistency();
        $this->assertNoWarnings($stack['logger'], 'd');

        // Phase e, pre-rollback: two more v3 issuances while the floor
        // is still 3. These are the residual records that will outlive
        // the rollback.
        $clock[0] += self::WALK_CACHE_MS;
        $this->issue($armedController, self::T_PRE_ROLLBACK, self::DEFAULT_TTL, 'e');
        $this->issue($armedController, self::T_PRE_ROLLBACK, self::MAX_TTL, 'e');
        [$pre1, $pre2] = $this->phaseRecords('e');
        self::assertSame(3, $pre1['protocol'], 'the pre-rollback issuance is still armed');
        self::assertSame(3, $pre2['protocol'], 'the pre-rollback issuance is still armed');

        // Rollback: the floor drops back to 2 and the writer switch is
        // disabled. The next issuance after the cache window must be
        // protocol v2 again: the floor is a non-monotonic capability
        // signal, never a sticky 3.
        $stack['redis']->hset(self::POLICY_KEY, SecurityEpochMonitor::MIN_PROTOCOL_VERSION_FIELD, '2');
        $clock[0] += self::WALK_CACHE_MS;
        $revertedController = $this->controllerFor($this->issuer(), $stack['monitor'], $stack['gateway'], false, $stack['logger']);
        $this->issue($revertedController, self::T_ROLLBACK, self::MAX_TTL, 'e');
        $this->issue($revertedController, self::T_ROLLBACK, self::DEFAULT_TTL, 'e');
        $probeController = $this->controllerFor($this->probeIssuer(), $stack['monitor'], $stack['gateway'], false, $stack['logger']);
        $this->issue($probeController, self::T_ROLLBACK, 1, 'e');
        [$post1, $post2, $probe] = array_slice($this->phaseRecords('e'), 2, 3);
        self::assertSame(2, $post1['protocol'], 'the rollback re-admits v2 emission on the next issuance');
        self::assertSame(2, $post2['protocol'], 'the rollback re-admits v2 emission on the next issuance');
        self::assertSame(2, $probe['protocol'], 'the real-expiry probe record is v2');
        self::assertSame(2, $stack['monitor']->minProtocolVersion(), 'the confirmed floor is back to 2');

        // The documented residual window: the rollback happened strictly
        // inside the v3 records' TTLs, so the walk can probe them. New
        // binaries keep verifying pre-rollback v3 records for the
        // remainder of their TTL, while a re-admitted v2-only binary
        // rejects them as malformed.
        $residual = $this->outstanding(self::T_ROLLBACK, 3);
        self::assertCount(5, $residual, 'all five pre-rollback v3 records are still outstanding at the rollback');
        self::assertSame([$d1['nonce'], $d2['nonce'], $d3['nonce'], $pre1['nonce'], $pre2['nonce']], array_column($residual, 'nonce'));
        $remaining = $this->entry($d3['nonce'])['virtualExpiresAt'] - self::T_ROLLBACK;
        self::assertGreaterThan(0, $remaining, 'the rollback must land inside the residual TTL window');
        $this->probeCurrent($d3['nonce'], 'a pre-rollback v3 record with '.$remaining.' s of TTL remaining');
        $this->probeV2Only($pre1['nonce'], 'a pre-rollback v3 record re-admitted to a v2-only binary');
        $this->probeCurrent($pre2['nonce'], 'a pre-rollback v3 record with most of its TTL remaining');
        $this->probeCurrent($post1['nonce'], 'a post-rollback v2 record');
        $this->probeV2OnlyAcceptingV2($post2['nonce'], 'a post-rollback v2 record');
        $this->assertLedgerConsistency();
        $this->assertNoWarnings($stack['logger'], 'e');

        // Phase f: retirement. The residual drain has run its full
        // course: at least the maximum challenge TTL has elapsed since
        // the last v3 issuance, so no v3 record can still be
        // outstanding. The documented wait after the floor drop is
        // satisfied too, so v2 support may be retired: the whole ledger
        // is drained.
        $this->assertDrainWindowComplete(self::T_F, self::T_PRE_ROLLBACK, 'the residual drain since the last v3 issuance');
        self::assertSame([], $this->outstanding(self::T_F, 3), 'no v3 record can still be outstanding at retirement');
        $this->assertDrainWindowComplete(self::T_F, self::T_ROLLBACK, 'the documented wait after the floor drop');
        $this->assertDrainWindowComplete(self::T_F, self::T_ROLLBACK, 'the v2 retirement window since the last v2 issuance');
        self::assertSame([], $this->outstanding(self::T_F), 'the whole ledger is drained, so v2 support may be retired');
        $this->assertLedgerConsistency();
        $this->assertNoWarnings($stack['logger'], 'f');

        // The real-Redis TTL lane, honestly exercised: the real-expiry
        // probe record mints with a 1 s real TTL and actually vanishes
        // from Redis after it lapses, proving the second-bounded TTLs
        // are real, not simulated.
        $this->assertGreaterThanOrEqual(1, $this->client->ttl(self::PREFIX.$probe['nonce']), 'the probe record carries a live 1 s TTL');
        sleep(2);
        self::assertNull($this->storage->find($probe['nonce']), 'a lapsed real TTL removes the record from Redis');
        self::assertSame(0, $this->client->exists(self::PREFIX.$probe['nonce']), 'the lapsed key is gone');

        // ── The execution phase : the protocol-v4 rollout ──
        // The v4 floor is raised only after the documented drain window
        // since the v3 era ended. The execution gate is then enabled
        // with the decoy writer: issuance arms both surfaces and writes
        // protocol v4 records carrying the signed execution commitment.
        // The current verifier accepts them; the v2-only and v3-only
        // simulators reject them deterministically, the exact
        // capability rule the v4 floor protects against.
        $this->assertDrainWindowComplete(self::T_V4_FLOOR_RAISED, self::T_F, 'the v4 floor must not be raised before the drain window since the v3 era ended');
        $stack['redis']->hset(self::POLICY_KEY, SecurityEpochMonitor::MIN_PROTOCOL_VERSION_FIELD, '4');
        $clock[0] += self::WALK_CACHE_MS;
        $stack['monitor']->refresh();
        self::assertSame(4, $stack['monitor']->minProtocolVersion(), 'the confirmed floor is now 4');

        // Phase g: floor 4 with the execution gate still disabled. The
        // raised floor permits v4 emission, but the disabled gate keeps
        // the fleet at decoy-armed v3.
        $gController = $this->controllerFor($this->issuer(), $stack['monitor'], $stack['gateway'], true, $stack['logger']);
        $this->issue($gController, self::T_G, self::MAX_TTL, 'g');
        $this->issue($gController, self::T_G, self::DEFAULT_TTL, 'g');
        [$g1, $g2] = $this->phaseRecords('g');
        self::assertSame(3, $g1['protocol'], 'the raised v4 floor alone never arms v4 emission');
        self::assertSame(3, $g2['protocol'], 'the execution gate is the independent emission switch');
        $this->probeCurrent($g1['nonce'], 'a floor-4 record emitted with the execution gate disabled');
        $this->probeV2Only($g2['nonce'], 'a floor-4 v3 record presented to a v2-only binary');
        $this->assertLedgerConsistency();
        $this->assertNoWarnings($stack['logger'], 'g');

        // Phase h: the execution gate enabled with the confirmed v4
        // floor. Issuance arms the execution dimension AND the decoy,
        // writing protocol v4 with the signed commitment (the full
        // decoy-capable canonical). The risk trigger is a non-Allow
        // pre-issue decision (minimum sha16), the same population the
        // decoy surface targets.
        $keys = RiskKeys::fromMaster(self::SECRET);
        $classifier = new CidrNetworkClassifier([]);
        $hPolicy = RiskPolicy::fromConfig([
            'version' => RiskPolicy::CONTRACT_VERSION,
            'weights' => [],
            'scopes' => [
                1 => ['base_risk' => 100, 'minimum' => 'sha16', 'post_solve_check' => false, 'degraded' => 'allow'],
            ],
        ]);
        $hGateway = new RiskGateway(
            new AdaptiveRiskEngine(new FakeRiskStateStore(), $classifier, new RiskIdentityFactory($keys), new RiskScorer(), $hPolicy, $keys),
            $classifier,
            new RiskProfileResolver(PoWAlgorithm::Sha256, 8),
            ['login' => 1],
            policy: $hPolicy,
        );
        $hController = $this->controllerFor($this->issuer(), $stack['monitor'], $hGateway, true, $stack['logger'], true);
        $clock[0] += self::WALK_CACHE_MS;
        $this->issue($hController, self::T_H, self::DEFAULT_TTL, 'h');
        $this->issue($hController, self::T_H, self::MAX_TTL, 'h');
        $this->issue($hController, self::T_H, self::DEFAULT_TTL, 'h');
        [$h1, $h2, $h3] = $this->phaseRecords('h');
        foreach ([$h1, $h2, $h3] as $record) {
            self::assertSame(4, $record['protocol'], 'the execution phase writes protocol v4');
            self::assertIsString($record['executionProgram'], 'every v4 record carries the execution program');
            self::assertIsString($record['decoyField'], 'the v4 record carries the decoy segment too');
        }
        $storedH = $this->storage->find($h1['nonce']);
        self::assertNotNull($storedH);
        self::assertSame(1, $storedH->executionVersion, 'execution_version is the canonical byte 1');
        self::assertSame(
            \KiwiCaptcha\Issuer::executionCommitment($storedH->executionProgram),
            $storedH->executionCommitment,
            'the signed commitment mirrors the stored program',
        );
        $this->probeCurrent($h1['nonce'], 'a v4 record issued with the execution gate enabled');
        $this->probeV2Only($h2['nonce'], 'a v4 record presented to a v2-only binary');
        $this->probeV3Only($h3['nonce'], 'a v4 record presented to a v3-only binary');
        $this->assertLedgerConsistency();
        $this->assertNoWarnings($stack['logger'], 'h');

        // The v4 residual window: v4 records stay verifiable on the
        // current generation for the remainder of their TTL, and a
        // re-admitted older binary rejects them for that whole window.
        $v4Residual = $this->outstanding(self::T_H, 4);
        self::assertCount(3, $v4Residual, 'all three v4 records are outstanding at the issuance instant');
        $this->probeV3Only($h2['nonce'], 'a v4 record re-presented to a v3-only binary');

        // The v4 retirement: after at least the maximum challenge TTL
        // since the last v4 issuance, no v4 record can still be
        // outstanding — the whole ledger is drained, so the v4 support
        // floor may stand alone.
        $this->assertDrainWindowComplete(self::T_H + self::MAX_TTL, self::T_H, 'the v4 residual drain since the last v4 issuance');
        $walkEnd = self::T_H + self::MAX_TTL;
        self::assertSame([], $this->outstanding($walkEnd, 4), 'no v4 record can still be outstanding at the v4 retirement');
        $this->assertLedgerConsistency();
    }
}

/**
 * Minimal PSR-3 logger spy for the walk: records warnings and infos
 * in-process so the phases can assert the gate stays silent on every
 * correctly sequenced transition.
 */
final class UpgradeWalkLoggerSpy implements LoggerInterface
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
