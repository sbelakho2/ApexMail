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
use KiwiCaptcha\Config;
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
use KiwiCaptcha\Verifier;
use KiwiCaptcha\VerifyError;
use PHPUnit\Framework\TestCase;

/**
 * The mixed-fleet invariants of the protocol-v3 two-phase rollout.
 * A v3-armed challenge issued under a confirmed central floor of 3
 * verifies through the current verifier, which accepts v2 and v3.
 * The same record is rejected as MalformedRecord by a simulated
 * parent-revision verifier whose supported-protocol set is {1, 2}.
 * That is the exact old-binary failure the rollout procedure prevents:
 * old binaries stay out of the pool until the floor is raised.
 * The symmetric invariant: v2 emission, the default, verifies through
 * both generations, so a rolling fleet never breaks availability.
 */
final class MixedFleetRolloutInvariantTest extends TestCase
{
    private const SECRET = '0123456789abcdef0123456789abcdef';

    private const POLICY_KEY = '{kiwi:test-ns}:security-policy';

    /**
     * A risk-wired controller over one ArrayStorage, decoy-v3 armed
     * under a confirmed central floor of 3. The issuer and the verifier
     * share one fixed clock, so the TTL checks never see a
     * future-issued or prematurely expired record.
     *
     * @return array{controller: ChallengeController, storage: ArrayStorage, verifier: Verifier}
     */
    private function armedStack(): array
    {
        $storage = new ArrayStorage();
        $now = static fn (): int => 1_800_000_000;
        $issuer = new Issuer(new Config(secretKey: self::SECRET, targetBits: 8, ttlSecs: 120, minDurationMs: 0), $storage, now: $now);
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
        $redis->hset(self::POLICY_KEY, SecurityEpochMonitor::MIN_PROTOCOL_VERSION_FIELD, '3');
        $redis->hset(self::POLICY_KEY, SecurityEpochMonitor::MIN_POLICY_EPOCH_FIELD, '1');
        $verifier = new Verifier($storage, now: static fn (): int => 1_800_000_000);
        $monitor = new SecurityEpochMonitor($verifier, $redis, 'test-ns', 1);
        $controller = new ChallengeController(
            $issuer,
            null,
            true,
            $gateway,
            new ContinuityCookie(),
            epochMonitor: $monitor,
            decoyV3Enabled: true,
        );

        return ['controller' => $controller, 'storage' => $storage, 'verifier' => $verifier];
    }

    /**
     * @return array{nonce: string, record: \KiwiCaptcha\ChallengeRecord, token: string}
     */
    private function issueAndSolve(ChallengeController $controller, ArrayStorage $storage): array
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
        $data = json_decode((string) $response->getContent(), true);
        self::assertSame(200, $response->getStatusCode(), 'issuance must succeed under a fresh confirmed policy');
        $record = $storage->find($data['nonce']);
        self::assertNotNull($record);

        // Brute-force the winning counter for the 8-bit SHA-256
        // challenge (fast), then build the solution token.
        $saltBytes = base64_decode($record->salt, true);
        $counter = 0;
        do {
            $hash = hash('sha256', $record->prefix.$counter.$saltBytes, true);
            $counter++;
        } while (Verifier::leadingZeroBits($hash) < $record->targetBits);
        --$counter;

        return [
            'nonce' => $data['nonce'],
            'record' => $record,
            'token' => SolutionToken::create($data['nonce'], $counter, 5000, [])->encode(),
        ];
    }

    public function testV3ArmedChallengeVerifiesThroughTheCurrentVerifier(): void
    {
        // The new-generation side of the invariant: a decoy-armed
        // (protocol v3) challenge issued under floor 3 solves and
        // verifies transparently through the current verifier, which
        // accepts v2 and v3.
        $stack = $this->armedStack();
        $issued = $this->issueAndSolve($stack['controller'], $stack['storage']);
        self::assertSame(3, $issued['record']->protocolVersion, 'the armed issuance writes protocol v3');
        self::assertNotNull($issued['record']->decoyField);

        $outcome = $stack['verifier']->verify(
            $issued['token'],
            self::SECRET,
            'login',
            '198.51.100.7',
            nowNs: $issued['record']->issuedAtNs + 1_000_000,
        );
        self::assertTrue($outcome->isOk(), sprintf('the current verifier must accept its own v3 record, got %s', $outcome->code()));
        self::assertSame($issued['record']->decoyField, $outcome->decoyField(), 'the valid outcome exposes the authenticated decoy name');
    }

    public function testTheSameV3RecordIsRejectedByAV2OnlyVerifierSimulator(): void
    {
        // The prior-generation side of the invariant, the failure the
        // two-phase rollout protects against: the parent-revision
        // verifier's protocol acceptance set is {1, 2}, so the very
        // same record and token fail closed as MalformedRecord — the
        // documented old-binary behavior. The rollout keeps such
        // binaries out of the pool (readiness drains them below the
        // floor) until every serving verifier accepts v3.
        $stack = $this->armedStack();
        $issued = $this->issueAndSolve($stack['controller'], $stack['storage']);
        self::assertSame(3, $issued['record']->protocolVersion, 'fixture is a genuine v3-armed record');

        // The direct version-acceptance predicate with an explicit max:
        // protocol 3 is outside {1, 2}.
        self::assertTrue(ProtocolV2OnlyVerifier::accepts(1, 2));
        self::assertTrue(ProtocolV2OnlyVerifier::accepts(2, 2));
        self::assertFalse(ProtocolV2OnlyVerifier::accepts(3, 2), 'protocol 3 must be outside the parent revision\'s acceptance set');
        self::assertTrue(ProtocolV2OnlyVerifier::accepts(3, 3), 'the new generation accepts v3 (its own max protocol)');

        // The wrapper simulates the parent-revision binary: its own
        // verifier over the storage it peeks. The gate rejects the v3
        // record before any delegation.
        $oldBinary = new ProtocolV2OnlyVerifier($stack['verifier'], $stack['storage']);
        $outcome = $oldBinary->verify(
            $issued['token'],
            self::SECRET,
            'login',
            '198.51.100.7',
            $issued['record']->issuedAtNs + 1_000_000,
        );
        self::assertSame(
            VerifyError::MalformedRecord,
            $outcome->error,
            'a parent-revision verifier must reject a v3 record as MalformedRecord'
        );
    }

    public function testV2EmissionVerifiesThroughBothGenerations(): void
    {
        // The symmetric availability invariant of the rolling fleet: the
        // default emission (protocol v2, decoy_v3_enabled off) solves
        // and verifies through the current verifier and the simulated
        // parent-revision verifier, so a mixed fleet serving v2 traffic
        // never breaks a solve while the rollout is in progress.
        $storage = new ArrayStorage();
        $now = static fn (): int => 1_800_000_000;
        $issuer = new Issuer(new Config(secretKey: self::SECRET, targetBits: 8, ttlSecs: 120, minDurationMs: 0), $storage, now: $now);
        $verifier = new Verifier($storage, now: static fn (): int => 1_800_000_000);
        $controller = new ChallengeController($issuer, decoyV3Enabled: false);

        $response = $controller->challenge(JsonRequest::create(
            '/kiwi-captcha/challenge',
            'POST',
            [],
            [],
            [],
            ['REMOTE_ADDR' => '198.51.100.7'],
            '{"scope":"login"}',
        ));
        $data = json_decode((string) $response->getContent(), true);
        self::assertSame(200, $response->getStatusCode());
        $record = $storage->find($data['nonce']);
        self::assertNotNull($record);
        self::assertSame(2, $record->protocolVersion, 'the default config emits protocol v2');

        $saltBytes = base64_decode($record->salt, true);
        $counter = 0;
        do {
            $hash = hash('sha256', $record->prefix.$counter.$saltBytes, true);
            $counter++;
        } while (Verifier::leadingZeroBits($hash) < $record->targetBits);
        --$counter;
        $token = SolutionToken::create($data['nonce'], $counter, 5000, [])->encode();

        $current = $verifier->verify($token, self::SECRET, 'login', '198.51.100.7', nowNs: $record->issuedAtNs + 1_000_000);
        self::assertTrue($current->isOk(), sprintf('the current verifier must accept v2, got %s', $current->code()));

        // The current verify consumed the record (one-shot); the
        // parent-revision simulation runs over a fresh storage holding
        // the same record bytes, with its own verifier over that
        // storage.
        $legacyStorage = new ArrayStorage();
        $legacyStorage->store($record);
        $legacyVerifier = new Verifier($legacyStorage, now: static fn (): int => 1_800_000_000);
        $oldBinary = new ProtocolV2OnlyVerifier($legacyVerifier, $legacyStorage);
        $legacy = $oldBinary->verify($token, self::SECRET, 'login', '198.51.100.7', $record->issuedAtNs + 1_000_000);
        self::assertTrue($legacy->isOk(), sprintf('a parent-revision verifier must keep serving v2 traffic, got %s', $legacy->code()));
    }
}
