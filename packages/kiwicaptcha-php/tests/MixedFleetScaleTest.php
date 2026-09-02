<?php

declare(strict_types=1);

namespace KiwiCaptcha\Tests;

use KiwiCaptcha\Challenge;
use KiwiCaptcha\Config;
use KiwiCaptcha\ExecutionChallengeGenerator;
use KiwiCaptcha\Issuer;
use KiwiCaptcha\PoWAlgorithm;
use KiwiCaptcha\SolutionToken;
use KiwiCaptcha\Storage\ArrayStorage;
use KiwiCaptcha\Storage\RedisStorage;
use KiwiCaptcha\Tests\Fixtures\ProtocolV2OnlyVerifier;
use KiwiCaptcha\Tests\Fixtures\Vectors;
use KiwiCaptcha\Verifier;
use KiwiCaptcha\VerifyError;
use PHPUnit\Framework\TestCase;

/**
 * The mixed-fleet deployment invariants at volume over real Redis.
 *
 * A fleet rollout is a rolling population, not a single pair of
 * records. This suite issues a batch of unarmed v2 records and a batch
 * of decoy-armed v3 records through the production RedisStorage, then
 * verifies every record through the current verifier and through the
 * ProtocolV2OnlyVerifier parent-revision simulator.
 *
 * Every v2 record solves on both generations, the availability side of
 * the contract. Every v3 record solves on the current generation and
 * is rejected as MalformedRecord by the simulator, the typed
 * fail-closed answer. Every consumed record keeps the one-shot
 * semantics with a committed result, so a v3 redemption can never be
 * double-spent.
 *
 * Runs when `KC_REDIS_URL` or `TEST_REDIS_URL` is set; skips otherwise.
 */
final class MixedFleetScaleTest extends TestCase
{
    private const PER_VERSION = 20;

    private \Predis\Client $client;

    private string $prefix;

    protected function setUp(): void
    {
        $url = getenv('KC_REDIS_URL');
        if (!\is_string($url) || $url === '') {
            $url = getenv('TEST_REDIS_URL');
        }
        if (!\is_string($url) || $url === '') {
            self::markTestSkipped('KC_REDIS_URL/TEST_REDIS_URL not set — the real-Redis mixed-fleet suite runs locally and in the Redis-service lane');
        }
        try {
            $this->client = new \Predis\Client($url, ['timeout' => 5.0, 'read_write_timeout' => 5.0]);
            $this->client->ping();
        } catch (\Throwable) {
            self::markTestSkipped('no Redis at the configured KC_REDIS_URL/TEST_REDIS_URL');
        }
        $this->client->flushdb();
        $this->prefix = 'fleet-scale-'.bin2hex(random_bytes(3)).'-';
    }

    private function shaConfig(): Config
    {
        return new Config(
            secretKey: Vectors::SECRET,
            algorithm: PoWAlgorithm::Sha256,
            mKib: 0,
            t: 1,
            p: 1,
            targetBits: 8,
            argon2TargetBits: 8,
            ttlSecs: 120,
            minDurationMs: 0,
            // The execution key is configured from the start so the v4
            // batch can arm (the issuance path decides, never the key).
            executionKey: Vectors::SECRET,
        );
    }

    /** Brute-force the winning counter for an 8-bit sha256 challenge. */
    private function solveCounter(Challenge $challenge): int
    {
        $counter = 0;
        $saltBytes = base64_decode($challenge->salt, true);
        do {
            $hash = hash('sha256', $challenge->prefix.$counter.$saltBytes, true);
            $counter++;
        } while (Verifier::leadingZeroBits($hash) < $challenge->targetBits);

        return $counter - 1;
    }

    private function verifier(\KiwiCaptcha\StorageInterface $storage): Verifier
    {
        return new Verifier($storage, now: static fn (): int => Vectors::NOW);
    }

    public function testMixedFleetVolumeVerifiesAcrossBothVerifierGenerations(): void
    {
        $storage = new RedisStorage($this->client, $this->prefix);
        $issuer = new Issuer($this->shaConfig(), $storage, now: static fn (): int => Vectors::NOW);

        $v2 = [];
        for ($i = 0; $i < self::PER_VERSION; $i++) {
            $challenge = $issuer->issue('login', Vectors::CLIENT_IP);
            $record = $storage->find($challenge->nonce);
            self::assertNotNull($record, 'every v2 issuance must round-trip through Redis');
            self::assertSame(2, $record->protocolVersion, 'an unarmed issuance writes protocol v2');
            self::assertNull($record->decoyField);
            $v2[] = [
                'challenge' => $challenge,
                'record' => $record,
                'token' => SolutionToken::create($challenge->nonce, $this->solveCounter($challenge), 5000, [])->encode(),
            ];
        }

        $v3 = [];
        for ($i = 0; $i < self::PER_VERSION; $i++) {
            $challenge = $issuer->issueWithDecoyField('login', Vectors::CLIENT_IP);
            $record = $storage->find($challenge->nonce);
            self::assertNotNull($record, 'every v3 issuance must round-trip through Redis');
            self::assertSame(3, $record->protocolVersion, 'an armed issuance writes protocol v3');
            self::assertNotNull($record->decoyField);
            $v3[] = [
                'challenge' => $challenge,
                'record' => $record,
                'token' => SolutionToken::create($challenge->nonce, $this->solveCounter($challenge), 5000, [])->encode(),
            ];
        }

        // Every v2 record verifies through the current verifier and
        // through the parent-revision simulator over the same record
        // bytes: a mixed fleet serving v2 traffic breaks no solve.
        $current = $this->verifier($storage);
        foreach ($v2 as $entry) {
            $record = $entry['record'];
            $outcome = $current->verify(
                $entry['token'],
                Vectors::SECRET,
                'login',
                Vectors::CLIENT_IP,
                nowNs: $record->issuedAtNs + 1_000_000,
            );
            self::assertTrue($outcome->isOk(), sprintf('the current verifier must accept v2 at scale, got %s', $outcome->code()));

            $legacyStorage = new ArrayStorage();
            $legacyStorage->store($record);
            $oldBinary = new ProtocolV2OnlyVerifier($this->verifier($legacyStorage), $legacyStorage);
            $legacy = $oldBinary->verify(
                $entry['token'],
                Vectors::SECRET,
                'login',
                Vectors::CLIENT_IP,
                $record->issuedAtNs + 1_000_000,
            );
            self::assertTrue($legacy->isOk(), sprintf('a parent-revision verifier must keep serving v2 at scale, got %s', $legacy->code()));
        }

        // Every v3 record verifies through the current verifier and is
        // rejected deterministically by the simulator as MalformedRecord,
        // the typed fail-closed answer, never a hang or a server error.
        foreach ($v3 as $entry) {
            $record = $entry['record'];
            $outcome = $current->verify(
                $entry['token'],
                Vectors::SECRET,
                'login',
                Vectors::CLIENT_IP,
                nowNs: $record->issuedAtNs + 1_000_000,
            );
            self::assertTrue($outcome->isOk(), sprintf('the current verifier must accept its own v3 record at scale, got %s', $outcome->code()));
            self::assertSame($record->decoyField, $outcome->decoyField(), 'the valid outcome exposes the authenticated decoy name');

            $legacyStorage = new ArrayStorage();
            $legacyStorage->store($record);
            $oldBinary = new ProtocolV2OnlyVerifier($this->verifier($legacyStorage), $legacyStorage);
            $legacy = $oldBinary->verify(
                $entry['token'],
                Vectors::SECRET,
                'login',
                Vectors::CLIENT_IP,
                $record->issuedAtNs + 1_000_000,
            );
            self::assertSame(
                VerifyError::MalformedRecord,
                $legacy->error,
                'a parent-revision verifier must reject every v3 record at scale as MalformedRecord'
            );
        }

        // The v4 batch: execution-armed records through the
        // production RedisStorage. Every v4 record verifies through the
        // current verifier (with the recomputed execution digest), and
        // is rejected deterministically by both older generations: the
        // v2-only simulator and the v3-only simulator (max protocol 3),
        // each answering MalformedRecord.
        $v4 = [];
        for ($i = 0; $i < self::PER_VERSION; $i++) {
            $challenge = $issuer->issueWithExecutionField('login', Vectors::CLIENT_IP, true, executionAction: 'login-action', armDecoyField: true);
            $record = $storage->find($challenge->nonce);
            self::assertNotNull($record, 'every v4 issuance must round-trip through Redis');
            self::assertSame(4, $record->protocolVersion, 'an execution-armed issuance writes protocol v4');
            self::assertNotNull($record->decoyField);
            self::assertSame(1, $record->executionVersion);
            self::assertSame(\KiwiCaptcha\Issuer::executionCommitment($record->executionProgram), $record->executionCommitment, 'the signed commitment mirrors the stored program at scale');
            $program = ExecutionChallengeGenerator::decode($challenge->executionProgram);
            self::assertNotNull($program);
            $trace = ExecutionChallengeGenerator::executedTraceFor($program);
            $digest = ExecutionChallengeGenerator::digestOverTrace($challenge->executionProgram, $challenge->nonce, $trace);
            self::assertNotNull($digest);
            $v4[] = [
                'challenge' => $challenge,
                'record' => $record,
                'token' => SolutionToken::create($challenge->nonce, $this->solveCounter($challenge), 5000, [], $digest, base64_encode($trace))->encode(),
            ];
        }
        foreach ($v4 as $entry) {
            $record = $entry['record'];
            $outcome = $current->verify(
                $entry['token'],
                Vectors::SECRET,
                'login',
                Vectors::CLIENT_IP,
                nowNs: $record->issuedAtNs + 1_000_000,
            );
            self::assertTrue($outcome->isOk(), sprintf('the current verifier must accept its own v4 record at scale, got %s', $outcome->code()));

            $oldStorage = new ArrayStorage();
            $oldStorage->store($record);
            $simulator = new ProtocolV2OnlyVerifier($this->verifier($oldStorage), $oldStorage);
            $v2Only = $simulator->verify(
                $entry['token'],
                Vectors::SECRET,
                'login',
                Vectors::CLIENT_IP,
                $record->issuedAtNs + 1_000_000,
            );
            self::assertSame(VerifyError::MalformedRecord, $v2Only->error, 'a v2-only binary must reject every v4 record at scale');
            $v3Only = $simulator->verify(
                $entry['token'],
                Vectors::SECRET,
                'login',
                Vectors::CLIENT_IP,
                $record->issuedAtNs + 1_000_000,
                ProtocolV2OnlyVerifier::MAX_SUPPORTED_PROTOCOL + 1,
            );
            self::assertSame(VerifyError::MalformedRecord, $v3Only->error, 'a v3-only binary must reject every v4 record at scale as MalformedRecord');
        }

        self::assertCount(self::PER_VERSION, $v2, 'the v2 batch must be complete');
        self::assertCount(self::PER_VERSION, $v3, 'the v3 batch must be complete');
        self::assertCount(self::PER_VERSION, $v4, 'the v4 batch must be complete');
    }

    public function testV3ConsumptionIsAtomicAndDoubleSpendIsDeterministic(): void
    {
        $storage = new RedisStorage($this->client, $this->prefix);
        $issuer = new Issuer($this->shaConfig(), $storage, now: static fn (): int => Vectors::NOW);
        $verifier = $this->verifier($storage);

        for ($i = 0; $i < 10; $i++) {
            $challenge = $issuer->issueWithDecoyField('login', Vectors::CLIENT_IP);
            $record = $storage->find($challenge->nonce);
            self::assertNotNull($record);
            $token = SolutionToken::create($challenge->nonce, $this->solveCounter($challenge), 5000, [])->encode();

            $first = $verifier->verify($token, Vectors::SECRET, 'login', Vectors::CLIENT_IP, nowNs: $record->issuedAtNs + 1_000_000);
            self::assertTrue($first->isOk(), sprintf('the first redemption of a v3 record must succeed, got %s', $first->code()));

            $consumed = $storage->consumedState($challenge->nonce);
            self::assertNotNull($consumed, 'the winner leaves the retained consumed record in place');
            self::assertNotNull($consumed->consumedResult, 'the winner commits the deterministic result');
            self::assertTrue($consumed->consumedResult->valid, 'the committed result is the valid success');

            // The double spend: the same token again on the current
            // verifier answers AlreadyConsumed, the typed one-shot
            // verdict, never a second success.
            $second = $verifier->verify($token, Vectors::SECRET, 'login', Vectors::CLIENT_IP, nowNs: $record->issuedAtNs + 2_000_000);
            self::assertSame(VerifyError::AlreadyConsumed, $second->error, 'a consumed v3 record can never be double-spent');

            // The parent-revision simulator over the shared Redis sees
            // the same consumed envelope and still answers the version
            // gate first: MalformedRecord, deterministic and fast.
            $oldBinary = new ProtocolV2OnlyVerifier($verifier, $storage);
            $legacy = $oldBinary->verify($token, Vectors::SECRET, 'login', Vectors::CLIENT_IP, $record->issuedAtNs + 2_000_000);
            self::assertSame(VerifyError::MalformedRecord, $legacy->error, 'the version gate wins even on a consumed v3 envelope');
        }
    }
}
