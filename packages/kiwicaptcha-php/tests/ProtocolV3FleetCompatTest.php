<?php

declare(strict_types=1);

namespace KiwiCaptcha\Tests;

use KiwiCaptcha\Challenge;
use KiwiCaptcha\Config;
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
 * The protocol-v3 mixed-fleet verification invariants, the PHP mirror
 * of the two-phase rollout contract.
 * A v3-armed challenge, the decoy-capable canonical, verifies through
 * the current verifier, whose acceptance set is {1, 2, 3}.
 * The same record and token are rejected as MalformedRecord by the
 * simulated parent-revision verifier, whose acceptance set is {1, 2}:
 * the exact old-binary behavior the rollout protects against.
 * The symmetric invariant: unarmed v2 emission verifies through both
 * generations, so a mixed fleet serving v2 traffic never breaks a
 * solve.
 */
final class ProtocolV3FleetCompatTest extends TestCase
{
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
        );
    }

    /** Brute-force the winning counter for an 8-bit SHA-256 challenge. */
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

    public function testV3ArmedChallengeVerifiesThroughTheCurrentVerifier(): void
    {
        // The new-generation side of the invariant: a decoy-armed
        // (protocol v3) challenge solves and verifies transparently
        // through the current verifier.
        $storage = new ArrayStorage();
        $issuer = new Issuer($this->shaConfig(), $storage, now: static fn (): int => Vectors::NOW);
        $challenge = $issuer->issueWithDecoyField('login', Vectors::CLIENT_IP);
        $record = $storage->find($challenge->nonce);
        self::assertNotNull($record);
        self::assertSame(3, $record->protocolVersion, 'an armed issuance writes protocol v3');
        self::assertNotNull($record->decoyField);

        $token = SolutionToken::create($challenge->nonce, $this->solveCounter($challenge), 5000, [])->encode();
        $outcome = $this->verifier($storage)->verify(
            $token,
            Vectors::SECRET,
            'login',
            Vectors::CLIENT_IP,
            nowNs: $record->issuedAtNs + 1_000_000,
        );
        self::assertTrue($outcome->isOk(), sprintf('the current verifier must accept its own v3 record, got %s', $outcome->code()));
        self::assertSame($record->decoyField, $outcome->decoyField(), 'the valid outcome exposes the authenticated decoy name');
    }

    public function testTheSameV3RecordIsRejectedByAV2OnlyVerifierSimulator(): void
    {
        // The prior-generation side of the invariant, the failure the
        // two-phase rollout protects against: the parent-revision
        // verifier's acceptance set is {1, 2}, so the very same record
        // and token fail closed as MalformedRecord. The rollout keeps
        // such binaries out of the pool (the readiness gate drains
        // anything whose max protocol is below the floor) until every
        // serving verifier accepts v3.
        $storage = new ArrayStorage();
        $issuer = new Issuer($this->shaConfig(), $storage, now: static fn (): int => Vectors::NOW);
        $challenge = $issuer->issueWithDecoyField('login', Vectors::CLIENT_IP);
        $record = $storage->find($challenge->nonce);
        self::assertNotNull($record);
        self::assertSame(3, $record->protocolVersion, 'fixture is a genuine v3-armed record');

        // The direct version-acceptance predicate with an explicit max:
        // protocol 3 is outside {1, 2}.
        self::assertTrue(ProtocolV2OnlyVerifier::accepts(1, 2));
        self::assertTrue(ProtocolV2OnlyVerifier::accepts(2, 2));
        self::assertFalse(ProtocolV2OnlyVerifier::accepts(3, 2), 'protocol 3 must be outside the parent revision\'s acceptance set');
        self::assertTrue(ProtocolV2OnlyVerifier::accepts(3, 3), 'the new generation accepts v3 (its own max protocol)');

        $token = SolutionToken::create($challenge->nonce, $this->solveCounter($challenge), 5000, [])->encode();
        $current = $this->verifier($storage)->verify(
            $token,
            Vectors::SECRET,
            'login',
            Vectors::CLIENT_IP,
            nowNs: $record->issuedAtNs + 1_000_000,
        );
        self::assertTrue($current->isOk(), 'the current verifier must accept the fixture record first');

        $oldBinary = new ProtocolV2OnlyVerifier($this->verifier($storage), $storage);
        $outcome = $oldBinary->verify(
            $token,
            Vectors::SECRET,
            'login',
            Vectors::CLIENT_IP,
            $record->issuedAtNs + 1_000_000,
        );
        self::assertSame(
            VerifyError::MalformedRecord,
            $outcome->error,
            'a parent-revision verifier must reject a v3 record as MalformedRecord'
        );
    }

    public function testV2EmissionVerifiesThroughBothGenerations(): void
    {
        // The symmetric availability invariant of the rolling fleet:
        // unarmed v2 emission solves and verifies through the current
        // verifier and the simulated parent-revision verifier, so a
        // mixed fleet serving v2 traffic never breaks a solve while the
        // rollout is in progress.
        $storage = new ArrayStorage();
        $issuer = new Issuer($this->shaConfig(), $storage, now: static fn (): int => Vectors::NOW);
        $challenge = $issuer->issue('login', Vectors::CLIENT_IP);
        $record = $storage->find($challenge->nonce);
        self::assertNotNull($record);
        self::assertSame(2, $record->protocolVersion);

        $token = SolutionToken::create($challenge->nonce, $this->solveCounter($challenge), 5000, [])->encode();
        $current = $this->verifier($storage)->verify(
            $token,
            Vectors::SECRET,
            'login',
            Vectors::CLIENT_IP,
            nowNs: $record->issuedAtNs + 1_000_000,
        );
        self::assertTrue($current->isOk(), sprintf('the current verifier must accept v2, got %s', $current->code()));

        // The current verify consumed the record (one-shot); the
        // parent-revision simulation runs over a fresh storage holding
        // the same record bytes, with its own verifier over that
        // storage.
        $legacyStorage = new ArrayStorage();
        $legacyStorage->store($record);
        $oldBinary = new ProtocolV2OnlyVerifier($this->verifier($legacyStorage), $legacyStorage);
        $legacy = $oldBinary->verify(
            $token,
            Vectors::SECRET,
            'login',
            Vectors::CLIENT_IP,
            $record->issuedAtNs + 1_000_000,
        );
        self::assertTrue($legacy->isOk(), sprintf('a parent-revision verifier must keep serving v2 traffic, got %s', $legacy->code()));
    }

    public function testV3RecordRoundTripsRealRedisAndTheV2OnlyVerifierRejectsIt(): void
    {
        // The real-Redis variant: a v3-armed record stored through the
        // production RedisStorage round-trips and verifies through the
        // current verifier, while the simulated parent-revision verifier
        // rejects the same token as MalformedRecord — the fleet
        // invariant holds on the production storage path too.
        // Runs when `KC_REDIS_URL` or `TEST_REDIS_URL` is set; skips
        // otherwise.
        $url = getenv('KC_REDIS_URL');
        if (!\is_string($url) || $url === '') {
            $url = getenv('TEST_REDIS_URL');
        }
        if (!\is_string($url) || $url === '') {
            self::markTestSkipped('KC_REDIS_URL/TEST_REDIS_URL not set — the real-Redis fleet test runs in the CI Redis-service job');
        }
        try {
            $client = new \Predis\Client($url, ['timeout' => 5.0, 'read_write_timeout' => 5.0]);
            $client->ping();
        } catch (\Throwable) {
            self::markTestSkipped('no Redis at the configured KC_REDIS_URL/TEST_REDIS_URL');
        }

        $storage = new RedisStorage($client, 'fleet-compat-'.bin2hex(random_bytes(4)).'-');
        $issuer = new Issuer($this->shaConfig(), $storage, now: static fn (): int => Vectors::NOW);
        $challenge = $issuer->issueWithDecoyField('login', Vectors::CLIENT_IP);
        $record = $storage->find($challenge->nonce);
        self::assertNotNull($record);
        self::assertSame(3, $record->protocolVersion, 'the armed record round-trips through Redis as protocol v3');

        $token = SolutionToken::create($challenge->nonce, $this->solveCounter($challenge), 5000, [])->encode();
        $current = $this->verifier($storage)->verify(
            $token,
            Vectors::SECRET,
            'login',
            Vectors::CLIENT_IP,
            nowNs: $record->issuedAtNs + 1_000_000,
        );
        self::assertTrue($current->isOk(), sprintf('the Redis round-tripped v3 record must verify on the current verifier, got %s', $current->code()));

        $oldBinary = new ProtocolV2OnlyVerifier($this->verifier($storage), $storage);
        $outcome = $oldBinary->verify(
            $token,
            Vectors::SECRET,
            'login',
            Vectors::CLIENT_IP,
            $record->issuedAtNs + 1_000_000,
        );
        self::assertSame(VerifyError::MalformedRecord, $outcome->error, 'a parent-revision verifier must reject the Redis-stored v3 record');
    }
}
