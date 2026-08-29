<?php

declare(strict_types=1);

namespace KiwiCaptcha\Tests;

use KiwiCaptcha\ChallengeRecord;
use KiwiCaptcha\Config;
use KiwiCaptcha\Issuer;
use KiwiCaptcha\PoWAlgorithm;
use KiwiCaptcha\Storage\ArrayStorage;
use PHPUnit\Framework\TestCase;

/**
 * The resume-claim storage-boundary contract (shared with the Redis
 * backend and the Rust verifier): the claim lease TTL must be >= 1
 * second, and an owner must be exactly 32 lowercase hex characters.
 * Malformed inputs are rejected with InvalidArgumentException at the
 * storage boundary, never passed through to the claim state.
 */
final class ArrayStorageResumeClaimValidationTest extends TestCase
{
    private const SECRET = '0123456789abcdef0123456789abcdef';

    private function makeRecord(string $nonce = 'array-nonce-1'): ChallengeRecord
    {
        return new ChallengeRecord(
            nonce: $nonce,
            scope: 'login',
            bindingTag: 'abc123',
            issuedAt: 1_800_000_000,
            expiresAt: 1_800_000_120,
            algorithm: PoWAlgorithm::Sha256,
            mKib: 0,
            t: 1,
            p: 1,
            targetBits: 8,
            salt: 'c2FsdA==',
            prefix: 'prefix',
            challenge: 'challenge',
            minDurationMs: 0,
            issuedAtNs: 123_456_789,
        );
    }

    public function testClaimTtlBelowOneIsRejectedAtTheStorageBoundary(): void
    {
        $storage = new ArrayStorage();

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('TTL');
        $storage->claimResumeDerivation('array-nonce-1', 0);
    }

    public function testOwnerShapeIsValidatedAtTheStorageBoundary(): void
    {
        $storage = new ArrayStorage();
        $storage->store($this->makeRecord());
        $storage->consume('array-nonce-1');
        $owner = $storage->claimResumeDerivation('array-nonce-1');
        self::assertIsString($owner);

        $badShapes = [
            strtoupper($owner),
            substr($owner, 0, 31),
            $owner.'a',
            'g'.substr($owner, 1),
        ];
        foreach ($badShapes as $shape) {
            try {
                $storage->releaseResumeDerivation('array-nonce-1', $shape);
                self::fail('a malformed release owner must be rejected: '.$shape);
            } catch (\InvalidArgumentException) {
                self::assertTrue(true);
            }
            try {
                $storage->commitResultResume('array-nonce-1', true, 'txn-1', $shape);
                self::fail('a malformed commit owner must be rejected: '.$shape);
            } catch (\InvalidArgumentException) {
                self::assertTrue(true);
            }
        }

        self::assertTrue($storage->commitResultResume('array-nonce-1', true, 'txn-1', $owner), 'the true owner still commits through the intact claim');
    }

    public function testValidShapedWrongOwnerIsRefusedNotThrown(): void
    {
        // A well-formed owner that is simply not the claim holder is a
        // refusal (false), never an exception: the boundary validation
        // only rejects malformed shapes.
        $storage = new ArrayStorage();
        $storage->store($this->makeRecord());
        $storage->consume('array-nonce-1');
        $owner = $storage->claimResumeDerivation('array-nonce-1');
        self::assertIsString($owner);

        self::assertFalse($storage->releaseResumeDerivation('array-nonce-1', str_repeat('b', 32)));
        self::assertFalse($storage->commitResultResume('array-nonce-1', true, 'txn-1', str_repeat('b', 32)));
        self::assertTrue($storage->releaseResumeDerivation('array-nonce-1', $owner), 'the true owner still releases');
    }

    public function testVerifierDrivenLifecycleStillUsesTheContract(): void
    {
        // The full issue/solve/resume path through the Issuer keeps
        // working: the generated owners and TTLs are valid under the
        // shared contract.
        $storage = new ArrayStorage();
        $issuer = new Issuer(new Config(secretKey: self::SECRET, targetBits: 8, ttlSecs: 120, minDurationMs: 0), $storage);
        $challenge = $issuer->issue('login', '198.51.100.7');
        $record = $storage->find($challenge->nonce);
        self::assertNotNull($record);
        $storage->consumeWithOperationIdentity($record->nonce, hash('sha256', 'logical-operation'));

        $claimed = $storage->claimResumeDerivation($record->nonce);
        self::assertIsString($claimed, 'a consumed, resultless record is claimable');
        self::assertTrue($storage->commitResultResume($record->nonce, true, $record->requestBinding, $claimed), 'the claim-bearing commit lands');
    }
}
