<?php

declare(strict_types=1);

namespace KiwiCaptcha\Tests;

use KiwiCaptcha\ChallengeRecord;
use KiwiCaptcha\Config;
use KiwiCaptcha\Issuer;
use KiwiCaptcha\PoWAlgorithm;
use KiwiCaptcha\SolutionToken;
use KiwiCaptcha\Storage\ArrayStorage;
use KiwiCaptcha\Verifier;
use KiwiCaptcha\VerifyError;
use KiwiCaptcha\Tests\Fixtures\Vectors;
use PHPUnit\Framework\TestCase;

/**
 * Post-derive final revalidation: after the proof derives successfully
 * and before returning Valid, the verifier re-checks against the
 * current server clock (its now closure) and the current expectations.
 *
 * Race tests:
 *  (a) a record with a tiny remaining lifetime: the first cheap TTL
 *      check passes, and the final re-check (with an advanced clock)
 *      rejects Expired; the challenge expired during the expensive
 *      derivation.
 *  (b) the expected policy_version rotates between the cheap check and
 *      the final re-check: the final re-check reads the current
 *      expectation and rejects WrongPolicyVersion (same for region and
 *      issuer).
 */
final class FinalRevalidationTest extends TestCase
{
    private const ISSUED_AT = 1_800_000_000;

    private const CLIENT_IP = '198.51.100.7';

    /** @return array{0: ChallengeRecord, 1: string} an issued+solved record/token pair */
    private function issueAndSolve(Config $config, int $issuedAt = self::ISSUED_AT): array
    {
        $storage = new ArrayStorage();
        $issuer = new Issuer($config, $storage, now: static fn (): int => $issuedAt);
        $challenge = $issuer->issue('login', self::CLIENT_IP);
        $record = $storage->find($challenge->nonce);
        self::assertNotNull($record);

        $saltBytes = base64_decode($challenge->salt, true);
        $counter = 0;
        do {
            $hash = hash('sha256', $challenge->prefix.$counter.$saltBytes, true);
            $counter++;
        } while (Verifier::leadingZeroBits($hash) < $challenge->targetBits);
        --$counter;

        return [$record, SolutionToken::create($challenge->nonce, $counter, 5000, [])->encode()];
    }

    private function shaConfig(int $ttlSecs = 120, int $policyVersion = 1, ?string $issuer = null): Config
    {
        return new Config(
            secretKey: Vectors::SECRET,
            algorithm: PoWAlgorithm::Sha256,
            mKib: 0,
            t: 1,
            p: 1,
            targetBits: 8,
            argon2TargetBits: 8,
            ttlSecs: $ttlSecs,
            minDurationMs: 0,
            policyVersion: $policyVersion,
            issuer: $issuer,
        );
    }

    public function testCheapCheckPassesButFinalRecheckRejectsExpiredDuringDerivation(): void
    {
        // Race (a): the challenge has ~1s of lifetime; the cheap TTL
        // check (first clock call, now = issued_at) passes, but the
        // expensive derivation crosses the expiry. The final re-check
        // reads the advanced clock (second call, now = expires_at) and
        // rejects Expired even though the proof was valid.
        [$record, $token] = $this->issueAndSolve($this->shaConfig(ttlSecs: 1));
        $storage = new ArrayStorage();
        $storage->store($record);

        $calls = 0;
        $clock = function () use (&$calls): int {
            ++$calls;

            return $calls === 1 ? self::ISSUED_AT : self::ISSUED_AT + 1;
        };

        $verifier = new Verifier($storage, now: $clock);
        $outcome = $verifier->verify($token, Vectors::SECRET, 'login', self::CLIENT_IP, nowNs: $record->issuedAtNs + 1_000_000);

        self::assertSame(2, $calls, 'the verifier clock must be read once for the cheap TTL check and once for the final re-check');
        self::assertSame(VerifyError::Expired, $outcome->error, 'a challenge expiring during the derivation must be rejected even though the proof is valid');
    }

    public function testFinalRecheckWithUnchangedClockStillVerifies(): void
    {
        // Control for (a): with a stable clock the final re-check passes and
        // the outcome is Valid.
        [$record, $token] = $this->issueAndSolve($this->shaConfig(ttlSecs: 1));
        $storage = new ArrayStorage();
        $storage->store($record);

        $verifier = new Verifier($storage, now: static fn (): int => self::ISSUED_AT);
        $outcome = $verifier->verify($token, Vectors::SECRET, 'login', self::CLIENT_IP, nowNs: $record->issuedAtNs + 1_000_000);

        self::assertTrue($outcome->isOk(), sprintf('a stable clock must pass the final re-check, got %s', $outcome->code()));
    }

    public function testPolicyVersionRotatedBetweenCheapAndFinalRecheck(): void
    {
        // Race (b): the deployment rotates its expected policy epoch
        // during the verification (the rotation lands on the second clock
        // read, the final re-check's expiry check, so the cheap check
        // already passed with the cheap-phase expectation). The final
        // re-check reads the current expected value and rejects
        // WrongPolicyVersion.
        [$record, $token] = $this->issueAndSolve($this->shaConfig(policyVersion: 2));
        $storage = new ArrayStorage();
        $storage->store($record);

        $verifier = null;
        $calls = 0;
        $clock = function () use (&$verifier, &$calls): int {
            ++$calls;
            if ($calls === 2) {
                // Rotation lands between the cheap check (call 1) and the
                // final re-check (call 2).
                $verifier?->rotateDeploymentExpectations(policyVersion: 3, region: null, issuer: null);
            }

            return self::ISSUED_AT;
        };

        $verifier = new Verifier($storage, now: $clock, expectedPolicyVersion: 2);
        $outcome = $verifier->verify($token, Vectors::SECRET, 'login', self::CLIENT_IP, nowNs: $record->issuedAtNs + 1_000_000);

        self::assertSame(VerifyError::WrongPolicyVersion, $outcome->error, 'a mid-derivation policy rotation must fail the final re-check');
    }

    public function testRegionRotatedBetweenCheapAndFinalRecheck(): void
    {
        [$record, $token] = $this->issueAndSolve($this->shaConfig());
        $storage = new ArrayStorage();
        $storage->store($record);

        $verifier = null;
        $calls = 0;
        $clock = function () use (&$verifier, &$calls): int {
            ++$calls;
            if ($calls === 2) {
                $verifier?->rotateDeploymentExpectations(policyVersion: null, region: 'us', issuer: null);
            }

            return self::ISSUED_AT;
        };

        $verifier = new Verifier($storage, now: $clock, region: 'eu');
        $outcome = $verifier->verify($token, Vectors::SECRET, 'login', self::CLIENT_IP, nowNs: $record->issuedAtNs + 1_000_000);

        self::assertSame(VerifyError::WrongRegion, $outcome->error, 'a mid-derivation region rotation must fail the final re-check');
    }

    public function testIssuerRotatedBetweenCheapAndFinalRecheck(): void
    {
        [$record, $token] = $this->issueAndSolve($this->shaConfig(issuer: 'dev'));
        $storage = new ArrayStorage();
        $storage->store($record);

        $verifier = null;
        $calls = 0;
        $clock = function () use (&$verifier, &$calls): int {
            ++$calls;
            if ($calls === 2) {
                $verifier?->rotateDeploymentExpectations(policyVersion: null, region: null, issuer: 'prod');
            }

            return self::ISSUED_AT;
        };

        $verifier = new Verifier($storage, now: $clock, expectedIssuer: 'dev');
        $outcome = $verifier->verify($token, Vectors::SECRET, 'login', self::CLIENT_IP, nowNs: $record->issuedAtNs + 1_000_000);

        self::assertSame(VerifyError::WrongIssuer, $outcome->error, 'a mid-derivation issuer rotation must fail the final re-check');
    }

    public function testRotationToMatchingExpectationsStillVerifies(): void
    {
        // Control: a rotation that lands on matching values must not
        // reject.
        [$record, $token] = $this->issueAndSolve($this->shaConfig(policyVersion: 2, issuer: 'prod'));
        $storage = new ArrayStorage();
        $storage->store($record);

        $verifier = null;
        $calls = 0;
        $clock = function () use (&$verifier, &$calls): int {
            ++$calls;
            if ($calls === 2) {
                $verifier?->rotateDeploymentExpectations(policyVersion: 2, region: null, issuer: 'prod');
            }

            return self::ISSUED_AT;
        };

        $verifier = new Verifier($storage, now: $clock, expectedPolicyVersion: 2, expectedIssuer: 'prod');
        $outcome = $verifier->verify($token, Vectors::SECRET, 'login', self::CLIENT_IP, nowNs: $record->issuedAtNs + 1_000_000);

        self::assertTrue($outcome->isOk(), sprintf('a rotation to matching expectations must verify, got %s', $outcome->code()));
    }

    public function testFinalRecheckRejectsExpiredConsumedRecord(): void
    {
        // Expiry at the final re-check happens after consume; the record
        // is already transitioned, so a subsequent retry (with a stable
        // clock) replays the committed valid outcome. But the first
        // attempt is Expired: the final re-check fires before any commit.
        [$record, $token] = $this->issueAndSolve($this->shaConfig(ttlSecs: 1));
        $storage = new ArrayStorage();
        $storage->store($record);

        $calls = 0;
        $clock = function () use (&$calls): int {
            ++$calls;

            return $calls === 1 ? self::ISSUED_AT : self::ISSUED_AT + 1;
        };

        $verifier = new Verifier($storage, now: $clock);
        $outcome = $verifier->verify($token, Vectors::SECRET, 'login', self::CLIENT_IP, nowNs: $record->issuedAtNs + 1_000_000);
        self::assertSame(VerifyError::Expired, $outcome->error);

        // The record is consumed without a committed result (the final
        // re-check failed before commit); a retry is intrinsically
        // ambiguous, never a replay of Valid.
        $retry = $storage->consume($record->nonce);
        self::assertNotNull($retry);
        self::assertTrue($retry->consumedBefore);
        self::assertNull($retry->consumedResult, 'no deterministic result may be committed for a final-recheck-rejected outcome');
    }

    public function testFinalRecheckRejectsExpiredEvenForAnInsufficientDerivation(): void
    {
        // Round-95 audit fix, Rust parity: the post-derive final
        // revalidation runs before the leading-zero verdict for both
        // outcomes, so an insufficient proof on a record that expired
        // during the derivation commits Expired, never a stale
        // InsufficientWork (the Rust mirror runs final_revalidate
        // before the leading-zero check).
        [$record, $token] = $this->issueAndSolve($this->shaConfig(ttlSecs: 1));
        $storage = new ArrayStorage();
        $storage->store($record);

        $wrongCounter = 0;
        $saltBytes = base64_decode($record->salt, true);
        while (Verifier::leadingZeroBits(hash('sha256', $record->prefix.$wrongCounter.$saltBytes, true)) >= $record->targetBits) {
            ++$wrongCounter;
        }
        $wrongToken = SolutionToken::create($record->nonce, $wrongCounter, 5000, [])->encode();

        $calls = 0;
        $clock = function () use (&$calls): int {
            ++$calls;

            return $calls === 1 ? self::ISSUED_AT : self::ISSUED_AT + 1;
        };

        $verifier = new Verifier($storage, now: $clock);
        $outcome = $verifier->verify($wrongToken, Vectors::SECRET, 'login', self::CLIENT_IP, nowNs: $record->issuedAtNs + 1_000_000);

        self::assertSame(VerifyError::Expired, $outcome->error, 'an insufficient derivation on a record expiring mid-derive must commit Expired (Rust parity), never InsufficientWork');
        self::assertSame(2, $calls, 'the verifier clock must be read once for the cheap TTL check and once for the final re-check');
        self::assertNull($storage->consumedState($record->nonce)?->consumedResult, 'the expired verification must not commit an invalid result');
    }
}
