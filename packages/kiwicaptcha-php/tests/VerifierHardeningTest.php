<?php

declare(strict_types=1);

namespace KiwiCaptcha\Tests;

use KiwiCaptcha\ChallengeRecord;
use KiwiCaptcha\Issuer;
use KiwiCaptcha\PoWAlgorithm;
use KiwiCaptcha\SolutionToken;
use KiwiCaptcha\Storage\ArrayStorage;
use KiwiCaptcha\Verifier;
use KiwiCaptcha\VerifyError;
use KiwiCaptcha\Tests\Fixtures\Vectors;
use PHPUnit\Framework\TestCase;

/**
 * Security-hardening behaviour of the verifier: server-measured minimum
 * duration (client-reported duration is no longer trusted), opt-in telemetry
 * enforcement, and attempt caps.
 */
final class VerifierHardeningTest extends TestCase
{
    private function makeConfig(int $minDurationMs = 1000, int $targetBits = 8): \KiwiCaptcha\Config
    {
        return new \KiwiCaptcha\Config(
            secretKey: Vectors::SECRET,
            algorithm: PoWAlgorithm::Sha256,
            mKib: 0,
            t: 1,
            p: 1,
            targetBits: $targetBits,
            argon2TargetBits: 8,
            ttlSecs: 120,
            minDurationMs: $minDurationMs,
        );
    }

    private function solveSha256(string $prefix, string $salt, int $targetBits): int
    {
        $saltBytes = base64_decode($salt, true);
        $counter = 0;
        do {
            $hash = hash('sha256', $prefix.$counter.$saltBytes, true);
            $counter++;
        } while (Verifier::leadingZeroBits($hash) < $targetBits);

        return $counter - 1;
    }

    /**
     * @return array{0: ChallengeRecord, 1: string}
     */
    private function issueAndSolve(ArrayStorage $storage, int $minDurationMs = 1000): array
    {
        $issuer = new Issuer($this->makeConfig($minDurationMs), $storage);
        $challenge = $issuer->issue('login', '198.51.100.77');
        $counter = $this->solveSha256($challenge->prefix, $challenge->salt, $challenge->targetBits);
        $token = SolutionToken::create($challenge->nonce, $counter, 5000, ['wd' => false, 'me' => 3, 'ke' => 1])->encode();
        $record = $storage->find($challenge->nonce);
        self::assertNotNull($record);

        return [$record, $token];
    }

    public function testServerMeasuredElapsedBelowFloorIsTooFast(): void
    {
        $storage = new ArrayStorage();
        [$record, $token] = $this->issueAndSolve($storage, minDurationMs: 1000);

        $verifier = new Verifier($storage);
        // Receipt 1ms before the 1000ms floor elapsed: rejected, even though
        // the client forged duration_ms = 5000. issuedAtNs and nowNs are in
        // the epoch-microsecond domain.
        $outcome = $verifier->verify(
            $token,
            Vectors::SECRET,
            'login',
            '198.51.100.77',
            nowNs: $record->issuedAtNs + 999_000,
        );

        self::assertSame(VerifyError::TooFast, $outcome->error);
    }

    public function testServerMeasuredElapsedAtFloorIsValid(): void
    {
        $storage = new ArrayStorage();
        [$record, $token] = $this->issueAndSolve($storage, minDurationMs: 1000);

        $verifier = new Verifier($storage);
        $outcome = $verifier->verify(
            $token,
            Vectors::SECRET,
            'login',
            '198.51.100.77',
            nowNs: $record->issuedAtNs + 1_000_000,
        );

        self::assertTrue($outcome->isOk(), sprintf('expected valid, got %s', $outcome->code()));
    }

    public function testForgedClientDurationCannotBypassFloor(): void
    {
        // The client claims a 5s solve; the server measures only 1ms of
        // wall-clock elapsed time. The server measurement wins.
        $storage = new ArrayStorage();
        [$record, $token] = $this->issueAndSolve($storage, minDurationMs: 1000);

        self::assertSame(5000, SolutionToken::decode($token)->durationMs, 'precondition: forged duration');

        $verifier = new Verifier($storage);
        $outcome = $verifier->verify(
            $token,
            Vectors::SECRET,
            'login',
            '198.51.100.77',
            nowNs: $record->issuedAtNs + 1_000,
        );

        self::assertSame(VerifyError::TooFast, $outcome->error);
    }

    public function testReceiptBeforeIssuanceWithinSkewToleranceSkipsFloor(): void
    {
        // The verifying host's clock is 1s BEHIND the issuing host's:
        // elapsed would be -1s (unmeasurable). Within the 5s skew
        // tolerance, so the floor check is skipped and the solve passes.
        $storage = new ArrayStorage();
        [$record, $token] = $this->issueAndSolve($storage, minDurationMs: 1000);

        $verifier = new Verifier($storage);
        $outcome = $verifier->verify(
            $token,
            Vectors::SECRET,
            'login',
            '198.51.100.77',
            nowNs: $record->issuedAtNs - 1_000_000,
        );

        self::assertTrue($outcome->isOk(), sprintf('skewed receipt must pass, got %s', $outcome->code()));
    }

    public function testSkewAtExactToleranceBoundaryPasses(): void
    {
        // Receipt exactly 5s before issuance sits at the SKEW_TOLERANCE_US
        // boundary: elapsed is clamped to "unmeasurable", floor skipped.
        $storage = new ArrayStorage();
        [$record, $token] = $this->issueAndSolve($storage, minDurationMs: 1000);

        $verifier = new Verifier($storage);
        $outcome = $verifier->verify(
            $token,
            Vectors::SECRET,
            'login',
            '198.51.100.77',
            nowNs: $record->issuedAtNs - 5_000_000,
        );

        self::assertTrue($outcome->isOk(), sprintf('boundary skew must pass, got %s', $outcome->code()));
    }

    public function testSkewWithinToleranceDoesNotBypassProofOfWork(): void
    {
        // Skipping the floor under skew must not skip the PoW check: a
        // wrong counter still fails with InsufficientWork.
        $storage = new ArrayStorage();
        [$record, $token] = $this->issueAndSolve($storage, minDurationMs: 1000);

        $wrongToken = SolutionToken::create($record->nonce, 1, 5000, ['wd' => false])->encode();

        $verifier = new Verifier($storage);
        $outcome = $verifier->verify(
            $wrongToken,
            Vectors::SECRET,
            'login',
            '198.51.100.77',
            nowNs: $record->issuedAtNs - 1_000_000,
        );

        self::assertSame(VerifyError::InsufficientWork, $outcome->error);
    }

    public function testSkewBeyondToleranceRejectsAsTooFast(): void
    {
        // Receipt 6s before issuance exceeds the 5s tolerance: physically
        // impossible, rejected as TooFast.
        $storage = new ArrayStorage();
        [$record, $token] = $this->issueAndSolve($storage, minDurationMs: 1000);

        $verifier = new Verifier($storage);
        $outcome = $verifier->verify(
            $token,
            Vectors::SECRET,
            'login',
            '198.51.100.77',
            nowNs: $record->issuedAtNs - 6_000_000,
        );

        self::assertSame(VerifyError::TooFast, $outcome->error);
    }

    public function testLegacyRecordWithoutIssuedAtNsUsesClientDurationFallback(): void
    {
        // Pre-upgrade records (issued_at_ns = 0) keep the old behaviour:
        // the client-reported duration drives the TooFast check.
        $storage = new ArrayStorage();
        [$record, $token] = $this->issueAndSolve($storage, minDurationMs: 1000);

        $legacy = new ChallengeRecord(
            nonce: $record->nonce,
            scope: $record->scope,
            ipHash: $record->ipHash,
            issuedAt: $record->issuedAt,
            expiresAt: $record->expiresAt,
            algorithm: $record->algorithm,
            mKib: $record->mKib,
            t: $record->t,
            p: $record->p,
            targetBits: $record->targetBits,
            salt: $record->salt,
            prefix: $record->prefix,
            challenge: $record->challenge,
            minDurationMs: 1000,
            issuedAtNs: 0,
        );

        $storage = new ArrayStorage();
        $storage->store($legacy);
        $verifier = new Verifier($storage);

        $fastToken = SolutionToken::create($record->nonce, SolutionToken::decode($token)->counter, 50, [])->encode();
        $outcome = $verifier->verify($fastToken, Vectors::SECRET, 'login', '198.51.100.77');
        self::assertSame(VerifyError::TooFast, $outcome->error, 'legacy fallback must reject fast client durations');

        $storage->store($legacy);
        $slowToken = SolutionToken::create($record->nonce, SolutionToken::decode($token)->counter, 2000, [])->encode();
        $outcome = $verifier->verify($slowToken, Vectors::SECRET, 'login', '198.51.100.77');
        self::assertTrue($outcome->isOk(), sprintf('legacy slow solve should pass, got %s', $outcome->code()));
    }

    public function testTelemetryRejectedOnlyWhenEnforced(): void
    {
        $storage = new ArrayStorage();
        [$record, $token] = $this->issueAndSolve($storage, minDurationMs: 0);

        $botToken = SolutionToken::create($record->nonce, SolutionToken::decode($token)->counter, 5000, ['wd' => true])->encode();

        $verifier = new Verifier($storage);
        $storage->store($record);
        $outcome = $verifier->verify($botToken, Vectors::SECRET, 'login', '198.51.100.77');
        self::assertTrue($outcome->isOk(), 'telemetry must be ignored when enforcement is off');

        $storage->store($record);
        $outcome = $verifier->verify($botToken, Vectors::SECRET, 'login', '198.51.100.77', enforceTelemetry: true);
        self::assertSame(VerifyError::TelemetryRejected, $outcome->error);
    }

    public function testEmptyTelemetryRejectedWhenEnforced(): void
    {
        // An attacker submitting {} must not bypass strict mode: a real
        // widget always reports telemetry fields.
        $storage = new ArrayStorage();
        [$record, $token] = $this->issueAndSolve($storage, minDurationMs: 0);

        $emptyToken = SolutionToken::create($record->nonce, SolutionToken::decode($token)->counter, 5000, [])->encode();

        $verifier = new Verifier($storage);
        $outcome = $verifier->verify($emptyToken, Vectors::SECRET, 'login', '198.51.100.77', enforceTelemetry: true);
        self::assertSame(VerifyError::TelemetryRejected, $outcome->error);
    }

    public function testEmptyTelemetryAllowedWhenNotEnforced(): void
    {
        $storage = new ArrayStorage();
        [$record, $token] = $this->issueAndSolve($storage, minDurationMs: 0);

        $emptyToken = SolutionToken::create($record->nonce, SolutionToken::decode($token)->counter, 5000, [])->encode();

        $verifier = new Verifier($storage);
        $outcome = $verifier->verify($emptyToken, Vectors::SECRET, 'login', '198.51.100.77');
        self::assertTrue($outcome->isOk(), sprintf('empty telemetry must pass when enforcement is off, got %s', $outcome->code()));
    }

    public function testScopeLongerThan128BytesThrows(): void
    {
        $storage = new ArrayStorage();
        $issuer = new Issuer($this->makeConfig(0), $storage);

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('1-128');
        $issuer->issue(str_repeat('a', 200), '198.51.100.77');
    }

    public function testScope129BytesThrows(): void
    {
        $storage = new ArrayStorage();
        $issuer = new Issuer($this->makeConfig(0), $storage);

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('1-128');
        $issuer->issue(str_repeat('a', 129), '198.51.100.77');
    }

    public function testScopeEmptyThrows(): void
    {
        $storage = new ArrayStorage();
        $issuer = new Issuer($this->makeConfig(0), $storage);

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('1-128');
        $issuer->issue('', '198.51.100.77');
    }

    public function testScope128BytesIsAccepted(): void
    {
        $storage = new ArrayStorage();
        $issuer = new Issuer($this->makeConfig(0), $storage);

        $scope = str_repeat('a', 128);
        $challenge = $issuer->issue($scope, '198.51.100.77');
        self::assertSame($scope, $storage->find($challenge->nonce)?->scope);
    }

    public function testUniformTimingBotRejectedWhenEnforced(): void
    {
        $storage = new ArrayStorage();
        [$record, $token] = $this->issueAndSolve($storage, minDurationMs: 0);

        $uniform = [];
        for ($i = 0; $i < 30; $i++) {
            $uniform[] = 100 + $i * 100;
        }
        $botToken = SolutionToken::create($record->nonce, SolutionToken::decode($token)->counter, 5000, [
            'wd' => false, 'me' => 20, 'ke' => 0, 'et' => $uniform,
        ])->encode();

        $verifier = new Verifier($storage);
        $storage->store($record);
        $outcome = $verifier->verify($botToken, Vectors::SECRET, 'login', '198.51.100.77', enforceTelemetry: true);
        self::assertSame(VerifyError::TelemetryRejected, $outcome->error);
    }

    public function testHumanJitteredTelemetryPassesWhenEnforced(): void
    {
        $storage = new ArrayStorage();
        [$record, $token] = $this->issueAndSolve($storage, minDurationMs: 0);

        $jittered = [];
        for ($i = 0; $i < 30; $i++) {
            $jittered[] = $i * 97 + ($i * 7 % 13);
        }
        $humanToken = SolutionToken::create($record->nonce, SolutionToken::decode($token)->counter, 5000, [
            'wd' => false, 'me' => 20, 'ke' => 0, 'et' => $jittered,
        ])->encode();

        $verifier = new Verifier($storage);
        $storage->store($record);
        $outcome = $verifier->verify($humanToken, Vectors::SECRET, 'login', '198.51.100.77', enforceTelemetry: true);
        self::assertTrue($outcome->isOk(), sprintf('human-like telemetry must pass, got %s', $outcome->code()));
    }

    public function testMaxAttemptsSingleAttemptThenRecordNotFound(): void
    {
        // consume() gives inherent single-use; with a best-effort counter
        // backend (ArrayStorage) the second attempt fails on the consumed
        // record, not on the counter.
        $storage = new ArrayStorage();
        [$record, $token] = $this->issueAndSolve($storage, minDurationMs: 0);

        $verifier = new Verifier($storage);
        $first = $verifier->verify($token, Vectors::SECRET, 'login', '198.51.100.77', maxAttempts: 1);
        self::assertTrue($first->isOk(), sprintf('first attempt must succeed, got %s', $first->code()));

        $second = $verifier->verify($token, Vectors::SECRET, 'login', '198.51.100.77', maxAttempts: 1);
        self::assertSame(VerifyError::RecordNotFound, $second->error);
        // Both attempts were counted (best-effort bookkeeping), and the
        // counter never rejected because consume() already exhausted the
        // single-use record.
        self::assertSame(2, $storage->attemptsUsed($record->nonce));
    }

    public function testMaxAttemptsCountsFailedVerifications(): void
    {
        $storage = new ArrayStorage();
        [$record, $token] = $this->issueAndSolve($storage, minDurationMs: 0);

        $wrongToken = SolutionToken::create($record->nonce, 1, 5000, [])->encode();

        $verifier = new Verifier($storage);
        $outcome = $verifier->verify($wrongToken, Vectors::SECRET, 'login', '198.51.100.77', maxAttempts: 1);
        self::assertSame(VerifyError::InsufficientWork, $outcome->error);

        $second = $verifier->verify($token, Vectors::SECRET, 'login', '198.51.100.77', maxAttempts: 1);
        self::assertSame(VerifyError::RecordNotFound, $second->error);
        self::assertSame(2, $storage->attemptsUsed($record->nonce));
    }

    public function testMaxAttemptsNullLeavesCounterUntouched(): void
    {
        $storage = new ArrayStorage();
        [$record, $token] = $this->issueAndSolve($storage, minDurationMs: 0);

        $verifier = new Verifier($storage);
        $outcome = $verifier->verify($token, Vectors::SECRET, 'login', '198.51.100.77');
        self::assertTrue($outcome->isOk());
        self::assertSame(0, $storage->attemptsUsed($record->nonce));
    }

    public function testIssuedRecordCarriesServerSideIssuedAtNs(): void
    {
        $storage = new ArrayStorage();
        [$record] = $this->issueAndSolve($storage, minDurationMs: 0);

        self::assertGreaterThan(0, $record->issuedAtNs);
        // issuedAtNs is WALL-CLOCK epoch microseconds (not per-host monotonic
        // nanoseconds): it must be in the recent past of this host's clock.
        $nowUs = (int) (microtime(true) * 1_000_000);
        self::assertLessThanOrEqual($nowUs, $record->issuedAtNs, 'issuance must precede the assertion instant');
        self::assertGreaterThan($nowUs - 5_000_000, $record->issuedAtNs, 'issuance must be within the recent past');
    }

    public function testIssuerNowClockOverrideDoesNotAffectIssuedAtNs(): void
    {
        // issuedAtNs comes from the wall-clock microtime(), not the
        // (injectable) unix clock.
        $storage = new ArrayStorage();
        $issuer = new Issuer(
            $this->makeConfig(0),
            $storage,
            now: static fn (): int => 1_800_000_000,
        );
        $challenge = $issuer->issue('login', '198.51.100.77');
        $record = $storage->find($challenge->nonce);

        self::assertSame(1_800_000_000, $record?->issuedAt);
        $nowUs = (int) (microtime(true) * 1_000_000);
        self::assertGreaterThan(0, $record?->issuedAtNs ?? 0);
        self::assertLessThanOrEqual($nowUs, $record?->issuedAtNs ?? PHP_INT_MAX);
        self::assertGreaterThan($nowUs - 5_000_000, $record?->issuedAtNs ?? 0);
    }
}
