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
 * duration (client-reported duration is no longer trusted), opt-in
 * telemetry enforcement, and the one-shot consume-on-verify model (a
 * wrong candidate burns the challenge; there is no maxAttempts).
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
     * The issuer now signs protocol v2 challenges; these tests exercise
     * timing/telemetry/one-shot behaviour, which is version-independent,
     * so swap the issued record for a v1-signed equivalent over the same
     * nonce/salt. The prefix is rebuilt (prefix = challenge|salt|) to
     * stay structurally consistent with the v1 challenge; the caller
     * re-solves the proof against the returned record's prefix.
     */
    private function asV1Record(ChallengeRecord $record): ChallengeRecord
    {
        $ipHash = Issuer::hashIp('198.51.100.77', Vectors::SECRET);
        $payload = sprintf('%s|%s|%s|%d', $record->nonce, $record->scope, $ipHash, $record->issuedAt);
        $challenge = base64_encode($payload).'.'.Issuer::signPayload($payload, Vectors::SECRET);

        return new ChallengeRecord(
            nonce: $record->nonce,
            scope: $record->scope,
            bindingTag: $ipHash,
            issuedAt: $record->issuedAt,
            expiresAt: $record->expiresAt,
            algorithm: $record->algorithm,
            mKib: $record->mKib,
            t: $record->t,
            p: $record->p,
            targetBits: $record->targetBits,
            salt: $record->salt,
            prefix: $challenge.'|'.$record->salt.'|',
            challenge: $challenge,
            minDurationMs: $record->minDurationMs,
            issuedAtNs: $record->issuedAtNs,
            protocolVersion: 1,
        );
    }

    /**
     * @return array{0: ChallengeRecord, 1: string}
     */
    private function issueAndSolve(ArrayStorage $storage, int $minDurationMs = 1000): array
    {
        $issuer = new Issuer($this->makeConfig($minDurationMs), $storage);
        $challenge = $issuer->issue('login', '198.51.100.77');
        $record = $storage->find($challenge->nonce);
        self::assertNotNull($record);
        $record = $this->asV1Record($record);
        $storage->store($record);
        // The v1 challenge carries a different prefix, so the proof must be
        // re-solved against the converted record's prefix.
        $counter = $this->solveSha256($record->prefix, $record->salt, $record->targetBits);
        $token = SolutionToken::create($challenge->nonce, $counter, 5000, ['wd' => false, 'me' => 3, 'ke' => 1])->encode();

        return [$record, $token];
    }

    public function testServerMeasuredElapsedBelowFloorIsTooFast(): void
    {
        $storage = new ArrayStorage();
        [$record, $token] = $this->issueAndSolve($storage, minDurationMs: 1000);

        $verifier = new Verifier($storage, acceptLegacyV1: true);
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

        $verifier = new Verifier($storage, acceptLegacyV1: true);
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

        $verifier = new Verifier($storage, acceptLegacyV1: true);
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
        // The verifying host's clock is 1s behind the issuing host's:
        // elapsed would be -1s (unmeasurable), within the 5s skew
        // tolerance, so the floor check is skipped and the solve passes.
        $storage = new ArrayStorage();
        [$record, $token] = $this->issueAndSolve($storage, minDurationMs: 1000);

        $verifier = new Verifier($storage, acceptLegacyV1: true);
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
        // Receipt exactly 5s before issuance sits at the skew tolerance
        // boundary: elapsed is clamped to "unmeasurable", floor skipped.
        $storage = new ArrayStorage();
        [$record, $token] = $this->issueAndSolve($storage, minDurationMs: 1000);

        $verifier = new Verifier($storage, acceptLegacyV1: true);
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

        // Provably-failing counter (a counter of 1 can coincidentally meet
        // the target — a flake seen in CI).
        $wrongCounter = 1;
        $saltBytes = base64_decode($record->salt, true);
        while (Verifier::leadingZeroBits(hash('sha256', $record->prefix.$wrongCounter.$saltBytes, true)) >= $record->targetBits) {
            ++$wrongCounter;
        }
        $wrongToken = SolutionToken::create($record->nonce, $wrongCounter, 5000, ['wd' => false])->encode();

        $verifier = new Verifier($storage, acceptLegacyV1: true);
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
        // Receipt 6s before issuance exceeds the 5s tolerance:
        // physically impossible, rejected as TooFast.
        $storage = new ArrayStorage();
        [$record, $token] = $this->issueAndSolve($storage, minDurationMs: 1000);

        $verifier = new Verifier($storage, acceptLegacyV1: true);
        $outcome = $verifier->verify(
            $token,
            Vectors::SECRET,
            'login',
            '198.51.100.77',
            nowNs: $record->issuedAtNs - 6_000_000,
        );

        self::assertSame(VerifyError::TooFast, $outcome->error);
    }

    public function testRecordWithoutIssuedAtNsIsMalformed(): void
    {
        // The client-duration fallback is gone: a record without a
        // server-side issued_at_ns cannot be timed and is rejected
        // outright (MalformedRecord) instead of trusting the forgeable
        // client duration. The malformed record is burned.
        $storage = new ArrayStorage();
        [$record, $token] = $this->issueAndSolve($storage, minDurationMs: 1000);

        $untimed = new ChallengeRecord(
            nonce: $record->nonce,
            scope: $record->scope,
            bindingTag: $record->ipHash(),
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
            protocolVersion: 1,
        );

        $storage = new ArrayStorage();
        $storage->store($untimed);
        $verifier = new Verifier($storage, acceptLegacyV1: true);

        $outcome = $verifier->verify($token, Vectors::SECRET, 'login', '198.51.100.77');
        self::assertSame(VerifyError::MalformedRecord, $outcome->error, 'untimed records must not fall back to client duration');
        self::assertNull($storage->find($record->nonce), 'the untimed record must be burned');
    }

    public function testTelemetryRejectedOnlyWhenEnforced(): void
    {
        $storage = new ArrayStorage();
        [$record, $token] = $this->issueAndSolve($storage, minDurationMs: 0);

        $botToken = SolutionToken::create($record->nonce, SolutionToken::decode($token)->counter, 5000, ['wd' => true])->encode();

        $verifier = new Verifier($storage, acceptLegacyV1: true);
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

        $verifier = new Verifier($storage, acceptLegacyV1: true);
        $outcome = $verifier->verify($emptyToken, Vectors::SECRET, 'login', '198.51.100.77', enforceTelemetry: true);
        self::assertSame(VerifyError::TelemetryRejected, $outcome->error);
    }

    public function testEmptyTelemetryAllowedWhenNotEnforced(): void
    {
        $storage = new ArrayStorage();
        [$record, $token] = $this->issueAndSolve($storage, minDurationMs: 0);

        $emptyToken = SolutionToken::create($record->nonce, SolutionToken::decode($token)->counter, 5000, [])->encode();

        $verifier = new Verifier($storage, acceptLegacyV1: true);
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

        $verifier = new Verifier($storage, acceptLegacyV1: true);
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

        $verifier = new Verifier($storage, acceptLegacyV1: true);
        $storage->store($record);
        $outcome = $verifier->verify($humanToken, Vectors::SECRET, 'login', '198.51.100.77', enforceTelemetry: true);
        self::assertTrue($outcome->isOk(), sprintf('human-like telemetry must pass, got %s', $outcome->code()));
    }

    /**
     * Consume-on-verify: a wrong candidate burns the challenge. The
     * record transitions to consumed and the deterministic invalid
     * outcome is committed, so the second (correct) verify sees the
     * same InsufficientWork instead of re-deriving the proof.
     */
    public function testWrongCandidateBurnsTheChallenge(): void
    {
        $storage = new ArrayStorage();
        [$record, $token] = $this->issueAndSolve($storage, minDurationMs: 0);

        // The wrong counter must be provably wrong: at the issued
        // difficulty a random counter coincidentally meets the target
        // with p=1/2^bits (a flake seen in CI). Search upward until the
        // hash provably misses.
        $wrongCounter = 1;
        $saltBytes = base64_decode($record->salt, true);
        while (Verifier::leadingZeroBits(hash('sha256', $record->prefix.$wrongCounter.$saltBytes, true)) >= $record->targetBits) {
            ++$wrongCounter;
        }
        $wrongToken = SolutionToken::create($record->nonce, $wrongCounter, 5000, [])->encode();

        $verifier = new Verifier($storage, acceptLegacyV1: true);
        $first = $verifier->verify($wrongToken, Vectors::SECRET, 'login', '198.51.100.77');
        self::assertSame(VerifyError::InsufficientWork, $first->error);

        $second = $verifier->verify($token, Vectors::SECRET, 'login', '198.51.100.77');
        self::assertSame(VerifyError::InsufficientWork, $second->error, 'the correct token arrives after the consumed marker: the stored invalid outcome replays');
    }

    /**
     * Consume-on-verify: a first verify that succeeds consumes the
     * record and commits the deterministic valid outcome, so a replay of
     * the exact same logical operation (the same operation identity)
     * returns the same Valid without re-deriving. The attempt bound is
     * the single-use record; there is no maxAttempts parameter.
     */
    public function testSuccessfulVerifyReplaysTheCommittedOutcome(): void
    {
        $storage = new ArrayStorage();
        [$record, $token] = $this->issueAndSolve($storage, minDurationMs: 0);
        $identity = 'op-'.hash('sha256', 'login-op');

        $verifier = new Verifier($storage, acceptLegacyV1: true);
        $first = $verifier->verify($token, Vectors::SECRET, 'login', '198.51.100.77', operationIdentity: $identity);
        self::assertTrue($first->isOk(), sprintf('first verify must succeed, got %s', $first->code()));

        $second = $verifier->verify($token, Vectors::SECRET, 'login', '198.51.100.77', operationIdentity: $identity);
        self::assertTrue($second->isOk(), sprintf('a replay of the same operation must return the committed stored outcome, got %s', $second->code()));
        self::assertTrue($second->fromStoredResult, 'the replay must come from the stored result, never a second derivation');
        self::assertNotNull($storage->find($record->nonce), 'the consumed record is KEPT until its TTL (replay protection is the consumed marker, not absence)');
    }

    public function testVerifySignatureHasNoMaxAttemptsParameter(): void
    {
        // The one-shot model replaces maxAttempts: the parameter must be
        // gone from the public API.
        $params = (new \ReflectionMethod(Verifier::class, 'verify'))->getParameters();
        $names = array_map(static fn (\ReflectionParameter $p): string => (string) $p->getName(), $params);

        self::assertNotContains('maxAttempts', $names);
    }

    public function testIssuedRecordCarriesServerSideIssuedAtNs(): void
    {
        $storage = new ArrayStorage();
        [$record] = $this->issueAndSolve($storage, minDurationMs: 0);

        self::assertGreaterThan(0, $record->issuedAtNs);
        // issuedAtNs is wall-clock epoch microseconds (not per-host
        // monotonic nanoseconds): it must be in the recent past of this
        // host's clock.
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
