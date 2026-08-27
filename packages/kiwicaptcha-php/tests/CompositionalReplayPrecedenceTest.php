<?php

declare(strict_types=1);

namespace KiwiCaptcha\Tests;

use KiwiCaptcha\Config;
use KiwiCaptcha\Issuer;
use KiwiCaptcha\SolutionToken;
use KiwiCaptcha\Storage\ArrayStorage;
use KiwiCaptcha\StorageInterface;
use KiwiCaptcha\Verifier;
use KiwiCaptcha\VerifyError;
use KiwiCaptcha\RequestBindingExpectation;
use KiwiCaptcha\VerifyOutcome;
use KiwiCaptcha\Tests\Fixtures\Vectors;
use PHPUnit\Framework\TestCase;

/**
 * Compositional replay precedence: when a retry of a consumed record
 * fails an exempt circumstance (the signed expiry, the IP binding, the
 * missing client IP), that exemption may never mask a hard security
 * verdict that also applies to the same retry. The cheap phase returns
 * the first failing check only, and the exempt set sits early in the
 * order, so a naive first-error routing lets an exempt failure shadow
 * every later hard invariant and replay the stored success around it.
 * The verifier therefore re-evaluates the hard-invariant set on a
 * consumed record before an exempt failure may route into the
 * identity-gated consumed branch. The set covers scope, the expected
 * request binding, region, policy epoch and issuer. Any hard failure
 * wins, the consumed evidence survives, and only an exempt-alone retry
 * replays.
 */
final class CompositionalReplayPrecedenceTest extends TestCase
{
    private const ISSUED_AT = 1_800_000_000;

    private const IDENTITY_A = 'op-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';

    private const IP = '198.51.100.7';

    private const OTHER_IP = '203.0.113.9';

    private static function clock(): \Closure
    {
        return static fn (): int => self::ISSUED_AT;
    }

    private static function expiredClock(): \Closure
    {
        return static fn (): int => self::ISSUED_AT + 121;
    }

    /**
     * Issues, solves and redeems a challenge once (fresh valid
     * derivation, consumed with the operation identity, committed valid
     * result), over a storage whose expectations match the issuance.
     *
     * @return array{0: ArrayStorage, 1: \KiwiCaptcha\ChallengeRecord, 2: string}
     */
    private function issueSolveAndConsume(?string $requestBinding = null): array
    {
        $storage = new ArrayStorage();
        $issuer = new Issuer(
            new Config(secretKey: Vectors::SECRET, targetBits: 8, ttlSecs: 120, minDurationMs: 0),
            $storage,
            now: static fn (): int => self::ISSUED_AT,
        );
        $challenge = $issuer->issue('login', self::IP, $requestBinding);
        $record = $storage->find($challenge->nonce);
        self::assertNotNull($record);

        $token = self::solveToken($challenge->prefix, $challenge->salt, $challenge->nonce, $challenge->targetBits);

        $verifier = new Verifier($storage, now: self::clock());
        $first = $verifier->verify($token, Vectors::SECRET, 'login', self::IP, operationIdentity: self::IDENTITY_A, bindingExpectation: RequestBindingExpectation::exact($requestBinding));
        self::assertTrue($first->isOk(), sprintf('the setup redemption must verify fresh, got %s', $first->code()));
        self::assertNotNull($storage->consumedState($record->nonce)?->consumedResult, 'the setup committed the valid result');

        return [$storage, $record, $token];
    }

    private static function solveToken(string $prefix, string $salt, string $nonce, int $targetBits): string
    {
        $saltBytes = base64_decode($salt, true);
        $counter = 0;
        do {
            $hash = hash('sha256', $prefix.$counter.$saltBytes, true);
            $counter++;
        } while (Verifier::leadingZeroBits($hash) < $targetBits);
        --$counter;

        return SolutionToken::create($nonce, $counter, 5000, [])->encode();
    }

    /**
     * Asserts the full evidence contract of a hard-wins replay: the hard
     * error is the outcome, and the consumed record, its committed valid
     * result and its recorded operation identity all survive.
     */
    private function assertHardFailureWinsWithEvidenceIntact(ArrayStorage $storage, \KiwiCaptcha\ChallengeRecord $record, VerifyOutcome $outcome, VerifyError $expected): void
    {
        self::assertSame($expected, $outcome->error, sprintf('the hard verdict must win over the exempt circumstance, got %s', $outcome->code()));
        self::assertNotSame(VerifyError::Expired, $outcome->error, 'the exempt expiry must not mask the hard verdict');
        self::assertNotSame(VerifyError::IpMismatch, $outcome->error, 'the exempt IP mismatch must not mask the hard verdict');
        self::assertNotSame(VerifyError::MissingClientIp, $outcome->error, 'the exempt missing IP must not mask the hard verdict');
        self::assertTrue(!$outcome->isOk(), 'a hard verdict never resolves to a stored-success replay');
        self::assertNotNull($storage->find($record->nonce), 'the consumed record is NEVER deleted by the hard verdict');
        $state = $storage->consumedState($record->nonce);
        self::assertNotNull($state, 'the record is still in the consumed state');
        self::assertTrue($state->consumedResult?->valid ?? false, 'the committed valid result survives intact');
        self::assertSame(self::IDENTITY_A, $state->operationIdentity, 'the recorded operation identity survives intact');
    }

    /**
     * The Cartesian exempt-plus-hard matrix on a consumed record with the
     * exact matching operation identity: every combination must resolve
     * to the hard error, never to a stored-success replay routed by the
     * exempt circumstance.
     *
     * @param \Closure(Verifier, string): VerifyOutcome $replayCall
     * @param \Closure(ArrayStorage): Verifier $replayVerifierFactory
     */
    public static function exemptMaskedHardProvider(): array
    {
        $secret = Vectors::SECRET;
        $clock = self::clock();
        $expired = self::expiredClock();

        return [
            // expired (the TTL group precedes everything below it)
            'expired + wrong scope' => [
                static fn (Verifier $v, string $t): VerifyOutcome => $v->verify($t, $secret, 'signup', self::IP, operationIdentity: self::IDENTITY_A, bindingExpectation: RequestBindingExpectation::exact('txn-123')),
                VerifyError::WrongScope,
                static fn (ArrayStorage $s): Verifier => new Verifier($s, now: $expired),
            ],
            'expired + request binding mismatch' => [
                static fn (Verifier $v, string $t): VerifyOutcome => $v->verify($t, $secret, 'login', self::IP, operationIdentity: self::IDENTITY_A, expectedRequestBinding: 'txn-OTHER'),
                VerifyError::RequestBindingMismatch,
                static fn (ArrayStorage $s): Verifier => new Verifier($s, now: $expired),
            ],
            'expired + wrong region' => [
                static fn (Verifier $v, string $t): VerifyOutcome => $v->verify($t, $secret, 'login', self::IP, operationIdentity: self::IDENTITY_A, bindingExpectation: RequestBindingExpectation::exact('txn-123')),
                VerifyError::WrongRegion,
                static fn (ArrayStorage $s): Verifier => new Verifier($s, now: $expired, region: 'eu'),
            ],
            'expired + wrong policy epoch' => [
                static fn (Verifier $v, string $t): VerifyOutcome => $v->verify($t, $secret, 'login', self::IP, operationIdentity: self::IDENTITY_A, bindingExpectation: RequestBindingExpectation::exact('txn-123')),
                VerifyError::WrongPolicyVersion,
                static fn (ArrayStorage $s): Verifier => new Verifier($s, now: $expired, expectedPolicyVersion: 2),
            ],
            'expired + wrong issuer' => [
                static fn (Verifier $v, string $t): VerifyOutcome => $v->verify($t, $secret, 'login', self::IP, operationIdentity: self::IDENTITY_A, bindingExpectation: RequestBindingExpectation::exact('txn-123')),
                VerifyError::WrongIssuer,
                static fn (ArrayStorage $s): Verifier => new Verifier($s, now: $expired, expectedIssuer: 'prod'),
            ],
            // IP mismatch (the IP group precedes region/policy/issuer)
            'ip mismatch + wrong region' => [
                static fn (Verifier $v, string $t): VerifyOutcome => $v->verify($t, $secret, 'login', self::OTHER_IP, operationIdentity: self::IDENTITY_A, bindingExpectation: RequestBindingExpectation::exact('txn-123')),
                VerifyError::WrongRegion,
                static fn (ArrayStorage $s): Verifier => new Verifier($s, now: $clock, region: 'eu'),
            ],
            'ip mismatch + wrong policy epoch' => [
                static fn (Verifier $v, string $t): VerifyOutcome => $v->verify($t, $secret, 'login', self::OTHER_IP, operationIdentity: self::IDENTITY_A, bindingExpectation: RequestBindingExpectation::exact('txn-123')),
                VerifyError::WrongPolicyVersion,
                static fn (ArrayStorage $s): Verifier => new Verifier($s, now: $clock, expectedPolicyVersion: 2),
            ],
            'ip mismatch + wrong issuer' => [
                static fn (Verifier $v, string $t): VerifyOutcome => $v->verify($t, $secret, 'login', self::OTHER_IP, operationIdentity: self::IDENTITY_A, bindingExpectation: RequestBindingExpectation::exact('txn-123')),
                VerifyError::WrongIssuer,
                static fn (ArrayStorage $s): Verifier => new Verifier($s, now: $clock, expectedIssuer: 'prod'),
            ],
            // missing client IP (checked before region/policy/issuer)
            'missing client ip + wrong region' => [
                static fn (Verifier $v, string $t): VerifyOutcome => $v->verify($t, $secret, 'login', null, operationIdentity: self::IDENTITY_A, bindingExpectation: RequestBindingExpectation::exact('txn-123')),
                VerifyError::WrongRegion,
                static fn (ArrayStorage $s): Verifier => new Verifier($s, now: $clock, region: 'eu'),
            ],
            'missing client ip + wrong policy epoch' => [
                static fn (Verifier $v, string $t): VerifyOutcome => $v->verify($t, $secret, 'login', null, operationIdentity: self::IDENTITY_A, bindingExpectation: RequestBindingExpectation::exact('txn-123')),
                VerifyError::WrongPolicyVersion,
                static fn (ArrayStorage $s): Verifier => new Verifier($s, now: $clock, expectedPolicyVersion: 2),
            ],
            'missing client ip + wrong issuer' => [
                static fn (Verifier $v, string $t): VerifyOutcome => $v->verify($t, $secret, 'login', null, operationIdentity: self::IDENTITY_A, bindingExpectation: RequestBindingExpectation::exact('txn-123')),
                VerifyError::WrongIssuer,
                static fn (ArrayStorage $s): Verifier => new Verifier($s, now: $clock, expectedIssuer: 'prod'),
            ],
        ];
    }

    /** @dataProvider exemptMaskedHardProvider */
    public function testAnExemptCircumstanceNeverMasksAHardVerdictOnAConsumedReplay(\Closure $replayCall, VerifyError $expected, \Closure $replayVerifierFactory): void
    {
        [$storage, $record, $token] = $this->issueSolveAndConsume(requestBinding: 'txn-123');

        $replayVerifier = $replayVerifierFactory($storage);
        $outcome = $replayCall($replayVerifier, $token);

        $this->assertHardFailureWinsWithEvidenceIntact($storage, $record, $outcome, $expected);
    }

    /**
     * The ordering pins that already hold and must keep holding: when the
     * hard invariant sits earlier in the cheap-phase order than the exempt
     * circumstance, the hard verdict is the first error and wins outright.
     *
     * @param \Closure(Verifier, string): VerifyOutcome $replayCall
     * @param \Closure(ArrayStorage): Verifier $replayVerifierFactory
     */
    public static function hardPrecedesExemptProvider(): array
    {
        $secret = Vectors::SECRET;
        $clock = self::clock();

        return [
            'ip mismatch behind wrong scope' => [
                static fn (Verifier $v, string $t): VerifyOutcome => $v->verify($t, $secret, 'signup', self::OTHER_IP, operationIdentity: self::IDENTITY_A, bindingExpectation: RequestBindingExpectation::exact('txn-123')),
                VerifyError::WrongScope,
                static fn (ArrayStorage $s): Verifier => new Verifier($s, now: $clock),
            ],
            'ip mismatch behind request binding mismatch' => [
                static fn (Verifier $v, string $t): VerifyOutcome => $v->verify($t, $secret, 'login', self::OTHER_IP, operationIdentity: self::IDENTITY_A, expectedRequestBinding: 'txn-OTHER'),
                VerifyError::RequestBindingMismatch,
                static fn (ArrayStorage $s): Verifier => new Verifier($s, now: $clock),
            ],
            'missing client ip behind wrong scope' => [
                static fn (Verifier $v, string $t): VerifyOutcome => $v->verify($t, $secret, 'signup', null, operationIdentity: self::IDENTITY_A, bindingExpectation: RequestBindingExpectation::exact('txn-123')),
                VerifyError::WrongScope,
                static fn (ArrayStorage $s): Verifier => new Verifier($s, now: $clock),
            ],
            'missing client ip behind request binding mismatch' => [
                static fn (Verifier $v, string $t): VerifyOutcome => $v->verify($t, $secret, 'login', null, operationIdentity: self::IDENTITY_A, expectedRequestBinding: 'txn-OTHER'),
                VerifyError::RequestBindingMismatch,
                static fn (ArrayStorage $s): Verifier => new Verifier($s, now: $clock),
            ],
            'telemetry gate behind wrong scope' => [
                static fn (Verifier $v, string $t): VerifyOutcome => $v->verify($t, $secret, 'signup', self::IP, enforceTelemetry: true, operationIdentity: self::IDENTITY_A, bindingExpectation: RequestBindingExpectation::exact('txn-123')),
                VerifyError::WrongScope,
                static fn (ArrayStorage $s): Verifier => new Verifier($s, now: $clock),
            ],
            'telemetry gate behind request binding mismatch' => [
                static fn (Verifier $v, string $t): VerifyOutcome => $v->verify($t, $secret, 'login', self::IP, enforceTelemetry: true, operationIdentity: self::IDENTITY_A, expectedRequestBinding: 'txn-OTHER'),
                VerifyError::RequestBindingMismatch,
                static fn (ArrayStorage $s): Verifier => new Verifier($s, now: $clock),
            ],
            'telemetry gate behind wrong region' => [
                static fn (Verifier $v, string $t): VerifyOutcome => $v->verify($t, $secret, 'login', self::IP, enforceTelemetry: true, operationIdentity: self::IDENTITY_A, bindingExpectation: RequestBindingExpectation::exact('txn-123')),
                VerifyError::WrongRegion,
                static fn (ArrayStorage $s): Verifier => new Verifier($s, now: $clock, region: 'eu'),
            ],
            'telemetry gate behind wrong policy epoch' => [
                static fn (Verifier $v, string $t): VerifyOutcome => $v->verify($t, $secret, 'login', self::IP, enforceTelemetry: true, operationIdentity: self::IDENTITY_A, bindingExpectation: RequestBindingExpectation::exact('txn-123')),
                VerifyError::WrongPolicyVersion,
                static fn (ArrayStorage $s): Verifier => new Verifier($s, now: $clock, expectedPolicyVersion: 2),
            ],
            'telemetry gate behind wrong issuer' => [
                static fn (Verifier $v, string $t): VerifyOutcome => $v->verify($t, $secret, 'login', self::IP, enforceTelemetry: true, operationIdentity: self::IDENTITY_A, bindingExpectation: RequestBindingExpectation::exact('txn-123')),
                VerifyError::WrongIssuer,
                static fn (ArrayStorage $s): Verifier => new Verifier($s, now: $clock, expectedIssuer: 'prod'),
            ],
        ];
    }

    /** @dataProvider hardPrecedesExemptProvider */
    public function testHardVerdictsEarlierInTheOrderKeepWinningOutright(\Closure $replayCall, VerifyError $expected, \Closure $replayVerifierFactory): void
    {
        [$storage, $record, $token] = $this->issueSolveAndConsume(requestBinding: 'txn-123');

        $replayVerifier = $replayVerifierFactory($storage);
        $outcome = $replayCall($replayVerifier, $token);

        $this->assertHardFailureWinsWithEvidenceIntact($storage, $record, $outcome, $expected);
    }

    // ── the balance: an exempt circumstance alone still replays ───────

    /**
     * @return array<string, array{0: \Closure(Verifier, string): VerifyOutcome, 1: \Closure(ArrayStorage): Verifier}>
     */
    public static function exemptAloneProvider(): array
    {
        $secret = Vectors::SECRET;
        $clock = self::clock();
        $expired = self::expiredClock();

        return [
            'expired alone' => [
                static fn (Verifier $v, string $t): VerifyOutcome => $v->verify($t, $secret, 'login', self::IP, operationIdentity: self::IDENTITY_A, bindingExpectation: RequestBindingExpectation::exact('txn-123')),
                static fn (ArrayStorage $s): Verifier => new Verifier($s, now: $expired),
            ],
            'ip mismatch alone' => [
                static fn (Verifier $v, string $t): VerifyOutcome => $v->verify($t, $secret, 'login', self::OTHER_IP, operationIdentity: self::IDENTITY_A, bindingExpectation: RequestBindingExpectation::exact('txn-123')),
                static fn (ArrayStorage $s): Verifier => new Verifier($s, now: $clock),
            ],
            'missing client ip alone' => [
                static fn (Verifier $v, string $t): VerifyOutcome => $v->verify($t, $secret, 'login', null, operationIdentity: self::IDENTITY_A, bindingExpectation: RequestBindingExpectation::exact('txn-123')),
                static fn (ArrayStorage $s): Verifier => new Verifier($s, now: $clock),
            ],
            'telemetry gate alone' => [
                static fn (Verifier $v, string $t): VerifyOutcome => $v->verify($t, $secret, 'login', self::IP, enforceTelemetry: true, operationIdentity: self::IDENTITY_A, bindingExpectation: RequestBindingExpectation::exact('txn-123')),
                static fn (ArrayStorage $s): Verifier => new Verifier($s, now: $clock),
            ],
        ];
    }

    /** @dataProvider exemptAloneProvider */
    public function testAnExemptCircumstanceAloneStillReplaysTheStoredSuccess(\Closure $replayCall, \Closure $replayVerifierFactory): void
    {
        [$storage, $record, $token] = $this->issueSolveAndConsume(requestBinding: 'txn-123');

        $replayVerifier = $replayVerifierFactory($storage);
        $replay = $replayCall($replayVerifier, $token);

        self::assertTrue($replay->isOk(), sprintf('the legit idempotent retry must still replay the stored success, got %s', $replay->code()));
        self::assertTrue($replay->fromStoredResult, 'the replay comes from the stored result, never a second derivation');
        self::assertNotNull($storage->find($record->nonce), 'the consumed evidence is retained');
        $state = $storage->consumedState($record->nonce);
        self::assertNotNull($state);
        self::assertTrue($state->consumedResult?->valid ?? false, 'the committed result is intact');
        self::assertSame(self::IDENTITY_A, $state->operationIdentity, 'the recorded identity is intact');
    }

    // ── the fresh-challenge precedence is unchanged ─────────────────────

    /**
     * A fresh (pending) challenge keeps the documented first-error
     * ordering. An expired token still reports Expired even when a hard
     * invariant would also fail: the replay-security re-evaluation only
     * exists on the consumed branch and must never leak into the fresh
     * path's public precedence.
     *
     * @param \Closure(Verifier, string): VerifyOutcome $call
     * @param \Closure(ArrayStorage): Verifier $verifierFactory
     */
    public static function freshPrecedenceProvider(): array
    {
        $secret = Vectors::SECRET;
        $expired = self::expiredClock();

        return [
            'expired precedes wrong scope' => [
                static fn (Verifier $v, string $t): VerifyOutcome => $v->verify($t, $secret, 'signup', self::IP),
                VerifyError::Expired,
                static fn (ArrayStorage $s): Verifier => new Verifier($s, now: $expired),
            ],
            'expired precedes request binding mismatch' => [
                static fn (Verifier $v, string $t): VerifyOutcome => $v->verify($t, $secret, 'login', self::IP, expectedRequestBinding: 'txn-OTHER'),
                VerifyError::Expired,
                static fn (ArrayStorage $s): Verifier => new Verifier($s, now: $expired),
            ],
            'expired precedes wrong region' => [
                static fn (Verifier $v, string $t): VerifyOutcome => $v->verify($t, $secret, 'login', self::IP),
                VerifyError::Expired,
                static fn (ArrayStorage $s): Verifier => new Verifier($s, now: $expired, region: 'eu'),
            ],
            'expired precedes wrong policy epoch' => [
                static fn (Verifier $v, string $t): VerifyOutcome => $v->verify($t, $secret, 'login', self::IP),
                VerifyError::Expired,
                static fn (ArrayStorage $s): Verifier => new Verifier($s, now: $expired, expectedPolicyVersion: 2),
            ],
            'expired precedes wrong issuer' => [
                static fn (Verifier $v, string $t): VerifyOutcome => $v->verify($t, $secret, 'login', self::IP),
                VerifyError::Expired,
                static fn (ArrayStorage $s): Verifier => new Verifier($s, now: $expired, expectedIssuer: 'prod'),
            ],
        ];
    }

    /** @dataProvider freshPrecedenceProvider */
    public function testFreshChallengesKeepTheFirstErrorPrecedence(\Closure $call, VerifyError $expected, \Closure $verifierFactory): void
    {
        $storage = new ArrayStorage();
        $issuer = new Issuer(
            new Config(secretKey: Vectors::SECRET, targetBits: 8, ttlSecs: 120, minDurationMs: 0),
            $storage,
            now: static fn (): int => self::ISSUED_AT,
        );
        $challenge = $issuer->issue('login', self::IP, 'txn-123');
        $record = $storage->find($challenge->nonce);
        self::assertNotNull($record);

        $token = self::solveToken($challenge->prefix, $challenge->salt, $challenge->nonce, $challenge->targetBits);

        $verifier = $verifierFactory($storage);
        $outcome = $call($verifier, $token);

        self::assertSame($expected, $outcome->error, sprintf('the fresh path keeps the first-error precedence, got %s', $outcome->code()));
        self::assertNull($storage->find($record->nonce), 'the pending record keeps the one-shot cheap-failure delete');
    }
}
