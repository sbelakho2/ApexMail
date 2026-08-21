<?php

declare(strict_types=1);

namespace KiwiCaptcha\Tests;

use KiwiCaptcha\ChallengeRecord;
use KiwiCaptcha\Config;
use KiwiCaptcha\Issuer;
use KiwiCaptcha\SolutionToken;
use KiwiCaptcha\Storage\ArrayStorage;
use KiwiCaptcha\StorageInterface;
use KiwiCaptcha\Verifier;
use KiwiCaptcha\VerifyError;
use KiwiCaptcha\Tests\Fixtures\Vectors;
use PHPUnit\Framework\TestCase;

/**
 * The replay identity gate: a consumed record's stored success replays
 * only to the exact logical operation that consumed it. The caller
 * proves the operation by passing the same identity the pending-to-consumed
 * transition recorded. A null operation identity never receives a stored
 * success; a replay without an identity, or with a different operation's
 * identity, is AlreadyConsumed. A stored invalid outcome replays
 * deterministically to any caller. The expected-request-binding
 * enforcement rejects a record that is not bound to the caller's
 * application transaction. The retained consumed state (result plus
 * identity) survives every cheap-phase failure, such as an expired or
 * wrong-scope replay, to its retention TTL. The cheap-phase delete
 * applies only to a not-yet-consumed record.
 */
final class ReplayIdentityGateTest extends TestCase
{
    private const ISSUED_AT = 1_800_000_000;

    private const IDENTITY_A = 'op-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
    private const IDENTITY_B = 'op-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';

    /** The pinned issuance-second clock every verifier in this suite uses. */
    private static function clock(): \Closure
    {
        return static fn (): int => self::ISSUED_AT;
    }

    /** @return array{0: ArrayStorage, 1: ChallengeRecord, 2: string} */
    private function issueAndSolve(int $targetBits = 8, ?string $requestBinding = null): array
    {
        $storage = new ArrayStorage();
        $issuer = new Issuer(
            new Config(secretKey: Vectors::SECRET, targetBits: $targetBits, ttlSecs: 120, minDurationMs: 0),
            $storage,
            now: static fn (): int => self::ISSUED_AT,
        );
        $challenge = $issuer->issue('login', '198.51.100.7', $requestBinding);
        $record = $storage->find($challenge->nonce);
        self::assertNotNull($record);

        $saltBytes = base64_decode($challenge->salt, true);
        $counter = 0;
        do {
            $hash = hash('sha256', $challenge->prefix.$counter.$saltBytes, true);
            $counter++;
        } while (Verifier::leadingZeroBits($hash) < $challenge->targetBits);
        --$counter;

        return [$storage, $record, SolutionToken::create($challenge->nonce, $counter, 5000, [])->encode()];
    }

    // ── the identity gate on the stored-success replay ─────────────────

    public function testIdentityMatchingRetryReplaysTheStoredSuccess(): void
    {
        [$storage, $record, $token] = $this->issueAndSolve();
        $verifier = new Verifier($storage, now: static fn (): int => self::ISSUED_AT);

        $first = $verifier->verify($token, Vectors::SECRET, 'login', '198.51.100.7', operationIdentity: self::IDENTITY_A);
        self::assertTrue($first->isOk(), sprintf('T + identity A must verify fresh, got %s', $first->code()));
        self::assertFalse($first->fromStoredResult, 'the first verification is a fresh derivation');

        // The exact same logical operation retries: the committed stored
        // success replays without re-deriving.
        $retry = $verifier->verify($token, Vectors::SECRET, 'login', '198.51.100.7', operationIdentity: self::IDENTITY_A);
        self::assertTrue($retry->isOk(), sprintf('T + A exact retry must replay the stored success, got %s', $retry->code()));
        self::assertTrue($retry->fromStoredResult, 'the retry comes from the stored result, never a second derivation');
        self::assertSame($record->nonce, $retry->nonce());
    }

    public function testDifferentIdentityRetryIsAlreadyConsumed(): void
    {
        [$storage, $record, $token] = $this->issueAndSolve();
        $verifier = new Verifier($storage, now: static fn (): int => self::ISSUED_AT);

        $first = $verifier->verify($token, Vectors::SECRET, 'login', '198.51.100.7', operationIdentity: self::IDENTITY_A);
        self::assertTrue($first->isOk());

        // T + b: a different logical operation presenting the same token
        // must never receive the stored success — one solve, one grant.
        $other = $verifier->verify($token, Vectors::SECRET, 'login', '198.51.100.7', operationIdentity: self::IDENTITY_B);
        self::assertSame(VerifyError::AlreadyConsumed, $other->error, 'a different operation is AlreadyConsumed, never Valid');
        self::assertNotNull($storage->find($record->nonce), 'the consumed evidence is retained');
    }

    public function testNullIdentityReplayIsAlreadyConsumed(): void
    {
        [$storage, $record, $token] = $this->issueAndSolve();
        $verifier = new Verifier($storage, now: static fn (): int => self::ISSUED_AT);

        $first = $verifier->verify($token, Vectors::SECRET, 'login', '198.51.100.7', operationIdentity: self::IDENTITY_A);
        self::assertTrue($first->isOk());

        $replay = $verifier->verify($token, Vectors::SECRET, 'login', '198.51.100.7');
        self::assertSame(VerifyError::AlreadyConsumed, $replay->error, 'a null identity never receives a stored success');
    }

    public function testNullIdentityFirstVerificationIsFreshValidAndItsReplayIsAlreadyConsumed(): void
    {
        [$storage, $record, $token] = $this->issueAndSolve();
        $verifier = new Verifier($storage, now: static fn (): int => self::ISSUED_AT);

        // T + null first: a fresh verification on the pending record is
        // Valid, exactly the plain-consume path.
        $first = $verifier->verify($token, Vectors::SECRET, 'login', '198.51.100.7');
        self::assertTrue($first->isOk(), sprintf('T + null first must verify fresh, got %s', $first->code()));
        self::assertFalse($first->fromStoredResult);

        // T + null second: the replay carries no identity, so it cannot
        // prove the logical operation that consumed the record.
        $second = $verifier->verify($token, Vectors::SECRET, 'login', '198.51.100.7');
        self::assertSame(VerifyError::AlreadyConsumed, $second->error, 'a null-identity replay is refused — a stored success requires the proven identity');
        self::assertNotNull($storage->find($record->nonce), 'the consumed evidence is retained');
    }

    public function testStoredInvalidOutcomeReplaysDeterministicallyToAnyCaller(): void
    {
        // Wrong proof first: the record is consumed and the deterministic
        // invalid outcome is committed. The same nonce later — with any
        // identity — replays the same InsufficientWork, never a Valid.
        [$storage, $record, $token] = $this->issueAndSolve();
        $wrongCounter = 1;
        $saltBytes = base64_decode($record->salt, true);
        while (Verifier::leadingZeroBits(hash('sha256', $record->prefix.$wrongCounter.$saltBytes, true)) >= $record->targetBits) {
            ++$wrongCounter;
        }
        $wrongToken = SolutionToken::create($record->nonce, $wrongCounter, 5000, [])->encode();

        $verifier = new Verifier($storage, now: static fn (): int => self::ISSUED_AT);
        $first = $verifier->verify($wrongToken, Vectors::SECRET, 'login', '198.51.100.7');
        self::assertSame(VerifyError::InsufficientWork, $first->error);

        foreach ([null, self::IDENTITY_A, self::IDENTITY_B] as $identity) {
            $replay = $verifier->verify($token, Vectors::SECRET, 'login', '198.51.100.7', operationIdentity: $identity);
            self::assertSame(VerifyError::InsufficientWork, $replay->error, 'the stored invalid outcome is deterministic for every caller');
        }
    }

    // ── the expected-request-binding enforcement ───────────────────────

    public function testMatchingExpectedRequestBindingVerifies(): void
    {
        [$storage, $record, $token] = $this->issueAndSolve(requestBinding: 'txn-123');
        $verifier = new Verifier($storage, now: static fn (): int => self::ISSUED_AT);

        $outcome = $verifier->verify($token, Vectors::SECRET, 'login', '198.51.100.7', expectedRequestBinding: 'txn-123');
        self::assertTrue($outcome->isOk(), sprintf('the matching binding must verify, got %s', $outcome->code()));
        self::assertSame('txn-123', $outcome->requestBinding, 'the binding is still returned in the outcome');
    }

    public function testMismatchedExpectedRequestBindingIsRejected(): void
    {
        // Record-bound mismatch: a challenge minted for one transaction
        // is never redeemable for another.
        [$storage, $record, $token] = $this->issueAndSolve(requestBinding: 'txn-123');
        $verifier = new Verifier($storage, now: static fn (): int => self::ISSUED_AT);

        $outcome = $verifier->verify($token, Vectors::SECRET, 'login', '198.51.100.7', expectedRequestBinding: 'txn-OTHER');
        self::assertSame(VerifyError::RequestBindingMismatch, $outcome->error, 'a record-bound mismatch is rejected before the consume');
        self::assertNull($storage->find($record->nonce), 'a PENDING record failing a cheap check is deleted per the one-shot policy');
    }

    public function testExpectedRequestBindingWithAnUnboundRecordIsRejected(): void
    {
        // No binding when one is expected: the caller demanded a bound
        // transaction and this challenge is not bound to any.
        [$storage, $record, $token] = $this->issueAndSolve();
        $verifier = new Verifier($storage, now: static fn (): int => self::ISSUED_AT);

        $outcome = $verifier->verify($token, Vectors::SECRET, 'login', '198.51.100.7', expectedRequestBinding: 'txn-123');
        self::assertSame(VerifyError::RequestBindingMismatch, $outcome->error, 'a record without a binding when one is expected is a mismatch');
    }

    public function testNullExpectedRequestBindingLeavesTheBindingUnenforced(): void
    {
        [$storage, $record, $token] = $this->issueAndSolve(requestBinding: 'txn-123');
        $verifier = new Verifier($storage, now: static fn (): int => self::ISSUED_AT);

        $outcome = $verifier->verify($token, Vectors::SECRET, 'login', '198.51.100.7');
        self::assertTrue($outcome->isOk(), 'null expected binding keeps the current behavior');
        self::assertSame('txn-123', $outcome->requestBinding, 'the binding is returned in the outcome, never enforced');
    }

    // ── the consumed-evidence preservation on cheap-phase failures ─────

    public function testExpiredReplayWithMatchingIdentityReplaysTheStoredSuccessAndKeepsTheRecord(): void
    {
        [$storage, $record, $token] = $this->issueAndSolve();
        $now = self::ISSUED_AT;
        $verifier = new Verifier($storage, now: function () use (&$now): int {
            return $now;
        });

        $first = $verifier->verify($token, Vectors::SECRET, 'login', '198.51.100.7', operationIdentity: self::IDENTITY_A);
        self::assertTrue($first->isOk());

        // Advance past the signed expiry: the cheap phase now fails
        // Expired, but the retained consumed state is recovery evidence
        // — it must not be deleted, and the consumed branch decides.
        $now = self::ISSUED_AT + 121;

        $replay = $verifier->verify($token, Vectors::SECRET, 'login', '198.51.100.7', operationIdentity: self::IDENTITY_A);
        self::assertTrue($replay->isOk(), sprintf('the identity-proven replay resolves through the consumed branch — the committed success replays, got %s', $replay->code()));
        self::assertTrue($replay->fromStoredResult, 'the committed outcome is expiry-exempt');
        self::assertNotNull($storage->find($record->nonce), 'the consumed recovery evidence STILL EXISTS after the expired replay');
        $state = $storage->consumedState($record->nonce);
        self::assertNotNull($state);
        self::assertSame(self::IDENTITY_A, $state->operationIdentity, 'the retained operation identity survives');
        self::assertNotNull($state->consumedResult, 'the retained deterministic result survives');
    }

    public function testExpiredReplayWithNullIdentityIsAlreadyConsumedAndKeepsTheRecord(): void
    {
        [$storage, $record, $token] = $this->issueAndSolve();
        $now = self::ISSUED_AT;
        $verifier = new Verifier($storage, now: function () use (&$now): int {
            return $now;
        });

        $first = $verifier->verify($token, Vectors::SECRET, 'login', '198.51.100.7', operationIdentity: self::IDENTITY_A);
        self::assertTrue($first->isOk());

        $now = self::ISSUED_AT + 121;

        $replay = $verifier->verify($token, Vectors::SECRET, 'login', '198.51.100.7');
        self::assertSame(VerifyError::AlreadyConsumed, $replay->error, 'an expired replay without the proven identity is AlreadyConsumed');
        self::assertNotNull($storage->find($record->nonce), 'the consumed recovery evidence STILL EXISTS after the expired replay');
    }

    public function testWrongScopeReplayIsAHardFailureEvenWithTheMatchingIdentityAndKeepsTheRecord(): void
    {
        [$storage, $record, $token] = $this->issueAndSolve();
        $verifier = new Verifier($storage, now: static fn (): int => self::ISSUED_AT);

        $first = $verifier->verify($token, Vectors::SECRET, 'login', '198.51.100.7', operationIdentity: self::IDENTITY_A);
        self::assertTrue($first->isOk());

        // Wrong scope is a security verdict about this redemption, not a
        // timing artifact of the original one: the identity-gated replay
        // exemption never overrides it. The consumed evidence survives.
        $replay = $verifier->verify($token, Vectors::SECRET, 'signup', '198.51.100.7', operationIdentity: self::IDENTITY_A);
        self::assertSame(VerifyError::WrongScope, $replay->error, 'a wrong-scope replay fails WrongScope even with the matching identity');
        self::assertNotNull($storage->find($record->nonce), 'the consumed recovery evidence STILL EXISTS after the wrong-scope replay');
        $state = $storage->consumedState($record->nonce);
        self::assertNotNull($state);
        self::assertTrue($state->consumedResult?->valid ?? false, 'the committed result survives');
        self::assertSame(self::IDENTITY_A, $state->operationIdentity, 'the recorded identity survives');
    }

    public function testExpiredReplayOfAConsumedWithoutResultRecordIsIndeterminateAndKeepsTheRecord(): void
    {
        // Crash between consume and commit, then the signed expiry
        // passes: the retained consumed-without-result state is evidence
        // too — never deleted by the cheap failure; the consumed branch
        // reports ConsumeIndeterminate.
        [$storage, $record, $token] = $this->issueAndSolve();
        $storage->store($record);
        $consumed = $storage->consumeWithOperationIdentity($record->nonce, self::IDENTITY_A);
        self::assertTrue($consumed?->consumedNow);

        $now = self::ISSUED_AT + 121;
        $verifier = new Verifier($storage, now: static fn (): int => $now);
        $outcome = $verifier->verify($token, Vectors::SECRET, 'login', '198.51.100.7', operationIdentity: self::IDENTITY_A);

        self::assertSame(VerifyError::ConsumeIndeterminate, $outcome->error, 'consumed-without-result stays indeterminate');
        self::assertNotNull($storage->find($record->nonce), 'the consumed evidence STILL EXISTS after the expired replay');
        $state = $storage->consumedState($record->nonce);
        self::assertNotNull($state);
        self::assertSame(self::IDENTITY_A, $state->operationIdentity, 'the retained identity survives');
    }

    // ── the replay-exemption classification ─────────────────────────────

    public function testExactlyTheTimingFailuresAreReplayExempt(): void
    {
        // The exemption is the narrow set of failures that describe the
        // original redemption's circumstances rather than this request's
        // authorization: expiry, the IP binding and the missing client
        // IP (the retry's context), and the telemetry gate (client-side
        // evidence about the original solve). Everything else — scope,
        // binding, policy epoch, region, issuer, kid, signature, record
        // shape, protocol/profile support, and the receipt-timing floor —
        // is a security verdict that must stand even when the operation
        // identity matches a consumed record's committed success.
        $exempt = [
            VerifyError::Expired,
            VerifyError::IpMismatch,
            VerifyError::MissingClientIp,
            VerifyError::TelemetryRejected,
        ];
        foreach (VerifyError::cases() as $error) {
            $expected = \in_array($error, $exempt, true);
            self::assertSame(
                $expected,
                $error->isReplayExempt(),
                sprintf('%s must %s the replay exemption', $error->name, $expected ? 'carry' : 'lack'),
            );
        }
    }

    /**
     * The parallel security-failure replay matrix: every hard failure
     * wins on a matching-identity replay of a consumed record, and the
     * consumed evidence (committed result + recorded identity) survives
     * the refusal.
     *
     * @param Verifier $replayVerifier the second verifier whose
     *                                 expectations differ from the
     *                                 issuing ones
     */
    public static function hardSecurityFailureProvider(): array
    {
        $secret = Vectors::SECRET;
        $other = str_rot13($secret);

        return [
            'wrong scope' => [
                static fn (Verifier $v, string $t): \KiwiCaptcha\VerifyOutcome => $v->verify($t, $secret, 'signup', '198.51.100.7', operationIdentity: self::IDENTITY_A),
                VerifyError::WrongScope,
            ],
            'changed expected request binding' => [
                static fn (Verifier $v, string $t): \KiwiCaptcha\VerifyOutcome => $v->verify($t, $secret, 'login', '198.51.100.7', operationIdentity: self::IDENTITY_A, expectedRequestBinding: 'txn-OTHER'),
                VerifyError::RequestBindingMismatch,
            ],
            'wrong policy epoch' => [
                static fn (Verifier $v, string $t): \KiwiCaptcha\VerifyOutcome => $v->verify($t, $secret, 'login', '198.51.100.7', operationIdentity: self::IDENTITY_A),
                VerifyError::WrongPolicyVersion,
                static fn (StorageInterface $s): Verifier => new Verifier($s, now: self::clock(), expectedPolicyVersion: 2),
            ],
            'wrong region' => [
                static fn (Verifier $v, string $t): \KiwiCaptcha\VerifyOutcome => $v->verify($t, $secret, 'login', '198.51.100.7', operationIdentity: self::IDENTITY_A),
                VerifyError::WrongRegion,
                static fn (StorageInterface $s): Verifier => new Verifier($s, now: self::clock(), region: 'eu'),
            ],
            'wrong issuer' => [
                static fn (Verifier $v, string $t): \KiwiCaptcha\VerifyOutcome => $v->verify($t, $secret, 'login', '198.51.100.7', operationIdentity: self::IDENTITY_A),
                VerifyError::WrongIssuer,
                static fn (StorageInterface $s): Verifier => new Verifier($s, now: self::clock(), expectedIssuer: 'prod'),
            ],
            'revoked kid' => [
                static fn (Verifier $v, string $t): \KiwiCaptcha\VerifyOutcome => $v->verify($t, $secret, 'login', '198.51.100.7', operationIdentity: self::IDENTITY_A),
                VerifyError::UnknownKid,
                static fn (StorageInterface $s): Verifier => new Verifier($s, now: self::clock(), revokedKids: [1]),
            ],
            'unknown kid (forward guard)' => [
                static fn (Verifier $v, string $t): \KiwiCaptcha\VerifyOutcome => $v->verify($t, $secret, 'login', '198.51.100.7', operationIdentity: self::IDENTITY_A),
                VerifyError::UnknownKid,
                static fn (StorageInterface $s): Verifier => new Verifier($s, now: self::clock(), secretsByKid: [2 => $other]),
            ],
            'bad signature (different secret)' => [
                static fn (Verifier $v, string $t): \KiwiCaptcha\VerifyOutcome => $v->verify($t, $other, 'login', '198.51.100.7', operationIdentity: self::IDENTITY_A),
                VerifyError::BadSignature,
            ],
        ];
    }

    /** @dataProvider hardSecurityFailureProvider */
    public function testHardSecurityFailuresWinOnAMatchingIdentityReplayAndKeepTheConsumedEvidence(\Closure $replayCall, VerifyError $expected, ?\Closure $replayVerifierFactory = null): void
    {
        [$storage, $record, $token] = $this->issueAndSolve(requestBinding: 'txn-123');
        $first = new Verifier($storage, now: static fn (): int => self::ISSUED_AT);
        self::assertTrue($first->verify($token, Vectors::SECRET, 'login', '198.51.100.7', operationIdentity: self::IDENTITY_A)->isOk());
        self::assertNotNull($storage->consumedState($record->nonce)?->consumedResult, 'the setup committed the valid result');

        $replayVerifier = $replayVerifierFactory !== null
            ? $replayVerifierFactory($storage)
            : new Verifier($storage, now: self::clock());
        $outcome = $replayCall($replayVerifier, $token);

        self::assertSame($expected, $outcome->error, sprintf('the security failure wins over the matching-identity replay, got %s', $outcome->code()));
        self::assertNotNull($storage->find($record->nonce), 'the consumed record is NEVER deleted by a hard security failure');
        $state = $storage->consumedState($record->nonce);
        self::assertNotNull($state);
        self::assertTrue($state->consumedResult?->valid ?? false, 'the committed valid result survives');
        self::assertSame(self::IDENTITY_A, $state->operationIdentity, 'the recorded operation identity survives');
    }

    public function testPendingRecordsKeepTheOneShotDeleteForHardSecurityFailures(): void
    {
        // The hard-failure win applies to consumed records (evidence
        // preserved); a pending record failing a hard security check
        // keeps the ordinary one-shot delete.
        [$storage, $record, $token] = $this->issueAndSolve();

        $verifier = new Verifier($storage, now: static fn (): int => self::ISSUED_AT);
        $outcome = $verifier->verify($token, Vectors::SECRET, 'signup', '198.51.100.7', operationIdentity: self::IDENTITY_A);

        self::assertSame(VerifyError::WrongScope, $outcome->error);
        self::assertNull($storage->find($record->nonce), 'a PENDING record failing a hard security check is deleted (one-shot)');
    }

    // ── the exempt set: the timing failures still route to the replay ───

    public function testIpMismatchReplayWithMatchingIdentityReplaysTheStoredSuccessAndKeepsTheRecord(): void
    {
        [$storage, $record, $token] = $this->issueAndSolve();
        $verifier = new Verifier($storage, now: static fn (): int => self::ISSUED_AT);

        self::assertTrue($verifier->verify($token, Vectors::SECRET, 'login', '198.51.100.7', operationIdentity: self::IDENTITY_A)->isOk());

        // The IP binding describes the original redemption's network
        // context; a legitimate retry may arrive from another address,
        // so the identity-proven replay carries (the expiry twin of this
        // test is above).
        $replay = $verifier->verify($token, Vectors::SECRET, 'login', '203.0.113.9', operationIdentity: self::IDENTITY_A);
        self::assertTrue($replay->isOk(), sprintf('the identity-proven IP-changed replay resolves through the consumed branch, got %s', $replay->code()));
        self::assertTrue($replay->fromStoredResult);
        self::assertNotNull($storage->find($record->nonce));
    }

    public function testMissingClientIpReplayWithMatchingIdentityReplaysTheStoredSuccess(): void
    {
        [$storage, $record, $token] = $this->issueAndSolve();
        $verifier = new Verifier($storage, now: static fn (): int => self::ISSUED_AT);

        self::assertTrue($verifier->verify($token, Vectors::SECRET, 'login', '198.51.100.7', operationIdentity: self::IDENTITY_A)->isOk());

        // A bound record without a client IP is the retryable context
        // gap (the record is kept even on the pending path); on the
        // consumed record the identity-proven replay resolves.
        $replay = $verifier->verify($token, Vectors::SECRET, 'login', null, operationIdentity: self::IDENTITY_A);
        self::assertTrue($replay->isOk(), sprintf('the identity-proven missing-IP replay resolves through the consumed branch, got %s', $replay->code()));
        self::assertTrue($replay->fromStoredResult);
        self::assertNotNull($storage->find($record->nonce));
    }

    public function testTelemetryRejectedReplayWithMatchingIdentityReplaysTheStoredSuccess(): void
    {
        [$storage, $record, $token] = $this->issueAndSolve();
        $verifier = new Verifier($storage, now: static fn (): int => self::ISSUED_AT);

        self::assertTrue($verifier->verify($token, Vectors::SECRET, 'login', '198.51.100.7', operationIdentity: self::IDENTITY_A)->isOk());

        // Telemetry is client-side evidence about the original solve:
        // the replay never re-scores it (empty payload here), and the
        // identity-proven replay resolves through the consumed branch.
        $replay = $verifier->verify($token, Vectors::SECRET, 'login', '198.51.100.7', enforceTelemetry: true, operationIdentity: self::IDENTITY_A);
        self::assertTrue($replay->isOk(), sprintf('the identity-proven telemetry-gate replay resolves through the consumed branch, got %s', $replay->code()));
        self::assertTrue($replay->fromStoredResult);
        self::assertNotNull($storage->find($record->nonce));
    }

    // ── cheap-failure evidence preservation (the Rust core's parity) ────

    /**
     * @return array{0: \KiwiCaptcha\StorageInterface, 1: ChallengeRecord, 2: string}
     *        the storage the record lives in, the record, the solved token
     */
    private function issueAndSolveInto(\KiwiCaptcha\StorageInterface $storage): array
    {
        $issuer = new Issuer(
            new Config(secretKey: Vectors::SECRET, targetBits: 8, ttlSecs: 120, minDurationMs: 0),
            $storage,
            now: static fn (): int => self::ISSUED_AT,
        );
        $challenge = $issuer->issue('login', '198.51.100.7');
        $record = $storage->find($challenge->nonce);
        self::assertNotNull($record);

        $saltBytes = base64_decode($challenge->salt, true);
        $counter = 0;
        do {
            $hash = hash('sha256', $challenge->prefix.$counter.$saltBytes, true);
            $counter++;
        } while (Verifier::leadingZeroBits($hash) < $challenge->targetBits);
        --$counter;

        return [$storage, $record, SolutionToken::create($challenge->nonce, $counter, 5000, [])->encode()];
    }

    public function testPendingExpiredReplayDeletesTheRecord(): void
    {
        // One-shot policy: a pending record failing a cheap check is
        // deleted (the failed challenge is burned), exactly the Rust
        // core's pending/missing branch.
        [$storage, $record, $token] = $this->issueAndSolve();

        $verifier = new Verifier($storage, now: static fn (): int => self::ISSUED_AT + 121);
        $outcome = $verifier->verify($token, Vectors::SECRET, 'login', '198.51.100.7');

        self::assertSame(VerifyError::Expired, $outcome->error, 'a pending expired submission is Expired');
        self::assertNull($storage->find($record->nonce), 'a PENDING record failing a cheap check is deleted (one-shot)');
    }

    public function testUnreadableConsumedStateOnACheapFailureIsStorageUnavailableAndNeverDeletes(): void
    {
        // The retained-state read fails while the record is intact and
        // (unknown to the verifier) already consumed with a committed
        // valid result: the consumed marker cannot be established, so the
        // record may be evidence — it is never deleted, and the caller
        // gets the retryable StorageUnavailable instead of a possibly
        // wrong cheap verdict. Mirrors the Rust core's fail-closed
        // evidence preservation on the retained-state read failure.
        $storage = new Fixtures\FlakyConsumedStateStorage();
        [$storage, $record, $token] = $this->issueAndSolveInto($storage);

        // The original verification consumes + commits the valid result.
        $verifier = new Verifier($storage, now: static fn (): int => self::ISSUED_AT);
        self::assertTrue($verifier->verify($token, Vectors::SECRET, 'login', '198.51.100.7', operationIdentity: self::IDENTITY_A)->isOk());
        self::assertNotNull($storage->consumedState($record->nonce)?->consumedResult);

        // The retained-state read now fails; the expired replay's cheap
        // phase would fail Expired, but the unreadable marker gates it.
        $storage->throwOnConsumedState = true;
        $late = new Verifier($storage, now: static fn (): int => self::ISSUED_AT + 121);
        $outcome = $late->verify($token, Vectors::SECRET, 'login', '198.51.100.7', operationIdentity: self::IDENTITY_A);

        self::assertSame(VerifyError::StorageUnavailable, $outcome->error, 'an unreadable consumed state is the retryable StorageUnavailable, never the cheap verdict');
        self::assertNotSame(VerifyError::Expired, $outcome->error);
        self::assertNotNull($storage->find($record->nonce), 'the possibly-consumed record is NEVER deleted on an unreadable retained state');

        // The read recovers: the evidence resolves through the consumed
        // branch exactly as before (the identity-gated replay).
        $storage->throwOnConsumedState = false;
        $recovered = $late->verify($token, Vectors::SECRET, 'login', '198.51.100.7', operationIdentity: self::IDENTITY_A);
        self::assertTrue($recovered->isOk() && $recovered->fromStoredResult, 'after the read recovers the identity-proven stored success replays');
        self::assertNotNull($storage->find($record->nonce));
    }

    public function testUnreadableConsumedStateOnTheTelemetryGateIsStorageUnavailableAndNeverDeletes(): void
    {
        // Same fail-closed rule on the telemetry cheap gate: the consumed
        // marker cannot be established, so the record survives and the
        // outcome is StorageUnavailable — never TelemetryRejected with a
        // deleted record.
        $storage = new Fixtures\FlakyConsumedStateStorage();
        [$storage, $record, $token] = $this->issueAndSolveInto($storage);

        $verifier = new Verifier($storage, now: static fn (): int => self::ISSUED_AT);
        self::assertTrue($verifier->verify($token, Vectors::SECRET, 'login', '198.51.100.7', enforceTelemetry: false, operationIdentity: self::IDENTITY_A)->isOk());

        $storage->throwOnConsumedState = true;
        $outcome = $verifier->verify($token, Vectors::SECRET, 'login', '198.51.100.7', enforceTelemetry: true, operationIdentity: self::IDENTITY_A);

        self::assertSame(VerifyError::StorageUnavailable, $outcome->error, 'the telemetry gate with an unreadable consumed state is StorageUnavailable');
        self::assertNotNull($storage->find($record->nonce), 'the possibly-consumed record is NEVER deleted');

        // The pending counterpart keeps the one-shot delete: a fresh
        // pending record failing the telemetry gate is burned.
        $storage2 = new Fixtures\FlakyConsumedStateStorage();
        [$storage2, $record2, $token2] = $this->issueAndSolveInto($storage2);
        $pending = new Verifier($storage2, now: static fn (): int => self::ISSUED_AT);
        $outcome2 = $pending->verify($token2, Vectors::SECRET, 'login', '198.51.100.7', enforceTelemetry: true);
        self::assertSame(VerifyError::TelemetryRejected, $outcome2->error);
        self::assertNull($storage2->find($record2->nonce), 'a PENDING record failing the telemetry gate is deleted (one-shot)');
    }

    public function testNonCapableStorageKeepsTheLegacyCheapFailureDelete(): void
    {
        // A storage without the consumed-state capability carries no
        // retained state to preserve: the legacy one-shot delete stays
        // for a consumed record failing a cheap check (documented
        // divergence from the capable backends; such storages cannot do
        // identity-gated replay anyway).
        $inner = new ArrayStorage();
        $storage = new class ($inner) implements \KiwiCaptcha\StorageInterface {
            public function __construct(private readonly ArrayStorage $inner)
            {
            }

            public function store(ChallengeRecord $record): void
            {
                $this->inner->store($record);
            }

            public function find(string $nonce): ?ChallengeRecord
            {
                return $this->inner->find($nonce);
            }

            public function consume(string $nonce): ?\KiwiCaptcha\ConsumedRecord
            {
                return $this->inner->consume($nonce);
            }

            public function commitResult(string $nonce, bool $valid, ?string $binding): bool
            {
                return $this->inner->commitResult($nonce, $valid, $binding);
            }

            public function delete(string $nonce): void
            {
                $this->inner->delete($nonce);
            }
        };
        [$storage, $record, $token] = $this->issueAndSolveInto($storage);

        $verifier = new Verifier($storage, now: static fn (): int => self::ISSUED_AT);
        self::assertTrue($verifier->verify($token, Vectors::SECRET, 'login', '198.51.100.7')->isOk());

        $late = new Verifier($storage, now: static fn (): int => self::ISSUED_AT + 121);
        $outcome = $late->verify($token, Vectors::SECRET, 'login', '198.51.100.7');
        self::assertSame(VerifyError::Expired, $outcome->error, 'a non-capable storage keeps the legacy cheap-failure verdict');
        self::assertNull($storage->find($record->nonce), 'a non-capable storage keeps the legacy one-shot delete (no retained state to preserve)');
    }
    // ── the atomic delete-if-pending wiring ─────────────────────────────

    public function testTheAtomicCleanupTransitionReplacesTheCheckThenDeletePair(): void
    {
        // A pending record failing a hard security check: the cleanup is
        // the one fused transition (deleteIfPending), never a separate
        // consumedState read + delete pair, and the record is gone.
        $storage = new Fixtures\AtomicCleanupStorage();
        [$storage, $record, $token] = $this->issueAndSolveInto($storage);

        $verifier = new Verifier($storage, now: self::clock());
        $outcome = $verifier->verify($token, Vectors::SECRET, 'signup', '198.51.100.7', operationIdentity: self::IDENTITY_A);

        self::assertSame(VerifyError::WrongScope, $outcome->error);
        self::assertSame(1, $storage->deleteIfPendingCalls, 'the cleanup went through the fused transition exactly once');
        self::assertSame(0, $storage->deleteCalls, 'no separate delete ran');
        self::assertSame(0, $storage->consumedStateCalls, 'no separate consumed-state read ran');
        self::assertNull($storage->find($record->nonce), 'the pending record is deleted');
    }

    public function testTheAtomicCleanupKeepsConsumedEvidenceForHardFailures(): void
    {
        $storage = new Fixtures\AtomicCleanupStorage();
        [$storage, $record, $token] = $this->issueAndSolveInto($storage);

        $verifier = new Verifier($storage, now: self::clock());
        self::assertTrue($verifier->verify($token, Vectors::SECRET, 'login', '198.51.100.7', operationIdentity: self::IDENTITY_A)->isOk());

        $outcome = $verifier->verify($token, Vectors::SECRET, 'signup', '198.51.100.7', operationIdentity: self::IDENTITY_A);
        self::assertSame(VerifyError::WrongScope, $outcome->error, 'the hard verdict stands on the matching-identity replay');
        self::assertSame(1, $storage->deleteIfPendingCalls);
        self::assertSame(0, $storage->deleteCalls, 'the fused transition never deletes a consumed record');
        $state = $storage->consumedState($record->nonce);
        self::assertNotNull($state);
        self::assertTrue($state->consumedResult?->valid ?? false, 'the committed evidence survives the cleanup');
    }

    public function testTheAtomicCleanupFallsThroughForExemptFailures(): void
    {
        $storage = new Fixtures\AtomicCleanupStorage();
        [$storage, $record, $token] = $this->issueAndSolveInto($storage);

        $verifier = new Verifier($storage, now: self::clock());
        self::assertTrue($verifier->verify($token, Vectors::SECRET, 'login', '198.51.100.7', operationIdentity: self::IDENTITY_A)->isOk());

        $replay = $verifier->verify($token, Vectors::SECRET, 'login', '203.0.113.9', operationIdentity: self::IDENTITY_A);
        self::assertTrue($replay->isOk() && $replay->fromStoredResult, 'the exempt IP-mismatch replay resolves through the consumed branch');
        self::assertSame(1, $storage->deleteIfPendingCalls);
        self::assertSame(0, $storage->deleteCalls);
        self::assertNotNull($storage->find($record->nonce));
    }

    public function testMissingClientIpOnAPendingRecordBypassesTheCleanupEntirely(): void
    {
        // The retryable context gap: a pending bound record without a
        // client IP is neither deleted nor cleaned up — the fused
        // transition must not run at all (it would delete the pending
        // record, closing the documented retry-with-IP path).
        $storage = new Fixtures\AtomicCleanupStorage();
        [$storage, $record, $token] = $this->issueAndSolveInto($storage);

        $verifier = new Verifier($storage, now: self::clock());
        $outcome = $verifier->verify($token, Vectors::SECRET, 'login', null, operationIdentity: self::IDENTITY_A);

        self::assertSame(VerifyError::MissingClientIp, $outcome->error);
        self::assertSame(0, $storage->deleteIfPendingCalls, 'the fused cleanup never runs for the missing-IP retry path');
        self::assertSame(0, $storage->deleteCalls);
        self::assertNotNull($storage->find($record->nonce), 'the pending record is kept for the retry with the IP');
    }
}
