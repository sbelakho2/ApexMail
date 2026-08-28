<?php

declare(strict_types=1);

namespace KiwiCaptcha\Tests;

use KiwiCaptcha\ChallengeRecord;
use KiwiCaptcha\RequestBindingExpectation;
use KiwiCaptcha\Config;
use KiwiCaptcha\ConsumedRecord;
use KiwiCaptcha\Issuer;
use KiwiCaptcha\PoWAlgorithm;
use KiwiCaptcha\SolutionToken;
use KiwiCaptcha\Storage\ArrayStorage;
use KiwiCaptcha\StorageInterface;
use KiwiCaptcha\AtomicStorageInterface;
use KiwiCaptcha\OperationIdentityAwareStorageInterface;
use KiwiCaptcha\VerificationAdmissionGate;
use KiwiCaptcha\Verifier;
use KiwiCaptcha\VerifyError;
use KiwiCaptcha\Tests\Fixtures\Vectors;
use PHPUnit\Framework\TestCase;

/**
 * Consumed-operation resume (resumeConsumedOperation): the narrowly
 * authorized crash-recovery path for the Siteverify takeover. The atomic
 * pending→consumed transition landed and recorded the logical-operation
 * identity, but the derivation/commit reply was lost; consumed_result
 * stays null forever for the ordinary verifier (ConsumeIndeterminate).
 * A caller that has proven the retained consumed record's exact
 * operation identity belongs to this logical operation may resume the
 * derivation, revalidate every immutable security property exactly like
 * the ordinary verify path, and commit the deterministic outcome. A
 * resultless resume re-checks the signed expiry against the current
 * clock before deriving and again after the derivation, before the
 * commit: the same acceptance boundary as ordinary verification. Past
 * the signed deadline it fails closed with Expired and commits nothing,
 * deterministically on every retry. Only the committed-result recovery
 * is expiry-exempt, since a committed result was durably recorded only
 * after the original final expiry check passed.
 */
final class VerifierResumeTest extends TestCase
{
    private const ISSUED_AT = 1_800_000_000;

    private const CLIENT_IP = '198.51.100.7';

    /** @return array{0: ArrayStorage, 1: ChallengeRecord, 2: string} */
    private function issueAndSolve(int $targetBits = 8, ?string $requestBinding = null): array
    {
        $storage = new ArrayStorage();
        $issuer = new Issuer(
            new Config(secretKey: Vectors::SECRET, targetBits: $targetBits, ttlSecs: 120, minDurationMs: 0),
            $storage,
            now: static fn (): int => self::ISSUED_AT,
        );
        $challenge = $issuer->issue('login', self::CLIENT_IP, $requestBinding);
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

    /** A token whose counter provably fails the record's target. */
    private function wrongCounterToken(ChallengeRecord $record): string
    {
        $saltBytes = base64_decode($record->salt, true);
        $wrong = 0;
        while (Verifier::leadingZeroBits(hash('sha256', $record->prefix.$wrong.$saltBytes, true)) >= $record->targetBits) {
            ++$wrong;
        }

        return SolutionToken::create($record->nonce, $wrong, 5000, [])->encode();
    }

    private function identity(string $suffix): string
    {
        return hash('sha256', 'logical-operation-'.$suffix);
    }

    /**
     * An Argon2id record issued under the given policy epoch / region /
     * issuer with the given TTL, already solved. The argon admission gate
     * is the only seam between the resume's pre-derive revalidation and
     * its commit, so the mid-derivation rotation and clock tests drive
     * it.
     *
     * @return array{0: ArrayStorage, 1: ChallengeRecord, 2: string}
     */
    private function issueAndSolveArgon(int $policyVersion = 1, ?string $region = null, ?string $issuer = null, int $ttlSecs = 120): array
    {
        $storage = new ArrayStorage();
        $issuer = new Issuer(
            new Config(
                secretKey: Vectors::SECRET,
                algorithm: PoWAlgorithm::Argon2id,
                mKib: 64,
                t: 3,
                p: 1,
                argon2TargetBits: 4,
                ttlSecs: $ttlSecs,
                minDurationMs: 0,
                policyVersion: $policyVersion,
                issuer: $issuer,
            ),
            $storage,
            now: static fn (): int => self::ISSUED_AT,
            region: $region,
        );
        $challenge = $issuer->issue('login', self::CLIENT_IP);
        $record = $storage->find($challenge->nonce);
        self::assertNotNull($record);

        $saltBytes = base64_decode($challenge->salt, true);
        $counter = 0;
        do {
            $hash = sodium_crypto_pwhash(32, $challenge->prefix.$counter, $saltBytes, 3, 64 * 1024, SODIUM_CRYPTO_PWHASH_ALG_ARGON2ID13);
            $counter++;
        } while (Verifier::leadingZeroBits($hash) < $challenge->targetBits);
        --$counter;

        return [$storage, $record, SolutionToken::create($challenge->nonce, $counter, 5000, [])->encode()];
    }

    /**
     * An admission gate that runs $onAcquire when the resume's Argon
     * admission happens, after the pre-derive revalidation and before
     * the commit: exactly the rotation window the post-derive re-check
     * must observe.
     */
    private function rotatingGate(\Closure $onAcquire): VerificationAdmissionGate
    {
        return new class($onAcquire) implements VerificationAdmissionGate {
            public function __construct(private readonly \Closure $onAcquire)
            {
            }

            public function acquire(): ?string
            {
                ($this->onAcquire)();

                return 'lease-rotate';
            }

            public function release(string $lease): void
            {
            }
        };
    }

    // ── The lost-reply storage seam ─────────────────────────────────────

    /**
     * A storage whose atomic consumeWithOperationIdentity() delegates:
     * the pending→consumed transition really executes and the identity
     * lands atomically with the state flip, and then it throws. This is
     * the lost-reply seam (the wire failure that produces
     * ConsumeIndeterminate even though the transition landed).
     * commitResult() can be armed the same way: the commit really lands
     * and the reply is then lost, exercising the resume's
     * read-after-failed-commit path.
     */
    private static function lostReplyStorage(ArrayStorage $inner, bool $consumeReplyLost, bool $commitReplyLost = false): AtomicStorageInterface
    {
        return new class($inner, $consumeReplyLost, $commitReplyLost) implements AtomicStorageInterface, OperationIdentityAwareStorageInterface {
            public function __construct(
                private readonly ArrayStorage $inner,
                private readonly bool $consumeReplyLost,
                private readonly bool $commitReplyLost,
            ) {
            }

            public function store(ChallengeRecord $record): void
            {
                $this->inner->store($record);
            }

            public function find(string $nonce): ?ChallengeRecord
            {
                return $this->inner->find($nonce);
            }

            public function consumedState(string $nonce): ?ConsumedRecord
            {
                return $this->inner->consumedState($nonce);
            }

            public function consume(string $nonce): ?ConsumedRecord
            {
                return $this->inner->consume($nonce);
            }

            public function consumeWithOperationIdentity(string $nonce, ?string $operationIdentity): ?ConsumedRecord
            {
                // The transition executes first: the identity lands
                // atomically with the state flip, and the reply is then
                // lost.
                $result = $this->inner->consumeWithOperationIdentity($nonce, $operationIdentity);
                if ($this->consumeReplyLost) {
                    throw new \RuntimeException('consume reply lost after the transition');
                }

                return $result;
            }

            public function commitResult(string $nonce, bool $valid, ?string $binding): bool
            {
                // The commit executes first: the deterministic result
                // lands, and the reply is then lost.
                $result = $this->inner->commitResult($nonce, $valid, $binding);
                if ($this->commitReplyLost) {
                    throw new \RuntimeException('commit reply lost after the commit');
                }

                return $result;
            }

            public function delete(string $nonce): void
            {
                $this->inner->delete($nonce);
            }
        };
    }

    // ── The resume contract ─────────────────────────────────────────────

    public function testValidShaResumeSucceedsAndCommits(): void
    {
        // The original attempt's consume reply is lost after the
        // transition landed (the identity is recorded atomically): the
        // record is consumed-without-result, so the ordinary verifier
        // says ConsumeIndeterminate forever. The identity-proven resume
        // derives and commits the deterministic outcome.
        [$inner, $record, $token] = $this->issueAndSolve();
        $storage = self::lostReplyStorage($inner, true);
        $verifier = new Verifier($storage, now: static fn (): int => self::ISSUED_AT);

        // The original attempt: the identity-bearing consume executes
        // (the transition lands, the identity is recorded atomically) and
        // the reply is lost; the verifier surfaces ConsumeIndeterminate.
        $original = $verifier->verify($token, Vectors::SECRET, 'login', self::CLIENT_IP, nowNs: $record->issuedAtNs + 1_000_000, operationIdentity: $this->identity('a'));
        self::assertSame(VerifyError::ConsumeIndeterminate, $original->error, 'the lost consume reply must surface as ConsumeIndeterminate');
        $consumed = $inner->consumedState($record->nonce);
        self::assertNotNull($consumed, 'the transition really executed');
        self::assertSame($this->identity('a'), $consumed->operationIdentity, 'the identity landed atomically with the transition');
        self::assertNull($consumed->consumedResult, 'the derivation never ran — consumed_result stays null');

        $outcome = $verifier->resumeConsumedOperation($token, Vectors::SECRET, $this->identity('a'), 'login', self::CLIENT_IP);
        self::assertTrue($outcome->isOk(), sprintf('the identity-proven resume must derive and commit the valid outcome, got %s', $outcome->code()));
        self::assertSame($record->nonce, $outcome->nonce());

        $after = $inner->consumedState($record->nonce);
        self::assertNotNull($after?->consumedResult, 'the resume must COMMIT the deterministic outcome');
        self::assertTrue($after->consumedResult->valid);

        // A second resume (e.g. a later same-key retry) returns the
        // committed outcome without re-deriving.
        $replay = $verifier->resumeConsumedOperation($token, Vectors::SECRET, $this->identity('a'), 'login', self::CLIENT_IP);
        self::assertTrue($replay->isOk());
        self::assertSame($record->nonce, $replay->nonce());
    }

    public function testInvalidShaResumeCommitsInsufficientWorkDeterministically(): void
    {
        [$inner, $record, $token] = $this->issueAndSolve();
        $storage = self::lostReplyStorage($inner, true);
        $verifier = new Verifier($storage);
        $wrongToken = $this->wrongCounterToken($record);
        self::assertNotSame($token, $wrongToken);

        $inner->consumeWithOperationIdentity($record->nonce, $this->identity('a'));

        $outcome = $verifier->resumeConsumedOperation($wrongToken, Vectors::SECRET, $this->identity('a'), 'login', self::CLIENT_IP);
        self::assertSame(VerifyError::InsufficientWork, $outcome->error, 'the resumed derivation must deterministically fail the wrong counter');

        $after = $inner->consumedState($record->nonce);
        self::assertNotNull($after?->consumedResult, 'the resume must COMMIT the invalid outcome too');
        self::assertFalse($after->consumedResult->valid);

        // Deterministic: a second resume returns the same stored failure
        // without re-deriving.
        $replay = $verifier->resumeConsumedOperation($wrongToken, Vectors::SECRET, $this->identity('a'), 'login', self::CLIENT_IP);
        self::assertSame(VerifyError::InsufficientWork, $replay->error, 'a retry must replay the committed invalid outcome');
    }

    public function testArgonResumeSucceeds(): void
    {
        $storage = new ArrayStorage();
        $issuer = new Issuer(new Config(
            secretKey: Vectors::SECRET,
            algorithm: PoWAlgorithm::Argon2id,
            mKib: 64,
            t: 3,
            p: 1,
            argon2TargetBits: 4,
            ttlSecs: 120,
            minDurationMs: 0,
        ), $storage, now: static fn (): int => self::ISSUED_AT);
        $challenge = $issuer->issue('login', self::CLIENT_IP);
        $record = $storage->find($challenge->nonce);
        self::assertNotNull($record);

        $saltBytes = base64_decode($challenge->salt, true);
        $counter = 0;
        do {
            $hash = sodium_crypto_pwhash(32, $challenge->prefix.$counter, $saltBytes, 3, 64 * 1024, SODIUM_CRYPTO_PWHASH_ALG_ARGON2ID13);
            $counter++;
        } while (Verifier::leadingZeroBits($hash) < $challenge->targetBits);
        --$counter;
        $token = SolutionToken::create($challenge->nonce, $counter, 5000, [])->encode();

        $lost = self::lostReplyStorage($storage, true);
        $verifier = new Verifier($lost);
        $storage->consumeWithOperationIdentity($record->nonce, $this->identity('argon'));
        self::assertNull($storage->consumedState($record->nonce)?->consumedResult);

        $outcome = $verifier->resumeConsumedOperation($token, Vectors::SECRET, $this->identity('argon'), 'login', self::CLIENT_IP);
        self::assertTrue($outcome->isOk(), sprintf('the Argon resume must derive and commit the valid outcome, got %s', $outcome->code()));
        $after = $storage->consumedState($record->nonce);
        self::assertNotNull($after?->consumedResult);
        self::assertTrue($after->consumedResult->valid);
    }

    public function testArgonResumeNeverBypassesAdmission(): void
    {
        // Argon admission applies to the resumed derivation: a saturated
        // gate rejects with CapacityExceeded without committing (a later
        // retry can resume once capacity is available), and a released
        // slot lets the resume through.
        $storage = new ArrayStorage();
        $issuer = new Issuer(new Config(
            secretKey: Vectors::SECRET,
            algorithm: PoWAlgorithm::Argon2id,
            mKib: 64,
            t: 3,
            p: 1,
            argon2TargetBits: 4,
            ttlSecs: 120,
            minDurationMs: 0,
        ), $storage, now: static fn (): int => self::ISSUED_AT);
        $challenge = $issuer->issue('login', self::CLIENT_IP);
        $record = $storage->find($challenge->nonce);
        self::assertNotNull($record);

        $saltBytes = base64_decode($challenge->salt, true);
        $counter = 0;
        do {
            $hash = sodium_crypto_pwhash(32, $challenge->prefix.$counter, $saltBytes, 3, 64 * 1024, SODIUM_CRYPTO_PWHASH_ALG_ARGON2ID13);
            $counter++;
        } while (Verifier::leadingZeroBits($hash) < $challenge->targetBits);
        --$counter;
        $token = SolutionToken::create($challenge->nonce, $counter, 5000, [])->encode();
        $storage->consumeWithOperationIdentity($record->nonce, $this->identity('gate'));

        // A gate with exactly ONE slot, saturated from the outside.
        $gate = new class() implements VerificationAdmissionGate {
            public ?string $held = null;

            public function acquire(): ?string
            {
                if ($this->held !== null) {
                    return null;
                }
                $this->held = 'lease-1';

                return $this->held;
            }

            public function release(string $lease): void
            {
                if ($this->held === $lease) {
                    $this->held = null;
                }
            }
        };
        $verifier = new Verifier($storage, $gate);

        self::assertIsString($gate->acquire(), 'saturate the single slot from the outside');
        $outcome = $verifier->resumeConsumedOperation($token, Vectors::SECRET, $this->identity('gate'), 'login', self::CLIENT_IP);
        self::assertSame(VerifyError::CapacityExceeded, $outcome->error, 'the resumed Argon derivation must respect the admission gate');
        self::assertNull($storage->consumedState($record->nonce)?->consumedResult, 'capacity exhaustion must NOT commit anything');

        $gate->release('lease-1');
        $outcome = $verifier->resumeConsumedOperation($token, Vectors::SECRET, $this->identity('gate'), 'login', self::CLIENT_IP);
        self::assertTrue($outcome->isOk(), sprintf('with capacity available the resume must derive and commit, got %s', $outcome->code()));
        self::assertNull($gate->held, 'the verifier must release its lease after the resumed derivation');
        self::assertNotNull($storage->consumedState($record->nonce)?->consumedResult);
    }

    public function testResultlessResumePastSignedExpiryIsDeterministicallyExpired(): void
    {
        // A resultless resume has no durable success marker: the
        // original attempt's derivation crossed the signed deadline and
        // verify() returned Expired without committing. Re-deriving after
        // expiry could turn that same logical redemption into a
        // post-deadline Valid, so the resume re-checks the signed expiry
        // before the derivation and fails closed: invalid(Expired),
        // nothing derived, nothing committed, deterministically on every
        // retry.
        [$inner, $record, $token] = $this->issueAndSolve();
        $storage = self::lostReplyStorage($inner, true);
        $farFuture = static fn (): int => self::ISSUED_AT + 10_000;
        $verifier = new Verifier($storage, now: $farFuture);
        $inner->consumeWithOperationIdentity($record->nonce, $this->identity('late'));

        // Control: a fresh pending record from the same issuer, verified
        // at the same far-future clock, is Expired; the clock really is
        // past the signed lifetime.
        $fresh = new ArrayStorage();
        $issuer = new Issuer(new Config(secretKey: Vectors::SECRET, targetBits: 8, ttlSecs: 120, minDurationMs: 0), $fresh, now: static fn (): int => self::ISSUED_AT);
        $freshChallenge = $issuer->issue('login', self::CLIENT_IP);
        $freshToken = $this->solveFresh($fresh, $freshChallenge);
        $control = (new Verifier($fresh, now: $farFuture))->verify($freshToken, Vectors::SECRET, 'login', self::CLIENT_IP);
        self::assertSame(VerifyError::Expired, $control->error, 'precondition: the clock is past the signed expiry');

        $outcome = $verifier->resumeConsumedOperation($token, Vectors::SECRET, $this->identity('late'), 'login', self::CLIENT_IP);
        self::assertSame(VerifyError::Expired, $outcome->error, 'a resultless resume past the signed expiry must fail closed with Expired');
        $after = $inner->consumedState($record->nonce);
        self::assertNull($after?->consumedResult, 'the expired resultless resume must NOT commit anything');

        // Deterministic: a second resume derives nothing and stays
        // Expired; the same logical redemption can never become Valid
        // after the signed deadline.
        $replay = $verifier->resumeConsumedOperation($token, Vectors::SECRET, $this->identity('late'), 'login', self::CLIENT_IP);
        self::assertSame(VerifyError::Expired, $replay->error, 'a second resume after the signed expiry must be Expired again');
        self::assertNull($inner->consumedState($record->nonce)?->consumedResult, 'nothing is ever committed for an expired resultless resume');
    }

    public function testResultlessResumeExpiringDuringDerivationIsDeterministicallyExpired(): void
    {
        // The recovery starts before the signed deadline but finishes
        // after it, a derivation longer than the remaining lifetime. The
        // pre-derive expiry gate passes (~1 second of lifetime left at
        // resume start), then the admission path advances the clock past
        // expiresAt during the expensive derivation (the same gate seam
        // the mid-derivation rotation tests drive). The post-derive
        // re-read must commit Expired, the same acceptance boundary as
        // the ordinary verifier, never a post-deadline Valid.
        [$storage, $record, $token] = $this->issueAndSolveArgon(ttlSecs: 1);
        $storage->consumeWithOperationIdentity($record->nonce, $this->identity('expire-mid-derive'));

        $clock = self::ISSUED_AT;
        $now = static function () use (&$clock): int {
            return $clock;
        };
        $gate = $this->rotatingGate(static function () use (&$clock): void {
            // The admission lands between the pre-derive expiry gate and
            // the post-derive re-read: the clock advances past the
            // record's signed expiry (issued_at + 1).
            $clock = self::ISSUED_AT + 10;
        });
        $verifier = new Verifier($storage, $gate, now: $now);

        $outcome = $verifier->resumeConsumedOperation($token, Vectors::SECRET, $this->identity('expire-mid-derive'), 'login', self::CLIENT_IP);
        self::assertSame(VerifyError::Expired, $outcome->error, 'a resultless resume whose derivation crosses the signed deadline must commit Expired');
        $after = $storage->consumedState($record->nonce);
        self::assertNull($after?->consumedResult, 'the mid-derivation expiry must NOT commit anything');

        // Deterministic: a second resume reproduces the identical
        // Expired (the clock is past the signed deadline now) — the same
        // logical redemption can never become Valid.
        $replay = $verifier->resumeConsumedOperation($token, Vectors::SECRET, $this->identity('expire-mid-derive'), 'login', self::CLIENT_IP);
        self::assertSame(VerifyError::Expired, $replay->error, 'a second resume must reproduce the identical Expired');
        self::assertNull($storage->consumedState($record->nonce)?->consumedResult, 'nothing is ever committed once the derivation crossed the signed deadline');
    }

    public function testResultlessResumeNearExpiryWithoutMidDeriveClockAdvanceStillCommitsValid(): void
    {
        // Control for the post-derive expiry re-read: the same setup
        // (signed expiry ~1 second in the future at resume start, gate
        // present) without the mid-derive clock advance commits Valid.
        // The clock advance inside the derivation is the only difference
        // between the Expired outcome above and this one.
        [$storage, $record, $token] = $this->issueAndSolveArgon(ttlSecs: 1);
        $storage->consumeWithOperationIdentity($record->nonce, $this->identity('near-expiry-valid'));

        $clock = self::ISSUED_AT;
        $now = static function () use (&$clock): int {
            return $clock;
        };
        $gate = $this->rotatingGate(static function (): void {
        });
        $verifier = new Verifier($storage, $gate, now: $now);

        $outcome = $verifier->resumeConsumedOperation($token, Vectors::SECRET, $this->identity('near-expiry-valid'), 'login', self::CLIENT_IP);
        self::assertTrue($outcome->isOk(), sprintf('without a mid-derive clock advance the near-expiry resume must commit Valid, got %s', $outcome->code()));
        $after = $storage->consumedState($record->nonce);
        self::assertNotNull($after?->consumedResult, 'the near-expiry resume must commit');
        self::assertTrue($after->consumedResult->valid);
    }

    public function testStoredResultReplayConfirmsTheReplicationBarrier(): void
    {
        // The failed-barrier replay hole: the consume/commit that produced
        // a stored success may have landed on the primary with its WAIT
        // failing. A later replay that accepts the stored success must
        // establish the replication fence first: a shortfall fails
        // closed (no unproven success), and a satisfied fence returns
        // the stored Valid.
        [$inner, $record, $token] = $this->issueAndSolve(requestBinding: 'txn-1');
        $inner->consumeWithOperationIdentity($record->nonce, $this->identity('barrier-replay'));
        self::assertTrue($inner->commitResult($record->nonce, true, 'txn-1'));

        // The barrier storage: a ReplicationBarrierInterface whose
        // confirmReplication is configurable.
        $barrier = new BarrierStorage($inner);
        $verifier = new Verifier($barrier, now: static fn (): int => self::ISSUED_AT);

        $barrier->confirmResult = false;
        try {
            $outcome = $verifier->verify($token, Vectors::SECRET, 'login', '198.51.100.7', operationIdentity: $this->identity('barrier-replay'), expectedRequestBinding: 'txn-1', bindingExpectation: RequestBindingExpectation::exact('txn-1'));
            self::fail('the stored-result replay must NOT return an unproven success');
        } catch (\RuntimeException $e) {
            self::assertSame('replication barrier shortfall', $e->getMessage());
        }

        // The barrier satisfied: the replay returns the stored Valid.
        $barrier->confirmResult = true;
        $outcome = $verifier->verify($token, Vectors::SECRET, 'login', '198.51.100.7', operationIdentity: $this->identity('barrier-replay'), expectedRequestBinding: 'txn-1', bindingExpectation: RequestBindingExpectation::exact('txn-1'));
        self::assertTrue($outcome->isOk());
        self::assertTrue($outcome->fromStoredResult, 'the replay is the stored Valid');

        // The same guard on resumeConsumedOperation's committed-result
        // fast path.
        $barrier->confirmResult = false;
        try {
            $verifier->resumeConsumedOperation($token, Vectors::SECRET, $this->identity('barrier-replay'), 'login', self::CLIENT_IP, 'txn-1', RequestBindingExpectation::exact('txn-1'));
            self::fail('the resumed committed-result must NOT return an unproven success');
        } catch (\RuntimeException $e) {
            self::assertSame('replication barrier shortfall', $e->getMessage());
        }
        $barrier->confirmResult = true;
        $resumed = $verifier->resumeConsumedOperation($token, Vectors::SECRET, $this->identity('barrier-replay'), 'login', self::CLIENT_IP, 'txn-1', RequestBindingExpectation::exact('txn-1'));
        self::assertTrue($resumed->isOk());
    }

    public function testResumeCommittedResultMatrixEnforcesTheExactExpectation(): void
    {
        // R68-02: the committed-result fast path must NOT bypass the exact
        // binding expectation — a stored success can never replay through
        // an old nullable interpretation. The full matrix against
        // resumeConsumedOperation() with a committed result:
        //   unbound / Exact(null) accept; bound A / Exact(A) accept;
        //   bound A / Exact(null) reject; unbound / Exact(A) reject;
        //   bound A / Exact(B) reject; any / Unenforced accept.
        $rows = [
            [null, null, true],
            ['txn-A', 'txn-A', true],
            ['txn-A', null, false],
            [null, 'txn-A', false],
            ['txn-A', 'txn-B', false],
            ['txn-A', 'txn-A', true, RequestBindingExpectation::unenforced()],
        ];
        foreach ($rows as $row) {
            [$recordBinding, $expected, $shouldPass] = $row;
            $expectation = $row[3] ?? RequestBindingExpectation::exact($expected);
            [$inner, $record, $token] = $this->issueAndSolve(requestBinding: $recordBinding);
            $identity = $this->identity('committed-'.($expected ?? 'null'));
            $inner->consumeWithOperationIdentity($record->nonce, $identity);
            self::assertTrue($inner->commitResult($record->nonce, true, $record->requestBinding), 'the committed result lands');
            $verifier = new Verifier($inner, now: static fn (): int => self::ISSUED_AT + 10_000);
            $outcome = $verifier->resumeConsumedOperation($token, Vectors::SECRET, $identity, 'login', self::CLIENT_IP, $expected, $expectation);
            self::assertSame($shouldPass, $outcome->isOk(), sprintf('resume matrix record=%s expected=%s pass=%s got=%s', var_export($recordBinding, true), var_export($expected, true), var_export($shouldPass, true), $outcome->code()));
        }
    }

    public function testResumeEnforcesTheExpectedRequestBindingBeforeDerivation(): void
    {
        // The resumed-operation path enforces the same pre-derivation
        // transaction-binding contract as the ordinary verify: a bound
        // record must equal the expected binding, and an explicitly
        // unbound record is permitted regardless of the expected binding.
        [$inner, $record, $token] = $this->issueAndSolve(requestBinding: 'txn-1');
        $inner->consumeWithOperationIdentity($record->nonce, $this->identity('bound-resume'));
        $verifier = new Verifier($inner, now: static fn (): int => self::ISSUED_AT);

        $mismatch = $verifier->resumeConsumedOperation($token, Vectors::SECRET, $this->identity('bound-resume'), 'login', self::CLIENT_IP, 'txn-OTHER');
        self::assertSame(VerifyError::RequestBindingMismatch, $mismatch->error, 'a bound record under the wrong transaction is refused before any derivation');

        $match = $verifier->resumeConsumedOperation($token, Vectors::SECRET, $this->identity('bound-resume'), 'login', self::CLIENT_IP, 'txn-1');
        self::assertTrue($match->isOk(), 'the exact bound transaction resumes');
    }

    public function testCommittedResultRecoveryPastSignedExpiryStillSucceeds(): void
    {
        // The committed-result path is the only expiry-exempt recovery:
        // a committed result was durably recorded only after the original
        // final expiry check passed, so recovering it after the signed
        // expiry remains correct — the exact deterministic outcome the
        // original logical redemption received.
        [$inner, $record, $token] = $this->issueAndSolve();
        $inner->consumeWithOperationIdentity($record->nonce, $this->identity('committed'));
        self::assertTrue($inner->commitResult($record->nonce, true, $record->requestBinding), 'the committed result lands');
        $farFuture = static fn (): int => self::ISSUED_AT + 10_000;

        $outcome = (new Verifier($inner, now: $farFuture))->resumeConsumedOperation($token, Vectors::SECRET, $this->identity('committed'), 'login', self::CLIENT_IP);
        self::assertTrue($outcome->isOk(), sprintf('the committed-result recovery must stay expiry-exempt, got %s', $outcome->code()));
        self::assertSame($record->nonce, $outcome->nonce());
        self::assertSame(true, $inner->consumedState($record->nonce)?->consumedResult?->valid);
    }

    /**
     * KCA-77-01: the resume post-commit read-back must accept a stored
     * Valid only behind the causal fence. The dangerous sequence: the
     * original consume lands with its WAIT failing, the resume's
     * commitResult write lands with its WAIT failing, and the
     * read-after-failure sees the stored Valid. Accepting it read-only
     * would return a success a stale-replica promotion could resurrect
     * into a second redemption. A shortfalling fence fails closed to
     * StorageUnavailable, never Valid; a satisfied fence returns the
     * stored Valid.
     */
    public function testResumePostCommitReadBackAcceptsStoredValidOnlyBehindTheCausalFence(): void
    {
        [$inner, $record, $token] = $this->issueAndSolve(requestBinding: 'txn-2');
        $inner->consumeWithOperationIdentity($record->nonce, $this->identity('post-commit-fence'));

        $barrier = new FailingCommitBarrierStorage($inner);
        $verifier = new Verifier($barrier, now: static fn (): int => self::ISSUED_AT);

        $barrier->failCommit = true;
        $barrier->confirmResult = false;
        $outcome = $verifier->resumeConsumedOperation($token, Vectors::SECRET, $this->identity('post-commit-fence'), 'login', self::CLIENT_IP, 'txn-2', RequestBindingExpectation::exact('txn-2'));
        self::assertFalse($outcome->isOk(), 'a shortfalling fence must never return the stored Valid');
        self::assertSame('storage_unavailable', $outcome->code(), 'the failed fence degrades to StorageUnavailable, never Valid');

        $barrier->confirmResult = true;
        $outcome = $verifier->resumeConsumedOperation($token, Vectors::SECRET, $this->identity('post-commit-fence'), 'login', self::CLIENT_IP, 'txn-2', RequestBindingExpectation::exact('txn-2'));
        self::assertTrue($outcome->isOk(), 'a satisfied fence returns the stored Valid');
        self::assertTrue($outcome->fromStoredResult, 'the accepted Valid is the read-back stored result');
    }

    public function testWrongIdentityIsRefused(): void
    {
        // The identity gate: a different logical operation (different
        // UUID / backend / response / remote-IP fingerprint) can never
        // resume the winner's derivation — ConsumeIndeterminate.
        [$inner, $record, $token] = $this->issueAndSolve();
        $storage = self::lostReplyStorage($inner, true);
        $verifier = new Verifier($storage);
        $inner->consumeWithOperationIdentity($record->nonce, $this->identity('a'));

        $outcome = $verifier->resumeConsumedOperation($token, Vectors::SECRET, $this->identity('b'), 'login', self::CLIENT_IP);
        self::assertSame(VerifyError::ConsumeIndeterminate, $outcome->error, 'a different identity must be refused');

        // The null identity (a no-key first redemption) is equally refused.
        [$inner2, $record2, $token2] = $this->issueAndSolve();
        $inner2->consume($record2->nonce);
        $refused = (new Verifier($inner2))->resumeConsumedOperation($token2, Vectors::SECRET, $this->identity('keyed'), 'login', self::CLIENT_IP);
        self::assertSame(VerifyError::ConsumeIndeterminate, $refused->error, 'a record without any identity must be refused');
    }

    public function testNonceWithNoRecordIsRefused(): void
    {
        $verifier = new Verifier(new ArrayStorage());

        // A never-stored nonce is refused.
        $neverStored = SolutionToken::create(base64_encode(random_bytes(32)), 5, 5000, [])->encode();
        $outcome = $verifier->resumeConsumedOperation($neverStored, Vectors::SECRET, $this->identity('a'), 'login', self::CLIENT_IP);
        self::assertSame(VerifyError::ConsumeIndeterminate, $outcome->error, 'a nonce with no consumed record must be refused');

        // A still-pending record is equally refused (consumedState is
        // defined for consumed records only).
        $pending = new ArrayStorage();
        $issuer = new Issuer(new Config(secretKey: Vectors::SECRET, targetBits: 8, ttlSecs: 120, minDurationMs: 0), $pending);
        $challenge = $issuer->issue('login', self::CLIENT_IP);
        $token2 = $this->solveFresh($pending, $challenge);
        $outcome2 = (new Verifier($pending))->resumeConsumedOperation($token2, Vectors::SECRET, $this->identity('a'), 'login', self::CLIENT_IP);
        self::assertSame(VerifyError::ConsumeIndeterminate, $outcome2->error, 'a still-pending record must be refused');
    }

    public function testMalformedTokenIsRefusedAsMalformed(): void
    {
        [$inner, $record] = $this->issueAndSolve();
        $inner->consumeWithOperationIdentity($record->nonce, $this->identity('a'));

        $outcome = (new Verifier($inner))->resumeConsumedOperation('not-a-token', Vectors::SECRET, $this->identity('a'), 'login', self::CLIENT_IP);
        self::assertSame(VerifyError::MalformedToken, $outcome->error);
    }

    public function testNonCapableStorageIsStorageUnavailable(): void
    {
        // A storage without the ConsumedStateReadableInterface capability
        // can never prove the identity — typed StorageUnavailable.
        [$inner, $record, $token] = $this->issueAndSolve();
        $inner->consumeWithOperationIdentity($record->nonce, $this->identity('a'));
        $nonCapable = new class($inner) implements StorageInterface {
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

            public function consume(string $nonce): ?ConsumedRecord
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

        $outcome = (new Verifier($nonCapable))->resumeConsumedOperation($token, Vectors::SECRET, $this->identity('a'), 'login', self::CLIENT_IP);
        self::assertSame(VerifyError::StorageUnavailable, $outcome->error);
    }

    public function testResumeRevalidatesScopeIpAndIdentitySecurity(): void
    {
        // Every immutable security property is revalidated exactly like
        // the ordinary verify path before the derivation resumes.
        [$inner, $record, $token] = $this->issueAndSolve();
        $storage = self::lostReplyStorage($inner, true);
        $verifier = new Verifier($storage);
        $inner->consumeWithOperationIdentity($record->nonce, $this->identity('a'));

        self::assertSame(
            VerifyError::WrongScope,
            $verifier->resumeConsumedOperation($token, Vectors::SECRET, $this->identity('a'), 'signup', self::CLIENT_IP)->error,
            'the expected scope must be revalidated on the resume path',
        );
        self::assertSame(
            VerifyError::IpMismatch,
            $verifier->resumeConsumedOperation($token, Vectors::SECRET, $this->identity('a'), 'login', '203.0.113.9')->error,
            'the IP binding must be revalidated on the resume path',
        );
        self::assertSame(
            VerifyError::MissingClientIp,
            $verifier->resumeConsumedOperation($token, Vectors::SECRET, $this->identity('a'), 'login', null)->error,
            'a missing client IP for a bound challenge fails closed on the resume path',
        );
        self::assertSame(
            VerifyError::BadSignature,
            $verifier->resumeConsumedOperation($token, str_repeat('f', 32), $this->identity('a'), 'login', self::CLIENT_IP)->error,
            'the HMAC signature must be revalidated on the resume path',
        );
        // A revalidation failure must NOT delete the retained evidence and
        // must NOT commit anything — a later retry can still resume.
        self::assertNotNull($inner->consumedState($record->nonce), 'the retained consumed record must survive a revalidation failure');
        self::assertNull($inner->consumedState($record->nonce)?->consumedResult, 'a revalidation failure must not commit anything');
    }

    public function testCommitReplyLostReadsBackTheWinnersResult(): void
    {
        // The commit reply is lost after the commit lands: the resume's
        // read-after-failed-commit resolves the winner's stored result
        // instead of failing.
        [$inner, $record, $token] = $this->issueAndSolve();
        $storage = self::lostReplyStorage($inner, true, true);
        $verifier = new Verifier($storage, now: static fn (): int => self::ISSUED_AT);

        $original = $verifier->verify($token, Vectors::SECRET, 'login', self::CLIENT_IP, nowNs: $record->issuedAtNs + 1_000_000, operationIdentity: $this->identity('c'));
        self::assertSame(VerifyError::ConsumeIndeterminate, $original->error, 'the lost consume reply must surface as ConsumeIndeterminate');
        self::assertNull($inner->consumedState($record->nonce)?->consumedResult, 'precondition: nothing committed yet');

        $outcome = $verifier->resumeConsumedOperation($token, Vectors::SECRET, $this->identity('c'), 'login', self::CLIENT_IP);
        self::assertTrue($outcome->isOk(), sprintf('the read-after-failed-commit must return the winner\'s stored result, got %s', $outcome->code()));
        self::assertSame($record->nonce, $outcome->nonce());
        $after = $inner->consumedState($record->nonce);
        self::assertNotNull($after?->consumedResult, 'the commit really landed');
        self::assertTrue($after->consumedResult->valid);
    }

    public function testCommitFailureWithNoStoredResultIsStorageUnavailable(): void
    {
        // When the commit fails AND nothing was stored (a genuine outage),
        // the resume reports the retryable StorageUnavailable.
        [$base, $record, $token] = $this->issueAndSolve();
        $storage = new class($base) implements AtomicStorageInterface, OperationIdentityAwareStorageInterface {
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

            public function consumedState(string $nonce): ?ConsumedRecord
            {
                return $this->inner->consumedState($nonce);
            }

            public function consume(string $nonce): ?ConsumedRecord
            {
                return $this->inner->consume($nonce);
            }

            public function consumeWithOperationIdentity(string $nonce, ?string $operationIdentity): ?ConsumedRecord
            {
                return $this->inner->consumeWithOperationIdentity($nonce, $operationIdentity);
            }

            public function commitResult(string $nonce, bool $valid, ?string $binding): bool
            {
                throw new \RuntimeException('storage down before the commit');
            }

            public function delete(string $nonce): void
            {
                $this->inner->delete($nonce);
            }
        };
        $storage->consumeWithOperationIdentity($record->nonce, $this->identity('outage'));

        $outcome = (new Verifier($storage))->resumeConsumedOperation($token, Vectors::SECRET, $this->identity('outage'), 'login', self::CLIENT_IP);
        self::assertSame(VerifyError::StorageUnavailable, $outcome->error);
    }

    public function testTwoVerifiersResolveOneDeterministicRetainedResult(): void
    {
        // Two verifier instances (two processes over one shared store)
        // resume the same consumed operation: the first derives and
        // commits; the second resolves the same stored outcome. One
        // deterministic retained result, never two derivations' worth of
        // divergence.
        [$inner, $record, $token] = $this->issueAndSolve();
        $inner->consumeWithOperationIdentity($record->nonce, $this->identity('shared'));
        $first = new Verifier($inner);
        $second = new Verifier($inner);

        $outcomeA = $first->resumeConsumedOperation($token, Vectors::SECRET, $this->identity('shared'), 'login', self::CLIENT_IP);
        $outcomeB = $second->resumeConsumedOperation($token, Vectors::SECRET, $this->identity('shared'), 'login', self::CLIENT_IP);

        self::assertTrue($outcomeA->isOk());
        self::assertTrue($outcomeB->isOk(), sprintf('the second verifier must resolve the retained result, got %s', $outcomeB->code()));
        self::assertSame($outcomeA->nonce(), $outcomeB->nonce(), 'both verifiers see the SAME nonce');
        self::assertSame($record->nonce, $outcomeB->nonce());

        $after = $inner->consumedState($record->nonce);
        self::assertNotNull($after?->consumedResult, 'exactly ONE deterministic result is retained');
        self::assertTrue($after->consumedResult->valid);
    }

    public function testOrdinaryVerifyStillIndeterminateForConsumedWithoutResult(): void
    {
        // Native replay security is unaffected: the ordinary verify() on
        // the consumed-without-result record still returns
        // ConsumeIndeterminate — only the identity-proven resume path can
        // derive.
        [$inner, $record, $token] = $this->issueAndSolve();
        $inner->consumeWithOperationIdentity($record->nonce, $this->identity('a'));

        $outcome = (new Verifier($inner, now: static fn (): int => self::ISSUED_AT))->verify($token, Vectors::SECRET, 'login', self::CLIENT_IP);
        self::assertSame(VerifyError::ConsumeIndeterminate, $outcome->error, 'the ordinary verifier must NOT derive a consumed-without-result record');

        $resume = (new Verifier($inner))->resumeConsumedOperation($token, Vectors::SECRET, $this->identity('a'), 'login', self::CLIENT_IP);
        self::assertTrue($resume->isOk(), 'only the identity-proven resume derives');
    }

    // ── Post-derive final revalidation (current expectations) ─────────

    public function testPolicyEpochRotationBetweenPreDeriveCheckAndCommitRefusesTheResume(): void
    {
        // The expected policy epoch rotates between the pre-derive
        // revalidation (which passed with the pre-rotation expectation)
        // and the commit; the post-derive re-check reads the current
        // expected epoch and refuses WrongPolicyVersion. Nothing is
        // committed, so a later same-identity resume with a matching
        // expectation can still run.
        [$storage, $record, $token] = $this->issueAndSolveArgon(policyVersion: 2);
        $storage->consumeWithOperationIdentity($record->nonce, $this->identity('rotate-policy'));

        $verifier = null;
        $gate = $this->rotatingGate(static function () use (&$verifier): void {
            $verifier?->rotateDeploymentExpectations(policyVersion: 3, region: null, issuer: null);
        });
        $verifier = new Verifier($storage, $gate, expectedPolicyVersion: 2);

        $outcome = $verifier->resumeConsumedOperation($token, Vectors::SECRET, $this->identity('rotate-policy'), 'login', self::CLIENT_IP);
        self::assertSame(VerifyError::WrongPolicyVersion, $outcome->error, 'a policy-epoch rotation mid-resume must fail the post-derive re-check');
        self::assertNull($storage->consumedState($record->nonce)?->consumedResult, 'the rotated resume must NOT commit anything');
    }

    public function testRegionRotationBetweenPreDeriveCheckAndCommitRefusesTheResume(): void
    {
        [$storage, $record, $token] = $this->issueAndSolveArgon(region: 'eu');
        $storage->consumeWithOperationIdentity($record->nonce, $this->identity('rotate-region'));

        $verifier = null;
        $gate = $this->rotatingGate(static function () use (&$verifier): void {
            $verifier?->rotateDeploymentExpectations(policyVersion: null, region: 'us', issuer: null);
        });
        $verifier = new Verifier($storage, $gate, region: 'eu');

        $outcome = $verifier->resumeConsumedOperation($token, Vectors::SECRET, $this->identity('rotate-region'), 'login', self::CLIENT_IP);
        self::assertSame(VerifyError::WrongRegion, $outcome->error, 'a region rotation mid-resume must fail the post-derive re-check');
        self::assertNull($storage->consumedState($record->nonce)?->consumedResult, 'the rotated resume must NOT commit anything');
    }

    public function testIssuerRotationBetweenPreDeriveCheckAndCommitRefusesTheResume(): void
    {
        [$storage, $record, $token] = $this->issueAndSolveArgon(issuer: 'dev');
        $storage->consumeWithOperationIdentity($record->nonce, $this->identity('rotate-issuer'));

        $verifier = null;
        $gate = $this->rotatingGate(static function () use (&$verifier): void {
            $verifier?->rotateDeploymentExpectations(policyVersion: null, region: null, issuer: 'prod');
        });
        $verifier = new Verifier($storage, $gate, expectedIssuer: 'dev');

        $outcome = $verifier->resumeConsumedOperation($token, Vectors::SECRET, $this->identity('rotate-issuer'), 'login', self::CLIENT_IP);
        self::assertSame(VerifyError::WrongIssuer, $outcome->error, 'an issuer rotation mid-resume must fail the post-derive re-check');
        self::assertNull($storage->consumedState($record->nonce)?->consumedResult, 'the rotated resume must NOT commit anything');
    }

    public function testRotationToMatchingExpectationsMidResumeStillCommits(): void
    {
        // Control: a rotation that lands on matching values must not
        // reject — the resumed derivation commits as today.
        [$storage, $record, $token] = $this->issueAndSolveArgon(policyVersion: 2, issuer: 'prod');
        $storage->consumeWithOperationIdentity($record->nonce, $this->identity('rotate-match'));

        $verifier = null;
        $gate = $this->rotatingGate(static function () use (&$verifier): void {
            $verifier?->rotateDeploymentExpectations(policyVersion: 2, region: null, issuer: 'prod');
        });
        $verifier = new Verifier($storage, $gate, expectedPolicyVersion: 2, expectedIssuer: 'prod');

        $outcome = $verifier->resumeConsumedOperation($token, Vectors::SECRET, $this->identity('rotate-match'), 'login', self::CLIENT_IP);
        self::assertTrue($outcome->isOk(), sprintf('a rotation to matching expectations must still commit the resume, got %s', $outcome->code()));
        $after = $storage->consumedState($record->nonce);
        self::assertNotNull($after?->consumedResult, 'the matching-rotation resume must commit');
        self::assertTrue($after->consumedResult->valid);
    }

    private function solveFresh(ArrayStorage $storage, \KiwiCaptcha\Challenge $challenge): string
    {
        $saltBytes = base64_decode($challenge->salt, true);
        $counter = 0;
        do {
            $hash = hash('sha256', $challenge->prefix.$counter.$saltBytes, true);
            $counter++;
        } while (Verifier::leadingZeroBits($hash) < $challenge->targetBits);
        --$counter;

        return SolutionToken::create($challenge->nonce, $counter, 5000, [])->encode();
    }

    public function testCommittedResultRecoveryRerunsTheHardSecurityContext(): void
    {
        // The committed-result fast path must NOT be a weaker verification
        // mode than the operation it recovers (the Rust mirror): the hard
        // replay invariants rerun before the stored Valid. Rotating any
        // immutable authorization/security context rejects the stored
        // success; only the correct-context control resolves it. The
        // current IP and the signed expiry stay deliberately exempt (the
        // same-operation recovery contract).

        // Wrong scope.
        [$inner, $record, $token] = $this->issueAndSolve();
        $identity = $this->identity('committed-ctx-scope');
        $inner->consumeWithOperationIdentity($record->nonce, $identity);
        self::assertTrue($inner->commitResult($record->nonce, true, $record->requestBinding));
        $verifier = new Verifier($inner, now: static fn (): int => self::ISSUED_AT);
        $outcome = $verifier->resumeConsumedOperation($token, Vectors::SECRET, $identity, 'payment', self::CLIENT_IP, null);
        self::assertSame(VerifyError::WrongScope, $outcome->error, 'a changed scope cannot consume the retained Valid');

        // Wrong secret / bad signature (the secret-set path).
        [$inner, $record, $token] = $this->issueAndSolve();
        $identity = $this->identity('committed-ctx-secret');
        $inner->consumeWithOperationIdentity($record->nonce, $identity);
        self::assertTrue($inner->commitResult($record->nonce, true, $record->requestBinding));
        $wrongSecret = new Verifier($inner, null, static fn (): int => self::ISSUED_AT, false, null, null, null, [1 => str_repeat('f', 32)]);
        $outcome = $wrongSecret->resumeConsumedOperation($token, str_repeat('f', 32), $identity, 'login', self::CLIENT_IP, null);
        self::assertSame(VerifyError::BadSignature, $outcome->error, 'a wrong signing secret cannot consume the retained Valid');

        // Revoked kid.
        [$inner, $record, $token] = $this->issueAndSolve();
        $identity = $this->identity('committed-ctx-revoked');
        $inner->consumeWithOperationIdentity($record->nonce, $identity);
        self::assertTrue($inner->commitResult($record->nonce, true, $record->requestBinding));
        $revoked = new Verifier($inner, null, static fn (): int => self::ISSUED_AT, false, null, null, null, [], [1]);
        $outcome = $revoked->resumeConsumedOperation($token, Vectors::SECRET, $identity, 'login', self::CLIENT_IP, null);
        self::assertSame(VerifyError::UnknownKid, $outcome->error, 'an emergency-revoked key cannot consume the retained Valid');

        // Wrong issuer.
        [$inner, $record, $token] = $this->issueAndSolve();
        $identity = $this->identity('committed-ctx-issuer');
        $inner->consumeWithOperationIdentity($record->nonce, $identity);
        self::assertTrue($inner->commitResult($record->nonce, true, $record->requestBinding));
        $wrongIssuer = new Verifier($inner, null, static fn (): int => self::ISSUED_AT, false, null, null, 'other-issuer');
        $outcome = $wrongIssuer->resumeConsumedOperation($token, Vectors::SECRET, $identity, 'login', self::CLIENT_IP, null);
        self::assertSame(VerifyError::WrongIssuer, $outcome->error, 'a wrong issuer cannot consume the retained Valid');

        // Wrong region.
        [$inner, $record, $token] = $this->issueAndSolveArgon(policyVersion: 1, region: 'eu');
        $identity = $this->identity('committed-ctx-region');
        $inner->consumeWithOperationIdentity($record->nonce, $identity);
        self::assertTrue($inner->commitResult($record->nonce, true, $record->requestBinding));
        $wrongRegion = new Verifier($inner, null, static fn (): int => self::ISSUED_AT, false, 'us');
        $outcome = $wrongRegion->resumeConsumedOperation($token, Vectors::SECRET, $identity, 'login', self::CLIENT_IP, null);
        self::assertSame(VerifyError::WrongRegion, $outcome->error, 'a wrong region cannot consume the retained Valid');

        // Changed policy epoch.
        [$inner, $record, $token] = $this->issueAndSolve();
        $identity = $this->identity('committed-ctx-policy');
        $inner->consumeWithOperationIdentity($record->nonce, $identity);
        self::assertTrue($inner->commitResult($record->nonce, true, $record->requestBinding));
        $bumpedPolicy = new Verifier($inner, null, static fn (): int => self::ISSUED_AT, false, null, 2);
        $outcome = $bumpedPolicy->resumeConsumedOperation($token, Vectors::SECRET, $identity, 'login', self::CLIENT_IP, null);
        self::assertSame(VerifyError::WrongPolicyVersion, $outcome->error, 'a bumped policy epoch cannot consume the retained Valid');

        // Protocol-version acceptance: a legacy-v1 record (converted like
        // the hardening suite) replayed under a verifier that does NOT
        // accept v1 is rejected at the protocol gate, even though its
        // result is committed. The Argon parameter ceilings are absolute
        // constants that issuance cannot legitimately exceed; their
        // re-run on this path is the same checkAuthenticatedShape call
        // that rejects this record's protocol version.
        $storage = new ArrayStorage();
        $issuer = new Issuer(new Config(secretKey: Vectors::SECRET, targetBits: 8, ttlSecs: 120, minDurationMs: 0), $storage, now: static fn (): int => self::ISSUED_AT);
        $challenge = $issuer->issue('login', self::CLIENT_IP);
        $record = $storage->find($challenge->nonce);
        $ipHash = Issuer::hashIp(self::CLIENT_IP, Vectors::SECRET);
        $payload = sprintf('%s|%s|%s|%d', $record->nonce, $record->scope, $ipHash, $record->issuedAt);
        $challengeWire = base64_encode($payload).'.'.Issuer::signPayload($payload, Vectors::SECRET);
        $v1 = new ChallengeRecord(
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
            prefix: $challengeWire,
            challenge: $challengeWire,
            minDurationMs: $record->minDurationMs,
            issuedAtNs: $record->issuedAtNs,
            protocolVersion: 1,
            region: $record->region,
            policyVersion: $record->policyVersion,
            requestBinding: $record->requestBinding,
            issuer: $record->issuer,
            kid: $record->kid,
        );
        $storage->store($v1);
        $v1Salt = base64_decode($v1->salt, true);
        $v1Counter = 0;
        do {
            $hash = hash('sha256', $challengeWire.$v1Counter.$v1Salt, true);
            $v1Counter++;
        } while (Verifier::leadingZeroBits($hash) < $v1->targetBits);
        --$v1Counter;
        $v1Token = SolutionToken::create($v1->nonce, $v1Counter, 5000, [])->encode();
        $identity = $this->identity('committed-ctx-v1');
        $storage->consumeWithOperationIdentity($v1->nonce, $identity);
        self::assertTrue($storage->commitResult($v1->nonce, true, $v1->requestBinding));
        $outcome = (new Verifier($storage, now: static fn (): int => self::ISSUED_AT))->resumeConsumedOperation($v1Token, Vectors::SECRET, $identity, 'login', self::CLIENT_IP, null);
        self::assertSame(VerifyError::MalformedRecord, $outcome->error, 'a legacy-v1 record cannot consume the retained Valid under a v2-only verifier');

        // Minimum-duration hard failure: a record with a long
        // server-measured floor, resumed immediately.
        $storage = new ArrayStorage();
        $issuer = new Issuer(new Config(secretKey: Vectors::SECRET, targetBits: 8, ttlSecs: 120, minDurationMs: 60_000), $storage, now: static fn (): int => self::ISSUED_AT);
        $challenge = $issuer->issue('login', self::CLIENT_IP);
        $record = $storage->find($challenge->nonce);
        $saltBytes = base64_decode($challenge->salt, true);
        $counter = 0;
        do {
            $hash = hash('sha256', $challenge->prefix.$counter.$saltBytes, true);
            $counter++;
        } while (Verifier::leadingZeroBits($hash) < $challenge->targetBits);
        --$counter;
        $token = SolutionToken::create($challenge->nonce, $counter, 5000, [])->encode();
        $identity = $this->identity('committed-ctx-mindur');
        $storage->consumeWithOperationIdentity($record->nonce, $identity);
        self::assertTrue($storage->commitResult($record->nonce, true, $record->requestBinding));
        $outcome = (new Verifier($storage, now: static fn (): int => self::ISSUED_AT))->resumeConsumedOperation($token, Vectors::SECRET, $identity, 'login', self::CLIENT_IP, null);
        self::assertSame(VerifyError::TooFast, $outcome->error, 'the minimum-duration floor is a hard invariant for the retained Valid');

        // Correct-context control: the stored success still resolves.
        [$inner, $record, $token] = $this->issueAndSolve();
        $identity = $this->identity('committed-ctx-control');
        $inner->consumeWithOperationIdentity($record->nonce, $identity);
        self::assertTrue($inner->commitResult($record->nonce, true, $record->requestBinding));
        $outcome = (new Verifier($inner, now: static fn (): int => self::ISSUED_AT))->resumeConsumedOperation($token, Vectors::SECRET, $identity, 'login', self::CLIENT_IP, null);
        self::assertTrue($outcome->isOk(), 'the correct context resolves the retained Valid');
    }
}

/**
 * The failed-barrier replay guard test storage: delegates to the inner
 * storage and lets the test control whether the replication barrier
 * confirms or shortfalls.
 */
final class BarrierStorage implements \KiwiCaptcha\AtomicStorageInterface, \KiwiCaptcha\ConsumedStateReadableInterface, \KiwiCaptcha\OperationIdentityAwareStorageInterface, \KiwiCaptcha\ReplicationBarrierInterface
{
    public bool $confirmResult = true;

    public function __construct(private readonly \KiwiCaptcha\Storage\ArrayStorage $inner)
    {
    }

    public function store(\KiwiCaptcha\ChallengeRecord $record): void
    {
        $this->inner->store($record);
    }

    public function find(string $nonce): ?\KiwiCaptcha\ChallengeRecord
    {
        return $this->inner->find($nonce);
    }

    public function consume(string $nonce): ?\KiwiCaptcha\ConsumedRecord
    {
        return $this->inner->consume($nonce);
    }

    public function consumeWithOperationIdentity(string $nonce, ?string $operationIdentity): ?\KiwiCaptcha\ConsumedRecord
    {
        return $this->inner->consumeWithOperationIdentity($nonce, $operationIdentity);
    }

    public function commitResult(string $nonce, bool $valid, ?string $binding): bool
    {
        return $this->inner->commitResult($nonce, $valid, $binding);
    }

    public function delete(string $nonce): void
    {
        $this->inner->delete($nonce);
    }

    public function consumedState(string $nonce): ?\KiwiCaptcha\ConsumedRecord
    {
        return $this->inner->consumedState($nonce);
    }

    public function establishReplicationFence(string $what): void
    {
        if (!$this->confirmResult) {
            throw new \RuntimeException('replication barrier shortfall');
        }
    }
}
/**
 * The barrier storage whose commitResult write lands but then throws
 * (the mutation reached the primary, its WAIT shortfalled): the resume
 * catch-branch reads the stored result back and must fence before
 * accepting it.
 */
final class FailingCommitBarrierStorage implements \KiwiCaptcha\AtomicStorageInterface, \KiwiCaptcha\ConsumedStateReadableInterface, \KiwiCaptcha\OperationIdentityAwareStorageInterface, \KiwiCaptcha\ReplicationBarrierInterface
{
    public bool $failCommit = false;

    public bool $confirmResult = true;

    public function __construct(private readonly \KiwiCaptcha\Storage\ArrayStorage $inner)
    {
    }

    public function store(\KiwiCaptcha\ChallengeRecord $record): void
    {
        $this->inner->store($record);
    }

    public function find(string $nonce): ?\KiwiCaptcha\ChallengeRecord
    {
        return $this->inner->find($nonce);
    }

    public function consume(string $nonce): ?\KiwiCaptcha\ConsumedRecord
    {
        return $this->inner->consume($nonce);
    }

    public function consumeWithOperationIdentity(string $nonce, ?string $operationIdentity): ?\KiwiCaptcha\ConsumedRecord
    {
        return $this->inner->consumeWithOperationIdentity($nonce, $operationIdentity);
    }

    public function commitResult(string $nonce, bool $valid, ?string $binding): bool
    {
        $ok = $this->inner->commitResult($nonce, $valid, $binding);
        if ($this->failCommit) {
            throw new \RuntimeException('the commit WAIT shortfalled');
        }

        return $ok;
    }

    public function delete(string $nonce): void
    {
        $this->inner->delete($nonce);
    }

    public function consumedState(string $nonce): ?\KiwiCaptcha\ConsumedRecord
    {
        return $this->inner->consumedState($nonce);
    }

    public function establishReplicationFence(string $what): void
    {
        if (!$this->confirmResult) {
            throw new \RuntimeException('replication barrier shortfall');
        }
    }
}
