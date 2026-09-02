<?php

declare(strict_types=1);

namespace KiwiCaptcha\Tests;

use KiwiCaptcha\ChallengeRecord;
use KiwiCaptcha\RequestBindingExpectation;
use KiwiCaptcha\Config;
use KiwiCaptcha\ConsumedRecord;
use KiwiCaptcha\ExecutionChallengeGenerator;
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

    private const EXECUTION_KEY = '0123456789abcdef0123456789abcdef';

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

    /** A token whose counter provably fails the record's Argon2id target. */
    private function wrongArgonCounterToken(ChallengeRecord $record): string
    {
        $saltBytes = base64_decode($record->salt, true);
        $wrong = 0;
        while (Verifier::leadingZeroBits(sodium_crypto_pwhash(32, $record->prefix.$wrong, $saltBytes, $record->t, $record->mKib * 1024, SODIUM_CRYPTO_PWHASH_ALG_ARGON2ID13)) >= $record->targetBits) {
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

    /**
     * An admission gate that counts every acquire and release and
     * tracks the live permits, so the resume's gate interaction is
     * observable. The counters record how many slots were acquired,
     * how many leases were released, and how many permits are still
     * live after the call. Saturation is modelled by pre-setting
     * `live` to the capacity before the resume (the slot held from the
     * outside).
     *
     * @param array{acquires?: int, releases?: int, live?: int} $counters
     */
    private function countingGate(int $capacity, array &$counters): VerificationAdmissionGate
    {
        return new class($capacity, $counters) implements VerificationAdmissionGate {
            private int $capacity;

            private array $counters;

            public function __construct(int $capacity, array &$counters)
            {
                $this->capacity = $capacity;
                $this->counters = &$counters;
            }

            public function acquire(): ?string
            {
                $this->counters['acquires']++;
                if ($this->counters['live'] >= $this->capacity) {
                    return null;
                }
                $this->counters['live']++;

                return 'lease-'.$this->counters['acquires'];
            }

            public function release(string $lease): void
            {
                $this->counters['releases']++;
                $this->counters['live']--;
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

    public function testResultlessResumeExpiringDuringDerivationWithInvalidProofIsExpired(): void
    {
        // Rust parity: the post-derive revalidation
        // runs for both a valid and an invalid derivation, so an
        // insufficient proof on a record that expires mid-derive
        // commits Expired, never a stale InsufficientWork (the Rust
        // mirror re-reads the clock after the derivation before the
        // leading-zero verdict).
        [$storage, $record, $token] = $this->issueAndSolveArgon(ttlSecs: 1);
        $storage->consumeWithOperationIdentity($record->nonce, $this->identity('expire-mid-derive-invalid'));
        $wrongToken = $this->wrongArgonCounterToken($record);

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

        $outcome = $verifier->resumeConsumedOperation($wrongToken, Vectors::SECRET, $this->identity('expire-mid-derive-invalid'), 'login', self::CLIENT_IP);
        self::assertSame(VerifyError::Expired, $outcome->error, 'an invalid derivation on a record expiring mid-derive must commit Expired (Rust parity), never InsufficientWork');
        $after = $storage->consumedState($record->nonce);
        self::assertNull($after?->consumedResult, 'the mid-derivation expiry must NOT commit anything');

        // Deterministic: a second resume reproduces the identical
        // Expired (the clock is past the signed deadline now) — the same
        // logical redemption can never become Valid.
        $replay = $verifier->resumeConsumedOperation($wrongToken, Vectors::SECRET, $this->identity('expire-mid-derive-invalid'), 'login', self::CLIENT_IP);
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
        $outcome = $verifier->verify($token, Vectors::SECRET, 'login', '198.51.100.7', operationIdentity: $this->identity('barrier-replay'), expectedRequestBinding: 'txn-1', bindingExpectation: RequestBindingExpectation::exact('txn-1'));
        self::assertSame(VerifyError::StorageUnavailable, $outcome->error, 'the stored-result replay must fail CLOSED to StorageUnavailable on a barrier shortfall, never return an unproven success and never leak a storage exception out of the verifier');

        // The barrier satisfied: the replay returns the stored Valid.
        $barrier->confirmResult = true;
        $outcome = $verifier->verify($token, Vectors::SECRET, 'login', '198.51.100.7', operationIdentity: $this->identity('barrier-replay'), expectedRequestBinding: 'txn-1', bindingExpectation: RequestBindingExpectation::exact('txn-1'));
        self::assertTrue($outcome->isOk());
        self::assertTrue($outcome->fromStoredResult, 'the replay is the stored Valid');

        // The same guard on resumeConsumedOperation's committed-result
        // fast path.
        $barrier->confirmResult = false;
        $failedResume = $verifier->resumeConsumedOperation($token, Vectors::SECRET, $this->identity('barrier-replay'), 'login', self::CLIENT_IP, 'txn-1', RequestBindingExpectation::exact('txn-1'));
        self::assertSame(VerifyError::StorageUnavailable, $failedResume->error, 'the resumed committed-result must fail CLOSED to StorageUnavailable on a barrier shortfall, never return an unproven success and never leak a storage exception out of the verifier');
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

    // ── the execution-armed v4 resume ───────────────────────────────────

    /**
     * Issues an execution-armed protocol-v4 challenge (the decoy
     * surface armed too), solves its PoW, and builds the wire token
     * with the executed trace and the digest over it.
     *
     * @return array{0: ArrayStorage, 1: ChallengeRecord, 2: string}
     */
    private function issueAndSolveArmed(): array
    {
        $storage = new ArrayStorage();
        $issuer = new Issuer(
            new Config(secretKey: Vectors::SECRET, targetBits: 8, ttlSecs: 120, minDurationMs: 0, executionKey: self::EXECUTION_KEY),
            $storage,
            now: static fn (): int => self::ISSUED_AT,
        );
        $challenge = $issuer->issueWithExecutionField('login', self::CLIENT_IP, true, executionAction: 'login-action', armDecoyField: true);
        $record = $storage->find($challenge->nonce);
        self::assertNotNull($record);

        $program = ExecutionChallengeGenerator::decode($challenge->executionProgram);
        self::assertNotNull($program);
        $trace = ExecutionChallengeGenerator::executedTraceFor($program);
        $digest = ExecutionChallengeGenerator::digestOverTrace($challenge->executionProgram, $challenge->nonce, $trace);
        self::assertNotNull($digest);

        $saltBytes = base64_decode($challenge->salt, true);
        $counter = 0;
        do {
            $hash = hash('sha256', $challenge->prefix.$counter.$saltBytes, true);
            $counter++;
        } while (Verifier::leadingZeroBits($hash) < $challenge->targetBits);
        --$counter;

        return [$storage, $record, SolutionToken::create($challenge->nonce, $counter, 5000, [], $digest, base64_encode($trace))->encode()];
    }

    public function testCommittedResultRecoveryArmedPastSignedExpiryStillSucceeds(): void
    {
        // The execution-armed committed-result recovery: the replay
        // security gate on the fast path must clear with the full
        // execution evidence, even past the signed expiry and from
        // another backend network path (the IP stays exempt).
        [$inner, $record, $token] = $this->issueAndSolveArmed();
        $inner->consumeWithOperationIdentity($record->nonce, $this->identity('armed-committed'));
        self::assertTrue($inner->commitResult($record->nonce, true, $record->requestBinding), 'the committed result lands');
        $farFuture = static fn (): int => self::ISSUED_AT + 10_000;

        $outcome = (new Verifier($inner, now: $farFuture))->resumeConsumedOperation($token, Vectors::SECRET, $this->identity('armed-committed'), 'login', '203.0.113.9');
        self::assertTrue($outcome->isOk(), sprintf('the armed committed-result recovery must stay expiry-exempt, got %s', $outcome->code()));
        self::assertTrue($outcome->fromStoredResult, 'the armed recovery is the stored committed result, never a re-derivation');
        self::assertSame($record->nonce, $outcome->nonce());
        self::assertSame(true, $inner->consumedState($record->nonce)?->consumedResult?->valid);
    }

    public function testResultlessArmedResumeSucceedsAndCommits(): void
    {
        // The resultless resume of an execution-armed record: the
        // derivation runs only after the shared cheap phase cleared the
        // execution binding with the full evidence.
        [$inner, $record, $token] = $this->issueAndSolveArmed();
        $storage = self::lostReplyStorage($inner, true);
        $verifier = new Verifier($storage, now: static fn (): int => self::ISSUED_AT);

        $original = $verifier->verify($token, Vectors::SECRET, 'login', self::CLIENT_IP, nowNs: $record->issuedAtNs + 1_000_000, operationIdentity: $this->identity('armed-a'));
        self::assertSame(VerifyError::ConsumeIndeterminate, $original->error, 'the lost consume reply must surface as ConsumeIndeterminate');
        self::assertNull($inner->consumedState($record->nonce)?->consumedResult, 'precondition: nothing committed yet');

        $outcome = $verifier->resumeConsumedOperation($token, Vectors::SECRET, $this->identity('armed-a'), 'login', self::CLIENT_IP);
        self::assertTrue($outcome->isOk(), sprintf('the armed identity-proven resume must derive and commit the valid outcome, got %s', $outcome->code()));
        self::assertSame($record->nonce, $outcome->nonce());

        $after = $inner->consumedState($record->nonce);
        self::assertNotNull($after?->consumedResult, 'the armed resume must commit the deterministic outcome');
        self::assertTrue($after->consumedResult->valid);
    }

    public function testChangedClientIpOnAnArmedResultlessResumeIsIpMismatch(): void
    {
        // The resultless resume revalidates the IP binding; a changed
        // client IP is the exempt network circumstance, so the verdict
        // falls to the compositional replay gate first. The execution
        // evidence must clear that gate, leaving IpMismatch as the
        // outcome — never an ExecutionMismatch.
        [$inner, $record, $token] = $this->issueAndSolveArmed();
        $inner->consumeWithOperationIdentity($record->nonce, $this->identity('armed-ip'));
        $verifier = new Verifier($inner, now: static fn (): int => self::ISSUED_AT);

        $outcome = $verifier->resumeConsumedOperation($token, Vectors::SECRET, $this->identity('armed-ip'), 'login', '203.0.113.9');
        self::assertSame(VerifyError::IpMismatch, $outcome->error, 'the changed client IP must refuse the armed resume as IpMismatch, never ExecutionMismatch');
        self::assertNull($inner->consumedState($record->nonce)?->consumedResult, 'the refused armed resume must not commit anything');
        self::assertNotNull($inner->consumedState($record->nonce), 'the retained consumed record survives the refusal');
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

    // ── The re-derivation claim ─────────────────────────────────────────

    public function testEarlyReturnReleasesTheClaim(): void
    {
        // The claim is released via compare-and-delete on every early
        // return after acquisition: a resume that fails the post-derive
        // revalidation (a policy-epoch rotation lands mid-derivation)
        // must release its claim, so a fresh claim succeeds immediately
        // and the next retry is never blocked by the failed attempt.
        [$storage, $record, $token] = $this->issueAndSolveArgon(policyVersion: 2);
        $storage->consumeWithOperationIdentity($record->nonce, $this->identity('claim-release'));

        $verifier = null;
        $gate = $this->rotatingGate(static function () use (&$verifier): void {
            $verifier?->rotateDeploymentExpectations(policyVersion: 3, region: null, issuer: null);
        });
        $verifier = new Verifier($storage, $gate, expectedPolicyVersion: 2);

        $outcome = $verifier->resumeConsumedOperation($token, Vectors::SECRET, $this->identity('claim-release'), 'login', self::CLIENT_IP);
        self::assertSame(VerifyError::WrongPolicyVersion, $outcome->error, 'the rotation must fail the post-derive re-check');
        self::assertNull($storage->consumedState($record->nonce)?->consumedResult, 'the rotated resume must NOT commit anything');

        // The early return released the claim: a fresh claim succeeds
        // immediately, nothing blocks the next retry.
        $reclaimed = $storage->claimResumeDerivation($record->nonce);
        self::assertIsString($reclaimed, 'a fresh claim must succeed right after the released early return');
        $storage->releaseResumeDerivation($record->nonce, $reclaimed);
    }

    public function testClaimedNonceRefusesAConcurrentRecoveryUntilReleased(): void
    {
        // Exactly one concurrent same-operation recovery derives: while
        // one caller holds the claim, the other observes the refusal,
        // re-reads the retained state, and (with no committed result
        // yet) answers the retryable ConsumeIndeterminate instead of
        // deriving. Releasing the claim lets the retry derive and
        // commit.
        [$storage, $record, $token] = $this->issueAndSolve();
        $storage->consumeWithOperationIdentity($record->nonce, $this->identity('claim-held'));

        $winner = $storage->claimResumeDerivation($record->nonce);
        self::assertIsString($winner);

        $outcome = (new Verifier($storage))->resumeConsumedOperation($token, Vectors::SECRET, $this->identity('claim-held'), 'login', self::CLIENT_IP);
        self::assertSame(VerifyError::ConsumeIndeterminate, $outcome->error, 'a refused claim while the winner is mid-derive must answer ConsumeIndeterminate, never derive');
        self::assertNull($storage->consumedState($record->nonce)?->consumedResult, 'the loser must not commit anything');

        $storage->releaseResumeDerivation($record->nonce, $winner);
        $outcome = (new Verifier($storage))->resumeConsumedOperation($token, Vectors::SECRET, $this->identity('claim-held'), 'login', self::CLIENT_IP);
        self::assertTrue($outcome->isOk(), 'after the release the retry derives and commits');
    }

    public function testClaimRefusedLoserResolvesTheWinnersCommittedOutcome(): void
    {
        // The loser re-reads the retained state after a refused claim:
        // a result committed between the loser's top-of-resume read and
        // its claim attempt is authoritative (the stored Valid behind
        // the fence), never a second derivation. The seam: the wrapper
        // serves ONE stale resultless snapshot at the top of the resume
        // (the interleaving where the winner commits right after), while
        // the inner store already holds the claim and the committed
        // result.
        [$inner, $record, $token] = $this->issueAndSolve();
        $inner->consumeWithOperationIdentity($record->nonce, $this->identity('claim-loser'));

        $winner = $inner->claimResumeDerivation($record->nonce);
        self::assertIsString($winner);
        $stale = $inner->consumedState($record->nonce);
        self::assertNotNull($stale);
        self::assertNull($stale->consumedResult);
        self::assertTrue($inner->commitResult($record->nonce, true, $record->requestBinding), 'the winner commits while holding the claim');

        $storage = new class($inner, $stale) implements StorageInterface, \KiwiCaptcha\ConsumedStateReadableInterface, \KiwiCaptcha\ResumeDerivationClaimInterface {
            public function __construct(
                private readonly ArrayStorage $inner,
                private readonly ConsumedRecord $stale,
                private bool $staleServed = false,
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

            public function consumedState(string $nonce): ?ConsumedRecord
            {
                // The first read serves the stale resultless snapshot
                // (the winner committed after it); every later read sees
                // the live store.
                if (!$this->staleServed) {
                    $this->staleServed = true;

                    return $this->stale;
                }

                return $this->inner->consumedState($nonce);
            }

            public function claimResumeDerivation(string $nonce, int $ttlSecs = 60): ?string
            {
                return $this->inner->claimResumeDerivation($nonce, $ttlSecs);
            }

            public function releaseResumeDerivation(string $nonce, string $owner): bool
            {
                return $this->inner->releaseResumeDerivation($nonce, $owner);
            }

            public function commitResultResume(string $nonce, bool $valid, ?string $binding, string $owner): bool
            {
                return $this->inner->commitResultResume($nonce, $valid, $binding, $owner);
            }
        };

        $outcome = (new Verifier($storage))->resumeConsumedOperation($token, Vectors::SECRET, $this->identity('claim-loser'), 'login', self::CLIENT_IP);
        self::assertTrue($outcome->isOk(), 'the loser resolves the winner\'s committed Valid after the refused claim');
        self::assertTrue($outcome->fromStoredResult, 'the resolved outcome is the stored result, not a derivation');
        self::assertSame($record->nonce, $outcome->nonce());
    }

    public function testCommitClearsTheClaimAndAStaleOwnerIsRefused(): void
    {
        // The commit clears the claim atomically with the result write:
        // after commitResultResume the claim is gone, a fresh claim
        // succeeds immediately, and the former owner's release is a
        // refused no-op (the claim it owns no longer exists). A stale
        // owner can never commit: commitResultResume with a wrong owner
        // writes nothing and keeps the claim for its true owner.
        [$storage, $record] = $this->issueAndSolve();
        $storage->consumeWithOperationIdentity($record->nonce, $this->identity('claim-commit'));

        $owner = $storage->claimResumeDerivation($record->nonce);
        self::assertIsString($owner);
        self::assertTrue($storage->commitResultResume($record->nonce, true, $record->requestBinding, $owner), 'the claim-bearing commit lands');

        $after = $storage->consumedState($record->nonce);
        self::assertNotNull($after?->consumedResult, 'the claim-bearing commit stores the result');
        self::assertTrue($after->consumedResult->valid);
        self::assertFalse($storage->releaseResumeDerivation($record->nonce, $owner), 'the commit already cleared the claim; the former owner release is a no-op');
        self::assertNull($storage->claimResumeDerivation($record->nonce), 'the committed record is no longer claimable');

        // Wrong owner: the commit is refused before any write and the
        // true owner's claim survives.
        [$storage2, $record2] = $this->issueAndSolve();
        $storage2->consumeWithOperationIdentity($record2->nonce, $this->identity('claim-wrong-owner'));
        $realOwner = $storage2->claimResumeDerivation($record2->nonce);
        self::assertIsString($realOwner);
        self::assertFalse($storage2->commitResultResume($record2->nonce, true, $record2->requestBinding, str_repeat('b', 32)), 'a stale owner can never commit');
        self::assertNull($storage2->consumedState($record2->nonce)?->consumedResult, 'the refused commit writes nothing');
        self::assertFalse($storage2->releaseResumeDerivation($record2->nonce, str_repeat('b', 32)), 'a stale owner can never release');
        self::assertNull($storage2->claimResumeDerivation($record2->nonce), 'the true owner still holds the claim');
        self::assertTrue($storage2->commitResultResume($record2->nonce, true, $record2->requestBinding, $realOwner), 'the true owner commits');
        self::assertFalse($storage2->releaseResumeDerivation($record2->nonce, $realOwner), 'the commit already cleared the claim; the former owner release is a refused no-op');
    }

    public function testClaimIsRefusedForNonResultlessRecords(): void
    {
        // The claimability contract: only a consumed, resultless record
        // is claimable. Missing, pending, committed and cancelled
        // records all refuse the claim.
        $storage = new ArrayStorage();

        $missing = $storage->claimResumeDerivation('never-stored');
        self::assertNull($missing, 'a missing record is not claimable');

        $issuer = new Issuer(new Config(secretKey: Vectors::SECRET, targetBits: 8, ttlSecs: 120, minDurationMs: 0), $storage, now: static fn (): int => self::ISSUED_AT);
        $challenge = $issuer->issue('login', self::CLIENT_IP);
        $record = $storage->find($challenge->nonce);
        self::assertNotNull($record);
        self::assertNull($storage->claimResumeDerivation($record->nonce), 'a pending record is not claimable');

        $storage->consumeWithOperationIdentity($record->nonce, $this->identity('claimability'));
        $storage->commitResult($record->nonce, true, null);
        self::assertNull($storage->claimResumeDerivation($record->nonce), 'a committed record is not claimable');

        $issuer2 = new Issuer(new Config(secretKey: Vectors::SECRET, targetBits: 8, ttlSecs: 120, minDurationMs: 0), $storage, now: static fn (): int => self::ISSUED_AT);
        $challenge2 = $issuer2->issue('login', self::CLIENT_IP);
        $record2 = $storage->find($challenge2->nonce);
        self::assertNotNull($record2);
        $storage->cancel($record2->nonce);
        self::assertNull($storage->claimResumeDerivation($record2->nonce), 'a cancelled record is not claimable');
    }

    public function testWithoutTheClaimCapabilityTheResumeDerivesExactlyAsBefore(): void
    {
        // A storage without the ResumeDerivationClaimInterface
        // capability resumes byte-identically to the legacy path: the
        // recovery derives and commits even while another caller holds
        // a claim-shaped lock it knows nothing about, and the
        // deterministic outcome converges on the single committed
        // result.
        [$inner, $record, $token] = $this->issueAndSolve();
        $storage = self::lostReplyStorage($inner, true);
        self::assertNotInstanceOf(\KiwiCaptcha\ResumeDerivationClaimInterface::class, $storage, 'precondition: the lost-reply storage lacks the capability');
        $verifier = new Verifier($storage, now: static fn (): int => self::ISSUED_AT);

        $original = $verifier->verify($token, Vectors::SECRET, 'login', self::CLIENT_IP, nowNs: $record->issuedAtNs + 1_000_000, operationIdentity: $this->identity('nocap'));
        self::assertSame(VerifyError::ConsumeIndeterminate, $original->error);

        $outcome = $verifier->resumeConsumedOperation($token, Vectors::SECRET, $this->identity('nocap'), 'login', self::CLIENT_IP);
        self::assertTrue($outcome->isOk(), sprintf('the capability-less resume must derive and commit, got %s', $outcome->code()));
        self::assertNotNull($inner->consumedState($record->nonce)?->consumedResult, 'the capability-less resume commits the deterministic outcome');
    }

    // ── Claim-before-admission (the Argon lease must not leak) ────────

    public function testClaimLoserNeverTouchesTheArgonGate(): void
    {
        // The claim is acquired before the Argon
        // admission gate. A recovery that loses the claim must never
        // have acquired an Argon capacity slot (the earlier order leaked
        // the slot for the whole lease TTL). The loser answers the
        // retryable ConsumeIndeterminate with the gate untouched.
        [$storage, $record, $token] = $this->issueAndSolveArgon();
        $storage->consumeWithOperationIdentity($record->nonce, $this->identity('gate-loser'));

        $winner = $storage->claimResumeDerivation($record->nonce);
        self::assertIsString($winner, 'precondition: the winner holds the claim');

        $counters = ['acquires' => 0, 'releases' => 0, 'live' => 0];
        $gate = $this->countingGate(1, $counters);
        $outcome = (new Verifier($storage, $gate))->resumeConsumedOperation($token, Vectors::SECRET, $this->identity('gate-loser'), 'login', self::CLIENT_IP);
        self::assertSame(VerifyError::ConsumeIndeterminate, $outcome->error, 'the claim loser must answer ConsumeIndeterminate, never derive');
        self::assertSame(0, $counters['acquires'], 'the claim loser must NEVER acquire an Argon capacity slot');
        self::assertSame(0, $counters['releases'], 'with no acquire there is nothing to release');
        self::assertSame(0, $counters['live'], 'no Argon permit may be live after the loser returns');
        self::assertNull($storage->consumedState($record->nonce)?->consumedResult, 'the loser must not commit anything');
    }

    public function testClaimBackendExceptionReturnsStorageUnavailableWithoutTouchingTheArgonGate(): void
    {
        // The claim-backend-exception branch: a storage whose
        // claimResumeDerivation throws fails closed to
        // StorageUnavailable (never an unsynchronized derive storm),
        // and the failure happens before the Argon gate — no capacity
        // slot is ever acquired.
        [$inner, $record, $token] = $this->issueAndSolveArgon();
        $inner->consumeWithOperationIdentity($record->nonce, $this->identity('claim-throw'));

        $storage = new class($inner) implements StorageInterface, \KiwiCaptcha\ConsumedStateReadableInterface, \KiwiCaptcha\ResumeDerivationClaimInterface {
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

            public function commitResult(string $nonce, bool $valid, ?string $binding): bool
            {
                return $this->inner->commitResult($nonce, $valid, $binding);
            }

            public function delete(string $nonce): void
            {
                $this->inner->delete($nonce);
            }

            public function claimResumeDerivation(string $nonce, int $ttlSecs = 60): ?string
            {
                throw new \RuntimeException('claim storage down');
            }

            public function releaseResumeDerivation(string $nonce, string $owner): bool
            {
                return $this->inner->releaseResumeDerivation($nonce, $owner);
            }

            public function commitResultResume(string $nonce, bool $valid, ?string $binding, string $owner): bool
            {
                return $this->inner->commitResultResume($nonce, $valid, $binding, $owner);
            }
        };

        $counters = ['acquires' => 0, 'releases' => 0, 'live' => 0];
        $gate = $this->countingGate(1, $counters);
        $outcome = (new Verifier($storage, $gate))->resumeConsumedOperation($token, Vectors::SECRET, $this->identity('claim-throw'), 'login', self::CLIENT_IP);
        self::assertSame(VerifyError::StorageUnavailable, $outcome->error, 'a claim-backend failure must fail closed to StorageUnavailable');
        self::assertSame(0, $counters['acquires'], 'the claim failure must NOT reach the Argon gate');
        self::assertSame(0, $counters['releases']);
        self::assertSame(0, $counters['live'], 'no Argon permit may be live after the claim failure');
        self::assertNull($inner->consumedState($record->nonce)?->consumedResult, 'nothing is committed on the claim failure');
    }

    public function testClaimWinnerAcquiresAndReleasesExactlyOneArgonLease(): void
    {
        // The winner path: the claim is held, exactly one Argon slot is
        // acquired, the derivation runs, the commit lands, and the
        // finally releases the lease — live permits are back to zero
        // after completion.
        [$storage, $record, $token] = $this->issueAndSolveArgon();
        $storage->consumeWithOperationIdentity($record->nonce, $this->identity('gate-winner'));

        $counters = ['acquires' => 0, 'releases' => 0, 'live' => 0];
        $gate = $this->countingGate(1, $counters);
        $outcome = (new Verifier($storage, $gate))->resumeConsumedOperation($token, Vectors::SECRET, $this->identity('gate-winner'), 'login', self::CLIENT_IP);
        self::assertTrue($outcome->isOk(), sprintf('the winner must derive and commit, got %s', $outcome->code()));
        self::assertSame(1, $counters['acquires'], 'the winner acquires exactly one Argon slot');
        self::assertSame(1, $counters['releases'], 'the winner releases exactly one lease');
        self::assertSame(0, $counters['live'], 'no Argon permit may be live after the winner returns');
        self::assertNotNull($storage->consumedState($record->nonce)?->consumedResult, 'the winner committed the deterministic outcome');
    }

    public function testCapacityExceededWithAHeldClaimReleasesTheClaim(): void
    {
        // The claim is held when the admission gate refuses: the resume
        // must return CapacityExceeded AND release the claim it held
        // (the finally covers the admission refusals too). A capacity
        // loser must never leave a 60s poison claim behind: a
        // subsequent resume on the same nonce can claim immediately.
        [$storage, $record, $token] = $this->issueAndSolveArgon();
        $storage->consumeWithOperationIdentity($record->nonce, $this->identity('gate-capacity'));

        $counters = ['acquires' => 0, 'releases' => 0, 'live' => 1];
        $gate = $this->countingGate(1, $counters);
        $outcome = (new Verifier($storage, $gate))->resumeConsumedOperation($token, Vectors::SECRET, $this->identity('gate-capacity'), 'login', self::CLIENT_IP);
        self::assertSame(VerifyError::CapacityExceeded, $outcome->error, 'the saturated gate refuses the resumed Argon derivation');
        self::assertSame(1, $counters['acquires'], 'the refusal attempted exactly one acquire');
        self::assertSame(0, $counters['releases'], 'the refused acquire held no lease to release');
        self::assertSame(1, $counters['live'], 'the outside slot is the only live permit');
        self::assertNull($storage->consumedState($record->nonce)?->consumedResult, 'capacity exhaustion must NOT commit anything');

        // The audit contract: the CapacityExceeded loser did NOT leave
        // the claim held — a fresh claim on the same nonce succeeds
        // immediately, no 60s poison.
        $reclaimed = $storage->claimResumeDerivation($record->nonce);
        self::assertIsString($reclaimed, 'a claim must succeed immediately after a CapacityExceeded return');
        $storage->releaseResumeDerivation($record->nonce, $reclaimed);

        // With capacity freed, the next resume claims again, derives
        // and commits, and releases everything.
        $counters['live'] = 0;
        $outcome = (new Verifier($storage, $gate))->resumeConsumedOperation($token, Vectors::SECRET, $this->identity('gate-capacity'), 'login', self::CLIENT_IP);
        self::assertTrue($outcome->isOk(), sprintf('with capacity available the resume must derive and commit, got %s', $outcome->code()));
        self::assertSame(2, $counters['acquires']);
        self::assertSame(1, $counters['releases']);
        self::assertSame(0, $counters['live'], 'no Argon permit may be live after the successful resume');
        self::assertNotNull($storage->consumedState($record->nonce)?->consumedResult);
    }

    public function testArrayStorageClaimExpiresAndIsReclaimable(): void
    {
        // Bug 3: the in-process claim carries the same bounded-lease
        // contract as the Redis backend. resume_until is now + TTL; a
        // claim whose lease expired is re-claimable (the release-less
        // crash path: a crashed recovery vanishes, its lease expires
        // with the clock), and a stale owner whose lease expired can
        // never commit. The clock advances through the $now closure.
        $clock = self::ISSUED_AT;
        $now = static function () use (&$clock): int {
            return $clock;
        };
        $storage = new ArrayStorage(now: $now);
        $issuer = new Issuer(new Config(secretKey: Vectors::SECRET, targetBits: 8, ttlSecs: 120, minDurationMs: 0), $storage, now: static fn (): int => self::ISSUED_AT);
        $challenge = $issuer->issue('login', self::CLIENT_IP);
        $record = $storage->find($challenge->nonce);
        self::assertNotNull($record);
        $storage->consumeWithOperationIdentity($record->nonce, $this->identity('claim-ttl'));

        $owner = $storage->claimResumeDerivation($record->nonce, 60);
        self::assertIsString($owner, 'a consumed, resultless record is claimable');
        self::assertNull($storage->claimResumeDerivation($record->nonce), 'a live claim is refused');
        self::assertFalse($storage->commitResultResume($record->nonce, true, null, str_repeat('b', 32)), 'a different owner can never commit');

        // The release-less crash path: no release, the clock advances
        // past the lease.
        $clock += 61;
        self::assertNull($storage->consumedState($record->nonce)?->consumedResult, 'nothing was committed by the crashed recovery');
        $reclaimed = $storage->claimResumeDerivation($record->nonce);
        self::assertIsString($reclaimed, 'an expired claim is re-claimable');
        self::assertFalse($storage->commitResultResume($record->nonce, true, null, $owner), 'the stale owner whose lease expired can never commit');
        self::assertNull($storage->consumedState($record->nonce)?->consumedResult, 'the stale commit writes nothing');
        self::assertTrue($storage->commitResultResume($record->nonce, true, null, $reclaimed), 'the fresh owner commits');
        self::assertNotNull($storage->consumedState($record->nonce)?->consumedResult);
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

    // ── The configurable resume-claim TTL ──────────────────────────────

    public function testResumeClaimTtlDefaultsToSixtyAndIsConfigurable(): void
    {
        // The claim lease must cover the maximum supported derivation
        // duration; a severely CPU-starved host could exceed the 60s
        // default in one derivation, so the constructor parameter lets
        // the bundle wire a `resume_claim_ttl_secs` config value in
        // (fencing stays correct on expiry either way). The default
        // keeps the Rust `CLAIM_TTL_SECS` mirror at 60, and a custom
        // value reaches the storage's claimResumeDerivation() verbatim.
        [$inner, $record, $token] = $this->issueAndSolveArgon();
        $inner->consumeWithOperationIdentity($record->nonce, $this->identity('claim-ttl'));

        $defaults = new class($inner) implements StorageInterface, \KiwiCaptcha\ConsumedStateReadableInterface, \KiwiCaptcha\ResumeDerivationClaimInterface {
            public ?int $lastTtl = null;

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

            public function commitResult(string $nonce, bool $valid, ?string $binding): bool
            {
                return $this->inner->commitResult($nonce, $valid, $binding);
            }

            public function delete(string $nonce): void
            {
                $this->inner->delete($nonce);
            }

            public function claimResumeDerivation(string $nonce, int $ttlSecs = 60): ?string
            {
                $this->lastTtl = $ttlSecs;

                return $this->inner->claimResumeDerivation($nonce, $ttlSecs);
            }

            public function releaseResumeDerivation(string $nonce, string $owner): bool
            {
                return $this->inner->releaseResumeDerivation($nonce, $owner);
            }

            public function commitResultResume(string $nonce, bool $valid, ?string $binding, string $owner): bool
            {
                return $this->inner->commitResultResume($nonce, $valid, $binding, $owner);
            }
        };

        $outcome = (new Verifier($defaults))->resumeConsumedOperation($token, Vectors::SECRET, $this->identity('claim-ttl'), 'login', self::CLIENT_IP);
        self::assertTrue($outcome->isOk(), sprintf('the default-TTL resume must derive and commit, got %s', $outcome->code()));
        self::assertSame(60, $defaults->lastTtl, 'the default claim TTL keeps the Rust CLAIM_TTL_SECS mirror at 60');

        // A second record: the first resume already committed its
        // deterministic result, and a committed record resolves through
        // the fast path without ever claiming.
        [$inner2, $record2, $token2] = $this->issueAndSolveArgon();
        $inner2->consumeWithOperationIdentity($record2->nonce, $this->identity('claim-ttl-configured'));
        $configured = new class($inner2) implements StorageInterface, \KiwiCaptcha\ConsumedStateReadableInterface, \KiwiCaptcha\ResumeDerivationClaimInterface {
            public ?int $lastTtl = null;

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

            public function commitResult(string $nonce, bool $valid, ?string $binding): bool
            {
                return $this->inner->commitResult($nonce, $valid, $binding);
            }

            public function delete(string $nonce): void
            {
                $this->inner->delete($nonce);
            }

            public function claimResumeDerivation(string $nonce, int $ttlSecs = 60): ?string
            {
                $this->lastTtl = $ttlSecs;

                return $this->inner->claimResumeDerivation($nonce, $ttlSecs);
            }

            public function releaseResumeDerivation(string $nonce, string $owner): bool
            {
                return $this->inner->releaseResumeDerivation($nonce, $owner);
            }

            public function commitResultResume(string $nonce, bool $valid, ?string $binding, string $owner): bool
            {
                return $this->inner->commitResultResume($nonce, $valid, $binding, $owner);
            }
        };

        $outcome = (new Verifier($configured, resumeClaimTtlSecs: 300))->resumeConsumedOperation($token2, Vectors::SECRET, $this->identity('claim-ttl-configured'), 'login', self::CLIENT_IP);
        self::assertTrue($outcome->isOk(), sprintf('the configured-TTL resume must derive and commit, got %s', $outcome->code()));
        self::assertSame(300, $configured->lastTtl, 'the configured claim TTL reaches the storage verbatim');
    }

    public function testResumeClaimTtlBelowOneRejectedAtConstruction(): void
    {
        // The core minimum is 1 second: the storage boundary rejects a
        // claim TTL below 1, and the verifier enforces the same floor
        // at construction, so a non-functional lease can never be
        // built (the bundle production policy stays >= 60 via its
        // Symfony config node).
        foreach ([0, -1, -60] as $bad) {
            try {
                new Verifier(new ArrayStorage(), resumeClaimTtlSecs: $bad);
                self::fail('a resume claim TTL below 1 must be rejected at construction');
            } catch (\InvalidArgumentException) {
                // expected
            }
        }
        self::assertTrue(true);
    }

    public function testResumeClaimTtlOneIsAcceptedAsTheCoreMinimum(): void
    {
        // 1 second is the documented core minimum, accepted by both
        // the storage boundary and the verifier. The claim TTL is an
        // efficiency bound; fencing stays correct on expiry either
        // way, while the bundle production policy keeps >= 60 in
        // real deployments.
        $verifier = new Verifier(new ArrayStorage(), resumeClaimTtlSecs: 1);
        self::assertInstanceOf(Verifier::class, $verifier);
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
