<?php

declare(strict_types=1);

namespace KiwiCaptcha\Tests;

use KiwiCaptcha\ChallengeRecord;
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
 * CONSUMED-OPERATION RESUME (resumeConsumedOperation): the narrowly
 * authorized crash-recovery path for the Siteverify takeover. The atomic
 * pending→consumed transition landed and recorded the logical-operation
 * identity, but the derivation/commit reply was lost — consumed_result
 * stays null forever for the ordinary verifier (ConsumeIndeterminate).
 * A caller that has PROVEN the retained consumed record's exact operation
 * identity belongs to this logical operation may RESUME the derivation,
 * revalidate every immutable security property exactly like the ordinary
 * verify path, and commit the deterministic outcome.
 */
final class VerifierResumeTest extends TestCase
{
    private const ISSUED_AT = 1_800_000_000;

    private const CLIENT_IP = '198.51.100.7';

    /** @return array{0: ArrayStorage, 1: ChallengeRecord, 2: string} */
    private function issueAndSolve(int $targetBits = 8): array
    {
        $storage = new ArrayStorage();
        $issuer = new Issuer(
            new Config(secretKey: Vectors::SECRET, targetBits: $targetBits, ttlSecs: 120, minDurationMs: 0),
            $storage,
            now: static fn (): int => self::ISSUED_AT,
        );
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

    // ── The lost-reply storage seam ─────────────────────────────────────

    /**
     * A storage whose atomic consumeWithOperationIdentity() DELEGATES —
     * the pending→consumed transition REALLY executes and the identity
     * lands atomically with the state flip — and THEN throws: the
     * lost-reply seam (the wire failure that produces ConsumeIndeterminate
     * even though the transition landed). commitResult() can be armed the
     * same way: the commit REALLY lands and the reply is then lost,
     * exercising the resume's read-after-failed-commit path.
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
                // The transition EXECUTES first — the identity lands
                // atomically with the state flip — and the reply is then
                // lost.
                $result = $this->inner->consumeWithOperationIdentity($nonce, $operationIdentity);
                if ($this->consumeReplyLost) {
                    throw new \RuntimeException('consume reply lost after the transition');
                }

                return $result;
            }

            public function commitResult(string $nonce, bool $valid, ?string $binding): bool
            {
                // The commit EXECUTES first — the deterministic result
                // lands — and the reply is then lost.
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
        // The original attempt's consume reply is lost AFTER the
        // transition landed (the identity is recorded atomically): the
        // record is consumed-without-result — the ordinary verifier says
        // ConsumeIndeterminate forever. The identity-proven resume derives
        // and COMMITS the deterministic outcome.
        [$inner, $record, $token] = $this->issueAndSolve();
        $storage = self::lostReplyStorage($inner, true);
        $verifier = new Verifier($storage, now: static fn (): int => self::ISSUED_AT);

        // The original attempt: the identity-bearing consume EXECUTES (the
        // transition lands, the identity is recorded atomically) and the
        // reply is lost — the verifier surfaces ConsumeIndeterminate.
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

        // Deterministic: a second resume returns the SAME stored failure
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
        // gate rejects with CapacityExceeded WITHOUT committing (a later
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

    public function testResumePastSignedExpirySucceeds(): void
    {
        // The signed expiry is EXEMPT on the resume path: the operation
        // already won atomic consumption before the response was lost. A
        // resume with the verifier clock far past the signed expiry
        // derives and commits the original outcome — the exact
        // late-lifetime recovery the retained-state horizon provides.
        [$inner, $record, $token] = $this->issueAndSolve();
        $storage = self::lostReplyStorage($inner, true);
        $farFuture = static fn (): int => self::ISSUED_AT + 10_000;
        $verifier = new Verifier($storage, now: $farFuture);
        $inner->consumeWithOperationIdentity($record->nonce, $this->identity('late'));

        // Control: a FRESH pending record from the same issuer, verified
        // at the same far-future clock, is Expired — the clock really is
        // past the signed lifetime.
        $fresh = new ArrayStorage();
        $issuer = new Issuer(new Config(secretKey: Vectors::SECRET, targetBits: 8, ttlSecs: 120, minDurationMs: 0), $fresh, now: static fn (): int => self::ISSUED_AT);
        $freshChallenge = $issuer->issue('login', self::CLIENT_IP);
        $freshToken = $this->solveFresh($fresh, $freshChallenge);
        $control = (new Verifier($fresh, now: $farFuture))->verify($freshToken, Vectors::SECRET, 'login', self::CLIENT_IP);
        self::assertSame(VerifyError::Expired, $control->error, 'precondition: the clock is past the signed expiry');

        $outcome = $verifier->resumeConsumedOperation($token, Vectors::SECRET, $this->identity('late'), 'login', self::CLIENT_IP);
        self::assertTrue($outcome->isOk(), sprintf('the resume must NOT reject the past signed expiry, got %s', $outcome->code()));
        self::assertSame($record->nonce, $outcome->nonce());
        $after = $inner->consumedState($record->nonce);
        self::assertNotNull($after?->consumedResult);
        self::assertTrue($after->consumedResult->valid);
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

        // A still-PENDING record is equally refused (consumedState is
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
        // The commit reply is lost AFTER the commit lands: the resume's
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
        // commits, the second resolves the SAME stored outcome — one
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
        // the consumed-without-result record STILL returns
        // ConsumeIndeterminate — only the identity-proven resume path can
        // derive.
        [$inner, $record, $token] = $this->issueAndSolve();
        $inner->consumeWithOperationIdentity($record->nonce, $this->identity('a'));

        $outcome = (new Verifier($inner, now: static fn (): int => self::ISSUED_AT))->verify($token, Vectors::SECRET, 'login', self::CLIENT_IP);
        self::assertSame(VerifyError::ConsumeIndeterminate, $outcome->error, 'the ordinary verifier must NOT derive a consumed-without-result record');

        $resume = (new Verifier($inner))->resumeConsumedOperation($token, Vectors::SECRET, $this->identity('a'), 'login', self::CLIENT_IP);
        self::assertTrue($resume->isOk(), 'only the identity-proven resume derives');
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
}
