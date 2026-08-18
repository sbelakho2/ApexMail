<?php

declare(strict_types=1);

namespace KiwiCaptcha\Tests;

use KiwiCaptcha\ChallengeRecord;
use KiwiCaptcha\Config;
use KiwiCaptcha\ConsumedRecord;
use KiwiCaptcha\ConsumedResult;
use KiwiCaptcha\Issuer;
use KiwiCaptcha\PoWAlgorithm;
use KiwiCaptcha\SolutionToken;
use KiwiCaptcha\Storage\ArrayStorage;
use KiwiCaptcha\StorageInterface;
use KiwiCaptcha\Verifier;
use KiwiCaptcha\VerifyError;
use KiwiCaptcha\Tests\Fixtures\Vectors;
use PHPUnit\Framework\TestCase;

/**
 * CONSUMED-STATE RETRY: consume() is a one-shot TRANSITION that
 * keeps the record until its TTL — replay protection is the consumed
 * marker, not absence. The deterministic verification result
 * (consumed_result) is committed best-effort, so a retry on an
 * already-consumed record returns the SAME outcome (Valid/InsufficientWork)
 * without re-deriving; a consumed record without a committed result (crash
 * between consume and commit) is reported as ConsumeIndeterminate.
 */
final class ConsumedStateRetryTest extends TestCase
{
    private const ISSUED_AT = 1_800_000_000;

    /** @return array{0: ArrayStorage, 1: ChallengeRecord, 2: string} */
    private function issueAndSolve(int $targetBits = 8): array
    {
        $storage = new ArrayStorage();
        $issuer = new Issuer(
            new Config(secretKey: Vectors::SECRET, targetBits: $targetBits, ttlSecs: 120, minDurationMs: 0),
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

    // ── Storage-level transition semantics (ArrayStorage mirror) ─────────

    public function testConsumeTransitionSemantics(): void
    {
        [$storage, $record] = $this->issueAndSolve();
        $storage->store($record);
        $nonce = $record->nonce;

        $winner = $storage->consume($nonce);
        self::assertNotNull($winner);
        self::assertInstanceOf(ConsumedRecord::class, $winner);
        self::assertTrue($winner->consumedNow);
        self::assertFalse($winner->consumedBefore);
        self::assertNull($winner->consumedResult);

        $retry = $storage->consume($nonce);
        self::assertNotNull($retry, 'the consumed record is KEPT until its TTL — replay protection is the marker, not absence');
        self::assertFalse($retry->consumedNow);
        self::assertTrue($retry->consumedBefore);
        self::assertNull($retry->consumedResult, 'nothing committed yet');
        self::assertSame($record->nonce, $retry->record->nonce);
        self::assertNotNull($storage->find($nonce), 'find still sees the consumed record');

        self::assertNull($storage->consume('never-stored'));
    }

    public function testCommitResultRules(): void
    {
        [$storage, $record] = $this->issueAndSolve();
        $storage->store($record);
        $nonce = $record->nonce;

        self::assertFalse($storage->commitResult($nonce, true, 'txn'), 'commit on a PENDING record must fail');
        $storage->consume($nonce);

        self::assertTrue($storage->commitResult($nonce, true, 'txn-9'));
        self::assertFalse($storage->commitResult($nonce, false, null), 'a second commit must be rejected');
        self::assertFalse($storage->commitResult('never-stored', true, null), 'commit on a missing record must fail');

        $retry = $storage->consume($nonce);
        self::assertNotNull($retry);
        self::assertInstanceOf(ConsumedResult::class, $retry->consumedResult);
        self::assertTrue($retry->consumedResult->valid);
        self::assertSame('txn-9', $retry->consumedResult->binding);
    }

    public function testConsumedResultRoundTripsThroughJson(): void
    {
        $result = new ConsumedResult(true, 'txn-1');
        $restored = ConsumedResult::fromArray($result->toArray());

        self::assertTrue($restored->valid);
        self::assertSame('txn-1', $restored->binding);

        $nullBinding = ConsumedResult::fromArray(['valid' => false, 'binding' => null]);
        self::assertFalse($nullBinding->valid);
        self::assertNull($nullBinding->binding);
    }

    public function testDeleteRemovesConsumedRecordsToo(): void
    {
        [$storage, $record] = $this->issueAndSolve();
        $storage->store($record);
        $storage->consume($record->nonce);
        $storage->commitResult($record->nonce, true, null);

        $storage->delete($record->nonce);

        self::assertNull($storage->find($record->nonce));
        self::assertNull($storage->consume($record->nonce), 'a deleted record is gone — retries see RecordNotFound');
    }

    // ── Verifier-level retry semantics ──────────────────────────────────

    public function testReplayOfAValidOutcomeReturnsValidWithoutRedoingWork(): void
    {
        [$storage, $record, $token] = $this->issueAndSolve();
        $verifier = new Verifier($storage, now: static fn (): int => self::ISSUED_AT);

        $first = $verifier->verify($token, Vectors::SECRET, 'login', '198.51.100.7', nowNs: $record->issuedAtNs + 1_000_000);
        self::assertTrue($first->isOk());

        // The committed stored outcome replays on a retry.
        $retry = $verifier->verify($token, Vectors::SECRET, 'login', '198.51.100.7', nowNs: $record->issuedAtNs + 1_000_000);
        self::assertTrue($retry->isOk(), sprintf('a retry must replay the committed Valid outcome, got %s', $retry->code()));
        self::assertSame($record->nonce, $retry->nonce());
        self::assertNotNull($storage->find($record->nonce), 'the consumed record is kept until its TTL');
    }

    public function testReplayOfAnInvalidOutcomeReturnsInsufficientWork(): void
    {
        [$storage, $record, $token] = $this->issueAndSolve();
        $verifier = new Verifier($storage, now: static fn (): int => self::ISSUED_AT);

        // Provably wrong counter.
        $wrongCounter = 1;
        $saltBytes = base64_decode($record->salt, true);
        while (Verifier::leadingZeroBits(hash('sha256', $record->prefix.$wrongCounter.$saltBytes, true)) >= $record->targetBits) {
            ++$wrongCounter;
        }
        $wrongToken = SolutionToken::create($record->nonce, $wrongCounter, 5000, [])->encode();

        $first = $verifier->verify($wrongToken, Vectors::SECRET, 'login', '198.51.100.7');
        self::assertSame(VerifyError::InsufficientWork, $first->error);

        // The correct token retries into the STORED invalid outcome — no
        // re-derivation, same InsufficientWork.
        $second = $verifier->verify($token, Vectors::SECRET, 'login', '198.51.100.7');
        self::assertSame(VerifyError::InsufficientWork, $second->error, 'a retry must replay the committed invalid outcome');
    }

    public function testConsumedWithoutCommittedResultIsIndeterminate(): void
    {
        // Crash between consume and commit: the record is consumed but no
        // result was stored. The verifier reports ConsumeIndeterminate — the
        // caller treats it as ambiguous (never re-derives, never replays).
        [$storage, $record, $token] = $this->issueAndSolve();
        $storage->store($record);
        $consumed = $storage->consume($record->nonce);
        self::assertTrue($consumed->consumedNow);
        // Simulated crash: the record is consumed but commitResult never ran.

        $verifier = new Verifier($storage, now: static fn (): int => self::ISSUED_AT);
        $outcome = $verifier->verify($token, Vectors::SECRET, 'login', '198.51.100.7');

        self::assertSame(VerifyError::ConsumeIndeterminate, $outcome->error);
    }

    public function testCommitResultFailureNeverChangesTheValidOutcome(): void
    {
        // Best-effort commit: a throwing storage must not turn Valid into a
        // failure — the outcome stands, the record stays consumed without a
        // result (a retry degrades to ConsumeIndeterminate, which is safer
        // than re-deriving a wrong outcome).
        [$base, $record, $token] = $this->issueAndSolve();
        $storage = new class($base) implements StorageInterface {
            public bool $threw = false;

            public function __construct(private ArrayStorage $inner)
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
                return null;
            }

            public function consume(string $nonce): ?ConsumedRecord
            {
                return $this->inner->consume($nonce);
            }

            public function commitResult(string $nonce, bool $valid, ?string $binding): bool
            {
                $this->threw = true;
                throw new \RuntimeException('storage down');
            }

            public function delete(string $nonce): void
            {
                $this->inner->delete($nonce);
            }
        };

        $verifier = new Verifier($storage, now: static fn (): int => self::ISSUED_AT);
        $outcome = $verifier->verify($token, Vectors::SECRET, 'login', '198.51.100.7', nowNs: $record->issuedAtNs + 1_000_000);

        self::assertTrue($outcome->isOk(), sprintf('a best-effort commit failure must NOT change the outcome, got %s', $outcome->code()));
        self::assertTrue($storage->threw, 'precondition: commitResult was attempted');

        $retry = $verifier->verify($token, Vectors::SECRET, 'login', '198.51.100.7');
        self::assertSame(VerifyError::ConsumeIndeterminate, $retry->error, 'without a committed result the retry is ambiguous');
    }

    public function testCommitResultFailureNeverChangesTheInvalidOutcome(): void
    {
        [$base, $record] = $this->issueAndSolve();
        $storage = new class($base) implements StorageInterface {
            public function __construct(private ArrayStorage $inner)
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
                return null;
            }

            public function consume(string $nonce): ?ConsumedRecord
            {
                return $this->inner->consume($nonce);
            }

            public function commitResult(string $nonce, bool $valid, ?string $binding): bool
            {
                throw new \RuntimeException('storage down');
            }

            public function delete(string $nonce): void
            {
                $this->inner->delete($nonce);
            }
        };

        $wrongCounter = 1;
        $saltBytes = base64_decode($record->salt, true);
        while (Verifier::leadingZeroBits(hash('sha256', $record->prefix.$wrongCounter.$saltBytes, true)) >= $record->targetBits) {
            ++$wrongCounter;
        }
        $wrongToken = SolutionToken::create($record->nonce, $wrongCounter, 5000, [])->encode();

        $verifier = new Verifier($storage, now: static fn (): int => self::ISSUED_AT);
        $outcome = $verifier->verify($wrongToken, Vectors::SECRET, 'login', '198.51.100.7');

        self::assertSame(VerifyError::InsufficientWork, $outcome->error, 'a best-effort commit failure must NOT change the invalid outcome');
    }
}
