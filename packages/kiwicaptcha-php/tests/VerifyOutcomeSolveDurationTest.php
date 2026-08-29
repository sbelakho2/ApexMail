<?php

declare(strict_types=1);

namespace KiwiCaptcha\Tests;

use KiwiCaptcha\Config;
use KiwiCaptcha\Issuer;
use KiwiCaptcha\PoWAlgorithm;
use KiwiCaptcha\SolutionToken;
use KiwiCaptcha\Storage\RedisStorage;
use KiwiCaptcha\Verifier;
use KiwiCaptcha\VerifyError;
use KiwiCaptcha\VerifyOutcome;
use KiwiCaptcha\Tests\Fixtures\FakePredisClient;
use KiwiCaptcha\Tests\Fixtures\Vectors;
use PHPUnit\Framework\TestCase;

/**
 * The server-measured solve duration exposed on valid outcomes, see
 * {@see \KiwiCaptcha\VerifyOutcome::solveDurationMs()}: computed from
 * the record's issued_at_ns and the verification receipt clock only,
 * never the client-reported token duration. The exact
 * skew-tolerance semantics of the minimum-duration floor apply: a
 * receipt preceding issuance within the 5s tolerance is unmeasurable
 * (null), and beyond it the record is TooFast, never a valid outcome
 * at all. Null on every non-valid outcome; purely additive.
 */
final class VerifyOutcomeSolveDurationTest extends TestCase
{
    private const ISSUED_AT = 1_800_000_000;

    private const CLIENT_IP = '198.51.100.7';

    /**
     * Issue a protocol-v2 SHA-256 challenge (floor 0, so the TooFast
     * gate never interferes with the skew scenarios) and solve it.
     *
     * @return array{0: RedisStorage, 1: \KiwiCaptcha\ChallengeRecord, 2: string}
     */
    private function issueAndSolve(FakePredisClient $client, string $prefix): array
    {
        $storage = new RedisStorage($client, $prefix);
        $issuer = new Issuer(
            new Config(
                secretKey: Vectors::SECRET,
                algorithm: PoWAlgorithm::Sha256,
                mKib: 0,
                t: 1,
                p: 1,
                targetBits: 8,
                argon2TargetBits: 8,
                ttlSecs: 120,
                minDurationMs: 0,
            ),
            $storage,
            now: static fn (): int => self::ISSUED_AT,
        );
        $challenge = $issuer->issue('login', self::CLIENT_IP);
        $record = $storage->find($challenge->nonce);
        self::assertNotNull($record);
        self::assertGreaterThan(0, $record->issuedAtNs, 'the issued record carries the issuance clock');

        $saltBytes = base64_decode($challenge->salt, true);
        $counter = 0;
        do {
            $hash = hash('sha256', $challenge->prefix.$counter.$saltBytes, true);
            $counter++;
        } while (Verifier::leadingZeroBits($hash) < $challenge->targetBits);
        --$counter;

        // The token reports a client-chosen 5000ms duration: the exposed
        // duration must never be this forgeable value.
        return [$storage, $record, SolutionToken::create($challenge->nonce, $counter, 5000, [])->encode()];
    }

    private function verifier(RedisStorage $storage): Verifier
    {
        return new Verifier($storage, now: static fn (): int => self::ISSUED_AT);
    }

    public function testFreshValidOutcomeCarriesTheServerMeasuredDuration(): void
    {
        if (!\class_exists(\Predis\Client::class)) {
            self::markTestSkipped('predis/predis is not installed');
        }
        $client = new FakePredisClient();
        [$storage, $record, $token] = $this->issueAndSolve($client, 'dur-');

        // Receipt 1.5s after issuance (well past any floor; the token's
        // forged 5000ms is ignored).
        $outcome = $this->verifier($storage)->verify(
            $token,
            Vectors::SECRET,
            'login',
            self::CLIENT_IP,
            nowNs: $record->issuedAtNs + 1_500_000,
        );

        self::assertTrue($outcome->isOk(), sprintf('expected valid, got %s', $outcome->code()));
        self::assertSame(1500, $outcome->solveDurationMs(), 'the duration is the server-measured span, not the client-reported 5000ms');
        self::assertFalse($outcome->fromStoredResult);
    }

    public function testSubMillisecondSpansFloorTowardZero(): void
    {
        if (!\class_exists(\Predis\Client::class)) {
            self::markTestSkipped('predis/predis is not installed');
        }
        $client = new FakePredisClient();
        [$storage, $record, $token] = $this->issueAndSolve($client, 'dur-floor-');

        $outcome = $this->verifier($storage)->verify(
            $token,
            Vectors::SECRET,
            'login',
            self::CLIENT_IP,
            nowNs: $record->issuedAtNs + 1_234_567,
        );

        self::assertTrue($outcome->isOk());
        self::assertSame(1234, $outcome->solveDurationMs(), 'sub-millisecond precision floors (1234.567ms -> 1234)');
    }

    public function testReceiptPrecedingIssuanceWithinTheSkewToleranceIsUnmeasurable(): void
    {
        if (!\class_exists(\Predis\Client::class)) {
            self::markTestSkipped('predis/predis is not installed');
        }
        $client = new FakePredisClient();
        [$storage, $record, $token] = $this->issueAndSolve($client, 'dur-skew-');

        // Receipt 2s before issuance: within the 5s skew tolerance the
        // two hosts' clocks are unsynced, so the elapsed time cannot be
        // measured reliably — exactly the semantics of the
        // minimum-duration floor's skip. The verification itself still
        // succeeds (the PoW check applies); the duration is null.
        $outcome = $this->verifier($storage)->verify(
            $token,
            Vectors::SECRET,
            'login',
            self::CLIENT_IP,
            nowNs: $record->issuedAtNs - 2_000_000,
        );

        self::assertTrue($outcome->isOk(), 'the skew window keeps the verification valid (floor skipped, PoW still applies)');
        self::assertNull($outcome->solveDurationMs(), 'a receipt preceding issuance within the skew tolerance is unmeasurable');
    }

    public function testReplayOfAStoredSuccessCarriesTheDurationToo(): void
    {
        if (!\class_exists(\Predis\Client::class)) {
            self::markTestSkipped('predis/predis is not installed');
        }
        $client = new FakePredisClient();
        [$storage, $record, $token] = $this->issueAndSolve($client, 'dur-replay-');
        $identity = 'op-'.hash('sha256', 'solve-duration-replay');
        $storage->consumeWithOperationIdentity($record->nonce, $identity);
        self::assertTrue($storage->commitResult($record->nonce, true, null));

        $outcome = $this->verifier($storage)->verify(
            $token,
            Vectors::SECRET,
            'login',
            self::CLIENT_IP,
            nowNs: $record->issuedAtNs + 30_000_000,
            operationIdentity: $identity,
        );

        self::assertTrue($outcome->isOk(), sprintf('the identity-proven replay resolves the stored success, got %s', $outcome->code()));
        self::assertTrue($outcome->fromStoredResult, 'the replay comes from the stored result');
        self::assertSame(30_000, $outcome->solveDurationMs(), 'the replay-of-valid path carries the server-measured span to its own receipt');
    }

    public function testNonValidOutcomesNeverCarryADuration(): void
    {
        if (!\class_exists(\Predis\Client::class)) {
            self::markTestSkipped('predis/predis is not installed');
        }
        $client = new FakePredisClient();
        [$storage, $record, $token] = $this->issueAndSolve($client, 'dur-invalid-');

        // A replay of a stored success without the operation identity is
        // refused (AlreadyConsumed) — no duration.
        $storage->consume($record->nonce);
        self::assertTrue($storage->commitResult($record->nonce, true, null));
        $refused = $this->verifier($storage)->verify(
            $token,
            Vectors::SECRET,
            'login',
            self::CLIENT_IP,
            nowNs: $record->issuedAtNs + 30_000_000,
        );
        self::assertSame(VerifyError::AlreadyConsumed, $refused->error);
        self::assertNull($refused->solveDurationMs(), 'a non-valid outcome never carries a duration');

        // A cheap-failure verdict (wrong scope) on a fresh challenge —
        // no duration either.
        $client2 = new FakePredisClient();
        [$storage2, $record2, $token2] = $this->issueAndSolve($client2, 'dur-scope-');
        $wrongScope = $this->verifier($storage2)->verify(
            $token2,
            Vectors::SECRET,
            'checkout',
            self::CLIENT_IP,
            nowNs: $record2->issuedAtNs + 1_000_000,
        );
        self::assertSame(VerifyError::WrongScope, $wrongScope->error);
        self::assertNull($wrongScope->solveDurationMs(), 'a non-valid outcome never carries a duration');
    }

    public function testOutcomeWithoutADurationBehavesLikeBefore(): void
    {
        // The additive contract: an unmeasurable duration is null, never
        // zero and never an error — older consumers that ignore the
        // field see exactly the pre-change behavior.
        $outcome = VerifyOutcome::valid('nonce', null);
        self::assertNull($outcome->solveDurationMs());
        self::assertNull(VerifyOutcome::invalid(VerifyError::Expired)->solveDurationMs());
        self::assertTrue($outcome->isOk());
    }
}
