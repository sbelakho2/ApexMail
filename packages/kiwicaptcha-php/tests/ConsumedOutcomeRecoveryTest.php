<?php

declare(strict_types=1);

namespace KiwiCaptcha\Tests;

use KiwiCaptcha\Config;
use KiwiCaptcha\ConsumedOutcomeRecovery;
use KiwiCaptcha\Issuer;
use KiwiCaptcha\SolutionToken;
use KiwiCaptcha\Storage\ArrayStorage;
use KiwiCaptcha\Verifier;
use KiwiCaptcha\VerifyError;
use KiwiCaptcha\Tests\Fixtures\Vectors;
use PHPUnit\Framework\TestCase;

/**
 * The identity gate of the retained-outcome recovery API. The stored
 * valid outcome of a consumed token is an authorization grant, handed
 * out only to a caller that proves the exact logical operation,
 * the same operation identity the pending-to-consumed transition
 * recorded, compared in constant time. Any caller holding only the raw
 * token, an unauthenticated replay, must never receive the stored
 * success. A mismatched or absent identity maps to the AlreadyConsumed
 * error outcome; an unknown token or an uncommitted result maps to
 * null, nothing recoverable; and a stored invalid outcome replays
 * deterministically
 * to any caller exactly like the core's replay path.
 */
final class ConsumedOutcomeRecoveryTest extends TestCase
{
    private const ISSUED_AT = 1_800_000_000;

    private const IDENTITY_A = 'op-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';

    private const IDENTITY_B = 'op-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';

    /** @return array{0: ArrayStorage, 1: string} */
    private function consumedWithStoredValid(string $identity): array
    {
        [$storage, $token] = $this->issuedAndSolved();
        $verifier = new Verifier($storage, now: static fn (): int => self::ISSUED_AT);
        $outcome = $verifier->verify($token, Vectors::SECRET, 'login', '198.51.100.7', operationIdentity: $identity);
        self::assertTrue($outcome->isOk(), sprintf('setup verification must succeed, got %s', $outcome->code()));

        return [$storage, $token];
    }

    /** @return array{0: ArrayStorage, 1: string} */
    private function issuedAndSolved(): array
    {
        $storage = new ArrayStorage();
        $issuer = new Issuer(
            new Config(secretKey: Vectors::SECRET, targetBits: 8, ttlSecs: 120, minDurationMs: 0),
            $storage,
            now: static fn (): int => self::ISSUED_AT,
        );
        $challenge = $issuer->issue('login', '198.51.100.7');
        $saltBytes = base64_decode($challenge->salt, true);
        $counter = 0;
        do {
            $hash = hash('sha256', $challenge->prefix.$counter.$saltBytes, true);
            $counter++;
        } while (Verifier::leadingZeroBits($hash) < $challenge->targetBits);
        --$counter;

        return [$storage, SolutionToken::create($challenge->nonce, $counter, 5000, [])->encode()];
    }

    public function testMatchingIdentityRecoversTheStoredOutcome(): void
    {
        [$storage, $token] = $this->consumedWithStoredValid(self::IDENTITY_A);
        $recovery = new ConsumedOutcomeRecovery($storage);

        $outcome = $recovery->recover($token, self::IDENTITY_A);
        self::assertNotNull($outcome);
        self::assertTrue($outcome->isOk(), 'the proven identity recovers the stored success');
        self::assertTrue($outcome->fromStoredResult, 'the recovery is the stored committed result, never a fresh derivation');
    }

    public function testMismatchedIdentityNeverRecoversTheStoredSuccess(): void
    {
        [$storage, $token] = $this->consumedWithStoredValid(self::IDENTITY_A);
        $recovery = new ConsumedOutcomeRecovery($storage);

        // A different logical operation's identity: the AlreadyConsumed
        // error outcome — never the stored valid outcome.
        $outcome = $recovery->recover($token, self::IDENTITY_B);
        self::assertNotNull($outcome);
        self::assertFalse($outcome->isOk());
        self::assertSame(VerifyError::AlreadyConsumed, $outcome->error);
    }

    public function testTheRawTokenAloneIsNeverASufficientProof(): void
    {
        // The replay-oracle probe: possession of the raw token (and even
        // of the nonce it encodes) must not yield the stored success. The
        // API has no identity-free path — the token-derived pseudo
        // identity (what the Symfony validator's fallback derivation
        // would produce) is NOT the identity the consume recorded, so the
        // oracle stays closed.
        [$storage, $token] = $this->consumedWithStoredValid(self::IDENTITY_A);
        $recovery = new ConsumedOutcomeRecovery($storage);
        $nonce = SolutionToken::decode($token)->nonce;
        $tokenDerivedIdentity = hash('sha256', 'login'."\0".'token:'.$nonce);

        $outcome = $recovery->recover($token, $tokenDerivedIdentity);
        self::assertNotNull($outcome);
        self::assertFalse($outcome->isOk(), 'a token-derived identity is not the recorded operation identity');
        self::assertSame(VerifyError::AlreadyConsumed, $outcome->error);
    }

    public function testARecordConsumedWithoutARecordedIdentityNeverRecoversValid(): void
    {
        // Consumed by a plain consume (no identity recorded): there is no
        // identity any caller could prove, so the stored success is
        // unrecoverable through this API — any presented identity is a
        // mismatch.
        [$storage, $token] = $this->issuedAndSolved();
        $consumed = $storage->consume($token === '' ? '' : SolutionToken::decode($token)->nonce);
        self::assertNotNull($consumed);
        $storage->commitResult($consumed->record->nonce, true, null);
        $recovery = new ConsumedOutcomeRecovery($storage);

        $outcome = $recovery->recover($token, self::IDENTITY_A);
        self::assertNotNull($outcome);
        self::assertFalse($outcome->isOk(), 'no recorded identity means no provable operation');
        self::assertSame(VerifyError::AlreadyConsumed, $outcome->error);
    }

    public function testUnknownTokenYieldsNothingRecoverable(): void
    {
        $storage = new ArrayStorage();
        $recovery = new ConsumedOutcomeRecovery($storage);

        $token = 'totally-unknown';
        self::assertNull($recovery->recover($token, self::IDENTITY_A), 'an unknown/undecodable token yields null, never a valid outcome');
    }

    public function testPendingOrUncommittedRecordYieldsNothingRecoverable(): void
    {
        [$storage, $token] = $this->issuedAndSolved();
        $nonce = SolutionToken::decode($token)->nonce;
        $storage->consumeWithOperationIdentity($nonce, self::IDENTITY_A); // consumed, no result committed
        $recovery = new ConsumedOutcomeRecovery($storage);

        self::assertNull($recovery->recover($token, self::IDENTITY_A), 'a consumed-without-result record is intrinsically ambiguous — null, never valid');
    }

    public function testStoredInvalidOutcomeReplaysDeterministically(): void
    {
        [$storage, $token] = $this->issuedAndSolved();
        $nonce = SolutionToken::decode($token)->nonce;
        $storage->consumeWithOperationIdentity($nonce, self::IDENTITY_A);
        $storage->commitResult($nonce, false, null);
        $recovery = new ConsumedOutcomeRecovery($storage);

        // The deterministic invalid outcome replays to any caller exactly
        // like the core's replay path (it grants nothing).
        $outcome = $recovery->recover($token, self::IDENTITY_B);
        self::assertNotNull($outcome);
        self::assertFalse($outcome->isOk());
        self::assertSame(VerifyError::InsufficientWork, $outcome->error);
    }
}
