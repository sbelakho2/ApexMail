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
        $recovery = new ConsumedOutcomeRecovery($storage, new Verifier($storage), Vectors::SECRET);

        $outcome = $recovery->recover($token, self::IDENTITY_A);
        self::assertNotNull($outcome);
        self::assertTrue($outcome->isOk(), 'the proven identity recovers the stored success');
        self::assertTrue($outcome->fromStoredResult, 'the recovery is the stored committed result, never a fresh derivation');
    }

    public function testRecoveryWithoutTheVerifierFailsTheStoredSuccessClosed(): void
    {
        // The stored success carries a server-state MAC; a recovery
        // that cannot check it (no verifier/secret) on a storage that
        // carries authenticated results never releases the grant.
        [$storage, $token] = $this->consumedWithStoredValid(self::IDENTITY_A);
        $outcome = (new ConsumedOutcomeRecovery($storage))->recover($token, self::IDENTITY_A);
        self::assertNotNull($outcome);
        self::assertSame(VerifyError::MalformedRecord, $outcome->error);
    }

    public function testAForgedStoredSuccessIsNeverRecovered(): void
    {
        // A storage writer consumes a pending record under its own
        // identity and commits valid=true without a MAC (it holds no
        // master secret), or with a wrong-key MAC: both are refused.
        foreach ([null, str_repeat('ab', 32)] as $mac) {
            [$storage, $token] = $this->issuedAndSolved();
            $nonce = SolutionToken::decode($token)->nonce;
            self::assertNotNull($storage->consumeWithOperationIdentity($nonce, self::IDENTITY_A));
            self::assertTrue($storage->commitAuthenticatedResult($nonce, new \KiwiCaptcha\ConsumedResult(true, null, $mac)));

            $outcome = (new ConsumedOutcomeRecovery($storage, new Verifier($storage), Vectors::SECRET))->recover($token, self::IDENTITY_A);
            self::assertNotNull($outcome);
            self::assertSame(VerifyError::MalformedRecord, $outcome->error, 'a forged stored success is never a grant');
        }
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

    public function testStoredResultRecoveryConfirmsTheReplicationBarrier(): void
    {
        // The failed-barrier replay hole on the recovery API: the
        // consume/commit that produced the stored success may have landed
        // on the primary with its WAIT failing. A recovery that accepts
        // the stored success must establish the replication fence first:
        // a shortfall fails closed (no unproven success), and a satisfied
        // fence returns the stored Valid — the same guard as the verify
        // and resume paths.
        [$inner, $token] = $this->consumedWithStoredValid(self::IDENTITY_A);
        $barrier = new RecoveryBarrierStorage($inner);
        $recovery = new ConsumedOutcomeRecovery($barrier);

        $barrier->confirmResult = false;
        $outcome = $recovery->recover($token, self::IDENTITY_A);
        self::assertNotNull($outcome);
        self::assertFalse($outcome->isOk(), 'a barrier shortfall must fail closed, never return an unproven success');
        self::assertSame(VerifyError::StorageUnavailable, $outcome->error, 'the failed-barrier recovery answers the retryable StorageUnavailable, never an escaped storage exception');

        $barrier->confirmResult = true;
        $outcome = $recovery->recover($token, self::IDENTITY_A);
        self::assertNotNull($outcome);
        self::assertTrue($outcome->isOk(), 'the satisfied fence releases the stored success');
        self::assertTrue($outcome->fromStoredResult, 'the recovery is the stored committed result, never a fresh derivation');
    }

    public function testAWrongNonceEnvelopeIsMalformedNeverTheStoredResult(): void
    {
        // The retained envelope was loaded by the token's nonce (the
        // storage key); a stored nonce field that differs is an
        // impossible key-value pair and answers the deterministic
        // MalformedRecord, never the retained result — mirroring the
        // verifier's consumed-envelope resolution.
        [$inner, $token] = $this->consumedWithStoredValid(self::IDENTITY_A);
        $consumed = $inner->consumedState(SolutionToken::decode($token)->nonce);
        self::assertNotNull($consumed);
        $mismatched = new MismatchedNonceStorage($consumed, 'foreign-nonce-not-the-tokens');
        $recovery = new ConsumedOutcomeRecovery($mismatched);

        $outcome = $recovery->recover($token, self::IDENTITY_A);
        self::assertNotNull($outcome);
        self::assertFalse($outcome->isOk(), 'an impossible key-value pair never replays the stored success');
        self::assertSame(VerifyError::MalformedRecord, $outcome->error);
    }
}

/**
 * The barrier storage of the recovery tests: a
 * {@see \KiwiCaptcha\ReplicationBarrierInterface} wrapper whose
 * establishReplicationFence is configurable, mirroring the verify-path
 * barrier tests.
 */
final class RecoveryBarrierStorage implements \KiwiCaptcha\StorageInterface, \KiwiCaptcha\ConsumedStateReadableInterface, \KiwiCaptcha\ReplicationBarrierInterface
{
    public bool $confirmResult = true;

    public function __construct(private readonly ArrayStorage $inner)
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
 * A consumed-state storage whose retained envelope always reports a
 * nonce different from the lookup key: the impossible key-value pair
 * the nonce guard refuses.
 */
final class MismatchedNonceStorage implements \KiwiCaptcha\StorageInterface, \KiwiCaptcha\ConsumedStateReadableInterface
{
    public function __construct(
        private readonly \KiwiCaptcha\ConsumedRecord $envelope,
        private readonly string $storedNonce,
    )
    {
    }

    public function store(\KiwiCaptcha\ChallengeRecord $record): void
    {
    }

    public function find(string $nonce): ?\KiwiCaptcha\ChallengeRecord
    {
        return null;
    }

    public function consume(string $nonce): ?\KiwiCaptcha\ConsumedRecord
    {
        return null;
    }

    public function commitResult(string $nonce, bool $valid, ?string $binding): bool
    {
        return false;
    }

    public function delete(string $nonce): void
    {
    }

    public function consumedState(string $nonce): ?\KiwiCaptcha\ConsumedRecord
    {
        return new \KiwiCaptcha\ConsumedRecord(
            new \KiwiCaptcha\ChallengeRecord(
                nonce: $this->storedNonce,
                scope: $this->envelope->record->scope,
                bindingTag: $this->envelope->record->bindingTag,
                issuedAt: $this->envelope->record->issuedAt,
                expiresAt: $this->envelope->record->expiresAt,
                algorithm: $this->envelope->record->algorithm,
                mKib: $this->envelope->record->mKib,
                t: $this->envelope->record->t,
                p: $this->envelope->record->p,
                targetBits: $this->envelope->record->targetBits,
                salt: $this->envelope->record->salt,
                prefix: $this->envelope->record->prefix,
                challenge: $this->envelope->record->challenge,
                minDurationMs: $this->envelope->record->minDurationMs,
                issuedAtNs: $this->envelope->record->issuedAtNs,
                protocolVersion: $this->envelope->record->protocolVersion,
                region: $this->envelope->record->region,
                policyVersion: $this->envelope->record->policyVersion,
                requestBinding: $this->envelope->record->requestBinding,
                issuer: $this->envelope->record->issuer,
                kid: $this->envelope->record->kid,
                hostname: $this->envelope->record->hostname,
                decoyField: $this->envelope->record->decoyField,
            ),
            $this->envelope->consumedNow,
            $this->envelope->consumedBefore,
            $this->envelope->consumedResult,
            $this->envelope->operationIdentity,
        );
    }
}
