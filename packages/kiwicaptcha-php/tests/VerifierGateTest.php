<?php

declare(strict_types=1);

namespace KiwiCaptcha\Tests;

use KiwiCaptcha\ChallengeRecord;
use KiwiCaptcha\Config;
use KiwiCaptcha\Issuer;
use KiwiCaptcha\PoWAlgorithm;
use KiwiCaptcha\SolutionToken;
use KiwiCaptcha\Storage\ArrayStorage;
use KiwiCaptcha\StorageInterface;
use KiwiCaptcha\VerificationAdmissionGate;
use KiwiCaptcha\Verifier;
use KiwiCaptcha\VerifyError;
use KiwiCaptcha\Tests\Fixtures\Vectors;
use PHPUnit\Framework\TestCase;

/**
 * The protocol-v2 Verifier: structural record validation, the
 * peek-then-consume one-shot flow (cheap checks burn the record, the
 * proof phase consumes it), and the optional Argon2id admission gate.
 * Also covers fail-closed behaviour on swapped records, server-side
 * timing without the client-duration fallback, and byte-exact parity
 * with the Rust shared fixture vector.
 */
final class VerifierGateTest extends TestCase
{
    private const ISSUED_AT = 1_700_000_000;

    private const CLIENT_IP = '192.168.1.5';

    private function validNonce(): string
    {
        return base64_encode(random_bytes(32));
    }

    private function validSalt(): string
    {
        return base64_encode(random_bytes(16));
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

    private function solveArgon2(string $prefix, string $salt, int $targetBits): int
    {
        $saltBytes = base64_decode($salt, true);
        $counter = 0;
        do {
            $hash = sodium_crypto_pwhash(
                32,
                $prefix.$counter,
                $saltBytes,
                3,
                8 * 1024,
                SODIUM_CRYPTO_PWHASH_ALG_ARGON2ID13,
            );
            $counter++;
        } while (Verifier::leadingZeroBits($hash) < $targetBits);

        return $counter - 1;
    }

    /**
     * A protocol-v2 SHA-256 record over the shared secret, with a
     * structurally consistent challenge/prefix (bindingTag bound to the
     * test client IP). Named overrides: nonce, scope, bindingTag,
     * issuedAt, expiresAt, salt, targetBits, minDurationMs, issuedAtNs,
     * protocolVersion.
     */
    private function v2Sha256Record(...$overrides): ChallengeRecord
    {
        $nonce = (string) ($overrides['nonce'] ?? $this->validNonce());
        $scope = (string) ($overrides['scope'] ?? 'login');
        $bindingTag = (string) ($overrides['bindingTag'] ?? Issuer::bindingTag($nonce, self::CLIENT_IP, Vectors::SECRET));
        $issuedAt = (int) ($overrides['issuedAt'] ?? self::ISSUED_AT);
        $expiresAt = (int) ($overrides['expiresAt'] ?? $issuedAt + 120);
        $salt = (string) ($overrides['salt'] ?? $this->validSalt());
        $targetBits = (int) ($overrides['targetBits'] ?? 8);
        $minDurationMs = (int) ($overrides['minDurationMs'] ?? 0);
        $canonical = Issuer::canonicalPayload(
            $nonce,
            $scope,
            $bindingTag,
            $issuedAt,
            $expiresAt,
            PoWAlgorithm::Sha256,
            0,
            1,
            1,
            $targetBits,
            $salt,
            $minDurationMs,
        );
        $challenge = base64_encode($canonical).'.'.Issuer::signPayloadV2($canonical, Vectors::SECRET);

        return new ChallengeRecord(
            nonce: $nonce,
            scope: $scope,
            bindingTag: $bindingTag,
            issuedAt: $issuedAt,
            expiresAt: $expiresAt,
            algorithm: PoWAlgorithm::Sha256,
            mKib: 0,
            t: 1,
            p: 1,
            targetBits: $targetBits,
            salt: $salt,
            prefix: $challenge.'|'.$salt.'|',
            challenge: $challenge,
            minDurationMs: $minDurationMs,
            issuedAtNs: (int) ($overrides['issuedAtNs'] ?? $issuedAt * 1_000_000),
            protocolVersion: (int) ($overrides['protocolVersion'] ?? 2),
        );
    }

    /**
     * A protocol-v2 Argon2id record (profile: t=3, p=1, mKib=8, 4 bits).
     * Named overrides: nonce, scope, bindingTag, issuedAt, expiresAt, salt,
     * targetBits, t, issuedAtNs.
     */
    private function argon2Record(...$overrides): ChallengeRecord
    {
        $nonce = (string) ($overrides['nonce'] ?? $this->validNonce());
        $scope = (string) ($overrides['scope'] ?? 'login');
        $bindingTag = (string) ($overrides['bindingTag'] ?? Issuer::bindingTag($nonce, self::CLIENT_IP, Vectors::SECRET));
        $issuedAt = (int) ($overrides['issuedAt'] ?? self::ISSUED_AT);
        $expiresAt = (int) ($overrides['expiresAt'] ?? $issuedAt + 120);
        $salt = (string) ($overrides['salt'] ?? $this->validSalt());
        $targetBits = (int) ($overrides['targetBits'] ?? 4);
        $t = (int) ($overrides['t'] ?? 3);
        $canonical = Issuer::canonicalPayload(
            $nonce,
            $scope,
            $bindingTag,
            $issuedAt,
            $expiresAt,
            PoWAlgorithm::Argon2id,
            8,
            $t,
            1,
            $targetBits,
            $salt,
            0,
        );
        $challenge = base64_encode($canonical).'.'.Issuer::signPayloadV2($canonical, Vectors::SECRET);

        return new ChallengeRecord(
            nonce: $nonce,
            scope: $scope,
            bindingTag: $bindingTag,
            issuedAt: $issuedAt,
            expiresAt: $expiresAt,
            algorithm: PoWAlgorithm::Argon2id,
            mKib: 8,
            t: $t,
            p: 1,
            targetBits: $targetBits,
            salt: $salt,
            prefix: $challenge.'|'.$salt.'|',
            challenge: $challenge,
            minDurationMs: 0,
            issuedAtNs: (int) ($overrides['issuedAtNs'] ?? $issuedAt * 1_000_000),
            protocolVersion: 2,
        );
    }

    private function tokenFor(string $nonce, int $counter): string
    {
        return SolutionToken::create($nonce, $counter, 5000, [])->encode();
    }

    /**
     * An admission gate that counts every acquire and release and
     * tracks the live permits, so the verifier's gate interaction is
     * observable. Saturation is modelled by pre-setting `live` to the
     * capacity before the call (a slot held from the outside).
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

    public function testCapacityExhaustedReturnsCapacityExceededWithoutConsumingOrDeleting(): void
    {
        $record = $this->argon2Record();
        $storage = new ArrayStorage();
        $storage->store($record);
        $gate = new class implements VerificationAdmissionGate {
            public function acquire(): ?string
            {
                return null;
            }

            public function release(string $lease): void
            {
            }
        };

        $verifier = new Verifier($storage, $gate, now: static fn (): int => self::ISSUED_AT);
        $outcome = $verifier->verify($this->tokenFor($record->nonce, 0), Vectors::SECRET, 'login', self::CLIENT_IP);

        self::assertSame(VerifyError::CapacityExceeded, $outcome->error);
        self::assertNotNull($storage->find($record->nonce), 'capacity rejection must not consume or delete the record');
    }

    public function testSha256VerificationNeverAcquiresTheArgonGate(): void
    {
        $record = $this->v2Sha256Record();
        $storage = new ArrayStorage();
        $storage->store($record);
        $counter = $this->solveSha256($record->prefix, $record->salt, $record->targetBits);
        $gate = new class implements VerificationAdmissionGate {
            public int $acquires = 0;

            public int $releases = 0;

            public function acquire(): ?string
            {
                $this->acquires++;

                return 'lease';
            }

            public function release(string $lease): void
            {
                $this->releases++;
            }
        };

        $verifier = new Verifier($storage, $gate, now: static fn (): int => self::ISSUED_AT);
        $outcome = $verifier->verify($this->tokenFor($record->nonce, $counter), Vectors::SECRET, 'login', self::CLIENT_IP);

        self::assertTrue($outcome->isOk(), sprintf('expected valid, got %s', $outcome->code()));
        self::assertSame(0, $gate->acquires, 'the Argon gate must not be consulted for SHA-256 records');
        self::assertSame(0, $gate->releases);
    }

    public function testValidArgonVerificationAcquiresAndReleasesOnce(): void
    {
        $record = $this->argon2Record();
        $storage = new ArrayStorage();
        $storage->store($record);
        $counter = $this->solveArgon2($record->prefix, $record->salt, $record->targetBits);
        $gate = new class implements VerificationAdmissionGate {
            public int $acquires = 0;

            public int $releases = 0;

            public function acquire(): ?string
            {
                $this->acquires++;

                return 'lease-1';
            }

            public function release(string $lease): void
            {
                $this->releases++;
            }
        };

        $verifier = new Verifier($storage, $gate, now: static fn (): int => self::ISSUED_AT);
        $outcome = $verifier->verify($this->tokenFor($record->nonce, $counter), Vectors::SECRET, 'login', self::CLIENT_IP);

        self::assertTrue($outcome->isOk(), sprintf('expected valid, got %s', $outcome->code()));
        self::assertSame(1, $gate->acquires);
        self::assertSame(1, $gate->releases, 'the lease must be released exactly once after a successful acquire');
    }

    // ── Terminal-state admission pre-check (round-94 audit fix) ─────────

    public function testCancelledArgonRecordReturnsRecordNotFoundWithoutAcquiringAdmission(): void
    {
        // A well-formed solved token for a cancelled Argon record
        // resolves to the pinned RecordNotFound through the
        // pre-admission terminal-state check, without acquiring an
        // Argon admission slot (previously the admission happened first
        // and the consume transition then revealed the terminal state
        // as missing).
        $record = $this->argon2Record();
        $storage = new ArrayStorage();
        $storage->store($record);
        $counter = $this->solveArgon2($record->prefix, $record->salt, $record->targetBits);
        $token = $this->tokenFor($record->nonce, $counter);
        self::assertSame('cancelled-now', $storage->cancel($record->nonce)?->state);

        $counters = ['acquires' => 0, 'releases' => 0, 'live' => 0];
        $gate = $this->countingGate(1, $counters);
        $outcome = (new Verifier($storage, $gate, now: static fn (): int => self::ISSUED_AT))->verify(
            $token,
            Vectors::SECRET,
            'login',
            self::CLIENT_IP,
        );

        self::assertSame(VerifyError::RecordNotFound, $outcome->error, 'a cancelled challenge fails closed as RecordNotFound');
        self::assertSame(0, $counters['acquires'], 'a cancelled record must NEVER acquire an Argon admission slot');
        self::assertSame(0, $counters['releases']);
        self::assertSame(0, $counters['live']);
        self::assertNotNull($storage->find($record->nonce), 'the cancelled record is retained until its TTL');
    }

    public function testCancelledArgonRecordWithBadSignatureKeepsTheCheapVerdictWithoutAcquiring(): void
    {
        // A token whose record fails the cheap-phase signature re-check
        // on a cancelled record keeps its cheap-phase verdict
        // (BadSignature): the terminal-state pre-check runs only after
        // the cheap phase, so the RecordNotFound pin can never override
        // an earlier security verdict. No admission slot is acquired
        // either way.
        $record = $this->argon2Record();
        $storage = new ArrayStorage();
        $storage->store($record);
        $counter = $this->solveArgon2($record->prefix, $record->salt, $record->targetBits);
        $token = $this->tokenFor($record->nonce, $counter);
        self::assertSame('cancelled-now', $storage->cancel($record->nonce)?->state);

        $counters = ['acquires' => 0, 'releases' => 0, 'live' => 0];
        $gate = $this->countingGate(1, $counters);
        $outcome = (new Verifier($storage, $gate, now: static fn (): int => self::ISSUED_AT))->verify(
            $token,
            str_rot13(Vectors::SECRET),
            'login',
            self::CLIENT_IP,
        );

        self::assertSame(VerifyError::BadSignature, $outcome->error, 'the cheap-phase verdict stands on a cancelled record');
        self::assertSame(0, $counters['acquires']);
        self::assertSame(0, $counters['releases']);
        self::assertSame(0, $counters['live']);
    }

    public function testConsumedArgonRecordReplayWithMatchingIdentityDoesNotAcquireAdmission(): void
    {
        // An already-consumed Argon record whose committed stored
        // success replays to the exact logical operation: the
        // pre-admission terminal-state check resolves the stored
        // outcome without a second derivation and without acquiring an
        // Argon slot.
        $record = $this->argon2Record();
        $storage = new ArrayStorage();
        $storage->store($record);
        $counter = $this->solveArgon2($record->prefix, $record->salt, $record->targetBits);
        $token = $this->tokenFor($record->nonce, $counter);
        $identity = 'op-'.hash('sha256', 'terminal-replay');
        $storage->consumeWithOperationIdentity($record->nonce, $identity);
        self::assertTrue($storage->commitResult($record->nonce, true, null), 'the committed stored success lands');

        $counters = ['acquires' => 0, 'releases' => 0, 'live' => 0];
        $gate = $this->countingGate(1, $counters);
        $outcome = (new Verifier($storage, $gate, now: static fn (): int => self::ISSUED_AT))->verify(
            $token,
            Vectors::SECRET,
            'login',
            self::CLIENT_IP,
            operationIdentity: $identity,
        );

        self::assertTrue($outcome->isOk(), sprintf('the identity-proven replay must resolve the stored success, got %s', $outcome->code()));
        self::assertTrue($outcome->fromStoredResult, 'the replay comes from the stored result, never a second derivation');
        self::assertSame(0, $counters['acquires'], 'a consumed record must never acquire an Argon admission slot');
        self::assertSame(0, $counters['releases']);
        self::assertSame(0, $counters['live']);
        self::assertNotNull($storage->find($record->nonce), 'the consumed evidence is retained until its TTL');
    }

    public function testConsumedArgonRecordReplayWithWrongOrNullIdentityDoesNotAcquireAdmission(): void
    {
        // A retry of a consumed Argon record whose stored success
        // cannot prove the logical operation: AlreadyConsumed, resolved
        // by the pre-admission terminal-state check without acquiring
        // an Argon slot.
        $record = $this->argon2Record();
        $storage = new ArrayStorage();
        $storage->store($record);
        $counter = $this->solveArgon2($record->prefix, $record->salt, $record->targetBits);
        $token = $this->tokenFor($record->nonce, $counter);
        $storage->consumeWithOperationIdentity($record->nonce, 'op-'.hash('sha256', 'terminal-replay'));
        self::assertTrue($storage->commitResult($record->nonce, true, null), 'the committed stored success lands');

        foreach ([null, 'op-'.hash('sha256', 'other-operation')] as $identity) {
            $counters = ['acquires' => 0, 'releases' => 0, 'live' => 0];
            $gate = $this->countingGate(1, $counters);
            $outcome = (new Verifier($storage, $gate, now: static fn (): int => self::ISSUED_AT))->verify(
                $token,
                Vectors::SECRET,
                'login',
                self::CLIENT_IP,
                operationIdentity: $identity,
            );
            self::assertSame(VerifyError::AlreadyConsumed, $outcome->error, 'a replay without the proven identity is AlreadyConsumed');
            self::assertSame(0, $counters['acquires'], 'a consumed record must never acquire an Argon admission slot');
            self::assertSame(0, $counters['releases']);
            self::assertSame(0, $counters['live']);
            self::assertNotNull($storage->find($record->nonce), 'the consumed evidence is retained');
        }
    }

    public function testPendingRaceBothRacersAcquireAndExactlyOneDerives(): void
    {
        // The pending first-race window: both racing requests pass the
        // terminal-state pre-check while the record is still pending,
        // so both acquire an Argon admission slot, exactly one wins the
        // consume and derives, and the loser resolves the winner's
        // committed stored outcome without a second derivation. The
        // race is emulated deterministically: racer B's admission
        // acquire runs racer A's full verification to completion, so B
        // had already passed the pre-check (the record was still
        // pending) when A consumed and committed. B's own consume then
        // sees the consumed envelope and resolves the stored success.
        $record = $this->argon2Record();
        $storage = new ArrayStorage();
        $storage->store($record);
        $counter = $this->solveArgon2($record->prefix, $record->salt, $record->targetBits);
        $token = $this->tokenFor($record->nonce, $counter);
        $identity = 'op-'.hash('sha256', 'pending-race');

        $gate = new class implements VerificationAdmissionGate {
            public int $acquires = 0;

            public int $releases = 0;

            public ?\KiwiCaptcha\VerifyOutcome $racerOutcome = null;

            private bool $racerFired = false;

            private ?\Closure $racer = null;

            public function setRacer(\Closure $racer): void
            {
                $this->racer = $racer;
            }

            public function acquire(): ?string
            {
                $this->acquires++;
                if (!$this->racerFired) {
                    $this->racerFired = true;
                    if ($this->racer !== null) {
                        $this->racerOutcome = ($this->racer)();
                    }
                }

                return 'lease-'.$this->acquires;
            }

            public function release(string $lease): void
            {
                $this->releases++;
            }
        };
        $gate->setRacer(static function () use ($storage, $gate, $token, $identity): \KiwiCaptcha\VerifyOutcome {
            return (new Verifier($storage, $gate, now: static fn (): int => self::ISSUED_AT))->verify(
                $token,
                Vectors::SECRET,
                'login',
                self::CLIENT_IP,
                operationIdentity: $identity,
            );
        });

        $loser = (new Verifier($storage, $gate, now: static fn (): int => self::ISSUED_AT))->verify(
            $token,
            Vectors::SECRET,
            'login',
            self::CLIENT_IP,
            operationIdentity: $identity,
        );

        self::assertTrue($loser->isOk(), sprintf('racer B must resolve the stored outcome, got %s', $loser->code()));
        self::assertTrue($loser->fromStoredResult, "racer B replays the winner's stored result, never a second derivation");
        self::assertNotNull($gate->racerOutcome, 'racer A ran inside racer B admission');
        self::assertTrue($gate->racerOutcome->isOk(), 'racer A derives and commits');
        self::assertFalse($gate->racerOutcome->fromStoredResult, 'racer A is the fresh derivation');
        self::assertSame(2, $gate->acquires, 'both racers acquire an Argon slot in the pending first-race window');
        self::assertSame(2, $gate->releases, 'every acquired lease is released');
        self::assertNotNull($storage->consumedState($record->nonce)?->consumedResult, 'the winner committed the deterministic result');
    }

    public function testCancelledArgonRecordInProcessEndToEndNeverAcquiresAdmission(): void
    {
        // The in-process (ArrayStorage) variant of the cancelled-Argon
        // admission fix: a real issued-and-solved Argon challenge
        // cancelled through the cancellation endpoint resolves to
        // RecordNotFound without ever touching the Argon admission
        // gate.
        $storage = new ArrayStorage();
        $issuer = new Issuer(
            new Config(
                secretKey: Vectors::SECRET,
                algorithm: PoWAlgorithm::Argon2id,
                mKib: 64,
                t: 3,
                p: 1,
                argon2TargetBits: 4,
                ttlSecs: 120,
                minDurationMs: 0,
            ),
            $storage,
            now: static fn (): int => self::ISSUED_AT,
        );
        $challenge = $issuer->issue('login', self::CLIENT_IP);
        $record = $storage->find($challenge->nonce);
        self::assertNotNull($record);
        self::assertSame(PoWAlgorithm::Argon2id, $record->algorithm);

        $saltBytes = base64_decode($record->salt, true);
        $counter = 0;
        do {
            $hash = sodium_crypto_pwhash(32, $record->prefix.$counter, $saltBytes, $record->t, $record->mKib * 1024, SODIUM_CRYPTO_PWHASH_ALG_ARGON2ID13);
            $counter++;
        } while (Verifier::leadingZeroBits($hash) < $record->targetBits);
        --$counter;
        $token = $this->tokenFor($record->nonce, $counter);
        self::assertSame('cancelled-now', $storage->cancel($record->nonce)?->state);

        $counters = ['acquires' => 0, 'releases' => 0, 'live' => 0];
        $gate = $this->countingGate(1, $counters);
        $outcome = (new Verifier($storage, $gate, now: static fn (): int => self::ISSUED_AT))->verify(
            $token,
            Vectors::SECRET,
            'login',
            self::CLIENT_IP,
            nowNs: $record->issuedAtNs + 1_000_000,
        );

        self::assertSame(VerifyError::RecordNotFound, $outcome->error, 'a cancelled challenge fails closed as RecordNotFound');
        self::assertSame(0, $counters['acquires'], 'the cancelled record must never acquire an Argon admission slot');
        self::assertSame(0, $counters['releases']);
        self::assertSame(0, $counters['live']);
    }

    public function testNoCapabilityStorageKeepsTheLegacyAdmissionThenRecordNotFoundBehavior(): void
    {
        // A storage without the runtime-state capability (and without
        // the consumed-state capability) keeps the OLD behavior: a
        // well-formed token for a cancelled record still acquires an
        // Argon admission slot, and the consume transition then reveals
        // the terminal state as RecordNotFound.
        $record = $this->argon2Record();
        $inner = new ArrayStorage();
        $inner->store($record);
        $inner->cancel($record->nonce);
        $storage = new class($inner) implements StorageInterface {
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

        $counters = ['acquires' => 0, 'releases' => 0, 'live' => 0];
        $gate = $this->countingGate(1, $counters);
        $outcome = (new Verifier($storage, $gate, now: static fn (): int => self::ISSUED_AT))->verify(
            $this->tokenFor($record->nonce, 0),
            Vectors::SECRET,
            'login',
            self::CLIENT_IP,
        );

        self::assertSame(VerifyError::RecordNotFound, $outcome->error, 'the legacy path still reports the cancelled record as missing');
        self::assertSame(1, $counters['acquires'], 'the legacy path still acquires before the consume reveals the cancelled state');
        self::assertSame(1, $counters['releases'], 'the acquired lease is released');
        self::assertSame(0, $counters['live'], 'no Argon permit remains live');
    }

    public function testToctouConsumedRecordDiffersFromPeekedIsMalformed(): void
    {
        $peek = $this->v2Sha256Record();
        // A second record over the same nonce but a different
        // salt/challenge: consume() returns it even though find()
        // returned $peek.
        $swapped = $this->v2Sha256Record(nonce: $peek->nonce, salt: $this->validSalt());
        self::assertNotSame($peek->challenge, $swapped->challenge);

        $storage = new class($peek, $swapped) implements StorageInterface {
            public function __construct(
                private ChallengeRecord $peek,
                private ChallengeRecord $swapped,
            ) {
            }

            public function store(ChallengeRecord $record): void
            {
            }

            public function find(string $nonce): ?ChallengeRecord
            {
                return $this->peek;
            }

            public function consumedState(string $nonce): ?\KiwiCaptcha\ConsumedRecord
            {
                return null;
            }

            public function consume(string $nonce): ?\KiwiCaptcha\ConsumedRecord
            {
                return new \KiwiCaptcha\ConsumedRecord($this->swapped, true, false, null);
            }

            public function commitResult(string $nonce, bool $valid, ?string $binding): bool
            {
                return false;
            }

            public function delete(string $nonce): void
            {
            }
        };

        $verifier = new Verifier($storage, now: static fn (): int => self::ISSUED_AT);
        $outcome = $verifier->verify($this->tokenFor($peek->nonce, 0), Vectors::SECRET, 'login', self::CLIENT_IP);

        self::assertSame(VerifyError::MalformedRecord, $outcome->error, 'a swapped consumed record must fail closed');
    }

    public function testMalformedNonceLengthBurnsRecord(): void
    {
        // The record's nonce field decodes to 31 bytes, not 32. The token's
        // nonce (the storage key) must stay in the valid 44-char wire format
        // — a 31-byte nonce base64-encodes with '==' padding and would be
        // rejected at token decode — so the mismatch is exercised through a
        // storage stub that serves the malformed record under any key.
        $record = $this->v2Sha256Record(nonce: base64_encode(random_bytes(31)));
        $storage = new class($record) implements StorageInterface {
            public ?ChallengeRecord $current;

            public function __construct(ChallengeRecord $record)
            {
                $this->current = $record;
            }

            public function store(ChallengeRecord $record): void
            {
            }

            public function find(string $nonce): ?ChallengeRecord
            {
                return $this->current;
            }

            public function consumedState(string $nonce): ?\KiwiCaptcha\ConsumedRecord
            {
                return null;
            }

            public function consume(string $nonce): ?\KiwiCaptcha\ConsumedRecord
            {
                $record = $this->current;
                $this->current = null;

                return $record === null ? null : new \KiwiCaptcha\ConsumedRecord($record, true, false, null);
            }

            public function commitResult(string $nonce, bool $valid, ?string $binding): bool
            {
                return false;
            }

            public function delete(string $nonce): void
            {
                $this->current = null;
            }
        };

        $verifier = new Verifier($storage, now: static fn (): int => self::ISSUED_AT);
        $outcome = $verifier->verify($this->tokenFor($this->validNonce(), 0), Vectors::SECRET);

        self::assertSame(VerifyError::MalformedRecord, $outcome->error);
        self::assertNull($storage->current, 'a malformed record must be deleted');
    }

    public function testMalformedSaltLengthBurnsRecord(): void
    {
        $record = $this->v2Sha256Record(salt: base64_encode(random_bytes(15)));
        $storage = new ArrayStorage();
        $storage->store($record);

        $verifier = new Verifier($storage, now: static fn (): int => self::ISSUED_AT);
        $outcome = $verifier->verify($this->tokenFor($record->nonce, 0), Vectors::SECRET);

        self::assertSame(VerifyError::MalformedRecord, $outcome->error);
        self::assertNull($storage->find($record->nonce));
    }

    public function testMalformedPrefixBurnsRecord(): void
    {
        $record = $this->v2Sha256Record();
        $storage = new ArrayStorage();
        $storage->store(new ChallengeRecord(
            nonce: $record->nonce,
            scope: $record->scope,
            bindingTag: $record->bindingTag,
            issuedAt: $record->issuedAt,
            expiresAt: $record->expiresAt,
            algorithm: $record->algorithm,
            mKib: $record->mKib,
            t: $record->t,
            p: $record->p,
            targetBits: $record->targetBits,
            salt: $record->salt,
            prefix: 'not-the-prefix',
            challenge: $record->challenge,
            minDurationMs: $record->minDurationMs,
            issuedAtNs: $record->issuedAtNs,
            protocolVersion: $record->protocolVersion,
        ));

        $verifier = new Verifier($storage, now: static fn (): int => self::ISSUED_AT);
        $outcome = $verifier->verify($this->tokenFor($record->nonce, 0), Vectors::SECRET);

        self::assertSame(VerifyError::MalformedRecord, $outcome->error);
        self::assertNull($storage->find($record->nonce));
    }

    public function testTtlAboveCeilingBurnsRecord(): void
    {
        // expiresAt - issuedAt = 301, above the 300 s TTL ceiling.
        $record = $this->v2Sha256Record(issuedAt: self::ISSUED_AT, expiresAt: self::ISSUED_AT + 301);
        $storage = new ArrayStorage();
        $storage->store($record);

        $verifier = new Verifier($storage, now: static fn (): int => self::ISSUED_AT);
        $outcome = $verifier->verify($this->tokenFor($record->nonce, 0), Vectors::SECRET, 'login', self::CLIENT_IP);

        self::assertSame(VerifyError::MalformedRecord, $outcome->error);
        self::assertNull($storage->find($record->nonce));
    }

    public function testLifetimeAtTheMaximumTtlCeilingIsAccepted(): void
    {
        // expiresAt - issuedAt = 300, exactly the TTL ceiling: within
        // the bound, so the record is structurally valid and verifies
        // end-to-end.
        $record = $this->v2Sha256Record(issuedAt: self::ISSUED_AT, expiresAt: self::ISSUED_AT + 300);
        $storage = new ArrayStorage();
        $storage->store($record);
        $counter = $this->solveSha256($record->prefix, $record->salt, $record->targetBits);

        $verifier = new Verifier($storage, now: static fn (): int => self::ISSUED_AT);
        $outcome = $verifier->verify($this->tokenFor($record->nonce, $counter), Vectors::SECRET, 'login', self::CLIENT_IP);

        self::assertTrue($outcome->isOk(), sprintf('a lifetime at the MAX_TTL_SECS boundary must verify, got %s', $outcome->code()));
    }

    public function testFutureIssuedBeyondClockSkewRejectedAsExpired(): void
    {
        // A signed challenge claiming issued_at = now + 61s exceeds the
        // 60 s future-skew bound; no real issuer host is that far ahead,
        // so the TTL check rejects it as Expired.
        $record = $this->v2Sha256Record(issuedAt: self::ISSUED_AT + 61, expiresAt: self::ISSUED_AT + 61 + 120);
        $storage = new ArrayStorage();
        $storage->store($record);

        $verifier = new Verifier($storage, now: static fn (): int => self::ISSUED_AT);
        $outcome = $verifier->verify($this->tokenFor($record->nonce, 0), Vectors::SECRET, 'login', self::CLIENT_IP);

        self::assertSame(VerifyError::Expired, $outcome->error);
        self::assertNull($storage->find($record->nonce), 'a future-issued record must be burned');
    }

    public function testFutureIssuedAtTheClockSkewBoundaryVerifies(): void
    {
        // issued_at = now + 60 sits exactly at the future-skew
        // boundary; the future bound uses `>`, so the record is accepted
        // and verifies end-to-end.
        $record = $this->v2Sha256Record(issuedAt: self::ISSUED_AT + 60, expiresAt: self::ISSUED_AT + 60 + 120);
        $storage = new ArrayStorage();
        $storage->store($record);
        $counter = $this->solveSha256($record->prefix, $record->salt, $record->targetBits);

        $verifier = new Verifier($storage, now: static fn (): int => self::ISSUED_AT);
        $outcome = $verifier->verify(
            $this->tokenFor($record->nonce, $counter),
            Vectors::SECRET,
            'login',
            self::CLIENT_IP,
            nowNs: $record->issuedAtNs + 1_000_000,
        );

        self::assertTrue($outcome->isOk(), sprintf('a record at the future-skew boundary must verify, got %s', $outcome->code()));
    }

    public function testMaxClockSkewConstantIsSixtySeconds(): void
    {
        self::assertSame(60, Verifier::MAX_CLOCK_SKEW);
    }

    public function testArgonTAboveProcessCeilingRejectsAsUnsupported(): void
    {
        // t=32 exceeds the absolute process ceiling of 16 passes. The
        // record is signed with the shared secret, so the failure is
        // UnsupportedArgon2Params (not MalformedRecord): the signature
        // authenticates the parameters before the ceiling check.
        $record = $this->argon2Record(t: 32);
        $storage = new ArrayStorage();
        $storage->store($record);

        $verifier = new Verifier($storage, now: static fn (): int => self::ISSUED_AT);
        $outcome = $verifier->verify($this->tokenFor($record->nonce, 0), Vectors::SECRET);

        self::assertSame(VerifyError::UnsupportedArgon2Params, $outcome->error);
        self::assertNull($storage->find($record->nonce), 'an unsupported record must be burned');
    }

    public function testReceiptOneSecondAheadOfIssuancePassesWithinSkewTolerance(): void
    {
        // Issuer host 1s ahead of the verifying host: elapsed would be
        // negative, but the skew is inside the 5s tolerance, so the floor
        // check is skipped and the solve passes.
        $record = $this->v2Sha256Record(minDurationMs: 1000);
        $storage = new ArrayStorage();
        $storage->store($record);
        $counter = $this->solveSha256($record->prefix, $record->salt, $record->targetBits);

        $verifier = new Verifier($storage, now: static fn (): int => self::ISSUED_AT);
        $outcome = $verifier->verify(
            $this->tokenFor($record->nonce, $counter),
            Vectors::SECRET,
            'login',
            self::CLIENT_IP,
            nowNs: $record->issuedAtNs - 1_000_000,
        );

        self::assertTrue($outcome->isOk(), sprintf('1s skew must pass, got %s', $outcome->code()));
    }

    public function testReceiptSixSecondsAheadOfIssuanceIsTooFast(): void
    {
        // Receipt 6s before issuance exceeds the 5s skew tolerance: the
        // issuance timestamps cannot come from real hosts, rejected.
        $record = $this->v2Sha256Record(minDurationMs: 1000);
        $storage = new ArrayStorage();
        $storage->store($record);

        $verifier = new Verifier($storage, now: static fn (): int => self::ISSUED_AT);
        $outcome = $verifier->verify(
            $this->tokenFor($record->nonce, 0),
            Vectors::SECRET,
            'login',
            self::CLIENT_IP,
            nowNs: $record->issuedAtNs - 6_000_000,
        );

        self::assertSame(VerifyError::TooFast, $outcome->error);
    }

    public function testMissingIssuedAtNsIsMalformedWithoutLegacyFallback(): void
    {
        // No client-duration fallback anymore: an untimed record cannot
        // be verified, even with a solved proof and an enforced floor.
        $record = $this->v2Sha256Record(minDurationMs: 1000, issuedAtNs: 0);
        $storage = new ArrayStorage();
        $storage->store($record);
        $counter = $this->solveSha256($record->prefix, $record->salt, $record->targetBits);

        $verifier = new Verifier($storage, now: static fn (): int => self::ISSUED_AT);
        $outcome = $verifier->verify($this->tokenFor($record->nonce, $counter), Vectors::SECRET, 'login', self::CLIENT_IP);

        self::assertSame(VerifyError::MalformedRecord, $outcome->error);
        self::assertNull($storage->find($record->nonce));
    }

    public function testV1RecordRejectedByDefault(): void
    {
        // The v1 migration window is closed by default: no legitimate
        // v1 record can outlive the 300 s maximum challenge lifetime.
        $nonce = $this->validNonce();
        $scope = 'login';
        $ipHash = Issuer::hashIp('198.51.100.77', Vectors::SECRET);
        $payload = sprintf('%s|%s|%s|%d', $nonce, $scope, $ipHash, self::ISSUED_AT);
        $challenge = base64_encode($payload).'.'.Issuer::signPayload($payload, Vectors::SECRET);
        $salt = $this->validSalt();
        $record = new ChallengeRecord(
            nonce: $nonce,
            scope: $scope,
            bindingTag: $ipHash,
            issuedAt: self::ISSUED_AT,
            expiresAt: self::ISSUED_AT + 120,
            algorithm: PoWAlgorithm::Sha256,
            mKib: 0,
            t: 1,
            p: 1,
            targetBits: 8,
            salt: $salt,
            prefix: $challenge.'|'.$salt.'|',
            challenge: $challenge,
            minDurationMs: 0,
            issuedAtNs: self::ISSUED_AT * 1_000_000,
            protocolVersion: 1,
        );
        $storage = new ArrayStorage();
        $storage->store($record);
        $counter = $this->solveSha256($record->prefix, $record->salt, $record->targetBits);

        $verifier = new Verifier($storage, now: static fn (): int => self::ISSUED_AT);
        $outcome = $verifier->verify($this->tokenFor($nonce, $counter), Vectors::SECRET, 'login', '198.51.100.77');

        self::assertSame(VerifyError::MalformedRecord->value, $outcome->code(), 'v1 must be rejected unless acceptLegacyV1 is set');
    }

    public function testV1RecordVerifiesEndToEnd(): void
    {
        // Legacy protocol v1: canonical "nonce|scope|ip_hash|issued_at" and
        // the stable IP hash as the binding.
        $nonce = $this->validNonce();
        $scope = 'login';
        $ipHash = Issuer::hashIp('198.51.100.77', Vectors::SECRET);
        $payload = sprintf('%s|%s|%s|%d', $nonce, $scope, $ipHash, self::ISSUED_AT);
        $challenge = base64_encode($payload).'.'.Issuer::signPayload($payload, Vectors::SECRET);
        $salt = $this->validSalt();
        $record = new ChallengeRecord(
            nonce: $nonce,
            scope: $scope,
            bindingTag: $ipHash,
            issuedAt: self::ISSUED_AT,
            expiresAt: self::ISSUED_AT + 120,
            algorithm: PoWAlgorithm::Sha256,
            mKib: 0,
            t: 1,
            p: 1,
            targetBits: 8,
            salt: $salt,
            prefix: $challenge.'|'.$salt.'|',
            challenge: $challenge,
            minDurationMs: 0,
            issuedAtNs: self::ISSUED_AT * 1_000_000,
            protocolVersion: 1,
        );
        $storage = new ArrayStorage();
        $storage->store($record);
        $counter = $this->solveSha256($record->prefix, $record->salt, $record->targetBits);

        $verifier = new Verifier($storage, now: static fn (): int => self::ISSUED_AT, acceptLegacyV1: true);
        $outcome = $verifier->verify($this->tokenFor($nonce, $counter), Vectors::SECRET, 'login', '198.51.100.77');

        self::assertTrue($outcome->isOk(), sprintf('v1 record must verify with the migration flag, got %s', $outcome->code()));
    }

    public function testV2RecordVerifiesEndToEnd(): void
    {
        $record = $this->v2Sha256Record();
        $storage = new ArrayStorage();
        $storage->store($record);
        $counter = $this->solveSha256($record->prefix, $record->salt, $record->targetBits);

        $verifier = new Verifier($storage, now: static fn (): int => self::ISSUED_AT);
        $outcome = $verifier->verify($this->tokenFor($record->nonce, $counter), Vectors::SECRET, 'login', self::CLIENT_IP);

        self::assertTrue($outcome->isOk(), sprintf('v2 record must verify, got %s', $outcome->code()));
    }

    public function testWrongClientIpIsIpMismatch(): void
    {
        $record = $this->v2Sha256Record();
        $storage = new ArrayStorage();
        $storage->store($record);
        $counter = $this->solveSha256($record->prefix, $record->salt, $record->targetBits);

        $verifier = new Verifier($storage, now: static fn (): int => self::ISSUED_AT);
        $outcome = $verifier->verify($this->tokenFor($record->nonce, $counter), Vectors::SECRET, 'login', '198.51.100.9');

        self::assertSame(VerifyError::IpMismatch, $outcome->error);
    }

    public function testEmptyBindingTagSkipsIpCheck(): void
    {
        // bindingTag '' = binding disabled: any client IP passes.
        $record = $this->v2Sha256Record(bindingTag: '');
        $storage = new ArrayStorage();
        $storage->store($record);
        $counter = $this->solveSha256($record->prefix, $record->salt, $record->targetBits);

        $verifier = new Verifier($storage, now: static fn (): int => self::ISSUED_AT);
        $outcome = $verifier->verify($this->tokenFor($record->nonce, $counter), Vectors::SECRET, 'login', '198.51.100.9');

        self::assertTrue($outcome->isOk(), sprintf('unbound record must verify from any IP, got %s', $outcome->code()));
    }

    public function testSharedFixtureVectorByteExactWithRust(): void
    {
        $secret = '0123456789abcdef0123456789abcdef';
        $nonce = base64_encode('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef');
        $salt = base64_encode('1234567890abcdef');
        $scope = 'login';
        $issuedAt = 1_700_000_000;
        $expiresAt = 1_700_000_120;
        $ip = '192.168.1.5';
        $bindingTag = Issuer::bindingTag($nonce, $ip, $secret);

        // Canonical v2 layout: the field order with
        // region/request_binding/issuer as empty segments, policy_version
        // 1, and the final kid segment 1.
        $canonicalV2 = 'v2|'.$nonce.'|'.$scope.'|'.$bindingTag.'|'.$issuedAt.'|'.$expiresAt.'|sha256|0|1|1|8|'.$salt.'|0||1|||1';
        self::assertSame(
            $canonicalV2,
            Issuer::canonicalPayload(
                $nonce,
                $scope,
                $bindingTag,
                $issuedAt,
                $expiresAt,
                PoWAlgorithm::Sha256,
                0,
                1,
                1,
                8,
                $salt,
                0,
            ),
            'canonicalPayload must produce the exact shared vector'
        );

        $challenge = base64_encode($canonicalV2).'.'.Issuer::signPayloadV2($canonicalV2, $secret);
        $prefix = $challenge.'|'.$salt.'|';
        $record = new ChallengeRecord(
            nonce: $nonce,
            scope: $scope,
            bindingTag: $bindingTag,
            issuedAt: $issuedAt,
            expiresAt: $expiresAt,
            algorithm: PoWAlgorithm::Sha256,
            mKib: 0,
            t: 1,
            p: 1,
            targetBits: 8,
            salt: $salt,
            prefix: $prefix,
            challenge: $challenge,
            minDurationMs: 0,
            issuedAtNs: $issuedAt * 1_000_000,
            protocolVersion: 2,
        );
        $storage = new ArrayStorage();
        $storage->store($record);
        $counter = $this->solveSha256($prefix, $salt, 8);

        $verifier = new Verifier($storage, now: static fn (): int => $issuedAt);
        $outcome = $verifier->verify(
            $this->tokenFor($nonce, $counter),
            $secret,
            'login',
            $ip,
            nowNs: $record->issuedAtNs + 1_000_000,
        );

        self::assertTrue($outcome->isOk(), sprintf('shared fixture vector must verify, got %s', $outcome->code()));
    }

    public function testLegacySecondPositionClosureIsTreatedAsClockOverride(): void
    {
        // BC shim: pre-gate callers passed the clock override
        // positionally as the constructor's second argument. It must be
        // treated as $now, not as an admission gate.
        $record = $this->v2Sha256Record();
        $storage = new ArrayStorage();
        $storage->store($record);

        $verifier = new Verifier($storage, static fn (): int => self::ISSUED_AT + 121);
        $outcome = $verifier->verify($this->tokenFor($record->nonce, 0), Vectors::SECRET, 'login', self::CLIENT_IP);

        self::assertSame(VerifyError::Expired, $outcome->error, 'a positional Closure must drive the TTL clock');
    }

    public function testBoundRecordWithoutClientIpFailsClosed(): void
    {
        // A non-empty binding tag means the challenge is bound: omitting
        // the client IP must fail with MissingClientIp, not silently skip
        // the check (the caller must provide the IP it passed to
        // issuance).
        $storage = new ArrayStorage();
        $secret = '0123456789abcdef0123456789abcdef';
        $issuer = new Issuer(new \KiwiCaptcha\Config(secretKey: $secret, targetBits: 8), $storage);
        $challenge = $issuer->issue('login', '198.51.100.7');
        $record = $storage->find($challenge->nonce);
        self::assertNotNull($record);
        self::assertNotSame('', $record->bindingTag, 'fixture must be a bound challenge');

        $counter = 0;
        do {
            $h = hash('sha256', $challenge->prefix.$counter.base64_decode($challenge->salt, true), true);
            $counter++;
        } while (Verifier::leadingZeroBits($h) < $challenge->targetBits);
        --$counter;
        $token = SolutionToken::create($challenge->nonce, $counter, 5000, [])->encode();

        $outcome = (new Verifier($storage))->verify($token, $secret, 'login', null, $record->issuedAtNs + 1_000_000);
        self::assertSame(VerifyError::MissingClientIp->value, $outcome->code());

        // BindingMode::None records (empty tag) still verify without an IP.
        $storage2 = new ArrayStorage();
        $issuer2 = new Issuer(new \KiwiCaptcha\Config(secretKey: $secret, targetBits: 8, bindingMode: \KiwiCaptcha\BindingMode::None), $storage2);
        $ch2 = $issuer2->issue('login', '198.51.100.7');
        $rec2 = $storage2->find($ch2->nonce);
        self::assertSame('', $rec2->bindingTag);
        $c2 = 0;
        do {
            $h2 = hash('sha256', $ch2->prefix.$c2.base64_decode($ch2->salt, true), true);
            $c2++;
        } while (Verifier::leadingZeroBits($h2) < $ch2->targetBits);
        --$c2;
        $t2 = SolutionToken::create($ch2->nonce, $c2, 5000, [])->encode();
        $o2 = (new Verifier($storage2))->verify($t2, $secret, 'login', null, $rec2->issuedAtNs + 1_000_000);
        self::assertTrue($o2->isOk(), sprintf('unbound record must verify without an IP, got %s', $o2->code()));
    }

    public function testProtocolVersion3IsMalformed(): void
    {
        // Only protocol versions 1 (legacy migration) and 2 (current)
        // exist in the wire contract; anything else is a corrupt or
        // foreign record.
        $storage = new ArrayStorage();
        $issuer = new Issuer(new \KiwiCaptcha\Config(secretKey: '0123456789abcdef0123456789abcdef', targetBits: 8), $storage);
        $challenge = $issuer->issue('login', '198.51.100.7');
        $record = $storage->find($challenge->nonce);
        self::assertNotNull($record);
        $storage->store(new \KiwiCaptcha\ChallengeRecord(
            nonce: $record->nonce,
            scope: $record->scope,
            bindingTag: $record->bindingTag,
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
            minDurationMs: $record->minDurationMs,
            issuedAtNs: $record->issuedAtNs,
            protocolVersion: 3,
        ));
        $counter = 0;
        do {
            $h = hash('sha256', $challenge->prefix . $counter . base64_decode($challenge->salt, true), true);
            $counter++;
        } while (Verifier::leadingZeroBits($h) < $challenge->targetBits);
        --$counter;
        $token = SolutionToken::create($challenge->nonce, $counter, 5000, [])->encode();
        $outcome = (new Verifier($storage))->verify($token, '0123456789abcdef0123456789abcdef', 'login', '198.51.100.7', $record->issuedAtNs + 1_000_000);
        self::assertSame(VerifyError::MalformedRecord->value, $outcome->code());
    }

    public function testValidOutcomeExposesTheDecodedNonce(): void
    {
        // The canonical replay id (jti) is the decoded token's nonce; a
        // valid outcome must expose it.
        $record = $this->v2Sha256Record();
        $storage = new ArrayStorage();
        $storage->store($record);
        $counter = $this->solveSha256($record->prefix, $record->salt, $record->targetBits);

        $verifier = new Verifier($storage, now: static fn (): int => self::ISSUED_AT);
        $outcome = $verifier->verify($this->tokenFor($record->nonce, $counter), Vectors::SECRET, 'login', self::CLIENT_IP);

        self::assertTrue($outcome->isOk());
        self::assertSame($record->nonce, $outcome->nonce());
    }

    public function testInvalidOutcomeNonceIsNull(): void
    {
        $record = $this->v2Sha256Record();
        $storage = new ArrayStorage();
        $storage->store($record);

        $verifier = new Verifier($storage, now: static fn (): int => self::ISSUED_AT + 1000);
        $outcome = $verifier->verify($this->tokenFor($record->nonce, 0), Vectors::SECRET, 'login', self::CLIENT_IP);

        self::assertSame(VerifyError::Expired, $outcome->error);
        self::assertNull($outcome->nonce());
    }

    public function testMalformedTokenNonceIsNull(): void
    {
        // The url-safe variant of a well-formed token decodes to the
        // same plaintext but is not canonical base64; the verifier
        // rejects it as MalformedToken and exposes no nonce. The
        // telemetry '?' bytes (positioned via duration=1000) guarantee
        // the token's base64 contains '/' so the variant genuinely
        // differs.
        $nonce = base64_encode(random_bytes(32));
        $raw = SolutionToken::create($nonce, 1, 1000, ['q' => '?>~?'])->encode();
        $urlSafe = strtr($raw, '+/', '-_');
        self::assertNotSame($raw, $urlSafe, 'precondition: the url-safe variant must differ');
        $verifier = new Verifier(new ArrayStorage());
        $outcome = $verifier->verify($urlSafe, Vectors::SECRET);

        self::assertSame(VerifyError::MalformedToken, $outcome->error);
        self::assertNull($outcome->nonce());
    }

    public function testRecordNotFoundNonceIsNull(): void
    {
        $verifier = new Verifier(new ArrayStorage());
        $token = SolutionToken::create($this->validNonce(), 1, 5000, [])->encode();

        $outcome = $verifier->verify($token, Vectors::SECRET);

        self::assertSame(VerifyError::RecordNotFound, $outcome->error);
        self::assertNull($outcome->nonce());
    }
}
