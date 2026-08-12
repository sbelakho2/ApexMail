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
 * The protocol-v2 Verifier rewrite: structural record validation, the
 * peek-then-consume one-shot flow (cheap checks burn the record, the proof
 * phase consumes it), the optional Argon2id admission gate, TOCTOU
 * fail-closed behaviour, server-side timing without the client-duration
 * fallback, and byte-exact parity with the Rust shared fixture vector.
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
     * structurally consistent challenge/prefix (bindingTag bound to
     * self::CLIENT_IP). Named overrides: nonce, scope, bindingTag, issuedAt,
     * expiresAt, salt, targetBits, minDurationMs, issuedAtNs, protocolVersion.
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
        $challenge = base64_encode($canonical).'.'.Issuer::signPayload($canonical, Vectors::SECRET);

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
        $challenge = base64_encode($canonical).'.'.Issuer::signPayload($canonical, Vectors::SECRET);

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

    public function testToctouConsumedRecordDiffersFromPeekedIsMalformed(): void
    {
        $peek = $this->v2Sha256Record();
        // A second record over the SAME nonce but a different salt/challenge:
        // consume() returns it even though find() returned $peek.
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

            public function consume(string $nonce): ?ChallengeRecord
            {
                return $this->swapped;
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

            public function consume(string $nonce): ?ChallengeRecord
            {
                $record = $this->current;
                $this->current = null;

                return $record;
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
        // expiresAt - issuedAt = 301 > MAX_TTL_SECS (300).
        $record = $this->v2Sha256Record(issuedAt: self::ISSUED_AT, expiresAt: self::ISSUED_AT + 301);
        $storage = new ArrayStorage();
        $storage->store($record);

        $verifier = new Verifier($storage, now: static fn (): int => self::ISSUED_AT);
        $outcome = $verifier->verify($this->tokenFor($record->nonce, 0), Vectors::SECRET);

        self::assertSame(VerifyError::MalformedRecord, $outcome->error);
        self::assertNull($storage->find($record->nonce));
    }

    public function testArgonT7BurnsRecord(): void
    {
        // t=7 exceeds MAX_ARGON_T (6): outside the browser-solvable profile.
        $record = $this->argon2Record(t: 7);
        $storage = new ArrayStorage();
        $storage->store($record);

        $verifier = new Verifier($storage, now: static fn (): int => self::ISSUED_AT);
        $outcome = $verifier->verify($this->tokenFor($record->nonce, 0), Vectors::SECRET);

        self::assertSame(VerifyError::MalformedRecord, $outcome->error);
        self::assertNull($storage->find($record->nonce));
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
        // No client-duration fallback anymore: an untimed record cannot be
        // verified, even with a solved proof and an enforced floor.
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
        // The v1 migration window is closed by default: no legitimate v1
        // record can outlive the 300 s maximum challenge lifetime.
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

        $canonicalV2 = 'v2|'.$nonce.'|'.$scope.'|'.$bindingTag.'|'.$issuedAt.'|'.$expiresAt.'|sha256|0|1|1|8|'.$salt.'|0';
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

        $challenge = base64_encode($canonicalV2).'.'.hash_hmac('sha256', $canonicalV2, $secret);
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
        // BC shim: pre-gate callers passed the clock override positionally
        // as the constructor's second argument. It must be treated as $now,
        // not as an admission gate.
        $record = $this->v2Sha256Record();
        $storage = new ArrayStorage();
        $storage->store($record);

        $verifier = new Verifier($storage, static fn (): int => self::ISSUED_AT + 121);
        $outcome = $verifier->verify($this->tokenFor($record->nonce, 0), Vectors::SECRET, 'login', self::CLIENT_IP);

        self::assertSame(VerifyError::Expired, $outcome->error, 'a positional Closure must drive the TTL clock');
    }

    public function testBoundRecordWithoutClientIpFailsClosed(): void
    {
        // A non-empty binding tag means the challenge IS bound — omitting
        // the client IP must fail with MissingClientIp, not silently skip
        // the check (the caller must provide the IP it passed to issuance).
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
        // Only protocol versions 1 (legacy migration) and 2 (current) exist
        // in the wire contract — anything else is a corrupt/foreign record.
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
}
