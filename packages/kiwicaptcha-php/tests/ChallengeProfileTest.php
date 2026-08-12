<?php

declare(strict_types=1);

namespace KiwiCaptcha\Tests;

use KiwiCaptcha\ChallengeProfile;
use KiwiCaptcha\Config;
use KiwiCaptcha\Issuer;
use KiwiCaptcha\PoWAlgorithm;
use KiwiCaptcha\SolutionToken;
use KiwiCaptcha\Storage\ArrayStorage;
use KiwiCaptcha\Tests\Fixtures\Vectors;
use KiwiCaptcha\Verifier;
use PHPUnit\Framework\TestCase;

/**
 * ChallengeProfile: adaptive-risk difficulty profiles and
 * Issuer::issueWithProfile() — profiles must validate against the SAME
 * bounds as Config/issuance and must issue challenges that are
 * byte-for-byte indistinguishable from a normal issue (same wire format,
 * signing, storage — only the parameters differ).
 */
final class ChallengeProfileTest extends TestCase
{
    /** @return array{Issuer, ArrayStorage} */
    private function issuer(): array
    {
        $config = new Config(
            secretKey: Vectors::SECRET,
            algorithm: PoWAlgorithm::Sha256,
            targetBits: 8,
            argon2TargetBits: 8,
            ttlSecs: 120,
            minDurationMs: null,
        );
        $storage = new ArrayStorage();

        return [new Issuer($config, $storage), $storage];
    }

    /** @return array{Issuer, ArrayStorage, ChallengeProfile} */
    private function issuerWith(ChallengeProfile $profile): array
    {
        [$issuer, $storage] = $this->issuer();

        return [$issuer, $storage, $profile];
    }

    private function assertInvalid(ChallengeProfile $profile): void
    {
        try {
            $profile->validate();
            self::fail(sprintf('profile (%s, targetBits=%d, mKib=%d, t=%d, p=%d) should have been rejected', $profile->algorithm->value, $profile->targetBits, $profile->mKib, $profile->t, $profile->p));
        } catch (\InvalidArgumentException $e) {
            self::assertNotSame('', $e->getMessage(), 'rejection must carry a clear message');
        }
    }

    private function assertValid(ChallengeProfile $profile): void
    {
        $profile->validate();
        self::assertTrue(true, sprintf('profile (%s, targetBits=%d, mKib=%d, t=%d, p=%d) must validate', $profile->algorithm->value, $profile->targetBits, $profile->mKib, $profile->t, $profile->p));
    }

    // ── Named profiles ────────────────────────────────────────────────

    public function testNamedProfilesCarryExpectedParameters(): void
    {
        $sha = ChallengeProfile::sha(16);
        self::assertSame(PoWAlgorithm::Sha256, $sha->algorithm);
        self::assertSame(16, $sha->targetBits);
        self::assertSame(0, $sha->mKib);

        $argon = ChallengeProfile::argon16();
        self::assertSame(PoWAlgorithm::Argon2id, $argon->algorithm);
        self::assertSame(16384, $argon->mKib);
        self::assertSame(3, $argon->t);
        self::assertSame(1, $argon->p);
        self::assertSame(1, $argon->targetBits);

        self::assertSame(32768, ChallengeProfile::argon32()->mKib);
        self::assertSame(65536, ChallengeProfile::argon64()->mKib);
    }

    // ── SHA-256 validation boundaries ─────────────────────────────────

    public function testShaProfileRejectsTargetBitsAboveCeiling(): void
    {
        $this->assertInvalid(ChallengeProfile::sha(21));
    }

    public function testShaProfileAcceptsTargetBitsAtCeiling(): void
    {
        $this->assertValid(ChallengeProfile::sha(20));
    }

    public function testShaProfileRejectsZeroTargetBits(): void
    {
        $this->assertInvalid(ChallengeProfile::sha(0));
    }

    // ── Argon2id validation boundaries ────────────────────────────────

    public function testArgonProfileRejectsTAboveCeiling(): void
    {
        $this->assertInvalid(new ChallengeProfile(PoWAlgorithm::Argon2id, 1, 16384, 7, 1));
    }

    public function testArgonProfileAcceptsTAtCeiling(): void
    {
        $this->assertValid(new ChallengeProfile(PoWAlgorithm::Argon2id, 1, 16384, 6, 1));
    }

    public function testArgonProfileRejectsMKibBelowMinimum(): void
    {
        $this->assertInvalid(new ChallengeProfile(PoWAlgorithm::Argon2id, 1, 7, 3, 1));
    }

    public function testArgonProfileAcceptsMKibAtCeiling(): void
    {
        $this->assertValid(new ChallengeProfile(PoWAlgorithm::Argon2id, 1, 65536, 3, 1));
    }

    public function testArgonProfileRejectsMKibAboveCeiling(): void
    {
        $this->assertInvalid(new ChallengeProfile(PoWAlgorithm::Argon2id, 1, 65537, 3, 1));
    }

    public function testArgonProfileRejectsTargetBitsAboveCeiling(): void
    {
        $this->assertInvalid(new ChallengeProfile(PoWAlgorithm::Argon2id, 11, 16384, 3, 1));
    }

    public function testArgonProfileRejectsZeroTargetBits(): void
    {
        $this->assertInvalid(new ChallengeProfile(PoWAlgorithm::Argon2id, 0, 16384, 3, 1));
    }

    public function testArgonProfileRejectsTBelowMinimum(): void
    {
        $this->assertInvalid(new ChallengeProfile(PoWAlgorithm::Argon2id, 1, 16384, 2, 1));
    }

    public function testArgonProfileRejectsPNotOne(): void
    {
        $this->assertInvalid(new ChallengeProfile(PoWAlgorithm::Argon2id, 1, 16384, 3, 2));
    }

    // ── issueWithProfile: end-to-end ──────────────────────────────────

    public function testIssueWithProfileSha16SolvesAndVerifies(): void
    {
        [$issuer, $storage, $profile] = $this->issuerWith(ChallengeProfile::sha(16));
        $challenge = $issuer->issueWithProfile('login', Vectors::CLIENT_IP, $profile, now: Vectors::ISSUED_AT);
        $record = $storage->find($challenge->nonce);
        self::assertNotNull($record);

        self::assertSame(PoWAlgorithm::Sha256, $record->algorithm);
        self::assertSame(16, $record->targetBits);
        self::assertSame(0, $record->mKib);
        self::assertSame(1, $record->t);
        self::assertSame(1, $record->p);

        $counter = $this->solveSha($challenge->prefix, $challenge->salt, $challenge->targetBits);
        $token = SolutionToken::create($challenge->nonce, $counter, 5000, [])->encode();
        $outcome = (new Verifier($storage))->verify($token, Vectors::SECRET, 'login', Vectors::CLIENT_IP, (int) (microtime(true) * 1_000_000) + 1_000_000);
        self::assertTrue($outcome->isOk(), sprintf('expected Valid, got %s', $outcome->code()));
    }

    public function testIssueWithProfileSha20SolvesAndVerifies(): void
    {
        // 20 bits needs ~1M hashes; a counter above the solver cap (5M)
        // makes the token malformed, so retry on a fresh challenge when an
        // unlucky solve exceeds it (~0.7% per attempt).
        $token = null;
        for ($attempt = 0; $attempt < 3; $attempt++) {
            [$issuer, $storage, $profile] = $this->issuerWith(ChallengeProfile::sha(20));
            $challenge = $issuer->issueWithProfile('login', Vectors::CLIENT_IP, $profile, now: Vectors::ISSUED_AT);
            $record = $storage->find($challenge->nonce);
            self::assertSame(20, $record?->targetBits);
            $counter = $this->solveSha($challenge->prefix, $challenge->salt, $challenge->targetBits);
            if ($counter <= SolutionToken::maxSolverCounter()) {
                $token = SolutionToken::create($challenge->nonce, $counter, 5000, [])->encode();
                break;
            }
        }
        self::assertNotNull($token, 'a sha-20 solve within the solver cap must be found');
        $outcome = (new Verifier($storage))->verify($token, Vectors::SECRET, 'login', Vectors::CLIENT_IP, (int) (microtime(true) * 1_000_000) + 1_000_000);
        self::assertTrue($outcome->isOk(), sprintf('expected Valid, got %s', $outcome->code()));
    }

    public function testIssueWithProfileArgon16SolvesAndVerifies(): void
    {
        [$issuer, $storage, $profile] = $this->issuerWith(ChallengeProfile::argon16());
        $challenge = $issuer->issueWithProfile('login', Vectors::CLIENT_IP, $profile, now: Vectors::ISSUED_AT);
        $record = $storage->find($challenge->nonce);
        self::assertNotNull($record);

        self::assertSame(PoWAlgorithm::Argon2id, $record->algorithm);
        self::assertSame(16384, $record->mKib);
        self::assertSame(3, $record->t);
        self::assertSame(1, $record->p);
        self::assertSame(1, $record->targetBits);

        $counter = $this->solveArgon($challenge->prefix, $challenge->salt, $challenge->targetBits, $challenge->mKib, $challenge->t);
        $token = SolutionToken::create($challenge->nonce, $counter, 5000, [])->encode();
        $outcome = (new Verifier($storage))->verify($token, Vectors::SECRET, 'login', Vectors::CLIENT_IP, (int) (microtime(true) * 1_000_000) + 1_000_000);
        self::assertTrue($outcome->isOk(), sprintf('expected Valid, got %s', $outcome->code()));
    }

    public function testIssueWithProfileDoesNotMutateIssuerConfig(): void
    {
        [$issuer, $storage] = $this->issuer();
        $issuer->issueWithProfile('login', Vectors::CLIENT_IP, ChallengeProfile::sha(16), now: Vectors::ISSUED_AT);

        // The issuer's own config must be untouched (profile issuance clones
        // it) — a subsequent plain issue still uses the configured params.
        self::assertSame(8, $issuer->config()->targetBits);

        $challenge = $issuer->issue('login', Vectors::CLIENT_IP);
        $record = $storage->find($challenge->nonce);
        self::assertSame(8, $record?->targetBits);
    }

    public function testIssueWithProfileRejectsInvalidProfile(): void
    {
        [$issuer] = $this->issuer();
        try {
            $issuer->issueWithProfile('login', Vectors::CLIENT_IP, ChallengeProfile::sha(21), now: Vectors::ISSUED_AT);
            self::fail('invalid profile must be rejected by issueWithProfile');
        } catch (\InvalidArgumentException $e) {
            self::assertStringContainsString('target bits', $e->getMessage());
        }
        try {
            $issuer->issueWithProfile('login', Vectors::CLIENT_IP, new ChallengeProfile(PoWAlgorithm::Argon2id, 1, 16384, 7, 1), now: Vectors::ISSUED_AT);
            self::fail('invalid argon profile must be rejected by issueWithProfile');
        } catch (\InvalidArgumentException $e) {
            self::assertStringContainsString('time cost', $e->getMessage());
        }
    }

    public function testIssueWithProfileDelegatesScopeValidation(): void
    {
        [$issuer] = $this->issuer();
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('scope');
        $issuer->issueWithProfile('', Vectors::CLIENT_IP, ChallengeProfile::sha(16));
    }

    // ── helpers ───────────────────────────────────────────────────────

    private function solveSha(string $prefix, string $saltB64, int $targetBits): int
    {
        $salt = base64_decode($saltB64, true);
        $base = hash_init('sha256');
        hash_update($base, $prefix);
        $counter = 0;
        do {
            $ctx = hash_copy($base);
            hash_update($ctx, (string) $counter);
            hash_update($ctx, $salt);
            $h = hash_final($ctx, true);
            ++$counter;
        } while (Verifier::leadingZeroBits($h) < $targetBits);

        return $counter - 1;
    }

    private function solveArgon(string $prefix, string $saltB64, int $targetBits, int $mKib, int $t): int
    {
        $salt = base64_decode($saltB64, true);
        $counter = 0;
        do {
            $h = sodium_crypto_pwhash(32, $prefix.$counter, $salt, $t, $mKib * 1024, SODIUM_CRYPTO_PWHASH_ALG_ARGON2ID13);
            ++$counter;
        } while (Verifier::leadingZeroBits((string) $h) < $targetBits);

        return $counter - 1;
    }
}
