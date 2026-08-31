<?php

declare(strict_types=1);

namespace KiwiCaptcha\Tests;

use KiwiCaptcha\Config;
use KiwiCaptcha\DerivedKeys;
use KiwiCaptcha\Issuer;
use KiwiCaptcha\PoWAlgorithm;
use KiwiCaptcha\SolutionToken;
use KiwiCaptcha\Storage\ArrayStorage;
use KiwiCaptcha\Verifier;
use KiwiCaptcha\VerifyError;
use KiwiCaptcha\Tests\Fixtures\Vectors;
use PHPUnit\Framework\TestCase;

/**
 * Secret-compartment fuzzing: two deployments with different secret
 * keys sharing one storage (the shared-Redis-prefix shape) must each
 * verify only their own tokens. The fuzz corpus mixes hex and non-hex
 * secrets across the accepted lengths (16 bytes and up), including
 * unicode and delimiter-bearing material.
 *
 * The properties under test: zero cross-secret acceptance, disjoint
 * HKDF-derived purpose keys, and a verifier keyring that resolves no
 * foreign token. Deterministic: one fixed seed, bounded iterations.
 */
final class TenantIsolationSecretFuzzTest extends TestCase
{
    private const SEED = 0x5EED;

    private const HEX_ALPHABET = '0123456789abcdef';

    private const WIDE_ALPHABET = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=[]{}|;:,.<>?/~` ';

    private function solve(string $prefix, string $salt, int $targetBits): int
    {
        $saltBytes = base64_decode($salt, true);
        $counter = 0;
        do {
            $hash = hash('sha256', $prefix.$counter.$saltBytes, true);
            $counter++;
        } while (Verifier::leadingZeroBits($hash) < $targetBits);

        return $counter - 1;
    }

    private function makeConfig(string $secret, int $kid = 1): Config
    {
        return new Config(
            secretKey: $secret,
            algorithm: PoWAlgorithm::Sha256,
            targetBits: 1,
            minDurationMs: 0,
            kid: $kid,
        );
    }

    /** @return array{0: ArrayStorage, 1: string} the token and the storage */
    private function issueAndSolve(ArrayStorage $storage, string $secret, int $kid = 1): array
    {
        $challenge = (new Issuer($this->makeConfig($secret, $kid), $storage))->issue('login', '198.51.100.7');
        $counter = $this->solve($challenge->prefix, $challenge->salt, $challenge->targetBits);

        return [$storage, SolutionToken::create($challenge->nonce, $counter, 5000, [])->encode()];
    }

    /** A seeded random secret over a given alphabet and length. */
    private function randomSecret(string $alphabet, int $length): string
    {
        $out = '';
        for ($i = 0; $i < $length; $i++) {
            $out .= $alphabet[mt_rand(0, \strlen($alphabet) - 1)];
        }

        return $out;
    }

    /**
     * The bounded secret corpus: hex and non-hex material across the
     * accepted lengths, plus unicode and separator-bearing values.
     *
     * @return list<string>
     */
    private function secretCorpus(): array
    {
        mt_srand(self::SEED);
        $secrets = [];
        foreach ([16, 17, 24, 32, 40, 64] as $length) {
            $secrets[] = $this->randomSecret(self::HEX_ALPHABET, $length);
            $secrets[] = $this->randomSecret(self::WIDE_ALPHABET, $length);
        }
        $secrets[] = '0123456789abcdef0123456789abcdef';
        $secrets[] = '秘密鍵1234567890abcdef';
        $secrets[] = 'tenant-a|0123456789abcdef';
        $secrets[] = 'tenant-a;0123456789abcdef';
        $secrets[] = "binary\x00key\x00\xff0123456789ab";
        $secrets[] = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
        $secrets[] = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';

        return $secrets;
    }

    public function testCrossSecretVerificationNeverAccepts(): void
    {
        $secrets = $this->secretCorpus();
        self::assertGreaterThanOrEqual(16, \count($secrets), 'the corpus must be bounded but broad');

        foreach ($secrets as $i => $secretA) {
            foreach ($secrets as $j => $secretB) {
                if ($i === $j) {
                    continue;
                }

                [$storage, $token] = $this->issueAndSolve(new ArrayStorage(), $secretA);
                $record = $storage->find(SolutionToken::decode($token)->nonce);
                self::assertNotNull($record);

                $cross = (new Verifier($storage))->verify(
                    $token,
                    $secretB,
                    'login',
                    '198.51.100.7',
                    nowNs: $record->issuedAtNs + 1_000_000,
                );
                self::assertSame(
                    VerifyError::BadSignature,
                    $cross->error,
                    sprintf('a token signed under secret %d must never verify under secret %d', $i, $j),
                );
                self::assertNull(
                    $storage->find($record->nonce),
                    'the cross-secret attempt must burn the challenge record',
                );
            }
        }
    }

    public function testOwnSecretVerifiesAcrossTheWholeCorpus(): void
    {
        foreach ($this->secretCorpus() as $secret) {
            [$storage, $token] = $this->issueAndSolve(new ArrayStorage(), $secret);
            $record = $storage->find(SolutionToken::decode($token)->nonce);
            self::assertNotNull($record);
            $outcome = (new Verifier($storage))->verify(
                $token,
                $secret,
                'login',
                '198.51.100.7',
                nowNs: $record->issuedAtNs + 1_000_000,
            );
            self::assertTrue($outcome->isOk(), sprintf('a token must verify under its own secret, got %s', $outcome->code()));
        }
    }

    public function testDerivedPurposeKeysAreDisjointAcrossSecrets(): void
    {
        $secrets = $this->secretCorpus();
        $challengeKeys = [];
        $ipBindKeys = [];
        foreach ($secrets as $secret) {
            $keys = DerivedKeys::fromMaster($secret);
            $challengeKeys[] = $keys->challengeKey();
            $ipBindKeys[] = $keys->ipBindKey();
        }

        self::assertSame(\count($challengeKeys), \count(array_unique($challengeKeys)), 'two secrets must never share a challenge purpose key');
        self::assertSame(\count($ipBindKeys), \count(array_unique($ipBindKeys)), 'two secrets must never share an IP-binding purpose key');
    }

    public function testKeyringResolvesNoForeignToken(): void
    {
        $secretA = '0123456789abcdef0123456789abcdef';
        $secretB = 'fedcba9876543210fedcba9876543210';

        [$storage, $token] = $this->issueAndSolve(new ArrayStorage(), $secretA, kid: 1);
        $record = $storage->find(SolutionToken::decode($token)->nonce);
        self::assertNotNull($record);

        $ringB = (new Verifier($storage, secretsByKid: [1 => $secretB]))->verify(
            $token,
            $secretB,
            'login',
            '198.51.100.7',
            nowNs: $record->issuedAtNs + 1_000_000,
        );
        self::assertSame(
            VerifyError::BadSignature,
            $ringB->error,
            'a keyring holding a different secret at the same kid must reject the token',
        );

        [$storage2, $token2] = $this->issueAndSolve(new ArrayStorage(), $secretA, kid: 1);
        $record2 = $storage2->find(SolutionToken::decode($token2)->nonce);
        self::assertNotNull($record2);
        $ringFutureKid = (new Verifier($storage2, secretsByKid: [2 => $secretA]))->verify(
            $token2,
            $secretA,
            'login',
            '198.51.100.7',
            nowNs: $record2->issuedAtNs + 1_000_000,
        );
        self::assertSame(
            VerifyError::UnknownKid,
            $ringFutureKid->error,
            'a keyring without the signing kid must reject the token as unknown',
        );
    }

    public function testConfigRefusesSecretsBelowSixteenBytes(): void
    {
        foreach (['', 'x', '0123456789abcde'] as $short) {
            try {
                new Config(secretKey: $short, targetBits: 8);
                self::fail(sprintf('a %d-byte secret must be refused', \strlen($short)));
            } catch (\InvalidArgumentException) {
            }
        }
        self::assertSame(16, \strlen('0123456789abcdef'));
    }
}
