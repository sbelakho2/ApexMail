<?php

declare(strict_types=1);

namespace KiwiCaptcha\Tests;

use KiwiCaptcha\ChallengeRecord;
use KiwiCaptcha\Config;
use KiwiCaptcha\Issuer;
use KiwiCaptcha\MalformedRecordException;
use KiwiCaptcha\PoWAlgorithm;
use KiwiCaptcha\SolutionToken;
use KiwiCaptcha\Storage\ArrayStorage;
use KiwiCaptcha\Verifier;
use KiwiCaptcha\VerifyError;
use KiwiCaptcha\Tests\Fixtures\Vectors;
use PHPUnit\Framework\TestCase;

/**
 * Scope-compartment fuzzing: a challenge issued under one scope must
 * verify only under that exact scope, and a stored record whose scope
 * is outside the identifier alphabet must be rejected as malformed.
 *
 * The fuzz corpus mixes seeded random scopes over the identifier
 * alphabet (bytes 1..128 of [A-Za-z0-9._:-]) with adversarial strings
 * (unicode, embedded separators such as | ; and the null byte,
 * whitespace, boundary lengths, case variants). Every generated scope
 * is driven through issuance and verification; every out-of-alphabet
 * string is driven through the issuer gate, the identifier validator
 * and the stored-record validator. The property under test is zero
 * cross-scope acceptance.
 *
 * Deterministic: one fixed seed, bounded iterations, no wall-clock
 * dependence.
 */
final class TenantIsolationScopeFuzzTest extends TestCase
{
    private const SEED = 0x5C0E;

    private const ALPHABET = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._:-';

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

    private function makeIssuer(ArrayStorage $storage): Issuer
    {
        return new Issuer(
            new Config(
                secretKey: Vectors::SECRET,
                algorithm: PoWAlgorithm::Sha256,
                targetBits: 1,
                minDurationMs: 0,
            ),
            $storage,
        );
    }

    private function makeVerifier(ArrayStorage $storage): Verifier
    {
        return new Verifier($storage);
    }

    /** @return array{0: ArrayStorage, 1: string} storage plus the solution token */
    private function issueAndSolve(ArrayStorage $storage, string $scope): array
    {
        $challenge = $this->makeIssuer($storage)->issue($scope, '198.51.100.7');
        $counter = $this->solve($challenge->prefix, $challenge->salt, $challenge->targetBits);

        return [$storage, SolutionToken::create($challenge->nonce, $counter, 5000, [])->encode()];
    }

    /**
     * A seeded random scope over the identifier alphabet, 1..128 bytes.
     */
    private function randomScope(): string
    {
        $len = mt_rand(1, 128);
        $out = '';
        for ($i = 0; $i < $len; $i++) {
            $out .= self::ALPHABET[mt_rand(0, \strlen(self::ALPHABET) - 1)];
        }

        return $out;
    }

    /**
     * The adversarial scope corpus: strings a hostile caller could send
     * through the public issuance surface. Each entry carries an
     * expectation flag: true when the string is a valid identifier and
     * must issue, false when the string must be refused everywhere.
     *
     * @return list<array{0: string, 1: bool}>
     */
    private function adversarialCorpus(): array
    {
        $long128 = str_repeat('a', 128);

        return [
            ['', false],
            [' ', false],
            ["\t", false],
            ["\n", false],
            [str_repeat('a', 129), false],
            [str_repeat('a', 200), false],
            ['login|admin', false],
            ['login;admin', false],
            ["login\0admin", false],
            ["logi\nn", false],
            ["logi\tn", false],
            [' login', false],
            ['login ', false],
            ['登录', false],
            ['logîn', false],
            ['lög.in', false],
            ["a\x00", false],
            ['a|b|c', false],
            [$long128, true],
            ['login', true],
            ['Login', true],
            ['LOGIN', true],
            ['LoGiN', true],
            ['login.', true],
            ['.login', true],
            ['login:', true],
            ['login-', true],
            ['login_', true],
            ['a.b-c:d_e', true],
            ['1', true],
        ];
    }

    public function testSeededRandomScopesNeverVerifyAcrossEachOther(): void
    {
        mt_srand(self::SEED);
        $count = 240;
        $scopes = [];
        for ($i = 0; $i < $count; $i++) {
            $scopes[] = $this->randomScope();
        }

        foreach ($scopes as $i => $scope) {
            $other = $scopes[($i + 1) % $count];

            [$storage, $token] = $this->issueAndSolve(new ArrayStorage(), $scope);
            $record = $storage->find(SolutionToken::decode($token)->nonce);
            self::assertNotNull($record);
            $outcome = $this->makeVerifier($storage)->verify(
                $token,
                Vectors::SECRET,
                $scope,
                '198.51.100.7',
                nowNs: $record->issuedAtNs + 1_000_000,
            );
            self::assertTrue(
                $outcome->isOk(),
                sprintf('scope %d must verify under its own scope, got %s', $i, $outcome->code()),
            );

            [$storage2, $token2] = $this->issueAndSolve(new ArrayStorage(), $scope);
            $record2 = $storage2->find(SolutionToken::decode($token2)->nonce);
            self::assertNotNull($record2);
            $cross = $this->makeVerifier($storage2)->verify(
                $token2,
                Vectors::SECRET,
                $other,
                '198.51.100.7',
                nowNs: $record2->issuedAtNs + 1_000_000,
            );
            self::assertSame(
                VerifyError::WrongScope,
                $cross->error,
                sprintf('scope %d must never verify under scope %d', $i, ($i + 1) % $count),
            );
            self::assertNull(
                $storage2->find($record2->nonce),
                'a cross-scope attempt must burn the challenge record',
            );
        }
    }

    public function testAdversarialScopesAreRefusedOrIsolatedPerExpectation(): void
    {
        mt_srand(self::SEED + 1);
        foreach ($this->adversarialCorpus() as [$scope, $valid]) {
            self::assertSame($valid, Config::isValidIdentifier($scope, 128), sprintf('identifier validator for %s', bin2hex($scope)));

            $storage = new ArrayStorage();
            if (!$valid) {
                try {
                    $this->makeIssuer($storage)->issue($scope, '198.51.100.7');
                    self::fail(sprintf('issuance must refuse scope %s', bin2hex($scope)));
                } catch (\InvalidArgumentException) {
                    self::assertNull($storage->find(''), 'nothing may be stored for a refused scope');
                }

                continue;
            }

            [$storage2, $token] = $this->issueAndSolve($storage, $scope);
            $record = $storage2->find(SolutionToken::decode($token)->nonce);
            self::assertNotNull($record);
            $outcome = $this->makeVerifier($storage2)->verify(
                $token,
                Vectors::SECRET,
                $scope,
                '198.51.100.7',
                nowNs: $record->issuedAtNs + 1_000_000,
            );
            self::assertTrue($outcome->isOk(), sprintf('valid scope %s must verify', bin2hex($scope)));
        }
    }

    public function testStoredRecordValidatorRejectsEveryOutOfAlphabetScope(): void
    {
        mt_srand(self::SEED + 2);
        $refused = array_values(array_filter(
            $this->adversarialCorpus(),
            static fn (array $entry): bool => !$entry[1],
        ));

        foreach ($refused as [$scope, ]) {
            [$source, $token] = $this->issueAndSolve(new ArrayStorage(), 'login');
            $record = $source->find(SolutionToken::decode($token)->nonce);
            self::assertNotNull($record);

            $data = $record->toArray();
            $data['scope'] = $scope;

            $storage = new ArrayStorage();
            try {
                $mutated = ChallengeRecord::fromArray($data);
            } catch (MalformedRecordException) {
                continue;
            }
            $storage->store($mutated);

            $outcome = $this->makeVerifier($storage)->verify($token, Vectors::SECRET, 'login', '198.51.100.7');
            self::assertSame(
                VerifyError::MalformedRecord,
                $outcome->error,
                sprintf('a stored scope of %s must be malformed, got %s', bin2hex($scope), $outcome->code()),
            );
        }
    }

    public function testBoundaryLengthsKeepTheirCompartment(): void
    {
        $long = str_repeat('x', 128);
        $short = 'x';

        [$storage, $token] = $this->issueAndSolve(new ArrayStorage(), $long);
        $record = $storage->find(SolutionToken::decode($token)->nonce);
        self::assertNotNull($record);
        $cross = $this->makeVerifier($storage)->verify($token, Vectors::SECRET, $short, '198.51.100.7');
        self::assertSame(VerifyError::WrongScope, $cross->error, 'a 128-byte scope must differ from a 1-byte scope');

        [$storage2, $token2] = $this->issueAndSolve(new ArrayStorage(), $short);
        $record2 = $storage2->find(SolutionToken::decode($token2)->nonce);
        self::assertNotNull($record2);
        $cross2 = $this->makeVerifier($storage2)->verify($token2, Vectors::SECRET, $long, '198.51.100.7');
        self::assertSame(VerifyError::WrongScope, $cross2->error, 'a 1-byte scope must differ from a 128-byte scope');
    }
}
