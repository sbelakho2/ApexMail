<?php

declare(strict_types=1);

namespace KiwiCaptcha\Tests;

use KiwiCaptcha\Config;
use KiwiCaptcha\Issuer;
use KiwiCaptcha\PoWAlgorithm;
use KiwiCaptcha\SolutionToken;
use KiwiCaptcha\Storage\RedisStorage;
use KiwiCaptcha\Tests\Fixtures\FakePredisClient;
use KiwiCaptcha\Tests\Fixtures\Vectors;
use KiwiCaptcha\Verifier;
use PHPUnit\Framework\TestCase;

/**
 * The decoy (honeypot) surface must be wire-cost neutral: arming the
 * decoy at issuance, and verifying an armed record, performs exactly
 * the same Redis command sequence as the unarmed flow. The decoy name
 * is signed into the record envelope by the issuer; it costs no extra
 * GET, eval, evalsha or WAIT on either side of the lifecycle. The
 * FakePredisClient records every command dispatch, so the parity
 * assertions compare the armed trace against the unarmed trace cell
 * for cell: the total command count, the eval count and the round-trip
 * count. Each command is one round trip on the wire, because the
 * Predis sync client sends no pipelined batch on these flows.
 */
final class DecoyRedisCommandParityTest extends TestCase
{
    private const ISSUED_AT = 1_800_000_000;

    private const CLIENT_IP = '198.51.100.7';

    private function config(): Config
    {
        return new Config(
            secretKey: Vectors::SECRET,
            algorithm: PoWAlgorithm::Sha256,
            mKib: 0,
            t: 1,
            p: 1,
            targetBits: 8,
            argon2TargetBits: 8,
            ttlSecs: 120,
            minDurationMs: 0,
        );
    }

    /**
     * Issue one challenge through RedisStorage on a fresh fake client,
     * armed or unarmed, and return the client, the storage, the
     * challenge and the stored record.
     *
     * @return array{0: FakePredisClient, 1: RedisStorage, 2: \KiwiCaptcha\Challenge, 3: \KiwiCaptcha\ChallengeRecord}
     */
    private function issue(bool $armed): array
    {
        $client = new FakePredisClient();
        $storage = new RedisStorage($client);
        $issuer = new Issuer($this->config(), $storage, now: static fn (): int => self::ISSUED_AT);
        $challenge = $armed
            ? $issuer->issueWithDecoyField('login', self::CLIENT_IP)
            : $issuer->issue('login', self::CLIENT_IP);
        $record = $storage->find($challenge->nonce);
        self::assertNotNull($record);

        return [$client, $storage, $challenge, $record];
    }

    /** Brute-force the winning counter for an 8-bit challenge (fast). */
    private function solveCounter(\KiwiCaptcha\Challenge $challenge): int
    {
        $counter = 0;
        $saltBytes = base64_decode($challenge->salt, true);
        do {
            $hash = hash('sha256', $challenge->prefix.$counter.$saltBytes, true);
            $counter++;
        } while (Verifier::leadingZeroBits($hash) < $challenge->targetBits);

        return $counter - 1;
    }

    public function testIssuanceWithTheDecoyArmedCostsTheSameRedisCommands(): void
    {
        if (!\class_exists(\Predis\Client::class)) {
            self::markTestSkipped('predis/predis is not installed');
        }
        [$armedClient, , $armedChallenge] = $this->issue(true);
        [$plainClient, , $plainChallenge] = $this->issue(false);

        self::assertNotNull($armedChallenge->decoyField, 'the armed fixture must carry a decoy name');
        self::assertNull($plainChallenge->decoyField, 'the plain fixture must carry no decoy name');
        self::assertSame(
            \count($plainClient->calls),
            \count($armedClient->calls),
            'issuance must send the same number of Redis commands with or without the decoy',
        );
        self::assertSame(
            \count($plainClient->evals),
            \count($armedClient->evals),
            'issuance must run the same number of Lua evals with or without the decoy',
        );
        self::assertSame(
            \count($plainClient->calls),
            \count($armedClient->calls),
            'issuance must cost the same number of round trips, one command per round trip',
        );
    }

    public function testVerificationWithTheDecoyArmedCostsTheSameRedisCommands(): void
    {
        if (!\class_exists(\Predis\Client::class)) {
            self::markTestSkipped('predis/predis is not installed');
        }
        [$armedClient, $armedStorage, $armedChallenge, $armedRecord] = $this->issue(true);
        [$plainClient, $plainStorage, $plainChallenge, $plainRecord] = $this->issue(false);

        $armedToken = SolutionToken::create($armedChallenge->nonce, $this->solveCounter($armedChallenge), 5000, [])->encode();
        $plainToken = SolutionToken::create($plainChallenge->nonce, $this->solveCounter($plainChallenge), 5000, [])->encode();

        $armedClient->calls = [];
        $armedClient->evals = [];
        $plainClient->calls = [];
        $plainClient->evals = [];

        $armedOutcome = (new Verifier($armedStorage, now: static fn (): int => self::ISSUED_AT))->verify(
            $armedToken,
            Vectors::SECRET,
            'login',
            self::CLIENT_IP,
            nowNs: $armedRecord->issuedAtNs + 1_000_000,
        );
        $plainOutcome = (new Verifier($plainStorage, now: static fn (): int => self::ISSUED_AT))->verify(
            $plainToken,
            Vectors::SECRET,
            'login',
            self::CLIENT_IP,
            nowNs: $plainRecord->issuedAtNs + 1_000_000,
        );

        self::assertTrue($armedOutcome->isOk(), sprintf('the armed record must verify, got %s', $armedOutcome->code()));
        self::assertTrue($plainOutcome->isOk(), sprintf('the plain record must verify, got %s', $plainOutcome->code()));
        self::assertSame(
            \count($plainClient->calls),
            \count($armedClient->calls),
            'verification must send the same number of Redis commands with or without the decoy',
        );
        self::assertSame(
            \count($plainClient->evals),
            \count($armedClient->evals),
            'verification must run the same number of Lua evals with or without the decoy',
        );
        self::assertSame(
            \count($plainClient->calls),
            \count($armedClient->calls),
            'verification must cost the same number of round trips, one command per round trip',
        );
    }
}
