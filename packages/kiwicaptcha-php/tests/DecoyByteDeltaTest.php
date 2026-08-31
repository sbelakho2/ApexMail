<?php

declare(strict_types=1);

namespace KiwiCaptcha\Tests;

use KiwiCaptcha\Config;
use KiwiCaptcha\Issuer;
use KiwiCaptcha\PoWAlgorithm;
use KiwiCaptcha\SolutionToken;
use KiwiCaptcha\Storage\ArrayStorage;
use KiwiCaptcha\Storage\RedisStorage;
use KiwiCaptcha\Tests\Fixtures\FakePredisClient;
use KiwiCaptcha\Tests\Fixtures\Vectors;
use KiwiCaptcha\Verifier;
use PHPUnit\Framework\TestCase;

/**
 * The decoy-enabled vs decoy-disabled wire delta (the
 * performance-budget invariant).
 *
 * Arming the decoy must not change the storage or verification command
 * profile: the decoy name is signed into the record in-process, never
 * an extra Redis round trip. The challenge-response JSON may only grow
 * by the decoy field's own bytes, a bounded delta far below 512 B.
 * The Redis command sequence of issuance and of verification must be
 * identical (same command IDs, same argument counts — the key names
 * and values necessarily differ).
 */
final class DecoyByteDeltaTest extends TestCase
{
    private const BYTE_DELTA_BOUND = 512;

    private function shaConfig(): Config
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

    /** The wire shape of the bundle /challenge response (camelCase keys, the decoy last). */
    private function wireBytes(array $challenge): int
    {
        return \strlen(json_encode($challenge, JSON_UNESCAPED_SLASHES));
    }

    /** The command profile of a client: command IDs plus argument counts only. */
    private function commandProfile(FakePredisClient $client): array
    {
        return array_map(static fn (array $call): array => [strtoupper((string) $call[0]), \count($call[1])], $client->calls);
    }

    /** Brute-force the winning counter for an 8-bit challenge (fast). */
    private function solveCounter($challenge): int
    {
        $counter = 0;
        $saltBytes = base64_decode($challenge->salt, true);
        do {
            $hash = hash('sha256', $challenge->prefix.$counter.$saltBytes, true);
            $counter++;
        } while (Verifier::leadingZeroBits($hash) < $challenge->targetBits);

        return $counter - 1;
    }

    public function testDecoyArmedWireDeltaIsBoundedAndTheRedisCommandProfileIsIdentical(): void
    {
        // Unarmed issuance (protocol v2) through the Redis path.
        $plainClient = new FakePredisClient();
        $plainStorage = new RedisStorage($plainClient);
        $plainIssuer = new Issuer($this->shaConfig(), $plainStorage, now: static fn (): int => Vectors::NOW);
        $plain = $plainIssuer->issue('login', Vectors::CLIENT_IP);
        $plainWire = $this->wireBytes($plain->toArray());

        // Armed issuance (protocol v3, decoy signed into the record)
        // through the Redis path.
        $armedClient = new FakePredisClient();
        $armedStorage = new RedisStorage($armedClient);
        $armedIssuer = new Issuer($this->shaConfig(), $armedStorage, now: static fn (): int => Vectors::NOW);
        $armed = $armedIssuer->issueWithDecoyField('login', Vectors::CLIENT_IP);
        $armedWire = $this->wireBytes($armed->toArray());

        $delta = abs($armedWire - $plainWire);
        self::assertLessThan(
            self::BYTE_DELTA_BOUND,
            $delta,
            "the armed response must differ from the unarmed response by less than ".self::BYTE_DELTA_BOUND." bytes (measured delta $delta: unarmed $plainWire, armed $armedWire)",
        );
        // The delta is exactly the decoy field's own serialization cost:
        // the JSON key plus the quoted name (16 + len), plus TWO
        // base64-encoded copies of the signed `|<name>` canonical segment
        // (the `challenge` and `prefix` response fields both carry the
        // canonical payload). The armed name is at most 47 bytes, so the
        // whole delta stays far under the 512-byte invariant.
        $nameLen = \strlen((string) $armed->decoyField);
        $expectedDelta = 18 + $nameLen + 2 * (4 * intdiv($nameLen + 3, 3));
        self::assertLessThanOrEqual(
            $expectedDelta,
            $delta,
            'the armed response must differ only by the decoy field bytes (key, name and the two base64 copies of the signed segment)',
        );

        // The Redis command profile of issuance is identical: same
        // command IDs in the same order, same argument counts.
        self::assertSame(
            $this->commandProfile($plainClient),
            $this->commandProfile($armedClient),
            'arming the decoy must not change the Redis command sequence of issuance',
        );

        // Verification through the Redis path: identical command
        // profiles too (the consume transition and the result commit run
        // the same commands; only the stored bytes differ).
        $plainToken = SolutionToken::create($plain->nonce, $this->solveCounter($plain), 5000, [])->encode();
        $plainRecord = $plainStorage->find($plain->nonce);
        self::assertNotNull($plainRecord);
        $plainOutcome = (new Verifier($plainStorage, now: static fn (): int => Vectors::NOW))->verify($plainToken, Vectors::SECRET, 'login', Vectors::CLIENT_IP, nowNs: $plainRecord->issuedAtNs + 1_000_000);
        self::assertTrue($plainOutcome->isOk(), sprintf('the unarmed record must verify, got %s', $plainOutcome->code()));

        $armedToken = SolutionToken::create($armed->nonce, $this->solveCounter($armed), 5000, [])->encode();
        $armedRecord = $armedStorage->find($armed->nonce);
        self::assertNotNull($armedRecord);
        $armedOutcome = (new Verifier($armedStorage, now: static fn (): int => Vectors::NOW))->verify($armedToken, Vectors::SECRET, 'login', Vectors::CLIENT_IP, nowNs: $armedRecord->issuedAtNs + 1_000_000);
        self::assertTrue($armedOutcome->isOk(), sprintf('the armed record must verify, got %s', $armedOutcome->code()));

        self::assertSame(
            $this->commandProfile($plainClient),
            $this->commandProfile($armedClient),
            'verifying an armed record must run the identical Redis command sequence as a plain record',
        );
    }
}
