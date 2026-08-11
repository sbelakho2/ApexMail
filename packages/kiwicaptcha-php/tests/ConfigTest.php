<?php

declare(strict_types=1);

namespace KiwiCaptcha\Tests;

use KiwiCaptcha\Config;
use KiwiCaptcha\PoWAlgorithm;
use KiwiCaptcha\Tests\Fixtures\Vectors;
use PHPUnit\Framework\TestCase;

final class ConfigTest extends TestCase
{
    private function base(array $overrides = []): array
    {
        return array_merge([
            'secretKey' => Vectors::SECRET,
            'algorithm' => PoWAlgorithm::Sha256,
            'mKib' => 0,
            't' => 1,
            'p' => 1,
            'targetBits' => 20,
            'argon2TargetBits' => 8,
            'ttlSecs' => 120,
            'minDurationMs' => null,
        ], $overrides);
    }

    public function testSha256DefaultsAreValid(): void
    {
        $config = new Config(...$this->base());
        self::assertSame(PoWAlgorithm::Sha256, $config->algorithm);
    }

    public function testArgon2WithT1Throws(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('libsodium');

        new Config(...$this->base([
            'algorithm' => PoWAlgorithm::Argon2id,
            'mKib' => 64,
            't' => 1,
        ]));
    }

    public function testArgon2WithT2Throws(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('t >= 3');

        new Config(...$this->base([
            'algorithm' => PoWAlgorithm::Argon2id,
            'mKib' => 64,
            't' => 2,
        ]));
    }

    public function testArgon2WithT3P1IsValid(): void
    {
        $config = new Config(...$this->base([
            'algorithm' => PoWAlgorithm::Argon2id,
            'mKib' => 64,
            't' => 3,
            'p' => 1,
            'targetBits' => 4,
            'argon2TargetBits' => 4,
        ]));
        self::assertSame(3, $config->t);
    }

    public function testArgon2WithP2Throws(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('p == 1');

        new Config(...$this->base([
            'algorithm' => PoWAlgorithm::Argon2id,
            'mKib' => 64,
            't' => 3,
            'p' => 2,
        ]));
    }

    public function testSha256WithT0Throws(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('t must be >= 1');

        new Config(...$this->base(['t' => 0]));
    }

    public function testSha256WithT1IsValid(): void
    {
        $config = new Config(...$this->base(['t' => 1]));
        self::assertSame(1, $config->t);
    }

    public function testP0Throws(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('p must be >= 1');

        new Config(...$this->base(['p' => 0]));
    }

    public function testArgon2TargetBitsBounds(): void
    {
        $args = [
            'algorithm' => PoWAlgorithm::Argon2id,
            'mKib' => 64,
            't' => 3,
            'p' => 1,
            'targetBits' => 4,
        ];

        foreach ([0, 11] as $bad) {
            try {
                new Config(...$this->base($args + ['argon2TargetBits' => $bad]));
                self::fail("argon2TargetBits=$bad should have been rejected");
            } catch (\InvalidArgumentException) {
                // expected
            }
        }

        foreach ([1, 10] as $good) {
            $config = new Config(...$this->base($args + ['argon2TargetBits' => $good]));
            self::assertSame($good, $config->argon2TargetBits);
        }
    }

    public function testSha256IgnoresArgon2TargetBits(): void
    {
        // Non-Argon2id configs are unaffected by the argon2-specific bounds.
        $config = new Config(...$this->base(['argon2TargetBits' => 0]));
        self::assertSame(0, $config->argon2TargetBits);
    }

    public function testTargetBitsBounds(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('0..24');

        new Config(...$this->base(['targetBits' => 25]));
    }

    public function testTargetBits24IsValid(): void
    {
        $config = new Config(...$this->base(['targetBits' => 24]));
        self::assertSame(24, $config->targetBits);
    }

    public function testMKibCeilingEnforced(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('65536');

        new Config(...$this->base([
            'algorithm' => PoWAlgorithm::Argon2id,
            'mKib' => 65_536 + 1,
            't' => 3,
            'p' => 1,
        ]));
    }

    public function testMKibBelow8PRejected(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('m_kib >= 8 * p');

        new Config(...$this->base([
            'algorithm' => PoWAlgorithm::Argon2id,
            'mKib' => 7,
            't' => 3,
            'p' => 1,
        ]));
    }

    public function testShortSecretRejected(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('at least 16 bytes');

        new Config(...$this->base(['secretKey' => 'tooshort']));
    }
}
