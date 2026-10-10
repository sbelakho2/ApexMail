<?php

declare(strict_types=1);

namespace KiwiCaptcha\Tests;

use KiwiCaptcha\Config;
use KiwiCaptcha\DerivedKeys;
use KiwiCaptcha\ExecutionChallengeGenerator;
use KiwiCaptcha\Storage\ArrayStorage;
use KiwiCaptcha\Verifier;
use PHPUnit\Framework\TestCase;

/**
 * The 32-byte secret floor at every PHP entry point, in exact parity with
 * the Rust core (keys::MIN_MASTER_BYTES / MIN_EXECUTION_KEY_BYTES). The
 * floor is a deployment safety contract, not a local choice: 31 bytes is
 * rejected and 32 bytes accepted in configuration, derivation, issuance,
 * execution generation and the verifier keyring. The shared register
 * (protocol/limits.json, tools/ci/limits-parity-check.sh) pins the same
 * values across PHP, Rust and the browser.
 */
final class SecretFloorBoundaryTest extends TestCase
{
    private const SHORT = '0123456789abcdef0123456789abcde';   // 31 bytes
    private const FLOOR = '0123456789abcdef0123456789abcdef';  // 32 bytes

    public function testConstantsAreTheSharedFloor(): void
    {
        self::assertSame(32, Config::MIN_SECRET_BYTES);
        self::assertSame(32, Config::MIN_EXECUTION_KEY_BYTES);
        self::assertSame(31, \strlen(self::SHORT), 'precondition: one byte below the floor');
        self::assertSame(32, \strlen(self::FLOOR), 'precondition: exactly at the floor');
    }

    public function testConfigRefusesShortSecretsAndAcceptsTheFloor(): void
    {
        try {
            new Config(secretKey: self::SHORT);
            self::fail('a 31-byte secret key must be refused');
        } catch (\InvalidArgumentException $e) {
            self::assertStringContainsString('at least 32 bytes', $e->getMessage());
        }
        self::assertInstanceOf(Config::class, new Config(secretKey: self::FLOOR));

        try {
            new Config(secretKey: self::FLOOR, executionKey: self::SHORT);
            self::fail('a 31-byte execution key must be refused');
        } catch (\InvalidArgumentException $e) {
            self::assertStringContainsString('at least 32 bytes', $e->getMessage());
        }
        self::assertInstanceOf(
            Config::class,
            new Config(secretKey: self::FLOOR, executionKey: self::FLOOR),
        );
    }

    public function testDerivationRefusesShortMastersAndAcceptsTheFloor(): void
    {
        try {
            DerivedKeys::fromMaster(self::SHORT);
            self::fail('a 31-byte master secret must be refused');
        } catch (\InvalidArgumentException $e) {
            self::assertStringContainsString('at least 32 bytes', $e->getMessage());
        }
        self::assertInstanceOf(DerivedKeys::class, DerivedKeys::fromMaster(self::FLOOR));
    }

    public function testExecutionGeneratorRefusesShortKeysAndAcceptsTheFloor(): void
    {
        try {
            ExecutionChallengeGenerator::generate(self::SHORT, 'nonce', 'login', 'login-action', 1);
            self::fail('a 31-byte execution key must be refused');
        } catch (\InvalidArgumentException $e) {
            self::assertStringContainsString('at least 32 bytes', $e->getMessage());
        }
        $program = ExecutionChallengeGenerator::generate(self::FLOOR, 'nonce', 'login', 'login-action', 1);
        self::assertNotSame('', $program);
    }

    public function testVerifierKeyringRefusesShortSecretsAndAcceptsTheFloor(): void
    {
        $storage = new ArrayStorage();

        try {
            new Verifier($storage, secretsByKid: [1 => self::SHORT]);
            self::fail('a 31-byte keyring secret must be refused');
        } catch (\InvalidArgumentException $e) {
            self::assertStringContainsString('at least 32 bytes', $e->getMessage());
        }
        self::assertInstanceOf(
            Verifier::class,
            new Verifier($storage, secretsByKid: [1 => self::FLOOR]),
        );
    }
}
