<?php

declare(strict_types=1);

namespace KiwiCaptcha\Tests;

use KiwiCaptcha\Config;
use KiwiCaptcha\DerivedKeys;
use KiwiCaptcha\Rsw;
use KiwiCaptcha\Storage\ArrayStorage;
use KiwiCaptcha\Tests\Fixtures\Vectors;
use KiwiCaptcha\Tests\Support\RswFixture;
use KiwiCaptcha\Verifier;
use PHPUnit\Framework\TestCase;

/**
 * The secret-bearing classes must never print their secrets under
 * var_dump/print_r. Every class exposes a __debugInfo that keeps the
 * full property shape visible under the exact property names with the
 * secret-bearing values replaced by '<redacted>'. The keys of a map are
 * identifiers, not secrets; the rsw modulus is public protocol material;
 * public protocol values stay inspectable.
 */
final class SecretRedactionDebugInfoTest extends TestCase
{
    private const SECRET_1 = '0123456789abcdef0123456789abcdef';

    private const SECRET_2 = 'fedcba9876543210fedcba9876543210';

    private const EXECUTION_KEY = 'abcdef0123456789abcdef0123456789';

    private const RSW_LAMBDA_PLACEHOLDER = 'not-a-real-lambda-b64';

    private static function varDump(mixed $value): string
    {
        ob_start();
        var_dump($value);

        return (string) ob_get_clean();
    }

    public function testConfigDebugInfoRedactsTheSecretValues(): void
    {
        $config = new Config(
            secretKey: self::SECRET_1,
            targetBits: 8,
            ttlSecs: 120,
            minDurationMs: 0,
            executionKey: self::EXECUTION_KEY,
            rswModulusN: 'not-a-real-modulus-b64',
            rswLambda: self::RSW_LAMBDA_PLACEHOLDER,
        );

        $dump = self::varDump($config);
        self::assertStringContainsString('<redacted>', $dump);
        self::assertStringNotContainsString(self::SECRET_1, $dump, 'the HMAC secret key must never print');
        self::assertStringNotContainsString(self::EXECUTION_KEY, $dump, 'the execution PRF key must never print');
        self::assertStringNotContainsString(self::RSW_LAMBDA_PLACEHOLDER, $dump, 'the rsw lambda must never print');
        self::assertStringContainsString('not-a-real-modulus-b64', $dump, 'the rsw modulus is public protocol material and stays inspectable');
        self::assertStringContainsString('targetBits', $dump, 'the full property shape stays visible under the exact property names');
        self::assertStringContainsString('rswT', $dump, 'the full property shape stays visible under the exact property names');
    }

    public function testVerifierDebugInfoRedactsTheSigningSecrets(): void
    {
        $hasGmp = \extension_loaded('gmp');
        $verifier = new Verifier(
            new ArrayStorage(),
            secretsByKid: [1 => self::SECRET_1, 2 => self::SECRET_2],
            revokedKids: [2],
            rswModulusN: $hasGmp ? RswFixture::MODULUS_N_B64 : null,
            rswLambda: $hasGmp ? RswFixture::LAMBDA_B64 : null,
        );

        $dump = self::varDump($verifier);
        self::assertStringContainsString('<redacted>', $dump);
        self::assertStringNotContainsString(self::SECRET_1, $dump, 'the kid-1 signing secret must never print');
        self::assertStringNotContainsString(self::SECRET_2, $dump, 'the kid-2 signing secret must never print');
        self::assertStringContainsString('[1]', $dump, 'the secretsByKid keys are kid identifiers and stay intact');
        self::assertStringContainsString('[2]', $dump, 'the secretsByKid keys are kid identifiers and stay intact');
        if ($hasGmp) {
            self::assertStringNotContainsString(RswFixture::LAMBDA_B64, $dump, 'the rsw lambda must never print');
            self::assertStringContainsString(RswFixture::MODULUS_N_B64, $dump, 'the rsw modulus is public protocol material and stays inspectable');
        }
    }

    public function testRswDebugInfoRedactsTheLambda(): void
    {
        if (!\extension_loaded('gmp')) {
            self::markTestSkipped('the rsw debug-info test needs the gmp extension');
        }

        $rsw = new Rsw(RswFixture::MODULUS_N_B64, RswFixture::LAMBDA_B64);
        $dump = self::varDump($rsw);
        self::assertStringContainsString('<redacted>', $dump);
        self::assertStringNotContainsString(RswFixture::LAMBDA_B64, $dump, 'the rsw lambda must never print');
        self::assertStringContainsString(RswFixture::MODULUS_N_B64, $dump, 'the rsw modulus is public protocol material and stays inspectable');
    }

    public function testDerivedKeysDebugInfoRedactsThePurposeKeys(): void
    {
        $keys = DerivedKeys::fromMaster(Vectors::SECRET);
        $dump = self::varDump($keys);
        self::assertStringContainsString('<redacted>', $dump);
        self::assertStringNotContainsString($keys->challengeKey(), $dump, 'the challenge-signing key must never print');
        self::assertStringNotContainsString($keys->ipBindKey(), $dump, 'the ip-binding key must never print');
        self::assertStringNotContainsString($keys->resultKey(), $dump, 'the result-token key must never print');
    }
}
