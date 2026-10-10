<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests;

use BelConsulting\KiwiCaptchaBundle\Security\StepUp\TotpCode;
use PHPUnit\Framework\TestCase;

/**
 * The RFC 6238 appendix B test vectors, asserted exactly, for both
 * implemented hashes, plus the RFC 4648 base32 vectors of the in-bundle
 * codec.
 */
final class TotpCodeTest extends TestCase
{
    /**
     * The RFC 6238 appendix B table (8 digits). The secrets are the
     * RFC's own seed strings truncated to the hash length.
     *
     * @return list<array{0: string, 1: int, 2: string, 3: string}>
     */
    public static function rfcVectors(): array
    {
        return [
            // [secret, unix time, expected 8-digit code, algorithm]
            ['12345678901234567890', 59, '94287082', 'sha1'],
            ['12345678901234567890', 1111111109, '07081804', 'sha1'],
            ['12345678901234567890', 1111111111, '14050471', 'sha1'],
            ['12345678901234567890', 1234567890, '89005924', 'sha1'],
            ['12345678901234567890', 2000000000, '69279037', 'sha1'],
            ['12345678901234567890', 20000000000, '65353130', 'sha1'],
            ['12345678901234567890123456789012', 59, '46119246', 'sha256'],
            ['12345678901234567890123456789012', 1111111109, '68084774', 'sha256'],
            ['12345678901234567890123456789012', 1111111111, '67062674', 'sha256'],
            ['12345678901234567890123456789012', 1234567890, '91819424', 'sha256'],
            ['12345678901234567890123456789012', 2000000000, '90698825', 'sha256'],
            ['12345678901234567890123456789012', 20000000000, '77737706', 'sha256'],
        ];
    }

    /**
     * @dataProvider rfcVectors
     */
    public function testTheRfc6238VectorsAssertExactly(string $secret, int $time, string $expected, string $algo): void
    {
        self::assertSame($expected, TotpCode::at($secret, TotpCode::stepOf($time), $algo, 8));
    }

    /**
     * The step math of the RFC: floor(unix / 30), verified against the
     * appendix's own moving factors.
     *
     * @return list<array{0: int, 1: int}>
     */
    public static function steps(): array
    {
        return [
            [59, 1],
            [1111111109, 37037036],
            [1234567890, 41152263],
            [20000000000, 666666666],
        ];
    }

    /** @dataProvider steps */
    public function testTheMovingFactorIsFloorOverThirtySeconds(int $time, int $step): void
    {
        self::assertSame($step, TotpCode::stepOf($time));
    }

    /**
     * The RFC 4648 base32 test vectors (padding stripped on encode,
     * padding optional on decode).
     *
     * @return list<array{0: string, 1: string}>
     */
    public static function base32Vectors(): array
    {
        return [
            ['f', 'MY'],
            ['fo', 'MZXQ'],
            ['foo', 'MZXW6'],
            ['foob', 'MZXW6YQ'],
            ['fooba', 'MZXW6YTB'],
            ['foobar', 'MZXW6YTBOI'],
        ];
    }

    /** @dataProvider base32Vectors */
    public function testBase32RoundTripsTheRfc4648Vectors(string $raw, string $encoded): void
    {
        self::assertSame($encoded, TotpCode::base32Encode($raw));
        self::assertSame($raw, TotpCode::base32Decode($encoded));
        // Padding, lowercase and internal whitespace are accepted on decode.
        self::assertSame($raw, TotpCode::base32Decode(strtolower($encoded)));
        self::assertSame($raw, TotpCode::base32Decode(strtolower($encoded).'===='));
    }

    public function testBase32RejectsInvalidInput(): void
    {
        self::assertNull(TotpCode::base32Decode('ABC1'));
        self::assertNull(TotpCode::base32Decode(''));
        self::assertNull(TotpCode::base32Decode('1'));
        self::assertNotNull(TotpCode::base32Decode('MZXW6==='));
    }

    public function testSixAndEightDigitsAreTheOnlyLengths(): void
    {
        $secret = '12345678901234567890';
        self::assertSame('287082', TotpCode::at($secret, 1, 'sha1', 6));
        $this->expectException(\InvalidArgumentException::class);
        TotpCode::at($secret, 1, 'sha1', 7);
    }

    public function testUnknownAlgorithmIsRefused(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        TotpCode::at('12345678901234567890', 1, 'sha512', 6);
    }
}
