<?php

declare(strict_types=1);

namespace KiwiCaptcha\Tests;

use KiwiCaptcha\DecodeError;
use KiwiCaptcha\SolutionToken;
use PHPUnit\Framework\TestCase;

final class SolutionTokenTest extends TestCase
{
    public function testRoundTrip(): void
    {
        $token = SolutionToken::create('abc+def/ghi=', 12345, 5000, ['wd' => false, 'me' => 1]);
        $raw = $token->encode();

        $decoded = SolutionToken::decode($raw);
        self::assertSame('abc+def/ghi=', $decoded->nonce);
        self::assertSame(12345, $decoded->counter);
        self::assertSame(5000, $decoded->durationMs);
        self::assertSame(['wd' => false, 'me' => 1], $decoded->telemetry);
    }

    public function testTelemetryWithDotsDecodesCorrectly(): void
    {
        // The telemetry JSON may contain dots; split on the first three only.
        $token = SolutionToken::create('nonce', 1, 100, ['et' => [1.5, 2.5], 'note' => 'a.b.c']);
        $raw = $token->encode();

        $decoded = SolutionToken::decode($raw);
        self::assertSame('nonce', $decoded->nonce);
        self::assertSame(['et' => [1.5, 2.5], 'note' => 'a.b.c'], $decoded->telemetry);
    }

    public function testRejectsInvalidBase64(): void
    {
        $this->expectException(DecodeError::class);
        SolutionToken::decode('!!!not-base64!!!');
    }

    public function testRejectsTooFewSegments(): void
    {
        $this->expectException(DecodeError::class);
        SolutionToken::decode(base64_encode('nonce.1.100'));
    }

    public function testRejectsNonDigitCounter(): void
    {
        $this->expectException(DecodeError::class);
        SolutionToken::decode(base64_encode('nonce.+1.100.{}'));
    }

    public function testRejectsEmptyCounter(): void
    {
        $this->expectException(DecodeError::class);
        SolutionToken::decode(base64_encode('nonce..100.{}'));
    }

    public function testAcceptsLeadingZeroCounter(): void
    {
        // Rust's u64 parse accepts "007" => 7.
        $token = SolutionToken::decode(base64_encode('nonce.007.100.{}'));
        self::assertSame(7, $token->counter);
    }

    public function testRejectsInvalidTelemetryJson(): void
    {
        $this->expectException(DecodeError::class);
        SolutionToken::decode(base64_encode('nonce.1.100.{not-json'));
    }
}
