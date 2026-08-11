<?php

declare(strict_types=1);

namespace KiwiCaptcha\Tests;

use KiwiCaptcha\DecodeError;
use KiwiCaptcha\SolutionToken;
use PHPUnit\Framework\TestCase;

final class SolutionTokenTest extends TestCase
{
    /** base64_encode(str_repeat('a', 32)) — a well-formed 44-char nonce. */
    private const NONCE = 'YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE=';

    public function testRoundTrip(): void
    {
        $token = SolutionToken::create(self::NONCE, 12345, 5000, ['wd' => false, 'me' => 1]);
        $raw = $token->encode();

        $decoded = SolutionToken::decode($raw);
        self::assertSame(self::NONCE, $decoded->nonce);
        self::assertSame(12345, $decoded->counter);
        self::assertSame(5000, $decoded->durationMs);
        self::assertSame(['wd' => false, 'me' => 1], $decoded->telemetry);
    }

    public function testTelemetryWithDotsDecodesCorrectly(): void
    {
        // The telemetry JSON may contain dots; split on the first three only.
        $token = SolutionToken::create(self::NONCE, 1, 100, ['et' => [1.5, 2.5], 'note' => 'a.b.c']);
        $raw = $token->encode();

        $decoded = SolutionToken::decode($raw);
        self::assertSame(self::NONCE, $decoded->nonce);
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
        SolutionToken::decode(base64_encode(self::NONCE.'.1.100'));
    }

    public function testRejectsNonDigitCounter(): void
    {
        $this->expectException(DecodeError::class);
        SolutionToken::decode(base64_encode(self::NONCE.'.+1.100.{}'));
    }

    public function testRejectsEmptyCounter(): void
    {
        $this->expectException(DecodeError::class);
        SolutionToken::decode(base64_encode(self::NONCE.'..100.{}'));
    }

    public function testAcceptsLeadingZeroCounter(): void
    {
        // Rust's u64 parse accepts "007" => 7.
        $token = SolutionToken::decode(base64_encode(self::NONCE.'.007.100.{}'));
        self::assertSame(7, $token->counter);
    }

    public function testRejectsInvalidTelemetryJson(): void
    {
        $this->expectException(DecodeError::class);
        SolutionToken::decode(base64_encode(self::NONCE.'.1.100.{not-json'));
    }

    public function testRejectsTokenLongerThan32Kb(): void
    {
        $this->expectException(DecodeError::class);

        // A huge telemetry payload pushes the encoded token past the 32 KB cap.
        $plain = sprintf(
            '%s.1.100.%s',
            self::NONCE,
            (string) json_encode(['pad' => str_repeat('a', 50_000)])
        );
        $raw = base64_encode($plain);
        self::assertGreaterThan(32_768, \strlen($raw), 'precondition: token must exceed 32 KB');

        SolutionToken::decode($raw);
    }

    public function testRejectsWrongLengthNonce(): void
    {
        // A nonce must be exactly 44 chars (base64 of 32 bytes, standard
        // alphabet, one padding '=').
        foreach (['short', '', 'YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE', 'YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE='] as $badNonce) {
            self::assertNotSame(44, \strlen($badNonce), 'precondition: nonce must not be 44 chars');
            try {
                SolutionToken::decode(base64_encode($badNonce.'.1.100.{}'));
                self::fail("nonce '$badNonce' should have been rejected");
            } catch (DecodeError) {
                // expected
            }
        }
    }

    public function testRejectsNonceWithInvalidBase64Alphabet(): void
    {
        // 44 chars but not standard base64 with padding (contains '-').
        $this->expectException(DecodeError::class);
        SolutionToken::decode(base64_encode('AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA-.1.100.{}'));
    }
}
