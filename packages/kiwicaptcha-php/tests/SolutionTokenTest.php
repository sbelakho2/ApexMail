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

    public function testRejectsCounterAboveSolverMaximum(): void
    {
        // The browser/wasm solver caps at 5,000,000 hashes; 5,000,001
        // cannot come from a legit solve.
        $this->expectException(DecodeError::class);
        $this->expectExceptionMessage('counter exceeds solver maximum');
        SolutionToken::decode(base64_encode(self::NONCE.'.5000001.100.{}'));
    }

    public function testRejectsCounterAtSolverMaximum(): void
    {
        // The JS solver searches counter < 5,000,000 (5M attempts), so the
        // largest legitimate counter is 4,999,999 — exactly 5,000,000 was
        // never minted by a real solve (off-by-one parity with Rust).
        $this->expectException(DecodeError::class);
        SolutionToken::decode(base64_encode(self::NONCE.'.5000000.100.{}'));
    }

    public function testAcceptsCounterJustBelowSolverMaximum(): void
    {
        $token = SolutionToken::decode(base64_encode(self::NONCE.'.4999999.100.{}'));
        self::assertSame(4_999_999, $token->counter);
    }

    public function testRejectsCounterLongerThanSevenDigits(): void
    {
        // 8 digits but numerically below the maximum — still rejected by
        // the digit-length bound (an absurdly long string would otherwise
        // silently clamp in the integer cast).
        $this->expectException(DecodeError::class);
        $this->expectExceptionMessage('counter exceeds solver maximum');
        SolutionToken::decode(base64_encode(self::NONCE.'.00000000.100.{}'));
    }

    public function testAcceptsSevenDigitCounterWithLeadingZeros(): void
    {
        $token = SolutionToken::decode(base64_encode(self::NONCE.'.0000007.100.{}'));
        self::assertSame(7, $token->counter);
    }

    public function testRejectsInvalidTelemetryJson(): void
    {
        $this->expectException(DecodeError::class);
        SolutionToken::decode(base64_encode(self::NONCE.'.1.100.{not-json'));
    }

    public function testRejectsNonObjectTelemetry(): void
    {
        // Wire parity with Rust: telemetry must be a JSON OBJECT.
        $rejected = 0;
        foreach (['[]', '"hello"', '123', 'true', 'null'] as $bad) {
            try {
                SolutionToken::decode(base64_encode(self::NONCE.'.1.100.'.$bad));
            } catch (DecodeError) {
                ++$rejected;
            }
        }
        self::assertSame(5, $rejected, 'all five non-object telemetry payloads must be rejected');
    }

    public function testRejectsDurationBeyondProtocolBound(): void
    {
        $this->expectException(DecodeError::class);
        SolutionToken::decode(base64_encode(self::NONCE.'.1.3600001.{}'));
    }

    public function testAcceptsDurationAtProtocolBound(): void
    {
        $token = SolutionToken::decode(base64_encode(self::NONCE.'.1.3600000.{}'));
        self::assertSame(3_600_000, $token->durationMs);
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

    public function testRejectsBase64UrlVariant(): void
    {
        // Audit #29: the same semantic token encoded with the base64url
        // alphabet (- _) must be rejected — exactly one canonical byte
        // representation is accepted. The telemetry '?' bytes (0x3F) are
        // positioned (duration=1000) so the token's base64 contains '/'
        // (0x3F & 0x3F = 63), guaranteeing the url-safe variant differs.
        $nonce = base64_encode(random_bytes(32));
        $raw = SolutionToken::create($nonce, 1, 1000, ['q' => '?>~?'])->encode();
        self::assertTrue(
            str_contains($raw, '+') || str_contains($raw, '/'),
            'precondition: the token base64 must contain a standard-only char',
        );
        $urlSafe = strtr($raw, '+/', '-_');
        self::assertNotSame($raw, $urlSafe, 'precondition: the url-safe variant must differ');

        $this->expectException(DecodeError::class);
        SolutionToken::decode($urlSafe);
    }

    public function testRejectsUnpaddedBase64(): void
    {
        // Audit #29: stripping the canonical padding decodes to the same
        // bytes in PHP but is NOT the canonical byte representation — the
        // canonical re-encode check rejects it.
        $nonce = base64_encode(str_repeat("\xff", 32));
        $raw = SolutionToken::create($nonce, 1, 100, [])->encode();
        self::assertSame('=', substr($raw, -1), 'precondition: canonical token is padded');
        $unpadded = rtrim($raw, '=');
        self::assertNotSame($raw, $unpadded, 'precondition: unpadded form differs');

        $this->expectException(DecodeError::class);
        SolutionToken::decode($unpadded);
    }

    public function testRejectsWhitespacePaddedBase64(): void
    {
        // Audit #29: the historical trim() leniency is gone — embedded or
        // surrounding whitespace is outside the canonical representation.
        $raw = SolutionToken::create(self::NONCE, 1, 100, [])->encode();
        foreach ([$raw."\n", ' '.$raw, str_replace('=', "=\n", $raw)] as $variant) {
            try {
                SolutionToken::decode($variant);
                self::fail('whitespace-padded token must be rejected');
            } catch (DecodeError) {
                // expected
            }
        }
        self::assertTrue(true);
    }

    public function testRejectsNonCanonicalPaddingTrailingBits(): void
    {
        // Audit #29: a valid-length base64 whose final group carries
        // non-zero trailing bits ('A' instead of '=' for a 1-byte remainder)
        // is not canonical even though strict decode may accept it.
        $plain = self::NONCE.'.1.100.{}';
        $raw = base64_encode($plain);
        // Rewrite the final '=' to a letter: decodes to the same bytes but
        // re-encodes differently.
        $altered = substr($raw, 0, -1).'A';
        try {
            $decoded = base64_decode($altered, true);
            if ($decoded !== false && base64_encode($decoded) === $altered) {
                self::markTestSkipped('PHP decoded the altered group canonically');
            }
        } catch (\Throwable) {
            // fall through — rejection either way
        }

        $this->expectException(DecodeError::class);
        SolutionToken::decode($altered);
    }
}
