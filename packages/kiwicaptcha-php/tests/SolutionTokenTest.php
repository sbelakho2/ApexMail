<?php

declare(strict_types=1);

namespace KiwiCaptcha\Tests;

use KiwiCaptcha\DecodeError;
use KiwiCaptcha\SolutionToken;
use PHPUnit\Framework\TestCase;

final class SolutionTokenTest extends TestCase
{
    /** base64_encode of str_repeat('a', 32); a well-formed 44-char nonce. */
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

    public function testRejectsLeadingZeroCounter(): void
    {
        // The counter segment is canonical decimal: a leading zero is
        // rejected unless the whole segment is exactly "0", so each value
        // has exactly one wire spelling in both implementations.
        $this->expectException(DecodeError::class);
        $this->expectExceptionMessage('invalid_counter');
        SolutionToken::decode(base64_encode(self::NONCE.'.007.100.{}'));
    }

    public function testRejectsCounterAboveSolverMaximum(): void
    {
        // The browser/wasm solver caps at 20,000,000 hashes; 20,000,001
        // cannot come from a legit solve.
        $this->expectException(DecodeError::class);
        $this->expectExceptionMessage('counter exceeds solver maximum');
        SolutionToken::decode(base64_encode(self::NONCE.'.20000001.100.{}'));
    }

    public function testRejectsCounterAtSolverMaximum(): void
    {
        // The JS solver searches counter < 20,000,000 (20M attempts), so
        // the largest legitimate counter is 19,999,999; exactly 20,000,000
        // was never minted by a real solve (off-by-one parity with
        // Rust).
        $this->expectException(DecodeError::class);
        SolutionToken::decode(base64_encode(self::NONCE.'.20000000.100.{}'));
    }

    public function testAcceptsCounterJustBelowSolverMaximum(): void
    {
        // The four-way boundary: 4,999,999 (the 5M ceiling's last valid
        // counter), 5,000,000 (the first counter the 5M contract refused
        // but the 20M solver can mint) and 19,999,999 (the 20M last valid
        // counter) all decode; 20,000,000 is refused by the sibling tests.
        foreach ([4_999_999, 5_000_000, 19_999_999] as $counter) {
            $token = SolutionToken::decode(base64_encode(self::NONCE.".{$counter}.100.{}"));
            self::assertSame($counter, $token->counter);
        }
    }

    public function testRejectsCounterLongerThanEightDigits(): void
    {
        // 9 canonical digits — rejected by the digit-length bound before
        // the value could clamp in the integer cast (the canonical rule
        // leaves no 8-digit spelling at or above the 20M maximum).
        $this->expectException(DecodeError::class);
        $this->expectExceptionMessage('counter exceeds solver maximum');
        SolutionToken::decode(base64_encode(self::NONCE.'.999999999.100.{}'));
    }

    public function testRejectsAllZeroCounterThatIsNotExactlyZero(): void
    {
        // "00" is not the canonical spelling of 0; only the exact string
        // "0" carries the value zero.
        $this->expectException(DecodeError::class);
        $this->expectExceptionMessage('invalid_counter');
        SolutionToken::decode(base64_encode(self::NONCE.'.00.100.{}'));
    }

    public function testAcceptsExactlyZeroCounterAndDuration(): void
    {
        // "0" is the canonical spelling of zero for both numeric segments.
        $token = SolutionToken::decode(base64_encode(self::NONCE.'.0.0.{}'));
        self::assertSame(0, $token->counter);
        self::assertSame(0, $token->durationMs);
    }

    public function testRejectsLeadingZeroDuration(): void
    {
        // The duration segment carries the same canonical-decimal rule:
        // "0042" is not a spelling the widget ever emits.
        $this->expectException(DecodeError::class);
        $this->expectExceptionMessage('invalid_duration');
        SolutionToken::decode(base64_encode(self::NONCE.'.0.0042.{}'));
    }

    public function testRejectsInvalidTelemetryJson(): void
    {
        $this->expectException(DecodeError::class);
        SolutionToken::decode(base64_encode(self::NONCE.'.1.100.{not-json'));
    }

    public function testRejectsNonObjectTelemetry(): void
    {
        // Wire parity with Rust: telemetry must be a JSON object.
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

    public function testRejectsMegabyteTokenByLengthCapBeforeAnyDecode(): void
    {
        // The 32,768-byte length cap is checked before
        // base64_decode — a 1 MB token must be rejected by the cap with no
        // huge decoded allocation behind it. A decode-before-cap regression
        // would materialize ~750 KB of plaintext here.
        $this->expectException(DecodeError::class);

        $plain = sprintf('%s.1.100.%s', self::NONCE, str_repeat('a', 1_000_000));
        $raw = base64_encode($plain);
        self::assertGreaterThan(1_000_000, \strlen($raw), 'precondition: token must exceed 1 MB');

        SolutionToken::decode($raw);
    }

    public function testDeeplyNestedTelemetryJsonFailsCleanly(): void
    {
        // json_decode runs at the default depth (512). A telemetry
        // segment nested far beyond it must fail cleanly with a typed
        // DecodeError, never a stack exhaustion or an untyped
        // JsonException escaping the parse path.
        $this->expectException(DecodeError::class);

        SolutionToken::decode(base64_encode(self::NONCE.'.1.100.'.str_repeat('[', 600).str_repeat(']', 600)));
    }

    public function testDecodeOnlyThrowsDecodeError(): void
    {
        // The public parse path must never throw anything
        // except DecodeError — adversarial inputs (huge, deeply nested,
        // non-numeric, malformed) all fail typed.
        $inputs = [
            '!!!not-base64!!!',
            base64_encode(self::NONCE.'.1.100.{not-json'),
            base64_encode(str_repeat('a', 50_000)),
            base64_encode(self::NONCE.'.1.100.'.str_repeat('[', 600).str_repeat(']', 600)),
            base64_encode(self::NONCE.'.'.str_repeat('9', 20).'.100.{}'),
            base64_encode(self::NONCE.'.1.'.str_repeat('9', 20).'.{}'),
            base64_encode(self::NONCE.'.1.100'),
            base64_encode('x.1.100.{}'),
        ];
        foreach ($inputs as $input) {
            try {
                SolutionToken::decode($input);
                self::fail('decode must reject input '.substr($input, 0, 40).'…');
            } catch (DecodeError) {
                // the only documented failure type
            }
        }
        self::assertTrue(true);
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

    public function testRejectsNonCanonicalNonceTrailingBitsInsideThePayload(): void
    {
        // Rust parity: `decode_rejects_noncanonical_nonce_inside_the_payload`
        // in packages/kiwicaptcha/src/token.rs requires the inner nonce to
        // decode to 32 bytes and re-encode byte-exact (`B64.decode` then
        // `B64.encode(&bytes) == nonce`). Its vectors are an unpadded 43-char
        // nonce (fails the length gate) and a url-safe alphabet swap (fails
        // the alphabet gate); this test covers the one shape those two miss:
        // a 43-char segment plus '=' that is shape-valid and strict-decodable
        // but whose final sextet carries non-zero unused bits. PHP's strict
        // base64_decode silently drops those bits, so only the canonical
        // re-encode can reject the spelling — the exact Rust rule.
        $canonical = self::NONCE;
        self::assertSame('=', substr($canonical, -1), 'precondition: canonical nonce is padded');
        self::assertSame('E', $canonical[42], 'precondition: 43rd char is the canonical final sextet');

        // The 43rd character of a 32-byte encoding carries 4 meaningful bits
        // and 2 unused bits that must be zero: 'E' (=4) is canonical, while
        // F/G/H (=5/6/7) have identical meaningful bits, decode to the same
        // 32 bytes, and re-encode to 'E'. Each is a distinct non-canonical
        // wire spelling PHP must refuse, exactly like Rust.
        $rejected = 0;
        foreach (['F', 'G', 'H'] as $final) {
            $nonce = substr($canonical, 0, 42).$final.'=';
            self::assertSame(44, \strlen($nonce), 'precondition: 44 chars');
            self::assertSame(1, preg_match('/^[A-Za-z0-9+\/]{43}=$/', $nonce), 'precondition: shape-valid');
            $bytes = base64_decode($nonce, true);
            self::assertNotFalse($bytes, 'precondition: strict decode accepts the spelling');
            self::assertSame(32, \strlen($bytes));
            self::assertSame($canonical, base64_encode($bytes), 'precondition: aliases the same 32 bytes');

            try {
                SolutionToken::decode(base64_encode($nonce.'.1.100.{}'));
                self::fail("non-canonical nonce ending '$final=' must be rejected");
            } catch (DecodeError) {
                ++$rejected;
            }
        }
        self::assertSame(3, $rejected, 'every shape-valid non-canonical nonce must be rejected');
    }

    public function testAcceptsCanonicalNonceControlForTrailingBits(): void
    {
        // The valid control for the trailing-bits matrix: the single
        // canonical spelling (final sextet 'E', zero unused bits) still
        // decodes in both implementations; the canonicality gate must not
        // over-reject it.
        $token = SolutionToken::decode(base64_encode(self::NONCE.'.1.100.{}'));
        self::assertSame(self::NONCE, $token->nonce);
    }

    public function testRejectsBase64UrlVariant(): void
    {
        // The same semantic token encoded with the base64url
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
        // Stripping the canonical padding decodes to the same
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
        // There is no trim() leniency — embedded or
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
        // A valid-length base64 whose final group carries
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
