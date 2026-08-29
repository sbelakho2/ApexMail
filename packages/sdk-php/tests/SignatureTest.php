<?php

declare(strict_types=1);

namespace ApexMail\Tests;

use ApexMail\Client;
use PHPUnit\Framework\TestCase;

/**
 * Webhook signature verification against the platform's exact wire format
 * (worker-processors/src/webhook/processor.rs):
 *
 *   X-ApexMail-Signature: sha256=<hex hmac>
 *   X-ApexMail-Timestamp: <milliseconds since epoch>
 *   signed message: "{timestamp_millis}.{payload}"  (HMAC-SHA256, hex)
 */
final class SignatureTest extends TestCase
{
    private const PAYLOAD = '{"test":true}';
    private const SECRET = 'whsec_test';

    /** Current platform-style millisecond timestamp (1s in the past). */
    private static function freshMillis(): string
    {
        return (string) (int) ((microtime(true) - 1.0) * 1000);
    }

    /** Reference implementation of the platform signer. */
    private static function platformSign(string $timestampMs, string $payload, string $secret): string
    {
        return 'sha256=' . hash_hmac('sha256', "{$timestampMs}.{$payload}", $secret);
    }

    public function testPlatformMillisecondHeaderPairVerifies(): void
    {
        $ts = self::freshMillis();
        $this->assertTrue(Client::verifyWebhookSignature(
            self::PAYLOAD,
            self::platformSign($ts, self::PAYLOAD, self::SECRET),
            self::SECRET,
            300,
            null,
            $ts,
        ));
    }

    /**
     * Known vector: HMAC-SHA256("1750000000000." + '{"test":true}', "whsec_test") —
     * proves the signed string is exactly "{ms}.{payload}" with the
     * millisecond digits verbatim.
     */
    public function testKnownVectorMatchesPlatformSigningFormat(): void
    {
        $this->assertSame(
            '31d18ff09cab4d0547ab1c518ffc67124406e128598a7ecfa5dbcc520e4996b2',
            hash_hmac('sha256', '1750000000000.' . self::PAYLOAD, self::SECRET),
        );
    }

    public function testTamperedPayloadFails(): void
    {
        $ts = self::freshMillis();
        $this->assertFalse(Client::verifyWebhookSignature(
            '{"test":false}',
            self::platformSign($ts, self::PAYLOAD, self::SECRET),
            self::SECRET,
            300,
            null,
            $ts,
        ));
    }

    public function testWrongSecretFails(): void
    {
        $ts = self::freshMillis();
        $this->assertFalse(Client::verifyWebhookSignature(
            self::PAYLOAD,
            self::platformSign($ts, self::PAYLOAD, self::SECRET),
            'whsec_other',
            300,
            null,
            $ts,
        ));
    }

    public function testStaleMillisecondTimestampFailsTolerance(): void
    {
        // 1750000000000 ms = 2025-06-15, far outside any sane tolerance.
        $ts = '1750000000000';
        $this->assertFalse(Client::verifyWebhookSignature(
            self::PAYLOAD,
            self::platformSign($ts, self::PAYLOAD, self::SECRET),
            self::SECRET,
            300,
            null,
            $ts,
        ));
    }

    public function testSigningTheWrongStringFails(): void
    {
        $ts = self::freshMillis();
        // Sign "{payload}.{ts}" (wrong order) — must not verify.
        $wrong = 'sha256=' . hash_hmac('sha256', self::PAYLOAD . '.' . $ts, self::SECRET);
        $this->assertFalse(Client::verifyWebhookSignature(
            self::PAYLOAD,
            $wrong,
            self::SECRET,
            300,
            null,
            $ts,
        ));
    }

    public function testMissingTimestampHeaderFails(): void
    {
        $ts = self::freshMillis();
        // sha256= header alone carries no timestamp — cannot verify.
        $this->assertFalse(Client::verifyWebhookSignature(
            self::PAYLOAD,
            self::platformSign($ts, self::PAYLOAD, self::SECRET),
            self::SECRET,
            300,
        ));
    }
}
