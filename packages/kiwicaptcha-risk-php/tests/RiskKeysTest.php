<?php

declare(strict_types=1);

namespace KiwiCaptcha\Risk\Tests;

use KiwiCaptcha\Risk\RiskKeys;
use PHPUnit\Framework\TestCase;

/**
 * hkdf-sha256 identity keys with master = 0x42 x 32. The hex values below
 * were computed independently with a reference script and MUST agree with
 * the Rust implementation: Hkdf::<Sha256>::new with the salt
 * b"kiwicaptcha-risk-v1".
 */
final class RiskKeysTest extends TestCase
{
    private const MASTER_HEX_KEYS = [
        'source' => 'c353fb1e6c7ceac79f19a45cd92f8dd24597f0c50df92a7f9139fa96e19b5b61',
        'subnet' => 'ec675a524f51caf7f85119e309d29d74fa554222ca12e8efc77631a5c8dc2460',
        'session' => 'bbb44b7be31ee827d07e8e5079eaca4608bf0c85db54aa9ce8582c777186029f',
        'principal' => '40459f71b2d98dc45f78b2ebe6eea9d7e68b55c3006b5408762f2c6f10e95c48',
        'event' => '10def12a515d1fcaa2a0ca79916eb916197b99af76b98b8317081accd9fb3e1f',
    ];

    public function testKeysMatchReferenceHexes(): void
    {
        $master = str_repeat(chr(0x42), 32);
        $keys = RiskKeys::fromMaster($master);

        self::assertSame(self::MASTER_HEX_KEYS['source'], bin2hex($keys->source));
        self::assertSame(self::MASTER_HEX_KEYS['subnet'], bin2hex($keys->subnet));
        self::assertSame(self::MASTER_HEX_KEYS['session'], bin2hex($keys->session));
        self::assertSame(self::MASTER_HEX_KEYS['principal'], bin2hex($keys->principal));
        self::assertSame(self::MASTER_HEX_KEYS['event'], bin2hex($keys->event));
    }

    public function testKeysAreDistinctAnd32Bytes(): void
    {
        $keys = RiskKeys::fromMaster(str_repeat(chr(0x42), 32));
        self::assertSame(32, strlen($keys->source));
        self::assertSame(32, strlen($keys->subnet));
        self::assertSame(32, strlen($keys->session));
        self::assertSame(32, strlen($keys->principal));
        self::assertSame(32, strlen($keys->event));
        self::assertCount(5, array_unique([$keys->source, $keys->subnet, $keys->session, $keys->principal, $keys->event]));
    }

    public function testDifferentMasterDerivesDifferentKeys(): void
    {
        $a = RiskKeys::fromMaster(str_repeat(chr(0x42), 32));
        $b = RiskKeys::fromMaster(str_repeat(chr(0x43), 32));
        self::assertNotSame($a->source, $b->source);
        self::assertNotSame($a->subnet, $b->subnet);
        self::assertNotSame($a->session, $b->session);
        self::assertNotSame($a->principal, $b->principal);
        self::assertNotSame($a->event, $b->event);
    }
}
