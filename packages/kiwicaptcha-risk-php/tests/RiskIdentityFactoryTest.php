<?php

declare(strict_types=1);

namespace KiwiCaptcha\Risk\Tests;

use KiwiCaptcha\Risk\RiskIdentityFactory;
use KiwiCaptcha\Risk\RiskKeys;
use PHPUnit\Framework\TestCase;

final class RiskIdentityFactoryTest extends TestCase
{
    private function factory(): RiskIdentityFactory
    {
        return new RiskIdentityFactory(RiskKeys::fromMaster(str_repeat(chr(0x42), 32)));
    }

    public function testCanonicalIpForms(): void
    {
        $f = $this->factory();
        self::assertSame("\x04" . inet_pton('203.0.113.27'), $f->canonicalIp('203.0.113.27'));
        self::assertSame("\x04" . inet_pton('192.0.2.1'), $f->canonicalIp('192.0.2.1'));
        self::assertSame("\x06" . inet_pton('2001:db8::1'), $f->canonicalIp('2001:db8::1'));
    }

    public function testIpv4MappedNormalizesToIpv4(): void
    {
        $f = $this->factory();
        self::assertSame($f->canonicalIp('203.0.113.27'), $f->canonicalIp('::ffff:203.0.113.27'));
        self::assertSame("\x04" . inet_pton('203.0.113.27'), $f->canonicalIp('::ffff:203.0.113.27'));
    }

    public function testInvalidIpThrows(): void
    {
        $f = $this->factory();
        $this->expectException(\InvalidArgumentException::class);
        $f->canonicalIp('not-an-ip');
    }

    public function testMaskIpv4With24(): void
    {
        $f = $this->factory();
        self::assertSame('04cb007100', bin2hex($f->maskIp('203.0.113.27', 24)));
        self::assertSame('04cb007100', bin2hex($f->maskIp('203.0.113.255', 24)));
    }

    public function testMaskIpv6With56(): void
    {
        $f = $this->factory();
        self::assertSame(
            '0620010db8abcd12000000000000000000',
            bin2hex($f->maskIp('2001:db8:abcd:12ff:ffff:ffff:ffff:ffff', 56))
        );
    }

    public function testMaskInvalidPrefixThrows(): void
    {
        $f = $this->factory();
        $this->expectException(\InvalidArgumentException::class);
        $f->maskIp('203.0.113.27', 33);
    }

    public function testSourceEpochSeparation(): void
    {
        $f = $this->factory();
        self::assertSame($f->sourceId('203.0.113.27', 0), $f->sourceId('203.0.113.27', 899));
        self::assertNotSame($f->sourceId('203.0.113.27', 0), $f->sourceId('203.0.113.27', 900));
        self::assertSame($f->sourceId('203.0.113.27', 900), $f->sourceId('203.0.113.27', 1799));
        self::assertNotSame($f->sourceId('203.0.113.27', 899), $f->sourceId('203.0.113.27', 900));
    }

    public function testSubnetEpochSeparation(): void
    {
        $f = $this->factory();
        self::assertSame($f->subnetId('203.0.113.27', 100), $f->subnetId('203.0.113.27', 899));
        self::assertNotSame($f->subnetId('203.0.113.27', 899), $f->subnetId('203.0.113.27', 900));
    }

    public function testSessionAndPrincipalHaveNoEpoch(): void
    {
        $f = $this->factory();
        self::assertSame($f->sessionId('cookie-bytes'), $f->sessionId('cookie-bytes'));
        self::assertSame($f->principalId('user-42'), $f->principalId('user-42'));
        self::assertNotSame($f->sessionId('a'), $f->sessionId('b'));
        self::assertNotSame($f->principalId('a'), $f->principalId('b'));
        self::assertNotSame($f->sessionId('x'), $f->principalId('x'));
    }

    public function testPseudonymsAre16BytesHex(): void
    {
        $f = $this->factory();
        foreach ([
            $f->sourceId('203.0.113.27', 123456),
            $f->subnetId('203.0.113.27', 123456),
            $f->sessionId('s'),
            $f->principalId('p'),
        ] as $id) {
            self::assertMatchesRegularExpression('/^[0-9a-f]{32}$/', $id);
        }
    }

    public function testSourceAndSubnetDiffer(): void
    {
        $f = $this->factory();
        self::assertNotSame($f->sourceId('203.0.113.27', 1000), $f->subnetId('203.0.113.27', 1000));
    }

    public function testPseudonymIsDeterministic(): void
    {
        $f = $this->factory();
        self::assertSame($f->sourceId('203.0.113.27', 1000), $f->sourceId('203.0.113.27', 1000));
    }
}
