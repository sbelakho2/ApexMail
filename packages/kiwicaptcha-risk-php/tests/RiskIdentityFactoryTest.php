<?php

declare(strict_types=1);

namespace KiwiCaptcha\Risk\Tests;

use KiwiCaptcha\Risk\Network\NetworkFlags;
use KiwiCaptcha\Risk\ResourcePressure;
use KiwiCaptcha\Risk\RiskContext;
use KiwiCaptcha\Risk\RiskEventKind;
use KiwiCaptcha\Risk\RiskIdentityFactory;
use KiwiCaptcha\Risk\RiskKeys;
use PHPUnit\Framework\TestCase;

final class RiskIdentityFactoryTest extends TestCase
{
    private function factory(): RiskIdentityFactory
    {
        return new RiskIdentityFactory(RiskKeys::fromMaster(str_repeat(chr(0x42), 32)));
    }

    private function context(): RiskContext
    {
        return new RiskContext(
            scope: 1,
            sourceIp: '203.0.113.27',
            sessionId: null,
            principalId: null,
            event: RiskEventKind::PreIssue,
            networkFlags: new NetworkFlags(),
            resources: new ResourcePressure(1000, 1000),
        );
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

    public function testSourceIdForEpochMatchesTheDerivation(): void
    {
        $f = $this->factory();
        $ctx = $this->context();
        $nowSecs = 1_700_000_000;
        $epoch = intdiv($nowSecs, 900);
        // The explicit-epoch form must agree with the derived form, and the
        // epoch±1 pseudonyms must differ (each epoch's key uses its own
        // pseudonym, never the current-epoch one).
        self::assertSame($f->sourceId('203.0.113.27', $nowSecs), $f->sourceIdForEpoch($ctx, $epoch));
        self::assertNotSame($f->sourceIdForEpoch($ctx, $epoch), $f->sourceIdForEpoch($ctx, $epoch - 1));
        self::assertNotSame($f->sourceIdForEpoch($ctx, $epoch), $f->sourceIdForEpoch($ctx, $epoch + 1));
        self::assertMatchesRegularExpression('/^[0-9a-f]{32}$/', $f->sourceIdForEpoch($ctx, $epoch));
    }

    public function testSubnetIdForEpochMatchesTheDerivation(): void
    {
        $f = $this->factory();
        $ctx = $this->context();
        $nowSecs = 1_700_000_000;
        $epoch = intdiv($nowSecs, 900);
        self::assertSame($f->subnetId('203.0.113.27', $nowSecs), $f->subnetIdForEpoch($ctx, $epoch));
        self::assertNotSame($f->subnetIdForEpoch($ctx, $epoch), $f->subnetIdForEpoch($ctx, $epoch - 1));
        self::assertNotSame($f->subnetIdForEpoch($ctx, $epoch), $f->subnetIdForEpoch($ctx, $epoch + 1));
        self::assertMatchesRegularExpression('/^[0-9a-f]{32}$/', $f->subnetIdForEpoch($ctx, $epoch));
    }
}
