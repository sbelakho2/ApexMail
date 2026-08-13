<?php

declare(strict_types=1);

namespace KiwiCaptcha\Risk\Tests;

use KiwiCaptcha\Risk\Network\CidrNetworkClassifier;
use KiwiCaptcha\Risk\Network\NetworkFlags;
use PHPUnit\Framework\TestCase;

final class CidrNetworkClassifierTest extends TestCase
{
    private function classifier(): CidrNetworkClassifier
    {
        return new CidrNetworkClassifier([
            ['cidr' => '203.0.113.0/24', 'flags' => ['hosting']],
            ['cidr' => '198.51.100.0/24', 'flags' => ['tor']],
            ['cidr' => '192.0.2.0/24', 'flags' => ['reserved', 'blocked']],
            ['cidr' => '2001:db8:1::/48', 'flags' => ['proxy']],
        ]);
    }

    public function testHostingCidr(): void
    {
        $flags = $this->classifier()->classify('203.0.113.27');
        self::assertTrue($flags->knownHosting);
        self::assertFalse($flags->reserved);
        self::assertFalse($flags->knownProxy);
        self::assertFalse($flags->torExit);
        self::assertFalse($flags->blocked());
        self::assertSame(600, $flags->networkRisk());
    }

    public function testTorExit(): void
    {
        $flags = $this->classifier()->classify('198.51.100.9');
        self::assertTrue($flags->torExit);
        self::assertFalse($flags->knownHosting);
        self::assertSame(650, $flags->networkRisk());
    }

    public function testBlocked(): void
    {
        $flags = $this->classifier()->classify('192.0.2.1');
        self::assertTrue($flags->blocked());
        self::assertTrue($flags->reserved);
        self::assertSame(1000, $flags->networkRisk());
        self::assertSame(255, $flags->localRiskBucket);
    }

    public function testReservedOnly(): void
    {
        $classifier = new CidrNetworkClassifier([
            ['cidr' => '198.18.0.0/15', 'flags' => ['reserved']],
        ]);
        $flags = $classifier->classify('198.18.3.4');
        self::assertTrue($flags->reserved);
        self::assertFalse($flags->blocked());
        self::assertSame(950, $flags->networkRisk(), 'reserved/impossible is below the policy deny line');
    }

    public function testUnknownIp(): void
    {
        $flags = $this->classifier()->classify('10.0.0.1');
        self::assertSame(0, $flags->networkRisk());
        self::assertFalse($flags->blocked());
        self::assertFalse($flags->torExit);
        self::assertFalse($flags->knownHosting);
        self::assertFalse($flags->reserved);
        self::assertFalse($flags->knownProxy);
    }

    public function testIpv6Matching(): void
    {
        $flags = $this->classifier()->classify('2001:db8:1::42');
        self::assertTrue($flags->knownProxy);
        self::assertSame(750, $flags->networkRisk());

        $flags = $this->classifier()->classify('2001:db8:2::42');
        self::assertSame(0, $flags->networkRisk());
    }

    public function testIpv4DoesNotMatchIpv6Entry(): void
    {
        $flags = $this->classifier()->classify('2001:db8:1::42');
        self::assertTrue($flags->knownProxy);

        $flags = $this->classifier()->classify('192.0.2.1');
        self::assertFalse($flags->knownProxy);
    }

    public function testIpv4MappedInputNormalizes(): void
    {
        $flags = $this->classifier()->classify('::ffff:203.0.113.7');
        self::assertTrue($flags->knownHosting);
    }

    public function testFlagUnionAcrossEntries(): void
    {
        $classifier = new CidrNetworkClassifier([
            ['cidr' => '10.0.0.0/8', 'flags' => ['hosting']],
            ['cidr' => '10.1.0.0/16', 'flags' => ['tor']],
        ]);
        $flags = $classifier->classify('10.1.2.3');
        self::assertTrue($flags->knownHosting);
        self::assertTrue($flags->torExit);
        self::assertSame(650, $flags->networkRisk(), 'flag union: the highest risk wins (tor 650 over hosting 600)');
    }

    public function testFromFile(): void
    {
        $path = sys_get_temp_dir() . '/risk-cidr-' . bin2hex(random_bytes(4)) . '.txt';
        file_put_contents($path, "# comment\n\n203.0.113.0/24,hosting\n198.51.100.0/24,tor\n192.0.2.0/24,reserved,blocked\n");
        try {
            $classifier = CidrNetworkClassifier::fromFile($path);
            self::assertTrue($classifier->classify('203.0.113.5')->knownHosting);
            self::assertTrue($classifier->classify('198.51.100.5')->torExit);
            self::assertTrue($classifier->classify('192.0.2.5')->blocked());
        } finally {
            @unlink($path);
        }
    }

    public function testInvalidIpThrows(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->classifier()->classify('banana');
    }

    public function testInvalidEntryThrows(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        new CidrNetworkClassifier([['cidr' => '203.0.113.0/33', 'flags' => []]]);
    }

    public function testUnknownFlagThrows(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        new CidrNetworkClassifier([['cidr' => '203.0.113.0/24', 'flags' => ['spooky']]]);
    }

    public function testNetworkFlagsDefaults(): void
    {
        $flags = new NetworkFlags();
        self::assertFalse($flags->reserved);
        self::assertFalse($flags->knownHosting);
        self::assertFalse($flags->knownProxy);
        self::assertFalse($flags->torExit);
        self::assertSame(0, $flags->localRiskBucket);
        self::assertSame(0, $flags->networkRisk());
    }
}
