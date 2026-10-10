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
        $cookieA = '5ae1a4b8c0d1e2f30011223344556677';
        $cookieB = '00112233445566778899aabbccddeeff';
        self::assertSame($f->sessionId($cookieA), $f->sessionId($cookieA));
        self::assertSame($f->principalId('user-42'), $f->principalId('user-42'));
        self::assertNotSame($f->sessionId($cookieA), $f->sessionId($cookieB));
        self::assertNotSame($f->principalId('a'), $f->principalId('b'));
        self::assertNotSame($f->sessionId($cookieA), $f->principalId($cookieA));
    }

    public function testSessionCookieMustBe32LowercaseHex(): void
    {
        $f = $this->factory();
        foreach ([
            'rawbytes',
            '5ae1a4b8c0d1e2f3001122334455667',
            '5ae1a4b8c0d1e2f300112233445566770',
            '5AE1A4B8C0D1E2F30011223344556677',
            '5ae1a4b8c0d1e2f3001122334455667z',
            "5ae1a4b8c0d1e2f30011223344556677\n",
        ] as $value) {
            try {
                $f->sessionId($value);
                self::fail(sprintf('the session value %s must be refused', var_export($value, true)));
            } catch (\InvalidArgumentException $e) {
                self::assertNotSame('', $e->getMessage());
            }
        }
    }

    public function testSessionPseudonymBindsTheDecodedBytesAndMatchesTheSharedVector(): void
    {
        $vectors = $this->fixtures()['identity_vectors'];
        $f = new RiskIdentityFactory(RiskKeys::fromMaster($vectors['master_key']));
        $cookieHex = $vectors['session']['cookie_hex'];
        self::assertSame($vectors['session']['cookie_raw_hex'], $cookieHex, 'the fixture states both representations of the same 16 bytes');
        self::assertSame($vectors['session']['expected_session_id'], $f->sessionId($cookieHex));

        // The representation split this vector guards: HMAC over the ASCII
        // hex bytes is a different pseudonym, so an implementation that
        // skips hex2bin() cannot pass.
        $asAscii = $f->pseudonym(hash_hkdf('sha256', $vectors['master_key'], 32, RiskKeys::INFO_SESSION, RiskKeys::SALT), 'sess', 0, $cookieHex);
        self::assertNotSame($vectors['session']['expected_session_id'], $asAscii);

        self::assertSame($vectors['principal']['expected_id'], $f->principalId($vectors['principal']['material_utf8']));
        self::assertSame(
            $vectors['source']['expected_id'],
            $f->sourceId($vectors['source']['ip'], (int) $vectors['source']['epoch'] * 900)
        );
        self::assertSame(
            $vectors['subnet']['expected_id'],
            $f->subnetId($vectors['subnet']['ip'], (int) $vectors['subnet']['epoch'] * 900)
        );

        // The IPv6 source is masked to its /64: two hosts in one /64
        // share the source pseudonym, a different /64 does not.
        $v6 = $vectors['source_ipv6'];
        $v6Epoch = (int) $v6['epoch'] * 900;
        self::assertSame($v6['expected_id'], $f->sourceId($v6['ip'], $v6Epoch));
        self::assertSame(
            $f->sourceId($v6['ip'], $v6Epoch),
            $f->sourceId($v6['sibling_ip'], $v6Epoch),
            'a /64 sibling must share the source pseudonym'
        );
        self::assertSame(
            $v6['expected_other_id'],
            $f->sourceId($v6['other_ip'], $v6Epoch),
            'a different /64 must derive a different source pseudonym'
        );
    }

    public function testPseudonymsAre16BytesHex(): void
    {
        $f = $this->factory();
        foreach ([
            $f->sourceId('203.0.113.27', 123456),
            $f->subnetId('203.0.113.27', 123456),
            $f->sessionId('5ae1a4b8c0d1e2f30011223344556677'),
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

    public function testZeroEpochWindowIsRefusedAtConstruction(): void
    {
        $keys = RiskKeys::fromMaster(str_repeat(chr(0x42), 32));
        foreach ([[0, 900], [900, 0], [-1, 900], [900, -1]] as [$source, $subnet]) {
            try {
                new RiskIdentityFactory($keys, sourceEpochSecs: $source, subnetEpochSecs: $subnet);
                self::fail(sprintf('the epoch windows %d/%d must be refused', $source, $subnet));
            } catch (\InvalidArgumentException $e) {
                self::assertStringContainsString('Epoch windows', $e->getMessage());
            }
        }
    }

    /** @return array<string, mixed> */
    private function fixtures(): array
    {
        $path = getenv('RISK_FIXTURES_PATH');
        if (!is_string($path) || $path === '') {
            $path = dirname(__DIR__).'/../../protocol/risk-v1/fixtures.json';
        }
        return json_decode((string) file_get_contents($path), true, 8, JSON_THROW_ON_ERROR);
    }
}
