<?php

declare(strict_types=1);

namespace KiwiCaptcha\Risk\Tests;

use KiwiCaptcha\Risk\Storage\RedisPrincipalNetworkTagStore;
use KiwiCaptcha\Risk\Storage\RedisRiskStateStore;
use PHPUnit\Framework\TestCase;

/**
 * The principal-network tag surface against real Redis: seen/record/
 * has_trusted, LRU eviction at the class caps, TTL expiry per class,
 * ARGV rejection, and the trust-only-on-Allow rule. Runs the canonical
 * principal_networks.lua through the production store — no in-memory
 * fake.
 */
final class PrincipalNetworkLuaTest extends TestCase
{
    private const PRINCIPAL = '9f1c4a7e2b8d63f05a1e9c4d7b2e6f18';

    private const HOME_ASN_TAG = 'asn:64512';

    /** @var \Predis\Client */
    private $client;

    protected function setUp(): void
    {
        $url = getenv('RISK_REDIS_URL');
        if (!is_string($url) || $url === '') {
            self::markTestSkipped('RISK_REDIS_URL not set; start redis with: redis-server --port 6421 --save "" --appendonly no --daemonize yes');
        }
        $this->client = RedisRiskStateStore::createClient($url);
        $this->client->ping();
    }

    private function store(int $sessionCap = 32, int $deviceCap = 16, bool $migrateLegacy = true): RedisPrincipalNetworkTagStore
    {
        return new RedisPrincipalNetworkTagStore(
            $this->client,
            'pnet-test-'.bin2hex(random_bytes(4)),
            sessionTtlMs: 3_600_000,
            deviceTtlMs: 7_776_000_000,
            sessionCap: $sessionCap,
            deviceCap: $deviceCap,
            netCap: 64,
            migrateLegacy: $migrateLegacy,
        );
    }

    public function testSeenAnswersZeroForAnUnknownTag(): void
    {
        $store = $this->store();
        self::assertFalse($store->principalNetworkSeen(self::PRINCIPAL, 'net:040a010203'));
    }

    public function testRecordThenSeenAnswersOne(): void
    {
        $store = $this->store();
        self::assertTrue($store->recordPrincipalNetworkTag(self::PRINCIPAL, 'net:040a010203'));
        self::assertTrue($store->principalNetworkSeen(self::PRINCIPAL, 'net:040a010203'));
    }

    public function testRecordIsSetNx(): void
    {
        $store = $this->store();
        self::assertTrue($store->recordPrincipalNetworkTag(self::PRINCIPAL, 'net:040a010203'));
        self::assertFalse($store->recordPrincipalNetworkTag(self::PRINCIPAL, 'net:040a010203'));
    }

    public function testTrustIsMintedOnlyOnAllow(): void
    {
        $store = $this->store();
        // No trust flag: the tag is seen but not trusted.
        $store->recordPrincipalNetworkTag(self::PRINCIPAL, 'session:aaaa0000000000000000000000000001');
        self::assertTrue($store->principalNetworkSeen(self::PRINCIPAL, 'session:aaaa0000000000000000000000000001'));
        self::assertFalse($store->tagIsTrusted(self::PRINCIPAL, 'session:aaaa0000000000000000000000000001'));

        // With trust: the tag is seen and trusted.
        $store->recordPrincipalNetworkTag(self::PRINCIPAL, 'session:aaaa0000000000000000000000000002', trusted: true);
        self::assertTrue($store->tagIsTrusted(self::PRINCIPAL, 'session:aaaa0000000000000000000000000002'));
    }

    public function testHasTrustedNetworkIsFalseWithoutTrust(): void
    {
        $store = $this->store();
        $store->recordPrincipalNetworkTag(self::PRINCIPAL, 'net:040a010203');
        self::assertFalse($store->principalHasTrustedNetwork(self::PRINCIPAL));
    }

    public function testHasTrustedNetworkIsTrueWithATrustedNetworkTag(): void
    {
        $store = $this->store();
        // A trusted network-class tag is what makes the account
        // network-trusted (the novelty gate's fallback evidence).
        $store->recordPrincipalNetworkTag(self::PRINCIPAL, 'asn:64496', trusted: true);
        self::assertTrue($store->principalHasTrustedNetwork(self::PRINCIPAL));
    }

    /**
     * The any-trusted probe counts only the network classes: session
     * and device mirrors are the continuity plane's evidence, so a
     * bound cookie vouches for a browser and never makes the account
     * network-trusted.
     */
    public function testASessionOrDeviceMirrorAloneIsNotATrustedNetwork(): void
    {
        $store = $this->store();
        $store->recordPrincipalNetworkTag(self::PRINCIPAL, 'session:aaaa0000000000000000000000000003', trusted: true);
        $store->recordPrincipalNetworkTag(self::PRINCIPAL, 'device:bbbb0000000000000000000000000009', trusted: true);
        self::assertFalse(
            $store->principalHasTrustedNetwork(self::PRINCIPAL),
            'a bound session or device is continuity evidence, never a trusted network',
        );
    }

    public function testLruEvictsOldestSessionAboveCap(): void
    {
        $store = $this->store(sessionCap: 3);
        $tag = static fn (int $i): string => sprintf('session:%032x', $i);
        foreach (range(1, 5) as $i) {
            $store->recordPrincipalNetworkTag(self::PRINCIPAL, $tag($i));
        }
        // Cap is 3: the oldest two (1 and 2) should be evicted.
        self::assertFalse($store->principalNetworkSeen(self::PRINCIPAL, $tag(1)));
        self::assertFalse($store->principalNetworkSeen(self::PRINCIPAL, $tag(2)));
        self::assertTrue($store->principalNetworkSeen(self::PRINCIPAL, $tag(3)));
        self::assertTrue($store->principalNetworkSeen(self::PRINCIPAL, $tag(4)));
        self::assertTrue($store->principalNetworkSeen(self::PRINCIPAL, $tag(5)));
    }

    public function testLruEvictsOldestDeviceAboveCap(): void
    {
        $store = $this->store(deviceCap: 2);
        $tag = static fn (int $i): string => sprintf('device:%032x', $i);
        foreach (range(1, 4) as $i) {
            $store->recordPrincipalNetworkTag(self::PRINCIPAL, $tag($i));
        }
        self::assertFalse($store->principalNetworkSeen(self::PRINCIPAL, $tag(1)));
        self::assertFalse($store->principalNetworkSeen(self::PRINCIPAL, $tag(2)));
        self::assertTrue($store->principalNetworkSeen(self::PRINCIPAL, $tag(3)));
        self::assertTrue($store->principalNetworkSeen(self::PRINCIPAL, $tag(4)));
    }

    public function testForgetDevicesRemovesSessionAndDeviceTags(): void
    {
        $store = $this->store();
        $store->recordPrincipalNetworkTag(self::PRINCIPAL, 'session:aaaa0000000000000000000000000004', trusted: true);
        $store->recordPrincipalNetworkTag(self::PRINCIPAL, 'device:bbbb0000000000000000000000000005', trusted: true);
        $store->recordPrincipalNetworkTag(self::PRINCIPAL, 'net:040a010203');
        $store->forgetDevices(self::PRINCIPAL);
        self::assertFalse($store->principalNetworkSeen(self::PRINCIPAL, 'session:aaaa0000000000000000000000000004'));
        self::assertFalse($store->principalNetworkSeen(self::PRINCIPAL, 'device:bbbb0000000000000000000000000005'));
        // Network seen-ness survives revocation.
        self::assertTrue($store->principalNetworkSeen(self::PRINCIPAL, 'net:040a010203'));
    }

    public function testForgetDevicesRevokesTheTrustMirrorsSoTheGateRearms(): void
    {
        // The revocation lane's documented intent: after a credential
        // change, the next login from any network is judged by the
        // first-attempt gate on its own evidence. A network whose only
        // vouches came from the compromised credentials must not keep
        // minting the account-level trusted-network answer, so the
        // trust mirrors go with the credentials while the bare
        // seen-ness (the long-memory evidence) survives.
        $store = $this->store();
        $store->recordPrincipalNetworkTag(self::PRINCIPAL, 'net:040a010204', trusted: true);
        $store->recordPrincipalNetworkTag(self::PRINCIPAL, self::HOME_ASN_TAG, trusted: true);
        $store->recordPrincipalNetworkTag(self::PRINCIPAL, 'session:aaaa0000000000000000000000000006', trusted: true);
        $store->recordPrincipalNetworkTag(self::PRINCIPAL, 'device:bbbb0000000000000000000000000007', trusted: true);
        self::assertTrue($store->principalHasTrustedNetwork(self::PRINCIPAL), 'the pre-revocation account reads network-trusted');
        $store->forgetDevices(self::PRINCIPAL);
        self::assertFalse($store->principalHasTrustedNetwork(self::PRINCIPAL), 'the revocation re-arms the trusted-network answer');
        self::assertTrue($store->principalNetworkSeen(self::PRINCIPAL, 'net:040a010204'), 'the bare network evidence survives');
        self::assertTrue($store->principalNetworkSeen(self::PRINCIPAL, self::HOME_ASN_TAG), 'the bare ASN evidence survives');
        self::assertFalse($store->tagIsTrusted(self::PRINCIPAL, 'device:bbbb0000000000000000000000000007'), 'no trust survives on the continuity plane either');
    }

    /**
     * F6/N11: the read paths honor the configured class TTL, never the
     * class maximum. A stored (backdated) device tag past the store's
     * configured device TTL answers "not seen" and "not trusted" even
     * though it sits far inside the canonical 365-day class ceiling.
     * A stolen device value cannot vouch server-side past the lifetime
     * the deployment actually configured.
     */
    public function testAReadPastTheConfiguredTtlDoesNotVouch(): void
    {
        $store = new RedisPrincipalNetworkTagStore(
            $this->client,
            'pnet-test-'.bin2hex(random_bytes(4)),
            sessionTtlMs: 3_600_000,
            deviceTtlMs: 60_000, // one minute: the device class floor
            netCap: 64,
        );
        $tag = 'device:cccc0000000000000000000000000006';
        self::assertTrue($store->recordPrincipalNetworkTag(self::PRINCIPAL, $tag, trusted: true));

        // Backdate the last-use two minutes: past the configured 60 s
        // device TTL, deep inside the 365-day class ceiling.
        $key = $store->tagKey(self::PRINCIPAL);
        $backdated = (string) ((int) floor(microtime(true) * 1000) - 120_000);
        $this->client->hset($key, $tag, $backdated);

        self::assertFalse(
            $store->principalNetworkSeen(self::PRINCIPAL, $tag),
            'past the configured device TTL the stored value must not vouch seen',
        );
        self::assertFalse(
            $store->tagIsTrusted(self::PRINCIPAL, $tag),
            'past the configured device TTL the trust flag must not vouch',
        );

        // The contrast: the same record inside the configured TTL still
        // vouches. The rewrite is not "newly created" (SET NX semantics,
        // false for an existing tag) but refreshes the last-use.
        self::assertFalse($store->recordPrincipalNetworkTag(self::PRINCIPAL, $tag));
        self::assertTrue($store->principalNetworkSeen(self::PRINCIPAL, $tag));
        self::assertTrue($store->tagIsTrusted(self::PRINCIPAL, $tag), 'the trust mirror survives the rewrite and reads trusted inside the TTL');
    }

    /**
     * The configured class TTL is mandatory on every read: the script
     * refuses a TTL outside the class range, and a deployment could
     * not sneak a 365-day vouching lifetime for a session tag past
     * the tree bounds. A read with no TTL at all is refused too.
     */
    public function testTheScriptRefusesReadsOutsideTheClassRange(): void
    {
        $script = file_get_contents(dirname(__DIR__).'/resources/principal_networks.lua');
        self::assertIsString($script);
        $key = 'pnet-refusal-'.bin2hex(random_bytes(4));
        $refused = 0;
        foreach (
            [
                ['seen', 'device:dddd0000000000000000000000000007', '31536000001'],
                ['seen', 'device:dddd0000000000000000000000000007', '59999'],
                ['has_trusted', 'session:eeee0000000000000000000000000008', '86400001'],
                ['seen', 'device:dddd0000000000000000000000000007'],
            ] as $args
        ) {
            try {
                $this->client->eval($script, 1, $key, ...$args);
                self::fail(sprintf('the %s read with [%s] must be refused by the script', $args[0], implode(', ', array_slice($args, 1))));
            } catch (\Throwable $e) {
                self::assertStringContainsString('ttl_ms outside the class range', $e->getMessage());
                $refused++;
            }
        }
        self::assertSame(4, $refused, 'every out-of-range or missing read TTL is refused');
    }

    /**
     * The read-through migration: history recorded under the legacy
     * shared-tag key (the spelling deployments wrote before the
     * principal moved into the hash tag) answers under the current key
     * after the first miss migrates it, and the legacy key is deleted.
     */
    public function testLegacyKeyHistoryIsMigratedOnAMiss(): void
    {
        $store = $this->store();
        $now = (string) (int) floor(microtime(true) * 1000);
        $legacyKey = $store->legacyTagKey(self::PRINCIPAL);
        $deviceTag = 'device:bbbb0000000000000000000000000010';
        $this->client->hset($legacyKey, 'net:040a010203', $now);
        $this->client->hset($legacyKey, 't:net:040a010203', '1');
        $this->client->hset($legacyKey, $deviceTag, $now);
        $this->client->hset($legacyKey, 't:'.$deviceTag, '1');

        // The first miss under the current key migrates and re-reads.
        self::assertTrue($store->principalNetworkSeen(self::PRINCIPAL, 'net:040a010203'));
        self::assertTrue($store->tagIsTrusted(self::PRINCIPAL, $deviceTag));
        self::assertTrue($store->principalHasTrustedNetwork(self::PRINCIPAL));
        // The legacy key is deleted after the copy.
        self::assertSame(0, (int) $this->client->exists($legacyKey));
    }

    /**
     * The migration probes the legacy key once per principal per
     * process: a record written to the legacy key after the one-shot
     * migration ran is never re-read by the same store instance.
     */
    public function testLegacyMigrationRunsOncePerPrincipal(): void
    {
        $store = $this->store();
        $now = (string) (int) floor(microtime(true) * 1000);
        $legacyKey = $store->legacyTagKey(self::PRINCIPAL);
        $this->client->hset($legacyKey, 'net:040a010203', $now);
        self::assertTrue($store->principalNetworkSeen(self::PRINCIPAL, 'net:040a010203'));

        // A late legacy write is not re-read: the probe is one-shot.
        $this->client->hset($legacyKey, 'net:040a010204', $now);
        self::assertFalse($store->principalNetworkSeen(self::PRINCIPAL, 'net:040a010204'));
    }

    /**
     * With the migration turned off, a miss stays a miss and the
     * legacy key stays untouched (the operator's off switch after the
     * one-release window).
     */
    public function testTheMigrationCanBeTurnedOff(): void
    {
        $store = $this->store(migrateLegacy: false);
        $now = (string) (int) floor(microtime(true) * 1000);
        $legacyKey = $store->legacyTagKey(self::PRINCIPAL);
        $this->client->hset($legacyKey, 'net:040a010203', $now);
        self::assertFalse($store->principalNetworkSeen(self::PRINCIPAL, 'net:040a010203'));
        self::assertSame(1, (int) $this->client->exists($legacyKey), 'the legacy key survives with the migration off');
    }

    public function testInvalidTagIsRefused(): void
    {
        $store = $this->store();
        $refused = 0;
        foreach (['', 'nope', 'net:', 'net:XYZ', 'session:tooshort!', 'asn:abc', str_repeat('x', 81)] as $bad) {
            try {
                $store->recordPrincipalNetworkTag(self::PRINCIPAL, $bad);
                self::fail(sprintf('tag %s must be refused', var_export($bad, true)));
            } catch (\InvalidArgumentException) {
                $refused++;
            }
        }
        self::assertSame(7, $refused, 'every malformed tag is refused');
    }

    public function testAsnTagIsAccepted(): void
    {
        $store = $this->store();
        self::assertTrue($store->recordPrincipalNetworkTag(self::PRINCIPAL, 'asn:64496'));
        self::assertTrue($store->principalNetworkSeen(self::PRINCIPAL, 'asn:64496'));
    }

    /**
     * The unlisted-ASN buckets (AsnBucket::forUnlistedIp spellings) are
     * first-class tags: a refusal would fail tag validation and leave
     * the novelty gate blind on exactly those networks.
     */
    public function testUnlistedAsnBucketsAreAccepted(): void
    {
        $store = $this->store();
        foreach (['asn:0', 'asn:1', 'asn:4294967294', 'asn:u4/0', 'asn:u4/65535', 'asn:u6/00000000', 'asn:u6/ffffffff'] as $shape) {
            self::assertTrue(
                $store->recordPrincipalNetworkTag(self::PRINCIPAL, $shape),
                sprintf('the unlisted-ASN shape %s must be recorded', $shape),
            );
            self::assertTrue($store->principalNetworkSeen(self::PRINCIPAL, $shape));
        }
        // Malformed neighbours stay refused: leading zeros, out-of-shape
        // u4/u6 spellings. (Numeric range checks live in AsnBucket at
        // the engine boundary; tag validation is grammar-only.)
        foreach (['asn:007', 'asn:u4/065535', 'asn:u4/655360', 'asn:u6/0000000', 'asn:u6/000000000', 'asn:u6/ABCDEFGH'] as $bad) {
            try {
                $store->recordPrincipalNetworkTag(self::PRINCIPAL, $bad);
                self::fail(sprintf('tag %s must be refused', var_export($bad, true)));
            } catch (\InvalidArgumentException) {
            }
        }
    }
}
