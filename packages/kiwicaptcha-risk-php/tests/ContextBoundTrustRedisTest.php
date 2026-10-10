<?php

declare(strict_types=1);

namespace KiwiCaptcha\Risk\Tests;

use KiwiCaptcha\Risk\Asn\AsnDataset;
use KiwiCaptcha\Risk\Storage\RedisRiskStateStore;
use KiwiCaptcha\Risk\Trust\ContextBoundTrust;
use PHPUnit\Framework\TestCase;

/**
 * Context-bound trust against real Redis: the thousand-foreign-buckets
 * replay earns nothing, the home-to-mobile commute keeps home credit
 * fully effective, the record TTL follows the session dimension, and
 * the surface validates its ids fail closed. The Rust mirror is
 * tests/context_trust_redis.rs.
 *
 * Decay is time-based (2 raw units per second), so the keep-home-credit
 * assertions allow a small wall-clock slack: a foreign presentation
 * itself must never remove a unit, only the passage of time can.
 */
final class ContextBoundTrustRedisTest extends TestCase
{
    private const SESSION = 'c7b3e1f9a5d24708b6e0c8a2f4d69123';

    private const DECAY_SLACK = 10;

    /** @var \Predis\Client */
    private $client;

    protected function setUp(): void
    {
        $url = getenv('RISK_REDIS_URL');
        if (!is_string($url) || $url === '') {
            self::markTestSkipped('RISK_REDIS_URL not set; start redis with: redis-server --port 6423 --save "" --appendonly no --daemonize yes');
        }
        $this->client = RedisRiskStateStore::createClient($url);
        $this->client->ping();
    }

    private function store(): RedisRiskStateStore
    {
        return new RedisRiskStateStore($this->client, 'trust-' . bin2hex(random_bytes(4)));
    }

    private function dataset(): AsnDataset
    {
        return AsnDataset::open(dirname(__DIR__) . '/../../protocol/asn/sample-asn.tsv');
    }

    public function testAThousandForeignBucketsEarnNothing(): void
    {
        $store = $this->store();
        $trust = new ContextBoundTrust($this->dataset(), $store);

        // The session earns full home credit in its home bucket.
        $home = $trust->earn(self::SESSION, '198.51.100.42', 10_000);
        self::assertSame(1000, $home->credit);
        self::assertTrue($home->isHome);

        // A trusted cookie replayed from one thousand distinct foreign
        // buckets earns nothing: each foreign bucket starts empty, and
        // the credit decision reads only that foreign record.
        for ($n = 0; $n < 1000; $n++) {
            $decision = $trust->creditFor(self::SESSION, sprintf('%d.%d.0.1', 45 + intdiv($n, 250), ($n % 250) + 1));
            self::assertSame(0, $decision->credit, "foreign bucket {$n} must earn nothing");
            self::assertFalse($decision->isHome);
        }

        // The home record is untouched by every foreign presentation;
        // only the decay channel may shave the slack window.
        $homeAfter = $trust->creditFor(self::SESSION, '198.51.100.42');
        self::assertGreaterThanOrEqual(10_000 - self::DECAY_SLACK, $homeAfter->rawTrust);
        self::assertGreaterThanOrEqual(1000 - intdiv(self::DECAY_SLACK, 10), $homeAfter->credit);

        $this->client->del([$store->bucketTrustKey(self::SESSION, $home->bucket)]);
    }

    public function testTheHomeToMobileCommuteKeepsHomeCredit(): void
    {
        $store = $this->store();
        $trust = new ContextBoundTrust($this->dataset(), $store);

        $earned = $trust->earn(self::SESSION, '198.51.100.42', 8_000);
        self::assertSame(800, $earned->credit);

        // A commute through foreign networks: reads only, never a write
        // to the home record, and each foreign read earns nothing.
        foreach (['203.0.113.150', '8.8.8.8', '2600::1', '2001:db8:5::1'] as $foreign) {
            self::assertSame(0, $trust->creditFor(self::SESSION, $foreign)->credit, "{$foreign} earns nothing");
        }

        // Presenting from home again: the full home credit applies,
        // never reduced by the foreign presentations themselves.
        $backHome = $trust->creditFor(self::SESSION, '198.51.100.42');
        self::assertSame($earned->bucket, $backHome->bucket);
        self::assertGreaterThanOrEqual(8_000 - self::DECAY_SLACK, $backHome->rawTrust);
        self::assertGreaterThanOrEqual(800 - intdiv(self::DECAY_SLACK, 10), $backHome->credit);

        // Earning more at home accumulates within the ceiling.
        $topped = $trust->earn(self::SESSION, '198.51.100.42', 5_000);
        self::assertGreaterThanOrEqual(10_000 - self::DECAY_SLACK, $topped->rawTrust);
        self::assertSame(1000, $topped->credit);

        $this->client->del([$store->bucketTrustKey(self::SESSION, 'a64498')]);
    }

    public function testRecordsCarryTheSessionDimensionTtlAndPureReads(): void
    {
        $store = $this->store();
        $trust = new ContextBoundTrust($this->dataset(), $store);
        $key = $store->bucketTrustKey(self::SESSION, 'a64498');

        try {
            $earned = $trust->earn(self::SESSION, '198.51.100.42', 3_000);
            $before = (int) $this->client->ttl($key);
            self::assertGreaterThan(0, $before);
            self::assertLessThanOrEqual(1800, $before, 'the record TTL follows the session dimension');

            // A pure read never refreshes the TTL nor mutates the
            // record: after a measurable pause the TTL keeps falling
            // through the reads.
            usleep(1_100_000);
            $read = $trust->creditFor(self::SESSION, '198.51.100.42');
            self::assertLessThanOrEqual($earned->rawTrust, $read->rawTrust, 'a read never adds trust');
            $throughReads = (int) $this->client->ttl($key);
            self::assertLessThan($before, $throughReads, 'a read must not refresh the TTL');
        } finally {
            $this->client->del([$key]);
        }
    }

    public function testTheSurfaceValidatesItsIdsFailClosed(): void
    {
        $store = $this->store();

        foreach (['', 'NOTHEX', 'c7b3e1f9a5d24708b6e0c8a2f4d6912'] as $badSession) {
            try {
                $store->bucketTrustKey($badSession, 'a1');
                self::fail("{$badSession} must be refused as a session id");
            } catch (\InvalidArgumentException) {
                self::addToAssertionCount(1);
            }
        }
        foreach (['', 'a0', 'u4/65536', 'u6/20010db', 'x1', 'a64496:x'] as $badBucket) {
            try {
                $store->bucketTrustKey(self::SESSION, $badBucket);
                self::fail("{$badBucket} must be refused as a bucket id");
            } catch (\InvalidArgumentException) {
                self::addToAssertionCount(1);
            }
        }
        self::assertSame("trust:{kiwi:{$store->namespace()}}:" . self::SESSION . ':a64496', $store->bucketTrustKey(self::SESSION, 'a64496'));
        try {
            $store->creditBucketTrust(self::SESSION, 'a1', 100_001);
            self::fail('an over-bound delta must be refused before Redis');
        } catch (\InvalidArgumentException) {
            self::addToAssertionCount(1);
        }

        // The policy computation and the record surface agree on the band.
        try {
            $store->creditBucketTrust(self::SESSION, 'a1', 2_500);
            $decision = ContextBoundTrust::decision('a1', $store->readBucketTrust(self::SESSION, 'a1'));
            self::assertLessThanOrEqual(2_500, $decision->rawTrust);
            self::assertLessThanOrEqual(250, $decision->credit);
        } finally {
            $this->client->del([$store->bucketTrustKey(self::SESSION, 'a1')]);
        }
    }
}
