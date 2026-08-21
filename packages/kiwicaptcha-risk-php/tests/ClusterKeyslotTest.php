<?php

declare(strict_types=1);

namespace KiwiCaptcha\Risk\Tests;

use KiwiCaptcha\Risk\Storage\RedisRiskStateStore;
use Predis\Client;
use PHPUnit\Framework\TestCase;

/**
 * Redis Cluster keyslot tests.
 *
 * Every multi-key Lua invocation must use keys in the same hash slot
 * (the {kiwi:<ns>} tag). For each canonical script's key set the keys
 * are built exactly as the production code builds them, then all slots
 * are asserted equal. The slot is asked from the server itself via the
 * cluster keyslot command when the instance serves it. Standalone Redis
 * 7 refuses the cluster command ("This instance has cluster support
 * disabled"), so the test falls back to the canonical CRC-16/xmodem
 * slot computation. That is the exact algorithm Redis Cluster uses for
 * hash tags: slot = crc16(tag) & 0x3FFF, whose reference vectors are
 * pinned in the store's assertSameSlot and the keyslot tests. Either
 * way every key of one script invocation must hash to one slot.
 *
 * Skipped unless a Redis URL is configured, like the other Redis-backed
 * tests.
 */
final class ClusterKeyslotTest extends TestCase
{
    private const SCRIPT_KEY_COUNTS = [
        'risk-v1.lua' => 10,
        'calibration.lua' => 25,
        'confirm.lua' => 3,
        'correction.lua' => 2,
        'register_decision.lua' => 3,
        'outcome_confirm.lua' => 1,
        'outcome_correct.lua' => 1,
        'outcome_register.lua' => 1,
        'sampling_metrics.lua' => 24,
    ];

    private ?Client $client = null;

    protected function setUp(): void
    {
        $url = getenv('RISK_REDIS_URL');
        if (!is_string($url) || $url === '') {
            self::markTestSkipped('RISK_REDIS_URL not set; start redis with: docker run -d -p 6399:6379 redis:7-alpine');
        }
        $this->client = RedisRiskStateStore::createClient($url);
    }

    /** The hash tag of a key ({...}), or null when absent. */
    private static function hashTag(string $key): ?string
    {
        $open = strpos($key, '{');
        $close = $open === false ? false : strpos($key, '}', $open);
        if ($open === false || $close === false) {
            return null;
        }
        return substr($key, $open + 1, $close - $open - 1);
    }

    /**
     * Server-authoritative slot when the instance serves the cluster
     * keyslot command; the canonical CRC-16/xmodem slot computation
     * otherwise, since standalone Redis refuses the cluster command.
     */
    private function slotOf(string $key): int
    {
        try {
            $reply = $this->client->executeRaw(['CLUSTER', 'KEYSLOT', $key]);
            if (is_int($reply)) {
                return $reply;
            }
            $message = (string) $reply;
            if (str_contains($message, 'cluster support disabled')) {
                return self::crc16Slot($key);
            }
            throw new \RuntimeException("CLUSTER KEYSLOT returned: {$message}");
        } catch (\Predis\Exception\ServerException $e) {
            if (str_contains($e->getMessage(), 'cluster support disabled')) {
                return self::crc16Slot($key);
            }
            throw $e;
        }
    }

    /** slot = crc16(tag) & 0x3FFF — the Redis Cluster hash-tag algorithm. */
    private static function crc16Slot(string $key): int
    {
        $tag = self::hashTag($key);
        if ($tag === null) {
            throw new \LogicException("key {$key} has no hash tag");
        }
        return RedisRiskStateStore::crc16($tag) & 0x3FFF;
    }

    private function assertSameSlot(string $script, array $keys): void
    {
        self::assertNotEmpty($keys, "$script: key set must not be empty");
        self::assertCount(
            self::SCRIPT_KEY_COUNTS[$script],
            $keys,
            "$script: canonical key-set size must stay pinned at " . self::SCRIPT_KEY_COUNTS[$script],
        );
        $slots = [];
        foreach ($keys as $key) {
            self::assertStringContainsString('{', $key, "$script: key $key must carry a hash tag");
            $slots[] = $this->slotOf($key);
        }
        self::assertSame(
            1,
            count(array_unique($slots)),
            sprintf('%s: all keys must hash to the SAME cluster slot (got %s)', $script, json_encode($slots)),
        );
    }

    public function testRiskV1KeySetSharesOneSlot(): void
    {
        $ns = 'ks' . bin2hex(random_bytes(4));
        $tag = "{kiwi:{$ns}}";
        $epoch = 12345;
        $keys = [
            "{$tag}:risk:src:{$epoch}:" . str_repeat('a', 32),
            "{$tag}:risk:src:" . ($epoch - 1) . ':' . str_repeat('b', 32),
            "{$tag}:risk:src:" . ($epoch + 1) . ':' . str_repeat('c', 32),
            "{$tag}:risk:net:{$epoch}:" . str_repeat('d', 32),
            "{$tag}:risk:net:" . ($epoch - 1) . ':' . str_repeat('e', 32),
            "{$tag}:risk:net:" . ($epoch + 1) . ':' . str_repeat('f', 32),
            "{$tag}:risk:session:" . str_repeat('0', 32),
            "{$tag}:risk:principal:" . str_repeat('0', 32),
            "{$tag}:risk:global",
            "{$tag}:risk:dedupe:" . str_repeat('c', 32),
        ];
        // Identical to the store's observe() construction (with the zero
        // placeholders for absent session/principal).
        $this->assertSameSlot('risk-v1.lua', $keys);
    }

    public function testCalibrationKeySetSharesOneSlot(): void
    {
        $ns = 'ks' . bin2hex(random_bytes(4));
        $scope = 1;
        $hour = 123456;
        $keys = [];
        for ($i = 0; $i < 24; $i++) {
            $keys[] = "{kiwi:{$ns}}:cal:{$scope}:" . ($hour - $i);
        }
        $keys[] = "{kiwi:{$ns}}:cal:state:{$scope}";
        // Identical to AggregateCalibrator::biasForScope()'s construction
        // (24 hourly buckets + the rate-limit state).
        $this->assertSameSlot('calibration.lua', $keys);
    }

    public function testConfirmKeySetSharesOneSlot(): void
    {
        $ns = 'ks' . bin2hex(random_bytes(4));
        $decisionId = str_repeat('9', 32);
        $keys = [
            "{kiwi:{$ns}}:cal:receipt:{$decisionId}",
            "{kiwi:{$ns}}:cal:2:123456",
            "{kiwi:{$ns}}:outcome:{$decisionId}",
        ];
        // receipt + decision-time bucket + outcome ledger (calibrator's
        // confirm path + the shared store ledgerKey()).
        $this->assertSameSlot('confirm.lua', $keys);
    }

    public function testCorrectionKeySetSharesOneSlot(): void
    {
        $ns = 'ks' . bin2hex(random_bytes(4));
        $decisionId = str_repeat('8', 32);
        $keys = [
            "{kiwi:{$ns}}:cal:receipt:{$decisionId}",
            "{kiwi:{$ns}}:cal:2:123456",
        ];
        $this->assertSameSlot('correction.lua', $keys);
    }

    public function testRegisterDecisionKeySetSharesOneSlot(): void
    {
        $ns = 'ks' . bin2hex(random_bytes(4));
        $decisionId = str_repeat('7', 32);
        $keys = [
            "{kiwi:{$ns}}:cal:receipt:{$decisionId}",
            "{kiwi:{$ns}}:cal:1:123456",
            "{kiwi:{$ns}}:outcome:{$decisionId}",
        ];
        // receipt + sampled denominator bucket + outcome ledger.
        $this->assertSameSlot('register_decision.lua', $keys);
    }

    public function testOutcomeScriptsUseOneKeyWithTheTag(): void
    {
        $ns = 'ks' . bin2hex(random_bytes(4));
        $decisionId = str_repeat('6', 32);
        $ledger = "{kiwi:{$ns}}:outcome:{$decisionId}";
        foreach (['outcome_confirm.lua', 'outcome_correct.lua', 'outcome_register.lua'] as $script) {
            $this->assertSameSlot($script, [$ledger]);
        }
    }

    public function testSamplingMetricsKeySetSharesOneSlot(): void
    {
        $ns = 'ks' . bin2hex(random_bytes(4));
        $scope = 1;
        $hour = 123456;
        $keys = [];
        for ($i = 0; $i < 24; $i++) {
            $keys[] = "{kiwi:{$ns}}:cal:{$scope}:" . ($hour - $i);
        }
        // Identical to AggregateCalibrator::samplingMetrics()'s construction
        // (24 hourly buckets, no state key).
        $this->assertSameSlot('sampling_metrics.lua', $keys);
    }

    public function testSlotAgreesWithTheLocalCrc16Assertion(): void
    {
        // The store's own assertSameSlot (pure CRC-16 over the tag) must
        // agree with the slot computation used by this test. On a
        // cluster-enabled instance the server's keyslot answer is used and
        // must agree with the local CRC-16 too.
        $ns = 'ks' . bin2hex(random_bytes(4));
        $store = new RedisRiskStateStore($this->client, namespace: $ns);
        $keys = [
            "{kiwi:{$ns}}:risk:src:1:" . str_repeat('a', 32),
            "{kiwi:{$ns}}:risk:global",
        ];
        $store->assertSameSlot($keys); // throws on mismatch
        $local = array_map(static fn (string $key): int => self::crc16Slot($key), $keys);
        $server = array_map(fn (string $key): int => $this->slotOf($key), $keys);
        self::assertSame(1, count(array_unique($server)), 'all keys must share one cluster slot');
        self::assertSame($local, $server, 'the local CRC-16 slot computation must agree with the server');
    }
}
