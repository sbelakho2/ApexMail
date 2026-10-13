<?php

declare(strict_types=1);

namespace KiwiCaptcha\Risk\Tests;

use KiwiCaptcha\Risk\RiskEventKind;
use KiwiCaptcha\Risk\RiskObservation;
use KiwiCaptcha\Risk\Storage\KeyspaceMode;
use KiwiCaptcha\Risk\Storage\RedisRiskStateStore;
use KiwiCaptcha\Risk\Storage\ShardedRedisRiskStateStore;
use PHPUnit\Framework\TestCase;
use Predis\Command\RawCommand;

/**
 * The single-slot hot path is gone (the H7 done-when), proven against
 * two throwaway redis-server stand-ins on their own ports:
 *
 * 1. the level-transition script and the session keys land on
 *    separate endpoints (separate cluster slots; the stand-in rule is
 *    slot modulo the endpoint list);
 * 2. the transition runs once per merge window on its own slot, never
 *    per assessment: the per-port EVALSHA budget of a measured run
 *    matches the exact routed expectation, which a per-assessment
 *    hysteresis call would exceed by one call per assessment;
 * 3. the session tag records live on the session family's slot, the
 *    hysteresis hash on the shared tag's slot, and neither ever appears
 *    on the other server.
 *
 * The harness spawns its own redis-server processes on free ports and
 * shuts every one down with a nosave final write, so the suite needs no
 * infrastructure and leaves no persistence artifacts.
 */
final class ShardedSlotSeparationTest extends TestCase
{
    private const assessmentCount = 40;

    /** @return list<int> free ports for the stand-in servers */
    private static function freePorts(int $count): array
    {
        $ports = [];
        while (count($ports) < $count) {
            $sock = stream_socket_server('tcp://127.0.0.1:0', $errno, $errstr);
            self::assertNotFalse($sock);
            $addr = stream_socket_get_name($sock, false);
            fclose($sock);
            $ports[] = (int) substr((string) $addr, (int) strrpos((string) $addr, ':') + 1);
        }

        return $ports;
    }

    /**
     * The suite needs the local binaries. It spawns its own two
     * stand-in servers: a single shared RISK_REDIS_URL cannot provide
     * the two-endpoint slot separation this test proves, and a shared
     * service container must never be shut down. A missing binary is
     * an explicit skip with the remedy, never a red exit code 127.
     */
    private static function requireStandinBinaries(): void
    {
        foreach (['redis-server', 'redis-cli'] as $binary) {
            if (trim((string) shell_exec('command -v ' . escapeshellarg($binary) . ' 2>/dev/null')) !== '') {
                continue;
            }
            self::markTestSkipped(sprintf(
                '%s is not on PATH; the sharded slot-separation suite spawns two throwaway local'
                . ' stand-in servers, so install redis-server and redis-cli (or run the suite in a'
                . ' lane image that ships them)',
                $binary,
            ));
        }
    }

    /** @return list<int> the stand-in ports */
    private static function startServers(int $count): array
    {
        self::requireStandinBinaries();
        $ports = self::freePorts($count);
        foreach ($ports as $port) {
            exec(sprintf(
                'redis-server --port %d --save "" --appendonly no --daemonize yes --pidfile /tmp/kiwi-slotsep-%d.pid',
                $port,
                $port,
            ), $out, $code);
            self::assertSame(0, $code, "redis-server on $port failed to start");
        }
        foreach ($ports as $port) {
            $client = RedisRiskStateStore::createClient("tcp://127.0.0.1:$port");
            $up = false;
            for ($i = 0; $i < 100; $i++) {
                try {
                    $client->ping();
                    $up = true;
                    break;
                } catch (\Throwable) {
                    usleep(20_000);
                }
            }
            self::assertTrue($up, "redis-server on $port never came up");
        }

        return $ports;
    }

    private static function stopServers(array $ports): void
    {
        foreach ($ports as $port) {
            exec("redis-cli -p $port shutdown nosave > /dev/null 2>&1");
        }
    }

    private static function observation(int $n): RiskObservation
    {
        return new RiskObservation(
            event: RiskEventKind::PreIssue,
            scope: 0,
            sourceEpoch: 1888,
            sourceIdPrev: str_repeat('aa', 15) . '01',
            sourceId: str_repeat('aa', 16),
            sourceIdNext: str_repeat('aa', 15) . '03',
            subnetEpoch: 1888,
            subnetIdPrev: str_repeat('bb', 15) . '01',
            subnetId: str_repeat('bb', 16),
            subnetIdNext: str_repeat('bb', 15) . '03',
            sessionId: null,
            principalId: null,
            eventId: str_pad((string) (100 + $n), 32, '0', STR_PAD_LEFT),
            networkRisk: 0,
            nowMs: 1_700_000_000_000,
        );
    }

    /** The cmdstat_evalsha:calls counter of one stand-in server. */
    private static function evalshaCalls(string $url): int
    {
        $client = RedisRiskStateStore::createClient($url);
        $info = (string) $client->executeCommand(new RawCommand('INFO', ['commandstats']));
        foreach (explode("\r\n", $info) as $line) {
            if (str_starts_with($line, 'cmdstat_evalsha:')) {
                foreach (explode(',', substr($line, strlen('cmdstat_evalsha:'))) as $field) {
                    if (str_starts_with($field, 'calls=')) {
                        return (int) substr($field, strlen('calls='));
                    }
                }
            }
        }

        return 0;
    }

    private static function resetStats(string $url): void
    {
        RedisRiskStateStore::createClient($url)
            ->executeCommand(new RawCommand('CONFIG', ['RESETSTAT']));
    }

    private static function keyExists(string $url, string $key): bool
    {
        return (int) RedisRiskStateStore::createClient($url)->exists($key) === 1;
    }

    public function testLevelTransitionLandsOnADifferentSlotThanTheSessionKeys(): void
    {
        $ports = self::startServers(2);
        try {
            $urls = array_map(static fn (int $port): string => "tcp://127.0.0.1:$port", $ports);

            // Search: the session ctx record's endpoint must differ from
            // the hysteresis hash's endpoint.
            $found = null;
            for ($seed = 0; $seed < 256 && $found === null; $seed++) {
                $namespace = sprintf('slotsep%02x%s', $seed, bin2hex(random_bytes(4)));
                $sessionHex = str_pad('5c', 32, '0', STR_PAD_LEFT);
                $probe = new ShardedRedisRiskStateStore($urls, namespace: $namespace);
                $sessionEndpoint = $probe->endpointForKey(
                    KeyspaceMode::sessionTagKey($probe->namespace(), 'ctx', $sessionHex),
                );
                $hystEndpoint = $probe->endpointForKey(
                    KeyspaceMode::hysteresisKey($probe->namespace()),
                );
                if ($sessionEndpoint !== $hystEndpoint) {
                    $found = [$namespace, $sessionHex];
                }
            }
            self::assertNotNull($found, 'a separating namespace exists within 256 seeds');
            [$namespace, $sessionHex] = $found;

            $store = new ShardedRedisRiskStateStore($urls, namespace: $namespace);
            $ns = $store->namespace();
            $hystKey = KeyspaceMode::hysteresisKey($ns);
            $sessionKey = KeyspaceMode::sessionTagKey($ns, 'ctx', $sessionHex);
            $hystEndpoint = $store->endpointForKey($hystKey);
            $sessionEndpoint = $store->endpointForKey($sessionKey);
            self::assertNotSame(
                $hystEndpoint,
                $sessionEndpoint,
                'the two keys must route to different stand-ins',
            );

            // The routed endpoint of every EVALSHA unit of one
            // assessment: six identity invocations (fixed ids, fixed
            // routing) plus the event's scope shard.
            $epochIds = static fn (string $base, string $marker): string => str_repeat($base, 15) . $marker;
            $identityUnitsOn = static fn (int $endpoint): int => (int) (
                $store->endpointForKey(KeyspaceMode::identityStateKey($ns, 'src', 1887, $epochIds('aa', '01'))) === $endpoint
            ) + (int) (
                $store->endpointForKey(KeyspaceMode::identityStateKey($ns, 'src', 1888, str_repeat('aa', 16))) === $endpoint
            ) + (int) (
                $store->endpointForKey(KeyspaceMode::identityStateKey($ns, 'src', 1889, $epochIds('aa', '03'))) === $endpoint
            ) + (int) (
                $store->endpointForKey(KeyspaceMode::identityStateKey($ns, 'net', 1887, $epochIds('bb', '01'))) === $endpoint
            ) + (int) (
                $store->endpointForKey(KeyspaceMode::identityStateKey($ns, 'net', 1888, str_repeat('bb', 16))) === $endpoint
            ) + (int) (
                $store->endpointForKey(KeyspaceMode::identityStateKey($ns, 'net', 1889, $epochIds('bb', '03'))) === $endpoint
            );
            $scopeUnitsOn = static fn (int $endpoint): int => (function () use ($store, $ns, $endpoint): int {
                $count = 0;
                for ($i = 0; $i < self::assessmentCount; $i++) {
                    $shard = KeyspaceMode::scopeShard(str_pad((string) (100 + $i), 32, '0', STR_PAD_LEFT), str_repeat('aa', 16));
                    $key = KeyspaceMode::scopeShardKey($ns, 'global', $shard);
                    if ($store->endpointForKey($key) === $endpoint) {
                        $count++;
                    }
                }

                return $count;
            })();
            $refreshScopeUnitsOn = static fn (int $endpoint): int => (function () use ($store, $ns, $endpoint): int {
                $count = 0;
                for ($shard = 0; $shard < 16; $shard++) {
                    $key = KeyspaceMode::scopeShardKey($ns, 'global', $shard);
                    if ($store->endpointForKey($key) === $endpoint) {
                        $count++;
                    }
                }

                return $count;
            })();

            // Warm-up: the first merge refresh creates the hysteresis
            // hash on its own server; a tag-bearing assessment puts the
            // session record on the session server.
            $store->observe(self::observation(0));
            $store->observe(self::observation(1));
            self::assertTrue(
                self::keyExists($urls[$hystEndpoint], $hystKey),
                'the merge refresh created the hysteresis hash on its own server',
            );
            self::assertFalse(
                self::keyExists($urls[$sessionEndpoint], $hystKey),
                'the hysteresis hash must never appear on the session server',
            );
            $tagged = self::observation(2);
            $tagged = new RiskObservation(
                event: $tagged->event,
                scope: $tagged->scope,
                sourceEpoch: $tagged->sourceEpoch,
                sourceIdPrev: $tagged->sourceIdPrev,
                sourceId: $tagged->sourceId,
                sourceIdNext: $tagged->sourceIdNext,
                subnetEpoch: $tagged->subnetEpoch,
                subnetIdPrev: $tagged->subnetIdPrev,
                subnetId: $tagged->subnetId,
                subnetIdNext: $tagged->subnetIdNext,
                sessionId: $sessionHex,
                principalId: null,
                eventId: $tagged->eventId,
                networkRisk: 0,
                nowMs: $tagged->nowMs,
            );
            $store->assessV2($tagged, 'tag', null);
            self::assertTrue(
                self::keyExists($urls[$sessionEndpoint], $sessionKey),
                'the session tag record lives on the session family server',
            );
            self::assertFalse(
                self::keyExists($urls[$hystEndpoint], $sessionKey),
                'the session tag record must never appear on the hysteresis server',
            );

            // The measured run: force the merge gate stale, reset both
            // command budgets, then run the measured assessment count.
            // The first triggers the refresh (16 scope reads plus one
            // transition), the rest ride the window. A per-assessment
            // transition would add one EVALSHA per assessment on the
            // hysteresis endpoint.
            usleep(1_150_000);
            self::resetStats($urls[0]);
            self::resetStats($urls[1]);
            for ($i = 0; $i < self::assessmentCount; $i++) {
                $store->observe(self::observation($i));
            }

            $expected = static fn (int $endpoint): int => $identityUnitsOn($endpoint) * self::assessmentCount
                + $scopeUnitsOn($endpoint)
                + $refreshScopeUnitsOn($endpoint)
                + ($endpoint === $hystEndpoint ? 1 : 0);
            foreach ($urls as $endpoint => $url) {
                self::assertSame(
                    $expected($endpoint),
                    self::evalshaCalls($url),
                    "server $endpoint: the EVALSHA budget must match the routed expectation exactly (a per-assessment transition would add one call per assessment)",
                );
            }
        } finally {
            self::stopServers($ports);
        }
    }
}
