<?php

declare(strict_types=1);

namespace KiwiCaptcha\Risk\Tests;

use KiwiCaptcha\Risk\RiskEventKind;
use KiwiCaptcha\Risk\Storage\ShardedRedisRiskStateStore;
use PHPUnit\Framework\TestCase;

/**
 * The Plane 7 done-when measurements for the PHP sharded store: the p99
 * assessment latency under a threaded-style hammer and the endpoint
 * (slot stand-in) scaling curve. Gated behind KIWI_SHARDING_BENCH=1 so
 * the regular suite never pays for it; the harness starts its own
 * throwaway redis-server processes (nosave shutdown) and prints both
 * numbers. PHP is request-bound per worker, so the hammer runs as
 * sequential bursts over one store per stand-in count (the honest
 * single-worker shape a PHP-FPM worker exhibits); the multi-node
 * scaling story is the Rust harness's worker processes.
 */
final class ShardedScalingTest extends TestCase
{
    private const T0 = 1_700_000_000_000;

    /** @return list<int> free ports for the stand-in servers */
    private static function freePorts(int $count): array
    {
        $ports = [];
        while (count($ports) < $count) {
            $sock = stream_socket_server('tcp://127.0.0.1:0', $errno, $errstr);
            self::assertNotFalse($sock);
            $name = stream_socket_get_name($sock, false);
            $ports[] = (int) substr((string) $name, (int) strrpos((string) $name, ':') + 1);
            fclose($sock);
        }

        return $ports;
    }

    /** @return array{0: list<int>, 1: list<resource>} ports and server handles */
    private static function startServers(int $count): array
    {
        $ports = self::freePorts($count);
        $servers = [];
        foreach ($ports as $port) {
            $cmd = sprintf(
                'redis-server --port %d --save "" --appendonly no --daemonize yes --pidfile /tmp/kiwi-bench-%d.pid',
                $port,
                $port,
            );
            exec($cmd, $out, $code);
            self::assertSame(0, $code, "redis-server on $port failed to start");
            $servers[] = null;
        }
        // Wait for every server to answer PING.
        foreach ($ports as $port) {
            $client = \KiwiCaptcha\Risk\Storage\RedisRiskStateStore::createClient("tcp://127.0.0.1:$port");
            $deadline = microtime(true) + 10;
            $up = false;
            while (microtime(true) < $deadline) {
                try {
                    $client->ping();
                    $up = true;
                    break;
                } catch (\Throwable) {
                    usleep(20000);
                }
            }
            self::assertTrue($up, "redis-server on $port never came up");
        }

        return [$ports, $servers];
    }

    private static function stopServers(array $ports): void
    {
        foreach ($ports as $port) {
            exec("redis-cli -p $port shutdown nosave > /dev/null 2>&1");
        }
    }

    private function observation(string $eventId): \KiwiCaptcha\Risk\RiskObservation
    {
        return new \KiwiCaptcha\Risk\RiskObservation(
            event: RiskEventKind::PreIssue,
            scope: 0,
            sourceEpoch: 12345,
            sourceIdPrev: str_repeat('a', 32),
            sourceId: str_repeat('b', 32),
            sourceIdNext: str_repeat('c', 32),
            subnetEpoch: 12345,
            subnetIdPrev: str_repeat('d', 32),
            subnetId: str_repeat('e', 32),
            subnetIdNext: str_repeat('f', 32),
            sessionId: null,
            principalId: null,
            eventId: $eventId,
            networkRisk: 0,
            nowMs: self::T0,
        );
    }

    public function testP99AssessmentLatencyAndScaling(): void
    {
        if (getenv('KIWI_SHARDING_BENCH') !== '1') {
            self::markTestSkipped('KIWI_SHARDING_BENCH != 1');
        }
        [$ports, $servers] = self::startServers(8);
        try {
            $urls = array_map(
                static fn (int $port): string => "tcp://127.0.0.1:$port",
                $ports,
            );

            // The p99 hammer: one store on all eight stand-ins, one
            // PHP worker (the honest PHP-FPM single-worker shape),
            // saturated for a fixed budget.
            $store = new ShardedRedisRiskStateStore(
                $urls,
                namespace: 'p99' . bin2hex(random_bytes(4)),
                connectTimeoutSecs: 2.0,
                commandTimeoutSecs: 2.0,
            );
            $latencies = [];
            $ops = 0;
            $start = microtime(true);
            $budget = 3.0;
            $i = 0;
            while (microtime(true) - $start < $budget) {
                $at = microtime(true);
                $store->observe($this->observation(str_pad(dechex($i), 32, '0', STR_PAD_LEFT)));
                $latencies[] = (int) round((microtime(true) - $at) * 1_000_000);
                $i++;
                $ops++;
            }
            $elapsed = microtime(true) - $start;
            sort($latencies);
            $percentile = static function (float $p) use ($latencies): float {
                return $latencies[(int) round((count($latencies) - 1) * $p)] / 1000.0;
            };
            $baseline = $ops / $elapsed;
            printf(
                "PHP sharded: baseline %.0f ops/s, samples %d, p50 %.3f ms, p99 %.3f ms, max %.3f ms\n",
                $baseline,
                count($latencies),
                $percentile(0.50),
                $percentile(0.99),
                $percentile(1.0),
            );

            // The scaling curve: same hammer, fewer stand-ins. Each
            // configuration gets a fresh namespace (fresh keyspace).
            foreach ([1, 2, 4] as $endpoints) {
                $scaled = new ShardedRedisRiskStateStore(
                    array_slice($urls, 0, $endpoints),
                    namespace: 'scale' . bin2hex(random_bytes(4)),
                    connectTimeoutSecs: 2.0,
                    commandTimeoutSecs: 2.0,
                );
                $ops = 0;
                $start = microtime(true);
                $i = 0;
                while (microtime(true) - $start < 2.0) {
                    $scaled->observe($this->observation(str_pad(dechex($i), 32, '0', STR_PAD_LEFT)));
                    $i++;
                    $ops++;
                }
                printf(
                    "PHP sharded: endpoints=%d ops/s=%.0f\n",
                    $endpoints,
                    $ops / (microtime(true) - $start),
                );
            }
            self::assertGreaterThan(0, $baseline);
        } finally {
            self::stopServers($ports);
        }
    }
}
