<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests;

use BelConsulting\KiwiCaptchaBundle\Security\RedisAdmissionSemaphore;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\FakePredisClient;
use PHPUnit\Framework\TestCase;

/**
 * The Cluster-slot contract of the admission semaphore: every KEYS
 * argument of every script the class issues (acquire, scoped acquire,
 * release, scoped release, usage) must occupy one Redis Cluster slot.
 * The fake client records each EVAL's key list verbatim. The slot is
 * computed with the canonical crc16/xmodem algorithm Redis Cluster
 * applies to a key's hash tag: slot = crc16(tag) & 0x3FFF. The
 * algorithm is pinned against vectors asked from a cluster-mode
 * server's own keyslot command. A derived key that ever loses its tag
 * would land in a different slot and fail the single-slot assertion
 * before a cross-slot refusal could reach a real Cluster.
 */
final class RedisAdmissionSemaphoreClusterSlotTest extends TestCase
{
    public function testCrc16XmodemMatchesTheServerAuthoritativeSlots(): void
    {
        // Vectors asked from a cluster-mode Redis server's own
        // keyslot command, where slot = crc16/xmodem(tag) & 0x3FFF:
        // the cluster-spec example pair, the plain-word fallback
        // hashing, and the checksum string.
        self::assertSame(3443, self::crc16('user1000') & 0x3FFF);
        self::assertSame(15495, self::crc16('a') & 0x3FFF);
        self::assertSame(4574, self::crc16('kiwicaptcha:argon2:leases') & 0x3FFF);
        self::assertSame(12739, self::crc16('123456789') & 0x3FFF);
    }

    /**
     * @dataProvider provideNamespacesAndScopes
     */
    public function testEveryScriptKeyOccupiesOneClusterSlot(string $namespace, ?string $scope): void
    {
        $client = new FakePredisClient();
        $sem = new RedisAdmissionSemaphore($client, 4, $namespace, 60_000, 8, 2);

        $lease = $sem->acquire($scope);
        self::assertNotNull($lease);
        $sem->release($lease);
        $sem->acquire($scope);
        $sem->usage();

        // The fake's public command log: every EVAL/EVALSHA entry
        // carries [script-or-sha, numKeys, keys..., args...].
        $invocations = [];
        foreach ($client->calls as [$cmd, $arguments]) {
            if ($cmd !== 'EVAL' && $cmd !== 'EVALSHA') {
                continue;
            }
            $numKeys = (int) $arguments[1];
            $invocations[] = array_map('strval', \array_slice($arguments, 2, $numKeys));
        }
        self::assertGreaterThanOrEqual(4, \count($invocations), 'acquire, release, re-acquire and usage must each have run');
        foreach ($invocations as $i => $keys) {
            self::assertNotSame([], $keys, "invocation {$i} carries keys");
            $slots = [];
            foreach ($keys as $key) {
                self::assertMatchesRegularExpression('/\{[^}]+\}/', $key, "key {$key} must carry a hash tag");
                $slots[] = self::crc16(self::hashTag($key)) & 0x3FFF;
            }
            self::assertSame(
                [$slots[0]],
                array_values(array_unique($slots)),
                "invocation {$i} (keys: ".implode(', ', $keys).") must occupy exactly one Cluster slot",
            );
        }

        // The family members are distinct keys in one slot: the global
        // set, the saturation gauge and (when scoped) the scope set
        // never collapse onto each other. The no-scope acquire
        // deliberately declares the global key in the scope-key slot,
        // so the distinctness floor is two members unscoped, three
        // scoped.
        $distinct = array_unique(array_merge(...$invocations));
        self::assertGreaterThanOrEqual($scope !== null ? 3 : 2, \count($distinct), 'the family members are distinct keys');
    }

    /** @return list<array{0: string, 1: string|null}> */
    public static function provideNamespacesAndScopes(): array
    {
        return [
            ['default', null],
            ['default', 'login'],
            ['prod-a', 'tenant_a'],
            ['prod_a', 'tenant:a'],
            ['ci.with.dots-and_underscores', 'a-very-long-scope-name-that-hashes-distinctly'],
        ];
    }

    private static function hashTag(string $key): string
    {
        $m = [];
        self::assertSame(1, preg_match('/\{([^}]*)\}/', $key, $m), "key {$key} must carry a hash tag");

        return $m[1];
    }

    /**
     * The crc16/xmodem checksum (polynomial 0x1021, init 0x0000, no
     * reflection, no final xor): the function Redis Cluster's
     * key-hash-slot computation applies to the bytes between the
     * hash-tag braces.
     */
    private static function crc16(string $bytes): int
    {
        $crc = 0;
        foreach (str_split($bytes) as $byte) {
            $crc ^= \ord($byte) << 8;
            for ($i = 0; $i < 8; ++$i) {
                $crc = ($crc & 0x8000) ? (($crc << 1) ^ 0x1021) & 0xFFFF : ($crc << 1) & 0xFFFF;
            }
        }

        return $crc;
    }
}
