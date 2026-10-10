<?php

declare(strict_types=1);

namespace KiwiCaptcha\Risk\Tests;

use KiwiCaptcha\Risk\Storage\KeyspaceMode;
use KiwiCaptcha\Risk\Storage\RedisRiskStateStore;
use PHPUnit\Framework\TestCase;

/**
 * Pure tests of the sharded keyspace contract (Plane 7): the FNV-1a
 * shard function with its cross-language reference vectors, the family
 * key shapes, and the key-tag correctness and dispersion rules. Every
 * sharded key's hash tag must be its family tag, and one dimension's
 * prefixes plus the 16 scope shards must disperse over many cluster
 * slots. No Redis needed.
 */
final class ShardedKeyspaceTest extends TestCase
{
    /** FNV-1a 32-bit reference vectors, pinned byte-identically in the Rust mirror. */
    public function testFnv1a32ReferenceVectors(): void
    {
        self::assertSame(0x811c9dc5, KeyspaceMode::fnv1a32(''));
        self::assertSame(0x1a47e90b, KeyspaceMode::fnv1a32('abc'));
        self::assertSame(0xf0c86445, KeyspaceMode::fnv1a32(str_repeat('0', 32)));
        self::assertSame(0xed928645, KeyspaceMode::fnv1a32(str_repeat('f', 32)));
        self::assertSame(0x1529abe5, KeyspaceMode::fnv1a32('a1b2c3d4e5f6a7b8a1b2c3d4e5f6a7b8'));
    }

    public function testScopeShardsAreDeterministicAndInBand(): void
    {
        self::assertSame(5, KeyspaceMode::scopeShard(''));
        self::assertSame(11, KeyspaceMode::scopeShard('abc'));
        for ($i = 0; $i < 64; $i++) {
            $id = str_pad(dechex($i), 32, '0', STR_PAD_LEFT);
            self::assertTrue(KeyspaceMode::scopeShard($id) <= 15);
            self::assertSame(KeyspaceMode::scopeShard($id), KeyspaceMode::scopeShard($id), 'deterministic');
        }
    }

    public function testIdPrefixIsTheFirstHexByte(): void
    {
        self::assertSame('a1', KeyspaceMode::idPrefix('a1b2c3'));
        self::assertSame('00', KeyspaceMode::idPrefix(str_repeat('0', 32)));
        self::assertSame('a', KeyspaceMode::idPrefix('a'));
        self::assertSame('', KeyspaceMode::idPrefix(''));
    }

    public function testFamilyKeysMatchTheContractShapes(): void
    {
        $ns = 'n1';
        self::assertSame(
            '{kiwi:n1:src:a1}:risk:src:900:a1b2',
            KeyspaceMode::identityStateKey($ns, 'src', 900, 'a1b2'),
        );
        self::assertSame(
            '{kiwi:n1:session:be}:risk:session:beef',
            KeyspaceMode::identityStateKey($ns, 'session', null, 'beef'),
        );
        self::assertSame(
            '{kiwi:n1:net:c0}:risk:dd:' . str_repeat('ab', 16),
            KeyspaceMode::identityMarkerKey($ns, 'net', 'c0de', str_repeat('ab', 16)),
        );
        self::assertSame(
            '{kiwi:n1:n:00}:risk:dedupe:' . str_repeat('00', 16),
            KeyspaceMode::nonceDedupeKey($ns, str_repeat('00', 16)),
        );
        self::assertSame(
            '{kiwi:n1:s:global:7}:scope:global:7',
            KeyspaceMode::scopeShardKey($ns, 'global', 7),
        );
        self::assertSame(
            '{kiwi:n1:s:global:7}:dd:abc',
            KeyspaceMode::scopeMarkerKey($ns, 'global', 7, 'abc'),
        );
        self::assertSame('{kiwi:n1}:risk:hyst', KeyspaceMode::hysteresisKey($ns));
        self::assertSame('{kiwi:n1}:mode', KeyspaceMode::modeMarkerKey($ns));
    }

    public function testKeyTagCorrectnessEveryShardedTagIsItsFamilyTag(): void
    {
        $ns = 'tagcheck';
        $tagOf = static function (string $key): string {
            $open = strpos($key, '{');
            $close = strpos($key, '}', (int) $open);

            return substr($key, (int) $open + 1, (int) $close - (int) $open - 1);
        };

        for ($i = 0; $i < 16; $i++) {
            $id = str_pad(dechex($i), 32, '0', STR_PAD_LEFT);
            $key = KeyspaceMode::identityStateKey($ns, 'src', 1, $id);
            self::assertSame(
                sprintf('kiwi:%s:src:%s', $ns, KeyspaceMode::idPrefix($id)),
                $tagOf($key),
                'the identity tag is the family tag',
            );
            $key = KeyspaceMode::nonceDedupeKey($ns, $id);
            self::assertSame(
                sprintf('kiwi:%s:n:%s', $ns, KeyspaceMode::idPrefix($id)),
                $tagOf($key),
                'the nonce tag is the family tag',
            );
        }
        for ($shard = 0; $shard < 16; $shard++) {
            $key = KeyspaceMode::scopeShardKey($ns, 'global', $shard);
            self::assertSame(
                sprintf('kiwi:%s:s:global:%d', $ns, $shard),
                $tagOf($key),
                'each shard is its own family',
            );
        }
    }

    /** One dimension's prefixes plus the 16 shards must disperse over many slots. */
    public function testShardedKeysDisperseAcrossClusterSlots(): void
    {
        $ns = 'disp';
        $slotOf = static fn (string $key): int => RedisRiskStateStore::crc16(
            substr($key, strpos($key, '{') + 1, (int) strpos($key, '}') - (int) strpos($key, '{') - 1),
        ) & 0x3FFF;

        $srcSlots = [];
        for ($i = 0; $i < 64; $i++) {
            $id = str_pad(dechex($i), 2, '0', STR_PAD_LEFT) . str_repeat('0', 30);
            $srcSlots[] = $slotOf(KeyspaceMode::identityStateKey($ns, 'src', 1, $id));
        }
        self::assertGreaterThan(
            16,
            \count(array_unique($srcSlots)),
            sprintf('64 prefixed source keys dispersed into %d slots', \count(array_unique($srcSlots))),
        );

        $shardSlots = [];
        for ($shard = 0; $shard < 16; $shard++) {
            $shardSlots[] = $slotOf(KeyspaceMode::scopeShardKey($ns, 'global', $shard));
        }
        self::assertGreaterThan(
            8,
            \count(array_unique($shardSlots)),
            sprintf('16 shards hit %d slots', \count(array_unique($shardSlots))),
        );
    }

    public function testKeySpaceModeMarkerValuesRoundTrip(): void
    {
        self::assertSame('legacy', KeyspaceMode::Legacy->value);
        self::assertSame('sharded', KeyspaceMode::Sharded->value);
        self::assertSame(KeyspaceMode::Legacy, KeyspaceMode::fromMarker('legacy'));
        self::assertSame(KeyspaceMode::Sharded, KeyspaceMode::fromMarker('sharded'));
        self::assertNull(KeyspaceMode::fromMarker('other'));
    }
}
