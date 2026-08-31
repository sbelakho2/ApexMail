<?php

declare(strict_types=1);

namespace KiwiCaptcha\Tests;

use KiwiCaptcha\ChallengeRecord;
use KiwiCaptcha\Config;
use KiwiCaptcha\Issuer;
use KiwiCaptcha\PoWAlgorithm;
use KiwiCaptcha\SolutionToken;
use KiwiCaptcha\Storage\RedisStorage;
use KiwiCaptcha\Verifier;
use KiwiCaptcha\VerifyError;
use KiwiCaptcha\Tests\Fixtures\RealRedisTestEnv;
use KiwiCaptcha\Tests\Fixtures\Vectors;
use PHPUnit\Framework\TestCase;

/**
 * Prefix-compartment fuzzing on one real Redis: two stores with
 * different key prefixes share the instance, and no record may ever be
 * readable across the boundary. The fuzz corpus covers delimiter
 * characters, unicode, casing, embedded null bytes, the empty prefix
 * and a long prefix near the practical key budget.
 *
 * Properties under test: a store reads nothing another prefix wrote,
 * every key stays under its own prefix, the same nonce under two
 * prefixes holds two independent records, and a cross-prefix
 * verification is RecordNotFound. Deterministic seeds, bounded
 * iterations, the database flushed before each run.
 *
 * Runs when `KC_REDIS_URL` or `TEST_REDIS_URL` is set (the shared
 * real-Redis env); the `KIWI_REQUIRE_REAL_REDIS_TESTS` helper turns a
 * missing environment into a hard failure in the dedicated CI lane.
 */
final class TenantIsolationPrefixFuzzTest extends TestCase
{
    private const SEED = 0xF0A2;

    private \Predis\Client $client;

    protected function setUp(): void
    {
        $url = RealRedisTestEnv::requireRedis('the real-Redis prefix-isolation fuzz suite');
        if ($url === null) {
            self::markTestSkipped('KC_REDIS_URL/TEST_REDIS_URL not set — the real-Redis prefix-isolation suite runs in the CI Redis-service job');
        }
        if (!\class_exists(\Predis\Client::class)) {
            RealRedisTestEnv::failWhenRequired('predis/predis is not installed', 'the real-Redis prefix-isolation fuzz suite');
            self::markTestSkipped('predis/predis is not installed');
        }
        try {
            $probe = new \Predis\Client($url, ['timeout' => 5.0, 'read_write_timeout' => 5.0]);
            $probe->ping();
        } catch (\Throwable) {
            RealRedisTestEnv::failWhenRequired('no Redis is reachable at the configured KC_REDIS_URL/TEST_REDIS_URL', 'the real-Redis prefix-isolation fuzz suite');
            self::markTestSkipped('no Redis at the configured KC_REDIS_URL/TEST_REDIS_URL');
        }
        $probe->flushdb();
        $this->client = $probe;
    }

    /**
     * The bounded prefix corpus: distinct namespaces over delimiters,
     * unicode, casing, an embedded null byte, the empty prefix and a
     * long prefix.
     *
     * @return list<string>
     */
    private function prefixCorpus(): array
    {
        return [
            'tenant-a:',
            'tenant-a',
            'tenant_a',
            'tenant-a|',
            'tenant-a;',
            '租户:',
            '租户|',
            'téner:',
            'PREFIX:',
            'prefix',
            '',
            'kiwicaptcha:',
            'a:b:c:d:',
            "prefix\x00inj",
            str_repeat('x', 200),
            'CASE:',
            'case:',
            'ns.1:',
            'ns-1:',
            'ns_1:',
        ];
    }

    /** A deterministic unique nonce per corpus index. */
    private function nonceFor(int $index): string
    {
        return base64_encode(hash('sha256', sprintf('kiwi-prefix-fuzz-%d', $index), true));
    }

    private function makeRecord(string $nonce, string $scope): ChallengeRecord
    {
        $salt = base64_encode(random_bytes(16));

        return new ChallengeRecord(
            nonce: $nonce,
            scope: $scope,
            bindingTag: '',
            issuedAt: 1_800_000_000,
            expiresAt: 1_800_000_120,
            algorithm: PoWAlgorithm::Sha256,
            mKib: 0,
            t: 1,
            p: 1,
            targetBits: 8,
            salt: $salt,
            prefix: 'prefix|'.$salt.'|',
            challenge: 'challenge',
            minDurationMs: 0,
            issuedAtNs: 1_800_000_000_000_000,
            protocolVersion: 2,
        );
    }

    public function testNoRecordIsReadableAcrossDistinctPrefixes(): void
    {
        $prefixes = $this->prefixCorpus();
        mt_srand(self::SEED);
        $pairCount = 0;

        foreach ($prefixes as $i => $prefixA) {
            foreach ($prefixes as $j => $prefixB) {
                if ($i === $j) {
                    continue;
                }
                $pairCount++;
                $nonce = $this->nonceFor($pairCount);
                $storeA = new RedisStorage($this->client, $prefixA);
                $storeB = new RedisStorage($this->client, $prefixB);

                $storeA->store($this->makeRecord($nonce, 'login'));
                self::assertNotNull($storeA->find($nonce), 'the owning store must read its own record');
                self::assertNull(
                    $storeB->find($nonce),
                    sprintf('store %d must never read a record written by store %d', $j, $i),
                );

                $storeA->delete($nonce);
            }
        }

        self::assertGreaterThanOrEqual(190, $pairCount, 'the prefix pair matrix must stay bounded but broad');
    }

    public function testEveryKeyStaysUnderItsOwnPrefix(): void
    {
        $prefixes = $this->prefixCorpus();
        $written = [];

        foreach ($prefixes as $i => $prefix) {
            $store = new RedisStorage($this->client, $prefix);
            $nonce = $this->nonceFor(1000 + $i);
            $store->store($this->makeRecord($nonce, 'login'));
            $written[$prefix] = $nonce;
        }

        $allKeys = $this->client->keys('*');
        self::assertSame(\count($prefixes), \count($allKeys), 'exactly one key per stored record');

        foreach ($written as $prefix => $nonce) {
            $expected = $prefix.$nonce;
            self::assertContains($expected, $allKeys, sprintf('the %s namespace must own its literal key', bin2hex($prefix)));
            foreach ($allKeys as $key) {
                if ($key === $expected) {
                    continue;
                }
                self::assertFalse(
                    str_starts_with($key, $expected),
                    sprintf('a key under %s must never extend another namespace key', bin2hex($prefix)),
                );
            }
        }
    }

    public function testSameNonceUnderTwoPrefixesIsTwoIndependentRecords(): void
    {
        $storeA = new RedisStorage($this->client, 'tenant-a:');
        $storeB = new RedisStorage($this->client, 'tenant-b:');
        $nonce = $this->nonceFor(7);

        $storeA->store($this->makeRecord($nonce, 'login'));
        $storeB->store($this->makeRecord($nonce, 'register'));

        self::assertSame('login', $storeA->find($nonce)?->scope, 'store A must see its own record');
        self::assertSame('register', $storeB->find($nonce)?->scope, 'store B must see its own record');
        self::assertCount(2, $this->client->keys('*'), 'one key per namespace for the shared nonce');

        $storeA->delete($nonce);
        self::assertNull($storeA->find($nonce), 'deleting through store A removes only A key');
        self::assertSame('register', $storeB->find($nonce)?->scope, 'store B record must survive the A delete');
    }

    public function testCrossPrefixVerificationIsRecordNotFound(): void
    {
        $storeA = new RedisStorage($this->client, 'tenant-a:');
        $storeB = new RedisStorage($this->client, 'tenant-b:');

        $issuer = new Issuer(
            new Config(secretKey: Vectors::SECRET, algorithm: PoWAlgorithm::Sha256, targetBits: 1, minDurationMs: 0),
            $storeA,
        );
        $challenge = $issuer->issue('login', '198.51.100.7');
        $record = $storeA->find($challenge->nonce);
        self::assertNotNull($record);

        $saltBytes = base64_decode($challenge->salt, true);
        $counter = 0;
        do {
            $hash = hash('sha256', $challenge->prefix.$counter.$saltBytes, true);
            $counter++;
        } while (Verifier::leadingZeroBits($hash) < $challenge->targetBits);
        $token = SolutionToken::create($challenge->nonce, $counter - 1, 5000, [])->encode();

        $cross = (new Verifier($storeB))->verify(
            $token,
            Vectors::SECRET,
            'login',
            '198.51.100.7',
            nowNs: $record->issuedAtNs + 1_000_000,
        );
        self::assertSame(VerifyError::RecordNotFound, $cross->error, 'the other namespace must resolve nothing');

        $own = (new Verifier($storeA))->verify(
            $token,
            Vectors::SECRET,
            'login',
            '198.51.100.7',
            nowNs: $record->issuedAtNs + 1_000_000,
        );
        self::assertTrue($own->isOk(), 'the owning namespace must verify its own challenge');
    }
}
