<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests;

use BelConsulting\KiwiCaptchaBundle\Security\IssuanceRateLimiter;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\RedisTestUrl;
use KiwiCaptcha\Issuer;
use PHPUnit\Framework\TestCase;

/**
 * Rate-limit identity-compartment fuzzing on one real Redis: the
 * per-client window identity is a peppered HMAC over the canonical IP.
 * Distinct clients never share a bucket, distinct deployment
 * namespaces never share a key space, and distinct peppers never
 * resolve to one identity. The fuzz corpus mixes IPv4, IPv6,
 * IPv4-mapped IPv6 spellings and invalid inputs.
 *
 * Properties under test: filling one client's window leaves another
 * client's window untouched, a full window in one namespace leaves the
 * same IP free in another namespace, a different pepper yields an
 * independent identity, and the deployment-global budget stays
 * namespace-scoped. Deterministic seeds, bounded iterations, the
 * database flushed before each run.
 *
 * Runs when `KC_REDIS_URL` or `TEST_REDIS_URL` is set; the
 * `KIWI_REQUIRE_REAL_REDIS_TESTS` flag turns a missing environment
 * into a hard failure in the dedicated real-Redis lane.
 */
final class TenantIsolationRateLimitFuzzTest extends TestCase
{
    private const SEED = 0x51DE;

    private \Predis\Client $client;

    protected function setUp(): void
    {
        $url = RedisTestUrl::resolve();
        if ($url === null) {
            $this->failIfRealRedisRequired('no Redis test URL (KC_REDIS_URL / TEST_REDIS_URL) is set');
            self::markTestSkipped('no Redis test URL (KC_REDIS_URL / TEST_REDIS_URL) — real-Redis rate-limit isolation fuzz skipped');
        }
        if (!\class_exists(\Predis\Client::class)) {
            $this->failIfRealRedisRequired('predis/predis is not installed');
            self::markTestSkipped('predis/predis not installed');
        }
        try {
            $probe = new \Predis\Client($url, ['timeout' => 5.0, 'read_write_timeout' => 5.0]);
            $probe->ping();
        } catch (\Throwable $e) {
            $this->failIfRealRedisRequired('Redis is unreachable at the configured URL');
            self::markTestSkipped('Redis unreachable: '.$e->getMessage());
        }
        $probe->flushdb();
        $this->client = $probe;
    }

    private function failIfRealRedisRequired(string $why): void
    {
        $flag = getenv('KIWI_REQUIRE_REAL_REDIS_TESTS');
        if (\is_string($flag) && $flag !== '' && $flag !== '0') {
            self::fail('KIWI_REQUIRE_REAL_REDIS_TESTS is set but '.$why.' — the rate-limit isolation fuzz must run in the real-Redis CI lane');
        }
    }

    /**
     * The bounded identity-input corpus: canonical IPs across both
     * families plus the IPv4-mapped IPv6 spelling of the same address.
     *
     * @return list<string>
     */
    private function ipCorpus(): array
    {
        return [
            '198.51.100.7',
            '198.51.100.8',
            '198.51.100.9',
            '203.0.113.1',
            '203.0.113.255',
            '10.0.0.1',
            '::1',
            '::2',
            '2001:db8::1',
            '2001:db8::2',
            '2001:db8:0:0:0:0:0:3',
            '::ffff:198.51.100.7',
            '2001:0db8:0:0:0:0:0:1',
            '2400:cb00::1',
            '2400:cb00::2',
        ];
    }

    private function limiter(string $namespace, string $pepper, int $maxPerClient = 1, int $globalMax = 0): IssuanceRateLimiter
    {
        return new IssuanceRateLimiter(
            $maxPerClient,
            60,
            redis: $this->client,
            pepper: $pepper,
            namespace: $namespace,
            globalMax: $globalMax,
        );
    }

    public function testFilledWindowOfOneClientNeverLeaksToAnother(): void
    {
        $ips = $this->ipCorpus();
        mt_srand(self::SEED);
        $pairs = 0;

        foreach ($ips as $i => $ipA) {
            foreach ($ips as $j => $ipB) {
                if ($i === $j) {
                    continue;
                }
                // Two textual spellings of one canonical address (the
                // IPv4-mapped form and the zero-padded hex form) are the
                // same client identity; only distinct canonical bytes
                // can prove bucket independence.
                try {
                    $canonicalA = Issuer::canonicalIpFamily($ipA);
                    $canonicalB = Issuer::canonicalIpFamily($ipB);
                } catch (\InvalidArgumentException) {
                    continue;
                }
                if ($canonicalA === $canonicalB) {
                    continue;
                }
                $pairs++;
                $namespace = 'iso-rl-'.$pairs;
                $limiter = $this->limiter($namespace, 'pepper');

                self::assertTrue($limiter->allow($ipA), 'the first client must be admitted');
                self::assertTrue($limiter->allow($ipB), 'a distinct client must never share the first window');
                self::assertFalse($limiter->allow($ipA), 'the first window must now be full');
                self::assertFalse($limiter->allow($ipB), 'the second window must now be full');

                $clientKeys = $this->client->keys('{kiwi:rl:'.$namespace.'}:client:*');
                self::assertCount(2, $clientKeys, 'each client must own exactly one pseudonym key');
                self::assertNotSame(
                    $clientKeys[0],
                    $clientKeys[1],
                    'the two client identities must be distinct literal keys',
                );
            }
        }

        self::assertGreaterThanOrEqual(200, $pairs, 'the identity pair matrix must stay bounded but broad');
    }

    public function testFullWindowInOneNamespaceLeavesSameIpFreeInAnother(): void
    {
        mt_srand(self::SEED + 1);
        foreach (['198.51.100.7', '::1', '2001:db8::1', '::ffff:198.51.100.7'] as $ip) {
            $this->client->flushdb();
            $a = $this->limiter('iso-rl-ns-a', 'pepper');
            self::assertTrue($a->allow($ip), 'the namespace A window must admit the client');
            self::assertFalse($a->allow($ip), 'the namespace A window must now be full');

            $b = $this->limiter('iso-rl-ns-b', 'pepper');
            self::assertTrue($b->allow($ip), 'namespace B must have an independent window for the same IP');
            self::assertFalse($b->allow($ip), 'namespace B window must now be full');

            $keysA = $this->client->keys('{kiwi:rl:iso-rl-ns-a}:client:*');
            $keysB = $this->client->keys('{kiwi:rl:iso-rl-ns-b}:client:*');
            self::assertCount(1, $keysA, 'namespace A owns its client key');
            self::assertCount(1, $keysB, 'namespace B owns its client key');
            self::assertSame([], array_intersect($keysA, $keysB), 'the namespace key sets must be disjoint');
        }
    }

    public function testDifferentPeppersResolveDistinctIdentities(): void
    {
        mt_srand(self::SEED + 2);
        foreach (['198.51.100.7', '2001:db8::1'] as $ip) {
            $withPepperA = $this->limiter('iso-rl-shared-ns', 'pepper-a');
            self::assertTrue($withPepperA->allow($ip), 'the first deployment must admit the client');
            self::assertFalse($withPepperA->allow($ip), 'the first deployment window must now be full');

            $withPepperB = $this->limiter('iso-rl-shared-ns', 'pepper-b');
            self::assertTrue($withPepperB->allow($ip), 'a different pepper must resolve a fresh identity for the same IP');
            self::assertFalse($withPepperB->allow($ip), 'the second deployment window must now be full');
        }
    }

    public function testGlobalBudgetIsNamespaceScoped(): void
    {
        $a = $this->limiter('iso-rl-global-a', 'pepper', maxPerClient: 0, globalMax: 1);
        self::assertTrue($a->allow('198.51.100.7'), 'the namespace A global window must admit the first client');
        self::assertSame(-1, $a->check('203.0.113.5'), 'the namespace A global budget must now be full');

        $b = $this->limiter('iso-rl-global-b', 'pepper', maxPerClient: 0, globalMax: 1);
        self::assertTrue($b->allow('198.51.100.7'), 'namespace B must have its own global budget');

        $globalKeysA = $this->client->keys('{kiwi:rl:iso-rl-global-a}:global');
        $globalKeysB = $this->client->keys('{kiwi:rl:iso-rl-global-b}:global');
        self::assertCount(1, $globalKeysA, 'namespace A owns its global key');
        self::assertCount(1, $globalKeysB, 'namespace B owns its global key');
        self::assertSame([], array_intersect($globalKeysA, $globalKeysB), 'the global keys must be disjoint');
    }

    public function testUnidentifiableClientsStayInsideTheirNamespace(): void
    {
        mt_srand(self::SEED + 3);
        $invalid = ['', 'not-an-ip', '999.1.1.1', ':::', 'localhost', '256.256.256.256'];

        foreach ($invalid as $index => $input) {
            // Every unidentifiable client shares the one unknown bucket
            // of a namespace by design, so each input needs its own
            // namespace to observe the first admission.
            $a = $this->limiter('iso-rl-unknown-a-'.$index, 'pepper');
            self::assertTrue($a->allow($input), 'the unknown-client bucket must admit the first attempt');
            self::assertFalse($a->allow($input), 'the unknown-client bucket must now be full');

            $b = $this->limiter('iso-rl-unknown-b-'.$index, 'pepper');
            self::assertTrue($b->allow($input), 'a different namespace must have its own unknown-client bucket');

            $keysA = $this->client->keys('{kiwi:rl:iso-rl-unknown-a-'.$index.'}:client:*');
            $keysB = $this->client->keys('{kiwi:rl:iso-rl-unknown-b-'.$index.'}:client:*');
            self::assertSame([], array_intersect($keysA, $keysB), 'the unknown-client keys must stay namespace-local');
        }
    }
}
