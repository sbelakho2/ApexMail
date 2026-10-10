<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests;

use BelConsulting\KiwiCaptchaBundle\RedisNamespace;
use BelConsulting\KiwiCaptchaBundle\Security\IssuanceRateLimiter;
use BelConsulting\KiwiCaptchaBundle\Security\RedisAdmissionSemaphore;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\FakePredisClient;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Cache\Adapter\ArrayAdapter;

/**
 * Cross-component deployment-namespace isolation: the raw configured
 * namespace is an identity discriminator, and the digest key version
 * derives every key family's Redis-safe segment from the complete
 * original bytes. Both collision classes a replacement-sanitized
 * derivation cannot distinguish must keep independent budgets and
 * disjoint key families in the rate limiter (the PSR-6 and the Redis
 * path alike) and the Argon admission semaphore. The classes:
 * namespaces differing only in a separator versus an underscore
 * (tenant/a versus tenant:a), and project directories differing only
 * in where the separator sits (/a/b_c versus /a_b/c, the shape the
 * kernel.project_dir default produces). The legacy key version keeps
 * the historical sanitized shape and is asserted to fold, the
 * documented default for an existing deployment.
 */
final class NamespaceIsolationTest extends TestCase
{
    /** @return list<array{0: string, 1: string}> */
    public static function provideCollidingPairs(): array
    {
        return [
            ['tenant/a', 'tenant:a'],
            ['/a/b_c', '/a_b/c'],
        ];
    }

    /**
     * @dataProvider provideCollidingPairs
     */
    public function testTheDigestDerivationDistinguishesEveryCollidingPair(string $a, string $b): void
    {
        self::assertNotSame(
            RedisNamespace::derive($a, RedisNamespace::VERSION_DIGEST),
            RedisNamespace::derive($b, RedisNamespace::VERSION_DIGEST),
        );
    }

    /**
     * @dataProvider provideCollidingPairs
     */
    public function testTheLegacyDerivationKeepsTheHistoricalSanitizedShape(string $a, string $b): void
    {
        // The legacy key version is the pre-digest sanitized shape: it
        // is the default so an existing deployment keeps its key space,
        // and the colliding pair folds by design (the documented reason
        // a new deployment chooses the digest version).
        self::assertSame(RedisNamespace::derive($a), RedisNamespace::derive($b));
        self::assertSame(
            preg_replace('/[^A-Za-z0-9_.-]/', '_', $a),
            RedisNamespace::derive($a),
        );
    }

    public function testTheDefaultKeyVersionIsTheLegacyShape(): void
    {
        self::assertSame(RedisNamespace::VERSION_LEGACY, RedisNamespace::DEFAULT_VERSION);
        self::assertSame(RedisNamespace::derive('prod'), RedisNamespace::derive('prod', RedisNamespace::VERSION_LEGACY));
        self::assertNotSame(RedisNamespace::derive('prod'), RedisNamespace::derive('prod', RedisNamespace::VERSION_DIGEST));
    }

    public function testTheReadNamespacesConsultTheLegacySegmentOnlyOnTheDigestVersion(): void
    {
        self::assertSame(
            [RedisNamespace::derive('prod', RedisNamespace::VERSION_LEGACY)],
            RedisNamespace::readNamespaces('prod', 'kiwi', RedisNamespace::VERSION_LEGACY),
        );
        self::assertSame(
            [
                RedisNamespace::derive('prod', RedisNamespace::VERSION_DIGEST),
                RedisNamespace::derive('prod', RedisNamespace::VERSION_LEGACY),
            ],
            RedisNamespace::readNamespaces('prod', 'kiwi', RedisNamespace::VERSION_DIGEST),
        );
    }

    public function testTheDerivationRefusesTheEmptyNamespace(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        RedisNamespace::derive('');
    }

    public function testTheDerivationFallbackIsExplicit(): void
    {
        self::assertSame(RedisNamespace::derive('fallback'), RedisNamespace::deriveOr('', 'fallback'));
        self::assertSame(RedisNamespace::derive('raw'), RedisNamespace::deriveOr('raw', 'fallback'));
    }

    /**
     * @dataProvider provideCollidingPairs
     */
    public function testThePsr6RateLimiterKeepsIndependentBudgets(string $a, string $b): void
    {
        $pool = new ArrayAdapter();
        $clock = 10_000.0;
        $now = static function () use (&$clock): float {
            return $clock;
        };
        $la = new IssuanceRateLimiter(100, 60, $pool, $now, 'pepper', null, 2, $a, 0, RedisNamespace::VERSION_DIGEST);
        $lb = new IssuanceRateLimiter(100, 60, $pool, $now, 'pepper', null, 2, $b, 0, RedisNamespace::VERSION_DIGEST);

        self::assertSame(1, $la->check('198.51.100.1'));
        self::assertSame(1, $la->check('198.51.100.2'));
        self::assertSame(-1, $la->check('198.51.100.3'), 'the first namespace hits its own global cap');
        self::assertSame(1, $lb->check('198.51.100.1'), 'the colliding-before-derivation namespace keeps its own budget');
        self::assertSame(1, $lb->check('198.51.100.2'));
        self::assertSame(-1, $lb->check('198.51.100.3'), 'the second namespace now hits its own cap');
        self::assertSame(-1, $la->check('198.51.100.4'), 'the first namespace stays saturated: the state never merged');
    }

    /**
     * @dataProvider provideCollidingPairs
     */
    public function testTheSemaphoreKeyFamiliesAreDisjoint(string $a, string $b): void
    {
        $keysA = $this->acquiredKeys($a);
        $keysB = $this->acquiredKeys($b);
        self::assertNotSame([], $keysA);
        foreach ($keysB as $key) {
            self::assertNotContains($key, $keysA, 'no lease-family key of one namespace appears in the colliding namespace family');
        }
    }

    /**
     * @return list<string> every script key one scoped acquire touches
     */
    private function acquiredKeys(string $namespace): array
    {
        $client = new FakePredisClient();
        $semaphore = new RedisAdmissionSemaphore($client, 4, $namespace, namespaceKeyVersion: RedisNamespace::VERSION_DIGEST);
        $lease = $semaphore->acquire('login');
        self::assertNotNull($lease);
        $keys = [];
        foreach ($client->calls as [$cmd, $arguments]) {
            if ($cmd !== 'EVAL' && $cmd !== 'EVALSHA') {
                continue;
            }
            $numKeys = (int) $arguments[1];
            foreach (\array_slice($arguments, 2, $numKeys) as $key) {
                $keys[] = (string) $key;
            }
        }

        return array_values(array_unique($keys));
    }
}
