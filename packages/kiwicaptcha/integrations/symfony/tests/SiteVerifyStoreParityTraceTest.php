<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests;

use BelConsulting\KiwiCaptchaBundle\SiteVerify\ArraySiteVerifyIdempotencyStore;
use BelConsulting\KiwiCaptchaBundle\SiteVerify\IdempotencyClaim;
use BelConsulting\KiwiCaptchaBundle\SiteVerify\RedisSiteVerifyIdempotencyStore;
use BelConsulting\KiwiCaptchaBundle\SiteVerify\SiteVerifyIdempotencyStore;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\RedisTestUrl;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\SiteVerifyStoreAssert;
use PHPUnit\Framework\TestCase;

/**
 * One trace, two stores. The in-memory Array store and the real-Redis
 * store must produce the same logical result for every step of the
 * idempotency lifecycle. The steps are claim, pending retry,
 * changed-identity conflict, lease expiry and takeover, owner-authorized
 * finalize, completed replay, and key expiry returning to a fresh claim.
 * The
 * Array store mirrors the production v2 record under a lifetime
 * envelope and enforces the lifetime at the start of every operation.
 * A test that observes the Array store therefore observes the
 * production state machine.
 *
 * Time is advanced per store: the Array clock moves virtually; the
 * Redis side sleeps through the 1-second lease or has its key expired
 * (the equivalent of the same wall-clock advance) so the trace stays
 * quick.
 */
final class SiteVerifyStoreParityTraceTest extends TestCase
{
    private const NAMESPACE = 'parity-ns';

    /** @return \Predis\Client|null */
    private function redisOrSkip(): ?\Predis\Client
    {
        if (!\class_exists(\Predis\Client::class)) {
            self::markTestSkipped('predis/predis is not installed');
        }
        $url = RedisTestUrl::resolve();
        if ($url === null) {
            self::markTestSkipped('KC_REDIS_URL/TEST_REDIS_URL not set — the real-Redis suites run in the CI Redis-service job');
        }
        try {
            $probe = new \Predis\Client($url, ['timeout' => 5.0, 'read_write_timeout' => 5.0]);
            $probe->ping();

            return $probe;
        } catch (\Throwable) {
            self::markTestSkipped('no Redis at '.$url);
        }
    }

    /**
     * Run the identical operation trace and return the logical result of
     * every step.
     *
     * @param callable(int):void $advanceLease advance store time past the lease
     * @param callable():void    $expireKey    advance store time past the key lifetime
     *
     * @return array<string, mixed>
     */
    private function runTrace(SiteVerifyIdempotencyStore $store, callable $advanceLease, callable $expireKey): array
    {
        $backendId = hash_hmac('sha256', 'login|0|', 'parity-trace');
        $uuid = 'c4f5a6b7-1111-4000-8000-00000000f001';
        $hash = hash('sha256', 'parity-response');
        $fingerprint = hash('sha256', 'parity-ip');
        $binding = hash('sha256', 'parity-binding');
        $result = ['success' => true, 'challenge_ts' => null, 'hostname' => null];

        $out = [];
        [$out['claim'], $owner1] = $store->claim($backendId, $uuid, $hash, 300, $fingerprint, null, $binding);
        [$out['pending_same']] = $store->claim($backendId, $uuid, $hash, 300, $fingerprint, null, $binding);
        [$out['changed_ip']] = $store->claim($backendId, $uuid, $hash, 300, hash('sha256', 'other-ip'), null, $binding);
        [$out['changed_binding']] = $store->claim($backendId, $uuid, $hash, 300, $fingerprint, null, hash('sha256', 'other-binding'));

        $advanceLease();
        [$out['takeover'], $owner2] = $store->takeover($backendId, $uuid, $hash, 300, $fingerprint, null, $binding);
        $out['owner_changed'] = \is_string($owner2) && $owner2 !== $owner1;
        $out['finalize_wrong_owner'] = $store->finalize($backendId, $uuid, $hash, (string) $owner1, $result);
        $out['finalize_owner'] = $store->finalize($backendId, $uuid, $hash, (string) $owner2, $result);
        $out['stored'] = SiteVerifyStoreAssert::completed($store->storedForOperation($backendId, $uuid, $hash, $fingerprint, $binding));
        [$out['replay']] = $store->claim($backendId, $uuid, $hash, 300, $fingerprint, null, $binding);

        $expireKey();
        [$out['fresh_after_expiry']] = $store->claim($backendId, $uuid, $hash, 300, $fingerprint, null, $binding);

        return $out;
    }

    /** Normalize enum results to their string values for comparison. */
    private function scrub(array $trace): array
    {
        return array_map(
            static fn (mixed $value): mixed => $value instanceof IdempotencyClaim ? $value->value : $value,
            $trace,
        );
    }

    public function testTheArrayAndRedisStoresShareOneLogicalStateMachine(): void
    {
        $probe = $this->redisOrSkip();
        if ($probe === null) {
            return;
        }
        $backendId = hash_hmac('sha256', 'login|0|', 'parity-trace');
        $uuid = 'c4f5a6b7-1111-4000-8000-00000000f001';
        $key = '{kiwi:'.self::NAMESPACE.'}:siteverify-idem:'.$backendId.':'.$uuid;
        $probe->del([$key]);

        // array: the clock is virtual.
        $now = 1_700_000_000;
        $clock = static function () use (&$now): int {
            return $now;
        };
        $array = new ArraySiteVerifyIdempotencyStore($clock, 1);
        $arrayTrace = $this->scrub($this->runTrace(
            $array,
            static function () use (&$now): void {
                $now += 5;
            },
            static function () use (&$now): void {
                $now += 301;
            },
        ));

        // redis: the 1-second lease is slept through; the key lifetime
        // is expired directly (the equivalent of the same advanced clock,
        // compressed so the trace stays quick).
        $redis = new RedisSiteVerifyIdempotencyStore($probe, self::NAMESPACE, 1);
        $redisTrace = $this->scrub($this->runTrace(
            $redis,
            static function (): void {
                // The lease is checked against Redis TIME in whole
                // seconds: cross the boundary plus a margin.
                usleep(2_200_000);
            },
            static function () use ($probe, $key): void {
                $probe->pexpire($key, 100);
                usleep(200_000);
            },
        ));

        $expected = [
            'claim' => 'claimed',
            'pending_same' => 'pending_same',
            'changed_ip' => 'conflict',
            'changed_binding' => 'conflict',
            'takeover' => 'took_over',
            'owner_changed' => true,
            'finalize_wrong_owner' => false,
            'finalize_owner' => true,
            'stored' => ['success' => true, 'challenge_ts' => null, 'hostname' => null],
            'replay' => 'complete_same',
            'fresh_after_expiry' => 'claimed',
        ];
        self::assertSame($expected, $arrayTrace, 'the Array store trace');
        self::assertSame($expected, $redisTrace, 'the Redis store trace');
        self::assertSame($arrayTrace, $redisTrace, 'both stores observe one logical state machine at every step');

        $probe->del([$key]);
    }
}
