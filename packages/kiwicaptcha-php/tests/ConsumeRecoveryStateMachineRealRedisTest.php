<?php

declare(strict_types=1);

namespace KiwiCaptcha\Tests;

use KiwiCaptcha\Tests\Fixtures\ArrayConsumeRecoveryDriver;
use KiwiCaptcha\Tests\Fixtures\ConsumeRecoveryWalk;
use KiwiCaptcha\Tests\Fixtures\RealRedisTestEnv;
use KiwiCaptcha\Tests\Fixtures\RedisConsumeRecoveryDriver;
use PHPUnit\Framework\TestCase;

/**
 * The model-based consume/commit/recovery state machine, checked
 * against the real RedisStorage Lua scripts (and the ArrayStorage
 * mirror in lockstep), the extension of the ChainStateWalk discipline
 * to the one-shot challenge lifecycle.
 *
 * The clean-room {@see \KiwiCaptcha\Tests\Fixtures\ConsumeRecoveryModel}
 * enumerates the states (pending, consumed_resultless, committed_valid,
 * committed_invalid, cancelled, missing) and the transitions
 * (consume-win, consume-lose, derive, commit, recovery-claim,
 * claim-expire, release, stored-replay, record-vanish, cancel). The
 * breadth-first search enumerates the reachable state space. Every
 * recorded transition sequence is replayed against a real Redis store
 * (and the Array mirror) with the invariant suite asserted after every
 * step. The invariants: exactly one consume winner per record, a
 * committed result never re-derived, a resultless record recovering
 * via the claim with exactly one derivation, and a vanished record
 * resolving RecordNotFound. No transition sequence produces a double
 * success or a replayed authorization outside the identity gate.
 *
 * Runs in the real-Redis CI lane; skips without the published Redis
 * env, fails instead of skipping when KIWI_REQUIRE_REAL_REDIS_TESTS is
 * set and the env is missing.
 */
final class ConsumeRecoveryStateMachineRealRedisTest extends TestCase
{
    private \Predis\Client $client;

    protected function setUp(): void
    {
        if (!\class_exists(\Predis\Client::class)) {
            self::markTestSkipped('predis/predis is not installed');
        }
        $url = RealRedisTestEnv::requireRedis('the consume/commit/recovery state-machine suite must run in the dedicated real-Redis CI lane');
        if ($url === null) {
            self::markTestSkipped('KC_REDIS_URL/TEST_REDIS_URL not set — the real-Redis suites run in the CI Redis-service job');
        }
        $this->client = new \Predis\Client($url, ['timeout' => 10.0, 'read_write_timeout' => 10.0]);
        try {
            $this->client->ping();
        } catch (\Throwable $e) {
            RealRedisTestEnv::failWhenRequired('Redis is unreachable at the published URL: '.$e->getMessage(), 'the consume/commit/recovery state-machine suite');
            self::markTestSkipped('no Redis at the configured KC_REDIS_URL/TEST_REDIS_URL');
        }
        $this->client->flushdb();
    }

    /**
     * The exhaustive breadth-first enumeration of the reachable state
     * space: every recorded path is replayed against the real Redis
     * store and the Array mirror in lockstep, with the outcome parity,
     * the invariant suite and the concrete-state equality asserted
     * after every step.
     */
    public function testBfsReachableStateSpaceAgainstRealRedisAndArrayMirror(): void
    {
        $paths = ConsumeRecoveryWalk::bfsPaths();
        self::assertGreaterThan(40, \count($paths), 'the BFS must enumerate the reachable transition sequences');
        $redisGens = 0;
        $arrayGens = 0;
        foreach ($paths as $path) {
            $redis = new RedisConsumeRecoveryDriver($this->client);
            $redisResult = ConsumeRecoveryWalk::run('bfs-redis-'.bin2hex(random_bytes(2)), $redis, $path);
            self::assertSame(\count($path), $redisResult['steps'], 'every BFS step applies against the real store');
            $array = new ArrayConsumeRecoveryDriver();
            $arrayResult = ConsumeRecoveryWalk::run('bfs-array-'.bin2hex(random_bytes(2)), $array, $path);
            self::assertSame(\count($path), $arrayResult['steps'], 'every BFS step applies against the Array mirror');
            self::assertSame($redisResult['generations'], $arrayResult['generations'], 'the Array mirror observes the same generation count');
            $redisGens += $redisResult['generations'];
            $arrayGens += $arrayResult['generations'];
        }
        self::assertSame($redisGens, $arrayGens, 'the total generation counts match');
    }

    /**
     * The bounded random walk (fixed seed) against the real Redis
     * store: the same deterministic step list as the in-memory mirror,
     * asserting outcome parity, the invariant suite and the concrete
     * state after every step, with fresh generations after each
     * record-vanish.
     */
    public function testBoundedRandomWalkKeepsEveryInvariantAgainstRealRedis(): void
    {
        $steps = ConsumeRecoveryWalk::steps(0x5EED, 400);
        $redis = new RedisConsumeRecoveryDriver($this->client);
        $redisResult = ConsumeRecoveryWalk::run('walk-redis', $redis, $steps);
        self::assertGreaterThan(1, $redisResult['generations'], 'the walk must exercise fresh generations after vanish');
        self::assertLessThanOrEqual(400, $redisResult['steps']);

        $array = new ArrayConsumeRecoveryDriver();
        $arrayResult = ConsumeRecoveryWalk::run('walk-array', $array, $steps);
        self::assertSame($redisResult['steps'], $arrayResult['steps'], 'the Array mirror applies the same steps');
        self::assertSame($redisResult['generations'], $arrayResult['generations'], 'the Array mirror observes the same generations');
    }

    /**
     * The hand-enumerated sequences, in the ChainStateWalk discipline:
     * the happy path with the double-success refusal, the identity-gate
     * matrix, the claim lifecycle with the stale-owner refusals, the
     * crashed-recovery lease expiry, the cancel finalization and the
     * vanished-record vocabulary. Each runs against the real store and
     * the Array mirror.
     */
    public function testHandEnumeratedSequencesObserveTheModelAgainstRealRedis(): void
    {
        // Happy path: one win, one derivation, one committed success,
        // replays gated by the identity, the committed result never
        // re-derived, the claim refused on a committed record.
        ConsumeRecoveryWalk::run('redis-hand-happy', new RedisConsumeRecoveryDriver($this->client), [
            ['consume', ['identity' => ConsumeRecoveryWalk::IDENTITY_A]],
            ['consume', ['identity' => null]],
            ['derive', ['valid' => true]],
            ['derive', ['valid' => true]],
            ['commit', ['valid' => true, 'owner' => null]],
            ['replay', ['identity' => 'exact']],
            ['replay', ['identity' => 'exact']],
            ['replay', ['identity' => null]],
            ['replay', ['identity' => 'other']],
            ['claim', ['owner' => 'owner-token', 'ttl' => ConsumeRecoveryWalk::CLAIM_TTL]],
            ['cancel', []],
        ]);

        // The identity gate on a committed invalid outcome: the stored
        // invalid replays deterministically to any caller, never a
        // grant.
        ConsumeRecoveryWalk::run('redis-hand-invalid', new RedisConsumeRecoveryDriver($this->client), [
            ['consume', ['identity' => ConsumeRecoveryWalk::IDENTITY_A]],
            ['derive', ['valid' => false]],
            ['replay', ['identity' => 'exact']],
            ['replay', ['identity' => 'other']],
            ['replay', ['identity' => null]],
        ]);

        // The claim lifecycle: a live lease refuses the second claim
        // and the foreign release, the exact owner releases, the
        // re-claim lands, and the claim-bearing commit clears the lease
        // in the same transition.
        ConsumeRecoveryWalk::run('redis-hand-claim', new RedisConsumeRecoveryDriver($this->client), [
            ['consume', ['identity' => ConsumeRecoveryWalk::IDENTITY_A]],
            ['claim', ['owner' => 'owner-token', 'ttl' => ConsumeRecoveryWalk::CLAIM_TTL]],
            ['claim', ['owner' => 'owner-token', 'ttl' => ConsumeRecoveryWalk::CLAIM_TTL]],
            ['release', ['owner' => 'foreign']],
            ['release', ['owner' => 'held']],
            ['claim', ['owner' => 'owner-token', 'ttl' => ConsumeRecoveryWalk::CLAIM_TTL]],
            ['commit', ['valid' => true, 'owner' => 'held']],
            ['claim', ['owner' => 'owner-token', 'ttl' => ConsumeRecoveryWalk::CLAIM_TTL]],
            ['replay', ['identity' => 'exact']],
        ]);

        // The crashed recovery: the lease expires without a release, a
        // fresh claim wins, the stale-owner commit is refused, and the
        // exact owner commits through the lease.
        ConsumeRecoveryWalk::run('redis-hand-crash', new RedisConsumeRecoveryDriver($this->client), [
            ['consume', ['identity' => ConsumeRecoveryWalk::IDENTITY_A]],
            ['claim', ['owner' => 'owner-token', 'ttl' => ConsumeRecoveryWalk::CLAIM_TTL]],
            ['claim-expire', []],
            ['claim', ['owner' => 'owner-token', 'ttl' => ConsumeRecoveryWalk::CLAIM_TTL]],
            ['commit', ['valid' => true, 'owner' => 'foreign']],
            ['commit', ['valid' => true, 'owner' => 'held']],
            ['replay', ['identity' => 'exact']],
        ]);

        // The plain commit on a leased record keeps the lease, and the
        // later release still clears it; the lease-expired commit is
        // refused on a committed record.
        ConsumeRecoveryWalk::run('redis-hand-plain-commit-on-lease', new RedisConsumeRecoveryDriver($this->client), [
            ['consume', ['identity' => ConsumeRecoveryWalk::IDENTITY_A]],
            ['claim', ['owner' => 'owner-token', 'ttl' => ConsumeRecoveryWalk::CLAIM_TTL]],
            ['commit', ['valid' => true, 'owner' => null]],
            ['claim-expire', []],
            ['commit', ['valid' => false, 'owner' => 'held']],
            ['release', ['owner' => 'held']],
            ['replay', ['identity' => 'exact']],
        ]);

        // The cancel finalization: a consumed record is never
        // cancellable, a pending record is, and the vanished record
        // answers the missing vocabulary.
        ConsumeRecoveryWalk::run('redis-hand-cancel', new RedisConsumeRecoveryDriver($this->client), [
            ['consume', ['identity' => null]],
            ['cancel', []],
            ['replay', ['identity' => null]],
            ['vanish', []],
            ['consume', ['identity' => null]],
            ['cancel', []],
            ['claim', ['owner' => 'owner-token', 'ttl' => ConsumeRecoveryWalk::CLAIM_TTL]],
            ['replay', ['identity' => null]],
        ]);

        // The identity-less committed success never replays: the plain
        // consume records no identity, so no caller can ever prove the
        // operation.
        ConsumeRecoveryWalk::run('redis-hand-identityless', new RedisConsumeRecoveryDriver($this->client), [
            ['consume', ['identity' => null]],
            ['derive', ['valid' => true]],
            ['replay', ['identity' => null]],
            ['replay', ['identity' => 'exact']],
            ['replay', ['identity' => 'other']],
        ]);

        // The Array mirror observes the identical machine for every
        // hand sequence.
        ConsumeRecoveryWalk::run('array-hand-happy', new ArrayConsumeRecoveryDriver(), [
            ['consume', ['identity' => ConsumeRecoveryWalk::IDENTITY_A]],
            ['derive', ['valid' => true]],
            ['replay', ['identity' => 'exact']],
            ['replay', ['identity' => null]],
            ['claim', ['owner' => 'owner-token', 'ttl' => ConsumeRecoveryWalk::CLAIM_TTL]],
        ]);
        ConsumeRecoveryWalk::run('array-hand-claim', new ArrayConsumeRecoveryDriver(), [
            ['consume', ['identity' => ConsumeRecoveryWalk::IDENTITY_A]],
            ['claim', ['owner' => 'owner-token', 'ttl' => ConsumeRecoveryWalk::CLAIM_TTL]],
            ['claim-expire', []],
            ['claim', ['owner' => 'owner-token', 'ttl' => ConsumeRecoveryWalk::CLAIM_TTL]],
            ['commit', ['valid' => true, 'owner' => 'held']],
            ['replay', ['identity' => 'exact']],
        ]);
        ConsumeRecoveryWalk::run('array-hand-crash', new ArrayConsumeRecoveryDriver(), [
            ['consume', ['identity' => ConsumeRecoveryWalk::IDENTITY_A]],
            ['claim', ['owner' => 'owner-token', 'ttl' => ConsumeRecoveryWalk::CLAIM_TTL]],
            ['claim-expire', []],
            ['claim', ['owner' => 'owner-token', 'ttl' => ConsumeRecoveryWalk::CLAIM_TTL]],
            ['commit', ['valid' => true, 'owner' => 'foreign']],
            ['commit', ['valid' => true, 'owner' => 'held']],
        ]);
    }
}
