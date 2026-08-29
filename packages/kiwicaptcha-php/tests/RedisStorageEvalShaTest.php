<?php

declare(strict_types=1);

namespace KiwiCaptcha\Tests;

use KiwiCaptcha\ChallengeRecord;
use KiwiCaptcha\PoWAlgorithm;
use KiwiCaptcha\Storage\RedisStorage;
use KiwiCaptcha\Tests\Fixtures\FakePredisClient;
use PHPUnit\Framework\TestCase;

/**
 * The `EVALSHA` transport of RedisStorage's Lua scripts: every transition
 * script runs through `EVALSHA` with a per-script sha established once by
 * `SCRIPT` `LOAD` (mirroring RedisRiskStateStore's cached-sha pattern), so
 * the ~2KB script body is never shipped on the steady-state path. The
 * second invocation of every script must reuse the cached sha and send
 * no script body, and a server-side script-cache loss (`NOSCRIPT`) is
 * repaired by one reload plus an `EVALSHA` retry — never by falling back
 * to shipping the body.
 */
final class RedisStorageEvalShaTest extends TestCase
{
    private const NONCE = 'evalsha-nonce-1';

    private function requirePredis(): FakePredisClient
    {
        if (!\class_exists(\Predis\Client::class)) {
            self::markTestSkipped('predis/predis is not installed; cannot test RedisStorage');
        }

        return new FakePredisClient();
    }

    private function makeRecord(string $nonce = self::NONCE): ChallengeRecord
    {
        return new ChallengeRecord(
            nonce: $nonce,
            scope: 'login',
            bindingTag: 'abc123',
            issuedAt: 1_800_000_000,
            expiresAt: 1_800_000_120,
            algorithm: PoWAlgorithm::Sha256,
            mKib: 0,
            t: 1,
            p: 1,
            targetBits: 8,
            salt: 'c2FsdA==',
            prefix: 'prefix',
            challenge: 'challenge',
            minDurationMs: 0,
            issuedAtNs: 123_456_789,
        );
    }

    /**
     * @return iterable<string, array{0: \Closure(RedisStorage, string): mixed, 1: \Closure(RedisStorage, string): mixed}>
     *         op (the script invocation under test, safe to run twice)
     *         and setup (the state the op needs), both over the same nonce
     */
    public static function provideScriptEntryPoints(): iterable
    {
        yield 'consume' => [
            static fn (RedisStorage $s, string $n): mixed => $s->consume($n),
            static fn (RedisStorage $s, string $n): mixed => null,
        ];
        yield 'consumeWithOperationIdentity' => [
            static fn (RedisStorage $s, string $n): mixed => $s->consumeWithOperationIdentity($n, 'order-42'),
            static fn (RedisStorage $s, string $n): mixed => null,
        ];
        yield 'deleteIfPending' => [
            static fn (RedisStorage $s, string $n): mixed => $s->deleteIfPending($n),
            static fn (RedisStorage $s, string $n): mixed => null,
        ];
        yield 'cancel' => [
            static fn (RedisStorage $s, string $n): mixed => $s->cancel($n),
            static fn (RedisStorage $s, string $n): mixed => null,
        ];
        yield 'commitResult' => [
            static fn (RedisStorage $s, string $n): mixed => $s->commitResult($n, true, null),
            static fn (RedisStorage $s, string $n): mixed => null,
        ];
        yield 'claimResumeDerivation' => [
            static fn (RedisStorage $s, string $n): mixed => $s->claimResumeDerivation($n),
            static fn (RedisStorage $s, string $n): mixed => $s->consume($n),
        ];
        yield 'releaseResumeDerivation' => [
            /** @phpstan-ignore-next-line closure uses the claim owner from setup via a static cache */
            static fn (RedisStorage $s, string $n): mixed => $s->releaseResumeDerivation($n, self::releaseOwner()),
            static fn (RedisStorage $s, string $n): mixed => self::releaseOwner(self::claimAfterConsume($s, $n)),
        ];
        yield 'commitResultResume' => [
            /** @phpstan-ignore-next-line closure uses the claim owner from setup via a static cache */
            static fn (RedisStorage $s, string $n): mixed => $s->commitResultResume($n, true, null, self::releaseOwner()),
            static fn (RedisStorage $s, string $n): mixed => self::releaseOwner(self::claimAfterConsume($s, $n)),
        ];
    }

    /** Consume the pending record, then claim the resume derivation (returns the owner token). */
    private static function claimAfterConsume(RedisStorage $storage, string $nonce): string
    {
        $storage->consume($nonce);
        $owner = $storage->claimResumeDerivation($nonce);
        \assert($owner !== null, 'a freshly consumed resultless record must be claimable');

        return $owner;
    }

    /** Static hand-off between a provider's setup and op closures (single test flow). */
    private static string $owner = '';

    private static function releaseOwner(?string $owner = null): string
    {
        if ($owner !== null) {
            self::$owner = $owner;
        }

        return self::$owner;
    }

    private function resetCounters(FakePredisClient $client): void
    {
        $client->calls = [];
        $client->evals = [];
        $client->evalshas = [];
        $client->scriptLoads = [];
    }

    /** @param list<array{0: string, 1: list<mixed>}> $calls */
    private function commands(FakePredisClient $client, string $id): array
    {
        return array_values(array_filter($client->calls, fn ($c) => $c[0] === $id));
    }

    /**
     * @dataProvider provideScriptEntryPoints
     */
    public function testSecondInvocationUsesEvalShaWithTheCachedShaAndNoBody(\Closure $op, \Closure $setup): void
    {
        $client = $this->requirePredis();
        $storage = new RedisStorage($client);
        $storage->store($this->makeRecord());
        $setup($storage, self::NONCE);
        $this->resetCounters($client);

        // First invocation: the sha is established with exactly one
        // `SCRIPT` `LOAD`, then the script runs through `EVALSHA`.
        $op($storage, self::NONCE);
        $loads = $client->scriptLoads;
        self::assertCount(1, $loads, 'the first invocation SCRIPT LOADs the script exactly once');
        $sha = sha1($loads[0]);
        self::assertCount(1, $client->evalshas, 'the first invocation runs the script through EVALSHA');
        self::assertSame($sha, $client->evalshas[0], 'the EVALSHA references the loaded script\'s sha');
        self::assertSame([], $this->commands($client, 'EVAL'), 'the script body is never shipped through plain EVAL');

        $this->resetCounters($client);

        // Second invocation: the cached sha serves — no `SCRIPT` `LOAD`, no
        // body, the same sha through `EVALSHA`.
        $op($storage, self::NONCE);
        self::assertSame([], $client->scriptLoads, 'the cached sha must serve; no SCRIPT LOAD on the second invocation');
        self::assertCount(1, $client->evalshas, 'the second invocation runs the script through EVALSHA');
        self::assertSame($sha, $client->evalshas[0], 'the second invocation uses the SAME cached sha');
        self::assertSame([], $this->commands($client, 'EVAL'), 'the script body is never shipped through plain EVAL');
        self::assertCount(1, $client->evals, 'exactly one Lua invocation ran');

        // No `EVALSHA` argument is the script body: the first argument is
        // the 40-hex sha and nothing carries the Lua source.
        foreach ($this->commands($client, 'EVALSHA') as $call) {
            self::assertSame(1, preg_match('/^[0-9a-f]{40}$/', (string) $call[1][0]), 'EVALSHA sends the sha, not a body');
            foreach ($call[1] as $argument) {
                self::assertStringNotContainsString('-- kiwicaptcha', (string) $argument, 'no EVALSHA argument may carry Lua source');
            }
        }
    }

    public function testNoScriptIsRepairedByOneReloadAndAnEvalShaRetry(): void
    {
        // A server-side script-cache loss (`SCRIPT` `FLUSH` or a restart):
        // the cached sha no longer resolves, the server answers
        // `NOSCRIPT`, and the storage reloads once and retries through
        // `EVALSHA` — the body is still never shipped through plain EVAL.
        $client = $this->requirePredis();
        $storage = new RedisStorage($client);
        $storage->store($this->makeRecord());
        $storage->consume(self::NONCE);
        $sha = $client->evalshas[0];
        $client->scriptsBySha = [];
        $this->resetCounters($client);

        $retry = $storage->consume(self::NONCE);

        self::assertNotNull($retry);
        self::assertTrue($retry->consumedBefore, 'the replay of the consumed record resolves normally past the NOSCRIPT repair');
        self::assertCount(1, $client->scriptLoads, 'the NOSCRIPT fallback reloads the script exactly once');
        self::assertCount(1, $client->evalshas, 'the retry runs through EVALSHA');
        self::assertSame($sha, $client->evalshas[0], 'the reload yields the same deterministic sha');
        self::assertSame([], $this->commands($client, 'EVAL'), 'the NOSCRIPT repair never ships the body through plain EVAL');
    }

    public function testStoreNeverRunsAnyLua(): void
    {
        // Only the transitions use Lua: an issuance is a single fused
        // SET (the TTL rides the command), so no script is loaded or
        // run at all.
        $client = $this->requirePredis();
        $storage = new RedisStorage($client);

        $storage->store($this->makeRecord());

        self::assertSame([], $client->evals);
        self::assertSame([], $client->evalshas);
        self::assertSame([], $client->scriptLoads);
    }
}
