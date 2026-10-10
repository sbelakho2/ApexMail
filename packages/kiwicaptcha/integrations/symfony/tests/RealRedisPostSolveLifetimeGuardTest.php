<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests;

use BelConsulting\KiwiCaptchaBundle\Risk\MalformedPostSolveDispositionException;
use BelConsulting\KiwiCaptchaBundle\Risk\PostSolveDisposition;
use BelConsulting\KiwiCaptchaBundle\Risk\PostSolveDispositionKind;
use BelConsulting\KiwiCaptchaBundle\Risk\PostSolveFinalizeOutcome;
use BelConsulting\KiwiCaptchaBundle\Risk\RedisChainedChallengeStateStore;
use BelConsulting\KiwiCaptchaBundle\Risk\RedisPostSolveDispositionStore;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\RedisTestUrl;
use PHPUnit\Framework\TestCase;

/**
 * The present-key lifetime boundary of the post-solve disposition
 * machine, against real Redis. The disposition record and every chain
 * the obligation guard consults must carry a Redis key lifetime. A
 * lifetime-stripped key is corrupt state and may never be
 * takeover-able, finalizable, replayable or trusted by the acceptance
 * guard. A signed-expired chain that Redis still holds is stale state
 * and must be refused the same way. Every refusal performs zero
 * authorization-bearing mutation.
 *
 * The guard's chain read runs through the same live-chain authority the
 * chain store's own live-read uses
 * ({@see \BelConsulting\KiwiCaptchaBundle\Risk\ChainV2LuaPredicate}),
 * so the two surfaces cannot drift into two definitions of a live
 * chain.
 */
final class RealRedisPostSolveLifetimeGuardTest extends TestCase
{
    private \Predis\Client $client;

    protected function setUp(): void
    {
        if (!\class_exists(\Predis\Client::class)) {
            self::markTestSkipped('predis/predis is not installed');
        }
        $url = RedisTestUrl::resolve();
        if ($url === null) {
            self::markTestSkipped('KC_REDIS_URL/TEST_REDIS_URL not set — the real-Redis suites run in the CI Redis-service job');
        }
        $this->client = new \Predis\Client($url);
        try {
            $this->client->ping();
        } catch (\Throwable $e) {
            self::markTestSkipped('no Redis at '.$url.': '.$e->getMessage());
        }
        $this->client->flushdb();
    }

    private static function nonce(): string
    {
        return base64_encode(random_bytes(32));
    }

    private static function owner(): string
    {
        return bin2hex(random_bytes(16));
    }

    private static function obligationId(): string
    {
        return bin2hex(random_bytes(32));
    }

    private static function chainId(): string
    {
        return 'chain-'.bin2hex(random_bytes(8));
    }

    private function recordKey(string $nonce): string
    {
        return '{kiwi:kiwi}:postsolve:'.$nonce;
    }

    private function chainKey(string $chainId): string
    {
        return '{kiwi:kiwi}:chain:'.$chainId;
    }

    private function obligationKey(string $obligationId): string
    {
        return '{kiwi:kiwi}:chain-obligation:'.$obligationId;
    }

    private function seedChain(string $chainId, string $obligationId): void
    {
        $chains = new RedisChainedChallengeStateStore($this->client, 'kiwi');
        $chains->createWithObligation($chainId, $obligationId, self::nonce(), 'login', null, 'sha20', 1, 300);
    }

    public function testAPersistedCompleteDispositionFailsClosedOnEveryPath(): void
    {
        $store = new RedisPostSolveDispositionStore($this->client, 'kiwi');
        $nonce = self::nonce();
        $owner = self::owner();
        [$status] = $store->claim($nonce, $owner, 300);
        self::assertSame('claimed', $status);
        self::assertTrue($store->finalize($nonce, $owner, new PostSolveDisposition(PostSolveDispositionKind::Pass)));
        self::assertNotNull($store->read($nonce)?->disposition, 'the completed Pass is readable while its lifetime is bounded');

        $key = $this->recordKey($nonce);
        $this->client->persist($key);
        self::assertSame(-1, (int) $this->client->ttl($key), 'precondition: the disposition record is now persistent');
        $before = $this->client->get($key);

        // The acceptance read refuses: a lifetime-stripped complete Pass
        // is corrupt state, never authorization-bearing state.
        try {
            $store->read($nonce);
            self::fail('the read must fail closed on a persistent disposition record');
        } catch (MalformedPostSolveDispositionException) {
        }

        // The claim refuses with the typed corruption answer.
        try {
            $store->claim($nonce, self::owner(), 300, null, null, null, null);
            self::fail('the claim must fail closed on a persistent disposition record');
        } catch (MalformedPostSolveDispositionException) {
        }

        // The plain finalize is an atomic no-op (false), never a write.
        self::assertFalse(
            $store->finalize($nonce, $owner, new PostSolveDisposition(PostSolveDispositionKind::Pass)),
            'a persistent disposition record is never finalizable',
        );

        // The guarded finalize reports the typed corrupt outcome.
        self::assertSame(
            PostSolveFinalizeOutcome::Corrupt,
            $store->finalizeGuarded($nonce, $owner, new PostSolveDisposition(PostSolveDispositionKind::Pass), null, null, null),
        );

        self::assertSame($before, $this->client->get($key), 'every refusal performed zero mutation');
        self::assertSame(-1, (int) $this->client->ttl($key), 'no lifetime is manufactured by any refusal');
    }

    public function testAPersistedChainIsRefusedByTheObligationGuard(): void
    {
        $obligationId = self::obligationId();
        $chainId = self::chainId();
        $this->seedChain($chainId, $obligationId);
        $chainKey = $this->chainKey($chainId);
        $this->client->persist($chainKey);
        self::assertSame(-1, (int) $this->client->ttl($chainKey), 'precondition: the chain key is now persistent');

        $store = new RedisPostSolveDispositionStore($this->client, 'kiwi');
        $nonce = self::nonce();
        $owner = self::owner();
        [$status] = $store->claim($nonce, $owner, 300, null, $obligationId, $chainId, $nonce);
        self::assertSame('claimed', $status);
        $before = $this->client->get($this->recordKey($nonce));

        // The Pass candidate consults the PERSISTed chain: corrupt state
        // fails closed, never Finalized.
        self::assertSame(
            PostSolveFinalizeOutcome::ObligationChanged,
            $store->finalizeGuarded($nonce, $owner, new PostSolveDisposition(PostSolveDispositionKind::Pass), $obligationId, $chainId, $nonce),
        );
        self::assertSame($before, $this->client->get($this->recordKey($nonce)), 'the refused Pass performs zero mutation');

        // Contrast: restore the bounded lifetime; the same record now
        // reaches the ordinary guard (the chain is open and this nonce is
        // not its stage-2 nonce) — proving the refusal above is the
        // stripped lifetime, not an unrelated guard failure.
        $this->client->expire($chainKey, 300);
        self::assertSame(
            PostSolveFinalizeOutcome::ChainRequired,
            $store->finalizeGuarded($nonce, $owner, new PostSolveDisposition(PostSolveDispositionKind::Pass), $obligationId, $chainId, $nonce),
        );
        self::assertSame($before, $this->client->get($this->recordKey($nonce)), 'the ChainRequired refusal performs zero mutation too');
    }

    public function testASignedExpiredButRedisLiveChainIsRefused(): void
    {
        $obligationId = self::obligationId();
        $chainId = self::chainId();
        $this->seedChain($chainId, $obligationId);
        $chainKey = $this->chainKey($chainId);
        // The signed expiry lapses while the Redis key is still live.
        $raw = json_decode((string) $this->client->get($chainKey), true, 8, JSON_THROW_ON_ERROR);
        $raw['expiresAt'] = time() - 10;
        $this->client->set($chainKey, (string) json_encode($raw, JSON_THROW_ON_ERROR), 'EX', 300);
        self::assertGreaterThan(0, (int) $this->client->ttl($chainKey), 'precondition: the chain key is still live');
        self::assertSame($obligationId, json_decode((string) $this->client->get($chainKey), true, 8, JSON_THROW_ON_ERROR)['obligationId']);

        $store = new RedisPostSolveDispositionStore($this->client, 'kiwi');
        $nonce = self::nonce();
        $owner = self::owner();
        [$status] = $store->claim($nonce, $owner, 300, null, $obligationId, $chainId, $nonce);
        self::assertSame('claimed', $status);
        $before = $this->client->get($this->recordKey($nonce));

        self::assertSame(
            PostSolveFinalizeOutcome::ObligationChanged,
            $store->finalizeGuarded($nonce, $owner, new PostSolveDisposition(PostSolveDispositionKind::Pass), $obligationId, $chainId, $nonce),
            'an expired-but-live chain is stale, never live authorization state',
        );
        self::assertSame($before, $this->client->get($this->recordKey($nonce)), 'zero mutation');
    }

    public function testARedirectedObligationMappingIsRefused(): void
    {
        $obligationId = self::obligationId();
        $chainId = self::chainId();
        $otherObligationId = self::obligationId();
        $otherChainId = self::chainId();
        $this->seedChain($chainId, $obligationId);
        $this->seedChain($otherChainId, $otherObligationId);
        // The corruption: this transaction's mapping is redirected to
        // another transaction's perfectly valid chain.
        $this->client->set($this->obligationKey($obligationId), $otherChainId, 'EX', 300);

        $store = new RedisPostSolveDispositionStore($this->client, 'kiwi');
        $nonce = self::nonce();
        $owner = self::owner();
        [$status] = $store->claim($nonce, $owner, 300, null, $obligationId, $otherChainId, $nonce);
        self::assertSame('claimed', $status);
        $before = $this->client->get($this->recordKey($nonce));
        $otherBefore = $this->client->get($this->chainKey($otherChainId));

        self::assertSame(
            PostSolveFinalizeOutcome::ObligationChanged,
            $store->finalizeGuarded($nonce, $owner, new PostSolveDisposition(PostSolveDispositionKind::Pass), $obligationId, $otherChainId, $nonce),
            'a chain that is not this transaction\'s obligation is corrupt state, never acceptance',
        );
        self::assertSame($before, $this->client->get($this->recordKey($nonce)), 'zero mutation on the disposition');
        self::assertSame($otherBefore, $this->client->get($this->chainKey($otherChainId)), 'the foreign chain is untouched');
    }

    public function testACompletePassReplayAgainstAPersistedChainIsRefused(): void
    {
        $obligationId = self::obligationId();
        $chainId = self::chainId();
        $this->seedChain($chainId, $obligationId);
        $this->client->persist($this->chainKey($chainId));

        // Seed a complete Pass disposition exactly as the writer emits it.
        $nonce = self::nonce();
        $record = [
            'v' => 1,
            'state' => 'complete',
            'owner' => null,
            'lease_until' => null,
            'disposition' => ['kind' => 'pass', 'decision_id' => null, 'chain_id' => null, 'chain_expires_at' => null],
            'decision_id' => null,
        ];
        $recordKey = $this->recordKey($nonce);
        $this->client->set($recordKey, (string) json_encode($record, JSON_THROW_ON_ERROR), 'EX', 300);
        $before = $this->client->get($recordKey);

        $store = new RedisPostSolveDispositionStore($this->client, 'kiwi');
        [$status, $carried, $outcome] = $store->claim($nonce, self::owner(), 300, null, $obligationId, $chainId, $nonce);
        self::assertSame('complete', $status);
        self::assertNotNull($carried);
        self::assertSame(
            PostSolveFinalizeOutcome::ObligationChanged,
            $outcome,
            'the stored Pass replay must not be accepted while its transaction chain is lifetime-stripped',
        );
        self::assertSame($before, $this->client->get($recordKey), 'the replay read performed zero mutation');
    }
}
