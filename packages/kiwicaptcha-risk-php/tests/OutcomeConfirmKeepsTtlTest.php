<?php

declare(strict_types=1);

namespace KiwiCaptcha\Risk\Tests;

use KiwiCaptcha\Risk\Storage\RedisRiskStateStore;
use PHPUnit\Framework\TestCase;

/**
 * The outcome-confirm TTL contract, against real Redis: a pending -> L/A
 * confirm must keep the ledger's remaining TTL (SET ... KEEPTTL),
 * never re-arm it to the configured outcome TTL. The register path
 * (outcome_register.lua / register_decision.lua) is the sole creator
 * and the only arm of the ledger TTL. A confirm landing hours into the
 * ledger's life must not hand the record a fresh full window — that
 * would let an abandoned decision's ledger outlive its registration by
 * unbounded confirm retries.
 */
final class OutcomeConfirmKeepsTtlTest extends TestCase
{
    private const OUTCOME_TTL_SECS = 6;

    /** @var \Predis\Client */
    private $client;

    protected function setUp(): void
    {
        $url = getenv('RISK_REDIS_URL');
        if (!is_string($url) || $url === '') {
            self::markTestSkipped('RISK_REDIS_URL not set; start redis with: docker run -d -p 6399:6379 redis:7-alpine');
        }
        $this->client = RedisRiskStateStore::createClient($url);
        $this->client->ping();
    }

    public function testConfirmPreservesTheRemainingLedgerTtlInsteadOfRearmingIt(): void
    {
        $store = new RedisRiskStateStore(
            $this->client,
            namespace: 'ttl-proof-' . bin2hex(random_bytes(4)),
            outcomeTtlSecs: self::OUTCOME_TTL_SECS,
        );
        $decisionId = bin2hex(random_bytes(16));
        $key = $store->ledgerKey($decisionId);

        try {
            self::assertTrue($store->registerOutcome($decisionId, 7, 0, 500), 'the pending ledger registers once');
            $ttlRegistered = (int) $this->client->ttl($key);
            self::assertGreaterThan(0, $ttlRegistered, 'the registered ledger carries the outcome TTL');
            self::assertLessThanOrEqual(self::OUTCOME_TTL_SECS, $ttlRegistered);

            // Let the ledger decay provably (a re-arming confirm would
            // restore the full window from here).
            sleep(2);
            $ttlAtConfirm = (int) $this->client->ttl($key);
            self::assertLessThan($ttlRegistered, $ttlAtConfirm, 'the decay window must be measurable before the confirm');

            self::assertSame(1, $store->confirmOutcome($decisionId, true), 'the PENDING -> L confirm applies exactly once');
            self::assertSame(0, $store->confirmOutcome($decisionId, true), 'the retry over the confirmed ledger is a no-op');

            $ttlAfterConfirm = (int) $this->client->ttl($key);
            self::assertGreaterThan(0, $ttlAfterConfirm, 'the confirmed ledger stays ephemeral');
            self::assertLessThanOrEqual(
                $ttlAtConfirm + 1,
                $ttlAfterConfirm,
                sprintf(
                    'the confirm must keep the remaining TTL (%d), not re-arm the %d-second outcome TTL (measured %d after the confirm)',
                    $ttlAtConfirm,
                    self::OUTCOME_TTL_SECS,
                    $ttlAfterConfirm,
                ),
            );

            $raw = (string) $this->client->get($key);
            self::assertStringContainsString('"o":"L"', $raw, 'the ledger value flipped to L');
        } finally {
            $this->client->del([$key]);
        }
    }
}
