<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests;

use BelConsulting\KiwiCaptchaBundle\Controller\KiwiHealthController;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\FakePredisClient;
use PHPUnit\Framework\TestCase;

/**
 * Rollback-resistant readiness: /health/live is always 200 while the
 * process runs (never tied to saturation). /health/ready is 200 only
 * when the signing keys are configured, the security Redis answers a
 * (cached, debounced) ping, and the central security-policy state
 * ({kiwi:<ns>}:security-policy) is compatible — min_protocol_version
 * <= 2 and min_policy_epoch <= the configured risk.policy_version. An
 * absent key leaves the binary's own configuration authoritative.
 */
final class KiwiHealthControllerTest extends TestCase
{
    private const SECRET = '0123456789abcdef0123456789abcdef';

    private function controller(FakePredisClient $client, int $policyVersion = 1, ?callable $nowMs = null): KiwiHealthController
    {
        return new KiwiHealthController(self::SECRET, $client, 'health-test', $policyVersion, $nowMs);
    }

    private function requirePredis(): FakePredisClient
    {
        $nested = \dirname(__DIR__).'/vendor/kiwicaptcha/kiwicaptcha-php/vendor/autoload.php';
        if (!\class_exists(\Predis\Client::class) && is_file($nested)) {
            require_once $nested;
        }
        if (!\class_exists(\Predis\Client::class)) {
            self::markTestSkipped('predis/predis is not installed; cannot test the health controller');
        }

        return new FakePredisClient();
    }

    private function setPolicy(FakePredisClient $client, int $minProtocolVersion, int $minPolicyEpoch): void
    {
        $client->hashes['{kiwi:health-test}:security-policy'] = [
            'min_protocol_version' => (string) $minProtocolVersion,
            'min_policy_epoch' => (string) $minPolicyEpoch,
        ];
    }

    public function testLiveIsAlways200(): void
    {
        $client = $this->requirePredis();
        $client->pingFails = true;
        $controller = $this->controller($client);

        $response = $controller->live();
        self::assertSame(200, $response->getStatusCode());
        self::assertSame(['status' => 'live'], json_decode((string) $response->getContent(), true));
        // Dynamic status documents are never cached.
        self::assertStringContainsString('no-store', $response->headers->get('Cache-Control'));
        self::assertSame('no-cache', $response->headers->get('Pragma'));
    }

    public function testReadyOkWithoutCentralPolicyKey(): void
    {
        $client = $this->requirePredis();
        $controller = $this->controller($client);

        $response = $controller->ready();
        self::assertSame(200, $response->getStatusCode(), 'an absent security-policy key leaves the binary\'s own configuration authoritative');
        self::assertSame(['status' => 'ready'], json_decode((string) $response->getContent(), true));
    }

    public function testReadyOkWithCompatibleCentralPolicy(): void
    {
        $client = $this->requirePredis();
        $this->setPolicy($client, 2, 1);
        $controller = $this->controller($client, policyVersion: 1);

        self::assertSame(200, $controller->ready()->getStatusCode(), 'min_protocol_version 2 <= the binary max (2) and min_policy_epoch 1 <= the configured epoch 1');
    }

    public function testReadyOkWithEpochExactlyAtTheConfiguredVersion(): void
    {
        $client = $this->requirePredis();
        $this->setPolicy($client, 1, 3);
        $controller = $this->controller($client, policyVersion: 3);

        self::assertSame(200, $controller->ready()->getStatusCode(), 'min_policy_epoch equal to the configured policy_version is compatible');
    }

    public function testNotReadyWhenCentralPolicyDemandsProtocol3(): void
    {
        $client = $this->requirePredis();
        $this->setPolicy($client, 3, 1);
        $controller = $this->controller($client);

        $response = $controller->ready();
        self::assertSame(503, $response->getStatusCode(), 'a central min_protocol_version of 3 exceeds this binary\'s max (2) — it must leave the pool (mixed-version rolling deployment)');
        self::assertStringContainsString('min_protocol_version', (string) $response->getContent());
    }

    public function testNotReadyWhenCentralPolicyDemandsANewerEpoch(): void
    {
        $client = $this->requirePredis();
        $this->setPolicy($client, 2, 2);
        $controller = $this->controller($client, policyVersion: 1);

        $response = $controller->ready();
        self::assertSame(503, $response->getStatusCode(), 'min_policy_epoch 2 > the configured risk.policy_version 1 — the policy was revoked while this binary still issues under it');
        self::assertStringContainsString('min_policy_epoch', (string) $response->getContent());
    }

    public function testNotReadyWhenSecurityRedisIsUnreachable(): void
    {
        $client = $this->requirePredis();
        $client->pingFails = true;
        $controller = $this->controller($client);

        $response = $controller->ready();
        self::assertSame(503, $response->getStatusCode(), 'a dead security Redis must fail readiness');
        self::assertStringContainsString('security_redis_unreachable', (string) $response->getContent());
    }

    public function testLiveStaysOkWhileReadyFails(): void
    {
        $client = $this->requirePredis();
        $this->setPolicy($client, 3, 1);
        $controller = $this->controller($client);

        self::assertSame(503, $controller->ready()->getStatusCode(), 'ready fails: central protocol 3');
        self::assertSame(200, $controller->live()->getStatusCode(), 'live must stay 200 while ready fails (the process is up, the pool just must not route to it)');
    }

    public function testReadyOkWithoutAnyRedisConfigured(): void
    {
        $controller = new KiwiHealthController(self::SECRET, null, 'health-test', 1);
        self::assertSame(200, $controller->ready()->getStatusCode(), 'no security Redis configured: the Redis legs are vacuous, the binary\'s config is authoritative');
    }

    public function testTransientProbeTimeoutNeverFailsReadinessOnItsOwn(): void
    {
        $client = $this->requirePredis();
        $now = [0.0];
        $controller = $this->controller($client, nowMs: static function () use (&$now): float {
            return $now[0];
        });

        // Healthy: probe succeeds, readiness OK.
        self::assertSame(200, $controller->ready()->getStatusCode());

        // The Redis starts timing out: the first failure is debounced for
        // one cache window — readiness holds (transient blip absorbed).
        $client->pingFails = true;
        $now[0] += 1100;
        self::assertSame(200, $controller->ready()->getStatusCode(), 'a single transient probe timeout must NOT fail readiness');

        // A second consecutive failure (after the debounce window) flips.
        $now[0] += 1100;
        self::assertSame(503, $controller->ready()->getStatusCode(), 'two consecutive probe failures must fail readiness');

        // Recovery flips back immediately.
        $client->pingFails = false;
        $now[0] += 1100;
        self::assertSame(200, $controller->ready()->getStatusCode());
    }

    public function testProbeResultIsCachedWithinTheWindow(): void
    {
        $client = $this->requirePredis();
        $now = [0.0];
        $controller = $this->controller($client, nowMs: static function () use (&$now): float {
            return $now[0];
        });
        $probesBefore = \count($client->calls);

        self::assertSame(200, $controller->ready()->getStatusCode());
        $afterFirst = \count($client->calls);

        // A second readiness check within the cache window must not re-probe.
        $now[0] += 500;
        self::assertSame(200, $controller->ready()->getStatusCode());
        self::assertSame($afterFirst, \count($client->calls), 'the PING probe must be cached ~1 s (no Redis round trip per readiness check)');

        // Past the window a fresh probe runs.
        $now[0] += 600;
        self::assertSame(200, $controller->ready()->getStatusCode());
        self::assertGreaterThan($afterFirst, \count($client->calls));
        self::assertGreaterThan($probesBefore, $afterFirst);
    }

// ── memory-budget readiness invariant ─────────────────────────────────────

    public function testMaxProfileMemoryReadsTheCoreProfileConstant(): void
    {
        self::assertSame(65536, \KiwiCaptcha\ChallengeProfile::argon64()->mKib, 'the largest adaptive profile is argon64 (65536 KiB = 64 MiB)');
        self::assertSame(64, (int) ceil(\KiwiCaptcha\ChallengeProfile::argon64()->mKib / 1024), 'the invariant\'s max profile memory must be 64 MiB');
    }

    public function testMemoryBudgetInvariantPassesWhenEnoughMemory(): void
    {
        // concurrency 2 x 64 MiB + 256 MiB headroom = 384 MiB <= 512 MiB.
        $controller = new KiwiHealthController(self::SECRET, null, 'health-test', 1, null, 2, 512);
        self::assertSame(200, $controller->ready()->getStatusCode());
        self::assertTrue($controller->memoryBudgetOk());
    }

    public function testMemoryBudgetInvariantFailsWhenTheBudgetIsTooSmall(): void
    {
        // concurrency 8 x 64 MiB + 256 MiB headroom = 768 MiB > 512 MiB.
        $controller = new KiwiHealthController(self::SECRET, null, 'health-test', 1, null, 8, 512);

        $response = $controller->ready();
        self::assertSame(503, $response->getStatusCode(), 'a container that cannot hold the worst-case verification memory must not be ready');
        self::assertStringContainsString('memory_budget_invariant', (string) $response->getContent());
    }

    public function testMemoryBudgetBoundaryIsExact(): void
    {
        // concurrency 4 x 64 + 256 = 512: the boundary budget is exactly
        // enough -> ready; one MiB less -> not ready.
        $ok = new KiwiHealthController(self::SECRET, null, 'health-test', 1, null, 4, 512);
        self::assertSame(200, $ok->ready()->getStatusCode(), 'required == budget is ready');

        $tooSmall = new KiwiHealthController(self::SECRET, null, 'health-test', 1, null, 4, 511);
        self::assertSame(503, $tooSmall->ready()->getStatusCode(), 'required > budget is not ready');
    }

    public function testMemoryBudgetSkippedWhenNotConfigured(): void
    {
        // container_memory_mib null (default): the invariant is skipped —
        // readiness is decided by the other legs only.
        $controller = new KiwiHealthController(self::SECRET, null, 'health-test', 1, null, 100, null);
        self::assertSame(200, $controller->ready()->getStatusCode(), 'a null budget must skip the invariant');
        self::assertTrue($controller->memoryBudgetOk());
    }

    public function testUnlimitedConcurrencyUsesOneHashForTheInvariant(): void
    {
        // argon2_max_concurrent_verifications = 0 (unlimited) is treated as 1
        // for the invariant (at least one hash must fit): 1 x 64 + 256 = 320.
        $ok = new KiwiHealthController(self::SECRET, null, 'health-test', 1, null, 0, 320);
        self::assertSame(200, $ok->ready()->getStatusCode(), 'the unlimited-cap floor (320 MiB) must fit');

        $tooSmall = new KiwiHealthController(self::SECRET, null, 'health-test', 1, null, 0, 319);
        self::assertSame(503, $tooSmall->ready()->getStatusCode());
    }
}
