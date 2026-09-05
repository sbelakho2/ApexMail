<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests;

use BelConsulting\KiwiCaptchaBundle\Controller\KiwiHealthController;
use BelConsulting\KiwiCaptchaBundle\Security\Authority\PinnedPrimaryAuthorityGuard;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\FakePredisClient;
use KiwiCaptcha\ExecutionChallengeGenerator;
use PHPUnit\Framework\TestCase;

/**
 * Rollback-resistant readiness: /health/live is always 200 while the
 * process runs (never tied to saturation). /health/ready is 200 only
 * when the signing keys are configured, the security Redis answers a
 * (cached, debounced) ping, and the central security-policy state
 * ({kiwi:<ns>}:security-policy) is compatible. Compatible means
 * min_protocol_version <= 4 (this binary's max protocol: the
 * execution-capable v4 canonical), min_execution_version <= the
 * generator max (this binary's max execution-program version; an
 * absent execution floor imposes nothing) and min_policy_epoch <= the
 * configured risk.policy_version. When risk.execution_challenge is on
 * the required execution tier must additionally be satisfiable
 * against the effective fleet tier, or the probe answers 503 with the
 * security_policy_incompatible:execution_required_R_effective_E
 * reason. An absent key leaves the binary's own configuration
 * authoritative. Under ha_authority pinned_primary the readiness
 * additionally forces a fresh authority-guard check per wired
 * authority (never the ordinary verification window) and answers 503
 * with ha_authority_uninitialized / ha_authority_changed /
 * ha_authority_unreachable when the pin is uninitialized or the
 * authority changed.
 */
final class KiwiHealthControllerTest extends TestCase
{
    private const SECRET = '0123456789abcdef0123456789abcdef';

    private function controller(FakePredisClient $client, int $policyVersion = 1, ?callable $nowMs = null, bool $executionGate = false, int $executionVersionCap = 1, int $executionRequiredVersion = 1): KiwiHealthController
    {
        return new KiwiHealthController(self::SECRET, $client, 'health-test', $policyVersion, $nowMs, 0, null, 16384, [], null, $executionGate, $executionVersionCap, $executionRequiredVersion);
    }

    /**
     * The pinned-authority controller: the guard is wired like the
     * extension wires it under ha_authority pinned_primary (the guard
     * binds the raw client, the readiness leg checks it fresh).
     */
    private function pinnedController(FakePredisClient $client, PinnedPrimaryAuthorityGuard $guard, ?\Predis\Client $riskRedis = null): KiwiHealthController
    {
        return new KiwiHealthController(
            self::SECRET,
            $client,
            'health-test',
            1,
            null,
            0,
            null,
            16384,
            ['storage' => $guard],
            $riskRedis,
        );
    }

    private function guard(FakePredisClient $client, int $reverifySecs = 60): PinnedPrimaryAuthorityGuard
    {
        return new PinnedPrimaryAuthorityGuard($client, 'health-test', $reverifySecs, 'storage');
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

    private function setPolicy(FakePredisClient $client, int $minProtocolVersion, int $minPolicyEpoch, ?int $minExecutionVersion = null): void
    {
        $policy = [
            'min_protocol_version' => (string) $minProtocolVersion,
            'min_policy_epoch' => (string) $minPolicyEpoch,
        ];
        if ($minExecutionVersion !== null) {
            $policy['min_execution_version'] = (string) $minExecutionVersion;
        }
        $client->hashes['{kiwi:health-test}:security-policy'] = $policy;
    }

    /**
     * A policy hash carrying a raw `min_execution_version` value (the
     * corrupt-field cases: the field is present, so it must never be
     * collapsed toward absent).
     */
    private function setRawExecutionFloor(FakePredisClient $client, string $raw): void
    {
        $client->hashes['{kiwi:health-test}:security-policy'] = [
            'min_protocol_version' => '1',
            'min_policy_epoch' => '1',
            'min_execution_version' => $raw,
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
        $this->setPolicy($client, 3, 1);
        $controller = $this->controller($client, policyVersion: 1);

        self::assertSame(200, $controller->ready()->getStatusCode(), 'min_protocol_version 3 <= the binary max (4, the execution-capable v4 canonical) and min_policy_epoch 1 <= the configured epoch 1');
    }

    public function testReadyOkWithTheExecutionCapableFloorFour(): void
    {
        // The binary's max protocol is now 4, so a central
        // floor of 4 (the execution-capable canonical) is compatible.
        $client = $this->requirePredis();
        $this->setPolicy($client, 4, 1);
        $controller = $this->controller($client, policyVersion: 1);

        self::assertSame(200, $controller->ready()->getStatusCode(), 'min_protocol_version 4 <= the binary max (4) — the v4-capable binary stays in the pool');
    }

    public function testReadyOkWithEpochExactlyAtTheConfiguredVersion(): void
    {
        $client = $this->requirePredis();
        $this->setPolicy($client, 1, 3);
        $controller = $this->controller($client, policyVersion: 3);

        self::assertSame(200, $controller->ready()->getStatusCode(), 'min_policy_epoch equal to the configured policy_version is compatible');
    }

    public function testNotReadyWhenCentralPolicyDemandsProtocol5(): void
    {
        $client = $this->requirePredis();
        $this->setPolicy($client, 5, 1);
        $controller = $this->controller($client);

        $response = $controller->ready();
        self::assertSame(503, $response->getStatusCode(), 'a central min_protocol_version of 5 exceeds this binary\'s max (4) — it must leave the pool (mixed-version rolling deployment)');
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

    public function testReadyOkWithTheExecutionFloorAtTheBinaryMax(): void
    {
        // The binary's max execution-program version is the generator
        // authority (5 today): a central floor at or under it is
        // compatible, like a protocol floor at or under the binary's
        // max.
        $client = $this->requirePredis();
        $this->setPolicy($client, 4, 1, 4);
        $controller = $this->controller($client, policyVersion: 1);

        self::assertSame(200, $controller->ready()->getStatusCode(), 'min_execution_version 4 <= the binary max — the binary stays in the pool');
    }

    public function testNotReadyWhenCentralPolicyDemandsAnExecutionVersionAboveTheBinaryMax(): void
    {
        // The execution floor is a reader floor exactly like the
        // protocol floor: a central min_execution_version above this
        // binary's max must take it out of the pool, or a mixed fleet
        // could hand it programs it cannot honor. The binary max is the
        // generator authority (5 today), so the demand that must leave
        // the pool is max + 1 (6).
        $client = $this->requirePredis();
        $this->setPolicy($client, 4, 1, ExecutionChallengeGenerator::MAX_EXECUTION_VERSION + 1);
        $controller = $this->controller($client, policyVersion: 1);

        $response = $controller->ready();
        self::assertSame(503, $response->getStatusCode(), 'a central min_execution_version above the binary max must leave the pool (mixed-version rolling deployment)');
        self::assertSame('security_policy_incompatible:min_execution_version_'.(ExecutionChallengeGenerator::MAX_EXECUTION_VERSION + 1), json_decode((string) $response->getContent(), true)['reason'], 'the machine-readable reason names the execution floor with its numeric suffix');
    }

    public function testNotReadyWhenCentralPolicyCarriesACorruptExecutionFloor(): void
    {
        // Corrupt present min_execution_version state must fail closed
        // exactly like the other two fields: abc, -1, 1.5 and integer
        // overflow are never silently collapsed toward zero and treated
        // as absent.
        foreach (['abc', '-1', '1.5', '99999999999999999999999999999999999999'] as $raw) {
            $client = $this->requirePredis();
            $this->setRawExecutionFloor($client, $raw);
            $controller = $this->controller($client, policyVersion: 1);

            $response = $controller->ready();
            self::assertSame(503, $response->getStatusCode(), 'a corrupt min_execution_version ('.$raw.') must fail readiness');
            self::assertSame('security_policy_state_corrupt:min_execution_version', json_decode((string) $response->getContent(), true)['reason'], 'the machine-readable reason names the corrupt execution field');
        }
    }

    public function testReadyOkWithNoExecutionFloorDeclared(): void
    {
        // The min_execution_version key is optional: a policy without it
        // declares no execution floor (parsed as 0), so the binary's
        // own execution capability decides.
        $client = $this->requirePredis();
        $this->setPolicy($client, 4, 1);
        $controller = $this->controller($client, policyVersion: 1);

        self::assertSame(200, $controller->ready()->getStatusCode(), 'an absent min_execution_version imposes no execution constraint');
    }

    // ── the execution-gate required-tier leg ─────────────────────────

    public function testMaxExecutionVersionEqualsTheGeneratorMaximum(): void
    {
        self::assertSame(
            ExecutionChallengeGenerator::MAX_EXECUTION_VERSION,
            KiwiHealthController::MAX_EXECUTION_VERSION,
            'the readiness max must track the core generator, never a literal',
        );
    }

    public function testExecutionGateReadinessTable(): void
    {
        // The exact readiness table for the armed execution dimension:
        // the effective fleet tier is the policy minimum of the node
        // cap, the parsed central floor (absent counts as version 1)
        // and the generator max, and a required tier above it refuses
        // readiness. Rows: gate, cap, floor, required, expected code.
        $rows = [
            [true, 2, null, 2, 503, 'security_policy_incompatible:execution_required_2_effective_1'],
            [true, 2, 1, 2, 503, 'security_policy_incompatible:execution_required_2_effective_1'],
            [true, 2, 2, 2, 200, null],
            [true, 3, 2, 3, 503, 'security_policy_incompatible:execution_required_3_effective_2'],
            [true, 3, 3, 3, 200, null],
            [false, 3, 1, 3, 200, null],
        ];
        foreach ($rows as [$gate, $cap, $floor, $required, $expectedCode, $expectedReason]) {
            $client = $this->requirePredis();
            $policy = ['min_protocol_version' => '4', 'min_policy_epoch' => '1'];
            if ($floor !== null) {
                $policy['min_execution_version'] = (string) $floor;
            }
            $client->hashes['{kiwi:health-test}:security-policy'] = $policy;
            $controller = $this->controller($client, executionGate: $gate, executionVersionCap: $cap, executionRequiredVersion: $required);

            $response = $controller->ready();
            $label = sprintf('gate %s cap %d floor %s required %d', $gate ? 'on' : 'off', $cap, var_export($floor, true), $required);
            self::assertSame($expectedCode, $response->getStatusCode(), $label);
            $body = json_decode((string) $response->getContent(), true);
            if ($expectedReason === null) {
                self::assertSame('ready', $body['status'], $label);
            } else {
                self::assertSame($expectedReason, $body['reason'], $label);
            }
        }
    }

    public function testExecutionGateLegIsInertWhileTheRequiredTierStaysAtOne(): void
    {
        // The default required tier 1 is always satisfiable: an armed
        // deployment with no confirmed floor (or no policy key at all)
        // stays ready, since the effective tier can never drop below 1.
        $client = $this->requirePredis();
        $this->setPolicy($client, 4, 1);
        $controller = $this->controller($client, executionGate: true, executionVersionCap: 2, executionRequiredVersion: 1);

        self::assertSame(200, $controller->ready()->getStatusCode());
    }

    public function testExecutionGateLegAppliesWithoutAnySecurityRedis(): void
    {
        // No central policy by design: the floor is unconfirmed, so the
        // effective tier is the node cap floored at 1. A required tier
        // of 2 is unsatisfiable and the probe refuses; the default
        // required tier 1 stays ready.
        $requiredTwo = new KiwiHealthController(self::SECRET, null, 'health-test', 1, null, 0, null, 16384, [], null, true, 2, 2);
        self::assertSame(503, $requiredTwo->ready()->getStatusCode());
        self::assertSame('security_policy_incompatible:execution_required_2_effective_1', json_decode((string) $requiredTwo->ready()->getContent(), true)['reason']);

        $requiredOne = new KiwiHealthController(self::SECRET, null, 'health-test', 1, null, 0, null, 16384, [], null, true, 2, 1);
        self::assertSame(200, $requiredOne->ready()->getStatusCode());
    }

    public function testExecutionGateLegHonorsTheGeneratorMaxRung(): void
    {
        // The cap and the required tier can reach the generator max:
        // with a floor at the max the effective tier is the max and the
        // probe is ready; with the floor absent only version 1 is
        // confirmed, so the max required tier is unsatisfiable.
        $client = $this->requirePredis();
        $this->setPolicy($client, 4, 1, 4);
        $floorAtMax = $this->controller($client, executionGate: true, executionVersionCap: 4, executionRequiredVersion: 4);
        self::assertSame(200, $floorAtMax->ready()->getStatusCode(), 'cap 4 required 4 with the floor at the generator max is ready');

        $unfloored = $this->requirePredis();
        $this->setPolicy($unfloored, 4, 1);
        $unsatisfiable = $this->controller($unfloored, executionGate: true, executionVersionCap: 4, executionRequiredVersion: 4);
        $response = $unsatisfiable->ready();
        self::assertSame(503, $response->getStatusCode(), 'cap 4 required 4 with no confirmed floor is not ready');
        self::assertSame('security_policy_incompatible:execution_required_4_effective_1', json_decode((string) $response->getContent(), true)['reason']);
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
        $this->setPolicy($client, 5, 1);
        $controller = $this->controller($client);

        self::assertSame(503, $controller->ready()->getStatusCode(), 'ready fails: central protocol 5');
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

    public function testUnlimitedConcurrencyWithABudgetIsNeverReady(): void
    {
        // argon2_max_concurrent_verifications = 0 (unlimited): an
        // unlimited memory-hard workload has NO finite worst-case
        // concurrency, so a finite container budget can never prove the
        // invariant — the readiness answers not-ready (and the container
        // refuses the combination at compile time), never a silently
        // floored 1.
        $unlimited = new KiwiHealthController(self::SECRET, null, 'health-test', 1, null, 0, 100_000);
        self::assertSame(503, $unlimited->ready()->getStatusCode(), 'unlimited concurrency with a finite budget is never ready');

        // A null budget + unlimited is allowed, explicitly unchecked.
        $unchecked = new KiwiHealthController(self::SECRET, null, 'health-test', 1, null, 0, null);
        self::assertSame(200, $unchecked->ready()->getStatusCode(), 'no budget means the invariant is skipped and documented');

        // A finite cap computes the exact worst case: 1 x 64 + 256 = 320.
        $exact = new KiwiHealthController(self::SECRET, null, 'health-test', 1, null, 1, 320);
        self::assertSame(200, $exact->ready()->getStatusCode(), 'exactly the required memory is ready');
        $oneBelow = new KiwiHealthController(self::SECRET, null, 'health-test', 1, null, 1, 319);
        self::assertSame(503, $oneBelow->ready()->getStatusCode(), 'one MiB below the requirement is not ready');
    }

    // ── the pinned-primary authority-eligibility leg ────────────────────

    public function testReadyRefusesAnUninitializedPinnedAuthority(): void
    {
        // Before kiwicaptcha:ha-initialize (and without
        // ha_authority_expected) the pin is uninitialized: the pod must
        // not be ready, or the LB routes traffic to an instance that
        // refuses every security-critical transition.
        $client = $this->requirePredis();
        $controller = $this->pinnedController($client, $this->guard($client));

        $response = $controller->ready();
        self::assertSame(503, $response->getStatusCode(), 'a pod whose authority pin is uninitialized must not be ready');
        $body = json_decode((string) $response->getContent(), true);
        self::assertSame('ha_authority_uninitialized', $body['reason'], 'the machine-readable reason names the uninitialized authority');
        self::assertSame('storage', $body['authority'], 'the failing authority label is reported');
    }

    public function testReadyPassesAnInitializedPinnedAuthority(): void
    {
        $client = $this->requirePredis();
        $guard = $this->guard($client);
        $guard->initializePin();
        $controller = $this->pinnedController($client, $guard);

        self::assertSame(200, $controller->ready()->getStatusCode(), 'an initialized, stable pinned authority is ready');
    }

    public function testReadyRefusesAChangedAuthority(): void
    {
        // The authority restarts (a new run_id on the same endpoint):
        // the pod must leave the pool immediately, even though the
        // ordinary guard check would still be cached.
        $client = $this->requirePredis();
        $guard = $this->guard($client);
        $guard->initializePin();
        $controller = $this->pinnedController($client, $guard);
        self::assertSame(200, $controller->ready()->getStatusCode(), 'ready while the authority is stable');

        $client->infoReplication['run_id'] = str_repeat('b', 40);
        $client->infoServer['run_id'] = str_repeat('b', 40);

        $response = $controller->ready();
        self::assertSame(503, $response->getStatusCode(), 'a changed authority must fail readiness immediately');
        $body = json_decode((string) $response->getContent(), true);
        self::assertSame('ha_authority_changed', $body['reason'], 'the machine-readable reason names the changed authority');
        self::assertSame('storage', $body['authority']);
    }

    public function testReadyRecoversAfterAnAuthorizedReinitialize(): void
    {
        // The documented recovery: quiesce, then re-initialize with
        // --force after the deliberate authority change. The pod is
        // ready again once the guard is re-pinned to the new identity.
        $client = $this->requirePredis();
        $guard = $this->guard($client);
        $guard->initializePin();
        $controller = $this->pinnedController($client, $guard);

        $client->infoReplication['run_id'] = str_repeat('b', 40);
        $client->infoServer['run_id'] = str_repeat('b', 40);
        self::assertSame(503, $controller->ready()->getStatusCode(), 'the changed authority is not ready');

        $guard->initializePin(true);
        self::assertSame(200, $controller->ready()->getStatusCode(), 'the authorized re-initialize restores readiness');
    }

    public function testReadyForcesAFreshGuardCheckNeverTheOrdinaryWindow(): void
    {
        // M2: the readiness leg must never serve on the guard's 5 s
        // ordinary verification cache: every probe re-verifies the
        // authority (the security-final lane), so a change is observed
        // immediately, not after the window.
        $client = $this->requirePredis();
        $guard = $this->guard($client, reverifySecs: 60);
        $guard->initializePin();
        $controller = $this->pinnedController($client, $guard);

        $infosBefore = \count(array_filter($client->calls, static fn (array $call): bool => $call[0] === 'INFO'));
        self::assertSame(200, $controller->ready()->getStatusCode());
        $infosAfterFirst = \count(array_filter($client->calls, static fn (array $call): bool => $call[0] === 'INFO'));

        self::assertSame(200, $controller->ready()->getStatusCode());
        $infosAfterSecond = \count(array_filter($client->calls, static fn (array $call): bool => $call[0] === 'INFO'));
        self::assertGreaterThan($infosBefore, $infosAfterFirst, 'the first probe verifies the authority');
        self::assertGreaterThan(
            $infosAfterFirst,
            $infosAfterSecond,
            'every readiness probe re-verifies the authority: never the ordinary 5 s verification window',
        );
    }

    public function testReadyPassesSilentlyWhenNoAuthorityGuardIsWired(): void
    {
        // ha_authority none (the default): the leg passes silently and
        // the existing readiness legs decide.
        $client = $this->requirePredis();
        $this->setPolicy($client, 5, 1);
        $controller = $this->controller($client);
        $response = $controller->ready();
        self::assertSame(503, $response->getStatusCode(), 'the other legs still decide');
        self::assertStringContainsString('min_protocol_version', (string) $response->getContent(), 'the failing leg is the central policy, not the authority leg');
    }

    public function testReadyRefusesAnUnreachablePinnedAuthority(): void
    {
        // The authority cannot be verified at all (the info read
        // fails): fail closed with the unreachable reason.
        $client = $this->requirePredis();
        $guard = $this->guard($client);
        $guard->initializePin();
        $controller = $this->pinnedController($client, $guard);

        $client->failCommand = 'INFO';
        $response = $controller->ready();
        self::assertSame(503, $response->getStatusCode(), 'an unverifiable pinned authority must not be ready');
        $body = json_decode((string) $response->getContent(), true);
        self::assertSame('ha_authority_unreachable', $body['reason']);
    }
}
