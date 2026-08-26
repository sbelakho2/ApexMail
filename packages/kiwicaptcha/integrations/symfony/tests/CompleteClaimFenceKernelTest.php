<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests;

use BelConsulting\KiwiCaptchaBundle\Risk\PostSolveDisposition;
use BelConsulting\KiwiCaptchaBundle\Risk\PostSolveDispositionKind;
use BelConsulting\KiwiCaptchaBundle\Risk\RedisPostSolveDispositionStore;
use BelConsulting\KiwiCaptchaBundle\Tests\Kernel\CompleteClaimFenceKernel;
use KiwiCaptcha\Storage\ReplicaWaitException;
use PHPUnit\Framework\TestCase;

/**
 * The terminal post-solve complete-claim acceptance is a causal fence
 * on the accepting (risk) connection, proven at the kernel level with
 * the bundle core Redis and risk.redis_service intentionally separate.
 *
 * Connection A finalizes a Pass with its mutation WAIT shortfalling: the
 * request fails, but the complete(Pass) record remains on the primary.
 * An unrelated fence on the separate core connection shares no
 * replication stream. Connection B then claims the same nonce and sees
 * 'complete': it must write its own fence (`SETEX` replication-fence) and
 * WAIT on the risk connection before the terminal record may be
 * returned. A shortfall raises ReplicaWaitException and never returns
 * the disposition; a satisfied fence returns it.
 */
final class CompleteClaimFenceKernelTest extends TestCase
{
    private const NAMESPACE = 'kiwi-wait-test';

    /** @return list<array{0: string, 1: list<mixed>}> the WAIT commands issued */
    private function waits(DispositionWaitRedisFake $fake): array
    {
        return array_values(array_filter($fake->calls, static fn (array $c): bool => $c[0] === 'WAIT'));
    }

    /** @return list<array{0: string, 1: list<mixed>}> the replication-fence `SETEX` commands */
    private function fenceWrites(DispositionWaitRedisFake $fake): array
    {
        return array_values(array_filter(
            $fake->calls,
            static fn (array $c): bool => $c[0] === 'SETEX' && \is_string($c[1][0] ?? null) && str_contains($c[1][0], 'replication-fence'),
        ));
    }

    public function testCompleteClaimFenceLandsOnTheRiskConnectionOnly(): void
    {
        $kernel = new CompleteClaimFenceKernel('test', true);
        $kernel->boot();
        try {
            $container = $kernel->getContainer();
            $wiredStore = $container->get(RedisPostSolveDispositionStore::class);
            $riskFake = $container->get('risk_fake_redis');
            $coreFake = $container->get('core_fake_redis');
            $nonce = bin2hex(random_bytes(16));

            // Connection A: the fresh claim + finalize mutate on the risk
            // primary; the finalize's own WAIT shortfalls -> the request
            // fails, but complete(Pass) remains on the primary.
            self::assertSame('claimed', $wiredStore->claim($nonce, 'owner-a', 300)[0]);
            $riskFake->waitAck = 0;
            try {
                $wiredStore->finalize($nonce, 'owner-a', new PostSolveDisposition(PostSolveDispositionKind::Pass));
                self::fail('the finalize must fail closed when its mutation WAIT shortfalls');
            } catch (ReplicaWaitException) {
            }

            // An unrelated core recovery fence on the separate core
            // connection: it must never cover the risk store's acceptance.
            $coreFake->calls = [];
            $coreFake->setex('{kiwi:core}:replication-fence', 60, 'unrelated-core-token');

            // Connection B: an independent client over the shared risk
            // state, on the bundle's actual risk namespace (derived from
            // the wired store's record key). The claim sees 'complete'
            // and MUST fence on the risk connection before returning the
            // terminal record.
            $postsolveKeys = array_keys(array_filter($riskFake->strings, static fn (string $k): bool => str_contains($k, ':postsolve:'.$nonce), ARRAY_FILTER_USE_KEY));
            self::assertCount(1, $postsolveKeys, 'the wired store must have written the risk record under the bundle namespace');
            self::assertMatchesRegularExpression('/\{kiwi:[^}]+\}:postsolve:/', $postsolveKeys[0]);
            preg_match('/\{kiwi:([^}]+)\}:postsolve:/', $postsolveKeys[0], $namespaceMatch);
            $clientB = new RedisPostSolveDispositionStore($riskFake, $namespaceMatch[1], 300, 1, 100);
            $riskFake->waitAck = 0;
            $riskFake->calls = [];
            try {
                $clientB->claim($nonce, 'owner-b', 300);
                self::fail('a complete claim must fail closed when its own fence WAIT shortfalls');
            } catch (ReplicaWaitException) {
            }
            self::assertCount(1, $this->fenceWrites($riskFake), 'the complete-claim acceptance writes its OWN causal fence on the risk connection');
            self::assertCount(1, $this->waits($riskFake), 'the complete-claim acceptance WAITs on the risk connection');
            self::assertCount(0, array_filter($coreFake->calls, static fn (array $c): bool => $c[0] === 'WAIT'), 'the unrelated core connection never satisfies the risk acceptance');

            // A satisfied fence returns the terminal record.
            $riskFake->waitAck = 1;
            $riskFake->calls = [];
            [$status, $record] = $clientB->claim($nonce, 'owner-b', 300);
            self::assertSame('complete', $status);
            self::assertSame(PostSolveDispositionKind::Pass, $record?->disposition?->kind, 'the satisfied fence returns the terminal Pass disposition');
            self::assertCount(1, $this->fenceWrites($riskFake), 'the satisfied complete claim still performs the causal fence');
            self::assertCount(1, $this->waits($riskFake), 'the satisfied complete claim still performs the verified WAIT');
            self::assertSame(['SETEX'], array_map(static fn (array $c): string => $c[0], $coreFake->calls), 'the core connection carries ONLY the unrelated core fence write — the risk acceptance never touches it');
        } finally {
            $kernel->shutdown();
        }
    }
}
