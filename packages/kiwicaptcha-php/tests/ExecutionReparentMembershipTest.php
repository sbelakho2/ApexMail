<?php

declare(strict_types=1);

namespace KiwiCaptcha\Tests;

use KiwiCaptcha\ExecutionChallengeGenerator;
use PHPUnit\Framework\TestCase;

/**
 * The version-5 reparent arm must update the document-membership set
 * exactly like the Rust mirror (execution.rs: doc_ids.insert/remove):
 * a node moved under an attached target becomes queryable, a node moved
 * under a detached target stops being queryable. The PHP arm used to
 * write to an unbound local, so the generator's expected trace diverged
 * from the interpreter for every later membership-dependent probe.
 */
final class ExecutionReparentMembershipTest extends TestCase
{
    /**
     * @param array<string, mixed> $ctx
     * @param array<string, true>  $docIds
     *
     * @return array{0: string, 1: array<string, true>, 2: string}
     */
    private function reparentThenQuery(array $ctx, array $cur, array $docIds, string $targetId): array
    {
        $rc = new \ReflectionClass(ExecutionChallengeGenerator::class);
        $simulate = $rc->getMethod('simulateOp');
        $u8 = array_fill(0, 8, 0);
        $entry = $simulate->invokeArgs(null, [
            (int) $rc->getConstant('OP_DOM_REPARENT'),
            ['id' => $targetId, 'cell' => 0],
            &$u8, &$cur, &$docIds, &$ctx,
        ]);
        $query = $simulate->invokeArgs(null, [
            (int) $rc->getConstant('OP_DOM_QUERY'),
            ['s' => $cur['id']],
            &$u8, &$cur, &$docIds, &$ctx,
        ]);

        return [$entry, $docIds, $query];
    }

    public function testMoveUnderAttachedTargetJoinsTheDocument(): void
    {
        $ctx = [
            'nodes' => [
                'target' => ['parent' => null, 'children' => [], 'appended' => true],
                'moved' => ['parent' => null, 'children' => [], 'appended' => false],
            ],
            'body' => ['target'],
            'frags' => [],
        ];
        $cur = ['id' => 'moved', 'parent' => null, 'appended' => false];

        [$entry, $docIds, $query] = $this->reparentThenQuery($ctx, $cur, ['target' => true], 'target');

        self::assertSame('1', $entry);
        self::assertArrayHasKey('moved', $docIds);
        self::assertSame('1', $query, 'a node moved under an attached target is in the document');
    }

    public function testMoveUnderDetachedTargetLeavesTheDocument(): void
    {
        $ctx = [
            'nodes' => [
                'target' => ['parent' => null, 'children' => [], 'appended' => false],
                'moved' => ['parent' => null, 'children' => [], 'appended' => true],
            ],
            'body' => ['moved'],
            'frags' => [],
        ];
        $cur = ['id' => 'moved', 'parent' => null, 'appended' => true];

        [$entry, $docIds, $query] = $this->reparentThenQuery($ctx, $cur, ['moved' => true], 'target');

        self::assertSame('1', $entry);
        self::assertArrayNotHasKey('moved', $docIds);
        self::assertSame('0', $query, 'a node moved under a detached target is out of the document');
    }
}
