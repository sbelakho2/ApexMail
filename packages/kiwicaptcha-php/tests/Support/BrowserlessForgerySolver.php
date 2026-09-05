<?php

declare(strict_types=1);

namespace KiwiCaptcha\Tests\Support;

/**
 * The browserless shadow solver of the execution grammars: a dev-only
 * oracle that forges verifier-accepted executed traces without a
 * browser for every live grammar rung, versions 1 through the
 * generator maximum (ExecutionChallengeGenerator::MAX_EXECUTION_VERSION),
 * the causal object-graph rung included.
 *
 * The solver replays the interpreter's own semantics over a decoded
 * program, which the caller obtains from
 * ExecutionChallengeGenerator::decode. At every observe op it chooses
 * an arbitrary legal observed height, the explicit solve parameter
 * where any value 1..255 works, and the chosen byte is propagated
 * through the u8 state so the whole causal chain stays coherent. The
 * dsib append-rank values and the qreal, evreal, sreal, geom and
 * point entries follow the canonical model.
 *
 * Reuse, never duplication: everything except the observe choice runs
 * on the fixture's behavior-exact state machine, reached through
 * ExecutionTraceFixture::executedTraceForWithObservedHeight. This
 * class carries no second copy of that machine. It documents the
 * explicit attack surface the fixture's fixed reference height (10)
 * would otherwise hide, so the forged observation is a named
 * parameter, never an implicit constant.
 *
 * The oracle is the forgeability regression benchmark, preserved on
 * purpose: the test sweeps 100 generated programs of every live
 * version through the generator maximum and asserts every forged
 * trace verifies and digests. The trace is supplementary evidence,
 * reproducible by a pure implementation of the public semantics. A
 * grammar beyond the generator maximum must make this solver fail
 * until it implements those real Web Platform semantics; the oracle
 * extends only together with them.
 */
final class BrowserlessForgerySolver
{
    private function __construct()
    {
    }

    /**
     * Forge the browser-equivalent executed trace of a decoded program
     * with the given observed height as the observe choice. Any value
     * of 1..255 is legal and the whole u8 chain stays coherent with
     * it, so the solver is a pure function of the program and the
     * choice.
     *
     * @param array{format: int, scope: string, action: string, op_version: int, ops: list<array{op: int, operands: array<string, mixed>}>} $program
     */
    public static function solve(array $program, int $observedHeight): string
    {
        return ExecutionTraceFixture::executedTraceForWithObservedHeight($program, $observedHeight);
    }
}
