<?php

declare(strict_types=1);

namespace KiwiCaptcha\Tests\Support;

/**
 * The browserless shadow solver of the execution grammars. A dev-only
 * oracle forges verifier-accepted executed traces without a browser
 * for the pure-semantics rungs, versions 1 through 5. The
 * causal object-graph rung included. On version 6 this naive solver is
 * rejected only because it emits the pure-sim placeholders rather than
 * the operand-derived envelope entries; a forger who implements the
 * published envelopes (WhiteBoxEnvelopeForger) passes every version-6
 * program without a browser. This solver is the lazy-forger baseline,
 * not a boundary measurement.
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
 * purpose: the test sweeps 100 generated programs of every
 * pure-semantics version and asserts every forged trace verifies and
 * digests, then sweeps version 6 and asserts this naive solver (which
 * emits pure-sim placeholders) is rejected. That rejection is NOT a
 * full-knowledge number: the white-box forger (WhiteBoxEnvelopeForger)
 * reimplements the five published envelopes and passes every
 * version-6 program without a browser. Versions 1-5 and version 6
 * alike cost an attacker one reading of the source; the whole ladder
 * is supplementary evidence, never a browser boundary.
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
