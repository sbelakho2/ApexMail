<?php

declare(strict_types=1);

namespace KiwiCaptcha\Tests\Support;

/**
 * The browserless shadow solver of the execution grammars. It forges
 * verifier-accepted executed traces without a browser. It covers the
 * pure-semantics rungs, versions 1 through 5. That includes the
 * causal-object-graph rung. On version 6 the naive solver is rejected.
 * It emits pure-sim placeholders instead of operand-derived envelope
 * entries. A forger who implements the published envelopes passes
 * every version-6 program without a browser. See WhiteBoxEnvelopeForger.
 * This solver is the lazy-forger baseline.
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
