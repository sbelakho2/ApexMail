<?php

declare(strict_types=1);

namespace KiwiCaptcha\Risk\Tests;

/**
 * Deterministic LCG vector generator for the 10k parity anchor and the
 * monotonicity property tests.
 *
 *   x_{n+1} = (x_n * 6364136223846793005 + 1442695040888963407) mod 2^64
 *   seed 42; values = (x >> 11) % 1001
 *
 * The state is kept as (hi, lo) 32-bit halves so the arithmetic is exact on
 * PHP's signed 64-bit ints; the multiplication is folded mod 2^64 with
 * 16-bit pieces. This MUST produce the same stream as any implementation
 * using full-width unsigned math (verified against a Python reference).
 */
final class SeededVector
{
    private const A_HI = 0x5851F42D;
    private const A_LO = 0x4C957F2D;
    private const C_HI = 0x14057B7E;
    private const C_LO = 0xF767814F;

    private int $xHi = 0;
    private int $xLo = 42;

    /** Next value in 0..1000. */
    public function next(): int
    {
        $this->step();
        return ((($this->xHi << 21) | ($this->xLo >> 11)) % 1001);
    }

    /** Next 13 values as a signals array in contract order. */
    public function vector(): array
    {
        return [
            'source_fast' => $this->next(),
            'source_slow' => $this->next(),
            'subnet_fast' => $this->next(),
            'issue_debt' => $this->next(),
            'bad_proof' => $this->next(),
            'malformed' => $this->next(),
            'replay' => $this->next(),
            'action_failure' => $this->next(),
            'scope_switch' => $this->next(),
            'global_pressure' => $this->next(),
            'network_risk' => $this->next(),
            'trust_credit' => $this->next(),
            'principal_credit' => $this->next(),
        ];
    }

    private function step(): void
    {
        [$xHi, $xLo] = self::mulMod2_64($this->xHi, $this->xLo, self::A_HI, self::A_LO);
        $sum = $xLo + self::C_LO;
        $xLo = $sum & 0xFFFFFFFF;
        $carry = $sum >> 32;
        $xHi = ($xHi + self::C_HI + $carry) & 0xFFFFFFFF;
        $this->xHi = $xHi;
        $this->xLo = $xLo;
    }

    /** (a * b) mod 2^64 with (hi, lo) 32-bit halves of each operand. */
    private static function mulMod2_64(int $aHi, int $aLo, int $bHi, int $bLo): array
    {
        $m = static function (int $x, int $y): array {
            $xHi = ($x >> 16) & 0xFFFF;
            $xLo = $x & 0xFFFF;
            $yHi = ($y >> 16) & 0xFFFF;
            $yLo = $y & 0xFFFF;
            $low = $xLo * $yLo;
            $mid = $xHi * $yLo + $xLo * $yHi;
            $lowLo = $low & 0xFFFF;
            $lowHi = ($low >> 16) & 0xFFFF;
            $midLo = $mid & 0xFFFF;
            $midHi = ($mid >> 16) & 0xFFFF;
            $carry = $midLo + $lowHi;
            $lo = (($carry & 0xFFFF) << 16) | $lowLo;
            $hi = ($xHi * $yHi + $midHi + ($carry >> 16)) & 0xFFFFFFFF;
            return [$hi, $lo];
        };
        [$t1Hi, $t1Lo] = $m($aHi, $bLo);
        [$t2Hi, $t2Lo] = $m($aLo, $bHi);
        $tLo = ($t1Lo + $t2Lo) & 0xFFFFFFFF;
        $tCarry = ($t1Lo + $t2Lo) >> 32;
        $tHi = ($t1Hi + $t2Hi + $tCarry) & 0xFFFFFFFF;
        [$pH, $pL] = $m($bLo, $aLo);
        $hi = ($tLo + $pH) & 0xFFFFFFFF;
        $lo = $pL;
        return [$hi, $lo];
    }
}
