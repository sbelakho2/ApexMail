<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Economics;

/**
 * The value-class pricing ceiling: the honest answer to the economics
 * finding that raw proof-of-work cannot price an arbitrarily valuable
 * action. Every rung's ceiling is the bench-measured attacker cost per
 * 1000 solves on the release bench host; the declared default of a
 * class is that anchor divided by the calibration margin, so the
 * shipped defaults always price inside their rung. A scope whose real
 * declared stake exceeds the ceiling cannot buy its protection from
 * the proof-of-work ladder at any difficulty. The documented answer is
 * the disposition escalation: the scope's risk minimum action
 * (risk.scopes.<name>.minimum in the bundle configuration) set to
 * step_up or deny, which the risk stage enforces underneath every
 * signal.
 *
 * This is the same calibration the solver's reference-costs.json
 * ships; the const table is pinned to that file by a test, so the two
 * surfaces cannot drift.
 */
final class ValueClassCeiling
{
    /**
     * The calibrated class table: rung, the declared default abuse
     * value, and the measured ceiling (the anchor the default derives
     * from), all dollars per 1000 solves.
     */
    public const PRICING = [
        'low' => ['rung' => 'sha16', 'declared_usd_per_1000' => 10.0, 'ceiling_usd_per_1000' => 0.000937],
        'standard' => ['rung' => 'sha18', 'declared_usd_per_1000' => 500.0, 'ceiling_usd_per_1000' => 0.001962],
        'high' => ['rung' => 'argon16', 'declared_usd_per_1000' => 5000.0, 'ceiling_usd_per_1000' => 0.001225],
        'critical' => ['rung' => 'argon64', 'declared_usd_per_1000' => 50000.0, 'ceiling_usd_per_1000' => 0.00421],
    ];

    /**
     * The verdict for one scope's value class and its configured
     * minimum action. A stake inside the ceiling prices normally; a
     * stake beyond the ceiling is answered with the escalation advice
     * (or the verified pass once a step_up or deny minimum carries it).
     *
     * @param array<string, array{rung: string, declared_usd_per_1000: float, ceiling_usd_per_1000: float}>|null $pricing
     *
     * @return array{0: string, 1: string} [status, detail]
     */
    public static function verdict(string $valueClass, string $minimumAction, ?array $pricing = null, ?float $stakeUsd = null): array
    {
        $pricing ??= self::PRICING;
        $row = $pricing[$valueClass] ?? null;
        if ($row === null) {
            return ['WARN', sprintf('unknown value class "%s"; the calibrated classes are %s', $valueClass, implode(', ', array_keys($pricing)))];
        }
        if ($stakeUsd !== null && $stakeUsd > 0) {
            // A per-action stake override: the value of one successful
            // abuse of this action replaces the class default.
            $row = [
                'rung' => $row['rung'],
                'declared_usd_per_1000' => $stakeUsd * 1000,
                'ceiling_usd_per_1000' => $row['ceiling_usd_per_1000'],
            ];
        }

        $declared = sprintf('%.5g', $row['declared_usd_per_1000']);
        $ceiling = sprintf('%.5g', $row['ceiling_usd_per_1000']);
        if ($row['declared_usd_per_1000'] <= $row['ceiling_usd_per_1000']) {
            return ['PASS', sprintf(
                'value class "%s" on %s declares $%s per 1000, inside the measured ceiling $%s per 1000 (the calibration margin applies); the scope minimum is "%s"',
                $valueClass,
                $row['rung'],
                $declared,
                $ceiling,
                $minimumAction,
            )];
        }

        if ($minimumAction === 'step_up' || $minimumAction === 'deny') {
            return ['PASS', sprintf(
                'value class "%s" declares $%s per 1000, beyond what any %s solve can price (measured ceiling $%s per 1000); the scope minimum "%s" carries the stake the proof of work cannot (verified)',
                $valueClass,
                $declared,
                $row['rung'],
                $ceiling,
                $minimumAction,
            )];
        }

        return ['WARN', sprintf(
            'value class "%s" declares $%s per 1000, beyond what any %s solve can price (measured ceiling $%s per 1000): raw proof of work cannot price this scope at any difficulty. Escalate the scope\'s disposition policy: set risk.scopes.<name>.minimum to step_up or deny (the risk-stage minimum actions are the enforcement knob)',
            $valueClass,
            $declared,
            $row['rung'],
            $ceiling,
        )];
    }
}
