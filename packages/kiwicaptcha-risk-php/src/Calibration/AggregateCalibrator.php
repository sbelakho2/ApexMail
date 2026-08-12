<?php

declare(strict_types=1);

namespace KiwiCaptcha\Risk\Calibration;

use KiwiCaptcha\Risk\RiskAction;

/**
 * Aggregate calibrator implementing the bounded adjustment rules:
 *
 * - retention: 24 h (samples are pruned on every record/bias read)
 * - minimum sample gate: 1000 per scope before any bias is computed
 * - bias range: -100..+150
 * - max change: 10 points per elapsed minute of application
 * - hysteresis: a new direction must hold for 10 minutes before it applies
 *
 * Raw bias is derived from the legitimate rate: raw = round((0.5 - rate) * 300),
 * clamped to the bias range (rate 0 -> +150, rate 1 -> -100, rate 0.5 -> 0).
 */
final class AggregateCalibrator implements CalibrationStore
{
    public const RETENTION_SECS = 86400;
    public const MIN_SAMPLES = 1000;
    public const BIAS_MIN = -100;
    public const BIAS_MAX = 150;
    public const MAX_CHANGE_PER_MIN = 10;
    public const HYSTERESIS_SECS = 600;

    /** @var array<int, list<array{ts:int, band:int, action:int, legitimate:bool}>> */
    private array $samples = [];

    /** @var array<int, array{ts:int, bias:int}> */
    private array $applied = [];

    /** @var array<int, array{ts:int, dir:int}> */
    private array $direction = [];

    /** @var callable(): int */
    private $clock;

    public function __construct(
        ?callable $clock = null,
        private readonly int $retentionSecs = self::RETENTION_SECS,
        private readonly int $minSamples = self::MIN_SAMPLES,
        private readonly int $maxAdjustment = self::BIAS_MAX,
        private readonly int $maxChangePerMinute = self::MAX_CHANGE_PER_MIN,
    ) {
        $this->clock = $clock ?? static fn (): int => time();
    }

    public function record(int $scope, int $band, RiskAction $action, bool $legitimate): void
    {
        $now = ($this->clock)();
        $this->prune($now);
        $this->samples[$scope][] = [
            'ts' => $now,
            'band' => $band,
            'action' => $action->rank(),
            'legitimate' => $legitimate,
        ];
    }

    public function biasForScope(int $scope, int $now): int
    {
        $this->prune($now);
        $samples = $this->samples[$scope] ?? [];
        if (count($samples) < $this->minSamples) {
            return 0;
        }

        $legit = 0;
        foreach ($samples as $s) {
            if ($s['legitimate']) {
                $legit++;
            }
        }
        $rate = $legit / count($samples);
        $raw = (int) round((0.5 - $rate) * 300.0);
        $raw = max(self::BIAS_MIN, min($this->maxAdjustment, $raw));

        $prev = $this->applied[$scope]['bias'] ?? 0;
        $dir = $raw <=> $prev;

        if ($dir === 0) {
            return $prev;
        }
        $current = $this->direction[$scope] ?? null;
        if ($current === null || $current['dir'] !== $dir) {
            $this->direction[$scope] = ['ts' => $now, 'dir' => $dir];
            return $prev;
        }
        if ($now - $current['ts'] < self::HYSTERESIS_SECS) {
            return $prev;
        }

        $lastAppliedTs = $this->applied[$scope]['ts'] ?? $now - self::HYSTERESIS_SECS;
        $elapsedMin = max(1, ($now - $lastAppliedTs) / 60.0);
        $allowed = $this->maxChangePerMinute * $elapsedMin;
        $delta = (int) round(max(-$allowed, min($allowed, $raw - $prev)));
        $next = $prev + $delta;

        $this->applied[$scope] = ['ts' => $now, 'bias' => $next];
        return $next;
    }

    private function prune(int $now): void
    {
        $cutoff = $now - $this->retentionSecs;
        foreach ($this->samples as $scope => $list) {
            $kept = [];
            foreach ($list as $s) {
                if ($s['ts'] > $cutoff) {
                    $kept[] = $s;
                }
            }
            if ($kept === []) {
                unset($this->samples[$scope]);
            } else {
                $this->samples[$scope] = $kept;
            }
        }
    }
}
