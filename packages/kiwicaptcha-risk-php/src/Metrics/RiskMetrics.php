<?php

declare(strict_types=1);

namespace KiwiCaptcha\Risk\Metrics;

/**
 * Aggregate, low-cardinality risk metrics. No identity labels are recorded.
 *
 * Decision counters use the tuple key "decisions:<scope>:<action>:<band>".
 * Gauges hold the latest value (e.g. global level, argon capacity ratio).
 * Latencies accumulate count + total for average computation.
 */
final class RiskMetrics
{
    /** @var array<string, int> */
    private array $counters = [];

    /** @var array<string, int|float> */
    private array $gauges = [];

    /** @var array<string, array{count:int, total:float}> */
    private array $latencies = [];

    public function increment(string $key, int $n = 1): void
    {
        $this->counters[$key] = ($this->counters[$key] ?? 0) + $n;
    }

    public function gauge(string $key, int|float $value): void
    {
        $this->gauges[$key] = $value;
    }

    public function recordLatency(string $key, float $milliseconds): void
    {
        $entry = $this->latencies[$key] ?? ['count' => 0, 'total' => 0.0];
        $entry['count']++;
        $entry['total'] += $milliseconds;
        $this->latencies[$key] = $entry;
    }

    public function snapshot(): array
    {
        $latencies = [];
        foreach ($this->latencies as $key => $entry) {
            $latencies[$key] = [
                'count' => $entry['count'],
                'avg_ms' => $entry['count'] > 0 ? $entry['total'] / $entry['count'] : 0.0,
            ];
        }
        return [
            'counters' => $this->counters,
            'gauges' => $this->gauges,
            'latencies' => $latencies,
        ];
    }

    public function reset(): void
    {
        $this->counters = [];
        $this->gauges = [];
        $this->latencies = [];
    }
}
