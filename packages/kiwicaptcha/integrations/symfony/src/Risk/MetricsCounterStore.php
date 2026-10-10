<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Risk;

/**
 * The exporter's cross-worker counter aggregation: APCu-inc'd,
 * TTL-bounded, per-deployment namespaced keys.
 *
 * The risk engine's own {@see \KiwiCaptcha\Risk\Metrics\RiskMetrics}
 * counters live in process memory, so the metrics exporter and the
 * outcome bridge push their exportable increments through this store
 * instead. With the APCu extension loaded the counters aggregate
 * across the workers of one deployment. Without it the store degrades
 * to per-process counters, and the exporter answers with a scope
 * header saying so, never a silent lie about the aggregation scope.
 *
 * Series names are a bounded, redacted vocabulary: fixed tokens joined
 * by colons (outcome wire names, booked/skipped results, canonical
 * scope ids). A name that fails the shape check is refused, never
 * stored, so no identity bytes can enter a key. APCu cannot enumerate
 * keys by prefix, so a bounded index key holds the known series list
 * and reads resolve the members explicitly.
 */
final class MetricsCounterStore
{
    /** Every counter key carries this bound, so abandoned deployments expire. */
    public const TTL_SECS = 86400;

    private const SERIES_PATTERN = '/^[a-zA-Z0-9][a-zA-Z0-9_:-]{0,127}$/D';

    /** @var array<string, int> the per-process fallback counters */
    private array $local = [];

    /**
     * @param string      $keyPrefix the per-deployment key prefix,
     *                               namespace and secret derived, like
     *                               the health controller's APCu keys
     * @param \Closure|null $apcu    APCu override (tests): a seam over
     *                               the shared segment with the
     *                               operations 'fetch', 'inc' and
     *                               'store'. Null uses the real APCu
     *                               when loaded.
     */
    public function __construct(
        private readonly string $keyPrefix,
        private readonly ?\Closure $apcu = null,
    ) {
    }

    /**
     * True when the counters aggregate across the workers of one
     * deployment (the APCu lane); false when they are per-process.
     */
    public function shared(): bool
    {
        return $this->apcu !== null || \function_exists('apcu_inc');
    }

    /**
     * Increments one series. A series name outside the bounded shape is
     * refused (never stored), so the redaction contract holds even for
     * a mistaken caller.
     */
    public function increment(string $series, int $n = 1): void
    {
        if ($n === 0 || preg_match(self::SERIES_PATTERN, $series) !== 1) {
            return;
        }
        if (!$this->shared()) {
            $this->local[$series] = ($this->local[$series] ?? 0) + $n;
            $this->local['.index'] = array_values(array_unique(array_merge(
                \is_array($this->local['.index'] ?? null) ? $this->local['.index'] : [],
                [$series],
            )));

            return;
        }
        $this->apcuInc($this->key($series), $n);
        $this->indexSeries($series);
    }

    /**
     * Every known series with its current value. Unknown or unreadable
     * entries answer 0, never an error: a scrape must degrade to zeros,
     * not fail.
     *
     * @return array<string, int>
     */
    public function all(): array
    {
        $series = $this->index();
        $values = [];
        foreach ($series as $name) {
            $value = $this->shared() ? $this->apcuFetch($this->key($name)) : ($this->local[$name] ?? null);
            $values[$name] = \is_int($value) ? $value : 0;
        }
        ksort($values);

        return $values;
    }

    /**
     * The bounded series index key: APCu offers no prefix enumeration,
     * so the index holds the known names and reads resolve members
     * explicitly. Concurrent first-increments may append twice; the
     * read path collapses duplicates, and the bounded vocabulary keeps
     * the key small.
     *
     * @return list<string>
     */
    private function index(): array
    {
        $raw = $this->shared() ? $this->apcuFetch($this->key('.index')) : ($this->local['.index'] ?? null);
        if (!\is_array($raw)) {
            return [];
        }
        $names = [];
        foreach ($raw as $name) {
            if (\is_string($name) && preg_match(self::SERIES_PATTERN, $name) === 1) {
                $names[$name] = true;
            }
        }

        return array_keys($names);
    }

    private function indexSeries(string $series): void
    {
        $key = $this->key('.index');
        $raw = $this->apcuFetch($key);
        if (\is_array($raw) && \in_array($series, $raw, true)) {
            return;
        }
        $raw = \is_array($raw) ? $raw : [];
        $raw[] = $series;
        $this->apcuStore($key, array_values(array_unique($raw)));
    }

    private function key(string $series): string
    {
        return $this->keyPrefix.'.'.$series;
    }

    private function apcuInc(string $key, int $n): void
    {
        if ($this->apcu !== null) {
            ($this->apcu)('inc', $key, $n, self::TTL_SECS);

            return;
        }
        if (!\function_exists('apcu_inc')) {
            return;
        }
        $ok = false;
        // The TTL applies when the increment creates the key; an
        // existing key keeps its original bounded expiry.
        @apcu_inc($key, $n, $ok, self::TTL_SECS);
        if (!$ok && \function_exists('apcu_add')) {
            // A lost create race (a concurrent worker created then
            // removed the key): initialize and retry once.
            @apcu_add($key, 0, self::TTL_SECS);
            @apcu_inc($key, $n, $ok, self::TTL_SECS);
        }
    }

    private function apcuStore(string $key, mixed $value): void
    {
        if ($this->apcu !== null) {
            ($this->apcu)('store', $key, $value, self::TTL_SECS);

            return;
        }
        if (!\function_exists('apcu_store')) {
            return;
        }
        @apcu_store($key, $value, self::TTL_SECS);
    }

    private function apcuFetch(string $key): mixed
    {
        if ($this->apcu !== null) {
            return ($this->apcu)('fetch', $key);
        }
        if (!\function_exists('apcu_fetch')) {
            return null;
        }
        $ok = false;
        $value = @apcu_fetch($key, $ok);
        if (!$ok) {
            return null;
        }

        return $value;
    }
}
