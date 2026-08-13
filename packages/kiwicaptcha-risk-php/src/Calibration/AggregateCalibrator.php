<?php

declare(strict_types=1);

namespace KiwiCaptcha\Risk\Calibration;

use KiwiCaptcha\Risk\RiskAction;
use Predis\Client;

/**
 * Aggregate calibrator: REDIS-BACKED bounded score-bucket statistics.
 *
 * Buckets are hourly hashes keyed {kiwi:<ns>}:cal:<scope>:<hour> with one
 * HINCRBY per recorded outcome and a 48 h EXPIRE — at most 24 keys per
 * scope, so the aggregate state is bounded and shared across processes.
 * No in-process samples, no pruning loops.
 *
 * Bias is derived from the last 24 hourly buckets (legit_total vs
 * abuse_total), integer math truncating toward zero (intdiv):
 *   total = legit + abuse
 *   total < minSamples -> bias 0 (no nonzero bias below the threshold)
 *   raw   = ((abuse - legit) * 1000 / total) * 2 / 10
 *   bias  = clamp(raw, -maxAdjustment, +maxAdjustment)
 * The whole read (24 HGETALLs) plus the rate-of-change clamp plus the
 * state write runs in ONE Lua script (single round trip); the clamp is
 * atomic (read prev -> clamp -> write) so concurrent processes never race.
 *
 * Rate of change: the previous bias and its timestamp live in the hash
 * {kiwi:<ns>}:cal:state:<scope> (fields bias_mp/ts, bias in MILLI-POINTS
 * so the allowance is proportional to the elapsed time):
 *   allowed = maxChangePerMinute * 1000 * elapsedMs / 60000
 *   bias    = clamp(raw, prevBias - allowed, prevBias + allowed)
 * The first call ever seeds bias_mp = 0 / ts = now BEFORE the threshold
 * check, so a fresh scope can never jump straight to ±maxAdjustment; the
 * timestamp is refreshed on EVERY call (below threshold too), so a long
 * below-threshold period cannot accumulate movement allowance. Below the
 * threshold the returned bias is 0 and bias_mp is untouched.
 *
 * The final bias is cached in-process per scope for 30 s (bounded to
 * 1024 scopes, oldest evicted first); cache hits never touch Redis — the
 * 0-below-threshold result is cached too. record() invalidates the
 * cached entry for the recorded scope so fresh outcomes are visible
 * immediately.
 *
 * Receipts pair a decision_id with its scope/band/action so a later
 * confirmed outcome (legit/abuse) is recorded against the ORIGINAL
 * decision's bucket: {kiwi:<ns>}:cal:receipt:<decision_id> holds the JSON
 * string {"scope":..,"band":..,"action":".."} with EXPIRE 300 s, consumed
 * once, atomically, via GETDEL (string-only in Redis).
 */
final class AggregateCalibrator implements CalibrationStore
{
    public const WINDOW_HOURS = 24;
    public const BUCKET_TTL_SECS = 172800; // 48 h
    public const RECEIPT_TTL_SECS = 300;
    public const CACHE_TTL_SECS = 30;
    public const CACHE_CAP = 1024;

    /**
     * The canonical cross-language calibration script, bundled with this
     * package at resources/calibration.lua (self-contained — no monorepo
     * paths), resolved via dirname(__DIR__, 2) . '/resources/calibration.lua'
     * and loaded at construction like RedisRiskStateStore loads risk-v1.lua.
     *
     * One atomic read->clamp->write:
     *   KEYS[1..24]  hourly score buckets (hash, fields b<band>a<action>:legit|:abuse)
     *   KEYS[25]     rate-limit state (hash, fields bias_mp/ts)
     *   ARGV[1]      now (epoch ms)
     *   ARGV[2]      minSamples
     *   ARGV[3]      maxAdjustment (points)
     *   ARGV[4]      maxChangePerMinute (points/minute)
     * Returns the final integer bias (points).
     */
    private readonly string $script;

    private readonly string $namespace;

    /** @var array<int, array{bias:int, expiresAt:float}> bounded per-scope cache */
    private array $biasCache = [];

    public function __construct(
        private readonly Client $client,
        string $namespace = 'd',
        private readonly int $minSamples = 1000,
        private readonly int $maxAdjustment = 150,
        private readonly int $maxChangePerMinute = 10,
        private readonly int $receiptTtlSecs = self::RECEIPT_TTL_SECS,
    ) {
        if ($namespace === '' || preg_match('/[{}]/', $namespace)) {
            throw new \InvalidArgumentException('Calibration namespace must be non-empty and free of braces');
        }
        if ($minSamples < 1 || $maxAdjustment < 1 || $maxChangePerMinute < 1 || $receiptTtlSecs < 1) {
            throw new \InvalidArgumentException('minSamples, maxAdjustment, maxChangePerMinute and receiptTtlSecs must be >= 1');
        }
        $this->namespace = $namespace;
        $path = dirname(__DIR__, 2) . '/resources/calibration.lua';
        if (!is_file($path)) {
            throw new \RuntimeException(
                'Cannot locate the bundled calibration script at resources/calibration.lua ' .
                '(resolved from ' . __DIR__ . '). The script ships with this package.'
            );
        }
        $script = @file_get_contents($path);
        if ($script === false) {
            throw new \RuntimeException(sprintf('Cannot read the bundled calibration script at %s', $path));
        }
        $this->script = $script;
    }

    /**
     * Predis client with the contract timeouts: connection 5 ms,
     * read/write 10 ms (seconds in predis).
     */
    public static function createClient(string $url): Client
    {
        return new Client($url, [
            'connection' => [
                'timeout' => 0.005,
                'read_write_timeout' => 0.010,
            ],
        ]);
    }

    public function namespace(): string
    {
        return $this->namespace;
    }

    public function record(int $scope, int $band, RiskAction $action, bool $legitimate): void
    {
        // Invalidate the cached bias for this scope so a fresh outcome is
        // visible immediately (Rust parity).
        unset($this->biasCache[$scope]);
        $hour = intdiv((int) floor(microtime(true) * 1000), 3_600_000);
        $key = "{kiwi:{$this->namespace}}:cal:{$scope}:{$hour}";
        $field = sprintf('b%da%s:%s', $band, $action->value, $legitimate ? 'legit' : 'abuse');
        $this->client->hincrby($key, $field, 1);
        $this->client->expire($key, self::BUCKET_TTL_SECS);
    }

    public function biasForScope(int $scope, int $now): int
    {
        $nowFloat = microtime(true);
        $cached = $this->biasCache[$scope] ?? null;
        if ($cached !== null && $nowFloat < $cached['expiresAt']) {
            return $cached['bias'];
        }

        $hour = intdiv($now, 3_600_000);
        $keys = [];
        for ($i = 0; $i < self::WINDOW_HOURS; $i++) {
            $keys[] = "{kiwi:{$this->namespace}}:cal:{$scope}:" . ($hour - $i);
        }
        $keys[] = "{kiwi:{$this->namespace}}:cal:state:{$scope}";

        $bias = (int) $this->client->eval(
            $this->script,
            count($keys),
            ...array_merge($keys, [$now, $this->minSamples, $this->maxAdjustment, $this->maxChangePerMinute]),
        );

        if (count($this->biasCache) >= self::CACHE_CAP && !isset($this->biasCache[$scope])) {
            // Evict the oldest entry (array_shift would renumber the int
            // keys and corrupt the scope -> entry map, so unset instead).
            unset($this->biasCache[array_key_first($this->biasCache)]);
        }
        $this->biasCache[$scope] = ['bias' => $bias, 'expiresAt' => $nowFloat + self::CACHE_TTL_SECS];
        return $bias;
    }

    public function recordReceipt(string $decisionId, int $scope, int $band, RiskAction $action): void
    {
        $key = "{kiwi:{$this->namespace}}:cal:receipt:{$decisionId}";
        $this->client->set(
            $key,
            (string) json_encode(['scope' => $scope, 'band' => $band, 'action' => $action->value]),
            'EX',
            $this->receiptTtlSecs
        );
    }

    public function consumeReceipt(string $decisionId): ?array
    {
        $key = "{kiwi:{$this->namespace}}:cal:receipt:{$decisionId}";
        // GETDEL is string-only in Redis: the receipt is stored as a JSON
        // string, so one atomic GETDEL both reads and removes it.
        $result = $this->client->getdel($key);
        if (!is_string($result) || $result === '') {
            return null;
        }
        $data = json_decode($result, true);
        if (!is_array($data)) {
            return null;
        }
        return [
            'scope' => (int) ($data['scope'] ?? 0),
            'band' => (int) ($data['band'] ?? 0),
            'action' => (string) ($data['action'] ?? 'allow'),
        ];
    }
}
