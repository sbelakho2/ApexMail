<?php

declare(strict_types=1);

namespace KiwiCaptcha\Risk\Calibration;

use KiwiCaptcha\Risk\RiskAction;
use Predis\Client;

/**
 * Aggregate calibrator: REDIS-BACKED bounded exact-score calibration.
 *
 * Buckets are hourly hashes keyed {kiwi:<ns>}:cal:<scope>:<hour> with
 * fields legit_count / legit_score_sum / abuse_count / abuse_score_sum
 * (EXACT scores, not band-quantized), written ONLY by the canonical
 * confirm.lua script (atomic receipt consumption + HINCRBYFLOAT + EXPIRE
 * 48 h) — at most 24 keys per scope, so the aggregate state is bounded and
 * shared across processes. No in-process samples, no pruning loops.
 *
 * Bias is derived from the last 24 hourly buckets (calibration.lua,
 * CLASS-NORMALIZED exact-score semantics, round 6):
 *   fp_mean = legit_score_sum / legit_count        (0 when none)
 *   fn_mean = (abuse_count*1000 - abuse_score_sum) / abuse_count
 *   error   = fn_mean * falseNegativeCost - fp_mean * falsePositiveCost
 *   raw     = trunc(error * 2 / 10), clamped ±maxAdjustment
 * below minSamples the TARGET is 0. Class normalization removes
 * label-volume dominance; the fp/fn cost knobs price false positives
 * against false negatives explicitly. The whole read (24 HGETALLs) plus
 * the rate-of-change clamp plus the state write runs in ONE Lua script
 * (single round trip); the clamp is atomic (read prev -> clamp -> write)
 * so concurrent processes never race.
 *
 * RANDOM-SAMPLE RESOLUTION GATE (KEYS[26]/KEYS[27] of calibration.lua):
 * in random_sample mode the bias target stays 0 while sample_total >=
 * minSamples AND sample_resolved < sample_total * minimumResolutionRatio
 * — the label-reporting process must demonstrably resolve a minimum
 * fraction of the server-selected sample before the model may move. The
 * TOTAL counter is booked by sample()/markSampled() at assessment time
 * (one INCR per sampled decision); the RESOLVED counter is INCRed by
 * confirm.lua on a status-1 confirmation.
 *
 * Rate of change: the previous bias and its timestamp live in the hash
 * {kiwi:<ns>}:cal:state:<scope> (fields bias_mp/ts, bias in MILLI-POINTS
 * so the allowance is proportional to the elapsed time):
 *   allowed = maxChangePerMinute * 1000 * elapsedMs / 60000
 *   bias    = clamp(raw, prevBias - allowed, prevBias + allowed)
 * The clock is Redis TIME (the script derives `now` itself; the ARGV[1]
 * nowMs slot is informational), so the allowance follows the distributed
 * clock authority, never app-node skew. The first call ever seeds
 * bias_mp = 0 / ts = now BEFORE the threshold check, so a fresh scope can
 * never jump straight to ±maxAdjustment; the timestamp is refreshed on
 * EVERY call (below threshold too), so a long below-threshold period
 * cannot accumulate movement allowance. Below the threshold the returned
 * bias is 0 but the stored bias_mp still moves toward 0 through the SAME
 * rate limiter (never an instant snap).
 *
 * The final bias is cached in-process per scope for 30 s (bounded to
 * 1024 scopes, oldest evicted first); cache hits never touch Redis — the
 * 0-below-threshold result is cached too. confirmOutcome() invalidates the
 * cached entry for the confirmed scope on status 1 or 2 (both are FIRST
 * confirmations; status 2 is a consumed outcome too — the cache would
 * otherwise go stale relative to the namespace counters the gate reads).
 *
 * Receipts pair a decision_id with its scope/band/action/score/sampled so
 * a later confirmed outcome (legit/abuse) is recorded against the ORIGINAL
 * decision's scope bucket: {kiwi:<ns>}:cal:receipt:<decision_id> holds the
 * JSON string {"scope":..,"band":..,"action":"..","score":..,"sampled":0|1}
 * with EXPIRE 300 s, consumed EXACTLY ONCE, atomically, by the canonical
 * confirm.lua script (GET -> validate mode/weight -> DEL -> HINCRBYFLOAT
 * -> EXPIRE in one round trip — no crash window between reading and
 * incrementing; argument validation happens BEFORE the DEL, so an invalid
 * mode/weight leaves the receipt intact). In random_sample mode an
 * unsampled decision (sampled == 0) is CONSUMED with status 2 — never
 * recorded, so the label can never select itself into the population.
 *
 * confirmOutcome() returns the SHARED accepted-outcome status (wire
 * contract with the Rust mirror): 0 = nothing consumed (missing / already
 * confirmed / corrupt), 1 = FIRST confirmation recorded (calibration +
 * resolved counter in random_sample mode), 2 = FIRST confirmation,
 * deliberately unsampled (consumed, no calibration). Statuses 1 and 2
 * both mean "first confirmation" — the engine books the first-party
 * reputation event exactly once; status 0 must not book any.
 */
final class AggregateCalibrator implements CalibrationStore
{
    public const WINDOW_HOURS = 24;
    public const BUCKET_TTL_SECS = 172800; // 48 h
    public const RECEIPT_TTL_SECS = 300;
    public const CACHE_TTL_SECS = 30;
    public const CACHE_CAP = 1024;
    public const DEFAULT_MIN_RESOLUTION_RATIO = 0.80;
    public const DEFAULT_FALSE_POSITIVE_COST = 1.0;
    public const DEFAULT_FALSE_NEGATIVE_COST = 2.0;

    private const MODE_COMPLETE = 0;
    private const MODE_RANDOM_SAMPLE = 1;
    private const MODE_WEIGHTED = 2;

    /**
     * The canonical cross-language scripts, bundled with this package at
     * resources/calibration.lua and resources/confirm.lua (self-contained —
     * no monorepo paths), resolved via dirname(__DIR__, 2) . '/resources/'
     * and loaded at construction like RedisRiskStateStore loads risk-v1.lua.
     *
     * calibration.lua — one atomic read->clamp->write:
     *   KEYS[1..24]  hourly score buckets (hash, fields legit_count /
     *                legit_score_sum / abuse_count / abuse_score_sum)
     *   KEYS[25]     rate-limit state (hash, fields bias_mp/ts)
     *   KEYS[26]     sampled-total counter (random_sample mode)
     *   KEYS[27]     sampled-resolved counter (random_sample mode)
     *   ARGV[1]      now (epoch ms — informational; the script's rate-limit
     *                clock is Redis TIME)
     *   ARGV[2]      minSamples
     *   ARGV[3]      maxAdjustment (points)
     *   ARGV[4]      maxChangePerMinute (points/minute)
     *   ARGV[5]      minimumResolutionRatio (float 0..1; 0 disables the gate)
     *   ARGV[6]      sampling mode (0 complete | 1 random_sample | 2 weighted)
     *   ARGV[7]      falsePositiveCost (float)
     *   ARGV[8]      falseNegativeCost (float)
     *   Returns the final integer bias (points).
     *
     * confirm.lua — one atomic consume-and-record (argument validation
     * BEFORE the receipt is deleted):
     *   KEYS[1]      receipt (STRING JSON)
     *   KEYS[2]      hourly bucket for receipt.scope
     *   KEYS[3]      sampled-resolved counter (random_sample mode)
     *   ARGV[1]      mode (0 complete | 1 random_sample | 2 weighted)
     *   ARGV[2]      weight (float; required and validated when mode == 2)
     *   ARGV[3]      legitimate (0/1)
     *   ARGV[4]      bucket TTL (seconds)
     *   Returns the shared status: 0 missing/already confirmed, 1 first
     *   confirmation recorded, 2 first confirmation deliberately unsampled.
     */
    private readonly string $calibrationScript;

    private readonly string $confirmScript;

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
        private readonly string $samplingMode = 'random_sample',
        private readonly int $samplingProbabilityPpm = 100_000,
        private readonly float $minimumResolutionRatio = self::DEFAULT_MIN_RESOLUTION_RATIO,
        private readonly float $falsePositiveCost = self::DEFAULT_FALSE_POSITIVE_COST,
        private readonly float $falseNegativeCost = self::DEFAULT_FALSE_NEGATIVE_COST,
    ) {
        if ($namespace === '' || preg_match('/[{}]/', $namespace)) {
            throw new \InvalidArgumentException('Calibration namespace must be non-empty and free of braces');
        }
        if ($minSamples < 1 || $maxAdjustment < 1 || $maxChangePerMinute < 1 || $receiptTtlSecs < 1) {
            throw new \InvalidArgumentException('minSamples, maxAdjustment, maxChangePerMinute and receiptTtlSecs must be >= 1');
        }
        if (!in_array($samplingMode, ['complete', 'random_sample', 'weighted'], true)) {
            throw new \InvalidArgumentException('samplingMode must be one of: complete, random_sample, weighted');
        }
        if ($samplingProbabilityPpm < 1 || $samplingProbabilityPpm > 1_000_000) {
            throw new \InvalidArgumentException('samplingProbabilityPpm must be within 1..1000000');
        }
        if ($minimumResolutionRatio < 0.0 || $minimumResolutionRatio > 1.0) {
            throw new \InvalidArgumentException('minimumResolutionRatio must be within 0..1');
        }
        if ($falsePositiveCost < 0.1 || $falsePositiveCost > 10.0
            || $falseNegativeCost < 0.1 || $falseNegativeCost > 10.0) {
            throw new \InvalidArgumentException('falsePositiveCost and falseNegativeCost must be within 0.1..10.0');
        }
        $this->namespace = $namespace;
        $this->calibrationScript = self::loadScript('calibration.lua');
        $this->confirmScript = self::loadScript('confirm.lua');
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

    /**
     * The assessment-time sampling decision: 'complete' and 'weighted'
     * always sample (in weighted mode the HOST governs the rate via the
     * weight it supplies at confirmation); 'random_sample' samples with
     * probability samplingProbabilityPpm / 1_000_000. A sampled decision
     * in random_sample mode ALSO books the namespace-wide sampled-TOTAL
     * counter {kiwi:<ns>}:cal:sample:total (one INCR per sampled decision)
     * — the resolution-gate denominator; complete/weighted never touch the
     * counters (the gate applies only to random_sample).
     */
    public function sample(): bool
    {
        if ($this->samplingMode !== 'random_sample') {
            return true;
        }
        if (random_int(0, 999_999) >= $this->samplingProbabilityPpm) {
            return false;
        }
        $this->markSampled();
        return true;
    }

    /**
     * Assessment-time accounting hook: books ONE sampled decision into the
     * sampled-TOTAL counter {kiwi:<ns>}:cal:sample:total. Only random_sample
     * mode touches the counter (the resolution gate applies exclusively to
     * it); complete/weighted are no-ops.
     */
    public function markSampled(): void
    {
        if ($this->samplingMode !== 'random_sample') {
            return;
        }
        $this->client->incr("{kiwi:{$this->namespace}}:cal:sample:total");
    }

    /**
     * Reserves the once-only correction slot for a decision: SET NX
     * {kiwi:<ns>}:cal:corrected:<hex(sha256($decisionId))> EX receiptTtl —
     * the receipt is already consumed by the first confirmation, so this
     * guard is the only protection against double-compensation. Returns
     * true when THIS call won the slot (the engine may record its
     * compensating event); false when the decision was already corrected.
     */
    public function reserveCorrection(string $decisionId): bool
    {
        $key = "{kiwi:{$this->namespace}}:cal:corrected:" . hash('sha256', $decisionId);
        $result = $this->client->set($key, '1', 'NX', 'EX', $this->receiptTtlSecs);
        return $result !== null;
    }

    public function recordReceipt(string $decisionId, int $scope, int $band, RiskAction $action, int $score, int $sampled): void
    {
        $key = "{kiwi:{$this->namespace}}:cal:receipt:{$decisionId}";
        $this->client->set(
            $key,
            (string) json_encode([
                'scope' => $scope,
                'band' => $band,
                'action' => $action->value,
                'score' => $score,
                'sampled' => $sampled ? 1 : 0,
            ]),
            'EX',
            $this->receiptTtlSecs
        );
    }

    /**
     * Atomically consumes the receipt and records the outcome in ONE
     * canonical confirm.lua script (no crash window between GETDEL and the
     * bucket increment). The bucket is the CURRENT hour of the receipt's
     * scope; the bucket hour for a decision can never drift because the
     * receipt is immutable once written (the pre-read only derives the
     * bucket key — the script itself re-checks the receipt atomically).
     *
     * Returns the SHARED accepted-outcome status (wire contract with the
     * Rust mirror):
     *   0 = nothing consumed (receipt missing / already confirmed / corrupt)
     *   1 = FIRST confirmation; calibration recorded (+ the sampled-resolved
     *       counter in random_sample mode)
     *   2 = FIRST confirmation; deliberately unsampled in random_sample
     *       mode (consumed, no calibration, no counter)
     * Status 1 and 2 both invalidate the scope's cached bias (a status-2
     * outcome is consumed too — the cache would otherwise go stale relative
     * to the namespace counters the resolution gate reads).
     */
    public function confirmOutcome(string $decisionId, bool $legitimate, ?float $weight = null): int
    {
        $receiptKey = "{kiwi:{$this->namespace}}:cal:receipt:{$decisionId}";
        $raw = $this->client->get($receiptKey);
        if (!is_string($raw) || $raw === '') {
            return 0;
        }
        $data = json_decode($raw, true);
        if (!is_array($data)) {
            return 0;
        }
        $scope = (int) ($data['scope'] ?? 0);
        if ($scope < 1) {
            return 0;
        }
        $hour = intdiv((int) floor(microtime(true) * 1000), 3_600_000);
        $bucketKey = "{kiwi:{$this->namespace}}:cal:{$scope}:{$hour}";
        $resolvedKey = "{kiwi:{$this->namespace}}:cal:sample:resolved";

        $mode = match ($this->samplingMode) {
            'complete' => self::MODE_COMPLETE,
            'weighted' => self::MODE_WEIGHTED,
            default => self::MODE_RANDOM_SAMPLE,
        };

        $status = (int) $this->client->eval(
            $this->confirmScript,
            3,
            $receiptKey,
            $bucketKey,
            $resolvedKey,
            (string) $mode,
            (string) ($weight ?? 1.0),
            $legitimate ? '1' : '0',
            (string) self::BUCKET_TTL_SECS,
        );

        if ($status !== 0) {
            // A FIRST confirmation (status 1 or 2) invalidates the cached
            // bias for this scope so a fresh outcome is visible immediately
            // (Rust parity).
            unset($this->biasCache[$scope]);
        }
        return $status;
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
        $keys[] = "{kiwi:{$this->namespace}}:cal:sample:total";
        $keys[] = "{kiwi:{$this->namespace}}:cal:sample:resolved";

        $mode = match ($this->samplingMode) {
            'complete' => self::MODE_COMPLETE,
            'weighted' => self::MODE_WEIGHTED,
            default => self::MODE_RANDOM_SAMPLE,
        };

        $bias = (int) $this->client->eval(
            $this->calibrationScript,
            count($keys),
            ...array_merge($keys, [
                $now,
                $this->minSamples,
                $this->maxAdjustment,
                $this->maxChangePerMinute,
                $this->minimumResolutionRatio,
                $mode,
                $this->falsePositiveCost,
                $this->falseNegativeCost,
            ]),
        );

        if (count($this->biasCache) >= self::CACHE_CAP && !isset($this->biasCache[$scope])) {
            // Evict the oldest entry (array_shift would renumber the int
            // keys and corrupt the scope -> entry map, so unset instead).
            unset($this->biasCache[array_key_first($this->biasCache)]);
        }
        $this->biasCache[$scope] = ['bias' => $bias, 'expiresAt' => $nowFloat + self::CACHE_TTL_SECS];
        return $bias;
    }

    private static function loadScript(string $file): string
    {
        $path = dirname(__DIR__, 2) . '/resources/' . $file;
        if (!is_file($path)) {
            throw new \RuntimeException(
                sprintf('Cannot locate the bundled script at resources/%s (resolved from %s). The script ships with this package.', $file, __DIR__)
            );
        }
        $script = @file_get_contents($path);
        if ($script === false) {
            throw new \RuntimeException(sprintf('Cannot read the bundled script at %s', $path));
        }
        return $script;
    }
}
