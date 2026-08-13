<?php

declare(strict_types=1);

namespace KiwiCaptcha\Risk\Calibration;

use KiwiCaptcha\Risk\RiskAction;
use Predis\Client;

/**
 * Aggregate calibrator: REDIS-BACKED bounded exact-score calibration.
 *
 * Buckets are hourly hashes keyed {kiwi:<ns>}:cal:<scope>:<hour> with
 * fields legit_count / legit_score_sum / abuse_count / abuse_score_sum /
 * sample_total / sample_resolved (EXACT scores, not band-quantized),
 * written ONLY by the canonical register_decision.lua / confirm.lua /
 * correction.lua scripts — at most 24 keys per scope, so the aggregate
 * state is bounded and shared across processes. No in-process samples, no
 * pruning loops.
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
 * RANDOM-SAMPLE RESOLUTION GATE (round 7): the counters live in the SAME
 * scope/hour buckets as the observations (sample_total / sample_resolved
 * hash fields), so scope, window, label population and resolution
 * population are exactly ONE cohort. In random_sample mode the bias target
 * stays 0 while the PER-SCOPE 24-bucket sample_total >= minSamples AND
 * sample_resolved < sample_total * minimumResolutionRatio — the
 * label-reporting process must demonstrably resolve a minimum fraction of
 * the server-selected sample before the model may move. The TOTAL is
 * booked ATOMICALLY with the receipt by register_decision.lua (HINCRBY
 * sample_total when sampled — a sample can never be counted without its
 * receipt); the RESOLVED counter is INCRed by confirm.lua on a status-1
 * confirmation.
 *
 * THE OUTCOME LEDGER IS ALWAYS ON and independent of calibration:
 * register_decision.lua creates the PENDING ledger entry
 * ({kiwi:<ns>}:cal:ledger:<decision_id>, JSON {"o":"P","scope","hour","score","w"})
 * ATOMICALLY with the receipt and denominator; confirm.lua performs the
 * ledger CAS PENDING -> LEGITIMATE/ABUSE exactly once and — as the
 * downstream observer — records the calibration bucket contribution;
 * correction.lua flips the ledger L <-> A and reverses/redoes the bucket
 * contribution. Confirmed outcomes work identically with or without
 * calibration; with calibration disabled the STORE writes the same ledger
 * (outcome_register/outcome_confirm/outcome_correct.lua) under the same
 * key.
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
 * decision's DECISION-TIME scope bucket: {kiwi:<ns>}:cal:receipt:<decision_id>
 * holds the JSON string
 * {"scope":..,"band":..,"action":"..","decision_hour":..,"score":..,"sampled":0|1}
 * with EXPIRE 300 s, created ATOMICALLY by register_decision.lua and
 * consumed EXACTLY ONCE, atomically, by the canonical confirm.lua script
 * (GET -> validate mode/weight/scope/hour -> DEL -> ledger CAS ->
 * HINCRBYFLOAT -> EXPIRE in one round trip — no crash window between
 * reading and incrementing; argument validation happens BEFORE any change,
 * so an invalid mode/weight leaves the receipt intact). In random_sample
 * mode an unsampled decision (sampled == 0) is CONSUMED with status 2 —
 * never recorded, so the label can never select itself into the
 * population.
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
    public const DEFAULT_OUTCOME_TTL_SECS = 86400;
    public const DEFAULT_MIN_RESOLUTION_RATIO = 0.80;
    public const DEFAULT_FALSE_POSITIVE_COST = 1.0;
    public const DEFAULT_FALSE_NEGATIVE_COST = 2.0;

    private const MODE_COMPLETE = 0;
    private const MODE_RANDOM_SAMPLE = 1;
    private const MODE_WEIGHTED = 2;

    /**
     * The canonical cross-language scripts, bundled with this package at
     * resources/ (self-contained — no monorepo paths), resolved via
     * dirname(__DIR__, 2) . '/resources/' and loaded at construction like
     * RedisRiskStateStore loads risk-v1.lua.
     *
     * calibration.lua — one atomic read->clamp->write:
     *   KEYS[1..24]  hourly score buckets (hash, fields legit_count /
     *                legit_score_sum / abuse_count / abuse_score_sum /
     *                sample_total / sample_resolved)
     *   KEYS[25]     rate-limit state (hash, fields bias_mp/ts)
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
     * register_decision.lua — receipt + sample denominator + PENDING
     * ledger entry in ONE atomic invocation:
     *   KEYS[1]      receipt (STRING JSON)
     *   KEYS[2]      decision-time calibration bucket for (scope, hour)
     *   KEYS[3]      outcome ledger entry (STRING JSON)
     *   ARGV[1]      receipt JSON
     *   ARGV[2]      receipt TTL (seconds)
     *   ARGV[3]      sampled (1/0)
     *   ARGV[4]      bucket TTL (seconds)
     *   ARGV[5]      outcome ledger TTL (seconds)
     *   ARGV[6]      scope
     *   ARGV[7]      decision_hour
     *   ARGV[8]      score
     *   ARGV[9]      weight (1.0 at registration)
     *   Returns 1 when registered, 0 when the decision_id already exists.
     *
     * confirm.lua — one atomic consume-and-record (argument validation
     * BEFORE any deletion or state change; the ledger is the exactly-once
     * authority, calibration is a downstream observer of the same script):
     *   KEYS[1]      receipt (STRING JSON)
     *   KEYS[2]      DECISION-TIME calibration bucket (receipt.scope,
     *                receipt.decision_hour)
     *   KEYS[3]      outcome ledger entry (STRING JSON)
     *   ARGV[1]      mode (0 complete | 1 random_sample | 2 weighted)
     *   ARGV[2]      weight (float; required and validated when mode == 2)
     *   ARGV[3]      legitimate (0/1)
     *   ARGV[4]      bucket TTL (seconds)
     *   ARGV[5]      outcome ledger TTL (seconds)
     *   ARGV[6]      expected scope
     *   ARGV[7]      expected decision_hour
     *   Returns the shared status: 0 missing/already confirmed, 1 first
     *   confirmation recorded, 2 first confirmation deliberately unsampled.
     *
     * correction.lua — flip the ledger + reverse/redo the bucket
     * contribution in one atomic invocation:
     *   KEYS[1]      outcome ledger entry (STRING JSON)
     *   KEYS[2]      DECISION-TIME calibration bucket (ledger.scope,
     *                ledger.hour)
     *   ARGV[1]      new outcome ('L'/'A')
     *   ARGV[2]      weight (decimal string; validated)
     *   ARGV[3]      bucket TTL (seconds)
     *   ARGV[4]      outcome ledger TTL (seconds)
     *   ARGV[5]      expected scope
     *   ARGV[6]      expected decision_hour
     *   Returns 1 when applied, 0 when unknown/expired/already target.
     *
     * sampling_metrics.lua — per-scope sampling statistics:
     *   KEYS[1..24]  hourly score buckets (hash)
     *   Returns {total, resolved} — the 24-bucket window sums.
     */
    private readonly string $calibrationScript;

    private readonly string $registerDecisionScript;

    private readonly string $confirmScript;

    private readonly string $correctionScript;

    private readonly string $samplingMetricsScript;

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
        private readonly int $outcomeTtlSecs = self::DEFAULT_OUTCOME_TTL_SECS,
    ) {
        if ($namespace === '' || preg_match('/[{}]/', $namespace)) {
            throw new \InvalidArgumentException('Calibration namespace must be non-empty and free of braces');
        }
        if ($minSamples < 1 || $maxAdjustment < 1 || $maxChangePerMinute < 1 || $receiptTtlSecs < 1 || $outcomeTtlSecs < 1) {
            throw new \InvalidArgumentException('minSamples, maxAdjustment, maxChangePerMinute, receiptTtlSecs and outcomeTtlSecs must be >= 1');
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
        $this->registerDecisionScript = self::loadScript('register_decision.lua');
        $this->confirmScript = self::loadScript('confirm.lua');
        $this->correctionScript = self::loadScript('correction.lua');
        $this->samplingMetricsScript = self::loadScript('sampling_metrics.lua');
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
     * The always-on outcome ledger key shared with the store
     * (RedisRiskStateStore::ledgerKey()): {kiwi:<ns>}:cal:ledger:<decisionId>.
     * With calibration enabled register_decision.lua / confirm.lua /
     * correction.lua own it; with calibration disabled the store's
     * outcome_*.lua scripts write the same key.
     */
    public function ledgerKey(string $decisionId): string
    {
        return "{kiwi:{$this->namespace}}:outcome:{$decisionId}";
    }

    /**
     * The assessment-time sampling decision: 'complete' and 'weighted'
     * always sample (in weighted mode the HOST governs the rate via the
     * weight it supplies at confirmation); 'random_sample' samples with
     * probability samplingProbabilityPpm / 1_000_000. PURE — no side
     * effects: the sampled-TOTAL denominator is booked ATOMICALLY with the
     * receipt by recordReceipt()/register_decision.lua (HINCRBY
     * sample_total in the decision-hour bucket when sampled).
     */
    public function sample(): bool
    {
        if ($this->samplingMode !== 'random_sample') {
            return true;
        }
        return random_int(0, 999_999) < $this->samplingProbabilityPpm;
    }

    /**
     * Registers the decision ATOMICALLY via the canonical
     * register_decision.lua: the receipt (JSON
     * {"scope","band","action","decision_hour","score","sampled"}), the
     * sampled-TOTAL denominator (HINCRBY sample_total in the decision-hour
     * bucket when sampled) and the PENDING outcome-ledger entry are created
     * in ONE invocation — a sample can never be counted without its receipt
     * (no permanently orphaned denominators), and a decision always has an
     * outcome-ledger entry regardless of calibration.
     *
     * @return bool true when registered, false when the decision_id is
     *              already registered
     */
    public function recordReceipt(string $decisionId, int $scope, int $band, RiskAction $action, int $score, int $sampled, int $decisionHour, float $weight = 1.0): bool
    {
        $receiptKey = "{kiwi:{$this->namespace}}:cal:receipt:{$decisionId}";
        $bucketKey = "{kiwi:{$this->namespace}}:cal:{$scope}:{$decisionHour}";
        $ledgerKey = $this->ledgerKey($decisionId);

        $result = $this->client->eval(
            $this->registerDecisionScript,
            3,
            $receiptKey,
            $bucketKey,
            $ledgerKey,
            (string) json_encode([
                'scope' => $scope,
                'band' => $band,
                'action' => $action->value,
                'decision_hour' => $decisionHour,
                'score' => $score,
                'sampled' => $sampled ? 1 : 0,
            ]),
            (string) $this->receiptTtlSecs,
            $sampled ? '1' : '0',
            (string) self::BUCKET_TTL_SECS,
            (string) $this->outcomeTtlSecs,
            (string) $scope,
            (string) $decisionHour,
            (string) $score,
            (string) $weight,
        );
        return ((int) $result) === 1;
    }

    /**
     * Atomically consumes the receipt and records the outcome in ONE
     * canonical confirm.lua script (no crash window between GETDEL and the
     * bucket increment). The bucket is the DECISION-TIME hour of the
     * receipt's scope (receipt.decision_hour — confirmed outcomes are
     * bucketed by when the DECISION was made, never by confirmation time);
     * the pre-read only derives the bucket key — the script itself
     * re-validates the receipt scope/hour atomically.
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
     *
     * @throws \InvalidArgumentException when the sampling mode is 'weighted'
     *                                   and $weight is null (weighted mode
     *                                   requires a sampling probability weight)
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
        $hour = (int) ($data['decision_hour'] ?? 0);
        $bucketKey = "{kiwi:{$this->namespace}}:cal:{$scope}:{$hour}";
        $ledgerKey = $this->ledgerKey($decisionId);

        $mode = match ($this->samplingMode) {
            'complete' => self::MODE_COMPLETE,
            'weighted' => self::MODE_WEIGHTED,
            default => self::MODE_RANDOM_SAMPLE,
        };
        if ($mode === self::MODE_WEIGHTED && $weight === null) {
            throw new \InvalidArgumentException('weighted mode requires a sampling probability weight');
        }

        $status = (int) $this->client->eval(
            $this->confirmScript,
            3,
            $receiptKey,
            $bucketKey,
            $ledgerKey,
            (string) $mode,
            (string) ($weight ?? 1.0),
            $legitimate ? '1' : '0',
            (string) self::BUCKET_TTL_SECS,
            (string) $this->outcomeTtlSecs,
            (string) $scope,
            (string) $hour,
        );

        if ($status !== 0) {
            // A FIRST confirmation (status 1 or 2) invalidates the cached
            // bias for this scope so a fresh outcome is visible immediately
            // (Rust parity).
            unset($this->biasCache[$scope]);
        }
        return $status;
    }

    /**
     * Corrects a previously confirmed outcome via the canonical
     * correction.lua: flips the ledger L <-> A, REVERSES the original
     * bucket contribution (exact recorded weight, clamped at zero) and adds
     * the corrected contribution — the decision-time bucket key is derived
     * from the ledger's own scope/hour (the pre-read only derives the key;
     * the script re-validates ledger.scope/hour atomically). The corrected
     * outcome is authoritative for future events; if the decision-time
     * bucket already expired, the ledger still flips and the old ephemeral
     * reputation pressure decays naturally.
     *
     * @return bool true when the correction was applied, false when the
     *              decision is unknown/expired or already carries the
     *              target outcome
     */
    public function correctOutcome(string $decisionId, bool $legitimate, ?float $weight = null): bool
    {
        $ledgerKey = $this->ledgerKey($decisionId);
        $raw = $this->client->get($ledgerKey);
        if (!is_string($raw) || $raw === '') {
            return false;
        }
        $data = json_decode($raw, true);
        if (!is_array($data)) {
            return false;
        }
        $scope = (int) ($data['scope'] ?? 0);
        $hour = (int) ($data['hour'] ?? 0);
        if ($scope < 1) {
            return false;
        }
        $bucketKey = "{kiwi:{$this->namespace}}:cal:{$scope}:{$hour}";

        $result = (int) $this->client->eval(
            $this->correctionScript,
            2,
            $ledgerKey,
            $bucketKey,
            $legitimate ? 'L' : 'A',
            (string) ($weight ?? 1.0),
            (string) self::BUCKET_TTL_SECS,
            (string) $this->outcomeTtlSecs,
            (string) $scope,
            (string) $hour,
        );
        if ($result === 1) {
            unset($this->biasCache[$scope]);
        }
        return $result === 1;
    }

    /**
     * Per-scope sampling resolution statistics over the 24-bucket window
     * (canonical sampling_metrics.lua — one round trip).
     *
     * @return array{sampledTotal: int, sampledResolved: int, resolutionRatio: float, sampledExpired: int}
     */
    public function samplingMetrics(int $scope, int $now): array
    {
        $hour = intdiv($now, 3_600_000);
        $keys = [];
        for ($i = 0; $i < self::WINDOW_HOURS; $i++) {
            $keys[] = "{kiwi:{$this->namespace}}:cal:{$scope}:" . ($hour - $i);
        }
        $result = $this->client->eval($this->samplingMetricsScript, count($keys), ...$keys);
        $total = (int) ($result[0] ?? 0);
        $resolved = (int) ($result[1] ?? 0);
        return [
            'sampledTotal' => $total,
            'sampledResolved' => $resolved,
            // (float) cast: PHP 8.5 division returns exact INT results.
            'resolutionRatio' => $total > 0 ? (float) ($resolved / $total) : 0.0,
            'sampledExpired' => max(0, $total - $resolved),
        ];
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
