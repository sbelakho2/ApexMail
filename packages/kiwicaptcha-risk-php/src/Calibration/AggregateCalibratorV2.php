<?php

declare(strict_types=1);

namespace KiwiCaptcha\Risk\Calibration;

use KiwiCaptcha\Risk\RiskAction;
use Predis\Client;
use Predis\Response\ServerException;

/**
 * Aggregate calibrator v2: the hardened generation of the outcome-feedback
 * calibration. It composes an {@see AggregateCalibrator} the same way the
 * Rust store composes its v1 inner (the with_* builder precedent):
 * identical client, namespace, key layout and knobs, so the two
 * generations address identical keys and an upgrade never orphans state.
 * The hardening has three parts: provenance classes, per-source
 * label-volume caps, and a plain weighted mean over clipped boundary
 * distances.
 *
 * What v2 adds over the v1 estimator:
 *
 * - Labels carry a provenance class ({@see ProvenanceClass}): human
 *   review (weight 1.0, the default for app-reported labels), security
 *   event (0.8) and payment network (1.2). The class weight scales every
 *   bucket contribution, so higher-trust channels dominate the estimate
 *   when they disagree with a low-trust flood.
 * - Every label names its reporting source (a bounded id 0..7, the app
 *   path that reported it). One source may admit at most
 *   self::PER_SOURCE_WINDOW_CAP labels per scope per hourly bucket,
 *   enforced atomically inside confirm_v2.lua; a label beyond the cap
 *   stays a real, exactly-once outcome (status 3) but contributes
 *   nothing to the estimator.
 * - The estimator (calibration_v2.lua) averages clipped boundary
 *   distances as a plain weighted mean over the per-distance mass
 *   histogram the confirm script writes. No tail is trimmed: the error
 *   signal lives in the small tail of misclassified samples, so a trim
 *   would erase exactly the movement the estimator exists to make. The
 *   caps and the provenance weights carry the flood resistance.
 *
 * Versioning: calibration v2 is the version new deployments use, and it
 * is discovered at first touch of the ledger. Registration stamps every
 * new receipt with "cv": 2 (the JSON is stored verbatim by the same
 * canonical register_decision.lua the v1 store uses). Confirmation reads
 * the receipt: cv == 2 routes to confirm_v2.lua with the caller's
 * provenance class, while every older receipt keeps confirming through
 * the v1 script with byte-identical v1 semantics — existing v1 ledgers
 * keep v1. The same discovery routes a ledger whose writer generation is
 * 3 to correction_v2.lua. The engine composition (which calibrator is
 * attached) selects the version for new decisions and for the bias read.
 *
 * The estimator wakes on admitted v2 samples alone (the n2 counter).
 * The min_samples gate and the volume caps compose. A single-window
 * forged flood through the reporting paths admits at most
 * sources x cap samples, so its influence on the mean is bounded by
 * the capped mass it can inject. The movement stays within the
 * documented tolerance. A flood that persists for days and
 * exceeds the honest population's mass is bounded by the caps' inflow
 * rate and by the proportional rate limiter. Label statistics cannot
 * reject labels that carry the only ground truth the system has: the
 * provenance weights exist to let the higher-trust channels outvote the
 * low-trust volume.
 *
 * The final bias is cached in-process per scope for 30 s (bounded to
 * 1024 scopes, oldest evicted first), the same policy as the v1 store;
 * a confirm or correct invalidates the scope's entry. Any backend
 * failure of the bias read returns 0 (fail-open, never breaks issuance).
 */
final class AggregateCalibratorV2 implements CalibrationStore
{
    /** One reporting source may admit at most this many labels per scope per hourly bucket. */
    public const PER_SOURCE_WINDOW_CAP = 100;

    /** The bounded reporting-source slot count (ids 0..7). */
    public const MAX_REPORTING_SOURCES = 8;

    private const SCRIPT_CALIBRATION_V2 = 'calibration_v2.lua';
    private const SCRIPT_CONFIRM_V2 = 'confirm_v2.lua';
    private const SCRIPT_CORRECTION_V2 = 'correction_v2.lua';

    private readonly Client $client;

    /** The composed v1 calibrator (same namespace, same knobs). */
    private readonly AggregateCalibrator $inner;

    /** @var array<string, string> cached sha1 of every static script */
    private array $scriptShas = [];

    /** @var array<int, array{bias:int, expiresAt:float, writtenAt:float}> bounded per-scope cache */
    private array $biasCache = [];

    private readonly string $calibrationV2Script;

    private readonly string $confirmV2Script;

    private readonly string $correctionV2Script;

    /**
     * Builds the v2 calibrator over a fresh composed v1 calibrator
     * constructed from exactly the knobs given here, so both generations
     * can never disagree about the gates, the clamps or the key layout.
     *
     * @throws \InvalidArgumentException when a knob violates the v1
     *                                   constructor contract or the cap
     *                                   is below 1
     */
    public function __construct(
        Client $client,
        string $namespace = 'd',
        private readonly int $minSamples = 1000,
        private readonly int $maxAdjustment = 150,
        private readonly int $maxChangePerMinute = 10,
        private readonly int $receiptTtlSecs = AggregateCalibrator::RECEIPT_TTL_SECS,
        private readonly string $samplingMode = 'random_sample',
        private readonly int $samplingProbabilityPpm = 100_000,
        private readonly float $minimumResolutionRatio = AggregateCalibrator::DEFAULT_MIN_RESOLUTION_RATIO,
        private readonly float $falsePositiveCost = AggregateCalibrator::DEFAULT_FALSE_POSITIVE_COST,
        private readonly float $falseNegativeCost = AggregateCalibrator::DEFAULT_FALSE_NEGATIVE_COST,
        private readonly int $outcomeTtlSecs = AggregateCalibrator::DEFAULT_OUTCOME_TTL_SECS,
        private readonly string $scopeHmacKey = '',
        int $namespaceKeyVersion = \KiwiCaptcha\Risk\DeploymentNamespace::VERSION_LEGACY,
        private readonly int $perSourceWindowCap = self::PER_SOURCE_WINDOW_CAP,
    ) {
        if ($perSourceWindowCap < 1) {
            throw new \InvalidArgumentException('perSourceWindowCap must be >= 1');
        }
        $this->client = $client;
        $this->inner = new AggregateCalibrator(
            $client,
            $namespace,
            $minSamples,
            $maxAdjustment,
            $maxChangePerMinute,
            $receiptTtlSecs,
            $samplingMode,
            $samplingProbabilityPpm,
            $minimumResolutionRatio,
            $falsePositiveCost,
            $falseNegativeCost,
            $outcomeTtlSecs,
            $scopeHmacKey,
            $namespaceKeyVersion,
        );
        $this->calibrationV2Script = self::loadScript(self::SCRIPT_CALIBRATION_V2);
        $this->confirmV2Script = self::loadScript(self::SCRIPT_CONFIRM_V2);
        $this->correctionV2Script = self::loadScript(self::SCRIPT_CORRECTION_V2);
    }

    /** The composed v1 calibrator (same namespace and knobs). */
    public function inner(): AggregateCalibrator
    {
        return $this->inner;
    }

    /** The configured per-source window cap. */
    public function perSourceWindowCap(): int
    {
        return $this->perSourceWindowCap;
    }

    public function namespace(): string
    {
        return $this->inner->namespace();
    }

    public function rawNamespace(): string
    {
        return $this->inner->rawNamespace();
    }

    public function scopeKey(int $scope): string
    {
        return $this->inner->scopeKey($scope);
    }

    /** Canonical short-round-trip weight text (the inner's cross-language spelling). */
    public static function weightText(float $weight): string
    {
        return AggregateCalibrator::weightText($weight);
    }

    public function ledgerKey(string $decisionId): string
    {
        return $this->inner->ledgerKey($decisionId);
    }

    private function receiptKey(string $decisionId): string
    {
        return "{kiwi:{$this->namespace()}}:cal:receipt:{$decisionId}";
    }

    private function bucketKey(int $scope, int $hour): string
    {
        return sprintf('{kiwi:%s}:cal:%s:%d', $this->namespace(), $this->scopeKey($scope), $hour);
    }

    private function stateKey(int $scope): string
    {
        return sprintf('{kiwi:%s}:cal:state:%s', $this->namespace(), $this->scopeKey($scope));
    }

    public function sample(): bool
    {
        return $this->inner->sample();
    }

    /**
     * Registers the decision atomically with a generation-2 receipt: the
     * same canonical register_decision.lua invocation the v1 store uses,
     * with the receipt JSON carrying the extra "cv": 2 field (stored
     * verbatim; the v1 script validates the shared fields).
     */
    public function recordReceipt(string $decisionId, int $scope, int $band, RiskAction $action, int $score, int $sampled, int $decisionHour, float $weight = 1.0): bool
    {
        \KiwiCaptcha\Risk\Storage\RedisRiskStateStore::assertKeySafeIdentifier('decisionId', $decisionId);
        $receiptKey = $this->receiptKey($decisionId);
        $bucketKey = $this->bucketKey($scope, $decisionHour);
        $ledgerKey = $this->ledgerKey($decisionId);

        $result = $this->runScript(
            $this->loadScript(self::SCRIPT_REGISTER_SHARED),
            [$receiptKey, $bucketKey, $ledgerKey],
            [
                (string) json_encode([
                    'scope' => $scope,
                    'band' => $band,
                    'action' => $action->value,
                    'decision_hour' => $decisionHour,
                    'score' => $score,
                    'sampled' => $sampled ? 1 : 0,
                    'cv' => 2,
                ]),
                (string) $this->receiptTtlSecs,
                $sampled ? '1' : '0',
                (string) AggregateCalibrator::BUCKET_TTL_SECS,
                (string) $this->outcomeTtlSecs,
                (string) $scope,
                (string) $decisionHour,
                (string) $score,
                self::weightText($weight),
            ],
        );

        return ((int) $result) === 1;
    }

    private const SCRIPT_REGISTER_SHARED = 'register_decision.lua';

    /**
     * Confirms the outcome of one decision, discovering the ledger's
     * generation at the receipt. A cv of 2 routes to the v2 confirm
     * with the human-review provenance on the default reporting source;
     * the explicit surface is confirmOutcomeWithProvenance. Every older
     * receipt keeps the v1 path with byte-identical v1 semantics.
     */
    public function confirmOutcome(string $decisionId, bool $legitimate, ?float $weight = null): int
    {
        return $this->confirmOutcomeWithProvenance(
            $decisionId,
            $legitimate,
            ProvenanceClass::HumanReview,
            0,
            $weight,
        );
    }

    /**
     * Confirms the outcome with the label's provenance class and
     * reporting source named explicitly.
     *
     * @param ProvenanceClass $provenance who asserted the outcome. The
     *                                    class weight scales the bucket
     *                                    contribution.
     * @param int             $source     the bounded reporting-source id
     *                                    0..7: the app path that reports
     *                                    this label. Its per-window
     *                                    admission is capped.
     *
     * @param string|null       $identity  the pseudonym whose reputation
     *                                    this label would credit. The
     *                                    per-identity trust cap of
     *                                    trust-granting labels applies.
     *
     * @return int the shared accepted-outcome status. 0 means nothing
     *             consumed. 1 is the first confirmation with calibration
     *             recorded. 2 is the first confirmation deliberately
     *             unsampled. 3 is the first confirmation with calibration
     *             withheld by the per-source window cap. 4 is the first
     *             confirmation whose trust-granting reputation credit is
     *             withheld by a trust cap. Reputation is authorized on 1
     *             and 2 (and on 3 only for abuse labels). Status 4 never
     *             authorizes it.
     *
     * @throws \InvalidArgumentException when the sampling mode is
     *                                   'weighted' and $weight is null
     */
    public function confirmOutcomeWithProvenance(
        string $decisionId,
        bool $legitimate,
        ProvenanceClass $provenance,
        int $source,
        ?float $weight = null,
        ?string $identity = null,
    ): int {
        \KiwiCaptcha\Risk\Storage\RedisRiskStateStore::assertKeySafeIdentifier('decisionId', $decisionId);
        if ($identity !== null) {
            \KiwiCaptcha\Risk\Storage\RedisRiskStateStore::assertKeySafeIdentifier('identity', $identity);
        }
        if ($source < 0 || $source >= self::MAX_REPORTING_SOURCES) {
            throw new \InvalidArgumentException(sprintf('source must be within 0..%d', self::MAX_REPORTING_SOURCES - 1));
        }
        if ($this->samplingMode === 'weighted' && $weight === null) {
            throw new \InvalidArgumentException('weighted mode requires a sampling probability weight');
        }

        // Version discovery at first touch of the ledger: the receipt
        // carries the generation; an older or missing receipt keeps the
        // v1 path (the inner calibrator re-validates everything).
        $raw = $this->client->get($this->receiptKey($decisionId));
        if (!is_string($raw) || $raw === '') {
            return $this->inner->confirmOutcome($decisionId, $legitimate, $weight);
        }
        $data = json_decode($raw, true);
        if (!is_array($data) || ($data['cv'] ?? null) !== 2) {
            return $this->inner->confirmOutcome($decisionId, $legitimate, $weight);
        }
        $scope = (int) ($data['scope'] ?? 0);
        $hour = (int) ($data['decision_hour'] ?? 0);
        if ($scope < 1) {
            return $this->inner->confirmOutcome($decisionId, $legitimate, $weight);
        }

        $mode = match ($this->samplingMode) {
            'complete' => 0,
            'weighted' => 2,
            default => 1,
        };
        $keys = [$this->receiptKey($decisionId), $this->bucketKey($scope, $hour), $this->ledgerKey($decisionId)];
        if ($identity !== null && $identity !== '') {
            $keys[] = $this->trustCapKey($identity);
        }
        $status = (int) $this->runScript(
            $this->confirmV2Script,
            $keys,
            [
                (string) $mode,
                self::weightText($weight ?? 1.0),
                $legitimate ? '1' : '0',
                (string) AggregateCalibrator::BUCKET_TTL_SECS,
                (string) $this->outcomeTtlSecs,
                (string) $scope,
                (string) $hour,
                (string) $provenance->value,
                (string) $source,
                (string) $this->perSourceWindowCap,
            ],
        );
        if ($status !== 0) {
            $this->invalidateBiasCache($scope);
        }

        return $status;
    }

    /**
     * The per-identity trust-cap counter key (shared tag, expiring with
     * the bucket window): the identity dimension of the trust-granting
     * reputation cap.
     */
    private function trustCapKey(string $identity): string
    {
        return \sprintf('{kiwi:%s}:trustcap:%s', $this->inner->namespace(), $identity);
    }

    /**
     * Corrects a confirmed outcome, discovering the writer generation at
     * the ledger: a v = 3 ledger routes to correction_v2.lua (which
     * reverses and redoes the histogram mass and the admitted counter),
     * every older ledger keeps the v1 correction script.
     */
    public function correctOutcome(string $decisionId, bool $legitimate, ?float $weight = null): bool
    {
        \KiwiCaptcha\Risk\Storage\RedisRiskStateStore::assertKeySafeIdentifier('decisionId', $decisionId);
        $ledgerKey = $this->ledgerKey($decisionId);
        $raw = $this->client->get($ledgerKey);
        if (!is_string($raw) || $raw === '') {
            return false;
        }
        $data = json_decode($raw, true);
        if (!is_array($data)) {
            return false;
        }
        if (($data['v'] ?? null) !== 3) {
            return $this->inner->correctOutcome($decisionId, $legitimate, $weight);
        }
        $scope = (int) ($data['scope'] ?? 0);
        $hour = (int) ($data['hour'] ?? 0);
        if ($scope < 1) {
            return false;
        }
        $result = (int) $this->runScript(
            $this->correctionV2Script,
            [$ledgerKey, $this->bucketKey($scope, $hour)],
            [
                $legitimate ? 'L' : 'A',
                self::weightText($weight ?? 1.0),
                (string) AggregateCalibrator::BUCKET_TTL_SECS,
                (string) $this->outcomeTtlSecs,
                (string) $scope,
                (string) $hour,
            ],
        );
        if ($result === 1) {
            $this->invalidateBiasCache($scope);
        }

        return $result === 1;
    }

    public function samplingMetrics(int $scope, int $now): array
    {
        return $this->inner->samplingMetrics($scope, $now);
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
        for ($i = 0; $i < AggregateCalibrator::WINDOW_HOURS; $i++) {
            $keys[] = $this->bucketKey($scope, $hour - $i);
        }
        $keys[] = $this->stateKey($scope);

        $mode = match ($this->samplingMode) {
            'complete' => 0,
            'weighted' => 2,
            default => 1,
        };

        $bias = AggregateCalibrator::toBoundedBias(
            $this->runScript(
                $this->calibrationV2Script,
                $keys,
                [
                    $now,
                    $this->minSamples,
                    $this->maxAdjustment,
                    $this->maxChangePerMinute,
                    $this->minimumResolutionRatio,
                    $mode,
                    $this->falsePositiveCost,
                    $this->falseNegativeCost,
                ],
            ),
            $this->maxAdjustment,
        );

        if (count($this->biasCache) >= AggregateCalibrator::CACHE_CAP && !isset($this->biasCache[$scope])) {
            // Evict the entry with the earliest write timestamp (the
            // v1 store's policy; a refresh re-ages the entry).
            $oldestScope = null;
            $oldestWrittenAt = null;
            foreach ($this->biasCache as $cachedScope => $entry) {
                if ($oldestWrittenAt === null || $entry['writtenAt'] < $oldestWrittenAt) {
                    $oldestScope = $cachedScope;
                    $oldestWrittenAt = $entry['writtenAt'];
                }
            }
            if ($oldestScope !== null) {
                unset($this->biasCache[$oldestScope]);
            }
        }
        $this->biasCache[$scope] = [
            'bias' => $bias,
            'expiresAt' => $nowFloat + AggregateCalibrator::CACHE_TTL_SECS,
            'writtenAt' => $nowFloat,
        ];

        return $bias;
    }

    /** Drops the scope's cached bias (both generations share the namespace). */
    private function invalidateBiasCache(int $scope): void
    {
        unset($this->biasCache[$scope]);
    }

    /**
     * evalsha with the cached-sha + SCRIPT LOAD repair pattern of the
     * v1 store: the script bytes ship to Redis only on a NOSCRIPT miss.
     *
     * @param list<string> $keys
     * @param list<int|string|float> $args
     * @return array<int|string>|int|string
     * @throws \RuntimeException on any redis failure (the calibrator's
     *         callers degrade silently)
     */
    private function runScript(string $script, array $keys, array $args)
    {
        $sha = $this->shaOf($script);
        $numKeys = count($keys);
        $callArgs = [...$keys, ...$args];

        try {
            return $this->client->evalsha($sha, $numKeys, ...$callArgs);
        } catch (ServerException $e) {
            if (str_contains($e->getMessage(), 'NOSCRIPT')) {
                try {
                    $sha = $this->scriptLoad($script);

                    return $this->client->evalsha($sha, $numKeys, ...$callArgs);
                } catch (\Predis\Exception\Exception $inner) {
                    throw new \RuntimeException('Calibration script execution failed: ' . $inner->getMessage(), 0, $inner);
                }
            }
            throw new \RuntimeException('Calibration script execution failed: ' . $e->getMessage(), 0, $e);
        } catch (\Predis\Exception\Exception $e) {
            throw new \RuntimeException('Calibration store connection failed: ' . $e->getMessage(), 0, $e);
        }
    }

    /** Cached sha1 of every static script (script load once per script per process). */
    private function shaOf(string $script): string
    {
        if (!isset($this->scriptShas[$script])) {
            $this->scriptShas[$script] = $this->scriptLoad($script);
        }

        return $this->scriptShas[$script];
    }

    private function scriptLoad(string $script): string
    {
        $sha = $this->client->script('LOAD', $script);
        if (!is_string($sha) || $sha === '') {
            throw new \RuntimeException('SCRIPT LOAD returned no sha');
        }

        return $sha;
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
