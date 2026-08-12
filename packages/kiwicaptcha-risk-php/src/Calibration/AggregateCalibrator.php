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
 * abuse_total), byte-identical integer math with the Rust implementation:
 *   total = legit + abuse
 *   total == 0 -> 0
 *   bias = clamp(((abuse - legit) * 1000 / total) * 2 / 10, -200, 200)
 * with every division truncating toward zero (intdiv).
 *
 * Receipts pair a decision_id with its scope/band/action so a later
 * confirmed outcome (legit/abuse) is recorded against the ORIGINAL
 * decision's bucket: {kiwi:<ns>}:cal:receipt:<decision_id> holds the JSON
 * string {"scope":..,"band":..,"action":".."} with EXPIRE 300 s, consumed
 * once, atomically, via GETDEL (string-only in Redis).
 */
final class AggregateCalibrator implements CalibrationStore
{
    public const BIAS_MIN = -200;
    public const BIAS_MAX = 200;
    public const WINDOW_HOURS = 24;
    public const BUCKET_TTL_SECS = 172800; // 48 h
    public const RECEIPT_TTL_SECS = 300;

    private readonly string $namespace;

    public function __construct(
        private readonly Client $client,
        string $namespace = 'd',
    ) {
        if ($namespace === '' || preg_match('/[{}]/', $namespace)) {
            throw new \InvalidArgumentException('Calibration namespace must be non-empty and free of braces');
        }
        $this->namespace = $namespace;
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
        $hour = intdiv((int) floor(microtime(true) * 1000), 3_600_000);
        $key = "{kiwi:{$this->namespace}}:cal:{$scope}:{$hour}";
        $field = sprintf('b%da%s:%s', $band, $action->value, $legitimate ? 'legit' : 'abuse');
        $this->client->hincrby($key, $field, 1);
        $this->client->expire($key, self::BUCKET_TTL_SECS);
    }

    public function biasForScope(int $scope, int $now): int
    {
        $hour = intdiv($now, 3_600_000);
        $legitTotal = 0;
        $abuseTotal = 0;
        for ($i = 0; $i < self::WINDOW_HOURS; $i++) {
            $bucket = $this->client->hgetall("{kiwi:{$this->namespace}}:cal:{$scope}:" . ($hour - $i));
            if (!is_array($bucket)) {
                continue;
            }
            foreach ($bucket as $field => $count) {
                if (str_ends_with((string) $field, ':legit')) {
                    $legitTotal += (int) $count;
                } else {
                    $abuseTotal += (int) $count;
                }
            }
        }

        $total = $legitTotal + $abuseTotal;
        if ($total === 0) {
            return 0;
        }
        $bias = intdiv(intdiv(($abuseTotal - $legitTotal) * 1000, $total) * 2, 10);
        return max(self::BIAS_MIN, min(self::BIAS_MAX, $bias));
    }

    public function recordReceipt(string $decisionId, int $scope, int $band, RiskAction $action): void
    {
        $key = "{kiwi:{$this->namespace}}:cal:receipt:{$decisionId}";
        $this->client->set(
            $key,
            (string) json_encode(['scope' => $scope, 'band' => $band, 'action' => $action->value]),
            'EX',
            self::RECEIPT_TTL_SECS
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
