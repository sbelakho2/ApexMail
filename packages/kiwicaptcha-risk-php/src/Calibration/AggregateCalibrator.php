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
 * {kiwi:<ns>}:cal:state:<scope> (fields bias/ts). The bias may move by at
 * most `maxChangePerMinute` per elapsed minute:
 *   jump = maxChangePerMinute * max(1, floor((now - prevTs) / 60000))
 *   bias = clamp(bias, prevBias - jump, prevBias + jump)
 * A first-ever value (no state) is stored without clamping.
 *
 * The final bias is cached in-process per scope for 30 s (bounded to
 * 1024 scopes, oldest evicted first); cache hits never touch Redis — the
 * 0-below-threshold result is cached too.
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
     * One atomic read->clamp->write:
     *   KEYS[1..24]  hourly score buckets (hash, fields b<band>a<action>:legit|:abuse)
     *   KEYS[25]     rate-limit state (hash, fields bias/ts)
     *   ARGV[1]      now (epoch ms)
     *   ARGV[2]      minSamples
     *   ARGV[3]      maxAdjustment
     *   ARGV[4]      maxChangePerMinute
     * Returns the final bias.
     */
    private const BIAS_SCRIPT = <<<'LUA'
local function trunc_div(n, d)
    local q = n / d
    if q > 0 then return math.floor(q) end
    return math.ceil(q)
end

local legit_total = 0
local abuse_total = 0
for i = 1, 24 do
    local b = redis.call('HGETALL', KEYS[i])
    for j = 1, #b, 2 do
        local count = tonumber(b[j + 1]) or 0
        if string.sub(b[j], -6) == ':legit' then
            legit_total = legit_total + count
        else
            abuse_total = abuse_total + count
        end
    end
end

local bias = 0
local total = legit_total + abuse_total
if total >= tonumber(ARGV[2]) and total > 0 then
    local raw = trunc_div((abuse_total - legit_total) * 1000, total)
    raw = trunc_div(raw * 2, 10)
    local max_adj = tonumber(ARGV[3])
    if raw > max_adj then raw = max_adj end
    if raw < -max_adj then raw = -max_adj end
    local prev_bias = redis.call('HGET', KEYS[25], 'bias')
    local prev_ts = redis.call('HGET', KEYS[25], 'ts')
    if prev_bias and prev_ts then
        local minutes = math.floor((tonumber(ARGV[1]) - tonumber(prev_ts)) / 60000)
        if minutes < 1 then minutes = 1 end
        local jump = tonumber(ARGV[4]) * minutes
        if raw > tonumber(prev_bias) + jump then raw = tonumber(prev_bias) + jump end
        if raw < tonumber(prev_bias) - jump then raw = tonumber(prev_bias) - jump end
    end
    bias = raw
    redis.call('HSET', KEYS[25], 'bias', bias, 'ts', ARGV[1])
end
return bias
LUA;

    private readonly string $namespace;

    /** @var array<int, array{bias:int, expiresAt:float}> bounded per-scope cache */
    private array $biasCache = [];

    public function __construct(
        private readonly Client $client,
        string $namespace = 'd',
        private readonly int $minSamples = 1000,
        private readonly int $maxAdjustment = 150,
        private readonly int $maxChangePerMinute = 10,
    ) {
        if ($namespace === '' || preg_match('/[{}]/', $namespace)) {
            throw new \InvalidArgumentException('Calibration namespace must be non-empty and free of braces');
        }
        if ($minSamples < 1 || $maxAdjustment < 1 || $maxChangePerMinute < 1) {
            throw new \InvalidArgumentException('minSamples, maxAdjustment and maxChangePerMinute must be >= 1');
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
            self::BIAS_SCRIPT,
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
