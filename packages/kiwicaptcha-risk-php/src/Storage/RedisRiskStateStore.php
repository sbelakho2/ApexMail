<?php

declare(strict_types=1);

namespace KiwiCaptcha\Risk\Storage;

use KiwiCaptcha\Risk\RiskObservation;
use KiwiCaptcha\Risk\SignalVector;
use Predis\Client;
use Predis\Response\ServerException;

/**
 * Redis-backed risk state store running the canonical risk-v1 Lua script.
 *
 * The script is the shared cross-language asset at
 * <repo-root>/protocol/risk-v1/risk.lua, resolved via
 * realpath(__DIR__.'/../../../../protocol/risk-v1/risk.lua') and loaded
 * with EVALSHA (NOSCRIPT fallback to EVAL + SCRIPT LOAD, sha cached).
 *
 * All keys carry the hash tag {kiwi:<namespace>} so the script is Cluster
 * safe. The Lua's network_risk slot (always 0) is overridden with the
 * observation's classifier-derived network risk; principal_credit (0,
 * reserved) is passed through.
 *
 * Timeouts: the predis Client is caller-supplied; createClient() builds
 * one with a 5 ms connection timeout and 10 ms read/write timeout. Predis
 * expresses both in SECONDS, and practical timeouts may be rounded up by
 * the platform — treat these as best-effort fail-fast values, not hard
 * deadlines.
 */
final class RedisRiskStateStore implements RiskStateStoreInterface
{
    public const DEFAULT_SATURATIONS = [
        'src_fast' => 8000,
        'src_slow' => 100000,
        'issue' => 6000,
        'bad' => 4000,
        'mal' => 3000,
        'rep' => 2000,
        'action' => 6000,
        'switch' => 10000,
        'global' => 70000,
        'trust' => 10000,
    ];

    private string $script;
    private ?string $scriptSha = null;
    private int $lastGlobalLevel = 0;
    private int $lastCooldownUntilMs = 0;

    /**
     * @param string   $namespace     deployment namespace used in the hash tag {kiwi:<namespace>}
     * @param int      $hysteresisMs  global level hysteresis window
     * @param array<string, int> $saturations raw saturation values keyed src_fast..trust (Lua ARGV order)
     */
    public function __construct(
        private readonly Client $client,
        private readonly string $namespace = 'd',
        private readonly int $sourceEpochSecs = 900,
        private readonly int $subnetEpochSecs = 900,
        private readonly int $stateTtlSecs = 1800,
        private readonly int $principalTtlSecs = 86400,
        private readonly int $dedupeTtlSecs = 60,
        private readonly int $hysteresisMs = 60000,
        private readonly array $saturations = self::DEFAULT_SATURATIONS,
    ) {
        if ($namespace === '' || preg_match('/[{}]/', $namespace)) {
            throw new \InvalidArgumentException('Risk namespace must be non-empty and free of braces');
        }
        $path = realpath(__DIR__ . '/../../../../protocol/risk-v1/risk.lua');
        if ($path === false || !is_file($path)) {
            throw new \RuntimeException(
                'Cannot locate the canonical risk-v1 script at protocol/risk-v1/risk.lua ' .
                '(resolved from ' . __DIR__ . '). This package is intended to run from the monorepo.'
            );
        }
        $script = @file_get_contents($path);
        if ($script === false) {
            throw new \RuntimeException(sprintf('Cannot read the canonical risk-v1 script at %s', $path));
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

    public function lastGlobalLevel(): int
    {
        return $this->lastGlobalLevel;
    }

    public function lastCooldownUntilMs(): int
    {
        return $this->lastCooldownUntilMs;
    }

    public function namespace(): string
    {
        return $this->namespace;
    }

    public function observe(RiskObservation $observation): SignalVector
    {
        $nowMs = $observation->nowMs;
        $nowSecs = intdiv($nowMs, 1000);
        $srcEpoch = intdiv($nowSecs, $this->sourceEpochSecs);
        $netEpoch = intdiv($nowSecs, $this->subnetEpochSecs);
        $ns = $this->namespace;
        $tag = "{kiwi:{$ns}}";
        $sourceId = $observation->sourceId;
        $subnetId = $observation->subnetId;
        $sessionId = $observation->sessionId ?? str_repeat('0', 32);
        $principalId = $observation->principalId ?? str_repeat('0', 32);

        $keys = [
            "{$tag}:risk:src:{$srcEpoch}:{$sourceId}",
            "{$tag}:risk:src:" . ($srcEpoch - 1) . ":{$sourceId}",
            "{$tag}:risk:src:" . ($srcEpoch + 1) . ":{$sourceId}",
            "{$tag}:risk:net:{$netEpoch}:{$subnetId}",
            "{$tag}:risk:net:" . ($netEpoch - 1) . ":{$subnetId}",
            "{$tag}:risk:net:" . ($netEpoch + 1) . ":{$subnetId}",
            "{$tag}:risk:session:{$sessionId}",
            "{$tag}:risk:principal:{$principalId}",
            "{$tag}:risk:global",
            "{$tag}:risk:dedupe:{$observation->eventId}",
        ];
        $this->assertSameSlot($keys);

        $sat = array_replace(self::DEFAULT_SATURATIONS, $this->saturations);
        $args = [
            $observation->event->value,
            $observation->scope,
            $nowMs,
            $observation->eventId,
            $this->dedupeTtlSecs,
            $this->stateTtlSecs,
            $this->hysteresisMs,
            $sat['src_fast'],
            $sat['src_slow'],
            $sat['issue'],
            $sat['bad'],
            $sat['mal'],
            $sat['rep'],
            $sat['action'],
            $sat['switch'],
            $sat['global'],
            $sat['trust'],
        ];

        $result = $this->runScript($keys, $args);

        if (is_array($result) && count($result) === 1 && (int) $result[0] === -1) {
            // Duplicate event_id: documented no-op returning the empty vector.
            return SignalVector::zero();
        }
        if (!is_array($result) || count($result) < 15) {
            throw new RiskStoreException('Risk script returned an unexpected payload');
        }

        $this->lastGlobalLevel = (int) $result[13];
        $this->lastCooldownUntilMs = (int) $result[14];

        return new SignalVector(
            sourceFast: (int) $result[0],
            sourceSlow: (int) $result[1],
            subnetFast: (int) $result[2],
            issueDebt: (int) $result[3],
            badProof: (int) $result[4],
            malformed: (int) $result[5],
            replay: (int) $result[6],
            actionFailure: (int) $result[7],
            scopeSwitch: (int) $result[8],
            globalPressure: (int) $result[9],
            networkRisk: $observation->networkRisk,
            trustCredit: (int) $result[11],
            principalCredit: 0,
        );
    }

    /**
     * EVALSHA with NOSCRIPT fallback (EVAL + SCRIPT LOAD, sha cached).
     *
     * @param list<string> $keys
     * @param list<int|string> $args
     * @return array<int|string>|int|string
     * @throws RiskStoreException on any non-NOSCRIPT redis failure
     */
    private function runScript(array $keys, array $args)
    {
        $numKeys = count($keys);
        $callArgs = [...$keys, ...$args];

        try {
            if ($this->scriptSha !== null) {
                return $this->client->evalsha($this->scriptSha, $numKeys, ...$callArgs);
            }
            $sha = $this->client->script('LOAD', $this->script);
            if (!is_string($sha) || $sha === '') {
                throw new RiskStoreException('SCRIPT LOAD returned no sha');
            }
            $this->scriptSha = $sha;
            return $this->client->evalsha($this->scriptSha, $numKeys, ...$callArgs);
        } catch (ServerException $e) {
            if (str_contains($e->getMessage(), 'NOSCRIPT')) {
                try {
                    $this->scriptSha = $this->client->script('LOAD', $this->script);
                    return $this->client->evalsha($this->scriptSha, $numKeys, ...$callArgs);
                } catch (\Predis\Exception\Exception $inner) {
                    throw new RiskStoreException('Risk script execution failed: ' . $inner->getMessage(), 0, $inner);
                }
            }
            throw new RiskStoreException('Risk script execution failed: ' . $e->getMessage(), 0, $e);
        } catch (\Predis\Exception\Exception $e) {
            throw new RiskStoreException('Risk store connection failed: ' . $e->getMessage(), 0, $e);
        }
    }

    /**
     * Asserts every key hashes to the same Redis Cluster slot (all share the
     * hash tag {kiwi:<ns>}).
     *
     * @param list<string> $keys
     * @throws \LogicException on slot mismatch
     */
    public function assertSameSlot(array $keys): void
    {
        $slot = null;
        foreach ($keys as $key) {
            $open = strpos($key, '{');
            $close = $open === false ? false : strpos($key, '}', $open);
            if ($open === false || $close === false) {
                throw new \LogicException(sprintf('Key %s has no hash tag', $key));
            }
            $tag = substr($key, $open + 1, $close - $open - 1);
            $s = self::crc16($tag) & 0x3FFF;
            if ($slot === null) {
                $slot = $s;
            } elseif ($s !== $slot) {
                throw new \LogicException(sprintf('Key %s slots to %d, expected %d', $key, $s, $slot));
            }
        }
    }

    /** CRC-16/XMODEM (poly 0x1021, init 0); "123456789" -> 0x31C3. */
    public static function crc16(string $data): int
    {
        $crc = 0;
        $len = strlen($data);
        for ($i = 0; $i < $len; $i++) {
            $crc ^= ord($data[$i]) << 8;
            for ($j = 0; $j < 8; $j++) {
                if (($crc & 0x8000) !== 0) {
                    $crc = (($crc << 1) ^ 0x1021) & 0xFFFF;
                } else {
                    $crc = ($crc << 1) & 0xFFFF;
                }
            }
        }
        return $crc;
    }
}
