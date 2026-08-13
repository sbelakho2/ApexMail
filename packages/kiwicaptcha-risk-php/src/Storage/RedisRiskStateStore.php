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
 * The script is the cross-language shared asset BUNDLED with this package
 * at resources/risk-v1.lua (self-contained — no monorepo paths), resolved
 * via dirname(__DIR__, 2) . '/resources/risk-v1.lua' and loaded with
 * EVALSHA (NOSCRIPT fallback to EVAL + SCRIPT LOAD, sha cached). The old
 * monorepo copy (protocol/risk-v1/risk.lua) is obsolete.
 *
 * All keys carry the hash tag {kiwi:<namespace>} so the script is Cluster
 * safe. The Lua's network_risk slot (always 0) is overridden with the
 * observation's classifier-derived network risk; principal_credit is the
 * REAL Lua value (no longer hardcoded 0); the duplicate flag (result[15])
 * is exposed via lastIsDuplicate(). Source/subnet keys use the
 * epoch-parameterized pseudonyms carried on the observation (each epoch's
 * key uses its OWN epoch's pseudonym, never the current-epoch one).
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
        'principal' => 10000,
    ];

    /** Default lifetime of the always-on outcome-ledger entries (86400 s). */
    public const DEFAULT_OUTCOME_TTL_SECS = 86400;

    private string $script;
    private ?string $scriptSha = null;
    private string $outcomeRegisterScript;
    private string $outcomeConfirmScript;
    private string $outcomeCorrectScript;
    private int $lastGlobalLevel = 0;
    private int $lastCooldownUntilMs = 0;
    private bool $lastIsDuplicate = false;

    /**
     * @param string   $namespace       deployment namespace used in the hash tag {kiwi:<namespace>}
     * @param int      $hysteresisMs    global level hysteresis window
     * @param array<string, int> $saturations raw saturation values keyed src_fast..principal (Lua ARGV order)
     */
    public function __construct(
        private readonly Client $client,
        private readonly string $namespace = 'd',
        private readonly int $sourceEpochSecs = 900,
        private readonly int $subnetEpochSecs = 900,
        private readonly int $stateTtlSecs = 1800,
        private readonly int $sessionTtlSecs = 1800,
        private readonly int $principalTtlSecs = 86400,
        private readonly int $dedupeTtlSecs = 60,
        private readonly int $hysteresisMs = 60000,
        private readonly array $saturations = self::DEFAULT_SATURATIONS,
        private readonly int $outcomeTtlSecs = self::DEFAULT_OUTCOME_TTL_SECS,
    ) {
        if ($namespace === '' || preg_match('/[{}]/', $namespace)) {
            throw new \InvalidArgumentException('Risk namespace must be non-empty and free of braces');
        }
        if ($outcomeTtlSecs < 1) {
            throw new \InvalidArgumentException('outcomeTtlSecs must be >= 1');
        }
        $path = dirname(__DIR__, 2) . '/resources/risk-v1.lua';
        if (!is_file($path)) {
            throw new \RuntimeException(
                'Cannot locate the bundled risk-v1 script at resources/risk-v1.lua ' .
                '(resolved from ' . __DIR__ . '). The script ships with this package — ' .
                'the old monorepo copy (protocol/risk-v1/risk.lua) is obsolete.'
            );
        }
        $script = @file_get_contents($path);
        if ($script === false) {
            throw new \RuntimeException(sprintf('Cannot read the bundled risk-v1 script at %s', $path));
        }
        $this->script = $script;
        $this->outcomeRegisterScript = self::loadOutcomeScript('outcome_register.lua');
        $this->outcomeConfirmScript = self::loadOutcomeScript('outcome_confirm.lua');
        $this->outcomeCorrectScript = self::loadOutcomeScript('outcome_correct.lua');
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

    public function lastIsDuplicate(): bool
    {
        return $this->lastIsDuplicate;
    }

    public function namespace(): string
    {
        return $this->namespace;
    }

    /**
     * The outcome ledger key shared with the calibrator's register_decision /
     * confirm / correction scripts: {kiwi:<ns>}:cal:ledger:<decisionId>.
     * The ledger is ALWAYS ON (calibration-independent): with calibration
     * enabled the calibrator writes it inside register_decision.lua; with
     * calibration disabled the store writes it here — one key, one
     * exactly-once authority.
     */
    public function ledgerKey(string $decisionId): string
    {
        return "{kiwi:{$this->namespace}}:outcome:{$decisionId}";
    }

    public function registerOutcome(string $decisionId, int $scope, int $decisionHour, int $score): bool
    {
        $result = $this->runScript(
            [$this->ledgerKey($decisionId)],
            [$scope, $decisionHour, $score, $this->outcomeTtlSecs],
            $this->outcomeRegisterScript,
        );
        return ((int) $result) === 1;
    }

    public function confirmOutcome(string $decisionId, bool $legitimate): int
    {
        $result = $this->runScript(
            [$this->ledgerKey($decisionId)],
            [$legitimate ? 'L' : 'A', $this->outcomeTtlSecs],
            $this->outcomeConfirmScript,
        );
        return (int) $result;
    }

    public function correctOutcome(string $decisionId, bool $legitimate): bool
    {
        $result = $this->runScript(
            [$this->ledgerKey($decisionId)],
            [$legitimate ? 'L' : 'A', $this->outcomeTtlSecs],
            $this->outcomeCorrectScript,
        );
        return ((int) $result) === 1;
    }

    public function observe(RiskObservation $observation): SignalVector
    {
        $ns = $this->namespace;
        $tag = "{kiwi:{$ns}}";
        $sourceId = $observation->sourceId;
        $subnetId = $observation->subnetId;
        $sessionId = $observation->sessionId ?? str_repeat('0', 32);
        $principalId = $observation->principalId ?? str_repeat('0', 32);

        $keys = [
            "{$tag}:risk:src:{$observation->sourceEpoch}:{$sourceId}",
            "{$tag}:risk:src:" . ($observation->sourceEpoch - 1) . ":{$observation->sourceIdPrev}",
            "{$tag}:risk:src:" . ($observation->sourceEpoch + 1) . ":{$observation->sourceIdNext}",
            "{$tag}:risk:net:{$observation->subnetEpoch}:{$subnetId}",
            "{$tag}:risk:net:" . ($observation->subnetEpoch - 1) . ":{$observation->subnetIdPrev}",
            "{$tag}:risk:net:" . ($observation->subnetEpoch + 1) . ":{$observation->subnetIdNext}",
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
            $observation->nowMs,
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
            $sat['principal'],
            $observation->sessionId !== null ? 1 : 0,
            $observation->principalId !== null ? 1 : 0,
            $this->sessionTtlSecs,
            $this->principalTtlSecs,
        ];

        $result = $this->runScript($keys, $args);

        if (!is_array($result) || count($result) < 16) {
            throw new RiskStoreException('Risk script returned an unexpected payload');
        }

        $this->lastGlobalLevel = (int) $result[13];
        $this->lastCooldownUntilMs = (int) $result[14];
        $this->lastIsDuplicate = ((int) $result[15]) === 1;

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
            principalCredit: (int) $result[12],
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
    private function runScript(array $keys, array $args, ?string $script = null)
    {
        $script ??= $this->script;
        $sha = $this->shaOf($script);
        $numKeys = count($keys);
        $callArgs = [...$keys, ...$args];

        try {
            return $this->client->evalsha($sha, $numKeys, ...$callArgs);
        } catch (ServerException $e) {
            if (str_contains($e->getMessage(), 'NOSCRIPT')) {
                try {
                    $sha = $this->loadScript($script);
                    return $this->client->evalsha($sha, $numKeys, ...$callArgs);
                } catch (\Predis\Exception\Exception $inner) {
                    throw new RiskStoreException('Risk script execution failed: ' . $inner->getMessage(), 0, $inner);
                }
            }
            throw new RiskStoreException('Risk script execution failed: ' . $e->getMessage(), 0, $e);
        } catch (\Predis\Exception\Exception $e) {
            throw new RiskStoreException('Risk store connection failed: ' . $e->getMessage(), 0, $e);
        }
    }

    /** Cached SHA1 of a script (SCRIPT LOAD once per script per process). */
    private function shaOf(string $script): string
    {
        if ($script === $this->script && $this->scriptSha !== null) {
            return $this->scriptSha;
        }
        $sha = $this->loadScript($script);
        if ($script === $this->script) {
            $this->scriptSha = $sha;
        }
        return $sha;
    }

    private function loadScript(string $script): string
    {
        $sha = $this->client->script('LOAD', $script);
        if (!is_string($sha) || $sha === '') {
            throw new RiskStoreException('SCRIPT LOAD returned no sha');
        }
        return $sha;
    }

    private static function loadOutcomeScript(string $file): string
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
