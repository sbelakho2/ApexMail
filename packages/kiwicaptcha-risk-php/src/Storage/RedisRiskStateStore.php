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
 * The script is the cross-language shared asset bundled with this package
 * at resources/risk-v1.lua (self-contained, no monorepo paths), resolved
 * via dirname(__DIR__, 2) . '/resources/risk-v1.lua' and loaded with
 * evalsha (noscript fallback to eval + script load, every static script's
 * sha cached in a script→sha map). The monorepo copy
 * (protocol/risk-v1/risk.lua) is obsolete.
 *
 * All keys carry the hash tag {kiwi:<namespace>} so the script is Cluster
 * safe. The Lua's network_risk slot (always 0) is overridden with the
 * observation's classifier-derived network risk; principal_credit is the
 * real Lua value; the duplicate flag (result[15]) is exposed via
 * lastIsDuplicate(). Source/subnet keys use the epoch-parameterized
 * pseudonyms carried on the observation (each epoch's key uses its own
 * epoch's pseudonym, never the current-epoch one).
 *
 * Timeouts: the predis Client is caller-supplied; createClient() builds
 * one with a 5 ms connection timeout and 10 ms read/write timeout. Predis
 * expresses both in seconds, and practical timeouts may be rounded up by
 * the platform — treat these as best-effort fail-fast values, not hard
 * deadlines.
 */
final class RedisRiskStateStore implements RiskStateStoreInterface, SessionContextTagStoreInterface, SessionTlsTagStoreInterface, ConsolidatedAssessmentStoreInterface
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
    /** @var array<string, string> cached sha1 of every static script, keyed by the script content */
    private array $scriptShas = [];
    private string $assessV2Script;
    private string $outcomeRegisterScript;
    private string $outcomeConfirmScript;
    private string $outcomeCorrectScript;
    private int $lastGlobalLevel = 0;
    private int $lastCooldownUntilMs = 0;
    private bool $lastIsDuplicate = false;

    /**
     * @param string   $namespace       deployment namespace used in the hash tag {kiwi:<namespace>}
     * @param int      $hysteresisMs    global level hysteresis window
     * @param array<string, int> $saturations raw saturation values keyed src_fast..principal (Lua argv order)
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
                'the monorepo copy (protocol/risk-v1/risk.lua) is obsolete.'
            );
        }
        $script = @file_get_contents($path);
        if ($script === false) {
            throw new \RuntimeException(sprintf('Cannot read the bundled risk-v1 script at %s', $path));
        }
        $this->script = $script;
        $this->assessV2Script = self::loadOutcomeScript('assess_v2.lua');
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
     * The ledger is always on (calibration-independent): with calibration
     * enabled the calibrator writes it inside register_decision.lua; with
     * calibration disabled the store writes it here. One key, one
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

    /**
     * The risk-v2 session client-context record
     * ({kiwi:<ns>}:risk:ctx:<session-pseudonym>): SET NX with the session
     * TTL (first write wins = the first tag the session ever presented),
     * then return the recorded tag. The record is keyed by the session
     * pseudonym only — the raw cookie value never appears in Redis — and
     * shares the hash tag with the risk-v1 state keys, so it is Cluster
     * safe.
     */
    public function sessionFirstContextTag(string $sessionId, string $tag): ?string
    {
        $key = "{kiwi:{$this->namespace}}:risk:ctx:{$sessionId}";
        try {
            $set = $this->client->set($key, $tag, 'EX', $this->sessionTtlSecs, 'NX');
            if ($set === 'OK') {
                return $tag;
            }
            $stored = $this->client->get($key);

            return \is_string($stored) && $stored !== '' ? $stored : null;
        } catch (\Predis\Exception\Exception $e) {
            throw new RiskStoreException('Risk context-tag record failed: ' . $e->getMessage(), 0, $e);
        }
    }

    /**
     * The risk-v2 session trusted-edge TLS record
     * ({kiwi:<ns>}:risk:tls:<session-pseudonym>): SET NX with the session
     * TTL (first write wins = the first coarse, server-attested TLS
     * classification the session ever presented), then return the recorded
     * tag. Mirrors the session_first_context_tag machinery exactly; the
     * Rust mirror names the record `session_first_tls_tag`. Keyed by the
     * session pseudonym only — the raw cookie value never appears in Redis
     * — and shares the hash tag with the risk-v1 state keys, so it is
     * Cluster safe.
     */
    public function sessionFirstTlsTag(string $sessionId, string $tag): ?string
    {
        $key = "{kiwi:{$this->namespace}}:risk:tls:{$sessionId}";
        try {
            $set = $this->client->set($key, $tag, 'EX', $this->sessionTtlSecs, 'NX');
            if ($set === 'OK') {
                return $tag;
            }
            $stored = $this->client->get($key);

            return \is_string($stored) && $stored !== '' ? $stored : null;
        } catch (\Predis\Exception\Exception $e) {
            throw new RiskStoreException('Risk TLS-tag record failed: ' . $e->getMessage(), 0, $e);
        }
    }

    public function observe(RiskObservation $observation): SignalVector
    {
        $keys = $this->observationKeys($observation);
        $this->assertSameSlot($keys);

        $args = $this->observationArgs($observation);
        $result = $this->runScript($keys, $args);

        if (!is_array($result) || count($result) < 16) {
            throw new RiskStoreException('Risk script returned an unexpected payload');
        }

        $this->lastGlobalLevel = (int) $result[13];
        $this->lastCooldownUntilMs = (int) $result[14];
        $this->lastIsDuplicate = ((int) $result[15]) === 1;

        return $this->signalVectorFromReply($result, $observation->networkRisk);
    }

    /**
     * The consolidated risk-v2 assessment: one atomic script call that
     * runs the v1 observation with the exact risk-v1 semantics. It
     * applies the session's first-seen client-context tag + first-seen
     * trusted-edge TLS tag records (SET NX, first write wins, session
     * TTL). When $registration is given, it registers the decision's
     * pending outcome-ledger entry (SET NX EX under the store's outcome
     * TTL), returning the signal vector, the recorded tag values and the
     * registration status. An established risk-v2 session therefore
     * costs one script call instead of the separate SET NX / GET tag
     * round trips and the separate outcome registration.
     *
     * $contextTag / $tlsTag are the presented tags of the current request
     * (null/'' = none presented; the corresponding record is untouched and
     * its existing value is reported as null). The engine passes them only
     * when a session pseudonym exists and the tag passes the contract
     * bounds. The records use the exact keys and TTL of
     * sessionFirstContextTag()/sessionFirstTlsTag(), so the two surfaces
     * are interchangeable. The ledger registration mirrors
     * registerOutcome() byte-for-byte (the score is computed inside the
     * script from the exact base risk and weights the engine scores
     * with). All keys share the hash tag — Cluster safe.
     *
     * @return array{0: SignalVector, 1: ?string, 2: ?string, 3: bool} the
     *         signal vector, the recorded client-context tag (null when
     *         none recorded/presented), and the recorded TLS tag (null
     *         when none recorded/presented). The registration status is
     *         true when the pending ledger entry was created, false when
     *         none was requested or the decision is already registered.
     */
    public function assessV2(RiskObservation $observation, ?string $contextTag, ?string $tlsTag, ?OutcomeRegistration $registration = null): array
    {
        $sessionId = $observation->sessionId ?? str_repeat('0', 32);
        $keys = [...$this->observationKeys($observation),
            "{kiwi:{$this->namespace}}:risk:ctx:{$sessionId}",
            "{kiwi:{$this->namespace}}:risk:tls:{$sessionId}",
        ];
        $registrationKey = null;
        if ($registration !== null) {
            $registrationKey = $this->ledgerKey($registration->decisionId);
            $keys[] = $registrationKey;
        }
        $this->assertSameSlot($keys);

        $args = [...$this->observationArgs($observation), $contextTag ?? '', $tlsTag ?? ''];
        if ($registration !== null) {
            $args = [...$args,
                $registration->decisionId,
                $registration->decisionHour,
                $this->outcomeTtlSecs,
                $observation->networkRisk,
                $registration->globalPressureEnabled ? 1 : 0,
                $registration->baseRisk,
                $registration->honeypotHit ? 1 : 0,
                ...array_values($registration->weights->toArray()),
                ...array_values($registration->v2Weights->toArray()),
            ];
        } else {
            $args = [...$args, '', 0, 0, 0, 1, 0, 0, ...array_fill(0, 16, 0)];
        }
        $result = $this->runScript($keys, $args, $this->assessV2Script);

        if (!is_array($result) || count($result) < 19) {
            throw new RiskStoreException('Risk script returned an unexpected payload');
        }

        $this->lastGlobalLevel = (int) $result[13];
        $this->lastCooldownUntilMs = (int) $result[14];
        $this->lastIsDuplicate = ((int) $result[15]) === 1;

        return [
            $this->signalVectorFromReply($result, $observation->networkRisk),
            (is_string($result[16]) && $result[16] !== '') ? $result[16] : null,
            (is_string($result[17]) && $result[17] !== '') ? $result[17] : null,
            ((int) $result[18]) === 1,
        ];
    }

    /**
     * The ten risk-v1 observation keys, in the Lua keys order
     * (source ±1 epoch, subnet ±1 epoch, session, principal, global,
     * dedupe). All share the {kiwi:<ns>} hash tag.
     *
     * @return list<string>
     */
    private function observationKeys(RiskObservation $observation): array
    {
        $ns = $this->namespace;
        $tag = "{kiwi:{$ns}}";
        $sourceId = $observation->sourceId;
        $subnetId = $observation->subnetId;
        $sessionId = $observation->sessionId ?? str_repeat('0', 32);
        $principalId = $observation->principalId ?? str_repeat('0', 32);

        return [
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
    }

    /**
     * The twenty-two risk-v1 script arguments, in the Lua argv order.
     *
     * @return list<int|string>
     */
    private function observationArgs(RiskObservation $observation): array
    {
        $sat = array_replace(self::DEFAULT_SATURATIONS, $this->saturations);

        return [
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
    }

    /** Maps the script reply's 13 signal slots onto the SignalVector. */
    private function signalVectorFromReply(array $result, int $networkRisk): SignalVector
    {
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
            networkRisk: $networkRisk,
            trustCredit: (int) $result[11],
            principalCredit: (int) $result[12],
        );
    }

    /**
     * evalsha with noscript fallback (eval + script load, sha cached).
     *
     * @param list<string> $keys
     * @param list<int|string> $args
     * @return array<int|string>|int|string
     * @throws RiskStoreException on any non-noscript redis failure
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

    /** Cached sha1 of every static script (script load once per script per process). */
    private function shaOf(string $script): string
    {
        if (!isset($this->scriptShas[$script])) {
            $this->scriptShas[$script] = $this->loadScript($script);
        }
        return $this->scriptShas[$script];
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

    /** CRC-16/xmodem (poly 0x1021, init 0); "123456789" -> 0x31C3. */
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
