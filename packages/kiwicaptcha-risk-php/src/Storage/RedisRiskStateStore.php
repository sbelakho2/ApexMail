<?php

declare(strict_types=1);

namespace KiwiCaptcha\Risk\Storage;

use KiwiCaptcha\Risk\Asn\AsnBucket;
use KiwiCaptcha\Risk\DeploymentNamespace;
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
final class RedisRiskStateStore implements RiskStateStoreInterface, SessionContextTagStoreInterface, SessionTlsTagStoreInterface, ConsolidatedAssessmentStoreInterface, OutcomeMarksStoreInterface, SessionBucketTrustStoreInterface, TargetStateStoreInterface
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

    /**
     * The mark dimensions of the long-memory outcomes surface: the four
     * identity dimensions the typed handles carry plus the asn dimension
     * the network-aware callers address. Shared verbatim with the Rust
     * mirror and the cross-language vectors.
     */
    public const MARK_DIMENSIONS = ['principal', 'target', 'session', 'agent', 'asn'];

    /** Default lifetime of a long-memory mark (90 days, 7776000 s). */
    public const DEFAULT_MARK_TTL_SECS = 7_776_000;

    /** The largest accepted mark kind length in bytes (the outcome name). */
    public const MAX_MARK_KIND_BYTES = 64;

    /** The largest accepted trust delta (fixed-point units) per write. */
    public const MAX_BUCKET_TRUST_DELTA = 100_000;

    /**
     * The largest accepted TTL in seconds (10 years). Values above it are
     * refused at construction: Redis rejects an expire value beyond its
     * ceiling at request time, and a script that had already written the
     * hash before the failing EXPIRE would leave it persistent. The Lua
     * scripts validate the same class of value as the last line of
     * defense.
     */
    public const MAX_TTL_SECS = 315_360_000;

    private string $script;
    /** @var array<string, string> cached sha1 of every static script, keyed by the script content */
    private array $scriptShas = [];
    private string $assessV2Script;
    private string $outcomeRegisterScript;
    private string $outcomeConfirmScript;
    private string $outcomeCorrectScript;
    private string $marksScript;
    private string $trustScript;
    private int $lastGlobalLevel = 0;
    private int $lastCooldownUntilMs = 0;
    private bool $lastIsDuplicate = false;

    /**
     * The encoded namespace inside the `{kiwi:<ns>}` hash tag, derived
     * from the raw configured discriminator through the shared
     * {@see DeploymentNamespace} derivation.
     */
    private readonly string $namespace;

    /** The raw configured deployment discriminator this store was built from. */
    private readonly string $rawNamespace;

    /** The key-version contract the encoded namespace was derived under. */
    private readonly int $namespaceVersion;

    /**
     * @param string   $namespace       the raw configured deployment
     *                                  discriminator. The store derives
     *                                  the encoded `{kiwi:<namespace>}`
     *                                  tag internally, so an encoded
     *                                  value is never passed here.
     * @param int      $hysteresisMs    global level hysteresis window
     * @param array<string, int> $saturations raw saturation values keyed by the
     *                                  src_fast..principal channel names (Lua
     *                                  argv order). A partial map is overlaid
     *                                  on {@see self::DEFAULT_SATURATIONS}, so
     *                                  an omitted channel keeps its contract
     *                                  default; an unknown key is refused
     *                                  because it would be silently ignored.
     * @param int      $namespaceKeyVersion the key-version contract
     *                                  ({@see DeploymentNamespace::VERSION_LEGACY}
     *                                  or
     *                                  {@see DeploymentNamespace::VERSION_DIGEST})
     */
    public function __construct(
        private readonly Client $client,
        string $namespace = 'd',
        private readonly int $sourceEpochSecs = 900,
        private readonly int $subnetEpochSecs = 900,
        private readonly int $stateTtlSecs = 1800,
        private readonly int $sessionTtlSecs = 1800,
        private readonly int $principalTtlSecs = 86400,
        private readonly int $dedupeTtlSecs = 60,
        private readonly int $hysteresisMs = 60000,
        private readonly array $saturations = self::DEFAULT_SATURATIONS,
        private readonly int $outcomeTtlSecs = self::DEFAULT_OUTCOME_TTL_SECS,
        private readonly int $targetTtlSecs = 86_400,
        int $namespaceKeyVersion = DeploymentNamespace::VERSION_LEGACY,
        private readonly int $markTtlSecs = self::DEFAULT_MARK_TTL_SECS,
    ) {
        if ($namespace === '' || preg_match('/[{}]/', $namespace)) {
            throw new \InvalidArgumentException('Risk namespace must be non-empty and free of braces');
        }
        // The configuration invariants live at the lowest public API
        // boundary, not only in the Symfony bundle: a standalone caller
        // must never be able to build a store that writes a persistent
        // risk hash (TTL 0/negative), an invalid `SET ... EX 0`, an
        // immediately-deleted record, or nonsensical epoch/hysteresis
        // behaviour. The bundle's tree gives the friendlier first error;
        // this constructor is the security validation every caller gets.
        foreach ([
            'stateTtlSecs' => $stateTtlSecs,
            'sessionTtlSecs' => $sessionTtlSecs,
            'principalTtlSecs' => $principalTtlSecs,
            'dedupeTtlSecs' => $dedupeTtlSecs,
            'outcomeTtlSecs' => $outcomeTtlSecs,
            'markTtlSecs' => $markTtlSecs,
            'sourceEpochSecs' => $sourceEpochSecs,
            'subnetEpochSecs' => $subnetEpochSecs,
            'hysteresisMs' => $hysteresisMs,
        ] as $knob => $value) {
            if ($value < 1) {
                throw new \InvalidArgumentException(sprintf(
                    '%s must be >= 1 (got %d): a non-positive TTL/epoch/hysteresis window would write persistent or immediately-expired risk state',
                    $knob,
                    $value,
                ));
            }
        }
        // TTLs additionally carry the 10-year upper bound. Epoch windows
        // and the hysteresis window are durations too, but they are not
        // Redis expire values, so only the five TTLs get the bound.
        foreach ([
            'stateTtlSecs' => $stateTtlSecs,
            'sessionTtlSecs' => $sessionTtlSecs,
            'principalTtlSecs' => $principalTtlSecs,
            'dedupeTtlSecs' => $dedupeTtlSecs,
            'outcomeTtlSecs' => $outcomeTtlSecs,
            'markTtlSecs' => $markTtlSecs,
        ] as $knob => $value) {
            if ($value > self::MAX_TTL_SECS) {
                throw new \InvalidArgumentException(sprintf(
                    '%s must be <= %d (got %d): Redis rejects a bigger expire value at request time, after the risk hash is already written',
                    $knob,
                    self::MAX_TTL_SECS,
                    $value,
                ));
            }
        }
        // The saturation map is deliberately allowed to be partial: every
        // read path overlays it on the contract defaults (the Symfony bundle
        // only exposes the channels it tunes), so an omitted channel keeps
        // its contract default. An unknown key, however, would be silently
        // dropped by that overlay and must be refused instead.
        foreach ($saturations as $key => $value) {
            if (!\is_string($key) || !\array_key_exists($key, self::DEFAULT_SATURATIONS)) {
                throw new \InvalidArgumentException(sprintf(
                    'saturations must be keyed by the known channel names src_fast..principal (unknown key %s)',
                    var_export($key, true),
                ));
            }
            if (!\is_int($value) || $value < 1) {
                throw new \InvalidArgumentException(sprintf(
                    'saturations[%s] must be a positive integer (got %s)',
                    (string) $key,
                    var_export($value, true),
                ));
            }
        }
        $this->rawNamespace = $namespace;
        $this->namespaceVersion = $namespaceKeyVersion;
        $this->namespace = DeploymentNamespace::derive($namespace, $namespaceKeyVersion);
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
        $this->marksScript = self::loadOutcomeScript('marks.lua');
        $this->trustScript = self::loadOutcomeScript('trust.lua');
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

    /** The encoded deployment namespace inside the `{kiwi:<ns>}` hash tag. */
    public function namespace(): string
    {
        return $this->namespace;
    }

    /** The raw configured deployment discriminator this store was built from. */
    public function rawNamespace(): string
    {
        return $this->rawNamespace;
    }

    /** The key-version contract the encoded namespace was derived under. */
    public function namespaceVersion(): int
    {
        return $this->namespaceVersion;
    }

    /**
     * The outcome ledger key shared with the calibrator's register_decision /
     * confirm / correction scripts: {kiwi:<ns>}:outcome:<decisionId>.
     * The ledger is always on (calibration-independent): with calibration
     * enabled the calibrator writes it inside register_decision.lua; with
     * calibration disabled the store writes it here. One key, one
     * exactly-once authority.
     */
    public function ledgerKey(string $decisionId): string
    {
        self::assertKeySafeIdentifier('decisionId', $decisionId);

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
     * The target-dimension state keys of one target pseudonym: the
     * failure hash plus the source/asn spread HLLs, on the target id's
     * own family slot ({kiwi:<ns>:target:<hex2>}) — byte-identical with
     * the keys assess_v2.lua maintains (KEYS[14..16]) and the Rust
     * `keyspace::target_state_keys`. A stuffing storm against one target
     * then hits that target's slot, never the shared {kiwi:<ns>}
     * primary.
     *
     * @return list<string>
     */
    private function targetStateKeys(string $targetId): array
    {
        self::assertKeySafeIdentifier('targetId', $targetId);
        $hex2 = substr($targetId, 0, 2);

        return [
            "{kiwi:{$this->namespace}:target:{$hex2}}:risk:tgt:{$targetId}",
            "{kiwi:{$this->namespace}:target:{$hex2}}:risk:tgt:src:{$targetId}",
            "{kiwi:{$this->namespace}:target:{$hex2}}:risk:tgt:asn:{$targetId}",
        ];
    }

    /**
     * One target_failure.lua op, returning
     * {fails, spread_sources, spread_asns, first_ms, last_ms}.
     *
     * @return array{fails: int, spread_sources: int, spread_asns: int, first_ms: int, last_ms: int}
     */
    private function runTargetOp(string $op, string $targetId, string $source, string $asn): array
    {
        $keys = $this->targetStateKeys($targetId);
        $result = $this->runScript(
            $keys,
            [$op, $source, $asn, (string) $this->principalTtlSecs],
            self::loadOutcomeScript('target_failure.lua'),
        );
        if (!\is_array($result) || \count($result) < 5) {
            throw new RiskStoreException('the target_failure reply is not a 5-slot array');
        }

        return [
            'fails' => self::scriptInteger($result[0], 'target fails'),
            'spread_sources' => self::scriptInteger($result[1], 'target spread sources'),
            'spread_asns' => self::scriptInteger($result[2], 'target spread asns'),
            'first_ms' => self::scriptInteger($result[3], 'target first_ms'),
            'last_ms' => self::scriptInteger($result[4], 'target last_ms'),
        ];
    }

    /** @inheritdoc */
    public function registerTargetFailure(string $targetId, string $source, string $asn): array
    {
        return $this->runTargetOp('fail', $targetId, $source, $asn);
    }

    /** @inheritdoc */
    public function clearTargetFailures(string $targetId): void
    {
        $this->runTargetOp('clear', $targetId, '', '');
    }

    /** @inheritdoc */
    public function readTargetState(string $targetId): array
    {
        return $this->runTargetOp('read', $targetId, '', '');
    }

    /**
     * The long-memory mark key of one dimension and identifier:
     * mark:{kiwi:<ns>}:<dim>:<id>. The hash tag keeps every mark in the
     * risk keyspace's cluster slot; the dimension is one of the five
     * contract dimensions and the identifier follows the shared
     * key-safety rule.
     */
    public function markKey(string $dimension, string $id): string
    {
        self::assertMarkDimension($dimension);
        self::assertKeySafeIdentifier('id', $id);

        return "mark:{kiwi:{$this->namespace}}:{$dimension}:{$id}";
    }

    /**
     * Writes one long-memory mark atomically through the canonical
     * marks.lua: the max-severity kind, the latest kind, the count
     * increment, the first/last timestamps and the refreshed whole-key
     * TTL land in one script call. The clock is the server's TIME; the
     * \$nowMs argument is kept for wire compatibility and ignored.
     * \$eventId dedupes the write ('' disables dedupe). Returns the
     * mark's total count.
     *
     * @throws RiskStoreException when the underlying state backend fails
     */
    public function writeMark(string $dimension, string $id, string $kind, int $nowMs, string $eventId = ''): int
    {
        $key = $this->markKey($dimension, $id);
        if ($kind === '' || strlen($kind) > self::MAX_MARK_KIND_BYTES) {
            throw new \InvalidArgumentException(sprintf(
                'kind must be a non-empty value of at most %d bytes',
                self::MAX_MARK_KIND_BYTES,
            ));
        }
        if ($nowMs < 0) {
            throw new \InvalidArgumentException('nowMs must be >= 0');
        }
        // KEYS[2] is the event-id dedupe marker on the same slot; with
        // dedupe disabled the script never touches it. The marker is
        // scoped to this mark (dimension + id), so a reused event id on
        // another dimension can never suppress a different mark. The
        // event id itself must be a safe key component. The marker TTL
        // is the script's retry horizon (24 h), not the mark's long
        // TTL: one marker key per event id must not pin the keyspace
        // for the whole mark life.
        if ($eventId !== '') {
            self::assertKeySafeIdentifier('eventId', $eventId);
        }
        $marker = $eventId === '' ? $key : "{$key}:dd:{$eventId}";
        $result = $this->runScript(
            [$key, $marker],
            [$kind, $nowMs, $this->markTtlSecs * 1000, $eventId],
            $this->marksScript,
        );

        return self::scriptInteger($result, 'mark count');
    }

    /**
     * The current mark of one dimension and identifier: the hash fields
     * kind (max severity), last_kind, count, first_ms and last_ms, or
     * null when no mark exists.
     *
     * @return null|array{kind: string, count: int, first_ms: int, last_ms: int}
     * @throws RiskStoreException when the underlying state backend fails
     */
    public function readMark(string $dimension, string $id): ?array
    {
        $key = $this->markKey($dimension, $id);
        try {
            $raw = $this->client->hgetall($key);
        } catch (\Predis\Exception\Exception $e) {
            throw new RiskStoreException('Risk mark read failed: ' . $e->getMessage(), 0, $e);
        }
        if (!\is_array($raw) || $raw === []) {
            return null;
        }
        // Every field of a written mark decodes with the same fail-closed
        // contract as the observation reply: a corrupt or truncated hash
        // raises instead of coercing to a zeroed mark.
        $kind = $raw['kind'] ?? null;
        if (!\is_string($kind) || $kind === '') {
            throw new RiskStoreException('Risk mark hash is missing its kind field');
        }
        // A pre-severity writer has no last_kind; its kind WAS the
        // latest write, so it doubles as the latest.
        $lastKind = $raw['last_kind'] ?? null;

        return [
            'kind' => $kind,
            'last_kind' => \is_string($lastKind) && $lastKind !== '' ? $lastKind : $kind,
            'count' => self::scriptInteger($raw['count'] ?? null, 'mark count'),
            'first_ms' => self::scriptInteger($raw['first_ms'] ?? null, 'mark first_ms'),
            'last_ms' => self::scriptInteger($raw['last_ms'] ?? null, 'mark last_ms'),
        ];
    }

    /**
     * Removes the mark of one dimension and identifier and returns the
     * number of keys removed (0 or 1): the erasure path of the outcomes
     * plane, built from the exact key with no scan.
     *
     * @throws RiskStoreException when the underlying state backend fails
     */
    public function forgetMarks(string $dimension, string $id): int
    {
        $key = $this->markKey($dimension, $id);
        try {
            $removed = $this->client->del($key);
        } catch (\Predis\Exception\Exception $e) {
            throw new RiskStoreException('Risk mark erasure failed: ' . $e->getMessage(), 0, $e);
        }

        return (int) $removed;
    }

    /**
     * The context-bound trust record key of one session and ASN bucket:
     * trust:{kiwi:<ns>}:<session>:<bucket>. The hash tag keeps every
     * bucket record in the risk keyspace's cluster slot; the session is
     * the 32-char lowercase hex pseudonym and the bucket follows the
     * shared bucket-id grammar (AsnBucket::isValid).
     */
    public function bucketTrustKey(string $sessionId, string $bucket): string
    {
        if (preg_match('/^[0-9a-f]{32}$/', $sessionId) !== 1) {
            throw new \InvalidArgumentException(sprintf(
                'sessionId must be a 16-byte hex pseudonym (got 0x%s)',
                bin2hex($sessionId),
            ));
        }
        if (!AsnBucket::isValid($bucket)) {
            throw new \InvalidArgumentException(sprintf(
                'bucket must be a canonical bucket id (a<asn>, u4/<prefix> or u6/<8hex>; got %s)',
                $bucket,
            ));
        }

        return "trust:{kiwi:{$this->namespace}}:{$sessionId}:{$bucket}";
    }

    /**
     * Runs one trust.lua op (read, credit or decay) on the session's
     * bucket record and returns the record's post-op raw trust. The
     * record TTL is the store's session TTL (the trust dimension stays
     * aligned with the session dimension).
     *
     * @throws \InvalidArgumentException on an invalid session id, bucket
     *                                   id or delta
     * @throws RiskStoreException when the state backend fails
     */
    private function applyBucketTrust(string $sessionId, string $bucket, string $op, int $delta): int
    {
        if ($delta < 0 || $delta > self::MAX_BUCKET_TRUST_DELTA) {
            throw new \InvalidArgumentException(sprintf(
                'delta must be within 0..%d (got %d)',
                self::MAX_BUCKET_TRUST_DELTA,
                $delta,
            ));
        }
        $result = $this->runScript(
            [$this->bucketTrustKey($sessionId, $bucket)],
            [$op, $delta, $this->sessionTtlSecs * 1000],
            $this->trustScript,
        );

        return max(0, self::scriptInteger($result, 'bucket trust'));
    }

    /**
     * The decayed bucket-local trust of one session and bucket (0 when
     * no record): a pure read through the canonical trust.lua, never
     * mutating the record, so a foreign presentation cannot reduce home
     * credit.
     */
    public function readBucketTrust(string $sessionId, string $bucket): int
    {
        return $this->applyBucketTrust($sessionId, $bucket, 'read', 0);
    }

    /**
     * Credits the session's bucket record atomically (clamped at the
     * fixed-point ceiling, whole-key TTL refreshed) and returns the
     * record's new raw trust.
     */
    public function creditBucketTrust(string $sessionId, string $bucket, int $delta): int
    {
        return $this->applyBucketTrust($sessionId, $bucket, 'credit', $delta);
    }

    /**
     * Decays the session's bucket record atomically and returns the
     * record's new raw trust.
     */
    public function decayBucketTrust(string $sessionId, string $bucket, int $delta): int
    {
        return $this->applyBucketTrust($sessionId, $bucket, 'decay', $delta);
    }

    /**
     * Refuses a mark dimension outside the five contract dimensions: an
     * unknown dimension would silently address a key family nothing ever
     * reads.
     */
    private static function assertMarkDimension(string $dimension): void
    {
        if (!\in_array($dimension, self::MARK_DIMENSIONS, true)) {
            throw new \InvalidArgumentException(sprintf(
                'mark dimension must be one of %s (got %s)',
                implode('|', self::MARK_DIMENSIONS),
                $dimension,
            ));
        }
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
        self::assertKeySafeIdentifier('sessionId', $sessionId);
        $key = "{kiwi:{$this->namespace}}:risk:ctx:{$sessionId}";
        try {
            $set = $this->client->set($key, $tag, 'EX', $this->sessionTtlSecs, 'NX');
            // predis answers SET with a Status object (whose payload is
            // 'OK'), never a bare 'OK' string; null is the NX miss.
            if ($set instanceof \Predis\Response\Status && $set->getPayload() === 'OK') {
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
        self::assertKeySafeIdentifier('sessionId', $sessionId);
        $key = "{kiwi:{$this->namespace}}:risk:tls:{$sessionId}";
        try {
            $set = $this->client->set($key, $tag, 'EX', $this->sessionTtlSecs, 'NX');
            // predis answers SET with a Status object (whose payload is
            // 'OK'), never a bare 'OK' string; null is the NX miss.
            if ($set instanceof \Predis\Response\Status && $set->getPayload() === 'OK') {
                return $tag;
            }
            $stored = $this->client->get($key);

            return \is_string($stored) && $stored !== '' ? $stored : null;
        } catch (\Predis\Exception\Exception $e) {
            throw new RiskStoreException('Risk TLS-tag record failed: ' . $e->getMessage(), 0, $e);
        }
    }

    /**
     * Applies the observation and returns the full reply as a value
     * object (the PHP mirror of Rust's `Observed`): vector, global level,
     * cooldown deadline and dedupe verdict of this call — no side-channel
     * reads.
     *
     * @throws RiskStoreException when the underlying state backend fails
     */
    public function observeWithReply(RiskObservation $observation): ObservationReply
    {
        $keys = $this->observationKeys($observation);
        $this->assertSameSlot($keys);

        $args = $this->observationArgs($observation);
        $result = $this->runScript($keys, $args);

        if (!is_array($result) || count($result) < 16) {
            throw new RiskStoreException('Risk script returned an unexpected payload');
        }

        return new ObservationReply(
            vector: $this->signalVectorFromReply($result, $observation->networkRisk),
            globalLevel: self::scriptInteger($result[13], 'global level'),
            cooldownUntilMs: self::scriptInteger($result[14], 'cooldown deadline'),
            isDuplicate: self::scriptInteger($result[15], 'duplicate flag') !== 0,
        );
    }

    /**
     * @deprecated use observeWithReply(): the reply object is call-scoped
     *             and immutable, while this method's companion side
     *             channels lastGlobalLevel(), lastCooldownUntilMs() and
     *             lastIsDuplicate() are shared mutable state — racy when
     *             a coroutine runtime interleaves two observations on one
     *             store instance. Kept as a delegating BC shim.
     */
    public function observe(RiskObservation $observation): SignalVector
    {
        $reply = $this->observeWithReply($observation);
        $this->lastGlobalLevel = $reply->globalLevel;
        $this->lastCooldownUntilMs = $reply->cooldownUntilMs;
        $this->lastIsDuplicate = $reply->isDuplicate;
        return $reply->vector;
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
    /**
     * The consolidated risk-v2 assessment as a value object (the PHP
     * mirror of Rust's `AssessV2Reply`): the signal vector, the global
     * level, the cooldown deadline, the dedupe verdict, the recorded tag
     * values and the registration status of this call. No side-channel
     * reads.
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
     * @throws RiskStoreException when the underlying state backend fails
     */
    public function assessV2WithReply(
        RiskObservation $observation,
        ?string $contextTag,
        ?string $tlsTag,
        ?OutcomeRegistration $registration = null,
    ): AssessV2Reply {
        $sessionId = $observation->sessionId ?? str_repeat('0', 32);
        $keys = [...$this->observationKeys($observation),
            "{kiwi:{$this->namespace}}:risk:ctx:{$sessionId}",
            "{kiwi:{$this->namespace}}:risk:tls:{$sessionId}",
        ];
        // Stable KEYS positions 13..16: ledger then the three target
        // slots, always present so the Lua index map never shifts.
        $keys[] = $registration !== null
            ? $this->ledgerKey($registration->decisionId)
            : "{kiwi:{$this->namespace}}:risk:ledger:unused";
        if ($registration !== null && $registration->targetId !== null && $registration->targetId !== '') {
            foreach ($this->targetStateKeys($registration->targetId) as $k) {
                $keys[] = $k;
            }
        } else {
            $keys[] = "{kiwi:{$this->namespace}}:risk:tgt:unused";
            $keys[] = "{kiwi:{$this->namespace}}:risk:tgt:src:unused";
            $keys[] = "{kiwi:{$this->namespace}}:risk:tgt:asn:unused";
        }
        $this->assertSameSlot($keys);

        $args = [...$this->observationArgs($observation), $contextTag ?? '', $tlsTag ?? ''];
        if ($registration !== null) {
            $v2w = $registration->v2Weights;
            $args = [...$args,
                $registration->decisionId,
                $registration->decisionHour,
                $this->outcomeTtlSecs,
                $observation->networkRisk,
                $registration->globalPressureEnabled ? 1 : 0,
                $registration->baseRisk,
                $registration->honeypotHit ? 1 : 0,
                ...array_values($registration->weights->toArray()),
                // The wire still takes exactly three risk-v2 weights at
                // ARGV[45..47]; the two target weights ride ARGV[52..53].
                $v2w->honeypot,
                $v2w->sessionInconsistency,
                $v2w->tls,
                ($registration->targetId !== null && $registration->targetId !== '') ? 1 : 0,
                '',
                '',
                $this->targetTtlSecs,
                $v2w->targetFailurePressure,
                $v2w->targetSpread,
            ];
        } else {
            $args = [...$args, '', 0, 0, 0, 1, 0, 0, ...array_fill(0, 16, 0), 0, '', '', $this->targetTtlSecs, 0, 0];
        }
        $result = $this->runScript($keys, $args, $this->assessV2Script);

        if (!is_array($result) || count($result) < 22) {
            throw new RiskStoreException('Risk script returned an unexpected payload');
        }

        return new AssessV2Reply(
            vector: $this->signalVectorFromReply($result, $observation->networkRisk),
            globalLevel: self::scriptInteger($result[13], 'global level'),
            cooldownUntilMs: self::scriptInteger($result[14], 'cooldown deadline'),
            isDuplicate: self::scriptInteger($result[15], 'duplicate flag') !== 0,
            existingContextTag: self::scriptTag($result[16], 'client-context tag'),
            existingTlsTag: self::scriptTag($result[17], 'TLS tag'),
            registrationStatus: self::scriptInteger($result[18], 'registration status') !== 0,
            targetFailures: self::scriptInteger($result[19], 'target failures'),
            targetSpreadSources: self::scriptInteger($result[20], 'target spread sources'),
            targetSpreadAsns: self::scriptInteger($result[21], 'target spread asns'),
        );
    }

    /**
     * @deprecated use assessV2WithReply(): the reply object is call-scoped
     *             and immutable, while this method's companion side
     *             channels lastGlobalLevel(), lastCooldownUntilMs() and
     *             lastIsDuplicate() are shared mutable state — racy when
     *             a coroutine runtime interleaves two assessments on one
     *             store instance. Kept as a delegating BC shim.
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
        $reply = $this->assessV2WithReply($observation, $contextTag, $tlsTag, $registration);
        $this->lastGlobalLevel = $reply->globalLevel;
        $this->lastCooldownUntilMs = $reply->cooldownUntilMs;
        $this->lastIsDuplicate = $reply->isDuplicate;
        return [
            $reply->vector,
            $reply->existingContextTag,
            $reply->existingTlsTag,
            $reply->registrationStatus,
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
        return self::keysFor(
            $this->rawNamespace,
            $this->namespaceVersion,
            $observation->sourceEpoch,
            $observation->sourceIdPrev,
            $observation->sourceId,
            $observation->sourceIdNext,
            $observation->subnetEpoch,
            $observation->subnetIdPrev,
            $observation->subnetId,
            $observation->subnetIdNext,
            $observation->sessionId,
            $observation->principalId,
            $observation->eventId,
        );
    }

    /**
     * The full key set for one observation, in the Lua keys order, built
     * from the RAW configured discriminator and an explicit key version:
     * the returned keys are exactly the keys a store constructed with the
     * same pair produces. Public so tests (and tooling) can build and
     * inspect the exact key layout; the Rust risk crate exposes the
     * identical builder as `RedisRiskStateStore::keys_for`.
     *
     * @return list<string>
     */
    public static function keysFor(
        string $rawNamespace,
        int $namespaceKeyVersion,
        int $sourceEpoch,
        string $sourceIdPrev,
        string $sourceId,
        string $sourceIdNext,
        int $subnetEpoch,
        string $subnetIdPrev,
        string $subnetId,
        string $subnetIdNext,
        ?string $sessionId,
        ?string $principalId,
        string $eventId,
    ): array {
        self::assertKeySafeIdentifier('sourceIdPrev', $sourceIdPrev);
        self::assertKeySafeIdentifier('sourceId', $sourceId);
        self::assertKeySafeIdentifier('sourceIdNext', $sourceIdNext);
        self::assertKeySafeIdentifier('subnetIdPrev', $subnetIdPrev);
        self::assertKeySafeIdentifier('subnetId', $subnetId);
        self::assertKeySafeIdentifier('subnetIdNext', $subnetIdNext);
        self::assertKeySafeIdentifier('eventId', $eventId);
        if ($sessionId !== null) {
            self::assertKeySafeIdentifier('sessionId', $sessionId);
        }
        if ($principalId !== null) {
            self::assertKeySafeIdentifier('principalId', $principalId);
        }

        $tag = '{kiwi:'.DeploymentNamespace::derive($rawNamespace, $namespaceKeyVersion).'}';
        $sessionId ??= str_repeat('0', 32);
        $principalId ??= str_repeat('0', 32);

        return [
            "{$tag}:risk:src:{$sourceEpoch}:{$sourceId}",
            "{$tag}:risk:src:" . self::offsetEpoch($sourceEpoch, -1) . ":{$sourceIdPrev}",
            "{$tag}:risk:src:" . self::offsetEpoch($sourceEpoch, 1) . ":{$sourceIdNext}",
            "{$tag}:risk:net:{$subnetEpoch}:{$subnetId}",
            "{$tag}:risk:net:" . self::offsetEpoch($subnetEpoch, -1) . ":{$subnetIdPrev}",
            "{$tag}:risk:net:" . self::offsetEpoch($subnetEpoch, 1) . ":{$subnetIdNext}",
            "{$tag}:risk:session:{$sessionId}",
            "{$tag}:risk:principal:{$principalId}",
            "{$tag}:risk:global",
            "{$tag}:risk:dedupe:{$eventId}",
        ];
    }

    /**
     * Adds a small epoch offset without leaving the integer range. At the
     * PHP_INT boundary the neighbouring epoch folds onto the boundary
     * (the value is astronomically outside any real clock window), so the
     * key grammar never receives a float in scientific notation. The
     * RiskObservation constructor refuses boundary epochs for its own
     * path; this keeps direct keysFor() callers safe too.
     */
    private static function offsetEpoch(int $epoch, int $delta): int
    {
        if ($delta > 0 && $epoch > PHP_INT_MAX - $delta) {
            return PHP_INT_MAX;
        }
        if ($delta < 0 && $epoch < PHP_INT_MIN - $delta) {
            return PHP_INT_MIN;
        }

        return $epoch + $delta;
    }

    /**
     * Refuses a caller identifier that would inject key structure or
     * control bytes into a Redis key. The engines pass 32-char lowercase
     * hex decision/session pseudonyms. Any other value must be a
     * non-empty, valid UTF-8 string free of control characters. The
     * refused class covers the ASCII controls, DEL, the encoded C1 range
     * and the Unicode line/paragraph separators, plus ":" and "}" (the
     * key separator and the hash-tag closing byte). Invalid UTF-8 — including a lone
     * raw C1 byte — is refused: it is not a displayable identifier and
     * its control interpretation is ambiguous. Throwing fails closed
     * before any key reaches Redis.
     */
    /**
     * The shared key-safety rule for caller-supplied identifiers: a
     * 32-char lowercase hex id always passes; otherwise the value must be
     * non-empty UTF-8 free of control characters, ":" and "}". Public so
     * the calibrator (whose receipt/ledger keys embed the decision id
     * verbatim) enforces the identical rule.
     */
    public static function assertKeySafeIdentifier(string $name, string $value): void
    {
        if (preg_match('/^[0-9a-f]{32}$/', $value) === 1) {
            return;
        }
        if ($value === '' || preg_match('//u', $value) !== 1
            || preg_match('/[\x00-\x1f\x7f:}]|\xc2[\x80-\x9f]|\xe2\x80[\xa8\xa9]/', $value) === 1) {
            throw new \InvalidArgumentException(sprintf(
                '%s must be a 32-char lowercase hex id or a non-empty UTF-8 value free of control characters, ":" and "}" (got 0x%s)',
                $name,
                bin2hex($value),
            ));
        }
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

    /**
     * Decodes one integer slot of a script reply with the same fail-closed
     * contract as the Rust core's `value_i64`: only an integer reply or a
     * parseable integer string is accepted, matching the typed `Vec<i64>`
     * decode the observation path uses. A malformed or shifted reply (a
     * Nil, an array, a non-numeric string) raises RiskStoreException
     * instead of coercing to 0, so a shifted reply can never zero a
     * signal slot.
     *
     * @throws RiskStoreException
     */
    private static function scriptInteger(mixed $value, string $slot): int
    {
        if (\is_int($value)) {
            return $value;
        }
        if (\is_string($value) && preg_match('/^[+-]?[0-9]+$/D', $value) === 1) {
            $parsed = filter_var($value, \FILTER_VALIDATE_INT);
            if ($parsed !== false) {
                return $parsed;
            }
        }

        throw new RiskStoreException(sprintf('Risk script returned a non-integer value for %s', $slot));
    }

    /**
     * Decodes one tag slot of a script reply: a string, or null for the
     * Redis Nil reply (an empty string is the normalization of "no
     * recorded tag"). Every other reply type fails closed exactly like
     * scriptInteger(), so a shifted integer/array in a tag slot can never
     * silently read as "no recorded tag".
     *
     * @throws RiskStoreException
     */
    private static function scriptTag(mixed $value, string $slot): ?string
    {
        if ($value === null) {
            return null;
        }
        if (\is_string($value)) {
            return $value === '' ? null : $value;
        }

        throw new RiskStoreException(sprintf('Risk script returned a non-string value for %s', $slot));
    }

    /** Maps the script reply's 13 signal slots onto the SignalVector. */
    private function signalVectorFromReply(array $result, int $networkRisk): SignalVector
    {
        return new SignalVector(
            sourceFast: self::scriptInteger($result[0], 'source_fast'),
            sourceSlow: self::scriptInteger($result[1], 'source_slow'),
            subnetFast: self::scriptInteger($result[2], 'subnet_fast'),
            issueDebt: self::scriptInteger($result[3], 'issue_debt'),
            badProof: self::scriptInteger($result[4], 'bad_proof'),
            malformed: self::scriptInteger($result[5], 'malformed'),
            replay: self::scriptInteger($result[6], 'replay'),
            actionFailure: self::scriptInteger($result[7], 'action_failure'),
            scopeSwitch: self::scriptInteger($result[8], 'scope_switch'),
            globalPressure: self::scriptInteger($result[9], 'global_pressure'),
            networkRisk: $networkRisk,
            trustCredit: self::scriptInteger($result[11], 'trust_credit'),
            principalCredit: self::scriptInteger($result[12], 'principal_credit'),
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
     * Asserts every key carries a known family hash tag: either the
     * shared {kiwi:<ns>} tag or the target family {kiwi:<ns>:target:<hex2>}
     * (the target failure hash and its spread HLLs ride their own slot so
     * a stuffing storm never hammers the shared primary).
     *
     * @param list<string> $keys
     * @throws \LogicException on an unknown or missing hash tag
     */
    public function assertSameSlot(array $keys): void
    {
        $shared = "{kiwi:{$this->namespace}}";
        $targetFamily = "{kiwi:{$this->namespace}:target:";
        foreach ($keys as $key) {
            if (str_starts_with($key, $shared) || str_starts_with($key, $targetFamily)) {
                continue;
            }
            throw new \LogicException(sprintf(
                'Key %s does not carry the %s hash tag or the target family',
                $key,
                $shared,
            ));
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
