<?php

declare(strict_types=1);

namespace KiwiCaptcha\Risk\Storage;

use KiwiCaptcha\Risk\DeploymentNamespace;
use KiwiCaptcha\Risk\RiskObservation;
use KiwiCaptcha\Risk\SignalVector;
use Predis\Client;
use Predis\Command\RawCommand;
use Predis\Response\ServerException;

/**
 * Redis-backed risk state store over the sharded keyspace (Plane 7):
 * the horizontally scalable layout, spread over Redis Cluster slots so
 * throughput scales with the shard count. Key derivation is
 * byte-identical with the Rust mirror `kiwicaptcha_risk::sharded`; both
 * run the sharded Lua family bundled at resources/sharded_*.lua (three
 * canonical copies: protocol/risk-v1/ and both packages, all
 * byte-equal).
 *
 * Key map: the family tag is the hash tag, and one script touches one
 * slot. The identity state lives at
 * `{kiwi:<ns>:<dim>:<hex2>}:risk:<dim>[:<epoch>]:<id>`. Its
 * per-dimension dedupe marker lives at
 * `{kiwi:<ns>:<dim>:<hex2>}:risk:dd:<event_id>`. The nonce dedupe key
 * lives at `{kiwi:<ns>:n:<hex2>}:risk:dedupe:<event_id>`. The scope
 * aggregate shard lives at
 * `{kiwi:<ns>:s:<id>:<shard>}:scope:<id>:<shard>`, with its marker at
 * `{kiwi:<ns>:s:<id>:<shard>}:dd:<event_id>`. The hysteresis state is
 * `{kiwi:<ns>}:risk:hyst` and the mode marker is `{kiwi:<ns>}:mode`.
 *
 * <dim> names a source, net, session or principal family. <hex2> is the
 * two hex characters of the family identifier's first byte. <shard> is
 * fnv1a32(event_id) mod 16. Source and subnet keep their epoch boundary
 * pseudonyms: each pseudonym carries its own family prefix, so the
 * boundary reads run as their own read-only invocations and the caller
 * sums the replies exactly per the risk-v1 sum3 contract.
 *
 * Batching contract: one assessment is one pipelined batch. The batch's
 * invocations are grouped by endpoint (the owner of each key's slot:
 * the real cluster node from the topology, or the slot-modulo stand-in
 * server). Every group is fully written before any reply is read, and
 * the read phase then drains each group. The wall clock is one round
 * trip per touched slot group, with the touched nodes processing in
 * parallel. Two batches exist per store instance: the assessment batch,
 * and the merge batch that re-reads the 16 scope shards, issued at most
 * once per second.
 *
 * Staleness contract of the merged aggregate: the scope/global pressure
 * lives in 16 shard counters and is merged on read. A merge may lag the
 * newest commit by at most one second. An assessment that arrives
 * inside the window reuses the last merged value for the level
 * transition, while the written shard's post-apply sum is written back
 * into the cache, so every committed increment is visible to the next
 * read.
 *
 * Atomicity boundaries (every transition and its boundary):
 *
 * - identity dimension apply: one state hash plus its marker, one Lua
 *   script on one slot. The marker is SET NX inside the script, so a
 *   partial-batch retry cannot double-count.
 * - scope shard increment: one shard hash plus its marker, one script,
 *   one slot, the same marker rule.
 * - nonce dedupe verdict: one marker key, one SET NX EX, single-slot
 *   and atomic.
 * - level/cooldown transition: one hysteresis hash, one script, one
 *   slot; concurrent assessments serialize on the hash.
 * - first-seen session tags: one record key each, one SET NX EX; the
 *   lifetime rides the write.
 * - outcome ledger register/confirm/correct: one ledger key, the
 *   canonical script per transition; pending flips exactly once,
 *   corrections only after confirmation.
 * - marks and bucket trust: one key each, the canonical script per op.
 * - cross-dimension max/sum: client-side, over already-committed
 *   per-slot state; each dimension's own atomicity stays per-slot.
 *
 * Single-use consume (the nonce marker, the ledger transitions, the
 * first-seen tags) and the level chain stay single-slot on purpose: a
 * wider batch would widen the atomicity boundary without adding
 * throughput, because these transitions touch one key each.
 *
 * Keyspace mode and the mixed-fleet rule: a namespace carries exactly
 * one layout, recorded in its mode marker key {kiwi:<ns>}:mode. This
 * store claims the marker (SET NX, persistent) with the sharded value
 * at construction and refuses a legacy-marked namespace with a
 * RiskStoreException; it never falls back. The classic
 * RedisRiskStateStore keeps its construction lazy, so an operator
 * wiring the legacy layout should assert the marker through
 * KeyspaceMode::claim($client, $ns, KeyspaceMode::Legacy) at wiring
 * time. The rule for a mixed fleet: pick the mode once per namespace
 * before any store serves traffic, and drain the stores of the other
 * mode before switching. The two layouts address disjoint state
 * families, so a straggler would observe an empty keyspace.
 *
 * Auxiliary surfaces: the outcome ledger, the long-memory marks, the
 * bucket trust records and the first-seen session tag records are
 * single-key scripts. Their slot placement is irrelevant to throughput,
 * so they keep the shared {kiwi:<ns>} tag in both modes and this store
 * delegates them to an embedded classic store aimed at the node that
 * owns that tag. The assessment path is where the sharded layout lives.
 */
final class ShardedRedisRiskStateStore implements RiskStateStoreInterface, SessionContextTagStoreInterface, SessionTlsTagStoreInterface, ConsolidatedAssessmentStoreInterface, OutcomeMarksStoreInterface, SessionBucketTrustStoreInterface, TargetStateStoreInterface
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

    /** The scope aggregate id the assessment path maintains. */
    public const GLOBAL_AGGREGATE_ID = 'global';

    /** The largest accepted TTL in seconds (10 years), mirroring the classic store's bound. */
    public const MAX_TTL_SECS = 315_360_000;

    private readonly string $namespace;
    private readonly string $rawNamespace;
    private readonly int $namespaceVersion;

    /** One Predis client per routed endpoint (cluster node or stand-in server). */
    private readonly array $clients;

    /** Cluster slot ranges over endpoint indices; empty for stand-in routing. */
    private readonly array $slotRanges;

    private RedisRiskStateStore $legacy;

    /** Cached script shas, keyed by script source. */
    private array $scriptShas = [];

    private int $lastGlobalLevel = 0;
    private int $lastCooldownUntilMs = 0;
    private bool $lastIsDuplicate = false;

    /** The per-shard merge cache and the millisecond it was refreshed at. */
    private array $mergePerShard = [];
    private int $mergedAtMs = 0;

    private readonly int $stateTtlSecs;
    private readonly int $sessionTtlSecs;
    private readonly int $principalTtlSecs;
    private readonly int $dedupeTtlSecs;
    private readonly int $hysteresisMs;
    private readonly int $outcomeTtlSecs;

    /** @var array<string, int> */
    private array $saturations;

    private readonly float $connectTimeoutSecs;
    private readonly float $commandTimeoutSecs;

    /**
     * @param list<string> $endpoints the routed Redis URLs. Without
     *                                cluster routing one stand-in server
     *                                per entry; with cluster routing the
     *                                first entry is the topology seed and
     *                                the discovered primaries replace the
     *                                list.
     * @param int             $poolSize advisory symmetry with the Rust
     *                                store's per-endpoint pools. The
     *                                Predis driver serves one request
     *                                per worker and opens one
     *                                connection per endpoint.
     * @param array<string, int> $saturations raw saturations keyed by
     *                                the src_fast..principal channel
     *                                names. A partial map is overlaid on
     *                                the contract defaults; an unknown
     *                                key is refused.
     *
     * @throws \InvalidArgumentException on the same configuration
     *                                    bounds the classic store
     *                                    enforces
     * @throws RiskStoreException when the namespace is marked for the
     *                            legacy layout, or when the backend
     *                            cannot serve the mode claim
     */
    public function __construct(
        array $endpoints,
        string $namespace = 'd',
        int $namespaceKeyVersion = DeploymentNamespace::VERSION_LEGACY,
        bool $cluster = false,
        int $poolSize = 2,
        int $stateTtlSecs = 1800,
        int $sessionTtlSecs = 1800,
        int $principalTtlSecs = 86400,
        int $dedupeTtlSecs = 60,
        int $hysteresisMs = 60000,
        array $saturations = self::DEFAULT_SATURATIONS,
        int $outcomeTtlSecs = RedisRiskStateStore::DEFAULT_OUTCOME_TTL_SECS,
        int $markTtlSecs = RedisRiskStateStore::DEFAULT_MARK_TTL_SECS,
        float $connectTimeoutSecs = 0.005,
        float $commandTimeoutSecs = 0.010,
    ) {
        if ($namespace === '' || preg_match('/[{}]/', $namespace) === 1) {
            throw new \InvalidArgumentException('Risk namespace must be non-empty and free of braces');
        }
        if ($endpoints === []) {
            throw new \InvalidArgumentException('the sharded store needs at least one endpoint');
        }
        if ($poolSize < 1) {
            throw new \InvalidArgumentException('poolSize must be >= 1');
        }
        foreach ([
            'stateTtlSecs' => $stateTtlSecs,
            'sessionTtlSecs' => $sessionTtlSecs,
            'principalTtlSecs' => $principalTtlSecs,
            'dedupeTtlSecs' => $dedupeTtlSecs,
            'outcomeTtlSecs' => $outcomeTtlSecs,
            'markTtlSecs' => $markTtlSecs,
            'hysteresisMs' => $hysteresisMs,
        ] as $knob => $value) {
            if ($value < 1) {
                throw new \InvalidArgumentException(sprintf(
                    '%s must be >= 1 (got %d): a non-positive TTL/window would write persistent or immediately-expired risk state',
                    $knob,
                    $value,
                ));
            }
        }
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
                    '%s must be <= %d (got %d)',
                    $knob,
                    self::MAX_TTL_SECS,
                    $value,
                ));
            }
        }
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
        $this->stateTtlSecs = $stateTtlSecs;
        $this->sessionTtlSecs = $sessionTtlSecs;
        $this->principalTtlSecs = $principalTtlSecs;
        $this->dedupeTtlSecs = $dedupeTtlSecs;
        $this->hysteresisMs = $hysteresisMs;
        $this->outcomeTtlSecs = $outcomeTtlSecs;
        $this->saturations = $saturations;
        $this->connectTimeoutSecs = $connectTimeoutSecs;
        $this->commandTimeoutSecs = $commandTimeoutSecs;

        // Endpoints: the seed list, or the cluster topology resolved
        // from the first seed.
        $clients = array_map(
            static fn (string $url): Client => self::createClient($url, $connectTimeoutSecs, $commandTimeoutSecs),
            array_values($endpoints),
        );
        $slotRanges = [];
        if ($cluster) {
            [$clients, $slotRanges] = $this->fetchClusterTopology($clients[0]);
        }
        $this->clients = $clients;
        $this->slotRanges = $slotRanges;

        // The mode marker claim: construction refuses a namespace the
        // other layout already governs (no silent fallback).
        $markerKey = KeyspaceMode::modeMarkerKey($this->namespace);
        KeyspaceMode::claim($this->clientForSlot($this->slotOf($markerKey)), $this->namespace, KeyspaceMode::Sharded);

        // The auxiliary single-key surfaces ride an embedded classic
        // store aimed at the endpoint owning the shared tag, carrying
        // this store's exact knobs.
        $sharedTag = "{kiwi:{$this->namespace}}";
        $this->legacy = new RedisRiskStateStore(
            $this->clientForSlot($this->slotOf($sharedTag)),
            namespace: $namespace,
            stateTtlSecs: $stateTtlSecs,
            sessionTtlSecs: $sessionTtlSecs,
            principalTtlSecs: $principalTtlSecs,
            dedupeTtlSecs: $dedupeTtlSecs,
            hysteresisMs: $hysteresisMs,
            saturations: $saturations,
            outcomeTtlSecs: $outcomeTtlSecs,
            namespaceKeyVersion: $namespaceKeyVersion,
            markTtlSecs: $markTtlSecs,
        );
    }

    /**
     * A client with the contract timeouts: connection 5 ms, read/write
     * 10 ms by default (seconds in Predis, and practical timeouts may be
     * rounded up by the platform; treat them as best-effort fail-fast
     * values). The store applies the same timeouts to the topology seed,
     * the discovered cluster nodes and the embedded classic store's
     * client is the caller's choice.
     */
    private static function createClient(string $url, float $connectTimeoutSecs, float $commandTimeoutSecs): Client
    {
        return new Client($url, [
            'connection' => [
                'timeout' => $connectTimeoutSecs,
                'read_write_timeout' => $commandTimeoutSecs,
            ],
        ]);
    }

    /** A client with this store's timeouts for a discovered cluster node. */
    private function clientForUrl(string $url): Client
    {
        return new Client($url, [
            'connection' => [
                'timeout' => $this->connectTimeoutSecs,
                'read_write_timeout' => $this->commandTimeoutSecs,
            ],
        ]);
    }

    /**
     * Test and operations hook: disconnects every endpoint connection,
     * so the next batch reconnects (the same eviction a failed batch
     * forces through the dispatch poison rule).
     *
     * @internal
     */
    public function disconnectAll(): void
    {
        foreach ($this->clients as $client) {
            try {
                $client->getConnection()->disconnect();
            } catch (\Throwable) {
                // Best effort: a wedged connection is replaced lazily.
            }
        }
    }

    /** The encoded deployment namespace inside the family tags. */
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

    /** The number of routed endpoints (cluster nodes or stand-in servers). */
    public function endpointCount(): int
    {
        return \count($this->clients);
    }

    /** The endpoint index that owns a key's cluster slot: the real topology range, or slot modulo the endpoint list. */
    public function endpointForKey(string $key): int
    {
        return $this->endpointForSlot($this->slotOf($key));
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

    /**
     * The merged scope aggregate pressure: the latest known per-shard
     * sums, refreshed through the merge batch when the window has
     * passed. Diagnostic and test surface for the staleness contract.
     *
     * @throws RiskStoreException when the merge batch cannot be served
     */
    public function mergedGlobalPressure(): int
    {
        return array_sum($this->mergedPerShard());
    }

    /**
     * Applies the observation through the sharded batch and returns the
     * full reply (the same contract the classic store's
     * observeWithReply gives).
     *
     * @throws RiskStoreException when the underlying state backend fails
     */
    public function observeWithReply(RiskObservation $observation): ObservationReply
    {
        $assessment = $this->runAssessment($observation, null, null, null);

        return new ObservationReply(
            vector: $assessment['vector'],
            globalLevel: $assessment['globalLevel'],
            cooldownUntilMs: $assessment['cooldownUntilMs'],
            isDuplicate: $assessment['isDuplicate'],
        );
    }

    /**
     * Applies the observation and returns the vector, refreshing the
     * call-scoped side channels (the delegating shape the classic
     * store's observe shim keeps for BC).
     *
     * @throws RiskStoreException when the underlying state backend fails
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
     * The sharded consolidated risk-v2 assessment: the same reply object
     * the classic store's assessV2WithReply gives. It is assembled from
     * the pipelined per-dimension batch, the single-key tag records and
     * the canonical ledger registration, whose score is computed
     * client-side from the exact signals, base risk and weights.
     *
     * @throws RiskStoreException when the underlying state backend fails
     */
    public function assessV2WithReply(
        RiskObservation $observation,
        ?string $contextTag,
        ?string $tlsTag,
        ?OutcomeRegistration $registration = null,
    ): AssessV2Reply {
        $assessment = $this->runAssessment($observation, $contextTag, $tlsTag, $registration);

        return new AssessV2Reply(
            vector: $assessment['vector'],
            globalLevel: $assessment['globalLevel'],
            cooldownUntilMs: $assessment['cooldownUntilMs'],
            isDuplicate: $assessment['isDuplicate'],
            existingContextTag: $assessment['existingContextTag'],
            existingTlsTag: $assessment['existingTlsTag'],
            registrationStatus: $assessment['registrationStatus'],
        );
    }

    /**
     * The delegating BC shim, mirroring the classic store's assessV2.
     *
     * @return array{0: SignalVector, 1: ?string, 2: ?string, 3: bool}
     *
     * @throws RiskStoreException when the underlying state backend fails
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
     * The canonical ledger registration on the decision-id key family
     * (the same key the assessment path's consolidated registration
     * writes), so confirm/correct resolve the same ledger.
     */
    public function registerOutcome(string $decisionId, int $scope, int $decisionHour, int $score): bool
    {
        $result = $this->runOutcomeScript('outcome_register.lua', $decisionId, [
            (string) $scope,
            (string) $decisionHour,
            (string) $score,
            (string) $this->outcomeTtlSecs,
        ]);

        return (int) $result !== 0;
    }

    /** The canonical exactly-once confirmation on the decision-id key family. */
    public function confirmOutcome(string $decisionId, bool $legitimate): int
    {
        return (int) $this->runOutcomeScript('outcome_confirm.lua', $decisionId, [
            $legitimate ? 'L' : 'A',
            (string) $this->outcomeTtlSecs,
        ]);
    }

    /** The canonical correction on the decision-id key family. */
    public function correctOutcome(string $decisionId, bool $legitimate): bool
    {
        $result = $this->runOutcomeScript('outcome_correct.lua', $decisionId, [
            $legitimate ? 'L' : 'A',
            (string) $this->outcomeTtlSecs,
        ]);

        return (int) $result !== 0;
    }

    /** One single-key canonical outcome-ledger script on the decision-id family key. */
    private function runOutcomeScript(string $file, string $decisionId, array $args): mixed
    {
        $key = KeyspaceMode::outcomeLedgerKey($this->namespace, $decisionId);
        $script = self::shardedScript($file);
        $replies = $this->dispatch([[
            'endpoint' => $this->endpointForKey($key),
            'cmd' => $this->evalshaCmd($script, [$key], $args),
            'script' => $script,
        ]]);

        return $replies[0] ?? null;
    }

    /** @inheritdoc */
    public function registerTargetFailure(string $targetId, string $source, string $asn): array
    {
        return $this->legacy->registerTargetFailure($targetId, $source, $asn);
    }

    /** @inheritdoc */
    public function clearTargetFailures(string $targetId): void
    {
        $this->legacy->clearTargetFailures($targetId);
    }

    /** @inheritdoc */
    public function readTargetState(string $targetId): array
    {
        return $this->legacy->readTargetState($targetId);
    }

    /** The classic mark key: the marks surface is mode-insensitive (shared tag). */
    public function markKey(string $dimension, string $id): string
    {
        return $this->legacy->markKey($dimension, $id);
    }

    /** The canonical mark write through the embedded classic store. */
    public function writeMark(string $dimension, string $id, string $kind, int $nowMs, string $eventId = ''): int
    {
        return $this->legacy->writeMark($dimension, $id, $kind, $nowMs, $eventId);
    }

    /** The canonical mark read through the embedded classic store. */
    public function readMark(string $dimension, string $id): ?array
    {
        return $this->legacy->readMark($dimension, $id);
    }

    /** The canonical mark erasure through the embedded classic store. */
    public function forgetMarks(string $dimension, string $id): int
    {
        return $this->legacy->forgetMarks($dimension, $id);
    }

    /** The classic trust record key: the trust surface is mode-insensitive (shared tag). */
    public function bucketTrustKey(string $sessionId, string $bucket): string
    {
        return $this->legacy->bucketTrustKey($sessionId, $bucket);
    }

    /** The canonical trust read through the embedded classic store. */
    public function readBucketTrust(string $sessionId, string $bucket): int
    {
        return $this->legacy->readBucketTrust($sessionId, $bucket);
    }

    /** The canonical trust credit through the embedded classic store. */
    public function creditBucketTrust(string $sessionId, string $bucket, int $delta): int
    {
        return $this->legacy->creditBucketTrust($sessionId, $bucket, $delta);
    }

    /** The canonical trust decay through the embedded classic store. */
    public function decayBucketTrust(string $sessionId, string $bucket, int $delta): int
    {
        return $this->legacy->decayBucketTrust($sessionId, $bucket, $delta);
    }

    /** The first-seen client-context record on the session key family. */
    public function sessionFirstContextTag(string $sessionId, string $tag): ?string
    {
        return $this->sessionFirstTagRecord(
            KeyspaceMode::sessionTagKey($this->namespace, 'ctx', $sessionId),
            $tag,
        );
    }

    /** The first-seen TLS record on the session key family. */
    public function sessionFirstTlsTag(string $sessionId, string $tag): ?string
    {
        return $this->sessionFirstTagRecord(
            KeyspaceMode::sessionTagKey($this->namespace, 'tls', $sessionId),
            $tag,
        );
    }

    /**
     * ONE atomic SET NX EX with a GET fallback on the lost first-write
     * race (the classic store's identical rule), on the given key.
     */
    private function sessionFirstTagRecord(string $key, string $tag): ?string
    {
        $replies = $this->dispatch([
            [
                'endpoint' => $this->endpointForKey($key),
                'cmd' => RawCommand::create('SET', $key, $tag, 'NX', 'EX', $this->sessionTtlSecs),
                'script' => null,
            ],
            [
                'endpoint' => $this->endpointForKey($key),
                'cmd' => RawCommand::create('GET', $key),
                'script' => null,
            ],
        ]);
        $set = $replies[0] ?? null;
        if ($set instanceof \Predis\Response\Status && $set->getPayload() === 'OK') {
            return $tag;
        }
        $stored = $replies[1] ?? null;

        return \is_string($stored) && $stored !== '' ? $stored : null;
    }

    /**
     * The full sharded assessment: one pipelined batch of per-dimension
     * scripts on their own slots, the nonce verdict and the single-slot
     * level transition, plus the consolidated single-key extras.
     *
     * @return array{vector: SignalVector, globalLevel: int, cooldownUntilMs: int, isDuplicate: bool, existingContextTag: ?string, existingTlsTag: ?string, registrationStatus: bool}
     *
     * @throws RiskStoreException when the underlying state backend fails
     */
    private function runAssessment(
        RiskObservation $observation,
        ?string $contextTag,
        ?string $tlsTag,
        ?OutcomeRegistration $registration,
    ): array {
        $ns = $this->namespace;
        $sessionHex = $observation->sessionId ?? str_repeat('0', 32);
        $principalHex = $observation->principalId ?? str_repeat('0', 32);
        $hasSession = $observation->sessionId !== null;
        $hasPrincipal = $observation->principalId !== null;

        // The merged aggregate feeds the global pressure signal; the
        // level transition runs inside the merge refresh (at most once
        // per second) and the published level/cooldown is what this
        // assessment reports.
        $snapshot = $this->mergedPerShard();
        // An empty event id (dedupe disabled) has no id bytes to spread;
        // the source pseudonym is the stable fallback so those writes do
        // not all funnel onto fnv1a32('')'s shard.
        $shard = KeyspaceMode::scopeShard($observation->eventId, $observation->sourceId);
        $sat = array_replace(self::DEFAULT_SATURATIONS, $this->saturations);

        $units = [];
        $pushIdentity = function (string $dimension, ?int $epoch, string $hexId, bool $hasWrite, int $ttl) use (&$units, $ns, $observation): void {
            $stateKey = KeyspaceMode::identityStateKey($ns, $dimension, $epoch, $hexId);
            $markerKey = KeyspaceMode::identityMarkerKey($ns, $dimension, $hexId, $observation->eventId);
            $units[] = [
                'endpoint' => $this->endpointForKey($stateKey),
                'cmd' => $this->identityEvalsha($stateKey, $markerKey, $observation, $dimension, $hasWrite, $ttl),
                'script' => self::shardedScript('sharded_identity.lua'),
            ];
        };
        $pushIdentity('src', $observation->sourceEpoch - 1, $observation->sourceIdPrev, false, $this->stateTtlSecs);
        $pushIdentity('src', $observation->sourceEpoch, $observation->sourceId, true, $this->stateTtlSecs);
        $pushIdentity('src', $observation->sourceEpoch + 1, $observation->sourceIdNext, false, $this->stateTtlSecs);
        $pushIdentity('net', $observation->subnetEpoch - 1, $observation->subnetIdPrev, false, $this->stateTtlSecs);
        $pushIdentity('net', $observation->subnetEpoch, $observation->subnetId, true, $this->stateTtlSecs);
        $pushIdentity('net', $observation->subnetEpoch + 1, $observation->subnetIdNext, false, $this->stateTtlSecs);
        if ($hasSession) {
            $pushIdentity('session', null, $sessionHex, true, $this->sessionTtlSecs);
        }
        if ($hasPrincipal) {
            $pushIdentity('principal', null, $principalHex, true, $this->principalTtlSecs);
        }

        // The event's scope shard: one of the 16 sharded counters.
        $shardKey = KeyspaceMode::scopeShardKey($ns, self::GLOBAL_AGGREGATE_ID, $shard);
        $shardMarker = KeyspaceMode::scopeMarkerKey($ns, self::GLOBAL_AGGREGATE_ID, $shard, $observation->eventId);
        $units[] = [
            'endpoint' => $this->endpointForKey($shardKey),
            'cmd' => $this->scopeEvalsha($shardKey, $shardMarker, $observation->event->value, $observation->scope, 1, $observation->eventId),
            'script' => self::shardedScript('sharded_scope.lua'),
        ];

        // The nonce-family verdict: one SET NX EX, the assessment-level
        // duplicate semantics of the legacy dedupe key.
        $hasNonce = $observation->eventId !== '';
        if ($hasNonce) {
            $nonceKey = KeyspaceMode::nonceDedupeKey($ns, $observation->eventId);
            $units[] = [
                'endpoint' => $this->endpointForKey($nonceKey),
                'cmd' => RawCommand::create('SET', $nonceKey, '1', 'NX', 'EX', $this->dedupeTtlSecs),
                'script' => null,
            ];
        }

        // The consolidated extras on the session family: the first-seen
        // tag records (SET NX + GET on the session pseudonym's own slot).
        // A tag that is not presented is not read at all (assess_v2
        // parity: the existing value is reported as absent).
        $mergedGp = array_sum($snapshot);
        foreach ([
            [KeyspaceMode::sessionTagKey($ns, 'ctx', $sessionHex), $contextTag],
            [KeyspaceMode::sessionTagKey($ns, 'tls', $sessionHex), $tlsTag],
        ] as [$recordKey, $presented]) {
            if (\is_string($presented) && $presented !== '') {
                $units[] = [
                    'endpoint' => $this->endpointForKey($recordKey),
                    'cmd' => RawCommand::create('SET', $recordKey, $presented, 'NX', 'EX', $this->sessionTtlSecs),
                    'script' => null,
                ];
                $units[] = [
                    'endpoint' => $this->endpointForKey($recordKey),
                    'cmd' => RawCommand::create('GET', $recordKey),
                    'script' => null,
                ];
            }
        }

        $replies = $this->dispatch($units);
        $it = $replies;
        $next = function () use (&$it): mixed {
            if ($it === []) {
                throw new RiskStoreException('the assessment batch returned fewer replies than commands');
            }

            return array_shift($it);
        };
        $channels = function (int $width, string $what) use ($next): array {
            $reply = $next();
            if (!\is_array($reply) || \count($reply) < $width) {
                throw new RiskStoreException(sprintf('the %s reply is not a %d-channel array', $what, $width));
            }
            $out = [];
            for ($i = 0; $i < $width; $i++) {
                $out[] = self::scriptInteger($reply[$i], $what);
            }

            return $out;
        };

        $sumChannels = static function (array $parts, int $index): int {
            $sum = 0;
            foreach ($parts as $part) {
                $sum += $part[$index];
            }

            return $sum;
        };
        $srcPrev = $channels(9, 'source boundary');
        $srcCur = $channels(9, 'source state');
        $srcNext = $channels(9, 'source boundary');
        $netPrev = $channels(9, 'subnet boundary');
        $netCur = $channels(9, 'subnet state');
        $netNext = $channels(9, 'subnet boundary');
        // Absent dimensions were never read: their channels are zero.
        $zeros = array_fill(0, 9, 0);
        $sess = $hasSession ? $channels(9, 'session state') : $zeros;
        $prin = $hasPrincipal ? $channels(9, 'principal state') : $zeros;
        $shardChannels = $channels(7, 'scope shard');
        $shardSum = array_sum($shardChannels);
        $src = [$srcPrev, $srcCur, $srcNext];
        $net = [$netPrev, $netCur, $netNext];
        $isDuplicate = false;
        if ($hasNonce) {
            $isDuplicate = $next() === null;
        }
        // The level/cooldown are the published merge-refresh values (the
        // transition is no longer run per assessment).
        $globalLevel = $this->lastGlobalLevel;
        $cooldownUntilMs = $this->lastCooldownUntilMs;

        // First-seen tag records: the SET reply (when the tag was
        // presented) wins; its null miss falls back to the GET reply. A
        // tag that was not presented was never read (assess_v2 parity).
        $readTag = function (?string $presented, string $what) use ($next): ?string {
            if (!\is_string($presented) || $presented === '') {
                return null;
            }
            $setReply = $next();
            if ($setReply instanceof \Predis\Response\Status && $setReply->getPayload() === 'OK') {
                $next();

                return $presented;
            }
            $reply = $next();
            if ($reply === null) {
                return null;
            }
            if (\is_string($reply)) {
                return $reply === '' ? null : $reply;
            }
            throw new RiskStoreException(sprintf('the %s reply is neither a string nor null', $what));
        };
        $existingContextTag = $readTag($contextTag, 'client-context tag');
        $existingTlsTag = $readTag($tlsTag, 'TLS tag');

        // The risk-v1 aggregation, client-side: rotated-epoch pseudonyms
        // of one dimension SUM (the replies carry the leaked channels),
        // identity dimensions MAX, every channel normalizes with the
        // saturation the legacy script divides by.
        $maxn = static fn (array $values): int => max($values);
        $srcRf = $sumChannels($src, 0);
        $srcRs = $sumChannels($src, 1);
        $srcIss = $sumChannels($src, 2);
        $srcBad = $sumChannels($src, 3);
        $srcMal = $sumChannels($src, 4);
        $srcRep = $sumChannels($src, 5);
        $srcAf = $sumChannels($src, 6);
        $srcSw = $sumChannels($src, 7);
        $srcTrust = $sumChannels($src, 8);
        $netRf = $sumChannels($net, 0);
        $freshGp = $mergedGp - ($snapshot[$shard] ?? 0) + $shardSum;

        $vector = new SignalVector(
            sourceFast: self::normalize($maxn([$srcRf, $sess[0], 0]), $sat['src_fast']),
            sourceSlow: self::normalize($maxn([$srcRs, $sess[1], 0]), $sat['src_slow']),
            subnetFast: self::normalize($netRf, $sat['src_fast']),
            issueDebt: self::normalize($maxn([$srcIss, $sess[2], 0]), $sat['issue']),
            badProof: self::normalize($maxn([$srcBad, $sess[3], $prin[3], 0]), $sat['bad']),
            malformed: self::normalize($maxn([$srcMal, $sess[4], $prin[4], 0]), $sat['mal']),
            replay: self::normalize($maxn([$srcRep, $sess[5], 0]), $sat['rep']),
            actionFailure: self::normalize($maxn([$srcAf, $sess[6], $prin[6], 0]), $sat['action']),
            scopeSwitch: self::normalize($maxn([$srcSw, $sess[7], 0]), $sat['switch']),
            globalPressure: self::normalize($freshGp, $sat['global']),
            networkRisk: $observation->networkRisk,
            trustCredit: self::normalize($maxn([$srcTrust, $sess[8], 0]), $sat['trust']),
            principalCredit: self::normalize($prin[8], $sat['principal']),
        );

        // The written shard's post-apply sum lands in the cache, so the
        // next merged read sees every committed increment.
        $this->mergePerShard[$shard] = $shardSum;
        $this->lastGlobalLevel = $globalLevel;
        $this->lastCooldownUntilMs = $cooldownUntilMs;
        $this->lastIsDuplicate = $isDuplicate;

        $registrationStatus = false;
        if ($registration !== null) {
            // The ledger score mirrors the assess_v2 formula exactly; the
            // canonical registration script runs as the batch's second
            // phase (SET NX on the decision id, idempotent under retry).
            $score = $this->ledgerScore(
                $observation,
                $vector,
                $existingContextTag,
                $existingTlsTag,
                $contextTag,
                $tlsTag,
                $registration,
            );
            $registrationStatus = $this->registerOutcome(
                $registration->decisionId,
                $observation->scope,
                $registration->decisionHour,
                $score,
            );
        }

        return [
            'vector' => $vector,
            'globalLevel' => $globalLevel,
            'cooldownUntilMs' => $cooldownUntilMs,
            'isDuplicate' => $isDuplicate,
            'existingContextTag' => $existingContextTag,
            'existingTlsTag' => $existingTlsTag,
            'registrationStatus' => $registrationStatus,
        ];
    }

    /**
     * The consolidated ledger score: base plus the weighted signals
     * (global pressure zeroed for the ledger when the feature flag is
     * off), clamped, then the weighted risk-v2 evidence factors added,
     * clamped again. The honeypot-derived event kinds 18..20 count as a
     * honeypot hit; a recorded first tag that differs from the presented
     * one counts as an inconsistency, an empty presented tag against a
     * recorded one included.
     */
    private function ledgerScore(
        RiskObservation $observation,
        SignalVector $vector,
        ?string $existingContextTag,
        ?string $existingTlsTag,
        ?string $presentedContextTag,
        ?string $presentedTlsTag,
        OutcomeRegistration $registration,
    ): int {
        $w = $registration->weights->toArray();
        $gp = $registration->globalPressureEnabled ? $vector->globalPressure : 0;
        $weighted = static fn (int $value, int $weight): int => intdiv($value * $weight, 1000);
        $risk = $registration->baseRisk
            + $weighted($vector->sourceFast, $w['source_fast'])
            + $weighted($vector->sourceSlow, $w['source_slow'])
            + $weighted($vector->subnetFast, $w['subnet_fast'])
            + $weighted($vector->issueDebt, $w['issue_debt'])
            + $weighted($vector->badProof, $w['bad_proof'])
            + $weighted($vector->malformed, $w['malformed'])
            + $weighted($vector->replay, $w['replay'])
            + $weighted($vector->actionFailure, $w['action_failure'])
            + $weighted($vector->scopeSwitch, $w['scope_switch'])
            + $weighted($gp, $w['global_pressure'])
            + $weighted($vector->networkRisk, $w['network_risk'])
            - $weighted($vector->trustCredit, $w['trust_credit'])
            - $weighted($vector->principalCredit, $w['principal_credit']);
        $risk = max(0, min(1000, $risk));

        $honeypot = ($registration->honeypotHit || \in_array($observation->event->value, [18, 19, 20], true)) ? 1000 : 0;
        $presentedCtx = $presentedContextTag ?? '';
        $presentedTls = $presentedTlsTag ?? '';
        $sessionInconsistency = (\is_string($existingContextTag) && $existingContextTag !== '' && $existingContextTag !== $presentedCtx) ? 1000 : 0;
        $tlsInconsistency = (\is_string($existingTlsTag) && $existingTlsTag !== '' && $existingTlsTag !== $presentedTls) ? 1000 : 0;
        $risk += $weighted($honeypot, $registration->v2Weights->honeypot);
        $risk += $weighted($sessionInconsistency, $registration->v2Weights->sessionInconsistency);
        $risk += $weighted($tlsInconsistency, $registration->v2Weights->tls);

        return max(0, min(1000, $risk));
    }

    /**
     * The merged per-shard snapshot: a merge batch of one read-only
     * scope invocation per shard, issued at most once per second, with
     * the per-shard sums the assessments write back into.
     *
     * @return list<int> 16 per-shard leaked sums
     *
     * @throws RiskStoreException when the merge batch cannot be served
     */
    private function mergedPerShard(): array
    {
        // hrtime is monotonic: a backward NTP step must never freeze
        // the refresh window the way a stepped-back wall clock would.
        $nowMs = (int) floor(hrtime(true) / 1e6);
        if (\count($this->mergePerShard) === KeyspaceMode::SCOPE_SHARDS
            && ($nowMs - $this->mergedAtMs) < KeyspaceMode::MERGE_STALENESS_MS) {
            return $this->mergePerShard;
        }
        $ns = $this->namespace;
        $units = [];
        for ($shard = 0; $shard < KeyspaceMode::SCOPE_SHARDS; $shard++) {
            $key = KeyspaceMode::scopeShardKey($ns, self::GLOBAL_AGGREGATE_ID, $shard);
            $marker = KeyspaceMode::scopeMarkerKey($ns, self::GLOBAL_AGGREGATE_ID, $shard, '');
            $units[] = [
                'endpoint' => $this->endpointForKey($key),
                'cmd' => $this->scopeEvalsha($key, $marker, 1, 0, 0, ''),
                'script' => self::shardedScript('sharded_scope.lua'),
            ];
        }
        $replies = $this->dispatch($units);
        $perShard = [];
        $mergedGp = 0;
        foreach ($replies as $reply) {
            if (!\is_array($reply) || \count($reply) < 7) {
                throw new RiskStoreException('the scope shard merge reply is not a 7-channel array');
            }
            $sum = 0;
            for ($i = 0; $i < 7; $i++) {
                $sum += self::scriptInteger($reply[$i], 'scope shard merge');
            }
            $perShard[] = $sum;
            $mergedGp += $sum;
        }
        $this->mergePerShard = $perShard;
        $this->mergedAtMs = $nowMs;

        // The level/cooldown ratchet runs here — once per staleness
        // window — not on every assessment: the hot path reuses the
        // published level/cooldown, so the hysteresis hash is no longer
        // a per-request single-slot write.
        $sat = array_replace(self::DEFAULT_SATURATIONS, $this->saturations);
        $hystKey = KeyspaceMode::hysteresisKey($this->namespace);
        $hystReplies = $this->dispatch([[
            'endpoint' => $this->endpointForKey($hystKey),
            'cmd' => $this->evalshaCmd(
                self::shardedScript('sharded_hysteresis.lua'),
                [$hystKey],
                [$mergedGp, $sat['global'], $this->hysteresisMs],
            ),
            'script' => self::shardedScript('sharded_hysteresis.lua'),
        ]]);
        $hyst = $hystReplies[0] ?? null;
        if (!\is_array($hyst) || \count($hyst) < 2) {
            throw new RiskStoreException('the hysteresis transition reply is not a 2-channel array');
        }
        $this->lastGlobalLevel = max(0, min(4, self::scriptInteger($hyst[0], 'hysteresis level')));
        $this->lastCooldownUntilMs = max(0, self::scriptInteger($hyst[1], 'hysteresis cooldown'));

        return $perShard;
    }

    /**
     * Dispatches one pipelined batch: the units are grouped by endpoint,
     * every group is written before any reply is read, and the read
     * phase drains each group in submission order. Any failure evicts
     * the failed endpoint's connection (Predis reconnects lazily); the
     * committed slot groups stay covered by their dedupe markers, so a
     * retry cannot double-count them.
     *
     * @param list<array{endpoint: int, cmd: RawCommand, script: ?string}> $units
     *
     * @return list<mixed> one reply per unit, in submission order
     *
     * @throws RiskStoreException on any backend failure
     */
    private function dispatch(array $units): array
    {
        /** @var array<int, list<int>> $groups endpoint index => unit indices */
        $groups = [];
        foreach ($units as $index => $unit) {
            $groups[$unit['endpoint']][] = $index;
        }

        $connections = [];
        try {
            // Send phase: every group fully written before any reply is
            // read (the pipelining contract).
            foreach (array_keys($groups) as $endpoint) {
                $connection = $this->clients[$endpoint]->getConnection();
                foreach ($groups[$endpoint] as $index) {
                    try {
                        $connection->writeRequest($units[$index]['cmd']);
                    } catch (\Predis\PredisException $e) {
                        throw new RiskStoreException('Risk store connection failed: ' . $e->getMessage(), 0, $e);
                    }
                }
                $connections[$endpoint] = $connection;
            }

            // Read phase: drain each group's replies in submission order.
            // A NOSCRIPT miss is retried only after the batch has been
            // fully drained (the reload's replies would otherwise read
            // the still-queued replies of the commands before it).
            $replies = [];
            $scriptRetries = [];
            foreach (array_keys($groups) as $endpoint) {
                $connection = $connections[$endpoint];
                foreach ($groups[$endpoint] as $index) {
                    $unit = $units[$index];
                    try {
                        $reply = $connection->readResponse($unit['cmd']);
                    } catch (ServerException $e) {
                        if (str_contains($e->getMessage(), 'NOSCRIPT') && $unit['script'] !== null) {
                            $scriptRetries[] = $index;
                            continue;
                        }
                        throw new RiskStoreException('Risk script execution failed: ' . $e->getMessage(), 0, $e);
                    } catch (\Predis\PredisException $e) {
                        throw new RiskStoreException('Risk store connection failed: ' . $e->getMessage(), 0, $e);
                    }
                    if ($reply instanceof \Predis\Response\Error) {
                        // The raw read path hands back error reply
                        // objects (executeCommand is what turns them
                        // into exceptions); a NOSCRIPT miss is retried
                        // after the batch drains, everything else fails
                        // the batch.
                        $message = $reply->getMessage();
                        if (str_contains($message, 'NOSCRIPT') && $unit['script'] !== null) {
                            $scriptRetries[] = $index;
                            continue;
                        }
                        throw new RiskStoreException("Risk script execution failed: {$message}");
                    }
                    $replies[$index] = $reply;
                }
            }
            foreach ($scriptRetries as $index) {
                $unit = $units[$index];
                $replies[$index] = $this->loadAndRetry($this->clients[$unit['endpoint']], $unit['script'], $unit['cmd']);
            }

            // The read loop fills by unit index in endpoint-group order;
            // the decoder drains in submission order, so re-sort.
            ksort($replies);

            return array_values($replies);
        } catch (RiskStoreException $e) {
            // A batch interrupted mid-drain leaves unread replies on
            // every connection that took part; disconnect all of them
            // (Predis reconnects lazily), the same poison rule the Rust
            // dispatch applies. The committed slot groups stay covered
            // by their dedupe markers, so a retry cannot double-count.
            foreach ($connections as $connection) {
                try {
                    $connection->disconnect();
                } catch (\Throwable) {
                    // The poison rule is best-effort: never mask the
                    // original failure.
                }
            }

            throw $e;
        }
    }

    /** The identity dimension EVALSHA (the sharded_identity.lua argv contract). */
    private function identityEvalsha(
        string $stateKey,
        string $markerKey,
        RiskObservation $observation,
        string $dimension,
        bool $hasWrite,
        int $stateTtlSecs,
    ): RawCommand {
        return $this->evalshaCmd(
            self::shardedScript('sharded_identity.lua'),
            [$stateKey, $markerKey],
            [
                $observation->event->value,
                $observation->scope,
                KeyspaceMode::DIMENSION_LUA_IDS[$dimension],
                $hasWrite ? 1 : 0,
                $this->dedupeTtlSecs,
                $observation->eventId,
                $stateTtlSecs,
            ],
        );
    }

    /** The scope shard EVALSHA (the sharded_scope.lua argv contract). */
    private function scopeEvalsha(
        string $shardKey,
        string $markerKey,
        int $event,
        int $scope,
        int $hasWrite,
        string $eventId,
    ): RawCommand {
        return $this->evalshaCmd(
            self::shardedScript('sharded_scope.lua'),
            [$shardKey, $markerKey],
            [$event, $scope, $hasWrite, $this->dedupeTtlSecs, $eventId],
        );
    }

    /** An EVALSHA raw command for a cached script hash. */
    private function evalshaCmd(string $script, array $keys, array $args): RawCommand
    {
        return RawCommand::create('EVALSHA', $this->shaOf($script), \count($keys), ...$keys, ...$args);
    }

    /** evalsha with noscript fallback on one client (script load once per process). */
    private function loadAndRetry(Client $client, string $script, RawCommand $failed): mixed
    {
        try {
            $sha = $this->loadScript($client, $script);
            $retry = RawCommand::create('EVALSHA', $sha, ...array_slice($failed->getArguments(), 1));

            return $client->executeCommand($retry);
        } catch (\Predis\PredisException $e) {
            throw new RiskStoreException('Risk script execution failed: ' . $e->getMessage(), 0, $e);
        }
    }

    /** Cached sha1 of every static script (script load once per script per client). */
    private function shaOf(string $script): string
    {
        if (!isset($this->scriptShas[$script])) {
            $this->scriptShas[$script] = $this->loadScript($this->clients[0], $script);
        }

        return $this->scriptShas[$script];
    }

    /** SCRIPT LOAD on one client (a sha is valid on every node of the same scripts set). */
    private function loadScript(Client $client, string $script): string
    {
        try {
            $sha = $client->executeCommand(RawCommand::create('SCRIPT', 'LOAD', $script));
        } catch (\Predis\PredisException $e) {
            throw new RiskStoreException('Risk script load failed: ' . $e->getMessage(), 0, $e);
        }
        if (!\is_string($sha) || $sha === '') {
            throw new RiskStoreException('SCRIPT LOAD returned no sha');
        }

        return $sha;
    }

    /** The bundled sharded script source (one of the three canonical copies). */
    private static function shardedScript(string $file): string
    {
        static $cache = [];
        if (isset($cache[$file])) {
            return $cache[$file];
        }
        $path = dirname(__DIR__, 2) . '/resources/' . $file;
        if (!is_file($path)) {
            throw new \RuntimeException(sprintf('Cannot locate the bundled script at resources/%s', $file));
        }
        $source = @file_get_contents($path);
        if ($source === false) {
            throw new \RuntimeException(sprintf('Cannot read the bundled script at %s', $path));
        }

        return $cache[$file] = $source;
    }

    /**
     * The client that owns a key's slot: the real topology range when
     * the store routes by the topology reply, slot modulo the endpoint
     * list otherwise (the stand-in rule).
     */
    private function clientForSlot(int $slot): Client
    {
        return $this->clients[$this->endpointForSlot($slot)];
    }

    private function endpointForSlot(int $slot): int
    {
        if ($this->slotRanges === []) {
            return $slot % \count($this->clients);
        }
        foreach ($this->slotRanges as [$start, $end, $endpoint]) {
            if ($slot >= $start && $slot <= $end) {
                return $endpoint;
            }
        }

        return 0;
    }

    /** CRC-16/xmodem (poly 0x1021, init 0) of the hash tag, masked to 14 bits, via the shared implementation. */
    private function slotOf(string $key): int
    {
        $open = strpos($key, '{');
        if ($open === false) {
            throw new \LogicException(sprintf('Key %s has no hash tag', $key));
        }
        $close = strpos($key, '}', $open);
        if ($close === false) {
            throw new \LogicException(sprintf('Key %s has no closing hash tag', $key));
        }
        $tag = substr($key, $open + 1, $close - $open - 1);

        return RedisRiskStateStore::crc16($tag) & 0x3FFF;
    }

    /**
     * Resolves the real cluster topology from one seed node: the primary
     * endpoints of every slot range plus the sorted range table, read
     * from the seed's topology reply. Replica rows are ignored
     * (assessments write; routing follows primaries).
     *
     * @return array{0: list<Client>, 1: list<array{0: int, 1: int, 2: int}>}
     *
     * @throws RiskStoreException when the topology cannot be resolved
     */
    private function fetchClusterTopology(Client $seed): array
    {
        try {
            $reply = $seed->executeCommand(RawCommand::create('CLUSTER', 'SLOTS'));
        } catch (\Predis\PredisException $e) {
            throw new RiskStoreException('CLUSTER SLOTS failed: ' . $e->getMessage(), 0, $e);
        }
        if (!\is_array($reply)) {
            throw new RiskStoreException('CLUSTER SLOTS did not return a topology array');
        }
        $urls = [];
        $ranges = [];
        foreach ($reply as $row) {
            if (!\is_array($row) || \count($row) < 3) {
                continue;
            }
            $start = $row[0];
            $end = $row[1];
            $node = $row[2];
            if (!\is_int($start) || !\is_int($end) || $start < 0 || $end > 16383 || !\is_array($node) || \count($node) < 2) {
                continue;
            }
            $host = $node[0];
            $port = $node[1];
            if (!\is_string($host) || !\is_int($port) || $port <= 0) {
                continue;
            }
            $url = sprintf('redis://%s:%d', $host, $port);
            $index = array_search($url, $urls, true);
            if ($index === false) {
                $urls[] = $url;
                $index = \count($urls) - 1;
            }
            $ranges[] = [$start, $end, $index];
        }
        if ($ranges === []) {
            throw new RiskStoreException('CLUSTER SLOTS returned no usable slot ranges');
        }
        usort($ranges, static fn (array $a, array $b): int => $a[0] <=> $b[0]);

        return [
            array_map(
                fn (string $url): Client => $this->clientForUrl($url),
                $urls,
            ),
            $ranges,
        ];
    }

    /** The client-side normalize: floor(v * 1000 / sat) capped at 1000, zero for a non-positive saturation. */
    private static function normalize(int $value, int $saturation): int
    {
        if ($saturation <= 0) {
            return 0;
        }

        return max(0, min(1000, intdiv($value * 1000, $saturation)));
    }

    /**
     * Decodes one integer slot of a script reply with the same
     * fail-closed contract as the classic store's scriptInteger.
     *
     * @throws RiskStoreException
     */
    private static function scriptInteger(mixed $value, string $slot): int
    {
        if (\is_int($value)) {
            return $value;
        }
        if (\is_string($value) && preg_match('/^[+-]?[0-9]+$/', $value) === 1) {
            $parsed = filter_var($value, FILTER_VALIDATE_INT);
            if ($parsed !== false) {
                return $parsed;
            }
        }

        throw new RiskStoreException(sprintf('Risk script returned a non-integer value for %s', $slot));
    }
}
