<?php

declare(strict_types=1);

namespace KiwiCaptcha\Risk\Storage;

use Predis\Client;

/**
 * The sharded keyspace contract (Plane 7): the per-namespace keyspace
 * mode, its marker key, and the shared key derivation for the sharded
 * families. Byte-identical with the Rust mirror
 * `kiwicaptcha_risk::keyspace`, so both cores address the same keys for
 * the same inputs.
 *
 * Families: the hash tag is the family tag, and every script touches
 * exactly one family slot. The identity state lives at
 * `{kiwi:<ns>:<dim>:<hex2>}:risk:<dim>[:<epoch>]:<id>`. Its
 * per-dimension dedupe marker lives at
 * `{kiwi:<ns>:<dim>:<hex2>}:risk:dd:<event_id>`. The session tag
 * records live at `{kiwi:<ns>:session:<hex2>}:risk:ctx|tls:<session>`.
 * The nonce dedupe key lives at
 * `{kiwi:<ns>:n:<hex2>}:risk:dedupe:<event_id>`. The scope aggregate
 * shard lives at `{kiwi:<ns>:s:<id>:<shard>}:scope:<id>:<shard>`, with
 * its marker at `{kiwi:<ns>:s:<id>:<shard>}:dd:<event_id>`. The outcome
 * ledger lives at `{kiwi:<ns>:o:<hex2>}:outcome:<decision_id>`. The
 * hysteresis state is `{kiwi:<ns>}:risk:hyst` and the mode marker is
 * `{kiwi:<ns>}:mode`.
 *
 * <dim> names a source, net, session, principal, asn, target or agent
 * family. <hex2> is the two hex characters of the family identifier's
 * first byte. <shard> is fnv1a32(event_id) mod 16 (or the caller's
 * stable fallback hash for an empty event id). The aggregate is merged
 * on read with a staleness contract of at most one second: the stores
 * refresh their merge at most once per second.
 */
enum KeyspaceMode: string
{
    /** The historical single-tag layout: the mode of the classic store. */
    case Legacy = 'legacy';

    /** The horizontally scalable per-family layout; the recommended mode for new namespaces. */
    case Sharded = 'sharded';

    /**
     * The marker key that records a namespace's keyspace mode:
     * {kiwi:<ns>}:mode. The key persists (no expiry): it is
     * configuration metadata, and an expiring claim would let a second
     * store re-claim the namespace in the other layout.
     */
    public static function modeMarkerKey(string $encodedNamespace): string
    {
        return "{kiwi:{$encodedNamespace}}:mode";
    }

    /**
     * The hysteresis state key (single slot by design): the level and
     * cooldown machine is a chained transition over one hash, so it
     * stays atomic even though the pressure it summarizes lives in
     * sharded counters.
     */
    public static function hysteresisKey(string $encodedNamespace): string
    {
        return "{kiwi:{$encodedNamespace}}:risk:hyst";
    }

    /**
     * Reads and claims a namespace's keyspace mode marker through the
     * given client (the client must be aimed at the node that owns the
     * marker slot). A missing marker is claimed (SET NX, persistent)
     * with this mode; an existing marker of any other mode is a refusal
     * (no silent fallback). Returns the marker mode that now governs the
     * namespace.
     *
     * @throws RiskStoreException when the namespace is marked for the
     *                            other mode, or when the backend cannot
     *                            serve the check
     */
    public static function claim(Client $client, string $encodedNamespace, self $mode): self
    {
        $key = self::modeMarkerKey($encodedNamespace);
        try {
            $stored = $client->get($key);
            if (is_string($stored) && $stored !== '') {
                $existing = self::fromMarker($stored);
                if ($existing === null) {
                    throw new RiskStoreException(sprintf(
                        'the keyspace mode marker of %s carries an unknown value',
                        $encodedNamespace,
                    ));
                }
                if ($existing !== $mode) {
                    throw new RiskStoreException(sprintf(
                        'keyspace mode mismatch for namespace %s: the marker says %s but this store is built for %s',
                        $encodedNamespace,
                        $existing->value,
                        $mode->value,
                    ));
                }

                return $existing;
            }
            // The claim only lands when the marker is still absent (SET
            // NX), so two stores racing the first claim settle on
            // exactly one winner.
            $claimed = $client->set($key, $mode->value, 'NX');
            if ($claimed !== null) {
                return $mode;
            }
            $stored = $client->get($key);
        } catch (\Predis\PredisException $e) {
            throw new RiskStoreException('keyspace mode check failed: ' . $e->getMessage(), 0, $e);
        }
        if (is_string($stored) && $stored !== '') {
            $existing = self::fromMarker($stored);
            if ($existing === $mode) {
                return $existing;
            }
        }

        throw new RiskStoreException(sprintf(
            'the keyspace mode marker of %s vanished mid-claim',
            $encodedNamespace,
        ));
    }

    /** The mode of a canonical marker value, or null for an unknown value (never silently defaulted). */
    public static function fromMarker(string $value): ?self
    {
        return self::tryFrom($value);
    }

    /** The number of scope aggregate shards (0..15). */
    public const SCOPE_SHARDS = 16;

    /** The staleness window of the merged aggregate read, in milliseconds. */
    public const MERGE_STALENESS_MS = 1000;

    /**
     * The two hex characters of the identifier's first byte: the family
     * prefix that disperses one dimension over 256 slots. Identifiers
     * are lowercase hex pseudonyms per the store's validation contract.
     */
    public static function idPrefix(string $hexId): string
    {
        return substr($hexId, 0, 2);
    }

    /**
     * FNV-1a 32-bit over the event id bytes: hash = (hash ^ byte) *
     * prime with offset 0x811c9dc5 and prime 0x01000193. Pinned by the
     * reference vectors the Rust mirror carries.
     */
    public static function fnv1a32(string $bytes): int
    {
        $hash = 0x811c9dc5;
        for ($i = 0, $len = \strlen($bytes); $i < $len; $i++) {
            $hash ^= \ord($bytes[$i]);
            $hash = ($hash * 0x01000193) & 0xFFFFFFFF;
        }

        return $hash;
    }

    /**
     * The scope shard an event id increments: fnv1a32(event_id) mod 16,
     * 0..15. The empty event id (dedupe disabled) has no id bytes to
     * hash. The caller's stable fallback (the assessment's source
     * pseudonym) is hashed instead. Routing every dedupe-less write to
     * the single fnv1a32('') shard would put all of that traffic on one
     * slot.
     */
    public static function scopeShard(string $eventId, string $fallback = ''): int
    {
        return self::fnv1a32($eventId === '' ? $fallback : $eventId) % self::SCOPE_SHARDS;
    }

    /** The Lua dimension argument of each identity family name. */
    public const DIMENSION_LUA_IDS = [
        'src' => 1,
        'net' => 2,
        'session' => 3,
        'principal' => 4,
        'asn' => 5,
        'target' => 6,
        'agent' => 7,
    ];

    /**
     * The identity state key of one pseudonym. Source and subnet keys
     * carry the epoch segment; session and principal keys do not.
     */
    public static function identityStateKey(
        string $encodedNamespace,
        string $dimension,
        ?int $epoch,
        string $hexId,
    ): string {
        $tag = sprintf('{kiwi:%s:%s:%s}', $encodedNamespace, $dimension, self::idPrefix($hexId));
        if ($epoch === null) {
            return "{$tag}:risk:{$dimension}:{$hexId}";
        }

        return "{$tag}:risk:{$dimension}:{$epoch}:{$hexId}";
    }

    /**
     * The per-dimension dedupe marker of one event id, on the same slot
     * as the state hash that increments behind it.
     */
    public static function identityMarkerKey(
        string $encodedNamespace,
        string $dimension,
        string $hexId,
        string $eventId,
    ): string {
        $tag = sprintf('{kiwi:%s:%s:%s}', $encodedNamespace, $dimension, self::idPrefix($hexId));

        return "{$tag}:risk:dd:{$eventId}";
    }

    /** The nonce-family dedupe key of one event id: a single SET NX EX gives the assessment-level duplicate verdict. */
    public static function nonceDedupeKey(string $encodedNamespace, string $eventId): string
    {
        return sprintf(
            '{kiwi:%s:n:%s}:risk:dedupe:%s',
            $encodedNamespace,
            self::idPrefix($eventId),
            $eventId,
        );
    }

    /**
     * The scope aggregate shard hash of one aggregate id and shard. The
     * assessment path uses the aggregate id 'global'; per-scope ids may
     * be decimal strings addressed through the same builder.
     */
    public static function scopeShardKey(string $encodedNamespace, string $aggregateId, int $shard): string
    {
        return sprintf(
            '{kiwi:%s:s:%s:%d}:scope:%s:%d',
            $encodedNamespace,
            $aggregateId,
            $shard,
            $aggregateId,
            $shard,
        );
    }

    /** The per-shard dedupe marker of one event id, on the same slot as the shard hash it guards. */
    public static function scopeMarkerKey(
        string $encodedNamespace,
        string $aggregateId,
        int $shard,
        string $eventId,
    ): string {
        return sprintf(
            '{kiwi:%s:s:%s:%d}:dd:%s',
            $encodedNamespace,
            $aggregateId,
            $shard,
            $eventId,
        );
    }

    /**
     * The session-family first-seen tag record ('ctx' or 'tls'). The
     * record lives on the session pseudonym's own family slot instead of
     * the shared namespace tag, so first-seen writes disperse with the
     * session dimension.
     */
    public static function sessionTagKey(string $encodedNamespace, string $kind, string $sessionHex): string
    {
        return sprintf(
            '{kiwi:%s:session:%s}:risk:%s:%s',
            $encodedNamespace,
            self::idPrefix($sessionHex),
            $kind,
            $sessionHex,
        );
    }

    /**
     * The decision-id-family outcome ledger key. The ledger of one
     * decision lives on the decision id's own family slot instead of the
     * shared namespace tag, so registration writes disperse instead of
     * funneling through one slot.
     */
    public static function outcomeLedgerKey(string $encodedNamespace, string $decisionId): string
    {
        return sprintf(
            '{kiwi:%s:o:%s}:outcome:%s',
            $encodedNamespace,
            self::idPrefix($decisionId),
            $decisionId,
        );
    }

    /** The event-id dedupe marker of one long-memory mark write, on the same slot as the mark hash. */
    public static function markDedupeKey(string $encodedNamespace, string $eventId): string
    {
        return "mark:{kiwi:{$encodedNamespace}}:dd:{$eventId}";
    }
}
