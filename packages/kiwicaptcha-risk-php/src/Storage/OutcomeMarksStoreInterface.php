<?php

declare(strict_types=1);

namespace KiwiCaptcha\Risk\Storage;

/**
 * The long-memory mark surface of the outcomes plane: the five mark
 * dimensions, one mark key per dimension and identifier, and the three
 * operations on it (write, read, forget). The Redis store implements
 * it with the canonical marks.lua script; the interface keeps the typed
 * outcomes facade testable against any marks-capable store.
 */
interface OutcomeMarksStoreInterface
{
    /**
     * The exact mark key of one dimension and identifier. The key
     * embeds the deployment hash tag, so every mark shares the risk
     * keyspace's cluster slot.
     */
    public function markKey(string $dimension, string $id): string;

    /**
     * Writes one mark atomically (max-severity kind, latest kind, count
     * increment, first/last timestamps, refreshed whole-key TTL) and
     * returns the mark's new total count. \$eventId dedupes the write
     * ('' disables dedupe): a retried report with the same id returns
     * the count unchanged. The clock is the server's TIME.
     *
     * @throws RiskStoreException when the underlying state backend fails
     */
    public function writeMark(string $dimension, string $id, string $kind, int $nowMs, string $eventId = ''): int;

    /**
     * The current mark of one dimension and identifier, or null when
     * no mark exists (never written, expired or forgotten).
     *
     * @return null|array{kind: string, last_kind: string, count: int, first_ms: int, last_ms: int}
     * @throws RiskStoreException when the underlying state backend fails
     */
    public function readMark(string $dimension, string $id): ?array;

    /**
     * Removes the mark of one dimension and identifier and returns the
     * number of keys removed (0 or 1): the erasure path of the outcomes
     * plane, constructed from the exact key without any scan.
     *
     * @throws RiskStoreException when the underlying state backend fails
     */
    public function forgetMarks(string $dimension, string $id): int;
}
