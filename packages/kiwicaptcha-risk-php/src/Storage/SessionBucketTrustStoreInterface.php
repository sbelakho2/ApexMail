<?php

declare(strict_types=1);

namespace KiwiCaptcha\Risk\Storage;

/**
 * The additive context-bound trust store surface, mirror of the Rust
 * `SessionBucketTrustStore` trait. The Redis store implements it with
 * the canonical trust.lua script; the interface keeps the facade
 * testable against any trust-capable store.
 */
interface SessionBucketTrustStoreInterface
{
    /**
     * The exact record key of one session and bucket
     * (trust:{kiwi:<ns>}:<session>:<bucket>).
     *
     * @throws \InvalidArgumentException when the session id is not a
     *                                   32-char lowercase hex pseudonym
     *                                   or the bucket id is not
     *                                   canonical
     */
    public function bucketTrustKey(string $sessionId, string $bucket): string;

    /**
     * The decayed bucket-local trust of the session (0 when no record):
     * a pure read that never mutates the record.
     *
     * @throws \InvalidArgumentException on an invalid session or bucket
     * @throws RiskStoreException when the state backend fails
     */
    public function readBucketTrust(string $sessionId, string $bucket): int;

    /**
     * Credits the bucket the request presents from (clamped at the
     * fixed-point ceiling, whole-key TTL refreshed) and returns the
     * record's new raw trust.
     *
     * @throws \InvalidArgumentException on an invalid session, bucket
     *                                   or delta
     * @throws RiskStoreException when the state backend fails
     */
    public function creditBucketTrust(string $sessionId, string $bucket, int $delta): int;

    /**
     * Decays the bucket record and returns its new raw trust.
     *
     * @throws \InvalidArgumentException on an invalid session, bucket
     *                                   or delta
     * @throws RiskStoreException when the state backend fails
     */
    public function decayBucketTrust(string $sessionId, string $bucket, int $delta): int;
}
