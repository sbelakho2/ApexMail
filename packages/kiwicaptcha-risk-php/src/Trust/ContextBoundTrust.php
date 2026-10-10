<?php

declare(strict_types=1);

namespace KiwiCaptcha\Risk\Trust;

use KiwiCaptcha\Risk\Asn\AsnDataset;
use KiwiCaptcha\Risk\Storage\SessionBucketTrustStoreInterface;

/**
 * Context-bound session trust: trust earned by a session is stored per
 * ASN bucket, trust[session][asn_bucket].
 *
 * A session presenting from a bucket where it earned nothing gets zero
 * credit there, full credit in its home bucket(s). This defeats
 * shared-cookie botnets without reducing a real user's cross-network
 * experience: a stolen cookie replayed from a thousand foreign networks
 * earns nothing, while a genuine home to mobile commute keeps every
 * unit of home credit. A foreign presentation is a read of the foreign
 * record only and never reduces the home entry.
 *
 * Storage rides the additive trust.lua record surface beside the
 * frozen risk-v1 observation wire (like the marks surface): the
 * canonical risk-v1 state script keeps owning the aggregate session
 * trust channel. The engine-side wiring belongs to the next plane:
 * when an assessment request context carries the session pseudonym
 * plus the request's ASN bucket, the policy replaces the aggregate
 * trust credit with the bucket-local decision this facade computes.
 * Until that plane lands, creditFor() is the read the policy will
 * perform and earn() the write the trust events will perform, in the
 * request's own bucket.
 */
final class ContextBoundTrust
{
    public function __construct(
        private readonly AsnDataset $dataset,
        private readonly SessionBucketTrustStoreInterface $store,
    ) {
    }

    /**
     * The applied trust credit of one request: the bucket resolved from
     * the source IP and the session's record in that bucket only.
     *
     * @throws \InvalidArgumentException on an invalid IP, session id or
     *                                   bucket id (fail closed before
     *                                   any backend call)
     * @throws \KiwiCaptcha\Risk\Storage\RiskStoreException when the
     *                                   record read fails
     */
    public function creditFor(string $sessionId, string $sourceIp): BucketTrustCredit
    {
        $bucket = $this->dataset->bucketId($sourceIp);

        return self::decision($bucket, $this->store->readBucketTrust($sessionId, $bucket));
    }

    /**
     * Credits the bucket the request presents from (trust is earned in
     * the bucket it is earned from) and returns the resulting credit.
     *
     * @throws \InvalidArgumentException on an invalid IP, session id,
     *                                   bucket id or delta
     * @throws \KiwiCaptcha\Risk\Storage\RiskStoreException when the
     *                                   record write fails
     */
    public function earn(string $sessionId, string $sourceIp, int $delta): BucketTrustCredit
    {
        $bucket = $this->dataset->bucketId($sourceIp);

        return self::decision($bucket, $this->store->creditBucketTrust($sessionId, $bucket, $delta));
    }

    /** The policy computation over one bucket-local record. */
    public static function decision(string $bucket, int $rawTrust): BucketTrustCredit
    {
        return new BucketTrustCredit(
            bucket: $bucket,
            isHome: $rawTrust > 0,
            rawTrust: $rawTrust,
            credit: self::normalize($rawTrust),
        );
    }

    /**
     * Normalizes a raw bucket trust value to the 0..1000 signal band,
     * the identical floor(value * 1000 / saturation) rule the risk-v1
     * state script applies to its trust channel.
     */
    public static function normalize(int $rawTrust): int
    {
        return intdiv(min($rawTrust, self::SATURATION), 10);
    }

    /** The raw fixed-point saturation of one bucket record. */
    public const SATURATION = 10_000;
}
