<?php

declare(strict_types=1);

namespace KiwiCaptcha\Risk\Trust;

/**
 * The applied trust credit of one request: the bucket-local record
 * only. An absent record (the session never earned in that bucket)
 * reads as raw 0 and yields zero credit; a record with residue yields
 * exactly that residue's credit. Cross-bucket earns nothing, and a
 * foreign bucket never consults the home record.
 */
final class BucketTrustCredit
{
    public function __construct(
        /** The request's ASN bucket id. */
        public readonly string $bucket,
        /** True when the session carries earned trust in this bucket. */
        public readonly bool $isHome,
        /** The bucket record's decayed raw trust (0 when absent). */
        public readonly int $rawTrust,
        /** The applied credit, 0..1000. */
        public readonly int $credit,
    ) {
    }
}
