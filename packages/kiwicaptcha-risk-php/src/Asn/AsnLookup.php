<?php

declare(strict_types=1);

namespace KiwiCaptcha\Risk\Asn;

/** The resolved bucket of one lookup. */
final class AsnLookup
{
    public function __construct(
        /** The listed ASN, or null for the reserved unlisted namespace. */
        public readonly ?int $asn,
        /** The bucket id (a..., u4/... or u6/...). */
        public readonly string $bucket,
    ) {
    }
}
