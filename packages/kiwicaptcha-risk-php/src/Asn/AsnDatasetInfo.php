<?php

declare(strict_types=1);

namespace KiwiCaptcha\Risk\Asn;

/**
 * The serving dataset snapshot's identity: the doctor surface. Exposes
 * the digest, the modification time and the row counts of the table
 * that is actually serving. No doctor lives inside the risk core, so
 * this is the public info() surface; the bundle-side doctor wiring
 * (printing digest and age) belongs to the bundle plane.
 */
final class AsnDatasetInfo
{
    public function __construct(
        /** The dataset path this table was loaded from. */
        public readonly string $path,
        /** The format version of the loader contract. */
        public readonly int $formatVersion,
        /** The sha256 of the loaded file bytes (hex). */
        public readonly string $sha256,
        /** The file's modification time (unix seconds, 0 when unavailable). */
        public readonly int $mtimeUnixSecs,
        /** The number of valid interval rows loaded. */
        public readonly int $validRows,
        /** The number of malformed rows skipped (counted, never fatal per row). */
        public readonly int $malformedRows,
        /** The size of the loaded file in bytes. */
        public readonly int $byteLen,
    ) {
    }

    /** The dataset's age in seconds at the given unix time (saturating). */
    public function ageSecs(int $nowUnixSecs): int
    {
        return max(0, $nowUnixSecs - $this->mtimeUnixSecs);
    }
}
