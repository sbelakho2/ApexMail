<?php

declare(strict_types=1);

namespace KiwiCaptcha\Risk\Asn;

use KiwiCaptcha\Issuer;

/**
 * ASN resolution from a free, redistributable dataset: the IPtoASN tsv
 * shapes, read once from local disk into sorted interval tables,
 * binary-searched per lookup, with digest-verified atomic hot reload.
 *
 * No network call ever happens: the dataset is a versioned file the
 * deployment ships (a public routing-table export or the free IPtoASN
 * dataset), never a paid feed or a runtime fetch. Addresses follow the
 * repo's canonical IP rules (Issuer::canonicalIpFamily, the identical
 * normalizer the risk identity factory uses), so a v4-mapped or
 * v4-compatible IPv6 resolves as its IPv4 address.
 *
 * Hot reload parses the new file fully off to the side and swaps the
 * snapshot with one property assignment, so a torn or half-parsed table
 * is never visible to a lookup. A rejected reload (unreadable file,
 * digest mismatch, zero valid rows) leaves the serving table untouched.
 */
final class AsnDataset
{
    public const FORMAT_VERSION = 1;

    public const BUCKET_ID_VERSION = 1;

    public const MAX_ASN = AsnBucket::MAX_ASN;

    private readonly string $path;

    /** The immutable serving snapshot; reload() replaces it in one assignment. */
    private AsnTable $table;

    private function __construct(string $path, AsnTable $table)
    {
        $this->path = $path;
        $this->table = $table;
    }

    /**
     * Opens and parses the dataset at the path.
     *
     * @throws AsnDatasetException when the file cannot be read or
     *                             carries no valid row (fail closed: an
     *                             empty table would silently resolve
     *                             every address to the unlisted
     *                             namespace)
     */
    public static function open(string $path): self
    {
        [$bytes, $mtime] = self::readDataset($path);
        $table = AsnTable::parse($bytes, hash('sha256', $bytes), $mtime);
        if ($table->validRows === 0) {
            throw new AsnDatasetException(
                sprintf('asn dataset %s carries no valid row (refusing to serve an empty table)', $path),
                AsnDatasetException::EMPTY,
            );
        }

        return new self($path, $table);
    }

    /**
     * Resolves one IP to its listed ASN and bucket id.
     *
     * @throws \InvalidArgumentException when the IP is not a valid IPv4
     *                                   or IPv6 address
     */
    public function lookup(string $ip): AsnLookup
    {
        $canonical = Issuer::canonicalIpFamily($ip);
        $family = $canonical[0];
        $bytes = substr($canonical, 1);
        $table = $family === "\x04" ? $this->table->v4 : $this->table->v6;
        $asn = self::resolveFamily($table, $bytes);
        if ($asn !== null) {
            return new AsnLookup($asn, AsnBucket::forKnownAsn($asn));
        }
        $bucket = $family === "\x04"
            ? AsnBucket::forUnlistedV4(substr($bytes, 0, 2))
            : AsnBucket::forUnlistedV6(substr($bytes, 0, 4));

        return new AsnLookup(null, $bucket);
    }

    /** The bucket id of one IP (the lookup's bucket alone). */
    public function bucketId(string $ip): string
    {
        return $this->lookup($ip)->bucket;
    }

    /** The serving snapshot's identity (the public info surface). */
    public function datasetInfo(): AsnDatasetInfo
    {
        return new AsnDatasetInfo(
            path: $this->path,
            formatVersion: self::FORMAT_VERSION,
            sha256: $this->table->digestHex,
            mtimeUnixSecs: $this->table->mtimeUnixSecs,
            validRows: $this->table->validRows,
            malformedRows: $this->table->malformedRows,
            byteLen: $this->table->byteLen,
        );
    }

    /**
     * Hot reload: reads the file again, verifies the digest when one is
     * supplied, parses the new table fully off to the side and swaps it
     * in with one property assignment. A rejected reload leaves the
     * serving table untouched, and no lookup can ever observe a
     * half-parsed table. No network call happens: the file is local
     * disk only.
     *
     * @throws AsnDatasetException on an unreadable file, a digest
     *                             mismatch or zero valid rows; the
     *                             serving table survives each
     */
    public function reload(?string $expectedSha256 = null): AsnDatasetInfo
    {
        [$bytes, $mtime] = self::readDataset($this->path);
        $digest = hash('sha256', $bytes);
        if ($expectedSha256 !== null && strcasecmp($expectedSha256, $digest) !== 0) {
            throw new AsnDatasetException(sprintf(
                'asn dataset %s digest mismatch: expected %s, computed %s',
                $this->path,
                $expectedSha256,
                $digest,
            ), AsnDatasetException::DIGEST_MISMATCH);
        }
        $table = AsnTable::parse($bytes, $digest, $mtime);
        if ($table->validRows === 0) {
            throw new AsnDatasetException(
                sprintf('asn dataset %s carries no valid row (refusing to serve an empty table)', $this->path),
                AsnDatasetException::EMPTY,
            );
        }
        $this->table = $table;

        return $this->datasetInfo();
    }

    /**
     * Reads the dataset bytes and modification time.
     *
     * @return array{0: string, 1: int}
     */
    private static function readDataset(string $path): array
    {
        $bytes = @file_get_contents($path);
        if ($bytes === false) {
            throw new AsnDatasetException(
                sprintf('asn dataset %s cannot be read: unreadable path', $path),
                AsnDatasetException::UNREADABLE,
            );
        }
        $mtime = @filemtime($path);

        return [$bytes, $mtime === false ? 0 : $mtime];
    }

    /**
     * Binary-searches one family table: the last interval whose first
     * endpoint is at or below the query, accepted when its last
     * endpoint covers it. Exact for disjoint intervals (the dataset's
     * guarantee) and deterministic for any input.
     *
     * @param list<array{first: string, last: string, asn: int}> $table
     */
    private static function resolveFamily(array $table, string $bytes): ?int
    {
        $lo = 0;
        $hi = \count($table);
        while ($lo < $hi) {
            $mid = ($lo + $hi) >> 1;
            if (strcmp($table[$mid]['first'], $bytes) <= 0) {
                $lo = $mid + 1;
            } else {
                $hi = $mid;
            }
        }
        if ($lo === 0) {
            return null;
        }
        $interval = $table[$lo - 1];

        return strcmp($interval['last'], $bytes) >= 0 ? $interval['asn'] : null;
    }
}
