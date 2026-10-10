<?php

declare(strict_types=1);

namespace KiwiCaptcha\Risk\Asn;

use KiwiCaptcha\Issuer;

/**
 * The immutable parsed dataset snapshot. Interval endpoints are the raw
 * canonical address bytes (4 or 16), so an unsigned numeric comparison
 * is the byte-wise strcmp and no big-number extension is needed.
 *
 * @internal
 */
final class AsnTable
{
    /** @var list<array{first: string, last: string, asn: int}> */
    public array $v4 = [];

    /** @var list<array{first: string, last: string, asn: int}> */
    public array $v6 = [];

    public int $validRows = 0;

    public int $malformedRows = 0;

    public function __construct(
        public readonly string $digestHex,
        public readonly int $mtimeUnixSecs,
        public readonly int $byteLen,
    ) {
    }

    /**
     * Parses the dataset bytes. Malformed rows are skipped and counted
     * (fail open per row); the counts ride the table for the info
     * surface.
     */
    public static function parse(string $bytes, string $digestHex, int $mtimeUnixSecs): self
    {
        $table = new self($digestHex, $mtimeUnixSecs, \strlen($bytes));
        foreach (explode("\n", $bytes) as $rawLine) {
            $line = rtrim($rawLine, " \t\r");
            if ($line === '' || $line[0] === '#') {
                continue;
            }
            $fields = explode("\t", $line);
            // Shape A: first_ip last_ip asn [cc registry allocated...].
            // Shape B: registry first_ip last_ip asn [cc allocated...].
            $count = \count($fields);
            if ($count >= 3 && self::tryIp($fields[0]) !== null && self::tryIp($fields[1]) !== null) {
                $picked = [$fields[0], $fields[1], $fields[2]];
            } elseif ($count >= 4 && self::tryIp($fields[1]) !== null && self::tryIp($fields[2]) !== null) {
                $picked = [$fields[1], $fields[2], $fields[3]];
            } else {
                $table->malformedRows++;
                continue;
            }
            $first = self::tryIp($picked[0]);
            $last = self::tryIp($picked[1]);
            $asn = self::asnFromDigits($picked[2]);
            if ($first === null || $last === null
                || $asn === null || $asn < 1 || $asn > AsnBucket::MAX_ASN
                || $first[0] !== $last[0] || strcmp(substr($first, 1), substr($last, 1)) > 0) {
                $table->malformedRows++;
                continue;
            }
            if ($first[0] === "\x04") {
                $table->v4[] = ['first' => substr($first, 1), 'last' => substr($last, 1), 'asn' => $asn];
            } else {
                $table->v6[] = ['first' => substr($first, 1), 'last' => substr($last, 1), 'asn' => $asn];
            }
            $table->validRows++;
        }
        // Stable sort by the first endpoint, the identical ordering the
        // Rust mirror's stable key sort produces.
        $byFirst = static fn (array $a, array $b): int => strcmp($a['first'], $b['first']);
        usort($table->v4, $byFirst);
        usort($table->v6, $byFirst);

        return $table;
    }

    /**
     * The canonical family+bytes form of one textual IP, or null when
     * the field does not parse (the shared normalizer, so v4-mapped and
     * v4-compatible IPv6 fold to family 4 exactly like Rust).
     */
    private static function tryIp(string $field): ?string
    {
        try {
            return Issuer::canonicalIpFamily($field);
        } catch (\InvalidArgumentException) {
            return null;
        }
    }

    /**
     * Parses an ASN field: digits only (leading zeros tolerated), 0
     * when the field is all zeros, null beyond ten significant digits.
     */
    private static function asnFromDigits(string $field): ?int
    {
        if ($field === '' || ctype_digit($field) !== true) {
            return null;
        }
        $trimmed = ltrim($field, '0');
        if ($trimmed === '') {
            return 0;
        }
        if (\strlen($trimmed) > 10) {
            return null;
        }

        return (int) $trimmed;
    }
}
