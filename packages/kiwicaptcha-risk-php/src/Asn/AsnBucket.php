<?php

declare(strict_types=1);

namespace KiwiCaptcha\Risk\Asn;

/**
 * The ASN bucket-id grammar, mirrored exactly by the Rust
 * `kiwicaptcha_risk::asn` and pinned by the shared vectors
 * (protocol/risk-v1/asn-vectors.json).
 *
 * A listed ASN encodes as `a<decimal asn>` (canonical decimal, no
 * leading zeros, 1..4294967294). An unknown ASN encodes as its own
 * bucket per prefix under the reserved unlisted namespace: `u4/<decimal
 * /16 prefix>` for IPv4 (0..65535) and `u6/<8 lowercase hex of the /32
 * prefix>` for IPv6. Two unlisted addresses share a bucket exactly when
 * they share that prefix.
 */
final class AsnBucket
{
    public const MAX_ASN = 4294967294;

    public const MAX_V4_PREFIX = 65535;

    private function __construct()
    {
    }

    /** The bucket id of a listed ASN (canonical decimal). */
    public static function forKnownAsn(int $asn): string
    {
        if ($asn < 1 || $asn > self::MAX_ASN) {
            throw new \InvalidArgumentException(sprintf(
                'a listed ASN must be within 1..%d (got %d)',
                self::MAX_ASN,
                $asn,
            ));
        }

        return 'a' . $asn;
    }

    /**
     * The bucket id of an unlisted IPv4 address: the decimal value of
     * its first two address bytes.
     */
    public static function forUnlistedV4(string $firstTwoOctets): string
    {
        if (\strlen($firstTwoOctets) !== 2) {
            throw new \InvalidArgumentException('an IPv4 /16 prefix needs exactly two bytes');
        }

        return 'u4/' . unpack('n', $firstTwoOctets)[1];
    }

    /**
     * The bucket id of an unlisted IPv6 address: the lowercase hex of
     * its first four address bytes.
     */
    public static function forUnlistedV6(string $firstFourBytes): string
    {
        if (\strlen($firstFourBytes) !== 4) {
            throw new \InvalidArgumentException('an IPv6 /32 prefix needs exactly four bytes');
        }

        return 'u6/' . bin2hex($firstFourBytes);
    }

    /**
     * The unlisted-namespace bucket id of one address, dataset-free: the
     * bucket a lookup falls back to when no dataset row covers the
     * address (and the bucket every address resolves to when no dataset
     * is attached at all). IPv4-mapped and IPv4-compatible IPv6
     * normalize to their IPv4 form first, exactly like
     * {@see \KiwiCaptcha\Risk\Asn\AsnDataset::lookup}. Rust mirror:
     * `asn::unlisted_bucket_for`.
     */
    public static function forUnlistedIp(string $ip): string
    {
        $canonical = \KiwiCaptcha\Issuer::canonicalIpFamily($ip);
        $bytes = substr($canonical, 1);

        return $canonical[0] === "\x04"
            ? self::forUnlistedV4(substr($bytes, 0, 2))
            : self::forUnlistedV6(substr($bytes, 0, 4));
    }

    /**
     * True when the value is a canonical bucket id of the grammar above.
     * Anything else is refused before it can reach a Redis key (fail
     * closed).
     */
    public static function isValid(string $bucket): bool
    {
        if (preg_match('/\Aa(0|[1-9][0-9]{0,9})\z/', $bucket) === 1) {
            $asn = (int) substr($bucket, 1);

            return $asn >= 1 && $asn <= self::MAX_ASN;
        }
        if (preg_match('/\Au4\/(0|[1-9][0-9]{0,4})\z/', $bucket) === 1) {
            return (int) substr($bucket, 3) <= self::MAX_V4_PREFIX;
        }

        return preg_match('/\Au6\/[0-9a-f]{8}\z/', $bucket) === 1;
    }
}
