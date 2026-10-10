<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Security\StepUp;

/**
 * The RFC 6238 time-based one-time passcode engine: hash_hmac over
 * the 8-byte big-endian moving factor, dynamic truncation, the modulo
 * digit projection. SHA-1 and SHA-256 are implemented (the two
 * algorithms of the RFC's appendix test vectors this bundle pins); the
 * base32 codec of RFC 4648 is in-bundle, so the handler carries no new
 * composer dependency.
 */
final class TotpCode
{
    public const STEP_SECS = 30;

    private const ALGOS = ['sha1' => true, 'sha256' => true];

    /** The RFC 4648 base32 alphabet. */
    private const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

    private function __construct()
    {
    }

    /**
     * The code of one time-step: the hmac-based one-time passcode value
     * of the moving factor under the raw secret, per RFC 6238.
     * Deterministic and pure.
     */
    public static function at(string $secretRaw, int $step, string $algo = 'sha1', int $digits = 6): string
    {
        self::assertAlgo($algo);
        if ($digits !== 6 && $digits !== 8) {
            throw new \InvalidArgumentException('The code length must be 6 or 8 digits');
        }
        $digest = hash_hmac($algo, pack('J', $step), $secretRaw, true);
        $offset = \ord($digest[\strlen($digest) - 1]) & 0x0F;
        $binary = ((\ord($digest[$offset]) & 0x7F) << 24)
            | (\ord($digest[$offset + 1]) << 16)
            | (\ord($digest[$offset + 2]) << 8)
            | \ord($digest[$offset + 3]);

        return str_pad((string) ($binary % (10 ** $digits)), $digits, '0', STR_PAD_LEFT);
    }

    /**
     * The moving factor of a Unix timestamp: floor(seconds / 30), the
     * RFC 6238 time-step.
     */
    public static function stepOf(int $unixTime): int
    {
        return intdiv($unixTime, self::STEP_SECS);
    }

    /**
     * RFC 4648 base32 encode (no padding).
     */
    public static function base32Encode(string $raw): string
    {
        $out = '';
        $bits = 0;
        $val = 0;
        foreach (str_split($raw) as $byte) {
            $val = ($val << 8) | \ord($byte);
            $bits += 8;
            while ($bits >= 5) {
                $bits -= 5;
                $out .= self::BASE32_ALPHABET[($val >> $bits) & 31];
            }
        }
        if ($bits > 0) {
            $out .= self::BASE32_ALPHABET[($val << (5 - $bits)) & 31];
        }

        return $out;
    }

    /**
     * RFC 4648 base32 decode: padding and internal whitespace are
     * ignored, mixed case is accepted, and any byte outside the
     * alphabet is rejected (an empty or invalid encoding answers null,
     * never a partial decode).
     */
    public static function base32Decode(string $encoded): ?string
    {
        $clean = strtoupper(str_replace([' ', "\t", "\r", "\n", '='], '', $encoded));
        if ($clean === '' || \strlen($clean) > 512 || preg_match('/^[A-Z2-7]+$/D', $clean) !== 1) {
            return null;
        }
        $out = '';
        $bits = 0;
        $val = 0;
        foreach (str_split($clean) as $char) {
            $digit = strpos(self::BASE32_ALPHABET, $char);
            \assert(\is_int($digit));
            $val = ($val << 5) | $digit;
            $bits += 5;
            if ($bits >= 8) {
                $bits -= 8;
                $out .= \chr(($val >> $bits) & 0xFF);
            }
        }

        return $out;
    }

    /** @pure */
    private static function assertAlgo(string $algo): void
    {
        if (!isset(self::ALGOS[$algo])) {
            throw new \InvalidArgumentException(sprintf('The RFC 6238 algorithm must be one of %s', implode('|', array_keys(self::ALGOS))));
        }
    }
}
