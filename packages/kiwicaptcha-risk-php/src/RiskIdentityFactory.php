<?php

declare(strict_types=1);

namespace KiwiCaptcha\Risk;

/**
 * Ephemeral identity derivation, byte-identical with the risk-v1 contract.
 *
 * - canonicalIp(): family byte 0x04/0x06 + packed bytes; IPv4-mapped IPv6
 *   (::ffff:a.b.c.d) is normalized to IPv4.
 * - pseudonym(): first 16 bytes of
 *   HMAC-SHA256(key, "kiwi-risk-id-v1\0" || context || "\0" ||
 *                epoch.to_be_bytes() || material)   (epoch big-endian 8 bytes)
 * - maskIp(): family byte + prefix-masked bytes (IPv4 /24, IPv6 /56).
 */
final class RiskIdentityFactory
{
    public function __construct(
        private readonly RiskKeys $keys,
        private readonly int $sourceEpochSecs = 900,
        private readonly int $subnetEpochSecs = 900,
    ) {
    }

    /**
     * Canonical IP form: family byte (0x04/0x06) + packed bytes.
     *
     * IPv4-mapped IPv6 addresses normalize to the 4-byte IPv4 form.
     *
     * @throws \InvalidArgumentException on any other length (invalid input)
     */
    public function canonicalIp(string $ip): string
    {
        $bytes = @inet_pton($ip);
        if ($bytes === false) {
            throw new \InvalidArgumentException(sprintf('Invalid IP address: %s', $ip));
        }
        $len = strlen($bytes);
        if ($len === 4) {
            return "\x04" . $bytes;
        }
        if ($len === 16) {
            if (substr($bytes, 0, 12) === "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff") {
                return "\x04" . substr($bytes, 12, 4);
            }
            return "\x06" . $bytes;
        }
        throw new \InvalidArgumentException(sprintf('Invalid IP address: %s', $ip));
    }

    /**
     * 128-bit ephemeral pseudonym (hex, 32 chars): first 16 bytes of the
     * HMAC-SHA256 described in the contract. Epoch is encoded as an 8-byte
     * big-endian unsigned integer (pack('J')).
     */
    public function pseudonym(string $key, string $context, int $epoch, string $material): string
    {
        $message = "kiwi-risk-id-v1\0" . $context . "\0" . pack('J', $epoch) . $material;
        return bin2hex(substr(hash_hmac('sha256', $message, $key, true), 0, 16));
    }

    /**
     * Family byte + masked bytes (IPv4 default /24, IPv6 default /56).
     */
    public function maskIp(string $ip, int $ipv4Prefix = 24, int $ipv6Prefix = 56): string
    {
        $canonical = $this->canonicalIp($ip);
        $family = $canonical[0];
        $bytes = substr($canonical, 1);
        $prefix = $family === "\x04" ? $ipv4Prefix : $ipv6Prefix;
        $maxBits = strlen($bytes) * 8;
        if ($prefix < 0 || $prefix > $maxBits) {
            throw new \InvalidArgumentException(sprintf('Prefix must be within 0..%d (got %d)', $maxBits, $prefix));
        }
        $masked = '';
        $remaining = $prefix;
        foreach (str_split($bytes) as $byte) {
            if ($remaining >= 8) {
                $masked .= $byte;
                $remaining -= 8;
            } elseif ($remaining > 0) {
                $masked .= chr(ord($byte) & (0xFF << (8 - $remaining) & 0xFF));
                $remaining = 0;
            } else {
                $masked .= "\x00";
            }
        }
        return $family . $masked;
    }

    /**
     * Source pseudonym: context "src", epoch = floor(now / sourceEpochSecs),
     * material = canonical IP bytes.
     */
    public function sourceId(string $ip, int $nowSecs): string
    {
        $epoch = intdiv($nowSecs, $this->sourceEpochSecs);
        return $this->pseudonym($this->keys->source, 'src', $epoch, $this->canonicalIp($ip));
    }

    /**
     * Subnet pseudonym: context "net", epoch = floor(now / subnetEpochSecs),
     * material = masked canonical network (IPv4 /24, IPv6 /56).
     */
    public function subnetId(string $ip, int $nowSecs): string
    {
        $epoch = intdiv($nowSecs, $this->subnetEpochSecs);
        return $this->pseudonym($this->keys->subnet, 'net', $epoch, $this->maskIp($ip));
    }

    /** Session pseudonym: context "sess", no epoch, raw session cookie value. */
    public function sessionId(string $session): string
    {
        return $this->pseudonym($this->keys->session, 'sess', 0, $session);
    }

    /** Principal pseudonym: context "prin", no epoch, app principal id bytes. */
    public function principalId(string $principal): string
    {
        return $this->pseudonym($this->keys->principal, 'prin', 0, $principal);
    }
}
