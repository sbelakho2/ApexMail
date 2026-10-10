<?php

declare(strict_types=1);

namespace KiwiCaptcha\Risk;

/**
 * Ephemeral identity derivation, byte-identical with the risk-v1 contract.
 *
 * - canonicalIp(): family byte 0x04/0x06 + packed bytes; IPv4-mapped IPv6
 *   (::ffff:a.b.c.d) and the deprecated IPv4-compatible 0::/96 form
 *   (::a.b.c.d, excluding :: and ::1) are normalized to IPv4.
 * - pseudonym(): first 16 bytes of
 *   HMAC-SHA256(key, "kiwi-risk-id-v1\0" || context || "\0" ||
 *                epoch.to_be_bytes() || material)   (epoch big-endian 8 bytes)
 * - maskIp(): family byte + prefix-masked bytes (IPv4 /24, IPv6 /56).
 */
final class RiskIdentityFactory
{
    /**
     * The ASN dimension's rotation window in seconds (six hours), per
     * the risk-v2 identity contract file protocol/risk-v2/identity.json.
     */
    public const ASN_EPOCH_SECS = 21600;

    public function __construct(
        private readonly RiskKeys $keys,
        private readonly int $sourceEpochSecs = 900,
        private readonly int $subnetEpochSecs = 900,
        private readonly int $ipv4Prefix = 24,
        private readonly int $ipv6Prefix = 56,
    ) {
        // A zero epoch window divides by zero in sourceId()/subnetId():
        // refuse it at construction instead of at request time.
        if ($sourceEpochSecs < 1 || $subnetEpochSecs < 1) {
            throw new \InvalidArgumentException(sprintf(
                'Epoch windows must be >= 1 second (source: %d, subnet: %d)',
                $sourceEpochSecs,
                $subnetEpochSecs,
            ));
        }
        // Out-of-range masks are refused at construction: maskIp() would
        // otherwise throw at request time, after the caller already built
        // an engine it cannot use.
        if ($ipv4Prefix < 0 || $ipv4Prefix > 32) {
            throw new \InvalidArgumentException(sprintf('ipv4Prefix must be within 0..32 (got %d)', $ipv4Prefix));
        }
        if ($ipv6Prefix < 0 || $ipv6Prefix > 128) {
            throw new \InvalidArgumentException(sprintf('ipv6Prefix must be within 0..128 (got %d)', $ipv6Prefix));
        }
    }

    /**
     * Canonical IP form: family byte (0x04/0x06) + packed bytes.
     *
     * IPv4-mapped IPv6 addresses normalize to the 4-byte IPv4 form, and
     * so do the deprecated IPv4-compatible ones (::a.b.c.d), except the
     * unspecified :: and the loopback ::1.
     *
     * @throws \InvalidArgumentException on every input that inet_pton
     *                                   cannot read as an IP address,
     *                                   including zone ids, leading-zero
     *                                   octets and null bytes
     */
    public function canonicalIp(string $ip): string
    {
        if (str_contains($ip, '%') || self::hasLeadingZeroOctet($ip)) {
            throw new \InvalidArgumentException(sprintf('Invalid IP address: %s', $ip));
        }
        try {
            $bytes = @inet_pton($ip);
        } catch (\ValueError $e) {
            throw new \InvalidArgumentException(sprintf('Invalid IP address: %s', $ip), 0, $e);
        }
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
            $low = substr($bytes, 12, 4);
            if (substr($bytes, 0, 12) === str_repeat("\x00", 12)
                && $low !== "\x00\x00\x00\x00"
                && $low !== "\x00\x00\x00\x01") {
                return "\x04" . $low;
            }
            return "\x06" . $bytes;
        }
        throw new \InvalidArgumentException(sprintf('Invalid IP address: %s', $ip));
    }

    /**
     * True when the literal carries a dotted-quad with a leading-zero
     * octet (203.0.113.027, 0177.0.0.1). inet_pton reads those octets as
     * decimal while other readers treat them as octal, and Rust's
     * IpAddr rejects them, so the canonical identity would split across
     * languages; refuse them up front. A single 0 octet stays valid.
     */
    private static function hasLeadingZeroOctet(string $ip): bool
    {
        if (!str_contains($ip, '.')) {
            return false;
        }
        $colon = strrpos($ip, ':');
        $quad = $colon === false ? $ip : substr($ip, $colon + 1);
        if (preg_match('/^[0-9.]+$/', $quad) !== 1) {
            return false;
        }
        foreach (explode('.', $quad) as $octet) {
            if (strlen($octet) > 1 && $octet[0] === '0') {
                return true;
            }
        }

        return false;
    }

    /**
     * 128-bit ephemeral pseudonym (hex, 32 chars): first 16 bytes of the
     * HMAC-SHA256 described in the contract. Epoch is encoded as an 8-byte
     * big-endian unsigned integer via pack('J').
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
     * material = canonical source bytes (full IPv4, IPv6 /64).
     */
    public function sourceId(string $ip, int $nowSecs): string
    {
        $epoch = self::floorDiv($nowSecs, $this->sourceEpochSecs);
        return $this->sourceIdForEpochIp($ip, $epoch);
    }

    /**
     * Subnet pseudonym: context "net", epoch = floor(now / subnetEpochSecs),
     * material = masked canonical network (IPv4 /24, IPv6 /56).
     */
    public function subnetId(string $ip, int $nowSecs): string
    {
        $epoch = self::floorDiv($nowSecs, $this->subnetEpochSecs);
        return $this->subnetIdForEpochIp($ip, $epoch);
    }

    /**
     * Floor division for the epoch windows: intdiv truncates toward
     * zero, so -1 would alias epoch 0 although the contract documents
     * floor(now / epoch). The non-negative fast path is unchanged.
     */
    private static function floorDiv(int $value, int $divisor): int
    {
        $quotient = intdiv($value, $divisor);
        if ($value < 0 && $value % $divisor !== 0) {
            $quotient--;
        }

        return $quotient;
    }

    /**
     * Source pseudonym for an explicit epoch (same canonical HMAC
     * construction as sourceId(), with the epoch passed in). The epoch±1
     * boundary keys must use their own epochs' pseudonyms, never the
     * current-epoch one.
     */
    public function sourceIdForEpoch(RiskContext $c, int $epoch): string
    {
        return $this->sourceIdForEpochIp($c->sourceIp, $epoch);
    }

    /**
     * Subnet pseudonym for an explicit epoch (same canonical HMAC
     * construction as subnetId(), with the epoch passed in).
     */
    public function subnetIdForEpoch(RiskContext $c, int $epoch): string
    {
        return $this->subnetIdForEpochIp($c->sourceIp, $epoch);
    }

    /** @internal string-IP variant shared by the epoch-parameterized derivations */
    private function sourceIdForEpochIp(string $ip, int $epoch): string
    {
        // Source material = the shared source identity: full IPv4, /64
        // IPv6 (a host controls at least a /64, so a /128-keyed source
        // lets it rotate addresses for a fresh pseudonym on every
        // request). Mirrors Rust identity.rs
        // `masked_network(ip, 32, 64)`; the subnet derivation below keeps
        // the configurable /24 // /56 window.
        return $this->pseudonym(
            $this->keys->source,
            'src',
            $epoch,
            \KiwiCaptcha\Issuer::canonicalSourceFamily($ip),
        );
    }

    /** @internal string-IP variant shared by the epoch-parameterized derivations */
    private function subnetIdForEpochIp(string $ip, int $epoch): string
    {
        return $this->pseudonym($this->keys->subnet, 'net', $epoch, $this->maskIp($ip, $this->ipv4Prefix, $this->ipv6Prefix));
    }

    /**
     * Session pseudonym: context "sess", no epoch. The material is the
     * decoded 16-byte session cookie value. The cookie travels as 32
     * lowercase hex chars (the browser representation) and the HMAC binds
     * the raw bytes here, so PHP and Rust derive one pseudonym per
     * browser identity instead of splitting on the representation.
     *
     * @throws \InvalidArgumentException when the value is not exactly 32
     *                                   lowercase hex chars
     */
    public function sessionId(string $session): string
    {
        if (preg_match('/^[0-9a-f]{32}\z/', $session) !== 1) {
            throw new \InvalidArgumentException(
                'The session cookie value must be 32 lowercase hex chars (16 raw bytes)'
            );
        }
        $raw = hex2bin($session);
        \assert(\is_string($raw));
        return $this->pseudonym($this->keys->session, 'sess', 0, $raw);
    }

    /** Principal pseudonym: context "prin", no epoch, app principal id bytes. */
    public function principalId(string $principal): string
    {
        return $this->pseudonym($this->keys->principal, 'prin', 0, $principal);
    }

    /**
     * ASN pseudonym for the epoch covering $nowSecs: context "asn",
     * material = the ASN bucket id string, keyed by the subnet HKDF key.
     * The context string and the six-hour rotation window are declared
     * by the risk-v2 identity contract file
     * (protocol/risk-v2/identity.json), which is their source of truth;
     * the derivation mirrors the source/subnet epoch pattern above
     * (floor division, epoch big-endian in the HMAC slot). The bucket
     * id comes from the free ASN dataset and never identifies a single
     * host.
     */
    public function asnId(string $bucketId, int $nowSecs): string
    {
        return $this->pseudonym(
            $this->keys->subnet,
            'asn',
            self::floorDiv($nowSecs, self::ASN_EPOCH_SECS),
            $bucketId,
        );
    }

    /**
     * Agent pseudonym: context "agent", no epoch, keyed by the
     * principal HKDF key. The material is the configured verified-agent
     * key id, a deployment identifier with no per-user cardinality. The
     * context string and the key assignment are declared by the
     * risk-v2 identity contract file, which is their source of truth.
     */
    public function agentId(string $agentKeyId): string
    {
        return $this->pseudonym($this->keys->principal, 'agent', 0, $agentKeyId);
    }

    /**
     * Target pseudonym: the full 32-byte HMAC-SHA256 (64 lowercase hex
     * chars) over a normalized target identifier. The message mirrors
     * the shared pseudonym framing with context "tgt" and the target
     * pipeline version in the epoch slot ("kiwi-risk-id-v1\0tgt\0" ||
     * pack('J', version) || normalized), keyed by the master-derived
     * target key. Unlike the 16-byte identity pseudonyms this digest is
     * kept whole: the target dimension is keyed by the full digest, and
     * the version stamp means a pipeline change can never collide with
     * pseudonyms derived under an earlier pipeline. The caller passes
     * only the output of TargetIdentifierNormalizer::normalize()
     * forward; the normalized value itself never leaves this boundary.
     */
    public function targetId(string $normalizedIdentifier): string
    {
        $message = "kiwi-risk-id-v1\0tgt\0" . pack('J', TargetIdentifierNormalizer::VERSION) . $normalizedIdentifier;
        return hash_hmac('sha256', $message, $this->keys->target);
    }
}
