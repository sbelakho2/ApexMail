<?php

declare(strict_types=1);

namespace KiwiCaptcha\Risk\Network;

/**
 * Static CIDR-block network classifier.
 *
 * Entries are (cidr, flags) pairs; flags may be any subset of
 * reserved, hosting, proxy, tor, blocked. Matching is done on the raw
 * prefix bits of the inet_pton bytes, so IPv4/IPv6 never cross-match.
 *
 * The rule set is compiled once at construction into a bitwise radix
 * trie (two children per level; IPv4 depth 32, IPv6 depth 128).
 * classify(ip) walks the trie in O(prefix depth) instead of an O(n)
 * CIDR scan, preserving the longest-prefix match semantics: the flags
 * of every matching prefix are OR'd into the same NetworkFlags fields
 * and labels.
 *
 * Constructor input format (per entry):
 *   ['cidr' => '203.0.113.0/24', 'flags' => ['hosting', 'proxy']]
 *
 * fromFile() parses one entry per line: "cidr,flag1,flag2" — lines starting
 * with '#' and blank lines are ignored, whitespace is trimmed.
 */
final class CidrNetworkClassifier implements NetworkClassifierInterface
{
    public const FLAG_RESERVED = 'reserved';
    public const FLAG_HOSTING = 'hosting';
    public const FLAG_PROXY = 'proxy';
    public const FLAG_TOR = 'tor';
    public const FLAG_BLOCKED = 'blocked';

    /**
     * Trie root: children keyed by the address family ('4' IPv4 / '6'
     * IPv6 — the raw inet_pton byte length, so IPv4/IPv6 never
     * cross-match), then a binary trie per family. Each node is
     * ['children' => array<int, array>, 'flags' => ?NetworkFlags].
     */
    private array $root;

    /** @param list<array{cidr:string, flags:list<string>}> $entries */
    public function __construct(array $entries)
    {
        $this->root = ['children' => [], 'flags' => null];
        foreach ($entries as $entry) {
            $parsed = $this->parseEntry($entry);
            $this->insert($parsed['network'], $parsed['prefix'], $parsed['flags']);
        }
    }

    public static function fromFile(string $path): self
    {
        $contents = @file_get_contents($path);
        if ($contents === false) {
            throw new \InvalidArgumentException(sprintf('Cannot read classifier file: %s', $path));
        }
        $entries = [];
        foreach (preg_split('/\r\n|\n|\r/', $contents) ?: [] as $line) {
            $line = trim($line);
            if ($line === '' || str_starts_with($line, '#')) {
                continue;
            }
            $parts = array_map('trim', explode(',', $line));
            $cidr = array_shift($parts);
            if ($cidr === null || $cidr === '') {
                continue;
            }
            $entries[] = ['cidr' => $cidr, 'flags' => array_values(array_filter($parts, static fn (string $f): bool => $f !== ''))];
        }
        return new self($entries);
    }

    public function classify(string $ip): NetworkFlags
    {
        $bytes = self::normalizeFamilyBytes(self::packIp($ip, sprintf('Invalid IP address: %s', $ip)));
        $family = strlen($bytes) === 4 ? '4' : '6';
        $bits = strlen($bytes) * 8;

        $accumulated = null;
        $node = $this->root['children'][$family] ?? null;
        if ($node !== null && $node['flags'] !== null) {
            // /0 rules attach to the family node and match every address.
            $accumulated = $this->mergeFlags($accumulated, $node['flags']);
        }
        for ($i = 0; $i < $bits && $node !== null; $i++) {
            $bit = (ord($bytes[intdiv($i, 8)]) >> (7 - ($i % 8))) & 1;
            $node = $node['children'][$bit] ?? null;
            if ($node !== null && $node['flags'] !== null) {
                $accumulated = $this->mergeFlags($accumulated, $node['flags']);
            }
        }

        return $accumulated ?? new NetworkFlags();
    }

    /**
     * Inserts one rule into the trie: walks the address bits up to the
     * prefix length, then ORs the entry flags into the node at that depth.
     */
    private function insert(string $bytes, int $prefix, NetworkFlags $flags): void
    {
        $family = strlen($bytes) === 4 ? '4' : '6';
        $node = &$this->root['children'][$family];
        if (!is_array($node)) {
            $node = ['children' => [], 'flags' => null];
        }
        for ($i = 0; $i < $prefix; $i++) {
            $bit = (ord($bytes[intdiv($i, 8)]) >> (7 - ($i % 8))) & 1;
            if (!isset($node['children'][$bit])) {
                $node['children'][$bit] = ['children' => [], 'flags' => null];
            }
            $node = &$node['children'][$bit];
        }
        $node['flags'] = $this->mergeFlags($node['flags'], $flags);
    }

    /** Flag union with the exact legacy semantics (localRiskBucket 0/255). */
    private function mergeFlags(?NetworkFlags $a, NetworkFlags $b): NetworkFlags
    {
        if ($a === null) {
            return $b;
        }
        return new NetworkFlags(
            reserved: $a->reserved || $b->reserved,
            knownHosting: $a->knownHosting || $b->knownHosting,
            knownProxy: $a->knownProxy || $b->knownProxy,
            torExit: $a->torExit || $b->torExit,
            localRiskBucket: ($a->blocked() || $b->blocked()) ? 255 : 0,
        );
    }

    /** @param array{cidr:string, flags:list<string>} $entry */
    private function parseEntry(array $entry): array
    {
        if (!isset($entry['cidr']) || !is_string($entry['cidr'])) {
            throw new \InvalidArgumentException('Classifier entries require a "cidr" string');
        }
        $cidr = $entry['cidr'];
        $slash = strpos($cidr, '/');
        if ($slash === false) {
            throw new \InvalidArgumentException(sprintf('CIDR entry must include a prefix: %s', $cidr));
        }
        $addr = substr($cidr, 0, $slash);
        $prefixRaw = substr($cidr, $slash + 1);
        // Canonical spelling only: `FILTER_VALIDATE_INT` trims surrounding
        // whitespace and rejects leading zeros, while Rust's u8::parse
        // trims nothing but accepts "+24"/"024"; the explicit canonical
        // grammar makes both cores load the same operator config.
        if (preg_match('/^(0|[1-9][0-9]*)$/D', $prefixRaw) !== 1) {
            throw new \InvalidArgumentException(sprintf('Invalid CIDR prefix: %s', $cidr));
        }
        $prefix = (int) $prefixRaw;
        $rawBytes = self::packIp($addr, sprintf('Invalid CIDR network address: %s', $cidr));
        $bytes = self::normalizeFamilyBytes($rawBytes);
        // A v6 spelling that canonicalizes to IPv4 (the mapped
        // ::ffff:a.b.c.d form or the deprecated compatible ::a.b.c.d
        // form, exactly the fold the walk applies) is stored as a v4
        // entry with the prefix shifted by 96. Without this, an entry
        // like ::ffff:192.0.2.0/120 was inserted into the v6 trie and
        // could never match 192.0.2.x while a genuine v6 address under
        // the same /32 was flagged; a prefix below /96 cannot address a
        // v4 network and is refused.
        if (\strlen($rawBytes) === 16 && \strlen($bytes) === 4) {
            if ($prefix < 96) {
                throw new \InvalidArgumentException(sprintf('Mapped IPv4 CIDR prefix %d is below /96: %s', $prefix, $cidr));
            }
            $prefix -= 96;
        }
        $maxBits = strlen($bytes) * 8;
        if ($prefix > $maxBits) {
            throw new \InvalidArgumentException(sprintf('CIDR prefix %d exceeds %d bits for %s', $prefix, $maxBits, $cidr));
        }

        $flags = ['flags' => $entry['flags'] ?? []];
        $reserved = false;
        $hosting = false;
        $proxy = false;
        $tor = false;
        $blocked = false;
        foreach ($flags['flags'] as $flag) {
            switch ($flag) {
                case self::FLAG_RESERVED:
                    $reserved = true;
                    break;
                case self::FLAG_HOSTING:
                    $hosting = true;
                    break;
                case self::FLAG_PROXY:
                    $proxy = true;
                    break;
                case self::FLAG_TOR:
                    $tor = true;
                    break;
                case self::FLAG_BLOCKED:
                    $blocked = true;
                    break;
                default:
                    throw new \InvalidArgumentException(sprintf('Unknown network flag: %s', $flag));
            }
        }

        return [
            'network' => $bytes,
            'prefix' => $prefix,
            'flags' => new NetworkFlags(
                reserved: $reserved,
                knownHosting: $hosting,
                knownProxy: $proxy,
                torExit: $tor,
                localRiskBucket: $blocked ? 255 : 0,
            ),
        ];
    }

    /**
     * inet_pton with the classifier's input contract: zone ids and
     * leading-zero dotted-quad octets are refused before the parser sees
     * them, and the null-byte ValueError is mapped onto the documented
     * InvalidArgumentException. The same rules guard the risk identity
     * factory, so one literal cannot classify in one layer and fail in
     * the other.
     */
    private static function packIp(string $ip, string $message): string
    {
        if (str_contains($ip, '%') || self::hasLeadingZeroOctet($ip)) {
            throw new \InvalidArgumentException($message);
        }
        try {
            $bytes = @inet_pton($ip);
        } catch (\ValueError $e) {
            throw new \InvalidArgumentException($message, 0, $e);
        }
        if ($bytes === false) {
            throw new \InvalidArgumentException($message);
        }

        return $bytes;
    }

    /**
     * IPv4-mapped and IPv4-compatible IPv6 addresses normalize to the
     * 4-byte IPv4 form, except the unspecified :: and the loopback ::1.
     * The risk identity factory applies the identical rule, so classify()
     * and canonicalIp() never disagree on the family.
     */
    private static function normalizeFamilyBytes(string $bytes): string
    {
        if (strlen($bytes) !== 16) {
            return $bytes;
        }
        $low = substr($bytes, 12, 4);
        if (substr($bytes, 0, 12) === "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff") {
            return $low;
        }
        if (substr($bytes, 0, 12) === str_repeat("\x00", 12)
            && $low !== "\x00\x00\x00\x00"
            && $low !== "\x00\x00\x00\x01") {
            return $low;
        }

        return $bytes;
    }

    /**
     * True when the literal carries a dotted-quad with a leading-zero
     * octet (203.0.113.027, 0177.0.0.1); a single 0 octet stays valid.
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
}
