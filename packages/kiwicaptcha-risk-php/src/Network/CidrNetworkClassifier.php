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
        $bytes = @inet_pton($ip);
        if ($bytes === false) {
            throw new \InvalidArgumentException(sprintf('Invalid IP address: %s', $ip));
        }
        // IPv4-mapped IPv6 normalizes to the IPv4 form.
        if (strlen($bytes) === 16 && substr($bytes, 0, 12) === "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff") {
            $bytes = substr($bytes, 12, 4);
        }
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
        $prefix = filter_var($prefixRaw, FILTER_VALIDATE_INT, ['options' => ['min_range' => 0]]);
        if ($prefix === false) {
            throw new \InvalidArgumentException(sprintf('Invalid CIDR prefix: %s', $cidr));
        }
        $bytes = @inet_pton($addr);
        if ($bytes === false) {
            throw new \InvalidArgumentException(sprintf('Invalid CIDR network address: %s', $cidr));
        }
        if (strlen($bytes) === 16 && substr($bytes, 0, 12) === "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff") {
            $bytes = substr($bytes, 12, 4);
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
}
