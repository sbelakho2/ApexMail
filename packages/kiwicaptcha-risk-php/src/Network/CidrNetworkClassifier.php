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

    /** @var list<array{network:string, prefix:int, flags:NetworkFlags}> */
    private array $entries = [];

    /** @param list<array{cidr:string, flags:list<string>}> $entries */
    public function __construct(array $entries)
    {
        foreach ($entries as $entry) {
            $this->entries[] = $this->parseEntry($entry);
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
        $family = strlen($bytes);

        $reserved = false;
        $hosting = false;
        $proxy = false;
        $tor = false;
        $blocked = false;

        foreach ($this->entries as $entry) {
            if (strlen($entry['network']) !== $family) {
                continue;
            }
            if ($this->matches($bytes, $entry['network'], $entry['prefix'])) {
                $f = $entry['flags'];
                $reserved = $reserved || $f->reserved;
                $hosting = $hosting || $f->knownHosting;
                $proxy = $proxy || $f->knownProxy;
                $tor = $tor || $f->torExit;
                $blocked = $blocked || $f->blocked();
            }
        }

        return new NetworkFlags(
            reserved: $reserved,
            knownHosting: $hosting,
            knownProxy: $proxy,
            torExit: $tor,
            localRiskBucket: $blocked ? 255 : 0,
        );
    }

    private function matches(string $ipBytes, string $networkBytes, int $prefix): bool
    {
        $fullBytes = intdiv($prefix, 8);
        for ($i = 0; $i < $fullBytes; $i++) {
            if ($ipBytes[$i] !== $networkBytes[$i]) {
                return false;
            }
        }
        $remain = $prefix % 8;
        if ($remain === 0) {
            return true;
        }
        $mask = 0xFF << (8 - $remain) & 0xFF;
        return (ord($ipBytes[$fullBytes]) & $mask) === (ord($networkBytes[$fullBytes]) & $mask);
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
