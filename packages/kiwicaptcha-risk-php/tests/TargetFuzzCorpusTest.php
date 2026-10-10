<?php

declare(strict_types=1);

namespace KiwiCaptcha\Risk\Tests;

use KiwiCaptcha\Risk\RiskIdentityFactory;
use KiwiCaptcha\Risk\RiskKeys;
use KiwiCaptcha\Risk\TargetIdentifierNormalizer;
use PHPUnit\Framework\TestCase;

/**
 * Confusables and homoglyph fuzz corpus for the target dimension.
 *
 * A deterministic seeded generator mutates a small base corpus ~5000
 * times with confusable-class mutations: fullwidth mapping, ASCII case
 * flips, whitespace padding, dot/plus/hyphen tag insertion, accent
 * injection and Cyrillic homoglyph substitution. The lcg runs entirely
 * in 31-bit integer arithmetic, so PHP and Rust walk the identical
 * stream.
 *
 * Every mutation carries its own rule-model expectation, independent of
 * the implementation. The aliasing classes (`NFKC` folding, table
 * provider rules) must collapse onto one target pseudonym. The
 * look-alike classes (accents, Cyrillic homoglyphs, embedded spaces,
 * plus tags and dots at providers outside the table) must stay distinct
 * targets. Pin both directions: under-normalizing splits one mailbox
 * into many targets, over-normalizing merges two mailboxes into one.
 */
final class TargetFuzzCorpusTest extends TestCase
{
    private const SEED = 0x6b6b6b01;
    private const MUTATIONS = 5000;

    private const BASES = [
        // [base identifier, provider class: g=gmail dots+plus, p=plus tag, h=hyphen tag, n=none]
        ['user.one@gmail.com', 'g'],
        ['ali.ce.b+shop@gmail.com', 'g'],
        ['bob.mailbox@googlemail.com', 'g'],
        ['carol.last+news@outlook.com', 'p'],
        ['dana.q+tag@live.com', 'p'],
        ['evan.t+cart@hotmail.com', 'p'],
        ['fiona+cloud@icloud.com', 'p'],
        ['greg.h-ytag@yahoo.com', 'h'],
        ['hilda@proton.me', 'n'],
        ['ivan@fastmail.com', 'n'],
        ['plainuser', 'n'],
        ['mixed.Case@Example.COM', 'n'],
    ];

    /** Cyrillic look-alikes with no `NFKC` fold onto the Latin letter. */
    private const CYRILLIC = [
        'a' => 'а', 'e' => 'е', 'o' => 'о', 'p' => 'р', 'c' => 'с',
        'y' => 'у', 'x' => 'х', 'i' => 'і', 'j' => 'ј', 's' => 'ѕ',
    ];

    private int $state;
    /** @var array<string, int> per-kind mutation counts (and skips) */
    private array $counts = [];

    /** 31-bit LCG: identical stream in PHP and Rust (u31 product fits both). */
    private function next(): int
    {
        $this->state = ($this->state * 1103515245 + 12345) & 0x7FFFFFFF;

        return $this->state;
    }

    private function pick(int $n): int
    {
        return $this->next() % $n;
    }

    /** Maps one ASCII char to its fullwidth form where one exists. */
    private static function fullwidth(string $ch): string
    {
        if ($ch >= '0' && $ch <= '9') {
            return mb_chr(0xFF10 + ord($ch) - ord('0'), 'UTF-8');
        }
        if ($ch >= 'A' && $ch <= 'Z') {
            return mb_chr(0xFF21 + ord($ch) - ord('A'), 'UTF-8');
        }
        if ($ch >= 'a' && $ch <= 'z') {
            return mb_chr(0xFF41 + ord($ch) - ord('a'), 'UTF-8');
        }

        return match ($ch) {
            '@' => "\u{FF20}",
            '.' => "\u{FF0E}",
            '+' => "\u{FF0B}",
            '-' => "\u{FF0D}",
            default => $ch,
        };
    }

    /**
     * The local part of an email base (the insertion range for provider
     * tag mutations); a plain identifier is its own range.
     */
    private static function localRange(string $base): int
    {
        $at = strrpos($base, '@');

        return $at === false ? \strlen($base) : $at;
    }

    /**
     * The insertion index for a tag/dot mutation. The index is chosen so
     * the mutation lands where the provider rules leave it visible
     * unless the class legitimately folds it: a stripping provider
     * appends its own tag at the end, the real-world aliasing form. The
     * non-folding insertions stay ahead of any existing tag marker, so a
     * strip rule cannot swallow them and fake a collapse.
     */
    private function insertionIndex(string $local, string $class, int $kind): int
    {
        $firstPlus = strpos($local, '+');
        $firstHyphen = strpos($local, '-');
        $rand = fn (): int => $this->pick(\strlen($local) + 1);
        if ($kind === 4) {
            // Plus tags: appended at the stripping providers, ahead of a
            // hyphen rule elsewhere.
            return match ($class) {
                'g', 'p' => \strlen($local),
                'h' => $firstHyphen === false ? $rand() : $firstHyphen,
                default => $rand(),
            };
        }
        if ($kind === 8) {
            // Hyphen tags: appended at the stripping provider, ahead of a
            // plus rule elsewhere.
            return match ($class) {
                'h' => \strlen($local),
                'g', 'p' => $firstPlus === false ? $rand() : $firstPlus,
                default => $rand(),
            };
        }
        // Dots fold only at gmail; elsewhere they must stay visible.
        if ($class === 'g') {
            return $rand();
        }

        return match ($class) {
            'p' => $firstPlus === false ? $rand() : $firstPlus,
            'h' => $firstHyphen === false ? $rand() : $firstHyphen,
            default => $rand(),
        };
    }

    /**
     * The length of the base's provider-visible prefix: the part of the
     * identifier that survives the class's strip rules. Mutations whose
     * distinctness is asserted must land inside it, or the strip rule
     * would swallow them and fake a collapse.
     */
    private static function visibleLength(string $base, string $class): int
    {
        $local = substr($base, 0, self::localRange($base));
        $marker = match ($class) {
            'g', 'p' => strpos($local, '+'),
            'h' => strpos($local, '-'),
            default => false,
        };

        return $marker === false ? \strlen($base) : $marker;
    }

    public function testFuzzCorpusCollapsesAndSplitsPerTheRuleModel(): void
    {
        $factory = new RiskIdentityFactory(RiskKeys::fromMaster(str_repeat("\x42", 32)));
        $id = fn (string $raw): string => $factory->targetId(TargetIdentifierNormalizer::normalize($raw));
        $normalized = fn (string $raw): string => TargetIdentifierNormalizer::normalize($raw);

        $this->state = self::SEED;
        for ($i = 0; $i < self::MUTATIONS; $i++) {
            [$base, $class] = self::BASES[$this->pick(\count(self::BASES))];
            $kind = $this->pick(9);
            $variant = $this->mutate($base, $class, $kind);
            $this->counts["k$kind"] = ($this->counts["k$kind"] ?? 0) + 1;
            if ($variant === null) {
                continue;
            }

            // The rule model, stated per mutation class and provider
            // class, decides the expectation before the pipeline runs.
            $collapses = match ($kind) {
                0, 1, 2 => true, // fullwidth, case flip, whitespace edges
                3 => $class === 'g', // dot insertion only folds at gmail
                4 => $class === 'g' || $class === 'p', // plus tags fold at table providers
                5 => false, // accent injection never folds
                6 => false, // Cyrillic homoglyphs never fold
                7 => false, // embedded whitespace is part of the identifier
                8 => $class === 'h', // hyphen tags fold only at yahoo
            };

            $baseNorm = $normalized($base);
            if ($collapses) {
                self::assertSame(
                    $baseNorm,
                    $normalized($variant),
                    sprintf('mutation %d of 0x%s must normalize onto the base (kind %d)', $i, bin2hex($variant), $kind),
                );
                self::assertSame(
                    $id($base),
                    $id($variant),
                    sprintf('mutation %d of 0x%s must collapse onto one target (kind %d)', $i, bin2hex($variant), $kind),
                );
            } else {
                self::assertNotSame(
                    $baseNorm,
                    $normalized($variant),
                    sprintf('mutation %d of 0x%s must stay a distinct identifier (kind %d)', $i, bin2hex($variant), $kind),
                );
                self::assertNotSame(
                    $id($base),
                    $id($variant),
                    sprintf('mutation %d of 0x%s must stay a distinct target (kind %d)', $i, bin2hex($variant), $kind),
                );
            }
        }

        // Every mutation family must have been exercised (a family that
        // silently stops generating would hollow out the corpus).
        for ($kind = 0; $kind <= 8; $kind++) {
            self::assertGreaterThan(
                150,
                $this->counts["k$kind"] ?? 0,
                sprintf('mutation kind %d must stay exercised', $kind),
            );
        }
        self::assertGreaterThanOrEqual(self::MUTATIONS, array_sum($this->counts));
    }

    /**
     * Applies one mutation of the given kind; null when the base offers
     * no position for that kind (a counted skip, never a silent one).
     * The provider class steers the tag insertions so the rule model's
     * expectation holds by construction.
     */
    private function mutate(string $base, string $class, int $kind): ?string
    {
        $len = \strlen($base);
        $visible = self::visibleLength($base, $class);
        switch ($kind) {
            case 0: // fullwidth window
                $start = $this->pick($len);
                $span = 1 + $this->pick(4);
                $out = '';
                for ($j = 0; $j < $len; $j++) {
                    $out .= ($j >= $start && $j < $start + $span) ? self::fullwidth($base[$j]) : $base[$j];
                }

                return $out;
            case 1: // ASCII case flips
                $out = '';
                for ($j = 0; $j < $len; $j++) {
                    $ch = $base[$j];
                    $out .= (($ch >= 'a' && $ch <= 'z') || ($ch >= 'A' && $ch <= 'Z')) && $this->pick(2) === 0
                        ? ($ch >= 'a' ? strtoupper($ch) : strtolower($ch))
                        : $ch;
                }

                return $out;
            case 2: // whitespace edges (space, tab, nbsp; `NFKC` folds nbsp)
                $padSet = [" \t", "\u{00A0}\u{00A0}", '  '];
                return $padSet[$this->pick(\count($padSet))] . $base . $padSet[$this->pick(\count($padSet))];
            case 3: // dot insertion inside the local part
            case 4: // plus-tag insertion inside the local part
            case 8: // hyphen-tag insertion inside the local part
                $local = substr($base, 0, self::localRange($base));
                $at = $this->insertionIndex($local, $class ?? 'n', $kind);
                $insert = match ($kind) {
                    3 => '.',
                    4 => '+t' . $this->pick(10),
                    8 => '-y' . $this->pick(10),
                };

                return substr($base, 0, $at) . $insert . substr($base, $at);
            case 5: // accent injection: one ASCII alnum becomes e-acute
                for ($try = 0; $try < 8; $try++) {
                    $at = $this->pick($visible);
                    if ($at < $len && ctype_alnum($base[$at])) {
                        return substr($base, 0, $at) . "\u{E9}" . substr($base, $at + 1);
                    }
                }

                return null;
            case 6: // Cyrillic homoglyph substitution
                $targets = [];
                for ($j = 0; $j < $visible && $j < $len; $j++) {
                    if (isset(self::CYRILLIC[$base[$j]])) {
                        $targets[] = $j;
                    }
                }
                if ($targets === []) {
                    return null;
                }
                $at = $targets[$this->pick(\count($targets))];

                return substr($base, 0, $at) . self::CYRILLIC[$base[$at]] . substr($base, $at + 1);
            case 7: // embedded space at an interior position
                if ($visible < 2) {
                    return null;
                }
                $at = 1 + $this->pick($visible - 1);

                return substr($base, 0, $at) . ' ' . substr($base, $at);
        }

        throw new \LogicException('unreachable mutation kind');
    }
}
