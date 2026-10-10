<?php

declare(strict_types=1);

namespace KiwiCaptcha\Risk;

/**
 * The versioned target-identifier normalization pipeline.
 *
 * Stages, in order: `NFKC` compatibility normalization
 * (\Normalizer::normalize with `FORM_KC`), Unicode case folding
 * (mb_strtolower, UTF-8), a trim of the ASCII whitespace edges, then the
 * free static per-provider email canonicalization table
 * ({@see TargetEmailCanonicalization}).
 *
 * Case-folding boundary, stated honestly: mb_strtolower applies the
 * locale-independent Unicode lowercasing, which covers the practical
 * fold space for identifiers (fullwidth and compatibility forms arrive
 * already folded by `NFKC`; the Turkish dotless i and the capital I fold
 * identically in both cores). It is not full Unicode case folding:
 * the German sharp s stays sharp s (never folds to "ss"). The shared
 * vector corpus (protocol/risk-v1/target-vectors.json) pins the exact
 * behavior in both languages.
 *
 * The version const is stamped into the derivation context of
 * {@see RiskIdentityFactory::targetId()}, so a pipeline change derives
 * fresh pseudonyms and can never collide with pseudonyms derived under an
 * earlier pipeline. Rust mirrors every stage and the version byte for
 * byte.
 *
 * Fail-closed: the pipeline requires ext-intl (Normalizer) and
 * ext-mbstring (mb_strtolower). Both are suggested, not required,
 * composer dependencies of this package, mirroring the optional gmp
 * handling of the rsw algorithm. The normalization refuses to run with a
 * clear exception when either extension is missing, instead of silently
 * skipping a stage, because a skipped stage would split one target's
 * pseudonyms in two.
 */
final class TargetIdentifierNormalizer
{
    /**
     * The pipeline version stamped into the target derivation context.
     * Bump on every change to any stage or to the provider table.
     */
    public const VERSION = 1;

    /**
     * Never instantiated: the pipeline is a pure static function.
     */
    private function __construct()
    {
    }

    /**
     * Normalizes a raw target identifier through the full pipeline.
     *
     * @throws \InvalidArgumentException when ext-intl or ext-mbstring is
     *                                   missing (fail-closed: a missing
     *                                   stage throws, it never skips)
     * @throws \RuntimeException         when the input is not valid
     *                                   UTF-8 (the ext-intl Normalizer
     *                                   refuses it)
     */
    public static function normalize(string $raw): string
    {
        if (!\extension_loaded('intl')) {
            throw new \InvalidArgumentException(
                'the target identifier pipeline requires the intl extension for nfkc normalization'
            );
        }
        if (!\extension_loaded('mbstring')) {
            throw new \InvalidArgumentException(
                'the target identifier pipeline requires the mbstring extension for unicode case folding'
            );
        }
        $nfkc = \Normalizer::normalize($raw, \Normalizer::FORM_KC);
        if ($nfkc === false) {
            throw new \RuntimeException(sprintf(
                'the target identifier must be valid UTF-8 (got 0x%s)',
                bin2hex($raw),
            ));
        }
        $folded = mb_strtolower($nfkc, 'UTF-8');
        $trimmed = trim($folded, " \t\n\r\0\x0B");

        return TargetEmailCanonicalization::canonicalize($trimmed);
    }
}
