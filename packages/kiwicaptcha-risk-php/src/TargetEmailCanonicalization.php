<?php

declare(strict_types=1);

namespace KiwiCaptcha\Risk;

/**
 * The free static per-provider email canonicalization table.
 *
 * A pure PHP table, no service and no network: the curated provider rules
 * shipped with the package. The input is the already-trimmed, folded and
 * `NFKC`-normalized identifier; the output collapses the provider-specific
 * aliasing that lets one mailbox appear under many spellings.
 *
 * Rules: googlemail.com rewrites to gmail.com, and gmail.com strips the
 * local part at the first plus tag and removes every dot. The providers
 * outlook.com, live.com, hotmail.com and icloud.com strip the local part
 * at the first plus tag but keep dots. Yahoo.com strips the local part at
 * the first hyphen tag. Every other provider keeps the local part
 * untouched except for the trim and case folding the pipeline already
 * applied, and the domain matches exactly (a bare or subdomained host is
 * never rewritten).
 *
 * The table has its own version const: any change to a rule bumps
 * {@see self::TABLE_VERSION} together with
 * {@see TargetIdentifierNormalizer::VERSION}, so the derived target
 * pseudonyms can never collide across table revisions.
 */
final class TargetEmailCanonicalization
{
    /** Version of the curated provider table (bump with the pipeline version). */
    public const TABLE_VERSION = 1;

    private const RULE_STRIP_PLUS_AND_DOTS = 0;
    private const RULE_STRIP_PLUS = 1;
    private const RULE_STRIP_HYPHEN = 2;

    /** Domain aliases rewritten before the rule lookup. */
    private const DOMAIN_ALIASES = [
        'googlemail.com' => 'gmail.com',
    ];

    /** The curated provider table: exact domain => local-part rule. */
    private const PROVIDERS = [
        'gmail.com' => self::RULE_STRIP_PLUS_AND_DOTS,
        'outlook.com' => self::RULE_STRIP_PLUS,
        'live.com' => self::RULE_STRIP_PLUS,
        'hotmail.com' => self::RULE_STRIP_PLUS,
        'icloud.com' => self::RULE_STRIP_PLUS,
        'yahoo.com' => self::RULE_STRIP_HYPHEN,
    ];

    /**
     * Never instantiated: the table is a free static asset.
     */
    private function __construct()
    {
    }

    /**
     * Canonicalizes an email-shaped identifier per the provider table.
     * A value without an at sign is returned unchanged (a plain username
     * has no provider rule). The local part splits at the last at sign,
     * so a quoted local part carrying an at sign stays one local part.
     */
    public static function canonicalize(string $identifier): string
    {
        $at = strrpos($identifier, '@');
        if ($at === false) {
            return $identifier;
        }
        $local = substr($identifier, 0, $at);
        $domain = substr($identifier, $at + 1);
        $domain = self::DOMAIN_ALIASES[$domain] ?? $domain;
        $rule = self::PROVIDERS[$domain] ?? null;
        if ($rule === null) {
            return $identifier;
        }
        if ($rule === self::RULE_STRIP_PLUS_AND_DOTS || $rule === self::RULE_STRIP_PLUS) {
            $plus = strpos($local, '+');
            if ($plus !== false) {
                $local = substr($local, 0, $plus);
            }
        } else {
            $hyphen = strpos($local, '-');
            if ($hyphen !== false) {
                $local = substr($local, 0, $hyphen);
            }
        }
        if ($rule === self::RULE_STRIP_PLUS_AND_DOTS) {
            $local = str_replace('.', '', $local);
        }

        return $local . '@' . $domain;
    }
}
