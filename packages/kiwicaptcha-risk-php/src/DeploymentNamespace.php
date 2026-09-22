<?php

declare(strict_types=1);

namespace KiwiCaptcha\Risk;

/**
 * The one derivation of a Redis-safe deployment namespace from its raw
 * configured bytes. Every risk key family in both languages shares it:
 * this package and the Rust crate `kiwicaptcha-risk`, whose `namespace`
 * module implements the identical byte-level algorithm. The shared
 * golden vectors in protocol/risk-v1/fixtures.json pin the two
 * implementations together.
 *
 * A namespace is an identity discriminator, never a display string.
 * Two derivations are defined, selected by an explicit version:
 *
 *  - Version 1, the legacy shape: replacement-sanitization of every
 *    byte outside `[A-Za-z0-9_.-]` to `_`. This is the historical key
 *    shape, so an existing deployment that upgrades the packages keeps
 *    its state. Distinct raw values can fold onto one sanitized value
 *    (`tenant/a` and `tenant:a` both become `tenant_a`), so a new
 *    deployment should not choose it.
 *  - Version 2, the digest shape: `n_` plus the first 128 bits (32 hex
 *    chars) of SHA-256 over the complete original bytes. Injective for
 *    every practical input, hex only (safe inside hash tags and every
 *    key grammar), and stable across processes.
 *
 * The version is never inferred from the string: a raw namespace is
 * always derived here, and the resulting encoded value is what key
 * builders interpolate. Switching an existing deployment to version 2
 * changes its key space, so it is a migration the operator performs
 * deliberately. The bundle's `namespace_key_version` carries the
 * drained-migration acknowledgment, and the security-policy and chain
 * readers additionally dual-read the legacy namespace as a safety net.
 */
final class DeploymentNamespace
{
    /** The historical sanitized derivation: `[A-Za-z0-9_.-]` kept, every other byte `_`. */
    public const VERSION_LEGACY = 1;

    /** The digest derivation: `n_` plus the first 128 bits of SHA-256, hex. */
    public const VERSION_DIGEST = 2;

    /**
     * @param string $raw     the raw configured namespace (a project
     *                        directory, a tenant label, any non-empty
     *                        string)
     * @param int    $version the key-version contract
     *                        ({@see self::VERSION_LEGACY} or
     *                        {@see self::VERSION_DIGEST})
     *
     * @throws \InvalidArgumentException when the raw namespace is empty or
     *                                   the version is unknown
     */
    public static function derive(string $raw, int $version = self::VERSION_LEGACY): string
    {
        return match ($version) {
            self::VERSION_LEGACY => self::legacy($raw),
            self::VERSION_DIGEST => self::digest($raw),
            default => throw new \InvalidArgumentException(sprintf(
                'namespace key version must be %d (legacy) or %d (digest), got %d',
                self::VERSION_LEGACY,
                self::VERSION_DIGEST,
                $version,
            )),
        };
    }

    /**
     * The legacy sanitized namespace: every byte outside [A-Za-z0-9_.-]
     * becomes `_` (byte-wise, so a multi-byte character contributes one
     * `_` per byte, exactly like the historical `preg_replace` without
     * the `/u` modifier).
     *
     * @throws \InvalidArgumentException when the raw namespace is empty
     */
    public static function legacy(string $raw): string
    {
        self::requireNonEmpty($raw);

        return preg_replace('/[^A-Za-z0-9_.-]/', '_', $raw) ?? $raw;
    }

    /**
     * The digest namespace: `n_` plus the first 128 bits of the SHA-256
     * of the complete raw bytes, lowercase hex.
     *
     * @throws \InvalidArgumentException when the raw namespace is empty
     */
    public static function digest(string $raw): string
    {
        self::requireNonEmpty($raw);

        return 'n_'.substr(hash('sha256', $raw), 0, 32);
    }

    private static function requireNonEmpty(string $raw): void
    {
        if ($raw === '') {
            throw new \InvalidArgumentException('the deployment namespace cannot be empty: derive() needs the raw configured discriminator');
        }
    }
}
