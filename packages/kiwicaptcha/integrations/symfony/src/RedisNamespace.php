<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle;

use KiwiCaptcha\Risk\DeploymentNamespace;

/**
 * The one derivation of a Redis-safe deployment namespace from its raw
 * configured bytes, at every bundle key family.
 *
 * A namespace is an identity discriminator, never a display string.
 * Replacement-sanitizing it first (`preg_replace` to `_`) folds
 * distinct raw values onto one sanitized value. The pair `tenant/a`
 * and `tenant:a` both become `tenant_a`, and two project directories
 * that differ only in a separator-versus-underscore byte merge. Two
 * deployments sharing one Redis backend would then share every key
 * family built on the namespace. The digest derivation is therefore
 * offered: a digest of the complete original bytes, injective for
 * every practical input, hex only (safe inside hash tags and every key
 * grammar), and stable across processes. Never derive from a sanitized
 * value.
 *
 * The derivation is versioned and the version is explicit
 * (`kiwi_captcha.namespace_key_version`):
 *
 *  - Version 1, the sanitized shape. It is the default, so an existing
 *    deployment that upgrades the bundle keeps its key space: pins,
 *    policy state, chain state, risk aggregates and limiter windows
 *    all stay where they are instead of silently starting from an
 *    empty key space.
 *  - Version 2, the digest shape, for a deployment that performs the
 *    namespace migration deliberately. The switch changes every key
 *    family at once, so the bundle requires an explicit migration phase
 *    (`kiwi_captcha.namespace_migration`). While the transitional
 *    `migrating_v2` phase is in effect the security-policy, chain and
 *    authority-pin readers additionally consult the legacy namespace, so
 *    an emergency revocation, an open chain obligation or a
 *    pre-cutover pin can never be silently abandoned by the cutover.
 *    `drained` marks the migration complete: digest-only, no legacy
 *    reads, the isolation the digest derivation exists for.
 */
final class RedisNamespace
{
    /** The sanitized derivation (see {@see DeploymentNamespace::VERSION_LEGACY}). */
    public const VERSION_LEGACY = DeploymentNamespace::VERSION_LEGACY;

    /** The digest derivation (see {@see DeploymentNamespace::VERSION_DIGEST}). */
    public const VERSION_DIGEST = DeploymentNamespace::VERSION_DIGEST;

    /** The key version an existing deployment stays on until it migrates. */
    public const DEFAULT_VERSION = self::VERSION_LEGACY;

    /**
     * @param string $raw     the raw configured namespace (a project
     *                        directory, a tenant label, any non-empty
     *                        string)
     * @param int    $version the key-version contract
     *
     * @throws \InvalidArgumentException when the raw namespace is empty
     *                                   or the version is unknown
     */
    public static function derive(string $raw, int $version = self::DEFAULT_VERSION): string
    {
        return DeploymentNamespace::derive($raw, $version);
    }

    /**
     * The derived namespace of a possibly-empty raw value under a
     * named fallback: an operator who explicitly leaves the namespace
     * unset shares the fallback's deployment scope by choice, never by
     * folding.
     */
    public static function deriveOr(string $raw, string $fallback, int $version = self::DEFAULT_VERSION): string
    {
        return self::derive($raw !== '' ? $raw : $fallback, $version);
    }

    /**
     * The namespaces a reader must consult, primary first: the
     * configured derivation, plus the legacy derivation when the
     * deployment is on the digest version.
     *
     * The extra read is the migration safety net for state that can
     * revoke or block something, such as the central security policy or
     * an open chain obligation. A digest key that is absent while
     * legacy state exists is never read as "no state configured". On
     * the legacy version the list holds one namespace, and a fresh
     * install (namespace_migration: fresh) passes
     * `$readLegacyFallback = false`: a brand-new deployment has no
     * pre-cutover state and must never adopt an unrelated deployment's
     * colliding legacy keys.
     *
     * @return list<string>
     */
    public static function readNamespaces(string $raw, string $fallback, int $version, bool $readLegacyFallback = true): array
    {
        $primary = self::deriveOr($raw, $fallback, $version);
        if ($version === self::VERSION_DIGEST && $readLegacyFallback) {
            return [$primary, self::deriveOr($raw, $fallback, self::VERSION_LEGACY)];
        }

        return [$primary];
    }
}
