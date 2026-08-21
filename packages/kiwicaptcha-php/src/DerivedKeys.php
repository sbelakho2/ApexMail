<?php

declare(strict_types=1);

namespace KiwiCaptcha;

/**
 * Purpose-key separation.
 *
 * Every cryptographic purpose derives its own 32-byte key from the single
 * master secret, so a key compromise in one purpose (challenge signing,
 * IP binding, result tokens) does not leak the others:
 *
 *     PRK        = HKDF-Extract(SHA-256, salt = deploy-salt, ikm = master).
 *     K_challenge = HKDF-Expand(PRK, "kiwi/v2/challenge-sign", 32).
 *     K_ip_bind   = HKDF-Expand(PRK, "kiwi/v2/ip-bind", 32).
 *     K_result    = HKDF-Expand(PRK, "kiwi/v2/result-token", 32).
 *
 * Tenant-scoped deployments additionally derive a per-tenant root and
 * the three purpose keys under it:
 *
 *     tenant_root = HKDF-Expand(PRK, "kiwi/v2/tenant/" + tenant_id, 32).
 *     PRK_t       = HKDF-Extract(SHA-256, salt = "", ikm = tenant_root).
 *     K_x_tenant  = HKDF-Expand(PRK_t, "kiwi/v2/" + purpose, 32).
 *
 * Cross-language parity, byte-for-byte with the Rust crate: the
 * construction above is exactly PHP's `hash_hkdf('sha256', $ikm, 32,
 * $info, $salt)`.
 * - The global keys: `hash_hkdf('sha256', $master, 32,
 *   'kiwi/v2/challenge-sign', 'kiwicaptcha/deploy-salt/v1')`, and the
 *   `ip-bind` / `result-token` infos.
 * - The tenant root: `hash_hkdf('sha256', $master, 32,
 *   'kiwi/v2/tenant/' . $tenant, 'kiwicaptcha/deploy-salt/v1')`.
 * - The tenant purpose keys: `hash_hkdf('sha256', $tenantRoot, 32,
 *   'kiwi/v2/' . $purpose, '')`.
 *
 * The Rust crate's `keys.rs` locks the same construction with reference
 * vectors; the interop tests derive from this class and verify against
 * them, so any deviation breaks cross-language verify/issue.
 *
 * The Issuer and Verifier derive their keys internally from the master
 * secret via {@see self::fromMaster()}, so existing constructor
 * signatures (secret string) keep working unchanged.
 */
final class DerivedKeys
{
    /**
     * The public (non-secret) deployment salt for the extraction step;
     * domain separation shared with the Rust core. The secrecy comes from
     * the master secret, not from this string.
     */
    public const HKDF_DEPLOY_SALT = 'kiwicaptcha/deploy-salt/v1';

    /** Info label for the challenge-signing purpose key. */
    public const INFO_CHALLENGE_SIGN = 'kiwi/v2/challenge-sign';

    /** Info label for the IP-binding purpose key. */
    public const INFO_IP_BIND = 'kiwi/v2/ip-bind';

    /** Info label for the result/solution-token purpose key. */
    public const INFO_RESULT_TOKEN = 'kiwi/v2/result-token';

    /** Prefix of the tenant-root info label: "kiwi/v2/tenant/" + tenant id. */
    public const INFO_TENANT_ROOT_PREFIX = 'kiwi/v2/tenant/';

    private function __construct(
        private readonly string $challengeKey,
        private readonly string $ipBindKey,
        private readonly string $resultKey,
    ) {
    }

    /**
     * Derive the three purpose keys from the master secret.
     *
     * @param string      $master   the deployment master secret (the HMAC
     *                              secret key)
     * @param string|null $tenantId optional tenant id. When given, the
     *                              purpose keys are derived under the
     *                              per-tenant root ("kiwi/v2/tenant/" +
     *                              tenant id), so tenants of a shared master
     *                              secret cannot forge each other's
     *                              challenges, binding tags, or result
     *                              tokens.
     */
    public static function fromMaster(string $master, ?string $tenantId = null): self
    {
        $salt = self::HKDF_DEPLOY_SALT;
        if ($tenantId !== null) {
            // The tenant root acts as new key material: re-extract with an
            // empty salt (PHP hash_hkdf salt: '') so the three purpose
            // keys are independent of both the master PRK and each other.
            $master = self::hkdf($master, self::INFO_TENANT_ROOT_PREFIX.$tenantId, $salt);
            $salt = '';
        }

        return new self(
            self::hkdf($master, self::INFO_CHALLENGE_SIGN, $salt),
            self::hkdf($master, self::INFO_IP_BIND, $salt),
            self::hkdf($master, self::INFO_RESULT_TOKEN, $salt),
        );
    }

    /** The challenge-signing key (K_challenge): HMAC over the canonical payload. */
    public function challengeKey(): string
    {
        return $this->challengeKey;
    }

    /** The IP-binding key (K_ip_bind): HMAC over the nonce + canonical IP bytes. */
    public function ipBindKey(): string
    {
        return $this->ipBindKey;
    }

    /** The result/solution-token key (K_result): MAC for result tokens. */
    public function resultKey(): string
    {
        return $this->resultKey;
    }

    /**
     * One extract-then-expand step: a 32-byte output key for the given
     * info and salt (RFC 5869).
     *
     * PHP < 8.4 returned lowercase hex from hash_hkdf() unless the
     * (removed) $binary flag was set; PHP 8.4+ always returns raw bytes.
     * Normalize to raw 32 bytes so the derived keys are identical on
     * every supported PHP.
     */
    private static function hkdf(string $ikm, string $info, string $salt): string
    {
        $key = hash_hkdf('sha256', $ikm, 32, $info, $salt);

        return \strlen($key) === 64 ? (string) hex2bin($key) : $key;
    }
}
