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
 *     PRK        = `HKDF`-Extract(SHA-256, salt = deploy-salt, ikm = master).
 *     K_challenge = `HKDF`-Expand(PRK, "kiwi/v2/challenge-sign", 32).
 *     K_ip_bind   = `HKDF`-Expand(PRK, "kiwi/v2/ip-bind", 32).
 *     K_result    = `HKDF`-Expand(PRK, "kiwi/v2/result-token", 32).
 *
 * Tenant-scoped deployments additionally derive a per-tenant root and
 * the three purpose keys under it:
 *
 *     tenant_root = `HKDF`-Expand(PRK, "kiwi/v2/tenant/" + tenant_id, 32).
 *     PRK_t       = `HKDF`-Extract(SHA-256, salt = "", ikm = tenant_root).
 *     K_x_tenant  = `HKDF`-Expand(PRK_t, "kiwi/v2/" + purpose, 32).
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

    /**
     * Cap of the per-process derivation memo below. A deployment holds a
     * handful of immutable master secrets: the configured signing kids,
     * since the documented FPM model constructs the Issuer and Verifier
     * once per process. The memo is tiny in practice. A pathological
     * caller deriving for many distinct secrets, e.g. a long-lived CLI
     * walking tenant keys, resets it instead of growing unboundedly,
     * degrading gracefully to a fresh derivation per call.
     */
    private const CACHE_LIMIT = 64;

    /**
     * Per-process memo of derived key sets, keyed by a collision-free
     * composite of the tenant id and the master secret. The key is a
     * deliberately unambiguous binary encoding: a presence-tag byte
     * (`\x00` = no tenant, `\x01` = tenant present), the tenant id's
     * 32-bit big-endian byte length, then the tenant id bytes. The
     * master secret's 32-bit big-endian byte length and bytes follow.
     * The composite is hashed with SHA-256 to the PHP array key. The
     * length prefixes and the presence tag make the encoding
     * structurally unambiguous: `(null, M)` and `("", M)` differ in the
     * presence tag (a null tenant derives the global root, an
     * empty-string tenant the "kiwi/v2/tenant/" root). The inputs
     * `("a", "b\0c")` and `("a\0b", "c")` differ in the length
     * boundaries. No two distinct `(tenant, master)` inputs can ever
     * collide on one memo entry. The master secret is immutable for a
     * deployment's lifetime, so a memoized entry can never go stale
     * within a process. The derivation is three `HKDF` steps that the
     * issuance and verification statics,
     * {@see \KiwiCaptcha\Issuer::signPayloadV2()} and
     * {@see \KiwiCaptcha\Issuer::bindingTag()}, otherwise repeat for
     * every single operation. The memoized values are exactly as
     * sensitive as the master secrets their callers already hold in
     * memory, so the cache adds no new exposure class.
     *
     * @var array<string, self>
     */
    private static array $cache = [];

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
     * Redacted dump shape: the three purpose keys are derived key
     * material (the effective challenge-signing, IP-binding and
     * result-token keys), so every field prints under its property name
     * with the value replaced by '<redacted>'.
     *
     * @return array<string, string>
     */
    public function __debugInfo(): array
    {
        return [
            'challengeKey' => '<redacted>',
            'ipBindKey' => '<redacted>',
            'resultKey' => '<redacted>',
        ];
    }

    /**
     * Derive the three purpose keys from the master secret. Memoized per
     * master secret (and tenant id) for the process lifetime: the
     * secrets are immutable deployment configuration, so the three `HKDF`
     * steps run once per distinct secret instead of per operation.
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
        // The structurally unambiguous encoding (see the $cache docblock):
        // the presence tag distinguishes a null tenant from an empty-string
        // tenant (different derivations — global root vs the
        // "kiwi/v2/tenant/" root), and the 32-bit length prefixes make
        // `("a", "b\0c")` and `("a\0b", "c")` distinct. The composite is
        // hashed so the PHP array key is a fixed-size string.
        $cacheKey = hash('sha256', (
            ($tenantId !== null ? "\x01" : "\x00")
            .pack('N', \strlen((string) $tenantId))
            .(string) $tenantId
            .pack('N', \strlen($master))
            .$master
        ));
        if (isset(self::$cache[$cacheKey])) {
            return self::$cache[$cacheKey];
        }

        $salt = self::HKDF_DEPLOY_SALT;
        if ($tenantId !== null) {
            // The tenant root acts as new key material: re-extract with an
            // empty salt (PHP hash_hkdf salt: '') so the three purpose
            // keys are independent of both the master PRK and each other.
            $master = self::hkdf($master, self::INFO_TENANT_ROOT_PREFIX.$tenantId, $salt);
            $salt = '';
        }

        if (\count(self::$cache) >= self::CACHE_LIMIT) {
            self::$cache = [];
        }

        return self::$cache[$cacheKey] = new self(
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
