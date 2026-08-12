<?php

declare(strict_types=1);

namespace KiwiCaptcha;

/**
 * Issues KiwiCaptcha challenges — byte-for-byte compatible with the Rust
 * crate's `issue_challenge`.
 *
 * Protocol v2 (default issuance, `protocol_version` 2):
 *   nonce      = base64(32 random bytes)
 *   salt       = base64(16 random bytes)
 *   binding_tag = HMAC-SHA256 over the canonical IP (see
 *                {@see self::bindingTag()}) — nonce-bound, so the stored
 *                binding is never a stable IP-derived identifier
 *   canonical  = "v2|{nonce}|{scope}|{binding_tag}|{issued_at}|{expires_at}|
 *                {algorithm}|{m_kib}|{t}|{p}|{target_bits}|{salt}|
 *                {min_duration_ms}"
 *   signature  = hex(hmac_sha256(secret_key, canonical))
 *   challenge  = base64(canonical) . "." . signature
 *   prefix     = "{challenge}|{salt}|"
 *   target     = effective difficulty for the configured algorithm
 *   min_duration_ms = configured override or derived from difficulty
 *
 * Legacy v1 issuance (`protocol_version` 1, payload
 * `"{nonce}|{scope}|{ip_hash}|{issued_at}"`) is not produced anymore, but
 * the v1 helpers remain: {@see self::hashIp()} computes the legacy IP hash
 * so v1 records (and the verifier's v1 path) keep working during the
 * migration window.
 *
 * The stored record additionally carries `issued_at_ns` (server-side
 * high-resolution issuance time) — never signed, never sent to the client.
 */
final class Issuer
{
    public function __construct(
        private readonly Config $config,
        private readonly StorageInterface $storage,
        /** @var callable(): int|null clock override (tests) */
        private $now = null,
    ) {
    }

    public function config(): Config
    {
        return $this->config;
    }

    /**
     * @throws \InvalidArgumentException when the scope is empty, longer than
     *                                   128 bytes, or contains '|'
     */
    public function issue(string $scope, string $clientIp): Challenge
    {
        $scopeLen = \strlen($scope);
        if ($scopeLen < 1 || $scopeLen > 128) {
            throw new \InvalidArgumentException('scope must be 1-128 bytes');
        }
        if (\str_contains($scope, '|')) {
            throw new \InvalidArgumentException('scope must not contain "|"');
        }
        $now = $this->nowUnix();

        $nonce = base64_encode(random_bytes(32));
        $salt = base64_encode(random_bytes(16));

        // Binding mode: 'none' issues challenges with an EMPTY binding tag
        // (maximum privacy — no client-derived identifier at all); the
        // verifier skips the binding check for empty tags.
        $bindingTag = $this->config->bindingMode === \KiwiCaptcha\BindingMode::None
            ? ''
            : self::bindingTag($nonce, $clientIp, $this->config->secretKey);
        $algorithm = $this->config->algorithm;
        $targetBits = $this->effectiveTargetBits();

        $expiresAt = $now + $this->config->ttlSecs;
        $minDurationMs = $this->config->minDurationMs
            ?? $this->deriveMinDurationMs($targetBits);

        $payload = self::canonicalPayload(
            $nonce,
            $scope,
            $bindingTag,
            $now,
            $expiresAt,
            $algorithm,
            $this->config->mKib,
            $this->config->t,
            $this->config->p,
            $targetBits,
            $salt,
            $minDurationMs,
        );
        $signature = self::signPayload($payload, $this->config->secretKey);

        $challenge = base64_encode($payload).'.'.$signature;
        $prefix = $challenge.'|'.$salt.'|';

        $record = new ChallengeRecord(
            nonce: $nonce,
            scope: $scope,
            bindingTag: $bindingTag,
            issuedAt: $now,
            expiresAt: $expiresAt,
            algorithm: $algorithm,
            mKib: $this->config->mKib,
            t: $this->config->t,
            p: $this->config->p,
            targetBits: $targetBits,
            salt: $salt,
            prefix: $prefix,
            challenge: $challenge,
            minDurationMs: $minDurationMs,
            // issuedAtNs = epoch MICROseconds since Unix epoch (wall clock,
            // hrtime(true) is monotonic and per-host so it must never be
            // persisted to shared storage — see README "server timing").
            // The name/JSON key stay issuedAtNs for ChallengeRecord
            // serialization stability.
            issuedAtNs: (int) (microtime(true) * 1_000_000),
            protocolVersion: 2,
        );
        $this->storage->store($record);

        return new Challenge(
            nonce: $nonce,
            challenge: $challenge,
            salt: $salt,
            algorithm: $algorithm,
            mKib: $this->config->mKib,
            t: $this->config->t,
            p: $this->config->p,
            targetBits: $targetBits,
            ttlSecs: $this->config->ttlSecs,
            minDurationMs: $minDurationMs,
            prefix: $prefix,
        );
    }

    /**
     * Issue a challenge from an adaptive-risk difficulty profile.
     *
     * Builds a Config clone from the profile (the issuer's own Config is
     * NEVER mutated): algorithm, m_kib, t, p, target_bits and
     * argon2_target_bits come from the profile (argon2_target_bits = the
     * profile's targetBits for Argon2id), while ttlSecs and minDurationMs
     * stay owned by the issuer Config. The profile is validated first
     * ({@see ChallengeProfile::validate()}); an invalid profile throws
     * \InvalidArgumentException before anything is issued.
     *
     * Delegates to the normal {@see self::issue()} path, so the wire format,
     * signing, and storage are IDENTICAL to a regular issue — only the
     * parameters differ.
     *
     * @throws \InvalidArgumentException when the profile is invalid (or the
     *                                   scope is invalid, per issue())
     */
    public function issueWithProfile(
        string $scope,
        string $clientIp,
        ChallengeProfile $profile,
        ?int $now = null,
    ): Challenge {
        $profile->validate();

        $config = new Config(
            secretKey: $this->config->secretKey,
            algorithm: $profile->algorithm,
            mKib: $profile->algorithm === PoWAlgorithm::Argon2id ? $profile->mKib : 0,
            // Profile t defaults to 0 (unused for SHA-256); Config requires
            // t >= 1 for every algorithm, so the clone normalizes it.
            t: $profile->t > 0 ? $profile->t : 1,
            p: $profile->p,
            targetBits: $profile->targetBits,
            argon2TargetBits: $profile->algorithm === PoWAlgorithm::Argon2id
                ? $profile->targetBits
                : $this->config->argon2TargetBits,
            ttlSecs: $this->config->ttlSecs,
            minDurationMs: $this->config->minDurationMs,
            solverMaxHashes: $this->config->solverMaxHashes,
            bindingMode: $this->config->bindingMode,
        );
        $nowFn = $now !== null ? static fn (): int => $now : $this->now;

        return (new self($config, $this->storage, $nowFn))->issue($scope, $clientIp);
    }

    /**
     * Protocol v2 nonce-bound IP binding tag.
     *
     * HMAC-SHA256 over the CANONICAL form of the client IP, keyed by the
     * secret and bound to the challenge nonce — so the stored binding is
     * unique per challenge and never a stable identifier that follows the
     * client across requests. IPv4-mapped IPv6 addresses
     * (`::ffff:a.b.c.d`) are normalized to their 4-byte IPv4 form so both
     * spellings of the same address produce the same tag.
     *
     * Message layout:
     *   "kiwicaptcha/ip-bind/v2\0" . nonce . "\0" . family . canonical_bytes
     * where family = "\x04" (IPv4) or "\x06" (IPv6) and canonical_bytes is
     * inet_pton() output (4 or 16 bytes).
     *
     * @throws \InvalidArgumentException when the IP is not a valid IPv4 or
     *                                   IPv6 address
     */
    public static function bindingTag(string $nonce, string $ip, string $secret): string
    {
        $family = self::canonicalIpFamily($ip);
        $message = "kiwicaptcha/ip-bind/v2\0".$nonce."\0".$family;

        return hash_hmac('sha256', $message, $secret);
    }

    /**
     * Canonical family byte + packed bytes for an IP: inet_pton() output
     * (4 or 16 bytes) with IPv4-mapped IPv6 (::ffff:a.b.c.d) normalized to
     * the 4-byte IPv4 form. Two textual spellings of the same address (e.g.
     * "2001:db8::1" and "2001:0db8:0:0:0:0:0:1") therefore produce the same
     * bytes — used by the challenge binding tag AND the rate-limiter
     * pseudonym so identity is exact.
     *
     * @throws \InvalidArgumentException when the IP is not a valid IPv4 or
     *                                   IPv6 address
     */
    public static function canonicalIpFamily(string $ip): string
    {
        $canonical = inet_pton($ip);
        if ($canonical === false) {
            throw new \InvalidArgumentException('Invalid IP address');
        }
        $len = \strlen($canonical);
        if ($len === 16 && str_starts_with($canonical, "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff")) {
            $canonical = substr($canonical, 12);
            $len = 4;
        }
        if ($len !== 4 && $len !== 16) {
            throw new \InvalidArgumentException('Invalid IP address');
        }

        return ($len === 4 ? "\x04" : "\x06").$canonical;
    }

    /**
     * Canonical protocol v2 payload — the exact byte string that is signed
     * and base64-encoded into the challenge. Shared with the verifier so
     * issuance and verification can never drift apart.
     */
    public static function canonicalPayload(
        string $nonce,
        string $scope,
        string $bindingTag,
        int $issuedAt,
        int $expiresAt,
        PoWAlgorithm $algorithm,
        int $mKib,
        int $t,
        int $p,
        int $targetBits,
        string $salt,
        int $minDurationMs,
    ): string {
        return sprintf(
            'v2|%s|%s|%s|%d|%d|%s|%d|%d|%d|%d|%s|%d',
            $nonce,
            $scope,
            $bindingTag,
            $issuedAt,
            $expiresAt,
            $algorithm->value,
            $mKib,
            $t,
            $p,
            $targetBits,
            $salt,
            $minDurationMs,
        );
    }

    /**
     * Legacy v1 IP hash: SHA-256 of (salt || ip) as lowercase hex —
     * identical to Rust's hash_ip. Kept for v1 records and the verifier's
     * v1 path during the migration window.
     */
    public static function hashIp(string $ip, string $salt): string
    {
        return hash('sha256', $salt.$ip);
    }

    /**
     * Hex HMAC-SHA256 of the canonical payload — identical to Rust's sign_payload.
     */
    public static function signPayload(string $canonicalPayload, string $secretKey): string
    {
        return hash_hmac('sha256', $canonicalPayload, $secretKey);
    }

    private function effectiveTargetBits(): int
    {
        // Defensive clamp: Config already rejects out-of-range values at
        // construction, but a hand-rolled ChallengeRecord (or a future config
        // path) must never reach the solver with an unsolvable difficulty.
        return match ($this->config->algorithm) {
            PoWAlgorithm::Sha256 => min($this->config->targetBits, Config::MAX_SHA_TARGET_BITS),
            PoWAlgorithm::Argon2id => min($this->config->argon2TargetBits, Config::MAX_ARGON2_TARGET_BITS),
        };
    }

    /**
     * Minimum plausible solve time, derived from algorithm + difficulty —
     * identical to Rust's ChallengeConfig::min_duration_ms_for.
     */
    private function deriveMinDurationMs(int $targetBits): int
    {
        $expected = 1 << min($targetBits, 31);
        if ($this->config->algorithm === PoWAlgorithm::Argon2id) {
            return max(50, (int) ceil($expected / 5e5 * 1000));
        }

        return max(5, (int) ceil($expected / 5e9 * 1000));
    }

    private function nowUnix(): int
    {
        return $this->now !== null ? (int) ($this->now)() : time();
    }
}
