<?php

declare(strict_types=1);

namespace KiwiCaptcha;

/**
 * Issues KiwiCaptcha challenges — byte-for-byte compatible with the Rust
 * crate's `issue_challenge`.
 *
 * Protocol (identical to the Rust implementation):
 *   nonce    = base64(32 random bytes)
 *   salt     = base64(16 random bytes)
 *   ip_hash  = sha256_hex(secret_key || client_ip)
 *   payload  = "{nonce}|{scope}|{ip_hash}|{issued_at}"
 *   signature= hex(hmac_sha256(secret_key, payload))
 *   challenge= base64(payload) . "." . signature
 *   prefix   = "{challenge}|{salt}|"
 *   target   = effective difficulty for the configured algorithm
 *   min_duration_ms = configured override or derived from difficulty
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
     * @throws \InvalidArgumentException when the scope contains '|'
     */
    public function issue(string $scope, string $clientIp): Challenge
    {
        if (\str_contains($scope, '|')) {
            throw new \InvalidArgumentException('scope must not contain "|"');
        }
        $now = $this->nowUnix();

        $nonce = base64_encode(random_bytes(32));
        $salt = base64_encode(random_bytes(16));

        $ipHash = self::hashIp($clientIp, $this->config->secretKey);
        $algorithm = $this->config->algorithm;
        $targetBits = $this->effectiveTargetBits();

        $payload = sprintf('%s|%s|%s|%d', $nonce, $scope, $ipHash, $now);
        $signature = self::signPayload($payload, $this->config->secretKey);

        $challenge = base64_encode($payload).'.'.$signature;
        $prefix = $challenge.'|'.$salt.'|';

        $expiresAt = $now + $this->config->ttlSecs;
        $minDurationMs = $this->config->minDurationMs
            ?? $this->deriveMinDurationMs($targetBits);

        $record = new ChallengeRecord(
            nonce: $nonce,
            scope: $scope,
            ipHash: $ipHash,
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
            // hrtime(true) is ALREADY nanoseconds (unlike the Rust equivalent
            // as_nanos() it needs no scaling) — multiplying by 1e9 would
            // overflow int64 within seconds of uptime.
            issuedAtNs: (int) hrtime(true),
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
     * SHA-256 of (salt || ip) as lowercase hex — identical to Rust's hash_ip.
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
        return match ($this->config->algorithm) {
            PoWAlgorithm::Sha256 => $this->config->targetBits,
            PoWAlgorithm::Argon2id => min($this->config->argon2TargetBits, 10),
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
