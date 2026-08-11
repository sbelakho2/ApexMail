<?php

declare(strict_types=1);

namespace KiwiCaptcha;

/**
 * Server-side challenge state, persisted by the storage backend.
 *
 * Mirrors the Rust `ChallengeRecord` fields so a PHP service and a Rust
 * service can share the same Redis/DB keys if ever mixed (though the two
 * projects are designed to be fully decoupled).
 *
 * `issuedAtNs` is a server-side-only high-resolution issuance timestamp
 * (monotonic nanoseconds, NOT Unix time). It is never signed into the
 * challenge payload and never sent to the client — the verifier uses it to
 * measure elapsed solve time on the server instead of trusting the
 * client-reported duration.
 */
final class ChallengeRecord
{
    public function __construct(
        public readonly string $nonce,
        public readonly string $scope,
        public readonly string $ipHash,
        public readonly int $issuedAt,
        public readonly int $expiresAt,
        public readonly PoWAlgorithm $algorithm,
        public readonly int $mKib,
        public readonly int $t,
        public readonly int $p,
        public readonly int $targetBits,
        public readonly string $salt,
        public readonly string $prefix,
        public readonly string $challenge,
        public readonly int $minDurationMs,
        public readonly int $issuedAtNs = 0,
    ) {
    }

    /** @return array<string, mixed> */
    public function toArray(): array
    {
        return [
            'nonce' => $this->nonce,
            'scope' => $this->scope,
            'ip_hash' => $this->ipHash,
            'issued_at' => $this->issuedAt,
            'expires_at' => $this->expiresAt,
            'algorithm' => $this->algorithm->value,
            'm_kib' => $this->mKib,
            't' => $this->t,
            'p' => $this->p,
            'target_bits' => $this->targetBits,
            'salt' => $this->salt,
            'prefix' => $this->prefix,
            'challenge' => $this->challenge,
            'min_duration_ms' => $this->minDurationMs,
            'issued_at_ns' => $this->issuedAtNs,
        ];
    }

    /** @param array<string, mixed> $data */
    public static function fromArray(array $data): self
    {
        return new self(
            nonce: (string) $data['nonce'],
            scope: (string) $data['scope'],
            ipHash: (string) $data['ip_hash'],
            issuedAt: (int) $data['issued_at'],
            expiresAt: (int) $data['expires_at'],
            algorithm: PoWAlgorithm::from((string) $data['algorithm']),
            mKib: (int) ($data['m_kib'] ?? 0),
            t: (int) ($data['t'] ?? 1),
            p: (int) ($data['p'] ?? 1),
            targetBits: (int) $data['target_bits'],
            salt: (string) $data['salt'],
            prefix: (string) $data['prefix'],
            challenge: (string) $data['challenge'],
            minDurationMs: (int) ($data['min_duration_ms'] ?? 0),
            issuedAtNs: (int) ($data['issued_at_ns'] ?? 0),
        );
    }
}
