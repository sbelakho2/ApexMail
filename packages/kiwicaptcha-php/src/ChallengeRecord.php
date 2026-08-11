<?php

declare(strict_types=1);

namespace KiwiCaptcha;

/**
 * Server-side challenge state, persisted by the storage backend.
 *
 * Mirrors the Rust `ChallengeRecord` fields EXACTLY (serde key names and
 * types), so a PHP service and a Rust service can share the same Redis
 * records: the JSON keys match the Rust serde schema one-to-one
 * (`nonce`, `scope`, `binding_tag`, `issued_at`, `expires_at`, `algorithm`
 * `'sha256'|'argon2id'`, `m_kib`, `t`, `p`, `target_bits`, `salt`,
 * `prefix`, `challenge`, `min_duration_ms`, `issued_at_ns`,
 * `protocol_version`).
 *
 * Protocol v2 migration: v2 records carry `binding_tag` (a nonce-bound
 * HMAC, never a stable IP-derived identifier — see
 * {@see Issuer::bindingTag()}) and `protocol_version` (2). `toArray()`
 * ALSO emits the legacy `ip_hash` key with the same value for one release
 * so old Rust readers keep loading v2 records, and `fromArray()` accepts
 * either key. Legacy records carrying only `ip_hash` decode as
 * `protocol_version` 1.
 *
 * `attempts_used` is emitted by {@see self::toArray()} as 0 for schema
 * symmetry with the Rust record (which has `#[serde(default)]`, so a Rust
 * reader accepts an absent field). PHP's one-shot model never increments
 * it — {@see self::fromArray()} accepts and ignores any value so records
 * written by the Rust verifier still load.
 *
 * `issuedAtNs` is a server-side-only high-resolution issuance timestamp in
 * WALL-CLOCK epoch microseconds (microseconds since Unix epoch, not
 * monotonic nanoseconds: hrtime() is per-host and cannot be persisted to
 * shared storage). The unit is IDENTICAL in the Rust crate (also being
 * moved to epoch microseconds in parallel), so records are interoperable.
 * The field name and JSON key stay `issuedAtNs` for serialization
 * stability; 0 remains the legacy "unknown" marker. It is never signed
 * into the challenge payload and never sent to the client — the verifier
 * uses it to measure elapsed solve time on the server instead of trusting
 * the client-reported duration.
 */
final class ChallengeRecord
{
    public function __construct(
        public readonly string $nonce,
        public readonly string $scope,
        public readonly string $bindingTag,
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
        public readonly int $protocolVersion = 2,
    ) {
    }

    /**
     * Compatibility accessor for callers of the pre-v2 `ipHash` property:
     * the field now stores the nonce-bound binding tag
     * ({@see Issuer::bindingTag()}). For v1 records this is exactly the
     * legacy `hash(sha256, secret || ip)` value, so the accessor returns
     * the same bytes callers of v1 records expect.
     */
    public function ipHash(): string
    {
        return $this->bindingTag;
    }

    /** @return array<string, mixed> */
    public function toArray(): array
    {
        return [
            'nonce' => $this->nonce,
            'scope' => $this->scope,
            // Protocol v2 primary key ONLY. The legacy `ip_hash` key must not
            // be emitted alongside it: the Rust reader uses serde
            // #[serde(alias = "ip_hash")], and serde rejects a struct that
            // carries BOTH the field and its alias ("duplicate field") — a
            // dual-key record would be unreadable by Rust. Readers still
            // ACCEPT legacy ip_hash-only records (migration window); writers
            // emit the v2 key only.
            'binding_tag' => $this->bindingTag,
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
            'protocol_version' => $this->protocolVersion,
            // Language-neutral symmetry with the Rust record: Rust has
            // #[serde(default)] for attempts_used, so PHP emits the field
            // explicitly to keep PHP→Rust records complete. The one-shot
            // model never increments it.
            'attempts_used' => 0,
        ];
    }

    /**
     * Rebuild a record from persisted (JSON-decoded) data.
     *
     * Unknown and absent keys are ignored gracefully — including
     * `attempts_used`, which the Rust verifier writes and PHP's one-shot
     * model does not use (accepted optionally, default 0). The binding
     * field is read from `binding_tag` (v2) or the legacy `ip_hash` (v1);
     * the protocol version defaults to 2 for records carrying
     * `binding_tag` and to 1 for legacy records carrying `ip_hash` only.
     *
     * @param array<string, mixed> $data
     */
    public static function fromArray(array $data): self
    {
        $protocolVersion = \array_key_exists('binding_tag', $data)
            ? (int) ($data['protocol_version'] ?? 2)
            : 1;

        // All reads are null-safe: corrupt/foreign stored data must never
        // raise warnings or exceptions here — unknown algorithm VALUES still
        // throw from PoWAlgorithm::from() (the storages catch that and treat
        // the record as absent), and structurally incomplete data degrades
        // into a record that the verifier's validateRecord() rejects.
        return new self(
            nonce: (string) ($data['nonce'] ?? ''),
            scope: (string) ($data['scope'] ?? ''),
            bindingTag: (string) ($data['binding_tag'] ?? $data['ip_hash'] ?? ''),
            issuedAt: (int) ($data['issued_at'] ?? 0),
            expiresAt: (int) ($data['expires_at'] ?? 0),
            algorithm: PoWAlgorithm::from((string) ($data['algorithm'] ?? '')),
            mKib: (int) ($data['m_kib'] ?? 0),
            t: (int) ($data['t'] ?? 1),
            p: (int) ($data['p'] ?? 1),
            targetBits: (int) ($data['target_bits'] ?? 0),
            salt: (string) ($data['salt'] ?? ''),
            prefix: (string) ($data['prefix'] ?? ''),
            challenge: (string) ($data['challenge'] ?? ''),
            minDurationMs: (int) ($data['min_duration_ms'] ?? 0),
            issuedAtNs: (int) ($data['issued_at_ns'] ?? 0),
            protocolVersion: $protocolVersion,
        );
    }
}
