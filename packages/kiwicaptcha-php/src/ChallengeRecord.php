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
 * `protocol_version`, `attempts_used`, `region`, `policy_version`,
 * `request_binding`, `issuer`, `kid` — 22 keys).
 *
 * Protocol v2 migration: v2 records carry `binding_tag` (a nonce-bound
 * HMAC, never a stable IP-derived identifier — see
 * {@see Issuer::bindingTag()}) and `protocol_version` (2). `toArray()`
 * emits the v2 key set only, and `fromArray()` accepts either `binding_tag`
 * or the legacy `ip_hash` key (serde `#[serde(alias = "ip_hash")]` — the
 * two must never appear together, exactly like serde's duplicate-field
 * rejection). Legacy records carrying only `ip_hash` decode as
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
 *
 * `region` is server-side deployment metadata (like `issuedAtNs` — never
 * signed into the challenge, though it IS part of the v2 canonical payload
 * since round 9; see {@see Issuer::canonicalPayload()}): the region the
 * challenge was issued for, or null when unbound. The JSON key is ALWAYS
 * present (null when unbound) for byte parity with the Rust serde schema
 * (21 keys), which the Rust reader requires via `#[serde(default)]` for
 * legacy records. A verifier configured with an expected region rejects
 * records whose region does not match exactly
 * ({@see \KiwiCaptcha\VerifyError::WrongRegion}).
 *
 * `issuer` (audit #67) is the deployment identity the challenge was issued
 * under (e.g. "dev", "staging", "prod") — a dev/staging/production
 * compartment that works even when deployments share secret keys. Like
 * `region` it is ALWAYS present in `toArray()` (null when unset) and is
 * part of the signed v2 canonical payload (final segment, appended AFTER
 * `request_binding` — see {@see Issuer::canonicalPayload()}). A verifier
 * configured with an expected issuer rejects records whose issuer does not
 * match exactly ({@see \KiwiCaptcha\VerifyError::WrongIssuer}).
 *
 * `policyVersion` (audit #42) is the security-policy epoch that authorized
 * this challenge — the Rust field is `policy_version: u32` with default 1,
 * never null on the wire. `requestBinding` (audit #41) is the
 * application-supplied transaction binding nonce the host must present
 * again on the final protected POST (Rust: `request_binding:
 * Option<String>`, null when unset). Both keys are ALWAYS present in
 * `toArray()`; `policy_version` serializes as 1 when the ctor value is null
 * (a null would be unreadable by the Rust u32 reader).
 *
 * `kid` (audit #91) is the signing key id the challenge was issued under
 * (Rust: `kid: u32` with serde default 1 — missing defaults to 1, so
 * pre-kid records keep their 659-corpus acceptance). Like `policy_version`
 * it is NEVER null on the wire: `toArray()` emits 1 when the ctor value is
 * null (a null would be unreadable by the Rust u32 reader). It is signed
 * as the FINAL v2 canonical field (appended AFTER `issuer` — see
 * {@see Issuer::canonicalPayload()}), and a verifier configured with a
 * kid-keyed secret set selects the signature secret per kid — rejecting
 * unknown kids and any record whose kid exceeds the newest configured kid
 * ({@see \KiwiCaptcha\VerifyError::UnknownKid}, the rollback/forward
 * guard).
 *
 * `fromArray()` is the strict serde-mirror parser (audit #56): it accepts
 * EXACTLY what the Rust `serde_json::from_str::<ChallengeRecord>` accepts —
 * whitelisted keys only, exact lowercase algorithm values, strict integer
 * types and ranges, strings capped at 4096 bytes, nulls only where
 * `Option` allows them. Anything else throws
 * {@see \KiwiCaptcha\MalformedRecordException}. NOTE: base64 is NOT
 * validated here — serde treats `nonce`/`salt` as plain strings at parse
 * time, and the differential fuzz corpus (1000 deterministic mutations)
 * pins both parsers to the same 659-accepted split.
 */
final class ChallengeRecord
{
    /**
     * The 22-key wire schema, mirroring the Rust serde struct fields
     * (deny_unknown_fields). `ip_hash` is the legacy v1 alias for
     * `binding_tag` (serde `#[serde(alias = "ip_hash")]`). `issuer`
     * (audit #67) is the deployment identity — always present, null when
     * unset. `kid` (audit #91) is the signing key id — always present,
     * default 1.
     */
    public const WIRE_KEYS = [
        'nonce', 'scope', 'binding_tag', 'issued_at', 'expires_at',
        'algorithm', 'm_kib', 't', 'p', 'target_bits', 'salt', 'prefix',
        'challenge', 'min_duration_ms', 'issued_at_ns', 'protocol_version',
        'attempts_used', 'region', 'policy_version', 'request_binding',
        'issuer', 'kid', 'hostname',
    ];

    /**
     * Fields serde requires (no `#[serde(default)]`).
     */
    private const REQUIRED_KEYS = [
        'nonce', 'scope', 'binding_tag', 'issued_at', 'expires_at',
        'algorithm', 'm_kib', 't', 'p', 'target_bits', 'salt', 'prefix',
        'challenge', 'min_duration_ms',
    ];

    /** Maximum byte length of any wire string (audit #56 ceiling). */
    public const MAX_STRING_BYTES = 4096;

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
        public readonly ?string $region = null,
        public readonly ?int $policyVersion = 1,
        public readonly ?string $requestBinding = null,
        public readonly ?string $issuer = null,
        public readonly ?int $kid = 1,
        // Server-side issuance metadata (round 24): the Host the challenge
        // was issued for (Siteverify `hostname`); never signed, never sent.
        public readonly ?string $hostname = null,
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
            // Deployment metadata — ALWAYS present (null when the challenge
            // is region-unbound) for byte parity with the Rust serde schema.
            'region' => $this->region,
            // Security-policy epoch (audit #42). The Rust field is u32 and
            // never serializes null — a null ctor value degrades to the
            // default epoch so PHP-written records stay readable by Rust.
            'policy_version' => $this->policyVersion ?? 1,
            // Application transaction binding (audit #41) — null when unset.
            'request_binding' => $this->requestBinding,
            // Deployment identity (audit #67) — ALWAYS present (null when
            // unset) for byte parity with the Rust serde schema.
            'issuer' => $this->issuer,
            // Signing key id (audit #91) — ALWAYS present. The Rust field is
            // u32 and never serializes null — a null ctor value degrades to
            // the default key id 1 so PHP-written records stay readable by
            // Rust (mirror of policy_version).
            'kid' => $this->kid ?? 1,
            // Server-side issuance metadata (round 24) — ALWAYS present
            // (null when unset) for byte parity with the Rust serde schema.
            'hostname' => $this->hostname,
        ];
    }

    /**
     * Rebuild a record from persisted (JSON-decoded) data — the strict
     * serde-mirror parser (audit #56).
     *
     * Accepts exactly what the Rust `ChallengeRecord` serde schema accepts:
     * - only the 22 whitelisted keys (plus the legacy `ip_hash` alias, which
     *   must not appear alongside `binding_tag`); unknown keys — including
     *   trailing garbage — throw {@see MalformedRecordException};
     * - required fields must be present; optional fields default
     *   (`issued_at_ns` 0, `attempts_used` 0, `protocol_version` 1,
     *   `region` null, `policy_version` 1, `request_binding` null,
     *   `issuer` null, `kid` 1);
     * - integers must be real JSON integers within the Rust type ranges
     *   (u8 for protocol_version, u32 for m_kib/t/p/target_bits/
     *   attempts_used/policy_version/kid, u64 for the timestamps) —
     *   negatives, floats, booleans, numeric strings, and overflow are
     *   rejected;
     * - strings must be JSON strings of at most 4096 bytes;
     * - `algorithm` must be exactly `sha256` or `argon2id` (no aliases);
     * - null is only legal for `region`, `request_binding` and `issuer`
     *   (Option fields);
     * - the deployment-bound identifiers `region`, `request_binding` and
     *   `issuer` must match the narrow identifier alphabet
     *   `[A-Za-z0-9._:-]+` (audit #96) with their length caps (64 / 128 /
     *   128 bytes) — Unicode, whitespace, invisible characters, empty
     *   strings and canonical separators are rejected. `scope` is
     *   deliberately NOT validated here: serde treats it as an opaque
     *   string, and the differential fuzz corpus pins both parsers to the
     *   same acceptance split — the verifier's validateRecord enforces the
     *   scope alphabet at verification time.
     *
     * base64 is deliberately NOT validated for `nonce`/`salt`: serde treats
     * them as plain strings at parse time, and the differential fuzz corpus
     * pins both parsers to the same acceptance split.
     *
     * @param array<string, mixed> $data
     *
     * @throws MalformedRecordException on any structural violation
     */
    public static function fromArray(array $data): self
    {
        // serde deny_unknown_fields: every key must be a whitelisted string
        // (the legacy `ip_hash` alias is remapped below, before validation).
        // A JSON array (integer keys) can never map to the record struct.
        foreach ($data as $key => $value) {
            if (!\is_string($key) || ($key !== 'ip_hash' && !\in_array($key, self::WIRE_KEYS, true))) {
                throw MalformedRecordException::unknownKey((string) $key);
            }
        }

        // Legacy v1 alias (serde #[serde(alias = "ip_hash")]): accepted in
        // place of binding_tag, never alongside it (serde rejects a struct
        // carrying both the field and its alias as a duplicate field).
        if (\array_key_exists('ip_hash', $data)) {
            if (\array_key_exists('binding_tag', $data)) {
                throw MalformedRecordException::duplicateAlias('binding_tag', 'ip_hash');
            }
            $data['binding_tag'] = $data['ip_hash'];
        }

        foreach (self::REQUIRED_KEYS as $field) {
            if (!\array_key_exists($field, $data)) {
                throw MalformedRecordException::missingField($field);
            }
        }

        foreach (['nonce', 'scope', 'binding_tag', 'salt', 'prefix', 'challenge'] as $field) {
            self::requireString($data[$field], $field);
        }

        foreach (['issued_at', 'expires_at', 'min_duration_ms'] as $field) {
            self::requireInt($data[$field], $field, 0, PHP_INT_MAX);
        }
        // Optional u64/u32/u8 fields: serde defaults when ABSENT, but a
        // present JSON null is still a type error — distinguish the two.
        self::requireInt(
            \array_key_exists('issued_at_ns', $data) ? $data['issued_at_ns'] : 0,
            'issued_at_ns',
            0,
            PHP_INT_MAX,
        );
        // m_kib/t/p/target_bits/attempts_used/policy_version/kid: u32.
        foreach (['m_kib', 't', 'p', 'target_bits', 'attempts_used'] as $field) {
            self::requireInt(
                \array_key_exists($field, $data) ? $data[$field] : 0,
                $field,
                0,
                4_294_967_295,
            );
        }
        foreach (['policy_version', 'kid'] as $field) {
            self::requireInt(
                \array_key_exists($field, $data) ? $data[$field] : 1,
                $field,
                0,
                4_294_967_295,
            );
        }
        // protocol_version: u8 (default 1 — serde's default_protocol_version).
        self::requireInt(
            \array_key_exists('protocol_version', $data) ? $data['protocol_version'] : 1,
            'protocol_version',
            0,
            255,
        );

        $algorithm = $data['algorithm'];
        if ($algorithm !== 'sha256' && $algorithm !== 'argon2id') {
            throw MalformedRecordException::invalidAlgorithm($algorithm);
        }

        // Option fields: null or string (region, request_binding, issuer).
        // The deployment-bound identifiers must also match the narrow
        // alphabet (audit #96) with their length caps: region <= 64,
        // request_binding <= 128, issuer <= 128. NOTE: scope is exempt —
        // serde treats it as an opaque string and the fuzz corpus pins both
        // parsers to the same 659-accepted split (the verifier's
        // validateRecord enforces the scope alphabet instead).
        foreach (['region', 'request_binding', 'issuer'] as $field) {
            if (isset($data[$field]) && $data[$field] !== null) {
                self::requireString($data[$field], $field);
                if (!Config::isValidIdentifier($data[$field], $field === 'region' ? 64 : 128)) {
                    throw MalformedRecordException::invalidIdentifier($field);
                }
            }
        }

        return new self(
            nonce: $data['nonce'],
            scope: $data['scope'],
            bindingTag: $data['binding_tag'],
            issuedAt: $data['issued_at'],
            expiresAt: $data['expires_at'],
            algorithm: PoWAlgorithm::from($algorithm),
            mKib: $data['m_kib'],
            t: $data['t'],
            p: $data['p'],
            targetBits: $data['target_bits'],
            salt: $data['salt'],
            prefix: $data['prefix'],
            challenge: $data['challenge'],
            minDurationMs: $data['min_duration_ms'],
            issuedAtNs: $data['issued_at_ns'] ?? 0,
            protocolVersion: $data['protocol_version'] ?? 1,
            region: $data['region'] ?? null,
            policyVersion: $data['policy_version'] ?? 1,
            requestBinding: $data['request_binding'] ?? null,
            issuer: $data['issuer'] ?? null,
            kid: $data['kid'] ?? 1,
        );
    }

    private static function requireString(mixed $value, string $field): void
    {
        if (!\is_string($value)) {
            throw MalformedRecordException::wrongType($field, 'a string', $value);
        }
        if (\strlen($value) > self::MAX_STRING_BYTES) {
            throw MalformedRecordException::oversized($field, \strlen($value));
        }
    }

    private static function requireInt(mixed $value, string $field, int $min, int $max): void
    {
        if (!\is_int($value)) {
            throw MalformedRecordException::wrongType($field, "an integer within $min..$max", $value);
        }
        if ($value < $min || $value > $max) {
            throw MalformedRecordException::outOfRange($field, $min, $max, $value);
        }
    }
}
