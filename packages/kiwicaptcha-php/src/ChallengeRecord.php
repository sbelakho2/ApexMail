<?php

declare(strict_types=1);

namespace KiwiCaptcha;

/**
 * Server-side challenge state, persisted by the storage backend.
 *
 * Mirrors the Rust `ChallengeRecord` fields exactly: serde key names
 * and types, so a PHP service and a Rust service can share the same
 * Redis records. The JSON keys match the Rust serde schema one-to-one.
 *
 * Protocol v2 records carry `binding_tag` (a nonce-bound HMAC, not a
 * stable IP-derived identifier) and `protocol_version` (2). `toArray()` emits the v2 key set only, and
 * `fromArray()` accepts either `binding_tag` or the legacy `ip_hash` key
 * (the serde alias attribute); the two must not appear
 * together, matching serde's duplicate-field rejection. Legacy records
 * carrying only `ip_hash` decode as `protocol_version` 1.
 *
 * Protocol v3 is the decoy-capable canonical: the v2 18-field base plus
 * the `|decoy_field` segment appended after `kid`. The decoy is
 * mandatory on v3, so an armed issuance writes protocol v3 with the
 * segment and an unarmed issuance stays protocol v2, byte-identical to
 * the pre-decoy format. The protocol-vs-decoy grammar is total and
 * enforced on both acceptance surfaces. A protocol-v2 record that
 * carries `decoy_field` is rejected explicitly, since the v2 canonical
 * never includes the segment. A protocol-v3 record without one is
 * rejected too: a signed v2 record with its stored version flipped to 3
 * can never verify, so the protocol capability is fully inferable from
 * the authenticated canonical shape. An old verifier rejects version 3
 * as unknown.
 *
 * Protocol v4 is the execution-capable canonical: the decoy-capable
 * canonical plus the `|execution_version|execution_commitment` segments
 * appended after the decoy (or after `kid` when no decoy is armed). The
 * execution segments are mandatory on v4 and are present iff the record
 * carries an execution program.
 * The signed commitment is therefore the exact mirror of the stored
 * program: commitment absent = program absent, commitment present =
 * program present, and SHA256(stored program) must equal the signed
 * commitment (constant time).
 * A v4 record without the commitment triplet, or a v2/v3 record
 * carrying any execution field, is rejected explicitly.
 * Stripping, substituting or injecting a program always invalidates
 * the challenge, because the canonical bytes are signed and the
 * tamper breaks the HMAC or the structural gate.
 * An old verifier rejects version 4 as unknown.
 * `fromArray()` accepts protocol versions 1, 2, 3 and 4 and rejects
 * every forbidden combination (v2-plus-decoy, decoyless-v3,
 * v2/v3-with-execution, executionless-v4 and any partial execution
 * field set); the verifier's malformed-record path enforces the same
 * split.
 *
 * `attempts_used` is emitted by {@see self::toArray()} as 0 for schema
 * symmetry with the Rust record, which has `#[serde(default)]` and
 * accepts an absent field. PHP's one-shot model never increments it;
 * {@see self::fromArray()} accepts and ignores any value so records
 * written by the Rust verifier still load.
 *
 * `issuedAtNs` is a server-side-only high-resolution issuance timestamp
 * in wall-clock epoch microseconds (microseconds since Unix epoch, not
 * monotonic nanoseconds: hrtime() is per-host and cannot be persisted to
 * shared storage). The unit is identical in the Rust crate, so records
 * are interoperable. The field name and JSON key stay `issuedAtNs` for
 * serialization stability; 0 marks an unknown issuance time. It is never
 * signed into the challenge payload and never sent to the client; the
 * verifier uses it to measure elapsed solve time on the server instead
 * of trusting the client-reported duration.
 *
 * `region` is server-side deployment metadata included in the v2
 * canonical payload, therefore authenticated by the challenge HMAC, see
 * {@see Issuer::canonicalPayload()}; it has no client authority. The
 * JSON key is always present (null when unbound) for byte parity with
 * the Rust serde schema, which reads the key via `#[serde(default)]` for
 * records written before the key existed. A verifier configured with an
 * expected region rejects records whose region does not match exactly,
 * see {@see \KiwiCaptcha\VerifyError::WrongRegion}.
 *
 * `issuer` is the deployment identity the challenge was issued under
 * (e.g. "dev", "staging", "prod"); a dev/staging/production compartment
 * that works even when deployments share secret keys. Like `region` it
 * is always present in `toArray()` (null when unset) and is part of the
 * signed v2 canonical payload, appended after `request_binding` with
 * `kid` following as the final field, see
 * {@see Issuer::canonicalPayload()}. A verifier configured with an
 * expected issuer rejects records whose issuer does not match exactly,
 * see {@see \KiwiCaptcha\VerifyError::WrongIssuer}.
 *
 * `policyVersion` is the security-policy epoch that authorized this
 * challenge; the Rust field is `policy_version: u32` with default 1,
 * never null on the wire. `requestBinding` is the application-supplied
 * transaction binding nonce the host must present again on the final
 * protected POST (Rust: `request_binding: Option<String>`, null when
 * unset). Both keys are always present in `toArray()`; `policy_version`
 * serializes as 1 when the ctor value is null, since a null would be
 * unreadable by the Rust u32 reader.
 *
 * `kid` is the signing key id the challenge was issued under (Rust:
 * `kid: u32` with serde default 1, so records written before key ids
 * existed still load). Like `policy_version` it is never null on the
 * wire: `toArray()` emits 1 when the ctor value is null. It is signed
 * as the final v2 canonical field, appended after `issuer`, see
 * {@see Issuer::canonicalPayload()}. A verifier configured with a
 * kid-keyed secret set selects the signature secret per kid. It rejects
 * unknown kids and any record whose kid exceeds the newest configured
 * kid, see {@see \KiwiCaptcha\VerifyError::UnknownKid} and the
 * rollback/forward guard.
 *
 * `hostname` is server-side issuance metadata (the Siteverify host the
 * challenge was issued for), always present in `toArray()` (null when
 * unset); it is never signed into the challenge and never sent to the
 * client.
 *
 * `decoyField` is the server-issued decoy (honeypot) form-field name
 * armed for this challenge, drawn from the combinatorial grammar (see
 * {@see Issuer::composeDecoyName()}). Null =
 * no decoy armed (the default, and the shape every pre-decoy record
 * carries). The name is an authenticated canonical field: the final
 * segment `|<decoy_field>`, appended after the `kid` (see
 * {@see Issuer::canonicalPayload()}), so a stored/tampered record cannot
 * change or drop it without breaking the signature. Wire compatibility:
 * unarmed records are byte-identical to the pre-decoy format. The JSON
 * key is absent when null (`skip_serializing_if`), so pre-decoy writers
 * and readers keep their exact byte format. A decoy-armed record is
 * protocol v3 (or v4 when the execution dimension is armed too) and
 * requires a v3-capable verifier: an old verifier rejects version 3 as
 * unknown, so the capability becomes inferable from protocol_version,
 * which is the point. Absent in legacy stored records; a present value
 * must match the decoy alphabet `[A-Za-z0-9_-]{1,64}`, see
 * {@see Config::isValidDecoyFieldName()}, and is enforced on read and
 * by the verifier's malformed-record path.
 *
 * `executionVersion` is the execution-dimension protocol version,
 * always 1 (the only canonical version; an old record without the field
 * is an unarmed record). It is an authenticated canonical field of
 * protocol v4: the `|execution_version` segment, see
 * {@see Issuer::canonicalPayload()}, so a stored/tampered record cannot
 * change or drop it without breaking the signature. The JSON key is
 * absent when null (`skip_serializing_if`).
 *
 * `executionCommitment` is the authenticated mirror of the stored
 * execution program: hex SHA-256 of the program's base64 wire string,
 * 64 lowercase hex characters. It is an authenticated canonical field
 * of protocol v4 (the final `|execution_commitment` segment), so a
 * stored/tampered record cannot strip, substitute or inject a program
 * without breaking the signature. The equivalence is exact and
 * enforced on every acceptance surface: signed commitment absent =
 * stored program absent, signed commitment present = stored program
 * present, and SHA256(stored program) == the signed commitment
 * (constant-time compare). The JSON key is absent when null
 * (`skip_serializing_if`).
 *
 * `fromArray()` is the strict serde-mirror parser: it accepts exactly
 * what the Rust `serde_json::from_str::<ChallengeRecord>` accepts.
 * Whitelisted keys only, exact lowercase algorithm values, strict
 * integer types and ranges, strings capped at 4096 bytes, and nulls
 * only where `Option` allows them. Anything else throws
 * {@see \KiwiCaptcha\MalformedRecordException}. base64 validation is
 * deliberately absent: serde treats `nonce`/`salt` as plain strings at
 * parse time, and the differential fuzz corpus pins both parsers to the
 * same acceptance split.
 */
final class ChallengeRecord
{
    /**
     * The canonical wire schema, mirroring the Rust serde struct fields
     * (deny_unknown_fields). `ip_hash` is the legacy v1 alias for
     * `binding_tag` (serde alias attribute). `issuer`
     * is the deployment identity, always present, null when
     * unset. `kid` is the signing key id, always present,
     * default 1. `decoy_field`, `execution_program`,
     * `execution_version` and `execution_commitment` are the optional
     * Option keys — unlike the always-present Option keys they are
     * omitted from `toArray()` when null (the Rust
     * `skip_serializing_if` mirror). The three execution keys are
     * present together or all absent.
     */
    public const WIRE_KEYS = [
        'nonce', 'scope', 'binding_tag', 'issued_at', 'expires_at',
        'algorithm', 'm_kib', 't', 'p', 'target_bits', 'salt', 'prefix',
        'challenge', 'min_duration_ms', 'issued_at_ns', 'protocol_version',
        'attempts_used', 'region', 'policy_version', 'request_binding',
        'issuer', 'kid', 'hostname', 'decoy_field', 'execution_program',
        'execution_version', 'execution_commitment',
    ];

    /**
     * Fields serde requires, without a `#[serde(default)]`.
     */
    private const REQUIRED_KEYS = [
        'nonce', 'scope', 'binding_tag', 'issued_at', 'expires_at',
        'algorithm', 'm_kib', 't', 'p', 'target_bits', 'salt', 'prefix',
        'challenge', 'min_duration_ms',
    ];

    /** Maximum byte length of any wire string, mirroring the serde parse ceiling. */
    public const MAX_STRING_BYTES = 4096;

    /**
     * The binary's maximum challenge protocol version, mirrored by the
     * Rust crate (`challenge::MAX_PROTOCOL_VERSION`) and the extension's
     * readiness probe (KiwiHealthController): 4 since the
     * execution-capable canonical (protocol v4) landed — armed issuance
     * writes version 4 and the verifier accepts versions 1..4. A
     * central security-policy floor above this means the binary cannot
     * verify the challenges the fleet now issues.
     */
    public const MAX_PROTOCOL_VERSION = 4;

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
        // Server-side issuance metadata: the Host the challenge
        // was issued for (Siteverify `hostname`); never signed, never sent.
        public readonly ?string $hostname = null,
        // The server-issued decoy (honeypot) form-field name armed for
        // this challenge, drawn from the combinatorial grammar (see
        // Issuer::composeDecoyName()); null = no decoy
        // (the legacy shape). Signed as the final v3 canonical segment,
        // appended after the kid; the JSON key is omitted when null.
        public readonly ?string $decoyField = null,
        // The ExecutionChallengeV1 program (base64 of the bytecode blob,
        // see ExecutionChallengeGenerator) armed for this challenge;
        // null = no execution dimension (the legacy shape, byte-identical
        // to the pre-execution wire format). The JSON key is omitted when
        // null. The program is never sent in the challenge payload; it
        // rides the challenge response for the driver. Its integrity is
        // bound by the execution commitment, an authenticated protocol v4
        // canonical segment (SHA-256 of this stored program, see
        // `executionCommitment`): a substituted or stripped program
        // breaks the signature, and a stored program whose hash does not
        // match the signed commitment is rejected before any execution
        // work.
        public readonly ?string $executionProgram = null,
        // The execution-dimension protocol version (the canonical
        // numeric byte 1), authenticated as the `|execution_version`
        // protocol v4 canonical segment. Present iff the record carries
        // an execution program; the JSON key is omitted when null.
        public readonly ?int $executionVersion = null,
        // The authenticated mirror of the stored execution program: hex
        // SHA-256 of the program's base64 wire string (64 lowercase hex),
        // the final `|execution_commitment` protocol v4 canonical
        // segment. Present iff the record carries an execution program;
        // the JSON key is omitted when null.
        public readonly ?string $executionCommitment = null,
    ) {
    }

    /**
     * Validates a wire hostname: a label string of at most 4096 bytes
     * with no whitespace/control characters, or null.
     *
     * @throws MalformedRecordException on structural violations
     */
    private static function validateHostname(mixed $value): ?string
    {
        if ($value === null) {
            return null;
        }
        if (!\is_string($value) || $value === '') {
            throw MalformedRecordException::wrongType('hostname', 'a non-empty string or null', $value);
        }
        if (\strlen($value) > self::MAX_STRING_BYTES) {
            throw MalformedRecordException::oversized('hostname', \strlen($value));
        }
        if (preg_match('/[\x00-\x20\x7f]/', $value) === 1) {
            throw MalformedRecordException::wrongType('hostname', 'a string without whitespace or control characters', $value);
        }

        return $value;
    }

    /**
     * Compatibility accessor exposing the binding tag under the legacy
     * `ipHash` name: the field stores the nonce-bound binding tag, see
     * {@see Issuer::bindingTag()}. For v1 records the binding tag is
     * exactly the legacy `hash(sha256, secret || ip)` value, so the
     * accessor returns the same bytes callers of v1 records expect.
     */
    public function ipHash(): string
    {
        return $this->bindingTag;
    }

    /** @return array<string, mixed> */
    public function toArray(): array
    {
        $data = [
            'nonce' => $this->nonce,
            'scope' => $this->scope,
            // Protocol v2 primary key only. The legacy `ip_hash` key must
            // not be emitted alongside it: the Rust reader uses serde
            // #[serde(alias = "ip_hash")], and serde rejects a struct that
            // carries both the field and its alias as a duplicate field; a
            // dual-key record would be unreadable by Rust. Readers still
            // accept legacy ip_hash-only records (migration window);
            // writers emit the v2 key only.
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
            // explicitly to keep PHP to Rust records complete. The one-shot
            // model never increments it.
            'attempts_used' => 0,
            // Deployment metadata, always present (null when the challenge
            // is region-unbound) for byte parity with the Rust serde schema.
            'region' => $this->region,
            // Security-policy epoch. The Rust field is u32 and
            // never serializes null; a null ctor value degrades to the
            // default epoch so PHP-written records stay readable by Rust.
            'policy_version' => $this->policyVersion ?? 1,
            // Application transaction binding, null when unset.
            'request_binding' => $this->requestBinding,
            // Deployment identity, always present (null when
            // unset) for byte parity with the Rust serde schema.
            'issuer' => $this->issuer,
            // Signing key id, always present. The Rust field is
            // u32 and never serializes null; a null ctor value degrades to
            // the default key id 1 so PHP-written records stay readable by
            // Rust (mirror of policy_version).
            'kid' => $this->kid ?? 1,
            // Server-side issuance metadata, always present
            // (null when unset) for byte parity with the Rust serde schema.
            'hostname' => $this->hostname,
        ];
        // The decoy (honeypot) field name is the ONE Option key that is
        // omitted when null — the exact mirror of the Rust
        // `#[serde(skip_serializing_if = "Option::is_none")]`: a null
        // must never serialize as a JSON `null` key, so unarmed records
        // keep the exact pre-decoy byte format (old records/tokens keep
        // verifying; old readers never see the key).
        if ($this->decoyField !== null) {
            $data['decoy_field'] = $this->decoyField;
        }
        // The execution program is omitted when unarmed, the same
        // skip_serializing_if mirror: an unarmed record is byte-identical
        // to the pre-execution format in both directions. The
        // execution_version and execution_commitment keys ride the same
        // presence rule (all three execution keys are present together or
        // all absent — the issuer always sets the triplet and fromArray()
        // rejects any partial set), so a record that carries a program
        // always carries its authenticated commitment and a record
        // without one never leaks a commitment key. toArray() emits the
        // exact stored values: a hand-rolled record with a partial set
        // serializes its partial set and is rejected by fromArray() on
        // the next read, never silently repaired.
        if ($this->executionProgram !== null) {
            $data['execution_program'] = $this->executionProgram;
        }
        if ($this->executionVersion !== null) {
            $data['execution_version'] = $this->executionVersion;
        }
        if ($this->executionCommitment !== null) {
            $data['execution_commitment'] = $this->executionCommitment;
        }

        return $data;
    }

    /**
     * Rebuild a record from persisted (JSON-decoded) data; the strict
     * serde-mirror parser.
     *
     * Accepts exactly what the Rust `ChallengeRecord` serde schema accepts.
     * - Only the whitelisted keys in the canonical key list plus the
     *   legacy `ip_hash` alias, which must not appear alongside
     *   `binding_tag`. Unknown keys, including trailing garbage, throw
     *   {@see MalformedRecordException}.
     * - Required fields must be present; optional fields default
     *   (`issued_at_ns` 0, `attempts_used` 0, `protocol_version` 1,
     *   `region` null, `policy_version` 1, `request_binding` null,
     *   `issuer` null, `kid` 1).
     * - Protocol versions 1, 2, 3 and 4 are accepted. The
     *   protocol-vs-decoy-vs-execution grammar is total: a protocol-v2
     *   record that carries `decoy_field` is rejected explicitly, and a
     *   protocol-v3 record without one is rejected too (the decoy
     *   segment is a protocol v3/v4 canonical extension that v3
     *   requires). A v2/v3 record carrying any execution field is
     *   rejected (the execution segments are a protocol v4 canonical
     *   extension), and a protocol-v4 record without the execution
     *   triplet (`execution_program` + `execution_version` +
     *   `execution_commitment`, present together) is rejected too. The
     *   execution triplet must be exact: version 1, a 64-lowercase-hex
     *   commitment, and SHA256(program) == commitment (constant time).
     *   The capability is fully inferable from the authenticated
     *   canonical shape; see the class docblock for the
     *   wire-compatibility statement.
     * - Integers must be real JSON integers within the Rust type ranges
     *   (u8 for protocol_version, u32 for m_kib/t/p/target_bits/
     *   attempts_used/policy_version/kid, u64 for the timestamps).
     *   Negatives, floats, booleans, numeric strings, and overflow are
     *   rejected.
     * - Strings must be JSON strings of at most 4096 bytes.
     * - `algorithm` must be exactly `sha256`, `argon2id` or `rsw` (no
     *   aliases). An rsw record carries its sequential-squaring cost T
     *   in the signed time-cost slot `t`. No rsw-specific key exists on
     *   the record: the canonical 18-field grammar carries every
     *   authenticated parameter, and the trapdoor secrets live in the
     *   issuer and verifier configuration, never in storage.
     * - Null is only legal for `region`, `request_binding`, `issuer` and
     *   `decoy_field` (Option fields).
     * - The deployment-bound identifiers `region`, `request_binding` and
     *   `issuer` must match the narrow identifier alphabet
     *   `[A-Za-z0-9._:-]+` with their length caps (64 / 128 /
     *   128 bytes). Unicode, whitespace, invisible characters, empty
     *   strings and canonical separators are rejected. The optional
     *   `decoy_field` honeypot name must match its own alphabet
     *   `[A-Za-z0-9_-]{1,64}` (no `.`, `:` or `|`, so the canonical
     *   segment structure can never be altered by a stored value). `scope`
     *   is deliberately not validated here: serde treats it as an opaque
     *   string, and the differential fuzz corpus pins both parsers to the
     *   same acceptance split. The verifier's validateRecord enforces the
     *   scope alphabet at verification time.
     *
     * base64 is deliberately not validated for `nonce`/`salt`: serde
     * treats them as plain strings at parse time, and the differential
     * fuzz corpus pins both parsers to the same acceptance split.
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

        // Legacy v1 alias (the serde alias attribute): accepted in
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
        // Optional u64/u32/u8 fields: serde defaults when absent, but a
        // present JSON null is still a type error; distinguish the two.
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
        // protocol_version: u8 (default 1, serde's default_protocol_version).
        self::requireInt(
            \array_key_exists('protocol_version', $data) ? $data['protocol_version'] : 1,
            'protocol_version',
            0,
            255,
        );

        $algorithm = $data['algorithm'];
        if ($algorithm !== 'sha256' && $algorithm !== 'argon2id' && $algorithm !== 'rsw') {
            throw MalformedRecordException::invalidAlgorithm($algorithm);
        }

        // Option fields: null or string (region, request_binding, issuer).
        // The deployment-bound identifiers must also match the narrow
        // identifier alphabet with their length caps: region <= 64,
        // request_binding <= 128, issuer <= 128. scope is exempt: serde
        // treats it as an opaque string, and the fuzz corpus pins both
        // parsers to the same acceptance split (the verifier's
        // validateRecord enforces the scope alphabet instead).
        foreach (['region', 'request_binding', 'issuer'] as $field) {
            if (isset($data[$field]) && $data[$field] !== null) {
                self::requireString($data[$field], $field);
                if (!Config::isValidIdentifier($data[$field], $field === 'region' ? 64 : 128)) {
                    throw MalformedRecordException::invalidIdentifier($field);
                }
            }
        }

        // Option field: the decoy (honeypot) field name. Absent (the
        // legacy shape) and an explicit JSON null both decode to null —
        // the serde Option semantics; a present string must match the
        // exact shape the issuer mints and the widget driver renders,
        // 1..=64 bytes of [A-Za-z0-9_-] (no `.`, `:` or `|`, so the
        // canonical segment structure can never be altered by a stored
        // value). A non-conforming name is a corrupt or foreign record.
        if (isset($data['decoy_field']) && $data['decoy_field'] !== null) {
            self::requireString($data['decoy_field'], 'decoy_field');
            if (!Config::isValidDecoyFieldName($data['decoy_field'])) {
                throw MalformedRecordException::invalidDecoyField();
            }
        }

        // Option field: the ExecutionChallengeV1 program. Absent (the
        // legacy shape) and an explicit JSON null both decode to null;
        // a present value must be a well-formed program (canonical
        // standard base64 of a parseable blob, bounded by
        // ExecutionChallengeGenerator::MAX_PROGRAM_BASE64), otherwise the
        // record cannot be verified against its execution dimension and
        // is corrupt or foreign.
        if (isset($data['execution_program']) && $data['execution_program'] !== null) {
            self::requireString($data['execution_program'], 'execution_program');
            if (\strlen($data['execution_program']) > ExecutionChallengeGenerator::MAX_PROGRAM_BASE64) {
                throw MalformedRecordException::oversized('execution_program', \strlen($data['execution_program']));
            }
            if (!ExecutionChallengeGenerator::isValidProgram($data['execution_program'])) {
                throw MalformedRecordException::invalidExecutionProgram();
            }
        }

        // The protocol-v4 execution triplet: execution_program,
        // execution_version (u8) and execution_commitment (exactly 64
        // lowercase hex) are present together or all absent — a partial
        // set cannot have come from a conforming issuer and is rejected.
        $executionProgram = isset($data['execution_program']) && $data['execution_program'] !== null
            ? $data['execution_program']
            : null;
        $hasExecutionVersion = \array_key_exists('execution_version', $data) && $data['execution_version'] !== null;
        $hasExecutionCommitment = \array_key_exists('execution_commitment', $data) && $data['execution_commitment'] !== null;
        if ($executionProgram !== null || $hasExecutionVersion || $hasExecutionCommitment) {
            if ($executionProgram === null || !$hasExecutionVersion || !$hasExecutionCommitment) {
                throw MalformedRecordException::incompleteExecutionFields();
            }
            self::requireInt($data['execution_version'], 'execution_version', 0, 255);
            if ($data['execution_version'] < 1 || $data['execution_version'] > 4) {
                throw MalformedRecordException::invalidExecutionVersion($data['execution_version']);
            }
            self::requireString($data['execution_commitment'], 'execution_commitment');
            if (preg_match('/^[0-9a-f]{64}$/D', $data['execution_commitment']) !== 1) {
                throw MalformedRecordException::invalidExecutionCommitment();
            }
            if (!hash_equals(Issuer::executionCommitment($executionProgram), $data['execution_commitment'])) {
                throw MalformedRecordException::executionCommitmentMismatch();
            }
        }

        // The protocol-vs-decoy-vs-execution grammar is total: the decoy
        // segment is a protocol v3/v4 canonical extension (v2 => no
        // decoy, v3 => decoy present, v4 => decoy optional) and the
        // execution commitment is a protocol v4 canonical extension
        // (v2/v3 => no execution, v4 => execution present). A v2 record
        // that carries decoy_field is rejected explicitly (the v2
        // canonical never includes the segment, so such a record cannot
        // have come from a conforming issuer — an armed issuance writes
        // protocol v3); a v3 record without one is rejected too (the
        // decoy is mandatory on v3). A v2/v3 record carrying any
        // execution field is rejected (the execution segments are a v4
        // canonical extension), and a v4 record without the execution
        // triplet is rejected (the commitment is mandatory on v4, so a
        // signed v3 record with its stored version flipped to 4 keeps
        // the plain canonical bytes and is refused here). v1 (legacy,
        // migration window), v2 (unarmed) and v3 (decoy) accept a null
        // execution triplet; the verifier's malformed-record path
        // enforces the same split.
        $protocolVersion = (int) ($data['protocol_version'] ?? 1);
        $decoyField = \array_key_exists('decoy_field', $data) ? $data['decoy_field'] : null;
        if ($protocolVersion === 2 && $decoyField !== null) {
            throw MalformedRecordException::decoyOnV2Record();
        }
        if ($protocolVersion === 3 && $decoyField === null) {
            throw MalformedRecordException::decoylessV3Record();
        }
        if (($protocolVersion === 2 || $protocolVersion === 3) && $executionProgram !== null) {
            throw MalformedRecordException::executionOnLegacyProtocol($protocolVersion);
        }
        if ($protocolVersion === 4 && $executionProgram === null) {
            throw MalformedRecordException::executionlessV4Record();
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
            // Server-owned issuance metadata: parsed, validated
            // and passed through so a serialize -> Redis -> deserialize
            // cycle preserves it.
            hostname: isset($data['hostname']) ? self::validateHostname($data['hostname']) : null,
            // The armed decoy (honeypot) name, or null for the legacy
            // shape (absent key / JSON null).
            decoyField: $data['decoy_field'] ?? null,
            // The armed ExecutionChallengeV1 program, or null for the
            // legacy shape (absent key / JSON null).
            executionProgram: $executionProgram,
            // The authenticated protocol v4 execution triplet mirrors
            // the stored program: present together or all absent (the
            // partial-set rejection above already established the exact
            // equivalence).
            executionVersion: $hasExecutionVersion ? $data['execution_version'] : null,
            executionCommitment: $hasExecutionCommitment ? $data['execution_commitment'] : null,
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
