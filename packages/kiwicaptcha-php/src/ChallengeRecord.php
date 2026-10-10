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
 * stable IP-derived identifier) and `protocol_version` (2). The
 * accepted protocol versions are 1 through 5; the maximum is the
 * `MAX_PROTOCOL_VERSION` constant below. `toArray()` emits the v2 key
 * set only, and
 * `fromArray()` accepts either `binding_tag` or the legacy `ip_hash` key
 * (the serde alias attribute); the two must not appear
 * together, matching serde's duplicate-field rejection. Legacy records
 * carrying only `ip_hash` decode as `protocol_version` 1.
 *
 * Protocol v3 is the decoy-capable canonical: the 18-field base plus
 * the tagged `|d={decoy_field}` segment appended after `kid`. The decoy
 * is mandatory on v3, so an armed issuance writes protocol v3 with the
 * segment and an unarmed issuance stays protocol v2 with no extension
 * segment. The protocol-vs-decoy grammar is total and
 * enforced on both acceptance surfaces. A protocol-v2 record that
 * carries `decoy_field` is rejected explicitly, since the v2 canonical
 * never includes the segment. A protocol-v3 record without one is
 * rejected too: a signed v2 record with its stored version flipped to 3
 * can never verify, so the protocol capability is fully inferable from
 * the authenticated canonical shape. An old verifier rejects version 3
 * as unknown.
 *
 * Protocol v4 is the execution-capable canonical: the decoy-capable
 * canonical plus the tagged `|e=execution_version,execution_commitment`
 * segment appended after the decoy (or after `kid` when no decoy is
 * armed). The execution segment is mandatory on v4 and is present iff
 * the record carries an execution program.
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
 *
 * Protocol v5 is the identity-bearing rsw canonical: the base canonical
 * plus the `|rsw_modulus_sha256` segment as the final signed field.
 * The identity is mandatory on v5. It is exactly the canonical
 * fingerprint of the decoded 256-byte modulus: 64 lowercase hex, the
 * keygen's `rsw_modulus_n_sha256`. A signed identityless record with
 * its stored version flipped to 5 keeps the plain canonical bytes and
 * is refused by the grammar. A v5 record is always an rsw record, and the
 * identity may ride neither a v1 record (whose canonical signs no
 * segment) nor a non-rsw record. The decoy and execution segments stay
 * governed by their own signed equivalence, so an rsw + execution
 * composition signs the identity last under the same version.
 * Identity-bearing records at versions 2..4 are the pre-v5 legacy shape
 * (the historical base64-text identity), accepted for the bounded
 * migration window.
 *
 * `fromArray()` accepts protocol versions 1 through 5. It rejects
 * every forbidden combination: v2-plus-decoy, decoyless-v3,
 * v2/v3-with-execution, executionless-v4, v5 without an rsw identity,
 * identity on a v1 or non-rsw record, and any partial execution field
 * set. The verifier's malformed-record path enforces the same split.
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
 * of trusting the client-reported duration. It is authenticated by
 * `serverMac` (see below): a storage writer without the master secret
 * cannot backdate it.
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
 * `hostname` is server-side issuance metadata: the Siteverify host the
 * challenge was issued for. It is always present in `toArray()`, null
 * when unset, and is neither signed into the challenge nor sent to the
 * client. It is authenticated by `serverMac`.
 *
 * `serverMac` is the record-metadata MAC: 64 lowercase hex HMAC-SHA256
 * under the server-state purpose key over the challenge string,
 * `issuedAtNs` and `hostname`, see {@see ServerStateMac::recordMeta()}.
 * The issuer always writes it. The verifier rejects a mismatching MAC
 * as a malformed record; a record without one carries untrusted
 * metadata, so it fails closed under a minimum-duration floor, reports
 * no measured solve duration, and exposes no hostname. The JSON key is
 * absent when null (`skip_serializing_if`).
 *
 * `decoyField` is the server-issued decoy (honeypot) form-field name
 * armed for this challenge, drawn from the combinatorial grammar (see
 * {@see Issuer::composeDecoyName()}). Null =
 * no decoy armed (the default). The name is an authenticated canonical
 * field: the tagged `|d={decoy_field}` segment, appended after the `kid`
 * as documented on {@see Issuer::canonicalPayload()}, so a stored/tampered record
 * cannot change or drop it without breaking the signature. Wire
 * compatibility: unarmed records carry no extension segment. The JSON
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
 * `executionVersion` is the execution-dimension protocol version, the
 * canonical numeric byte carrying the armed program's execution grammar
 * version, 1..{@see ExecutionChallengeGenerator::MAX_EXECUTION_VERSION}
 * (an old record without the field is an unarmed record). It is an
 * authenticated canonical field of
 * protocol v4: the first element of the tagged `e=` segment, see
 * {@see Issuer::canonicalPayload()}, so a stored/tampered record cannot
 * change or drop it without breaking the signature. The JSON key is
 * absent when null (`skip_serializing_if`).
 *
 * `executionCommitment` is the authenticated mirror of the stored
 * execution program: hex SHA-256 of the program's base64 wire string,
 * 64 lowercase hex characters. It is an authenticated canonical field
 * of protocol v4 (the `e=` segment's second element), so a
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
        'execution_version', 'execution_commitment', 'rsw_modulus_sha256',
        'server_mac',
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
     * The base challenge protocol version every binary reads: the
     * identityless, decoyless, executionless canonical. Unarmed issuance
     * always writes it, so it needs no confirmed fleet capability.
     */
    public const BASE_PROTOCOL_VERSION = 2;

    /** The decoy-capable canonical version (requires a confirmed ceiling of at least 3). */
    public const DECOY_PROTOCOL_VERSION = 3;

    /** The execution-capable canonical version (requires a confirmed ceiling of at least 4). */
    public const EXECUTION_PROTOCOL_VERSION = 4;

    /**
     * The binary's maximum challenge protocol version is 5, mirrored by
     * the Rust crate (`challenge::MAX_PROTOCOL_VERSION`) and the
     * extension's readiness probe (`KiwiHealthController`).
     * Identity-armed rsw issuance writes version 5 and the verifier
     * accepts versions 1..5. A central security-policy floor above this
     * means the binary cannot verify the challenges the fleet now
     * issues.
     */
    public const MAX_PROTOCOL_VERSION = 5;

    /**
     * The first protocol version that requires the authenticated rsw
     * modulus identity on an rsw record. Identity-bearing records at
     * versions 2..4 are the pre-v5 legacy shape, accepted (and resolved
     * through the legacy base64-text alias) for the bounded migration
     * window.
     */
    public const RSW_IDENTITY_PROTOCOL_VERSION = 5;

    /**
     * The wire-key whitelist as a flipped isset() hash, built once per
     * process from {@see self::WIRE_KEYS}: the deny-unknown-fields gate
     * answers every key of a parsed record with one hash lookup instead
     * of a linear scan over the constant list.
     *
     * @var array<string, true>
     */
    private static array $wireKeyLookup = [];

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
        // numeric byte carrying the program's execution grammar version,
        // up to ExecutionChallengeGenerator::MAX_EXECUTION_VERSION),
        // authenticated as the first element of the tagged `e=`
        // protocol v4 canonical segment. Present iff the record carries
        // an execution program; the JSON key is omitted when null.
        public readonly ?int $executionVersion = null,
        // The authenticated mirror of the stored execution program: hex
        // SHA-256 of the program's base64 wire string (64 lowercase hex),
        // the second element of the tagged `e=` protocol v4 canonical
        // segment. Present iff the record carries an execution program;
        // the JSON key is omitted when null.
        public readonly ?string $executionCommitment = null,
        // The authenticated rsw trapdoor identity: hex SHA-256 of the
        // modulus (base64) this record was issued under, the
        // `|rsw_modulus_sha256` canonical segment. Present iff the
        // record is an rsw record issued after the binding existed; a
        // legacy rsw record carries none and resolves through the active
        // pair. The JSON key is omitted when null.
        public readonly ?string $rswModulusSha256 = null,
        // The record-metadata MAC over the challenge string, issuedAtNs
        // and hostname (64 lowercase hex), see ServerStateMac. The JSON
        // key is omitted when null.
        public readonly ?string $serverMac = null,
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
        if ($this->rswModulusSha256 !== null) {
            $data['rsw_modulus_sha256'] = $this->rswModulusSha256;
        }
        if ($this->serverMac !== null) {
            $data['server_mac'] = $this->serverMac;
        }

        return $data;
    }

    /**
     * The protocol-vs-extension grammar, the one explicit matrix every
     * boundary applies (this decoder and the verifier's structural
     * validation). v1 and v2 carry neither extension: the legacy v1
     * canonical signs no extension segment, so a stored v1 record
     * carrying either would hold unauthenticated semantics. v3
     * requires the decoy and carries no execution. v4 requires the
     * execution triplet and may also carry the decoy (the canonical
     * appends both segments).
     */
    public static function protocolExtensionGrammarOk(int $protocolVersion, bool $decoyPresent, bool $executionPresent, bool $rswIdentityPresent = false): bool
    {
        return match ($protocolVersion) {
            // The legacy v1 signature covers no canonical segment at
            // all, so the identity is refused there too.
            1 => !$decoyPresent && !$executionPresent && !$rswIdentityPresent,
            self::BASE_PROTOCOL_VERSION => !$decoyPresent && !$executionPresent,
            self::DECOY_PROTOCOL_VERSION => $decoyPresent && !$executionPresent,
            self::EXECUTION_PROTOCOL_VERSION => $executionPresent,
            // The identity-bearing rsw grammar: the identity is
            // mandatory (a signed identityless record with its stored
            // version flipped to 5 would keep the signatureless-identity
            // canonical bytes — the identity requirement is what refuses
            // it). The decoy and execution segments remain governed by
            // their own canonical shape and signed equivalence, so an
            // rsw + execution composition signs the identity as the
            // final segment under the same version.
            self::RSW_IDENTITY_PROTOCOL_VERSION => $rswIdentityPresent,
            default => false,
        };
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
     * - Protocol versions 1 through 5 are accepted. The
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
     * - Integers must be real JSON integers within the accepted ranges:
     *   u32 for m_kib/t/p/target_bits/attempts_used, u64 for the
     *   timestamps. The three sequence fields take the canonical
     *   protocol bounds rather than the bare integer widths —
     *   protocol_version 1..MAX_PROTOCOL_VERSION (policy_version and
     *   kid stay bare u32 like the Rust serde boundary: epoch 0 is the
     *   legitimate pre-epoch rotation state). Negatives, floats,
     *   booleans, numeric strings, overflow, and protocol_version 0 or
     *   above the maximum are rejected at the parse boundary.
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
        // The whitelist answers through the flipped isset() hash, never a
        // linear scan per key.
        if (!self::$wireKeyLookup) {
            self::$wireKeyLookup = array_fill_keys(self::WIRE_KEYS, true);
        }
        foreach ($data as $key => $value) {
            if (!\is_string($key) || ($key !== 'ip_hash' && !isset(self::$wireKeyLookup[$key]))) {
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
        // m_kib/t/p/target_bits/attempts_used: u32.
        foreach (['m_kib', 't', 'p', 'target_bits', 'attempts_used'] as $field) {
            self::requireInt(
                \array_key_exists($field, $data) ? $data[$field] : 0,
                $field,
                0,
                4_294_967_295,
            );
        }
        // policy_version/kid: u32 with the serde defaults 1. The
        // floors stay at the bare u32 width: epoch 0 is a legitimate
        // stored value (the pre-epoch migration state a rotation walks
        // forward from), and the Rust serde boundary accepts any u32
        // for both fields, so the parse must agree cross-language.
        foreach (['policy_version', 'kid'] as $field) {
            self::requireInt(
                \array_key_exists($field, $data) ? $data[$field] : 1,
                $field,
                0,
                4_294_967_295,
            );
        }
        // protocol_version: the canonical protocol range 1..
        // MAX_PROTOCOL_VERSION (default 1, serde's
        // default_protocol_version). Versions 0 and everything above the
        // current maximum are corrupt or foreign values rejected at the
        // parse boundary, mirroring the Rust serde boundary.
        self::requireInt(
            \array_key_exists('protocol_version', $data) ? $data['protocol_version'] : 1,
            'protocol_version',
            1,
            self::MAX_PROTOCOL_VERSION,
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
            if ($data['execution_version'] < 1 || $data['execution_version'] > ExecutionChallengeGenerator::MAX_EXECUTION_VERSION) {
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
        // The authenticated rsw trapdoor identity, parsed before the
        // grammar so the matrix sees its presence. The identity may only
        // ride an rsw record and is a v2+ canonical segment (v1 has no
        // identity segment at all).
        $rswModulusSha256 = self::parseRswModulusSha256($data);
        // The shared grammar matrix: every protocol-version and
        // extension combination is judged by one table, so the decoder
        // and the verifier can never disagree about which records are
        // structurally valid — including the legacy v1 shape, which
        // admits neither extension, the pre-v5 identity-bearing rsw
        // shape (protocol 2..4, accepted for the bounded migration
        // window) and the v5 grammar, which requires the identity and
        // combines it with neither of the other extensions.
        if (!self::protocolExtensionGrammarOk($protocolVersion, $decoyField !== null, $executionProgram !== null, $rswModulusSha256 !== null)) {
            throw MalformedRecordException::invalidProtocolFieldCombination($protocolVersion);
        }

        // Option field: the record-metadata MAC. Absent and JSON null
        // both decode to null (untrusted metadata, judged by the
        // verifier); a present value must be exactly 64 lowercase hex.
        $serverMac = null;
        if (isset($data['server_mac'])) {
            self::requireString($data['server_mac'], 'server_mac');
            if (preg_match(ServerStateMac::PATTERN, $data['server_mac']) !== 1) {
                throw MalformedRecordException::wrongType('server_mac', '64 lowercase hex characters', $data['server_mac']);
            }
            $serverMac = $data['server_mac'];
        }

        // The remaining structural contract of the Rust `validate_record`
        // (the twin of the Rust serde decode boundary, which applies the
        // full structural authority before any typed record surfaces):
        // the scope identifier alphabet, the difficulty floor/ceiling,
        // the exact nonce/salt wire shapes, the lifetime bounds and the
        // derived prefix. The checks above already cover the protocol
        // grammar, the identifier alphabets of the optional deployment
        // fields, the execution triplet, the decoy/rsw shapes and the
        // server_mac shape. A record violating any of these is corrupt
        // or foreign — refused here exactly like the Rust Deserialize
        // boundary, so both parsers accept exactly one record language.
        if (!Config::isValidIdentifier($data['scope'], 128)) {
            throw MalformedRecordException::invalidIdentifier('scope');
        }
        self::requireInt($data['target_bits'], 'target_bits', Config::MIN_DIFFICULTY, Config::MAX_DIFFICULTY);
        // The nonce is the 44-char standard-base64 encoding of 32 bytes
        // and the salt the 24-char encoding of 16 bytes (the exact
        // issuer wire shapes; the length pre-bound keeps oversized
        // attacker text from driving a decode buffer).
        if (\strlen($data['nonce']) !== 44) {
            throw MalformedRecordException::wrongType('nonce', '44 base64 characters of a 32-byte nonce', $data['nonce']);
        }
        $nonceBytes = base64_decode($data['nonce'], true);
        if ($nonceBytes === false || \strlen($nonceBytes) !== 32) {
            throw MalformedRecordException::wrongType('nonce', '44 base64 characters of a 32-byte nonce', $data['nonce']);
        }
        if (\strlen($data['salt']) !== 24) {
            throw MalformedRecordException::wrongType('salt', '24 base64 characters of a 16-byte salt', $data['salt']);
        }
        $saltBytes = base64_decode($data['salt'], true);
        if ($saltBytes === false || \strlen($saltBytes) !== 16) {
            throw MalformedRecordException::wrongType('salt', '24 base64 characters of a 16-byte salt', $data['salt']);
        }
        // The lifetime is strictly positive and bounded by the protocol
        // TTL ceiling (the verifier refuses longer spans as malformed).
        if ($data['expires_at'] <= $data['issued_at']) {
            throw MalformedRecordException::for('expires_at must be greater than issued_at');
        }
        if ($data['expires_at'] - $data['issued_at'] > Config::MAX_TTL_SECS) {
            throw MalformedRecordException::for('challenge lifetime exceeds the protocol TTL ceiling of '.Config::MAX_TTL_SECS.' seconds');
        }
        // The prefix is a derived field: exactly `challenge|salt|`.
        if ($data['prefix'] !== $data['challenge'].'|'.$data['salt'].'|') {
            throw MalformedRecordException::for('prefix must equal challenge|salt|');
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
            // The authenticated rsw trapdoor identity (absent on legacy
            // rsw records and on every non-rsw record).
            rswModulusSha256: $rswModulusSha256,
            serverMac: $serverMac,
        );
    }

    /**
     * The optional authenticated rsw modulus identity: absent/null on
     * every record except an identity-bearing rsw record. A present value
     * must be 64 lowercase hex, may only ride an rsw record, and may not
     * ride the legacy v1 canonical (which signs no identity segment, so
     * a v1 identity would be unauthenticated).
     *
     * @param array<string, mixed> $data
     */
    private static function parseRswModulusSha256(array $data): ?string
    {
        $value = $data['rsw_modulus_sha256'] ?? null;
        if ($value === null) {
            return null;
        }
        if (!\is_string($value) || preg_match(RswModulusIdentity::FINGERPRINT_PATTERN, $value) !== 1) {
            throw MalformedRecordException::for('rsw_modulus_sha256 must be 64 lowercase hex characters');
        }
        if (($data['algorithm'] ?? null) !== PoWAlgorithm::Rsw->value) {
            throw MalformedRecordException::for('rsw_modulus_sha256 may only ride an rsw record');
        }
        if ((int) ($data['protocol_version'] ?? 1) === 1) {
            throw MalformedRecordException::for('rsw_modulus_sha256 may not ride the v1 canonical (the v1 signature carries no identity segment)');
        }

        return $value;
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
