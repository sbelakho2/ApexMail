<?php

declare(strict_types=1);

namespace KiwiCaptcha;

/**
 * Issues KiwiCaptcha challenges, byte-for-byte compatible with the Rust
 * crate's `issue_challenge`.
 *
 * Protocol v2 (default issuance, `protocol_version` 2):
 *   nonce      = base64(32 random bytes)
 *   salt       = base64(16 random bytes)
 *   binding_tag = HMAC-SHA256 over the canonical IP, see
 *                {@see self::bindingTag()}; nonce-bound, so the stored
 *                binding is never a stable IP-derived identifier.
 *   canonical  = "v4|{protocol_version}|{nonce}|{scope}|{binding_tag}|
 *                {issued_at}|{expires_at}|{algorithm}|{m_kib}|{t}|{p}|
 *                {target_bits}|{salt}|{min_duration_ms}|{region}|
 *                {policy_version}|{request_binding}|{issuer}|{kid}".
 *                Region, request_binding and issuer render as the empty
 *                segment when unset; policy_version as the configured
 *                security-policy epoch; kid as the configured signing
 *                key id, the final base field. The protocol version is
 *                signed, and every armed extension is appended tagged:
 *                d={decoy_field} (protocol v3+), e={version},
 *                {commitment} (protocol v4+), r={modulus_sha256}
 *                (protocol v5), m=1 (the record-metadata MAC marker,
 *                revision 4). The tags make the encoding injective.
 *                The m=1 marker commits the sealed server_mac, so
 *                stripping the MAC breaks the signature. A stored
 *                version flip or extension swap always breaks the
 *                signature. Unarmed issuance stays protocol v2 with
 *                the same revision-4 base shape.
 *                The commitment is the hex SHA-256 of the program's
 *                base64 wire string, so the signed canonical is the
 *                exact mirror of the stored program. Stripping,
 *                substituting or injecting a program always breaks the
 *                signature.
 *   signature  = hex(H), where H = hmac_sha256(K_challenge, canonical),
 *                an `HKDF`-derived purpose key, see {@see DerivedKeys}.
 *                The master secret is never used directly as the signing
 *                key.
 *   challenge  = base64(canonical) . "." . signature.
 *   prefix     = "{challenge}|{salt}|".
 *   target     = effective difficulty for the configured algorithm.
 *   min_duration_ms = configured override or derived from difficulty.
 *
 * The nonce-bound binding tag is keyed by the `HKDF`-derived K_ip_bind
 * purpose key (never the master secret). The record additionally carries
 * a region (deployment metadata) that is part of the v2 canonical
 * payload, so it is signed into the record like every other immutable v2
 * parameter, see {@see self::canonicalPayload()}. The region is
 * authenticated and therefore client-decodable from the challenge's
 * canonical payload, but never separately exposed as a top-level
 * response property.
 *
 * Legacy v1 issuance (`protocol_version` 1, payload
 * `"{nonce}|{scope}|{ip_hash}|{issued_at}"`) is not produced anymore.
 * The v1 helpers remain: {@see self::hashIp()} computes the legacy IP
 * hash and {@see self::signPayload()} the legacy master-key signature,
 * so v1 records and the verifier's v1 path keep working during the
 * migration window, byte-identical to the Rust crate's v1 path.
 *
 * The stored record additionally carries `issued_at_ns` (server-side
 * high-resolution issuance time), never signed, never sent to the client.
 */
final class Issuer
{
    /**
     * The combinatorial decoy-name grammar, the server-side naming space
     * for decoy (honeypot) form fields. When a deployment arms the decoy
     * surface, see {@see self::issueWithDecoyField()}, the issuer draws
     * one lowercase word per slot with `random_int` (`CSPRNG`) and joins
     * them with '_' to form the grammar prefix {slot1}_{slot2}_{slot3},
     * e.g. `secondary_contact_phone` or `billing_company_url`. The three
     * position-specific vocabularies below are shared verbatim with the
     * Rust `DECOY_GRAMMAR_SLOT1_QUALIFIER` / `_SLOT2_CATEGORY` /
     * `_SLOT3_FORM` (same words, same order). The pick itself is never
     * coordinated between the languages: the issuing core signs whatever
     * it picked, and verification validates alphabet plus canonical,
     * never the name.
     *
     * The armed name is the prefix plus a per-issuance random suffix:
     * {slot1}_{slot2}_{slot3}_{suffix} with a 16-lowercase-hex suffix
     * drawn from 8 `CSPRNG` bytes, e.g.
     * `billing_address_line_a3f9c21d8e5b7401`, see
     * {@see self::composeDecoyName()} and {@see self::decoyNameSuffix()}.
     * The suffix is the collision disambiguator: an application field
     * whose name equals a grammar prefix (a plausible real field name,
     * e.g. `billing_address_line`) can still collide with an armed name
     * only when it also equals the per-issuance 64-bit suffix. The
     * accidental-match probability for a given issued name is 2^-64, so
     * a forced collision is a deliberate act, never an accident.
     *
     * Prefix space size: len(`SLOT1`) * len(`SLOT2`) * len(`SLOT3`) =
     * 32 * 29 * 30 = 27,840 distinct prefixes. Each triple joins to a
     * unique string, because '_' cannot occur inside a word. The prefix
     * is `[a-z_]+` of at most 30 bytes (the longest word is 10 bytes);
     * the armed name adds 1 + 16 bytes for the '_' + suffix, at most 47
     * bytes. Every armed name is a subset of the
     * `[A-Za-z0-9_-]{1,64}` shape the widget driver and the validation
     * accept, see {@see Config::isValidDecoyFieldName()}. No name can
     * ever smuggle the `|` canonical-payload separator. The legacy
     * 10-name pool words (company_website, fax_number, ...) all remain
     * present as vocabulary entries. The prefix selection is
     * combinatorial: a fixed 10-name pool is log2(10) ~ 3.32 bits of
     * enumerable space, the grammar prefix space is log2(27,840) ~ 14.8
     * bits. The armed name space is 27,840 * 2^64, so two consecutive
     * challenges share a full name with probability ~2^-64.
     */
    public const DECOY_GRAMMAR_SLOT1_QUALIFIER = [
        'secondary', 'alternate', 'billing', 'office', 'personal', 'company',
        'home', 'backup', 'department', 'business', 'primary', 'work',
        'emergency', 'mobile', 'regional', 'corporate', 'team', 'project',
        'default', 'temporary', 'external', 'internal', 'private', 'shared',
        'general', 'local', 'main', 'national', 'seasonal', 'guest',
        'middle', 'assistant',
    ];

    public const DECOY_GRAMMAR_SLOT2_CATEGORY = [
        'contact', 'address', 'phone', 'email', 'website', 'fax', 'company',
        'account', 'profile', 'order', 'invoice', 'support', 'service',
        'sales', 'location', 'region', 'branch', 'division', 'directory',
        'registry', 'record', 'file', 'entry', 'channel', 'portal',
        'platform', 'list', 'archive', 'history',
    ];

    public const DECOY_GRAMMAR_SLOT3_FORM = [
        'phone', 'url', 'number', 'line', 'code', 'name', 'extension',
        'email', 'address', 'link', 'id', 'key', 'value', 'info', 'details',
        'notes', 'lookup', 'search', 'query', 'reference', 'alias', 'handle',
        'username', 'label', 'tag', 'entry', 'record', 'index', 'field',
        'form',
    ];

    /**
     * The authenticated rsw trapdoor identity: the canonical
     * {@see RswModulusIdentity::fingerprint()} — lowercase-hex SHA-256 of
     * the decoded 256-byte modulus. This is exactly the
     * `rsw_modulus_n_sha256` the shipped rsw-keygen prints.
     */
    public static function rswModulusSha256(string $modulusNBase64): string
    {
        return RswModulusIdentity::fingerprint($modulusNBase64);
    }

    public function __construct(
        private readonly Config $config,
        private readonly StorageInterface $storage,
        /** @var callable(): int|null clock override (tests) */
        private $now = null,
        /**
         * Deployment region bound to every issued record (e.g. "eu").
         * Null = region-unbound. The record's `region` JSON key is always
         * present (null when unbound) for parity with the Rust schema; a
         * verifier configured with an expected region rejects records
         * whose region does not match exactly. Must match the narrow
         * identifier alphabet, at most 64 bytes of [A-Za-z0-9._:-].
         */
        private readonly ?string $region = null,
        /**
         * The optional rsw trapdoor rotation keyring: a map of the
         * modulus SHA-256 (the authenticated rsw_modulus_sha256 riding
         * each issued record) to that trapdoor's {modulus_n, lambda}
         * pair. Reconstruction (responseFromRecord) resolves a record's
         * authenticated identity here, so a rotated or mixed-node
         * deployment still re-emits the modulus the challenge was
         * issued under instead of the newly active one.
         *
         * @var array<string, array{modulus_n: string, lambda: string}>
         */
        private readonly array $rswVerificationKeys = [],
        /**
         * The bounded legacy rsw identity migration mode (default false):
         * while enabled, the historical base64-text identity alias stays
         * accepted for identity-bearing records below protocol v5 and as
         * a keyring key. Enable it only while pre-v5 identity-bearing
         * records drain (the maximum challenge TTL plus clock skew), then
         * leave it off: a drained deployment must refuse the temporary
         * grammar fail-closed.
         */
        private readonly bool $allowLegacyRswIdentity = false,
    ) {
        if ($region !== null && !Config::isValidIdentifier($region, 64)) {
            throw new \InvalidArgumentException(
                'region must be 1-64 characters of [A-Za-z0-9._:-] when set'
            );
        }
        foreach ($rswVerificationKeys as $hash => $pair) {
            if (!\is_string($hash) || preg_match(RswModulusIdentity::FINGERPRINT_PATTERN, $hash) !== 1
                || !\is_array($pair)
                || !\is_string($pair['modulus_n'] ?? null) || $pair['modulus_n'] === ''
            ) {
                throw new \InvalidArgumentException(
                    'rswVerificationKeys must map a 64-hex modulus SHA-256 to a {modulus_n, lambda} pair'
                );
            }
            // The keyring key must be an identity form of the paired
            // modulus under THE active mode: the canonical fingerprint
            // (the keygen's rsw_modulus_n_sha256) always, the legacy
            // base64-text alias only while the migration mode is enabled.
            if (!RswModulusIdentity::matches($hash, $pair['modulus_n'], $this->allowLegacyRswIdentity)) {
                throw new \InvalidArgumentException(
                    'rswVerificationKeys keys must be the canonical SHA-256 of the decoded modulus_n'
                    .' (or its legacy base64-text alias while allowLegacyRswIdentity is enabled)'
                );
            }
            // The accepted identity forms resolve to the pair, so a
            // legacy identity-bearing record (in the migration window)
            // and a canonical v5 record resolve against the same keyring
            // entry.
            $forms = $this->allowLegacyRswIdentity
                ? RswModulusIdentity::allFingerprints($pair['modulus_n'])
                : [RswModulusIdentity::fingerprint($pair['modulus_n'])];
            foreach ($forms as $identity) {
                $this->rswModuliByHash[$identity] = $pair['modulus_n'];
            }
            $this->rswModuliByHash[$hash] = $pair['modulus_n'];
        }
    }

    /**
     * Whether `$identity` is an accepted identity form of `$modulusNBase64`
     * for the record's protocol version: the canonical fingerprint always,
     * the legacy base64-text alias only on a pre-v5 identity-bearing
     * record.
     */
    public static function isRswIdentityOfModulus(string $identity, string $modulusNBase64, bool $allowLegacyAlias = true): bool
    {
        return RswModulusIdentity::matches($identity, $modulusNBase64, $allowLegacyAlias);
    }

    /**
     * The rsw trapdoor rotation keyring (modulus identity -> modulus),
     * see the constructor parameter.
     *
     * @var array<string, string>
     */
    private array $rswModuliByHash = [];

    public function config(): Config
    {
        return $this->config;
    }

    /**
     * An issuer with the given Config, every constructor field of
     * this one carried over directly: storage, the clock override,
     * region, the rsw trapdoor rotation keyring and the legacy-identity
     * migration mode.
     *
     * No reflection: the constructor is the one authoritative copy of
     * the issuer's deployment state.
     */
    public function withConfig(Config $config): self
    {
        return new self($config, $this->storage, $this->now, $this->region, $this->rswVerificationKeys, $this->allowLegacyRswIdentity);
    }

    /**
     * Return an issuer with the same secret, storage, clock and region
     * but the given challenge lifetime. The Config is cloned with only
     * ttlSecs replaced; storage and the clock override are carried over
     * directly (no reflection). The caller keeps the same storage.
     */
    public function withTtl(int $ttlSecs): self
    {
        // Every constructor field is carried over, including the rsw
        // trapdoor rotation keyring: a TTL-variant issuer must resolve
        // the same outstanding records as its source.
        return $this->withConfig($this->config->withOverrides(ttlSecs: $ttlSecs));
    }

    /**
     * `$maxProtocolVersionToEmit` is the confirmed write capability
     * ceiling, documented on {@see self::issueWithDecoyField()}. This
     * entry point issues the capability-free base shape, so its default
     * is {@see ChallengeRecord::BASE_PROTOCOL_VERSION}.
     *
     * @throws \InvalidArgumentException when the scope is empty, longer than
     *                                   128 bytes, or outside the identifier
     *                                   alphabet [A-Za-z0-9._:-];
     *                                   when the request binding is longer
     *                                   than 128 bytes or outside the same
     *                                   alphabet
     */
    public function issue(
        string $scope,
        string $clientIp,
        ?string $requestBinding = null,
        ?string $hostname = null,
        int $maxProtocolVersionToEmit = ChallengeRecord::BASE_PROTOCOL_VERSION,
    ): Challenge {
        return $this->issueChallenge($scope, $clientIp, $requestBinding, $hostname, null, false, null, 1, $maxProtocolVersionToEmit);
    }

    /**
     * Issue a challenge with the decoy (honeypot) surface armed, the
     * issuance-side switch of the risk engine's honeypot/decoy signals
     * (`DecoyFieldSubmitted`, `honeypot_hit`). Identical to
     * {@see self::issue()} in every other respect: same wire format,
     * same signing, same storage. When `$armDecoyField` is true the
     * issuer picks a fresh armed name, a grammar prefix plus a fresh
     * 16-hex `CSPRNG` suffix, see {@see self::composeDecoyName()}. The
     * suffix gives every issuance its own 64 random bits, so the
     * probability that two consecutive challenges share a full name is
     * ~2^-64 — accidental collision with any other name, application
     * fields included, is cryptographically impossible.
     * The name is set on the client-facing
     * {@see Challenge::$decoyField}, the key the widget driver renders
     * the hidden input from, and on the stored record's authenticated
     * {@see ChallengeRecord::$decoyField}. It is signed into the
     * canonical input as the final `|<decoy_field>` segment, and the
     * stored record's protocol_version is 3 (the decoy-capable
     * canonical): an old verifier rejects version 3 as unknown, so the
     * capability becomes inferable from protocol_version. A client
     * cannot strip or swap the decoy without breaking the signature the
     * verifier re-checks. `false` (or
     * the plain {@see self::issue()}) behaves exactly like the legacy
     * path: protocol v2, no decoy, byte-identical canonical string, and
     * neither JSON surface carries the key.
     *
     * `$decoyNameOverride` is a fixture/test seam: when non-null the
     * armed name is exactly this value (validated against the same
     * `[A-Za-z0-9_-]{1,64}` alphabet) instead of a fresh random pick.
     * Production callers omit it.
     *
     * `$executionVersion` is the execution-dimension protocol version,
     * the canonical numeric byte carrying the execution grammar version,
     * 1..{@see ExecutionChallengeGenerator::MAX_EXECUTION_VERSION} (the
     * generator's live maximum), passed as an int — never a string that
     * is cast.
     *
     * `$maxProtocolVersionToEmit` is the confirmed write capability
     * ceiling: the highest challenge protocol version this writer's
     * fleet has been confirmed to read. It is a real authority over
     * every protocol extension, not a hint. Arming the decoy requires a
     * ceiling of at least {@see ChallengeRecord::DECOY_PROTOCOL_VERSION},
     * and arming the execution program requires at least
     * {@see ChallengeRecord::EXECUTION_PROTOCOL_VERSION}. A request
     * beyond the confirmed ceiling fails issuance with
     * {@see EmissionCapabilityExceededException} instead of silently
     * downgrading, and a ceiling below
     * {@see ChallengeRecord::BASE_PROTOCOL_VERSION} is rejected
     * outright.
     *
     * The one documented fallback is the rsw modulus identity. It is
     * emitted only at {@see ChallengeRecord::RSW_IDENTITY_PROTOCOL_VERSION}
     * and otherwise falls back to the identityless legacy base shape.
     * The identity is additive signing metadata with a defined
     * backward-compatible form. This entry point arms the decoy by
     * default, so its default ceiling is the decoy version; pass the
     * confirmed central floor explicitly for a real rollout ceiling.
     *
     * @throws \InvalidArgumentException when `$decoyNameOverride` is set
     *                                   but not a valid decoy field name
     */
    public function issueWithDecoyField(
        string $scope,
        string $clientIp,
        bool $armDecoyField = true,
        ?string $requestBinding = null,
        ?string $hostname = null,
        ?string $decoyNameOverride = null,
        bool $armExecution = false,
        ?string $executionAction = null,
        int $executionVersion = 1,
        int $maxProtocolVersionToEmit = ChallengeRecord::DECOY_PROTOCOL_VERSION,
    ): Challenge {
        if ($decoyNameOverride !== null && !Config::isValidDecoyFieldName($decoyNameOverride)) {
            throw new \InvalidArgumentException('decoy name override must be 1-64 characters of [A-Za-z0-9_-]');
        }

        return $this->issueChallenge(
            $scope,
            $clientIp,
            $requestBinding,
            $hostname,
            $armDecoyField ? ($decoyNameOverride ?? self::pickDecoyField()) : null,
            $armExecution,
            $executionAction,
            $executionVersion,
            $maxProtocolVersionToEmit,
        );
    }

    /**
     * Issue a challenge with the ExecutionChallengeV1 dimension armed,
     * the browser-execution surface of the adaptive-risk layer.
     * When `$armExecution` is true the issuer generates a deterministic
     * bytecode program from the challenge context via
     * {@see ExecutionChallengeGenerator::generate()}, stamps it on the
     * stored record's `execution_program` and on the client-facing
     * {@see Challenge::$executionProgram}, base64, omitted when
     * unarmed. The driver runs the program in its sandboxed ephemeral
     * interpreter and presents the resulting execution digest with the
     * solution token. The verifier recomputes the expected digest from
     * the stored program and rejects a mismatch with the deterministic
     * ExecutionMismatch outcome. The dimension is supplementary
     * evidence only, never the sole acceptance boundary. The PoW proof
     * and the record state machinery still gate.
     *
     * Arming requires the configured execution_key (see
     * {@see Config::$executionKey}); arming without the key throws
     * {@see \InvalidArgumentException}, so a deployment cannot arm the
     * dimension by accident. `$executionAction` is the provider-style
     * action of the request, 1..32 chars of [A-Za-z0-9._:-], default
     * "default", and `$executionVersion` the dimension protocol
     * version, the canonical numeric byte carrying the execution
     * grammar version, 1..{@see ExecutionChallengeGenerator::MAX_EXECUTION_VERSION}
     * (int, never a string that is cast). Both are embedded in the
     * program and bound by the commitment.
     *
     * An armed issuance writes protocol v4: the stored record carries
     * `execution_program` plus the authenticated `execution_version`
     * and `execution_commitment` (hex SHA-256 of the program) signed
     * into the canonical payload as the tagged
     * `|e=execution_version,execution_commitment` segment.
     * Stripping, substituting or injecting a program always breaks the
     * signature.
     *
     * @throws \InvalidArgumentException when arming without an
     *                                   execution_key, or with an invalid
     *                                   action/version
     */
    public function issueWithExecutionField(
        string $scope,
        string $clientIp,
        bool $armExecution,
        ?string $requestBinding = null,
        ?string $hostname = null,
        ?string $executionAction = null,
        int $executionVersion = 1,
        bool $armDecoyField = false,
        ?string $decoyNameOverride = null,
        ?ChallengeProfile $profile = null,
        int $maxProtocolVersionToEmit = ChallengeRecord::EXECUTION_PROTOCOL_VERSION,
    ): Challenge {
        if ($profile !== null) {
            return $this->issueWithProfile(
                $scope,
                $clientIp,
                $profile,
                requestBinding: $requestBinding,
                hostname: $hostname,
                armDecoyField: $armDecoyField,
                armExecution: $armExecution,
                executionAction: $executionAction,
                executionVersion: $executionVersion,
                maxProtocolVersionToEmit: $maxProtocolVersionToEmit,
            );
        }
        if ($decoyNameOverride !== null && !Config::isValidDecoyFieldName($decoyNameOverride)) {
            throw new \InvalidArgumentException('decoy name override must be 1-64 characters of [A-Za-z0-9_-]');
        }

        return $this->issueChallenge(
            $scope,
            $clientIp,
            $requestBinding,
            $hostname,
            $armDecoyField ? ($decoyNameOverride ?? self::pickDecoyField()) : null,
            $armExecution,
            $executionAction,
            $executionVersion,
            $maxProtocolVersionToEmit,
        );
    }

    /**
     * Pick a random armed decoy field name: a grammar prefix plus the
     * fresh 16-hex `CSPRNG` suffix, see {@see self::composeDecoyName()},
     * never a weak or insecure fallback. An
     * RNG failure propagates to the caller as a Random\RandomException,
     * exactly like the nonce/salt draws. Mirrors the Rust
     * `pick_decoy_field`.
     */
    private static function pickDecoyField(): string
    {
        return self::composeDecoyName(
            random_int(0, \count(self::DECOY_GRAMMAR_SLOT1_QUALIFIER) - 1),
            random_int(0, \count(self::DECOY_GRAMMAR_SLOT2_CATEGORY) - 1),
            random_int(0, \count(self::DECOY_GRAMMAR_SLOT3_FORM) - 1),
        );
    }

    /**
     * The per-issuance random suffix of an armed decoy name: 16
     * lowercase hex characters drawn from 8 bytes of the `CSPRNG`
     * (`random_bytes`), 64 random bits. The suffix is the collision
     * disambiguator of the armed name space: a grammar prefix alone is
     * a plausible real field name, so only the suffix makes an armed
     * name unguessable and accidental collision impossible. Mirrors the
     * Rust `decoy_name_suffix`.
     */
    public static function decoyNameSuffix(): string
    {
        return bin2hex(random_bytes(8));
    }

    /**
     * The deterministic grammar prefix for the given slot indices,
     * {slot1}_{slot2}_{slot3}. Pure and public so tests can enumerate
     * the prefix space, pin the vocabularies, and run fixed-seed
     * collision statistics without touching the `CSPRNG`.
     *
     * @throws \OutOfBoundsException when any index is outside its
     *                               vocabulary
     */
    public static function composeDecoyPrefix(int $slot1, int $slot2, int $slot3): string
    {
        $s1 = self::DECOY_GRAMMAR_SLOT1_QUALIFIER[$slot1] ?? null;
        $s2 = self::DECOY_GRAMMAR_SLOT2_CATEGORY[$slot2] ?? null;
        $s3 = self::DECOY_GRAMMAR_SLOT3_FORM[$slot3] ?? null;
        if ($s1 === null || $s2 === null || $s3 === null) {
            throw new \OutOfBoundsException('decoy grammar slot index out of range');
        }

        return $s1.'_'.$s2.'_'.$s3;
    }

    /**
     * The armed decoy name for the given slot indices:
     * {slot1}_{slot2}_{slot3}_{suffix}, the grammar prefix composed by
     * {@see self::composeDecoyPrefix()} plus the per-issuance 16-hex
     * `CSPRNG` suffix, e.g. `billing_address_line_a3f9c21d8e5b7401`.
     * At most 47 bytes, a subset of the `[A-Za-z0-9_-]{1,64}` shape.
     *
     * @throws \OutOfBoundsException when any index is outside its
     *                               vocabulary
     */
    public static function composeDecoyName(int $slot1, int $slot2, int $slot3): string
    {
        return self::composeDecoyPrefix($slot1, $slot2, $slot3).'_'.self::decoyNameSuffix();
    }

    /**
     * The combinatorial prefix space size, len(SLOT1) * len(SLOT2) *
     * len(SLOT3).
     */
    public static function decoyGrammarSpaceSize(): int
    {
        return \count(self::DECOY_GRAMMAR_SLOT1_QUALIFIER)
            * \count(self::DECOY_GRAMMAR_SLOT2_CATEGORY)
            * \count(self::DECOY_GRAMMAR_SLOT3_FORM);
    }

    /**
     * Whether $name is a grammar prefix: three underscore-joined
     * vocabulary words, each from its position-specific list, within the
     * `[A-Za-z0-9_-]{1,64}` validation shape.
     */
    public static function isGrammarDecoyPrefix(string $name): bool
    {
        if (!Config::isValidDecoyFieldName($name)) {
            return false;
        }
        $parts = explode('_', $name);
        if (\count($parts) !== 3) {
            return false;
        }

        return \in_array($parts[0], self::DECOY_GRAMMAR_SLOT1_QUALIFIER, true)
            && \in_array($parts[1], self::DECOY_GRAMMAR_SLOT2_CATEGORY, true)
            && \in_array($parts[2], self::DECOY_GRAMMAR_SLOT3_FORM, true);
    }

    /**
     * Whether $name is an armed decoy name: a grammar prefix, see
     * {@see self::isGrammarDecoyPrefix()}, plus '_' plus the 16
     * lowercase hex suffix characters, within the
     * `[A-Za-z0-9_-]{1,64}` validation shape.
     */
    public static function isGrammarDecoyName(string $name): bool
    {
        if (!Config::isValidDecoyFieldName($name)) {
            return false;
        }
        $parts = explode('_', $name);
        if (\count($parts) !== 4) {
            return false;
        }

        return \in_array($parts[0], self::DECOY_GRAMMAR_SLOT1_QUALIFIER, true)
            && \in_array($parts[1], self::DECOY_GRAMMAR_SLOT2_CATEGORY, true)
            && \in_array($parts[2], self::DECOY_GRAMMAR_SLOT3_FORM, true)
            && preg_match('/^[0-9a-f]{16}$/D', $parts[3]) === 1;
    }

    /**
     * The shared issuance body, see the {@see self::issue()} contract;
     * `$decoyField` is the already-picked honeypot name, or null for the
     * legacy unarmed path. `$armExecution` arms the
     * ExecutionChallengeV1 dimension (see
     * {@see self::issueWithExecutionField()}): the program is generated
     * from the challenge context after the nonce exists. The program
     * binds the nonce, so it can only be minted inside issuance.
     */
    private function issueChallenge(
        string $scope,
        string $clientIp,
        ?string $requestBinding,
        ?string $hostname,
        ?string $decoyField,
        bool $armExecution = false,
        ?string $executionAction = null,
        int $executionVersion = 1,
        int $maxProtocolVersionToEmit = ChallengeRecord::BASE_PROTOCOL_VERSION,
    ): Challenge {
        $scopeLen = \strlen($scope);
        if ($scopeLen < 1 || $scopeLen > 128) {
            throw new \InvalidArgumentException('scope must be 1-128 bytes');
        }
        // The narrow identifier alphabet subsumes the '|'
        // separator check — no scope can smuggle a canonical separator,
        // whitespace, invisible characters, or multi-byte text into the
        // signed payload.
        if (!\preg_match('/^[A-Za-z0-9._:-]+$/D', $scope)) {
            throw new \InvalidArgumentException('scope must contain only [A-Za-z0-9._:-] characters');
        }
        if ($requestBinding !== null && !Config::isValidIdentifier($requestBinding, 128)) {
            throw new \InvalidArgumentException('request binding must be 1-128 characters of [A-Za-z0-9._:-]');
        }
        // The emission ceiling is a real protocol authority: a value below
        // the base protocol cannot describe any readable fleet, and every
        // requested extension is checked against it below.
        if ($maxProtocolVersionToEmit < ChallengeRecord::BASE_PROTOCOL_VERSION) {
            throw new \InvalidArgumentException(
                'maxProtocolVersionToEmit must be at least the base protocol version ('.ChallengeRecord::BASE_PROTOCOL_VERSION.')'
            );
        }
        if ($decoyField !== null && $maxProtocolVersionToEmit < ChallengeRecord::DECOY_PROTOCOL_VERSION) {
            throw new EmissionCapabilityExceededException(
                'the decoy field requires an emission ceiling of at least '.ChallengeRecord::DECOY_PROTOCOL_VERSION
                .'; the confirmed ceiling is '.$maxProtocolVersionToEmit
            );
        }
        $now = $this->nowUnix();

        $nonce = base64_encode(random_bytes(32));
        $salt = base64_encode(random_bytes(16));

        // Binding mode: 'none' issues challenges with an empty binding tag
        // (maximum privacy, no client-derived identifier at all); the
        // verifier skips the binding check for empty tags.
        $bindingTag = $this->config->bindingMode === \KiwiCaptcha\BindingMode::None
            ? ''
            : self::bindingTag($nonce, $clientIp, $this->config->secretKey, $this->config->tenantId);
        $algorithm = $this->config->algorithm;
        $targetBits = $this->effectiveTargetBits();

        // The rsw canonical parameter mapping: the fixed v2 slots carry
        // the time-lock's knobs, since no canonical segment changes. The
        // sequential-squaring cost T rides the time-cost slot t; the
        // memory slot m_kib is 0, the parallelism slot p is 1, and the
        // difficulty slot carries the rsw target_bits pin (1, the
        // protocol floor) because the canonical always renders the field
        // and rsw has no leading-zero target. The verifier's rsw path
        // reads t and never consults the other slots. Any other
        // algorithm keeps the exact historical parameter mapping.
        $isRsw = $algorithm === PoWAlgorithm::Rsw;
        $issuedMKib = $isRsw ? 0 : $this->config->mKib;
        $issuedT = $isRsw ? $this->config->rswT : $this->config->t;
        $issuedP = $isRsw ? 1 : $this->config->p;

        $expiresAt = $now + $this->config->ttlSecs;
        $minDurationMs = $this->config->minDurationMs
            ?? $this->deriveMinDurationMs($targetBits);

        // The decoy (honeypot) field name, when armed, was picked before
        // the canonical input is built: it is an authenticated issuance
        // parameter (the `|<decoy_field>` segment), signed like every
        // other.
        //
        // The ExecutionChallengeV1 program is minted before the canonical
        // input too: the commitment segments are part of the signed
        // canonical, and the commitment is a function of the program (the
        // program itself binds the nonce, which exists by now). Arming
        // without the configured execution_key is a misconfiguration and
        // refuses the issuance: the execution dimension can never be
        // armed by accident.
        $executionProgram = null;
        if ($armExecution) {
            if ($this->config->executionKey === null) {
                throw new \InvalidArgumentException(
                    'execution challenges are armed but no execution_key is configured'
                );
            }
            if ($maxProtocolVersionToEmit < ChallengeRecord::EXECUTION_PROTOCOL_VERSION) {
                throw new EmissionCapabilityExceededException(
                    'the execution program requires an emission ceiling of at least '.ChallengeRecord::EXECUTION_PROTOCOL_VERSION
                    .'; the confirmed ceiling is '.$maxProtocolVersionToEmit
                );
            }
            $executionProgram = ExecutionChallengeGenerator::generate(
                $this->config->executionKey,
                $nonce,
                $scope,
                $executionAction ?? 'default',
                $executionVersion,
            );
        }
        // The authenticated commitment is the hex SHA-256 of the stored
        // program's base64 wire string — the exact mirror of the stored
        // program, signed into the canonical below.
        $executionCommitment = $executionProgram !== null
            ? self::executionCommitment($executionProgram)
            : null;
        // The authenticated rsw trapdoor identity (protocol v5): the
        // canonical-byte modulus fingerprint, signed as the tagged `r=`
        // segment. It may compose with the decoy/execution
        // segments (their own signed segments stay authoritative); the
        // identity is appended before the m= marker, see
        // {@see self::canonicalPayload()}.
        $rswIdentity = null;
        if ($isRsw
            && $this->config->rswModulusN !== null
            && $maxProtocolVersionToEmit >= ChallengeRecord::RSW_IDENTITY_PROTOCOL_VERSION
        ) {
            $rswIdentity = self::rswModulusSha256($this->config->rswModulusN);
        }
        // The protocol version is part of the signed canonical (revision
        // 4): a stored version flip must break the signature. Compute it
        // before signing and reuse the exact value in the stored record.
        $issuedProtocolVersion = $rswIdentity !== null
            ? ChallengeRecord::RSW_IDENTITY_PROTOCOL_VERSION
            : ($executionProgram !== null
                ? ChallengeRecord::EXECUTION_PROTOCOL_VERSION
                : ($decoyField !== null ? ChallengeRecord::DECOY_PROTOCOL_VERSION : ChallengeRecord::BASE_PROTOCOL_VERSION));
        $payload = self::canonicalPayload(
            $issuedProtocolVersion,
            $nonce,
            $scope,
            $bindingTag,
            $now,
            $expiresAt,
            $algorithm,
            $issuedMKib,
            $issuedT,
            $issuedP,
            $targetBits,
            $salt,
            $minDurationMs,
            $this->region,
            $this->config->policyVersion,
            $requestBinding,
            $this->config->issuer,
            $this->config->kid,
            $decoyField,
            // The canonical execution segments ride only an armed
            // issuance: the version and the commitment are passed
            // together (or both null for the unarmed path), so the
            // signed canonical can never carry a partial execution
            // segment.
            $executionProgram !== null ? $executionVersion : null,
            $executionCommitment,
            // The rsw trapdoor identity: only an identity-armed rsw
            // issuance carries it.
            $rswIdentity,
            // Every issuance seals a record-metadata MAC below, so the
            // signed canonical commits the m=1 marker.
            true,
        );
        $signature = self::signPayloadV2($payload, $this->config->secretKey, $this->config->tenantId);

        $challenge = base64_encode($payload).'.'.$signature;
        $prefix = $challenge.'|'.$salt.'|';
        // issuedAtNs = epoch microseconds since Unix epoch (wall clock;
        // hrtime(true) is monotonic and per-host, so it must never be
        // persisted to shared storage). The name/JSON key stay
        // issuedAtNs for ChallengeRecord serialization stability. The
        // value and the hostname are not part of the signed canonical
        // fields, so the record-metadata MAC authenticates them under
        // the server-state purpose key; the signed m=1 marker commits
        // that the MAC exists.
        $issuedAtNs = (int) (microtime(true) * 1_000_000);
        $serverMac = ServerStateMac::recordMeta(
            ServerStateMac::key($this->config->secretKey, $this->config->tenantId),
            $challenge,
            $issuedAtNs,
            $hostname,
        );

        $record = new ChallengeRecord(
            nonce: $nonce,
            scope: $scope,
            bindingTag: $bindingTag,
            issuedAt: $now,
            expiresAt: $expiresAt,
            algorithm: $algorithm,
            mKib: $issuedMKib,
            t: $issuedT,
            p: $issuedP,
            targetBits: $targetBits,
            salt: $salt,
            prefix: $prefix,
            challenge: $challenge,
            minDurationMs: $minDurationMs,
            issuedAtNs: $issuedAtNs,
            // Protocol version by arm: an identity-armed rsw record
            // carries the identity-capable v5 canonical (the tagged
            // `r=` segment before the m= marker), so it is protocol v5 — a
            // pre-v5 verifier rejects the unknown version instead of
            // silently ignoring the identity; an execution-armed record
            // carries the execution-capable canonical (the
            // `e=version,commitment` segments after the decoy/kid), so it
            // is protocol v4; a decoy-only record
            // carries the decoy-capable canonical (the `d=` segment
            // after the kid), so it is protocol v3; an unarmed
            // record keeps protocol v2 with the plain base
            // canonical and the trailing m= marker.
            protocolVersion: $issuedProtocolVersion,
            region: $this->region,
            policyVersion: $this->config->policyVersion,
            requestBinding: $requestBinding,
            hostname: $hostname,
            issuer: $this->config->issuer,
            kid: $this->config->kid,
            decoyField: $decoyField,
            executionProgram: $executionProgram,
            // The authenticated v4 execution triplet: the version and
            // the commitment ride the stored record exactly as they were
            // signed (never recomputed), so the equivalence between the
            // signed canonical and the stored program is preserved
            // byte-for-byte through storage round-trips.
            executionVersion: $executionProgram !== null ? $executionVersion : null,
            executionCommitment: $executionCommitment,
            rswModulusSha256: $rswIdentity,
            serverMac: $serverMac,
        );
        $this->storage->store($record);

        return new Challenge(
            nonce: $nonce,
            challenge: $challenge,
            salt: $salt,
            algorithm: $algorithm,
            mKib: $issuedMKib,
            t: $issuedT,
            p: $issuedP,
            targetBits: $targetBits,
            ttlSecs: $this->config->ttlSecs,
            minDurationMs: $minDurationMs,
            prefix: $prefix,
            decoyField: $decoyField,
            executionProgram: $executionProgram,
            // The rsw modulus rides the client-facing response (the
            // solver squares modulo n); lambda never leaves the server.
            rswModulus: $isRsw ? $this->config->rswModulusN : null,
        );
    }

    /**
     * Reconstruct the client-facing challenge response from a stored
     * record: the canonical inverse of the issue path, used by
     * integrations that hand the record back to the client (fresh
     * issuance handoff, issued-stage-2 recovery, lost-response
     * reconstruction).
     *
     * The record itself carries every algorithm-independent field; the
     * algorithm-specific public material comes from this issuer's
     * Config, so an rsw deployment re-emits the exact configured
     * modulus. A record the configured algorithm cannot serve (a
     * different algorithm family, a malformed rsw record) returns null:
     * the caller must fail closed rather than hand out a challenge the
     * client cannot solve.
     */
    public function responseFromRecord(\KiwiCaptcha\ChallengeRecord $record): ?Challenge
    {
        $rswModulus = null;
        if ($record->algorithm === PoWAlgorithm::Rsw) {
            // Only the trapdoor owner can reconstruct an rsw challenge;
            // lambda never leaves the server. The modulus is selected by
            // the record's authenticated identity, never by whatever pair
            // is currently active: the keyring (a rotation or mixed-node
            // record) first, then the active pair, including a legacy
            // record that predates the identity. The legacy base64-text
            // alias resolves only a pre-v5 identity; a v5 record resolves
            // its canonical fingerprint exactly. An identity in neither
            // fails closed. SHA and Argon records are self-contained
            // (Argon carries its full parameter set on the record), so a
            // risk-escalated Argon challenge issued by a SHA-configured
            // deployment reconstructs without the rsw material.
            if ($record->rswModulusSha256 !== null) {
                $allowLegacyAlias = $this->allowLegacyRswIdentity && $record->protocolVersion <= 4;
                $rswModulus = $this->rswModuliByHash[$record->rswModulusSha256] ?? null;
                if ($rswModulus !== null && !self::isRswIdentityOfModulus($record->rswModulusSha256, $rswModulus, $allowLegacyAlias)) {
                    $rswModulus = null;
                }
                if ($rswModulus === null && $this->config->rswModulusN !== null
                    && self::isRswIdentityOfModulus($record->rswModulusSha256, $this->config->rswModulusN, $allowLegacyAlias)
                ) {
                    $rswModulus = $this->config->rswModulusN;
                }
            } elseif ($this->config->algorithm === PoWAlgorithm::Rsw) {
                $rswModulus = $this->config->rswModulusN;
            }
            if ($rswModulus === null) {
                return null;
            }
        }

        return new Challenge(
            nonce: $record->nonce,
            challenge: $record->challenge,
            salt: $record->salt,
            algorithm: $record->algorithm,
            mKib: $record->mKib,
            t: $record->t,
            p: $record->p,
            targetBits: $record->targetBits,
            ttlSecs: max(0, $record->expiresAt - $record->issuedAt),
            minDurationMs: $record->minDurationMs,
            prefix: $record->prefix,
            decoyField: $record->decoyField,
            executionProgram: $record->executionProgram,
            rswModulus: $rswModulus,
        );
    }

    /**
     * Issue a challenge from an adaptive-risk difficulty profile.
     *
     * Builds a Config clone from the profile; the issuer's own Config is
     * never mutated. Algorithm, m_kib, t, p, target_bits and
     * argon2_target_bits come from the profile (argon2_target_bits equals
     * the profile's targetBits for Argon2id), while ttlSecs and
     * minDurationMs stay owned by the issuer Config. The profile is
     * validated first, see {@see ChallengeProfile::validate()}; an
     * invalid profile throws \InvalidArgumentException before anything is
     * issued.
     *
     * Delegates to the normal {@see self::issue()} path, so the wire
     * format, signing, and storage are identical to a regular issue; only
     * the parameters differ. When `$armDecoyField` is true the issuance
     * is the armed variant, {@see self::issueWithDecoyField()}: a
     * random pool name is picked per issuance.
     * The record is protocol v3 (or v4 when the execution dimension is
     * armed too) and the authenticated name rides the challenge
     * response.
     *
     * @throws \InvalidArgumentException when the profile is invalid (or the
     *                                   scope is invalid, per issue())
     */
    public function issueWithProfile(
        string $scope,
        string $clientIp,
        ChallengeProfile $profile,
        ?int $now = null,
        ?string $requestBinding = null,
        ?string $hostname = null,
        bool $armDecoyField = false,
        bool $armExecution = false,
        ?string $executionAction = null,
        int $executionVersion = 1,
        int $maxProtocolVersionToEmit = ChallengeRecord::EXECUTION_PROTOCOL_VERSION,
    ): Challenge {
        $profile->validate();

        // Server-owned difficulty floors: a client-reported
        // capability can never lower the difficulty below the absolute
        // bounds the issuer signs. Argon2id memory must be 8..65536 KiB, the
        // time cost t >= 3 and parallelism exactly 1 — anything below would
        // let an attacker skip the work the server believes it issued (the
        // widget sends no difficulty parameters; these floors are the
        // issuance-side mirror of the verifier's absolute ceilings).
        if ($profile->algorithm === PoWAlgorithm::Argon2id) {
            if ($profile->mKib < 8 || $profile->mKib > 65536) {
                throw new \InvalidArgumentException(sprintf(
                    'Argon2id memory m_kib must be within 8..65536 (got %d) — the issuer never signs below-floor work',
                    $profile->mKib
                ));
            }
            if ($profile->t < 3) {
                throw new \InvalidArgumentException(sprintf(
                    'Argon2id time cost t must be >= 3 (got %d) — the issuer never signs below-floor work',
                    $profile->t
                ));
            }
            if ($profile->p !== 1) {
                throw new \InvalidArgumentException(sprintf(
                    'Argon2id parallelism p must be 1 (got %d) — the issuer never signs below-floor work',
                    $profile->p
                ));
            }
        }

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
            policyVersion: $this->config->policyVersion,
            issuer: $this->config->issuer,
            kid: $this->config->kid,
            executionKey: $this->config->executionKey,
            rswModulusN: $this->config->rswModulusN,
            rswLambda: $this->config->rswLambda,
            rswT: $this->config->rswT,
            tenantId: $this->config->tenantId,
        );
        $nowFn = $now !== null ? static fn (): int => $now : $this->now;

        // The hostname (server-owned issuance metadata) must
        // survive the profile path, and every constructor field is
        // carried — including the rsw trapdoor rotation keyring, so the
        // profile clone resolves the same outstanding records.
        return (new self($config, $this->storage, $nowFn, $this->region, $this->rswVerificationKeys, $this->allowLegacyRswIdentity))
            ->issueWithDecoyField($scope, $clientIp, $armDecoyField, $requestBinding, $hostname, null, $armExecution, $executionAction, $executionVersion, $maxProtocolVersionToEmit);
    }

    /**
     * Protocol v2 nonce-bound IP binding tag.
     *
     * HMAC-SHA256 over the canonical form of the client IP, keyed by the
     * `HKDF`-derived IP-binding purpose key (K_ip_bind, see
     * {@see DerivedKeys}; never the master secret itself) and bound to
     * the challenge nonce. The stored binding is unique per challenge and
     * never a stable identifier that follows the client across requests.
     * IPv4-mapped IPv6 addresses (`::ffff:a.b.c.d`) are normalized to
     * their 4-byte IPv4 form. The deprecated IPv4-compatible forms
     * (`::a.b.c.d`, excluding `::` and `::1`) are normalized the same
     * way. Every spelling of the same address therefore produces one tag,
     * in agreement with the risk identity layer and the Rust core. A non-null $tenantId derives K_ip_bind under
     * the per-tenant root, so tenants of a shared master secret cannot
     * forge each other's binding tags; null (the default) keeps the
     * global key, byte-identical to the tenantless tag.
     *
     * Message layout:
     *   "kiwicaptcha/ip-bind/v2\0" . nonce . "\0" . family . canonical_bytes
     * where family = "\x04" (IPv4) or "\x06" (IPv6) and canonical_bytes is
     * inet_pton() output (4 or 16 bytes).
     *
     * @throws \InvalidArgumentException when the IP is not a valid IPv4 or
     *                                   IPv6 address
     */
    public static function bindingTag(string $nonce, string $ip, string $secret, ?string $tenantId = null): string
    {
        $family = self::canonicalIpFamily($ip);
        $message = "kiwicaptcha/ip-bind/v2\0".$nonce."\0".$family;

        return hash_hmac('sha256', $message, DerivedKeys::fromMaster($secret, $tenantId)->ipBindKey());
    }

    /**
     * Canonical family byte + packed bytes for an IP: inet_pton() output
     * (4 or 16 bytes) with IPv4-mapped IPv6 (::ffff:a.b.c.d) AND the
     * deprecated IPv4-compatible IPv6 form (::a.b.c.d, excluding :: and
     * ::1) normalized to the 4-byte IPv4 form. Two textual spellings of
     * the same address (e.g. "2001:db8::1" and "2001:0db8:0:0:0:0:0:1")
     * therefore produce the same bytes — used by the challenge binding
     * tag AND the rate-limiter pseudonym so identity is exact. This
     * mirrors the risk identity layer's `RiskIdentityFactory::canonicalIp`
     * and the Rust core `canonical_ip` byte-for-byte, so the issuance
     * tag, the siteverify remoteip path and the risk source/subnet
     * identity always agree on exactly one canonical family per address.
     *
     * @throws \InvalidArgumentException when the IP is not a valid IPv4 or
     *                                   IPv6 address
     */
    public static function canonicalIpFamily(string $ip): string
    {
        // The strict validator is the grammar gate: the platform's
        // inet_pton accepts some non-canonical IPv4 spellings
        // (leading-zero forms among them) and normalizes them
        // inconsistently.
        if (filter_var($ip, FILTER_VALIDATE_IP) === false) {
            throw new \InvalidArgumentException('Invalid IP address');
        }
        $canonical = inet_pton($ip);
        if ($canonical === false) {
            throw new \InvalidArgumentException('Invalid IP address');
        }
        $len = \strlen($canonical);
        if ($len === 16) {
            $low = substr($canonical, 12);
            $mapped = substr($canonical, 0, 12) === "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff";
            $compatible = substr($canonical, 0, 12) === str_repeat("\x00", 12)
                && $low !== "\x00\x00\x00\x00"
                && $low !== "\x00\x00\x00\x01";
            if ($mapped || $compatible) {
                $canonical = $low;
                $len = 4;
            }
        }
        if ($len !== 4 && $len !== 16) {
            throw new \InvalidArgumentException('Invalid IP address');
        }

        return ($len === 4 ? "\x04" : "\x06").$canonical;
    }

    /**
     * The source identity shared by every abuse-tracking layer (the
     * issuance/cancellation limiter budget, OutstandingChallenges, the
     * risk source pseudonym, the siteverify idempotency source and the
     * client-IP budget): the canonical family bytes with IPv6 masked to
     * its /64. A host controls at least a /64, so a /128-keyed source
     * lets it rotate addresses and take a fresh identity on every
     * request. The /64 bucket matches the Rust risk core, where
     * `source_id_for_epoch` masks with `masked_network(ip, 32, 64)`:
     * full IPv4, /64 IPv6. The challenge binding tag keeps the full
     * /128 via
     * {@see self::canonicalIpFamily()}.
     *
     * @throws \InvalidArgumentException when the IP is not a valid IPv4 or
     *                                   IPv6 address
     */
    public static function canonicalSourceFamily(string $ip): string
    {
        $identity = self::canonicalIpFamily($ip);
        $family = $identity[0];
        $bytes = substr($identity, 1);
        $prefix = $family === "\x04" ? 32 : 64;
        $masked = '';
        $remaining = $prefix;
        foreach (str_split($bytes) as $byte) {
            if ($remaining >= 8) {
                $masked .= $byte;
                $remaining -= 8;
            } elseif ($remaining > 0) {
                $masked .= chr(ord($byte) & (0xFF << (8 - $remaining) & 0xFF));
                $remaining = 0;
            } else {
                $masked .= "\x00";
            }
        }

        return $family.$masked;
    }

    /**
     * Canonical payload (revision 4): the exact byte string that is
     * signed and base64-encoded into the challenge. Shared with the
     * verifier so issuance and verification can never drift apart.
     *
     * Byte-identical to the Rust `canonical_signing_input_v2`:
     *
     *     v4|protocol_version|nonce|scope|binding_tag|issued_at|expires_at|
     *       algorithm|m_kib|t|p|target_bits|salt|min_duration_ms|region|
     *       policy_version|request_binding|issuer|kid
     *
     * `region`, `request_binding` and `issuer` render as the empty
     * segment when unset; `kid` is the final base field (always present,
     * the configured signing key id, default 1).
     *
     * # Armed extensions (tagged)
     *
     * Each armed extension is appended after the base with an explicit
     * tag, in capability order:
     *
     *     ...|kid|d={decoy_field}|e={version},{commitment}|r={modulus_sha256}|m=1
     *
     * - `d=` (protocol v3): the armed decoy name, see
     *   {@see self::issueWithDecoyField()}. `null` renders no segment.
     * - `e=` (protocol v4): the ExecutionChallengeV1 version and the hex
     *   SHA-256 of the program's base64 wire string, see
     *   {@see self::issueWithExecutionField()}. They are always present
     *   together; the signed commitment is the exact mirror of the stored
     *   program, and the verifier additionally checks
     *   SHA256(stored program) == commitment.
     * - `r=` (protocol v5): the canonical-byte rsw modulus fingerprint.
     * - `m=1` (revision 4): the record-metadata MAC marker, appended last
     *   whenever the record carries a `server_mac`. The marker is what
     *   makes stripping the MAC break the signature and lets the verifier
     *   require a valid MAC without trusting the stored MAC presence.
     *
     * # Why the tags and the signed version
     *
     * Revision 2 signed `v2|...` for every protocol version and appended
     * the extensions as bare positional segments, so the encoding was
     * not injective. A v5 rsw record with identity `H` and no decoy
     * signed the same bytes as a v3 record with decoy `H`. A v4
     * execution pair signed the same bytes as a v5 decoy plus identity
     * pair. An attacker who can write challenge storage could therefore
     * reshape a record while keeping a valid signature, for example
     * downgrading v5 to v3 and stripping the rsw identity pinning.
     * Revision 3 signs `protocol_version` and tags every extension, so
     * distinct capability shapes can never collide. Revision 4 adds the
     * signed `m=1` marker. Supporting both layouts by version would keep
     * the attack alive for stored records, so the current revision is a
     * hard cutover.
     */
    public static function canonicalPayload(
        int $protocolVersion,
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
        ?string $region = null,
        int $policyVersion = 1,
        ?string $requestBinding = null,
        ?string $issuer = null,
        int $kid = 1,
        ?string $decoyField = null,
        ?int $executionVersion = null,
        ?string $executionCommitment = null,
        ?string $rswModulusSha256 = null,
        bool $serverMacCommitted = false,
    ): string {
        $base = sprintf(
            'v4|%d|%s|%s|%s|%d|%d|%s|%d|%d|%d|%d|%s|%d|%s|%d|%s|%s|%d',
            $protocolVersion,
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
            $region ?? '',
            $policyVersion,
            $requestBinding ?? '',
            $issuer ?? '',
            $kid,
        );

        // The decoy segment is appended only when armed: null renders
        // nothing extra, so the unarmed base keeps the plain field set.
        // The m= marker is appended separately when the record carries
        // a server_mac.
        if ($decoyField !== null) {
            $base .= '|d='.$decoyField;
        }
        // The execution commitment segments are appended only when the
        // record carries an execution program — and only as the exact
        // pair. The issuer always passes both; a caller passing exactly
        // one is a programming error that must never reach a signed
        // payload (the canonical would be ambiguous across languages).
        if ($executionVersion !== null || $executionCommitment !== null) {
            if ($executionVersion === null || $executionCommitment === null) {
                throw new \InvalidArgumentException(
                    'execution_version and execution_commitment must be passed together'
                );
            }
            $base .= '|e='.$executionVersion.','.$executionCommitment;
        }
        // The rsw trapdoor identity is appended only when the record
        // carries it: a legacy rsw record (bound before the identity
        // existed) signs the canonical it always signed, and a
        // post-binding record authenticates its modulus.
        if ($rswModulusSha256 !== null) {
            $base .= '|r='.$rswModulusSha256;
        }
        // The record-metadata MAC marker is appended last whenever the
        // signed record carries a server_mac: stripping the MAC then
        // changes the signed bytes.
        if ($serverMacCommitted) {
            $base .= '|m=1';
        }

        return $base;
    }

    /**
     * True when the challenge's signed canonical carries the
     * record-metadata MAC marker (`m=1`). The marker is parsed from the
     * base64 canonical embedded in the challenge string, never inferred
     * from the stored `server_mac` presence. A record whose signature
     * covers `m=1` must carry a valid MAC, while a record signed without
     * the marker accepts an absent MAC. A malformed challenge decodes to
     * false. Mirrors the Rust `signed_canonical_commits_record_meta`.
     */
    public static function signedCanonicalCommitsRecordMeta(string $challenge): bool
    {
        $pos = strrpos($challenge, '.');
        if ($pos === false) {
            return false;
        }
        $canonical = base64_decode(substr($challenge, 0, $pos), true);
        if ($canonical === false) {
            return false;
        }

        return str_starts_with($canonical, 'v4|') && str_ends_with($canonical, '|m=1');
    }

    /**
     * The authenticated execution commitment of a stored program: hex
     * SHA-256 of the program's base64 wire string, 64 lowercase hex
     * characters. This is the value signed into the protocol v4
     * canonical (the second element of the tagged `|e=execution_version,
     * execution_commitment` segment), so the
     * verifier's constant-time equivalence check
     * `SHA256(stored program) == signed commitment` is byte-exact in
     * both languages. Mirrors the Rust `execution_commitment` helper.
     */
    public static function executionCommitment(string $executionProgram): string
    {
        return hash('sha256', $executionProgram);
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
     * Legacy v1 signature: hex HMAC-SHA256 of the v1 canonical payload
     * with the master secret used directly as the key, byte-identical to
     * the Rust crate's v1 path. This is the historical format; v1 is
     * only kept for the migration window. Protocol v2 signatures use the
     * `HKDF`-derived challenge key via {@see self::signPayloadV2()}.
     */
    public static function signPayload(string $canonicalPayload, string $secretKey): string
    {
        return hash_hmac('sha256', $canonicalPayload, $secretKey);
    }

    /**
     * Protocol v2 signature: hex HMAC-SHA256 of the canonical v2 payload
     * keyed by the `HKDF`-derived challenge-signing purpose key
     * (K_challenge). See {@see DerivedKeys}. The master secret is never
     * used directly as the signing key. A non-null $tenantId derives
     * K_challenge under the per-tenant root ("kiwi/v2/tenant/" + tenant
     * id), so tenants of a shared master secret cannot sign each other's
     * challenges. Null (the default) keeps the global key,
     * byte-identical to the tenantless signature and to the Rust
     * crate's `sign_canonical_v2`.
     */
    public static function signPayloadV2(string $canonicalPayload, string $secretKey, ?string $tenantId = null): string
    {
        return hash_hmac('sha256', $canonicalPayload, DerivedKeys::fromMaster($secretKey, $tenantId)->challengeKey());
    }

    private function effectiveTargetBits(): int
    {
        // Defensive clamp: Config already rejects out-of-range values at
        // construction, but a hand-rolled ChallengeRecord (or a future
        // config path) must not reach the solver with an unsolvable
        // difficulty. RSW has no leading-zero target: the canonical
        // always renders the field, so issuance pins the protocol floor.
        return match ($this->config->algorithm) {
            PoWAlgorithm::Sha256 => min($this->config->targetBits, Config::MAX_SHA_TARGET_BITS),
            PoWAlgorithm::Argon2id => min($this->config->argon2TargetBits, Config::MAX_ARGON2_TARGET_BITS),
            PoWAlgorithm::Rsw => Config::RSW_TARGET_BITS_PIN,
        };
    }

    /**
     * Minimum plausible solve time, derived from algorithm + difficulty —
     * identical to Rust's ChallengeConfig::min_duration_ms_for.
     */
    private function deriveMinDurationMs(int $targetBits): int
    {
        // The rsw floor derives from the sequential cost T: even a
        // native-optimized squarer cannot finish T 2048-bit squarings
        // below T / 5e6 seconds (the browser BigInt solver is slower),
        // so a faster receipt is a timing anomaly. The 50 ms absolute
        // floor mirrors the Argon2id rule.
        if ($this->config->algorithm === PoWAlgorithm::Rsw) {
            return max(50, (int) ceil($this->config->rswT / 5e6 * 1000));
        }
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
