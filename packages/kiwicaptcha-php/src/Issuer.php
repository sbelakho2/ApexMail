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
 *   canonical  = "v2|{nonce}|{scope}|{binding_tag}|{issued_at}|{expires_at}|
 *                {algorithm}|{m_kib}|{t}|{p}|{target_bits}|{salt}|
 *                {min_duration_ms}|{region}|{policy_version}|
  *                {request_binding}|{issuer}|{kid}". Region,
  *                request_binding and issuer render as the empty segment
  *                when unset; policy_version as the configured
  *                security-policy epoch; kid as the configured signing
  *                key id, the final canonical field. Protocol v3 is the
  *                decoy-capable canonical: when a decoy (honeypot) field
  *                is armed, see {@see self::issueWithDecoyField()},
  *                exactly one more segment is appended after the kid,
  *                ...|{issuer}|{kid}|{decoy_field}, and the stored
  *                record's protocol_version is 3 — see
  *                {@see self::canonicalPayload()}. Unarmed issuance
  *                stays protocol v2, byte-identical to the pre-decoy
  *                format.
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
    ) {
        if ($region !== null && !Config::isValidIdentifier($region, 64)) {
            throw new \InvalidArgumentException(
                'region must be 1-64 characters of [A-Za-z0-9._:-] when set'
            );
        }
    }

    public function config(): Config
    {
        return $this->config;
    }

    /**
     * Return an issuer with the same secret, storage, clock and region
     * but the given challenge lifetime. The Config is cloned with only
     * ttlSecs replaced; storage and the clock override are carried over
     * directly (no reflection). The caller keeps the same storage.
     */
    public function withTtl(int $ttlSecs): self
    {
        $c = $this->config;
        $clone = new Config(
            secretKey: $c->secretKey,
            algorithm: $c->algorithm,
            mKib: $c->mKib,
            t: $c->t,
            p: $c->p,
            targetBits: $c->targetBits,
            argon2TargetBits: $c->argon2TargetBits,
            ttlSecs: $ttlSecs,
            minDurationMs: $c->minDurationMs,
            solverMaxHashes: $c->solverMaxHashes,
            bindingMode: $c->bindingMode,
            policyVersion: $c->policyVersion,
            issuer: $c->issuer,
            kid: $c->kid,
            executionKey: $c->executionKey,
        );

        return new self($clone, $this->storage, $this->now, $this->region);
    }

    /**
     * @throws \InvalidArgumentException when the scope is empty, longer than
     *                                   128 bytes, or outside the identifier
     *                                   alphabet [A-Za-z0-9._:-];
     *                                   when the request binding is longer
     *                                   than 128 bytes or outside the same
     *                                   alphabet
     */
    public function issue(string $scope, string $clientIp, ?string $requestBinding = null, ?string $hostname = null): Challenge
    {
        return $this->issueChallenge($scope, $clientIp, $requestBinding, $hostname, null);
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
        string $executionVersion = '1',
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
     * version, default 1. Both are embedded in the program and bound by
     * the digest.
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
        string $executionVersion = '1',
        bool $armDecoyField = false,
        ?string $decoyNameOverride = null,
        ?ChallengeProfile $profile = null,
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
        string $executionVersion = '1',
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
        $now = $this->nowUnix();

        $nonce = base64_encode(random_bytes(32));
        $salt = base64_encode(random_bytes(16));

        // Binding mode: 'none' issues challenges with an empty binding tag
        // (maximum privacy, no client-derived identifier at all); the
        // verifier skips the binding check for empty tags.
        $bindingTag = $this->config->bindingMode === \KiwiCaptcha\BindingMode::None
            ? ''
            : self::bindingTag($nonce, $clientIp, $this->config->secretKey);
        $algorithm = $this->config->algorithm;
        $targetBits = $this->effectiveTargetBits();

        $expiresAt = $now + $this->config->ttlSecs;
        $minDurationMs = $this->config->minDurationMs
            ?? $this->deriveMinDurationMs($targetBits);

        // The decoy (honeypot) field name, when armed, was picked before
        // the canonical input is built: it is an authenticated issuance
        // parameter (the final `|<decoy_field>` segment), signed like
        // every other.
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
            $this->region,
            $this->config->policyVersion,
            $requestBinding,
            $this->config->issuer,
            $this->config->kid,
            $decoyField,
        );
        $signature = self::signPayloadV2($payload, $this->config->secretKey);

        $challenge = base64_encode($payload).'.'.$signature;
        $prefix = $challenge.'|'.$salt.'|';

        // The ExecutionChallengeV1 program, minted from the challenge
        // context once the nonce exists (the program binds the nonce).
        // Arming without the configured execution_key is a
        // misconfiguration and refuses the issuance: the execution
        // dimension can never be armed by accident.
        $executionProgram = null;
        if ($armExecution) {
            if ($this->config->executionKey === null) {
                throw new \InvalidArgumentException(
                    'execution challenges are armed but no execution_key is configured'
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
            // issuedAtNs = epoch microseconds since Unix epoch (wall clock;
            // hrtime(true) is monotonic and per-host, so it must never be
            // persisted to shared storage). The name/JSON key stay
            // issuedAtNs for ChallengeRecord serialization stability.
            issuedAtNs: (int) (microtime(true) * 1_000_000),
            // Protocol version by decoy arm: an armed record carries the
            // decoy-capable canonical (the `|decoy_field` segment after
            // the kid), so it is protocol v3; an unarmed record keeps
            // protocol v2 with the byte-identical 18-field canonical.
            protocolVersion: $decoyField !== null ? 3 : 2,
            region: $this->region,
            policyVersion: $this->config->policyVersion,
            requestBinding: $requestBinding,
            hostname: $hostname,
            issuer: $this->config->issuer,
            kid: $this->config->kid,
            decoyField: $decoyField,
            executionProgram: $executionProgram,
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
            decoyField: $decoyField,
            executionProgram: $executionProgram,
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
     * random pool name is picked per issuance, the record is protocol v3
     * and the authenticated name rides the challenge response.
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
        string $executionVersion = '1',
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
        );
        $nowFn = $now !== null ? static fn (): int => $now : $this->now;

        // The hostname (server-owned issuance metadata) must
        // survive the profile path.
        return (new self($config, $this->storage, $nowFn, $this->region))
            ->issueWithDecoyField($scope, $clientIp, $armDecoyField, $requestBinding, $hostname, null, $armExecution, $executionAction, $executionVersion);
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
     * their 4-byte IPv4 form so both spellings of the same address
     * produce the same tag.
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

        return hash_hmac('sha256', $message, DerivedKeys::fromMaster($secret)->ipBindKey());
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
     * Canonical protocol v2 payload: the exact byte string that is signed
     * and base64-encoded into the challenge. Shared with the verifier so
     * issuance and verification can never drift apart.
     *
     * The v2 layout is byte-identical to the Rust crate's
     * `canonical_signing_input_v2`:
     *
     *     v2|nonce|scope|binding_tag|issued_at|expires_at|algorithm|m_kib|t|
     *       p|target_bits|salt|min_duration_ms|region|policy_version|
     *       request_binding|issuer|kid
     *
     * `region`, `request_binding` and `issuer` render as the empty segment
     * when unset. A null region + policy 1 + null binding + null issuer +
     * kid 1 ends the canonical with `|0||1|||1`. `kid` is the final
     * field, appended after `issuer`; it is always present (the
     * configured signing key id, default 1).
     *
     * # The decoy-field extension (protocol v3)
     *
     * When the issuer arms a decoy (honeypot) form field, the field
     * name is appended as one extra final segment after the `kid`; see
     * {@see self::issueWithDecoyField()}. Armed records are protocol
     * v3; unarmed records stay protocol v2, byte-identical to the
     * pre-decoy format.
     *
     * ```text
     * v2|nonce|scope|binding_tag|issued_at|expires_at|algorithm|m_kib|t|p|
     *   target_bits|salt|min_duration_ms|region|policy_version|request_binding|
     *   issuer|kid|decoy_field
     * ```
     *
     * - `decoy_field` is the literal armed decoy name: a grammar prefix
     * plus the 16-hex `CSPRNG` suffix (e.g.
     * `billing_address_line_a3f9c21d8e5b7401`), see
     * {@see self::composeDecoyName()}, so it can never contain
     * the `|` separator (the alphabet is `[a-z_0-9]`; validation
     * accepts `[A-Za-z0-9_-]` only, 1..=64 bytes).
     * - The segment is appended only when a decoy is armed, and the
     * protocol-vs-decoy grammar is total: v2 => no decoy, v3 => decoy
     * present. `null` renders
     * nothing extra, so the canonical string is byte-identical to the
     * pre-extension format. Outstanding unarmed challenges and
     * cross-language records keep verifying unchanged across the
     * upgrade, and the extension is invisible until a deployment opts
     * in. The exact recipe: build the same 18-field base string, then
     * append `'|' . $decoyField` if and only if the record carries a
     * non-null `decoy_field`; sign/HMAC-verify the result with the
     * `HKDF`-derived challenge key (`K_challenge`) exactly as before.
     * The stored record JSON carries the optional string key
     * `decoy_field` (absent when null — not a JSON `null` key); the
     * client-facing challenge response carries the optional key
     * `decoy_field` with the same value.
     * - Wire compatibility: unarmed records are byte-identical in both
     * directions; armed records are protocol v3 and require a
     * v3-capable verifier (an old verifier rejects version 3 as
     * unknown — the capability becomes inferable from
     * protocol_version, which is the point). The grammar is enforced on
     * both acceptance surfaces: a v2 record carrying `decoy_field` is
     * malformed, and a v3 record without one is malformed too. The
     * decoy is mandatory on v3, so a stored version flip can never
     * change the effective protocol.
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
        ?string $region = null,
        int $policyVersion = 1,
        ?string $requestBinding = null,
        ?string $issuer = null,
        int $kid = 1,
        ?string $decoyField = null,
    ): string {
        $base = sprintf(
            'v2|%s|%s|%s|%d|%d|%s|%d|%d|%d|%d|%s|%d|%s|%d|%s|%s|%d',
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
        // nothing extra, so the unarmed canonical stays byte-identical to
        // the legacy 18-field format.
        return $decoyField !== null ? $base.'|'.$decoyField : $base;
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
     * used directly as the signing key. Byte-identical to the Rust
     * crate's `sign_canonical_v2`.
     */
    public static function signPayloadV2(string $canonicalPayload, string $secretKey): string
    {
        return hash_hmac('sha256', $canonicalPayload, DerivedKeys::fromMaster($secretKey)->challengeKey());
    }

    private function effectiveTargetBits(): int
    {
        // Defensive clamp: Config already rejects out-of-range values at
        // construction, but a hand-rolled ChallengeRecord (or a future
        // config path) must not reach the solver with an unsolvable
        // difficulty.
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
