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
  *                key id, the final canonical field. When a decoy
  *                (honeypot) field is armed, see
  *                {@see self::issueWithDecoyField()}, exactly one more
  *                segment is appended after the kid:
  *                ...|{issuer}|{kid}|{decoy_field} — see
  *                {@see self::canonicalPayload()}.
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
     * The server-side pool of decoy (honeypot) form-field names. When a
     * deployment arms the decoy surface, see
     * {@see self::issueWithDecoyField()}, the issuer picks one name
     * uniformly at random (`CSPRNG`) per issuance. The names look like
     * ordinary optional form fields a generic bot filler would populate,
     * while a human never sees them: the widget driver renders the chosen
     * name as a hidden, never-auto-filled text input.
     *
     * The pool alphabet is deliberately `[a-z_]`, a subset of the
     * `[A-Za-z0-9_-]{1,64}` shape the widget driver accepts and of the
     * validation alphabet, see {@see Config::isValidDecoyFieldName()}.
     * No pool name can ever smuggle the `|` canonical-payload separator
     * or any other structurally meaningful character. PHP maintains the
     * identical pool (same names, same order) as the Rust
     * `DECOY_FIELD_POOL`. The picked name is authenticated by the v2
     * signature, so the two cores never need to agree on the pick, only
     * on the pool's alphabet and the canonical-format extension
     * documented on {@see self::canonicalPayload()}.
     */
    public const DECOY_FIELD_POOL = [
        'company_website',
        'fax_number',
        'secondary_phone',
        'office_extension',
        'alternate_email',
        'home_address_line',
        'middle_name',
        'assistant_name',
        'department_code',
        'backup_phone',
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
     * issuer picks a random field name from the server-side
     * {@see self::DECOY_FIELD_POOL}, `CSPRNG`, a fresh independent pick
     * per issuance so two challenges never share a predictable decoy.
     * The name is set on the client-facing
     * {@see Challenge::$decoyField}, the key the widget driver renders
     * the hidden input from, and on the stored record's authenticated
     * {@see ChallengeRecord::$decoyField}. It is signed into the v2
     * canonical input as the final `|<decoy_field>` segment. A client
     * cannot strip or swap the decoy without breaking the signature the
     * verifier re-checks. `false` (or
     * the plain {@see self::issue()}) behaves exactly like the legacy
     * path: no decoy, byte-identical canonical string, and neither JSON
     * surface carries the key.
     */
    public function issueWithDecoyField(
        string $scope,
        string $clientIp,
        bool $armDecoyField = true,
        ?string $requestBinding = null,
        ?string $hostname = null,
    ): Challenge {
        return $this->issueChallenge(
            $scope,
            $clientIp,
            $requestBinding,
            $hostname,
            $armDecoyField ? self::pickDecoyField() : null,
        );
    }

    /**
     * Pick a random decoy field name from {@see self::DECOY_FIELD_POOL}
     * with the `CSPRNG`, `random_int`, never a weak or insecure
     * fallback. An RNG failure propagates to the caller as a
     * Random\RandomException, exactly like the nonce/salt draws.
     * Mirrors the Rust `pick_decoy_field`.
     */
    private static function pickDecoyField(): string
    {
        return self::DECOY_FIELD_POOL[random_int(0, \count(self::DECOY_FIELD_POOL) - 1)];
    }

    /**
     * The shared issuance body, see the {@see self::issue()} contract;
     * `$decoyField` is the already-picked honeypot name, or null for the
     * legacy unarmed path.
     */
    private function issueChallenge(
        string $scope,
        string $clientIp,
        ?string $requestBinding,
        ?string $hostname,
        ?string $decoyField,
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
            protocolVersion: 2,
            region: $this->region,
            policyVersion: $this->config->policyVersion,
            requestBinding: $requestBinding,
            hostname: $hostname,
            issuer: $this->config->issuer,
            kid: $this->config->kid,
            decoyField: $decoyField,
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
     * the parameters differ.
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
        );
        $nowFn = $now !== null ? static fn (): int => $now : $this->now;

        // The hostname (server-owned issuance metadata) must
        // survive the profile path.
        return (new self($config, $this->storage, $nowFn, $this->region))->issue($scope, $clientIp, $requestBinding, $hostname);
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
     * # The decoy-field extension
     *
     * When the issuer arms a decoy (honeypot) form field, the field
     * name is appended as one extra final segment after the `kid`; see
     * {@see self::issueWithDecoyField()}.
     *
     * ```text
     * v2|nonce|scope|binding_tag|issued_at|expires_at|algorithm|m_kib|t|p|
     *   target_bits|salt|min_duration_ms|region|policy_version|request_binding|
     *   issuer|kid|decoy_field
     * ```
     *
     * - `decoy_field` is the literal decoy name (e.g. `company_website`),
     * drawn from {@see self::DECOY_FIELD_POOL}, so it can never contain
     * the `|` separator (the pool alphabet is `[a-z_]`; validation
     * accepts `[A-Za-z0-9_-]` only, 1..=64 bytes).
     * - The segment is appended only when a decoy is armed. `null` renders
     * nothing extra, so the canonical string is byte-identical to the
     * pre-extension format. Outstanding challenges and cross-language
     * records keep verifying unchanged across the upgrade, and the
     * extension is invisible until a deployment opts in. The exact
     * recipe: build the same 18-field base string, then append
     * `'|' . $decoyField` if and only if the record carries a non-null
     * `decoy_field`; sign/HMAC-verify the result with the `HKDF`-derived
     * challenge key (`K_challenge`) exactly as before. The stored record
     * JSON carries the optional string key `decoy_field` (absent when
     * null — not a JSON `null` key); the client-facing challenge response
     * carries the optional key `decoy_field` with the same value.
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
