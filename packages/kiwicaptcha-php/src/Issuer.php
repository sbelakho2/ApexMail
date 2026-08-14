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
 *                {min_duration_ms}|{region}|{policy_version}|
 *                {request_binding}|{issuer}|{kid}" — region, request_binding
 *                and issuer render as the empty segment when unset,
 *                policy_version as the configured security-policy epoch
 *                (audits #42/#41/#67), kid as the configured signing key id
 *                (audit #91) — the FINAL canonical field
 *   signature  = hex(hmac_sha256(K_challenge, canonical)) — HKDF-derived
 *                purpose key (audit #21, {@see DerivedKeys}); the master
 *                secret is never used directly as the signing key
 *   challenge  = base64(canonical) . "." . signature
 *   prefix     = "{challenge}|{salt}|"
 *   target     = effective difficulty for the configured algorithm
 *   min_duration_ms = configured override or derived from difficulty
 *
 * The nonce-bound binding tag is keyed by the HKDF-derived K_ip_bind
 * purpose key (never the master secret). The record additionally carries a
 * region (deployment metadata) that IS part of the v2 canonical payload —
 * it is signed into the record like every other immutable v2 parameter
 * (see {@see self::canonicalPayload()}) — and is never sent to the client.
 *
 * Legacy v1 issuance (`protocol_version` 1, payload
 * `"{nonce}|{scope}|{ip_hash}|{issued_at}"`) is not produced anymore, but
 * the v1 helpers remain: {@see self::hashIp()} computes the legacy IP hash
 * and {@see self::signPayload()} the legacy master-key signature, so v1
 * records (and the verifier's v1 path) keep working during the migration
 * window — byte-identical to the Rust crate's v1 path.
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
        /**
         * Deployment region bound to every issued record (e.g. "eu").
         * Null = region-unbound. The record's `region` JSON key is always
         * present (null when unbound) for parity with the Rust schema; a
         * verifier configured with an expected region rejects records whose
         * region does not match exactly. Must match the narrow identifier
         * alphabet (audit #96) — at most 64 bytes of [A-Za-z0-9._:-].
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
     * @throws \InvalidArgumentException when the scope is empty, longer than
     *                                   128 bytes, or outside the identifier
     *                                   alphabet [A-Za-z0-9._:-] (audit #96);
     *                                   when the request binding is longer
     *                                   than 128 bytes or outside the same
     *                                   alphabet
     */
    public function issue(string $scope, string $clientIp, ?string $requestBinding = null): Challenge
    {
        $scopeLen = \strlen($scope);
        if ($scopeLen < 1 || $scopeLen > 128) {
            throw new \InvalidArgumentException('scope must be 1-128 bytes');
        }
        // Audit #96: the narrow identifier alphabet subsumes the legacy '|'
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
            $this->region,
            $this->config->policyVersion,
            $requestBinding,
            $this->config->issuer,
            $this->config->kid,
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
            // issuedAtNs = epoch MICROseconds since Unix epoch (wall clock,
            // hrtime(true) is monotonic and per-host so it must never be
            // persisted to shared storage — see README "server timing").
            // The name/JSON key stay issuedAtNs for ChallengeRecord
            // serialization stability.
            issuedAtNs: (int) (microtime(true) * 1_000_000),
            protocolVersion: 2,
            region: $this->region,
            policyVersion: $this->config->policyVersion,
            requestBinding: $requestBinding,
            issuer: $this->config->issuer,
            kid: $this->config->kid,
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
        ?string $requestBinding = null,
    ): Challenge {
        $profile->validate();

        // Server-owned difficulty floors (audit #25): a client-reported
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

        return (new self($config, $this->storage, $nowFn, $this->region))->issue($scope, $clientIp, $requestBinding);
    }

    /**
     * Protocol v2 nonce-bound IP binding tag.
     *
     * HMAC-SHA256 over the CANONICAL form of the client IP, keyed by the
     * HKDF-derived IP-binding purpose key (K_ip_bind — audit #21,
     * {@see DerivedKeys}; never the master secret itself) and bound to the
     * challenge nonce — so the stored binding is unique per challenge and
     * never a stable identifier that follows the client across requests.
     * IPv4-mapped IPv6 addresses (`::ffff:a.b.c.d`) are normalized to their
     * 4-byte IPv4 form so both spellings of the same address produce the
     * same tag.
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
     * Canonical protocol v2 payload — the exact byte string that is signed
     * and base64-encoded into the challenge. Shared with the verifier so
     * issuance and verification can never drift apart.
     *
     * Round-11 layout (audits #41/#42/#67/#91), byte-identical to the Rust
     * crate's `canonical_signing_input_v2`:
     *
     *     v2|nonce|scope|binding_tag|issued_at|expires_at|algorithm|m_kib|t|
     *       p|target_bits|salt|min_duration_ms|region|policy_version|
     *       request_binding|issuer|kid
     *
     * with `region`, `request_binding` and `issuer` rendering as the EMPTY
     * segment when unset — so a null region + policy 1 + null binding +
     * null issuer + kid 1 ends the canonical with `|0||1|||1`. `kid` is
     * the FINAL field (audit #91), appended AFTER `issuer`; it is ALWAYS
     * present (the configured signing key id, default 1).
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
    ): string {
        return sprintf(
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
     * Legacy v1 signature: hex HMAC-SHA256 of the v1 canonical payload with
     * the MASTER secret used directly as the key — byte-identical to the
     * Rust crate's v1 path (the historical format; v1 is only kept for the
     * migration window). Protocol v2 signatures use the HKDF-derived
     * challenge key via {@see self::signPayloadV2()}.
     */
    public static function signPayload(string $canonicalPayload, string $secretKey): string
    {
        return hash_hmac('sha256', $canonicalPayload, $secretKey);
    }

    /**
     * Protocol v2 signature: hex HMAC-SHA256 of the canonical v2 payload
     * keyed by the HKDF-derived challenge-signing purpose key (K_challenge,
     * audit #21 — {@see DerivedKeys}; the master secret is never used
     * directly as the signing key). Byte-identical to the Rust crate's
     * `sign_canonical_v2`.
     */
    public static function signPayloadV2(string $canonicalPayload, string $secretKey): string
    {
        return hash_hmac('sha256', $canonicalPayload, DerivedKeys::fromMaster($secretKey)->challengeKey());
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
