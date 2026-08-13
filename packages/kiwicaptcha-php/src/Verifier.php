<?php

declare(strict_types=1);

namespace KiwiCaptcha;

/**
 * Verifies client-submitted solutions — byte-for-byte compatible with the
 * Rust crate's `verify_solution`.
 *
 * Verification is ONE-SHOT: any verification attempt burns the challenge
 * record. The cheap checks (record structure, signature, TTL, scope,
 * binding, server timing, telemetry) run against a PEEKED record and delete
 * it on failure; the proof phase consumes the record before re-deriving the
 * hash — so a wrong candidate burns the challenge and the client must fetch
 * and solve a fresh one. This deliberately bounds the server-side cost of
 * memory-hard verification: each submitted token can cost at most one
 * Argon2id (or SHA-256) hash, and replaying a token always fails with
 * RecordNotFound. There is no maxAttempts parameter: the one-shot model IS
 * the attempt bound.
 *
 * STRICT single-use under concurrency requires an AtomicStorageInterface
 * backend (e.g. Redis GETDEL): the load-and-remove is fused, so two racing
 * requests can never both win the record. PSR-6-backed consume() is
 * best-effort — the read and the delete cannot be fused, so racing requests
 * may both observe the record. The TOCTOU challenge re-check in the proof
 * phase makes a swapped record fail closed (MalformedRecord) either way.
 *
 * Check order:
 *   1. Structural validation of the stored record: scope shape, nonce/salt
 *      sizes, TTL ceiling (MAX_TTL_SECS), prefix binding, and the
 *      per-algorithm difficulty range.
 *   2. Re-check the challenge HMAC signature (constant-time compare) —
 *      protocol v1 payloads use the legacy canonical form signed with the
 *      master key, protocol v2 uses the full-parameter canonical payload
 *      signed with the HKDF-derived K_challenge.
 *   2b. Absolute Argon2id process ceilings (audit #32): the SIGNED
 *      parameters are checked against MIN/MAX_ARGON_* AFTER signature
 *      authentication and BEFORE any allocation — out-of-range yields
 *      UnsupportedArgon2Params.
 *   3. TTL: now < expires_at.
 *   4. Scope: challenge scope matches the expected flow.
 *   5. IP binding: v2 records recompute the nonce-bound binding tag (keyed
 *      by the HKDF-derived K_ip_bind); v1 records compare the legacy IP
 *      hash. An empty binding tag disables the check; with a nonempty
 *      binding tag a missing client IP fails closed (MissingClientIp) — a
 *      null IP NEVER skips the binding.
 *   5b. Region binding (audit #22, Option A): a verifier configured with an
 *      expected region rejects any record whose region does not match
 *      exactly (WrongRegion) — including unbound (NULL) records, which are
 *      redeemable in every region.
 *   6. Minimum duration: measured SERVER-SIDE from the record's issued_at_ns
 *      (epoch microseconds) to the verification receipt time — the
 *      client-reported duration can no longer be forged to bypass the
 *      floor, and records without issued_at_ns are malformed (no legacy
 *      client-duration fallback). Host clock skew up to SKEW_TOLERANCE_US
 *      is absorbed (the floor check is skipped, the PoW check still
 *      applies); a receipt time that precedes issuance beyond the tolerance
 *      is impossible and rejected as TooFast.
 *   7. Telemetry (optional, opt-in): when enforceTelemetry is set, the
 *      client-controlled telemetry is scored and bot signals rejected.
 *   8. Argon2id admission gate (optional): when a VerificationAdmissionGate
 *      is configured, it must grant capacity before the memory-hard hash
 *      runs; exhaustion yields CapacityExceeded WITHOUT burning the record.
 *   9. Consume the record, re-derive the hash (SHA-256 or Argon2id per the
 *      record's algorithm), and require >= target_bits leading zero bits.
 */
final class Verifier
{
    /**
     * Host-clock skew tolerance for the server-measured minimum-duration
     * check, in MICROSECONDS.
     *
     * issued_at_ns is a wall-clock timestamp written by whichever host
     * issued the challenge; verification may run on a different host whose
     * clock is slightly behind. A receipt time that precedes issuance by
     * less than the tolerance is therefore treated as unmeasurable elapsed
     * time (the floor check is skipped for that verification — the PoW
     * check still applies), while a receipt time preceding issuance by
     * MORE than the tolerance is physically impossible and rejected as
     * TooFast. Hosts should be NTP-synced; 5s of skew is a generous bound.
     */
    private const SKEW_TOLERANCE_US = 5_000_000;

    /**
     * Hard ceiling for a stored record's lifetime (expires_at - issued_at).
     * Issuance uses the configured TTL (default 120s); anything beyond 300s
     * cannot come from a KiwiCaptcha issuer and is rejected as malformed.
     */
    private const MAX_TTL_SECS = Config::MAX_TTL_SECS;

    /**
     * Absolute process ceilings for Argon2id parameters (audit #32).
     *
     * After the challenge signature is authenticated, the signed parameters
     * are validated against these hard bounds BEFORE any memory allocation
     * or computation: out-of-range values yield UnsupportedArgon2Params.
     * The issuance side never mints outside the browser-solvable profile
     * (Config/ChallengeProfile), so a signed record violating a ceiling is
     * foreign or corrupt. MAX_ARGON_TIME (16) is the process ceiling — the
     * browser solver caps at 6 (Config::MAX_ARGON_T, issuance-side).
     */
    public const MIN_ARGON_MEMORY_KIB = 8;

    public const MAX_ARGON_MEMORY_KIB = 65536;

    public const MIN_ARGON_TIME = 3;

    public const MAX_ARGON_TIME = 16;

    public const MIN_PARALLELISM = 1;

    public const MAX_PARALLELISM = 4;

    /**
     * @var \Closure|null clock override for tests
     */
    private $now;

    private readonly ?VerificationAdmissionGate $argonGate;

    public function __construct(
        private readonly StorageInterface $storage,
        $argonGate = null,
        ?\Closure $now = null,
        /**
         * Accept protocol-v1 (legacy) challenges. v2 has been the issuance
         * format for longer than the maximum challenge lifetime (300 s), so
         * no legitimate v1 record can still exist — v1 is rejected by
         * default. Set this ONLY during a coordinated migration window.
         */
        private readonly bool $acceptLegacyV1 = false,
        /**
         * Expected deployment region (e.g. "eu"). When non-null, a record
         * whose `region` does not match EXACTLY — including a NULL
         * (unbound) record region — is rejected with WrongRegion: a
         * region-bound challenge is never redeemable elsewhere or on an
         * unbound record. Null (default) disables the check entirely.
         */
        private readonly ?string $region = null,
    ) {
        // BC shim: pre-gate callers passed the clock override positionally
        // as the second argument. A Closure in that slot is $now, not an
        // admission gate (the parameter is intentionally untyped so the
        // Closure can reach this branch — the type check happens below).
        if ($argonGate instanceof \Closure) {
            $now = $argonGate;
            $argonGate = null;
        }
        if ($argonGate !== null && !$argonGate instanceof VerificationAdmissionGate) {
            throw new \TypeError(sprintf(
                'Verifier::__construct(): Argument #2 ($argonGate) must be of type ?KiwiCaptcha\VerificationAdmissionGate, %s given',
                get_debug_type($argonGate),
            ));
        }
        $this->argonGate = $argonGate;
        $this->now = $now;
    }

    /**
     * @param string      $rawToken        base64 solution token from the widget
     * @param string      $secretKey       HMAC secret key
     * @param string|null $expectedScope   required challenge scope (null = any)
     * @param string|null $clientIp        client IP for the optional IP binding
     * @param int|null    $nowNs           server receipt time in epoch
     *                                     MICROSECONDS (defaults to
     *                                     microtime(true) * 1e6); used for
     *                                     the server-measured minimum-duration
     *                                     check. Test hook.
     * @param bool        $enforceTelemetry when true, bot-signal telemetry is
     *                                     rejected with TelemetryRejected.
     *                                     Telemetry is client-controlled, so
     *                                     enforcement is opt-in defense-in-depth
     *                                     only.
     *
     * One-shot model: cheap-check failures delete the peeked record; the
     * proof phase consumes it before the hash is re-derived. A failed
     * verification burns the challenge (no maxAttempts parameter — the
     * one-shot semantics ARE the attempt bound).
     */
    public function verify(
        string $rawToken,
        string $secretKey,
        ?string $expectedScope = null,
        ?string $clientIp = null,
        ?int $nowNs = null,
        bool $enforceTelemetry = false,
    ): VerifyOutcome {
        try {
            $token = SolutionToken::decode($rawToken);
        } catch (DecodeError $e) {
            return VerifyOutcome::malformedToken($e->getMessage());
        }

        try {
            $peek = $this->storage->find($token->nonce);
        } catch (\Throwable) {
            // Backend failure: typed result, challenge presumed intact
            // (the client can retry once storage recovers).
            return VerifyOutcome::invalid(VerifyError::StorageUnavailable);
        }
        if ($peek === null) {
            return VerifyOutcome::invalid(VerifyError::RecordNotFound);
        }

        if (!$this->validateRecord($peek)) {
            $this->bestEffortDelete($token->nonce);

            return VerifyOutcome::invalid(VerifyError::MalformedRecord);
        }

        // 1b. Protocol version gate: v1 (legacy, less comprehensively
        //     signed) is only accepted during an explicit migration window —
        //     v2 has been the issuance format longer than the maximum
        //     challenge lifetime, so any surviving v1 record is stale or
        //     foreign.
        if ($peek->protocolVersion === 1 && !$this->acceptLegacyV1) {
            $this->bestEffortDelete($token->nonce);

            return VerifyOutcome::invalid(VerifyError::MalformedRecord);
        }

        // 2. Signature re-check: reconstruct the payload from the record and
        //    compare against the signature embedded in the challenge string.
        //    Protocol v1 uses the legacy canonical form; protocol v2 uses the
        //    full-parameter canonical payload.
        if (!$this->verifyRecordSignature($peek, $secretKey)) {
            $this->bestEffortDelete($token->nonce);

            return VerifyOutcome::invalid(VerifyError::BadSignature);
        }

        // 2b. Absolute Argon2id process ceilings (audit #32): the SIGNED
        //     parameters are validated AFTER signature authentication and
        //     BEFORE any allocation or computation. Out-of-range values are
        //     authentic-but-unsupported — UnsupportedArgon2Params, not
        //     MalformedRecord (the record really came from an issuer holding
        //     the secret, it just violates the hard process limits).
        if (!$this->argon2CeilingsOk($peek)) {
            $this->bestEffortDelete($token->nonce);

            return VerifyOutcome::invalid(VerifyError::UnsupportedArgon2Params);
        }

        // 3. TTL.
        $now = $this->now !== null ? (int) ($this->now)() : time();
        if ($now >= $peek->expiresAt) {
            $this->bestEffortDelete($token->nonce);

            return VerifyOutcome::invalid(VerifyError::Expired);
        }

        // 4. Scope validation.
        if ($expectedScope !== null && $peek->scope !== $expectedScope) {
            $this->bestEffortDelete($token->nonce);

            return VerifyOutcome::invalid(VerifyError::WrongScope);
        }

        // 5. IP binding. The stored record is AUTHORITATIVE: an empty
        //    binding tag means binding is disabled (BindingMode::None);
        //    a NON-EMPTY tag means the challenge IS bound, so a missing
        //    client IP fails closed (MissingClientIp) instead of silently
        //    skipping the check — the caller must provide the IP it would
        //    have passed to issuance. Protocol v2 records carry a nonce-bound
        //    binding tag (recomputed here); v1 records carry the legacy
        //    stable IP hash.
        if ($peek->bindingTag !== '') {
            if ($clientIp === null) {
                return VerifyOutcome::invalid(VerifyError::MissingClientIp);
            }
            $expectedTag = $peek->protocolVersion === 1
                ? Issuer::hashIp($clientIp, $secretKey)
                : Issuer::bindingTag($peek->nonce, $clientIp, $secretKey);
            if (!hash_equals($expectedTag, $peek->bindingTag)) {
                $this->bestEffortDelete($token->nonce);

                return VerifyOutcome::invalid(VerifyError::IpMismatch);
            }
        }

        // 5b. Region binding (audit #22, Option A): a verifier configured
        //     with an expected region rejects any record whose region does
        //     not match EXACTLY — an unbound (NULL) record region fails
        //     closed, because a region-unbound record is redeemable in every
        //     region and must not satisfy a region-bound verifier.
        if ($this->region !== null && $peek->region !== $this->region) {
            $this->bestEffortDelete($token->nonce);

            return VerifyOutcome::invalid(VerifyError::WrongRegion);
        }

        // 6. Minimum duration, measured on the SERVER: elapsed_us is the gap
        //    between the record's high-resolution issuance timestamp (epoch
        //    microseconds) and the verification receipt time. The
        //    client-reported durationMs is forgeable, so it no longer drives
        //    the TooFast check and there is no legacy fallback — a record
        //    without issued_at_ns cannot be timed and is malformed.
        if ($peek->issuedAtNs <= 0) {
            $this->bestEffortDelete($token->nonce);

            return VerifyOutcome::invalid(VerifyError::MalformedRecord);
        }
        $floor = max(0, $peek->minDurationMs);
        if ($floor > 0) {
            $receiptNs = $nowNs ?? (int) (microtime(true) * 1_000_000);
            if ($receiptNs >= $peek->issuedAtNs) {
                if ($receiptNs - $peek->issuedAtNs < $floor * 1_000) {
                    $this->bestEffortDelete($token->nonce);

                    return VerifyOutcome::invalid(VerifyError::TooFast);
                }
            } elseif ($peek->issuedAtNs - $receiptNs > self::SKEW_TOLERANCE_US) {
                // Receipt before issuance by more than the skew bound is
                // physically impossible — reject as TooFast. Within the
                // bound the two hosts' clocks are unsynced, so the elapsed
                // time cannot be measured reliably and the floor check is
                // skipped for this verification — the proof-of-work check
                // still applies, so no attacker advantage is gained.
                $this->bestEffortDelete($token->nonce);

                return VerifyOutcome::invalid(VerifyError::TooFast);
            }
        }

        // 7. Telemetry scoring (opt-in). The telemetry is client-controlled,
        //    so this is a defense-in-depth signal, not a hard gate — it only
        //    runs when the caller explicitly opts in. An EMPTY telemetry
        //    payload ({} or []) is itself a bot signal (a real widget always
        //    reports fields): it must not bypass strict mode.
        if ($enforceTelemetry && (empty($token->telemetry) || Telemetry::score($token->telemetry, $token->durationMs))) {
            $this->bestEffortDelete($token->nonce);

            return VerifyOutcome::invalid(VerifyError::TelemetryRejected);
        }

        // 8. Argon2id admission: the memory-hard hash is expensive, so an
        //    optional gate bounds concurrency. Exhaustion rejects WITHOUT
        //    consuming or deleting the record — the client can retry.
        $lease = null;
        if ($peek->algorithm === PoWAlgorithm::Argon2id && $this->argonGate !== null) {
            try {
                $lease = $this->argonGate->acquire();
            } catch (\Throwable) {
                // Backend failure: report a typed, NON-CONSUMING result so
                // the challenge stays intact and can be retried after the
                // admission backend recovers (never propagate, never treat
                // the failure as full free capacity).
                return VerifyOutcome::invalid(VerifyError::AdmissionUnavailable);
            }
            if ($lease === null) {
                return VerifyOutcome::invalid(VerifyError::CapacityExceeded);
            }
        }

        try {
            // 9. Consume (one-shot) and re-derive the proof.
            try {
                $record = $this->storage->consume($token->nonce);
            } catch (\Throwable) {
                // A lost GETDEL response is intrinsically ambiguous: the
                // challenge may or may not have been consumed. Report the
                // indeterminate state instead of RecordNotFound.
                return VerifyOutcome::invalid(VerifyError::ConsumeIndeterminate);
            }
            if ($record === null) {
                return VerifyOutcome::invalid(VerifyError::RecordNotFound);
            }
            // TOCTOU guard: the consumed instance must be the SAME challenge
            // we validated and HMAC-checked via peek. Because the v2 HMAC
            // signs EVERY immutable parameter, full re-validation + signature
            // re-verification on the consumed instance is the robust check —
            // a swapped/racing record fails closed instead of verifying
            // against bytes that were never validated.
            if (
                !hash_equals($peek->challenge, $record->challenge)
                || !$this->validateRecord($record)
                || !$this->verifyRecordSignature($record, $secretKey)
            ) {
                return VerifyOutcome::invalid(VerifyError::MalformedRecord);
            }

            // The allocation gate sits at the computation site too: the
            // consumed instance's signed parameters must satisfy the hard
            // ceilings before the memory-hard hash runs.
            if (!$this->argon2CeilingsOk($record)) {
                return VerifyOutcome::invalid(VerifyError::UnsupportedArgon2Params);
            }

            $hash = $this->deriveHash($record, $token->counter);
            if ($hash === null) {
                // An Argon2id record whose parameters are within the ceilings
                // but cannot be represented by the libsodium-backed verifier
                // (p != 1) is authentic-but-unsupported. A SHA-256 null can
                // only be a salt-decode failure (already shape-validated) —
                // malformed.
                return VerifyOutcome::invalid($record->algorithm === PoWAlgorithm::Argon2id
                    ? VerifyError::UnsupportedArgon2Params
                    : VerifyError::MalformedRecord);
            }
            if (self::leadingZeroBits($hash) < $record->targetBits) {
                return VerifyOutcome::invalid(VerifyError::InsufficientWork);
            }

            return VerifyOutcome::valid($token->nonce);
        } finally {
            if ($lease !== null) {
                try {
                    $this->argonGate?->release($lease);
                } catch (\Throwable) {
                    // Best-effort: a failed release must NEVER override the
                    // verification result (the challenge is already
                    // consumed). A leaked lease is recovered by its TTL.
                }
            }
        }
    }

    /**
     * Structural validation of a stored record BEFORE any crypto or timing
     * work: scope shape, nonce/salt sizes, TTL ceiling, the prefix binding,
     * and the per-algorithm difficulty range. A record failing any check is
     * malformed — it cannot have come from a KiwiCaptcha issuer.
     *
     * Argon2id memory/time/parallelism are NOT bounded here anymore: the
     * absolute process ceilings (audit #32) apply to the SIGNED parameters
     * AFTER signature authentication ({@see self::argon2CeilingsOk()}),
     * so a validly-signed out-of-range record is reported as
     * UnsupportedArgon2Params rather than MalformedRecord, while unsigned
     * foreign records fail the signature check.
     */
    private function validateRecord(ChallengeRecord $record): bool
    {
        // Protocol version is part of the wire contract: only 1 (legacy,
        // migration window) and 2 (current) exist. Anything else is a
        // corrupt/foreign record.
        if ($record->protocolVersion !== 1 && $record->protocolVersion !== 2) {
            return false;
        }
        $scopeLen = \strlen($record->scope);
        if ($scopeLen < 1 || $scopeLen > 128 || \str_contains($record->scope, '|')) {
            return false;
        }
        $nonceBytes = base64_decode($record->nonce, true);
        if ($nonceBytes === false || \strlen($nonceBytes) !== 32) {
            return false;
        }
        $saltBytes = base64_decode($record->salt, true);
        if ($saltBytes === false || \strlen($saltBytes) !== 16) {
            return false;
        }
        if ($record->expiresAt <= $record->issuedAt || $record->expiresAt - $record->issuedAt > self::MAX_TTL_SECS) {
            return false;
        }
        if (!hash_equals($record->challenge.'|'.$record->salt.'|', $record->prefix)) {
            return false;
        }
        if ($record->algorithm === PoWAlgorithm::Argon2id) {
            if ($record->targetBits < 1 || $record->targetBits > 10) {
                return false;
            }
        } elseif ($record->targetBits < 1 || $record->targetBits > 20) {
            return false;
        }

        return true;
    }

    /**
     * Absolute process ceilings for Argon2id parameters (audit #32) — the
     * SIGNED record's memory/time/parallelism must sit within
     * [MIN..MAX]_ARGON_* before any allocation or computation. Runs after
     * signature authentication (cheap phase) and again at the computation
     * site (proof phase). Returns true for SHA-256 records.
     */
    private function argon2CeilingsOk(ChallengeRecord $record): bool
    {
        if ($record->algorithm !== PoWAlgorithm::Argon2id) {
            return true;
        }

        return $record->mKib >= self::MIN_ARGON_MEMORY_KIB
            && $record->mKib <= self::MAX_ARGON_MEMORY_KIB
            && $record->t >= self::MIN_ARGON_TIME
            && $record->t <= self::MAX_ARGON_TIME
            && $record->p >= self::MIN_PARALLELISM
            && $record->p <= self::MAX_PARALLELISM;
    }

    /**
     * Re-derive the proof-of-work hash.
     *
     * SHA-256: hash(prefix || decimal(counter) || salt_bytes)
     * Argon2id: argon2id(password=prefix||decimal(counter), salt=salt_bytes,
     *           m_cost=m_kib KiB, t_cost=t, p_cost=p, output=32 bytes)
     *
     * Returns null when the record is malformed or the algorithm cannot be
     * computed (e.g. Argon2id parameters outside KiwiCaptcha's protocol
     * profile — t < 3 or p != 1).
     */
    /**
     * Terminal cheap-failure cleanup. Deletion is NOT security-critical
     * once the challenge has been rejected, and a storage outage must not
     * turn a cheap invalid submission into an application exception — the
     * typed VerifyOutcome already returned stands.
     */
    private function bestEffortDelete(string $nonce): void
    {
        try {
            $this->storage->delete($nonce);
        } catch (\Throwable) {
        }
    }

    private function deriveHash(ChallengeRecord $record, int $counter): ?string
    {
        $saltBytes = base64_decode($record->salt, true);
        if ($saltBytes === false) {
            return null;
        }
        $password = $record->prefix.$counter;

        return match ($record->algorithm) {
            PoWAlgorithm::Sha256 => hash('sha256', $password.$saltBytes, true),
            PoWAlgorithm::Argon2id => $this->argon2id($password, $saltBytes, $record),
        };
    }

    private function argon2id(string $password, string $saltBytes, ChallengeRecord $record): ?string
    {
        // KiwiCaptcha's protocol profile is p == 1 && t >= 3 (t >= 3 is
        // intentional, not a libsodium limit — libsodium accepts t >= 1).
        // Parameters outside the profile cannot be reproduced by the
        // libsodium-backed verifier, so fail closed with a distinguishable
        // error instead of silently verifying wrong bytes.
        if ($record->p !== 1 || $record->t < 3) {
            return null;
        }
        // Protocol unit: m_kib is KIBIBYTES (65536 = 64 MiB). sodium's
        // memlimit is in bytes, so convert once (mKib KiB -> bytes).
        $memlimit = $record->mKib * 1024;
        if ($memlimit < 8192) {
            return null;
        }

        $hash = sodium_crypto_pwhash(
            32,
            $password,
            $saltBytes,
            $record->t,
            $memlimit,
            SODIUM_CRYPTO_PWHASH_ALG_ARGON2ID13,
        );

        return $hash === false ? null : $hash;
    }

    /**
     * Recompute the expected HMAC signature for a record (per its protocol
     * version) and compare it constant-time against the signature embedded
     * in the challenge string. Because the v2 canonical payload covers EVERY
     * immutable parameter, a valid signature proves the whole record is
     * authentic — used in the cheap phase AND re-applied to the CONSUMED
     * instance (TOCTOU guard).
     */
    private function verifyRecordSignature(ChallengeRecord $record, string $secretKey): bool
    {
        $expected = $record->protocolVersion === 1
            ? Issuer::signPayload(sprintf(
                '%s|%s|%s|%d',
                $record->nonce,
                $record->scope,
                $record->ipHash(),
                $record->issuedAt,
            ), $secretKey)
            : Issuer::signPayloadV2(Issuer::canonicalPayload(
                $record->nonce,
                $record->scope,
                $record->bindingTag,
                $record->issuedAt,
                $record->expiresAt,
                $record->algorithm,
                $record->mKib,
                $record->t,
                $record->p,
                $record->targetBits,
                $record->salt,
                $record->minDurationMs,
            ), $secretKey);

        return hash_equals($expected, self::signatureFromChallenge($record->challenge));
    }

    /**
     * The signature is the hex tag after the last '.' in the challenge string
     * (the base64 payload contains no dots).
     */
    private static function signatureFromChallenge(string $challenge): string
    {
        $pos = strrpos($challenge, '.');
        if ($pos === false) {
            return '';
        }

        return substr($challenge, $pos + 1);
    }

    /**
     * Constant-time string comparison (XOR accumulation, no short-circuit).
     */
    public static function constantTimeEquals(string $a, string $b): bool
    {
        return hash_equals($a, $b);
    }

    /**
     * Count leading zero BITS of a 32-byte hash (big-endian bit order) —
     * identical to Rust's leading_zero_bits.
     */
    public static function leadingZeroBits(string $hash): int
    {
        $count = 0;
        $len = \strlen($hash);
        for ($i = 0; $i < $len; $i++) {
            $byte = \ord($hash[$i]);
            if ($byte === 0) {
                $count += 8;
                continue;
            }
            $b = $byte;
            while (($b & 0x80) === 0) {
                $count++;
                $b <<= 1;
            }
            break;
        }

        return $count;
    }
}
