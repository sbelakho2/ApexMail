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
 * Argon2id (or SHA-256) hash. Replay protection is the CONSUMED marker, not
 * absence (audit #74): the record survives until its TTL carrying the
 * deterministic verification result, so a retry returns the SAME outcome
 * (Valid/InsufficientWork) without re-deriving; a consumed record without a
 * committed result (crash between consume and commit) is reported as
 * ConsumeIndeterminate. There is no maxAttempts parameter: the one-shot
 * model IS the attempt bound.
 *
 * STRICT single-use under concurrency requires an AtomicStorageInterface
 * backend (e.g. Redis): the load-and-transition is fused, so two racing
 * requests can never both win the consume transition. PSR-6-backed consume()
 * is best-effort — the read and the transition cannot be fused, so racing
 * requests may both observe the pending record. The TOCTOU challenge
 * re-check in the proof phase makes a swapped record fail closed
 * (MalformedRecord) either way.
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
 *   3. TTL: now < expires_at AND now >= issued_at - MAX_CLOCK_SKEW (audit
 *      #76: a signed challenge claiming to be issued more than 60s in the
 *      future is invalid).
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
 *   5c. Security-policy epoch (audit #42) and deployment issuer (audit
 *      #67): a verifier configured with an expected policy epoch / issuer
 *      rejects records issued under a different epoch / by a different
 *      deployment (WrongPolicyVersion / WrongIssuer).
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
 *   9. Consume the record (one-shot transition), re-derive the hash
 *      (SHA-256 or Argon2id per the record's algorithm), and require >=
 *      target_bits leading zero bits. A retry on an already-consumed record
 *      returns its committed deterministic result (Valid/InsufficientWork)
 *      without re-deriving, or ConsumeIndeterminate when no result was
 *      committed.
 *  10. POST-DERIVE FINAL REVALIDATION (audit #59): after the proof derives
 *      successfully and BEFORE returning Valid, re-check with the CURRENT
 *      server clock (the verifier's now closure) and the CURRENT
 *      expectations: the challenge must not have expired during the
 *      expensive derivation (Expired), and the expected policy epoch,
 *      region, and issuer must still match — a rotation landing mid-
 *      derivation fails the re-check. Only then is the deterministic
 *      result committed (best-effort) and Valid returned.
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
     * Maximum tolerated FUTURE skew for a record's issuance timestamp
     * (audit #76): a signed challenge claiming issued_at > now + 60s cannot
     * have come from a real issuer host (even under clock drift) and is
     * rejected by the TTL check as Expired.
     */
    public const MAX_CLOCK_SKEW = 60;

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
        private ?string $region = null,
        /**
         * The CURRENT security-policy epoch (audit #42). When non-null, a
         * record whose `policy_version` differs is rejected with
         * WrongPolicyVersion — outstanding challenges die immediately on
         * policy revocation (origin/action-policy changes, emergency
         * revocation, compromised tenant). Null (default) disables the check.
         */
        private ?int $expectedPolicyVersion = null,
        /**
         * Expected deployment issuer (audit #67). When non-null, a record
         * whose `issuer` does not match EXACTLY — including a NULL (unbound)
         * record issuer — is rejected with WrongIssuer: a dev/staging/prod
         * compartment that holds even when deployments share secret keys.
         * Null (default) disables the check.
         */
        private ?string $expectedIssuer = null,
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

        // 3. TTL. Both bounds use the verifier's clock: a challenge expired
        //    before the check (now >= expires_at) OR claiming to have been
        //    issued more than MAX_CLOCK_SKEW in the future (audit #76 — a
        //    signed record cannot legitimately come from a host clock that
        //    far ahead) is rejected.
        $now = $this->now !== null ? (int) ($this->now)() : time();
        if ($now >= $peek->expiresAt) {
            $this->bestEffortDelete($token->nonce);

            return VerifyOutcome::invalid(VerifyError::Expired);
        }
        if ($peek->issuedAt > $now + self::MAX_CLOCK_SKEW) {
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

        // 5c. Security-policy epoch (audit #42): the policy that authorized
        //     this challenge must still be in force — the verifier rejects
        //     records issued under a different epoch (WrongPolicyVersion).
        if ($this->expectedPolicyVersion !== null && ($peek->policyVersion ?? 1) !== $this->expectedPolicyVersion) {
            $this->bestEffortDelete($token->nonce);

            return VerifyOutcome::invalid(VerifyError::WrongPolicyVersion);
        }

        // 5d. Deployment issuer (audit #67): a verifier configured with an
        //     expected issuer rejects any record whose issuer does not match
        //     EXACTLY — an unbound (NULL) record issuer fails closed, because
        //     an unbound record is redeemable by every deployment and must
        //     not satisfy an issuer-bound verifier.
        if ($this->expectedIssuer !== null && $peek->issuer !== $this->expectedIssuer) {
            $this->bestEffortDelete($token->nonce);

            return VerifyOutcome::invalid(VerifyError::WrongIssuer);
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
            // 9. Consume (one-shot transition, audit #74) and re-derive the
            //    proof. The record is marked consumed and KEPT until its TTL.
            try {
                $consumed = $this->storage->consume($token->nonce);
            } catch (\Throwable) {
                // A lost transition response is intrinsically ambiguous: the
                // challenge may or may not have been consumed. Report the
                // indeterminate state instead of RecordNotFound.
                return VerifyOutcome::invalid(VerifyError::ConsumeIndeterminate);
            }
            if ($consumed === null) {
                return VerifyOutcome::invalid(VerifyError::RecordNotFound);
            }

            // Consumed-state retry (audit #74): an already-consumed record
            // replays its committed deterministic result WITHOUT re-deriving
            // the proof — a retry sees exactly what the consuming attempt
            // saw (Valid/InsufficientWork). A consumed record without a
            // committed result (crash between consume and commit) is
            // intrinsically ambiguous — the caller treats it as such.
            if ($consumed->consumedBefore) {
                if ($consumed->consumedResult !== null) {
                    return $consumed->consumedResult->valid
                        ? VerifyOutcome::valid($consumed->record->nonce, $consumed->consumedResult->binding, true)
                        : VerifyOutcome::invalid(VerifyError::InsufficientWork);
                }

                return VerifyOutcome::invalid(VerifyError::ConsumeIndeterminate);
            }
            $record = $consumed->record;

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

            // Security-policy epoch on the CONSUMED instance (audit #42): a
            // racing swap that replaced the record between peek and consume
            // must fail closed here too — the instance that actually proves
            // the PoW must be from the current policy epoch.
            if ($this->expectedPolicyVersion !== null && ($record->policyVersion ?? 1) !== $this->expectedPolicyVersion) {
                return VerifyOutcome::invalid(VerifyError::WrongPolicyVersion);
            }

            // Deployment issuer on the CONSUMED instance (audit #67): the
            // same racing-swap fail-closed guarantee as the policy check —
            // the instance that actually proves the PoW must be from the
            // expected deployment.
            if ($this->expectedIssuer !== null && $record->issuer !== $this->expectedIssuer) {
                return VerifyOutcome::invalid(VerifyError::WrongIssuer);
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
                // Commit the deterministic invalid outcome (best-effort) so
                // a retry sees the SAME InsufficientWork without re-deriving.
                $this->bestEffortCommit($record->nonce, false, $record->requestBinding);

                return VerifyOutcome::invalid(VerifyError::InsufficientWork);
            }

            // 10. POST-DERIVE FINAL REVALIDATION (audit #59): the expensive
            //     derivation succeeded — re-check against the CURRENT server
            //     clock and the CURRENT expectations BEFORE accepting. The
            //     challenge may have expired DURING the derivation (the
            //     clock read here is the verifier's now closure, so tests
            //     can drive it), and the policy epoch / region / issuer may
            //     have rotated mid-derivation. The expectation values read
            //     here are the CURRENT ones, not a snapshot from the cheap
            //     phase.
            $now = $this->now !== null ? (int) ($this->now)() : time();
            if ($now >= $record->expiresAt) {
                return VerifyOutcome::invalid(VerifyError::Expired);
            }
            if ($this->expectedPolicyVersion !== null && ($record->policyVersion ?? 1) !== $this->expectedPolicyVersion) {
                return VerifyOutcome::invalid(VerifyError::WrongPolicyVersion);
            }
            if ($this->region !== null && $record->region !== $this->region) {
                return VerifyOutcome::invalid(VerifyError::WrongRegion);
            }
            if ($this->expectedIssuer !== null && $record->issuer !== $this->expectedIssuer) {
                return VerifyOutcome::invalid(VerifyError::WrongIssuer);
            }

            // Commit the deterministic valid outcome (best-effort — a
            // storage failure must NEVER change the outcome) so a retry
            // replays it without re-deriving.
            $this->bestEffortCommit($record->nonce, true, $record->requestBinding);

            return VerifyOutcome::valid($record->nonce, $record->requestBinding);
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

    /**
     * Terminal result commit for a consumed record (audit #74). Best-effort
     * by design: a failed commit must NEVER override the already-determined
     * verification outcome — without the stored result a retry of the
     * consumed record degrades to ConsumeIndeterminate, which is strictly
     * safer than re-deriving a wrong outcome.
     */
    private function bestEffortCommit(string $nonce, bool $valid, ?string $binding): void
    {
        try {
            $this->storage->commitResult($nonce, $valid, $binding);
        } catch (\Throwable) {
        }
    }

    /**
     * @internal Race-test seam (audit #59): rotate the CURRENT deployment
     * expectations (policy epoch, region, issuer) to model a rotation that
     * lands between the cheap checks and the post-derive final revalidation.
     * The final re-check always reads the CURRENT values, so a rotation
     * performed at any point before it (e.g. by a stateful clock/storage
     * stub mid-verification) is observed. All three parameters are applied
     * as given. Not part of the public verification contract — production
     * deployments configure the expectations once at construction.
     */
    public function rotateDeploymentExpectations(?int $policyVersion, ?string $region, ?string $issuer): void
    {
        $this->expectedPolicyVersion = $policyVersion;
        $this->region = $region;
        $this->expectedIssuer = $issuer;
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
                $record->region,
                $record->policyVersion ?? 1,
                $record->requestBinding,
                $record->issuer,
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
