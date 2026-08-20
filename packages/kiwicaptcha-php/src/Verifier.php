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
 * absence: the record survives until its TTL carrying the
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
 *      per-algorithm difficulty range (the protocol bounds 1..MAX_DIFFICULTY,
 *      so the leading-zero comparison only ever runs against a
 *      validated difficulty).
 *   2. Kid gate: a record whose kid is in the
 *      verifier's revokedKids set fails with UnknownKid IMMEDIATELY — even
 *      when the kid's secret is present in secretsByKid (compromise
 *      revocation overrides the normal rotation grace). Otherwise, when a
 *      secretsByKid set is configured, the signature secret for the
 *      record's kid is selected here — an unknown kid, or a kid beyond the
 *      newest configured kid (the rollback/forward guard — a future-keyed
 *      challenge must never verify on an older node), fails with
 *      UnknownKid. An empty set keeps the legacy single-secret path (the
 *      verify() secret parameter).
 *   2. Re-check the challenge HMAC signature (constant-time compare) —
 *      protocol v1 payloads use the legacy canonical form signed with the
 *      master key, protocol v2 uses the full-parameter canonical payload
 *      (kid included) signed with the HKDF-derived K_challenge of the
 *      kid-selected secret.
 *   2b. Absolute Argon2id process ceilings: the SIGNED
 *      parameters are checked against MIN/MAX_ARGON_* AFTER signature
 *      authentication and BEFORE any allocation — out-of-range yields
 *      UnsupportedArgon2Params.
 *   3. TTL: now < expires_at AND now >= issued_at - MAX_CLOCK_SKEW (a
 *      signed challenge claiming to be issued more than 60s in the
 *      future is invalid).
 *   4. Scope: challenge scope matches the expected flow.
 *   5. IP binding: v2 records recompute the nonce-bound binding tag (keyed
 *      by the HKDF-derived K_ip_bind); v1 records compare the legacy IP
 *      hash. An empty binding tag disables the check; with a nonempty
 *      binding tag a missing client IP fails closed (MissingClientIp) — a
 *      null IP NEVER skips the binding.
 *   5b. Region binding: a verifier configured with an
 *      expected region rejects any record whose region does not match
 *      exactly (WrongRegion) — including unbound (NULL) records, which
 *      FAIL CLOSED (a region-unbound record satisfies no region-bound
 *      verifier). When NO expected region is configured, region is not
 *      enforced and unbound records verify.
 *   5c. Security-policy epoch and deployment issuer: a verifier configured
 *      with an expected policy epoch / issuer rejects records issued under
 *      a different epoch / by a different deployment (WrongPolicyVersion /
 *      WrongIssuer).
 *   6. Minimum duration: measured SERVER-SIDE from the record's issued_at_ns
 *      (epoch microseconds) to the verification receipt time — the
 *      client-reported duration can no longer be forged to bypass the
 *      floor, and records without issued_at_ns are malformed (no legacy
 *      client-duration fallback). Host clock skew up to SKEW_TOLERANCE_US
 *      is absorbed (the floor check is skipped, the PoW check still
 *      applies); a receipt time that precedes issuance beyond the tolerance
 *      is impossible and rejected as TooFast.
 *   7. Telemetry (legacy opt-in hard gate): when enforceTelemetry is set,
 *      the client-controlled telemetry is scored and bot signals rejected.
 *      This hard rejection remains ONLY as an explicit legacy compatibility
 *      behavior — new automation heuristics must become bounded risk
 *      factors, never additions to this gate; the gate is deprecated in
 *      favor of probabilistic risk scoring.
 *   8. Argon2id admission gate (optional): when a VerificationAdmissionGate
 *      is configured, it must grant capacity before the memory-hard hash
 *      runs; exhaustion yields CapacityExceeded WITHOUT burning the record.
 *   9. Consume the record (one-shot transition), re-derive the hash
 *      (SHA-256 or Argon2id per the record's algorithm), and require >=
 *      target_bits leading zero bits. A retry on an already-consumed record
 *      returns its committed deterministic result (Valid/InsufficientWork)
 *      without re-deriving, or ConsumeIndeterminate when no result was
 *      committed.
 *  10. POST-DERIVE FINAL REVALIDATION: after the proof derives
 *      successfully and BEFORE returning Valid, re-check with the CURRENT
 *      server clock (the verifier's now closure) and the CURRENT
 *      expectations: the challenge must not have expired during the
 *      expensive derivation (Expired), and the expected policy epoch,
 *      region, and issuer must still match — a rotation landing mid-
 *      derivation fails the re-check. Only then is the deterministic
 *      result committed (best-effort) and Valid returned.
 *
 * The cheap-phase checks (1-6 above) are shared with the NARROWLY
 * AUTHORIZED consumed-operation resume path
 * ({@see self::resumeConsumedOperation()}): a caller that has PROVEN the
 * retained consumed record's exact operation identity belongs to this
 * logical operation may resume and commit the interrupted derivation —
 * ordinary replays of a consumed-without-result record still report
 * ConsumeIndeterminate.
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
     * Maximum tolerated FUTURE skew for a record's issuance timestamp:
     * a signed challenge claiming issued_at > now + 60s cannot
     * have come from a real issuer host (even under clock drift) and is
     * rejected by the TTL check as Expired.
     */
    public const MAX_CLOCK_SKEW = 60;

    /**
     * Absolute process ceilings for Argon2id parameters.
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
         * The CURRENT security-policy epoch. When non-null, a
         * record whose `policy_version` differs is rejected with
         * WrongPolicyVersion — outstanding challenges die immediately on
         * policy revocation (origin/action-policy changes, emergency
         * revocation, compromised tenant). Null (default) disables the check.
         */
        private ?int $expectedPolicyVersion = null,
        /**
         * Expected deployment issuer. When non-null, a record
         * whose `issuer` does not match EXACTLY — including a NULL (unbound)
         * record issuer — is rejected with WrongIssuer: a dev/staging/prod
         * compartment that holds even when deployments share secret keys.
         * Null (default) disables the check.
         */
        private ?string $expectedIssuer = null,
        /**
         * Secret set keyed by signing key id. When NON-EMPTY,
         * the secret for the record's `kid` is selected for the signature
         * re-check (and the IP-binding re-derivation): a record whose kid is
         * unknown — or whose kid exceeds the newest configured kid (the
         * rollback/forward guard: a future-keyed challenge must never verify
         * on an older node) — is rejected with UnknownKid. Keys are the
         * monotonic kid sequence 1..N (positive integers). When EMPTY, the
         * legacy single-secret path stays: the verify() $secretKey parameter
         * is used for every record.
         */
        private readonly array $secretsByKid = [],
        /**
         * Compromised signing key ids. A record whose `kid`
         * appears here is rejected with UnknownKid BEFORE any signature
         * work — IMMEDIATELY, even when the kid's secret is present in
         * secretsByKid: compromise revocation overrides the normal rotation
         * grace (a kid past the newest configured kid would otherwise
         * verify until its secret leaves the set). Values are kid ids
         * (positive integers). Empty (default) disables the revocation set.
         */
        private readonly array $revokedKids = [],
    ) {
        // Backward-compatibility shim: callers may pass the clock override
        // positionally in the second slot. A Closure there is $now, not an
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
        foreach ($secretsByKid as $kid => $secret) {
            if (!\is_int($kid) || $kid < 1 || !\is_string($secret) || \strlen($secret) < 16) {
                throw new \InvalidArgumentException(
                    'secretsByKid keys must be positive integer kid values 1..N with secrets of at least 16 bytes'
                );
            }
        }
        foreach ($revokedKids as $kid) {
            if (!\is_int($kid) || $kid < 1) {
                throw new \InvalidArgumentException(
                    'revokedKids values must be positive integer kid values 1..N'
                );
            }
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
     *                                     LEGACY hard gate kept only for
     *                                     explicit compatibility — do not add
     *                                     new heuristics here; uncertain
     *                                     browser evidence belongs in the
     *                                     risk-scoring layer. Telemetry is
     *                                     client-controlled, so enforcement is
     *                                     opt-in defense-in-depth only.
     * @param string|null $operationIdentity the logical-operation identity
     *                                     to record WITH the pending→consumed
     *                                     transition (see
     *                                     {@see OperationIdentityAwareStorageInterface::consumeWithOperationIdentity()}).
     *                                     Null (the default — every native
     *                                     caller) records no identity and is
     *                                     byte-identical to the plain consume.
     *                                     A storage without the identity
     *                                     capability verifies normally but
     *                                     records no identity.
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
        ?string $operationIdentity = null,
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

        // 1-6. The cheap-phase security checks — structural validation,
        // protocol version gate, kid gate + resolution, HMAC signature
        // re-check, Argon2id process ceilings, TTL, scope, IP binding,
        // region, policy epoch, issuer, server-measured minimum duration —
        // run in the EXACT order of the original path inside one shared
        // helper ({@see self::cheapPhaseCheck()}): the first failing check
        // decides the outcome, and the delete policy is preserved exactly —
        // every cheap failure deletes the PEEKED record except the
        // missing-client-IP failure (a bound challenge without a client IP
        // is rejected but the record is kept, so the caller can retry with
        // the IP). The same helper revalidates the retained consumed record
        // on the consumed-operation resume path
        // ({@see self::resumeConsumedOperation()}).
        $failure = $this->cheapPhaseCheck($peek, $secretKey, $expectedScope, $clientIp, true, $nowNs);
        if ($failure !== null) {
            if ($failure !== VerifyError::MissingClientIp) {
                $this->bestEffortDelete($token->nonce);
            }

            return VerifyOutcome::invalid($failure);
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
            // 9. Consume (one-shot transition) and re-derive the
            //    proof. The record is marked consumed and KEPT until its TTL.
            //    An identity-bearing consume records the logical-operation
            //    identity ATOMICALLY with the state flip (a storage without
            //    the identity capability verifies normally but records no
            //    identity).
            try {
                $consumed = $operationIdentity !== null && $this->storage instanceof OperationIdentityAwareStorageInterface
                    ? $this->storage->consumeWithOperationIdentity($token->nonce, $operationIdentity)
                    : $this->storage->consume($token->nonce);
            } catch (\Throwable) {
                // A lost transition response is intrinsically ambiguous: the
                // challenge may or may not have been consumed. Report the
                // indeterminate state instead of RecordNotFound.
                return VerifyOutcome::invalid(VerifyError::ConsumeIndeterminate);
            }
            if ($consumed === null) {
                return VerifyOutcome::invalid(VerifyError::RecordNotFound);
            }

            // Consumed-state retry: an already-consumed record
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
            // signs EVERY immutable parameter (kid included), full
            // re-validation + signature re-verification on the consumed
            // instance is the robust check — a swapped/racing record fails
            // closed instead of verifying against bytes that were never
            // validated. The signature secret is re-resolved for the
            // CONSUMED record's kid: an instance whose kid is
            // unknown (or ahead of the newest configured kid) cannot be
            // authenticated and fails closed as MalformedRecord.
            $consumedSecret = $this->secretForKey($record, $secretKey);
            if (
                !hash_equals($peek->challenge, $record->challenge)
                || $this->isRevokedKid($record->kid)
                || $consumedSecret === null
                || !$this->validateRecord($record)
                || !$this->verifyRecordSignature($record, $consumedSecret)
            ) {
                return VerifyOutcome::invalid(VerifyError::MalformedRecord);
            }

            // The allocation gate sits at the computation site too: the
            // consumed instance's signed parameters must satisfy the hard
            // ceilings before the memory-hard hash runs.
            if (!$this->argon2CeilingsOk($record)) {
                return VerifyOutcome::invalid(VerifyError::UnsupportedArgon2Params);
            }

            // Security-policy epoch on the CONSUMED instance: a
            // racing swap that replaced the record between peek and consume
            // must fail closed here too — the instance that actually proves
            // the PoW must be from the current policy epoch.
            if ($this->expectedPolicyVersion !== null && ($record->policyVersion ?? 1) !== $this->expectedPolicyVersion) {
                return VerifyOutcome::invalid(VerifyError::WrongPolicyVersion);
            }

            // Deployment issuer on the CONSUMED instance: the
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

            // 10. POST-DERIVE FINAL REVALIDATION: the expensive
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
     * RESUME a consumed logical operation's derivation — the narrowly
     * authorized crash-recovery path for the Siteverify takeover.
     *
     * STRONG CONTRACT — this is NOT an ordinary verification retry API
     * and NOT a replay API: it may be called ONLY by a caller that has
     * INDEPENDENTLY proven that the retained consumed record's exact
     * operation identity belongs to this logical operation (the Siteverify
     * takeover gate proves it by comparing the consumed record's OWN
     * operation identity — written ATOMICALLY with the pending→consumed
     * transition — against the claim fingerprint: same backend, same
     * idempotency key, same response hash, same remote-IP fingerprint).
     * The record must be CONSUMED (this logical operation won the atomic
     * pending→consumed transition) and carry EXACTLY the given identity:
     * any mismatch — a missing record, a not-yet-consumed record, a null
     * identity (e.g. a no-key first redemption), a different identity (a
     * different UUID, backend secret, response or remote-IP) — is refused
     * with ConsumeIndeterminate. "Close enough" is NEVER sufficient: the
     * same response hash, the same backend, or the same nonce without the
     * exact fingerprint are all refused.
     *
     * When the retained record already carries a committed deterministic
     * result, that result is returned unchanged (the ordinary
     * committed-outcome semantics). Otherwise the derivation is RESUMED
     * and committed: every immutable security property is revalidated
     * EXACTLY like the ordinary verify path ({@see self::cheapPhaseCheck()}
     * — record structural validity, protocol version gate, kid
     * validity/revocation, HMAC signature, Argon2id process ceilings,
     * expected scope, IP binding when enabled, region, policy epoch,
 *      issuer, token counter bounds), and Argon2id admission still applies
 *      to the resumed derivation — resource admission is NEVER bypassed.
 *      Before the commit the CURRENT expectations are re-checked exactly
 *      like the ordinary post-derive final revalidation (policy epoch,
 *      region, issuer — the values read at commit time, never a cheap-
 *      phase snapshot), so a rotation landing mid-derivation refuses the
 *      resume.
 *      Two timing checks are deliberately EXEMPT: the signed expiry (the
     * operation already won atomic consumption before the response was
     * lost — this path exists precisely to recover past the signed
     * lifetime inside the retained-state horizon) and the
     * minimum-duration floor (it was passed before the consume). The
     * commit is NOT best-effort: a failed commit reads the state back — a
     * concurrent recovery's committed result is then returned (the
     * winner's stored outcome), and only a genuinely missing result
     * yields StorageUnavailable.
     *
     * Native replay security is UNAFFECTED: the ordinary
     * {@see self::verify()} still returns ConsumeIndeterminate for a
     * consumed record without a committed result, and the identity gate
     * here can never be satisfied by a different logical operation.
     *
     * @param string      $rawToken          base64 solution token from the widget
     * @param string      $secretKey         HMAC secret key
     * @param string      $operationIdentity the logical-operation identity the
     *                                       caller PROVED the retained consumed
     *                                       record carries — its exact match is
     *                                       the sole authorization to resume
     * @param string|null $expectedScope     required challenge scope (null = any)
     * @param string|null $clientIp          client IP for the optional IP binding
     */
    public function resumeConsumedOperation(
        string $rawToken,
        string $secretKey,
        string $operationIdentity,
        ?string $expectedScope = null,
        ?string $clientIp = null,
    ): VerifyOutcome {
        try {
            $token = SolutionToken::decode($rawToken);
        } catch (DecodeError $e) {
            return VerifyOutcome::malformedToken($e->getMessage());
        }

        // The retained consumed state must be readable (the bundle enforces
        // the ConsumedStateReadableInterface contract at configuration time;
        // a non-capable storage degrades to a typed, retryable result).
        try {
            if (!$this->storage instanceof ConsumedStateReadableInterface) {
                return VerifyOutcome::invalid(VerifyError::StorageUnavailable);
            }
            $consumed = $this->storage->consumedState($token->nonce);
        } catch (\Throwable) {
            return VerifyOutcome::invalid(VerifyError::StorageUnavailable);
        }

        // THE IDENTITY GATE: only a consumed record carrying EXACTLY this
        // operation identity may have its derivation resumed — the identity
        // was written atomically with the pending→consumed transition, so
        // it is provably the ACTUAL atomic consume winner's. Anything else
        // is ambiguous for this caller and refused as ConsumeIndeterminate
        // (retryable; the caller should not have reached this path).
        if (
            $consumed === null
            || $consumed->operationIdentity === null
            || !hash_equals($consumed->operationIdentity, $operationIdentity)
        ) {
            return VerifyOutcome::invalid(VerifyError::ConsumeIndeterminate);
        }

        // Committed-result fast path: the deterministic outcome already
        // stored by this logical operation (or a concurrent recovery of it)
        // is returned unchanged — exactly the committed-outcome semantics
        // of the ordinary verify path.
        if ($consumed->consumedResult !== null) {
            return $consumed->consumedResult->valid
                ? VerifyOutcome::valid($consumed->record->nonce, $consumed->consumedResult->binding, true)
                : VerifyOutcome::invalid(VerifyError::InsufficientWork);
        }
        $record = $consumed->record;

        // Revalidate every immutable security property EXACTLY like the
        // ordinary verify path (the shared cheap-phase helper; timing
        // exempted per the contract above). The retained record is NOT
        // deleted on a failure — it is the recovery evidence and must
        // survive for a later retry (it is already consumed; deletion buys
        // nothing).
        $failure = $this->cheapPhaseCheck($record, $secretKey, $expectedScope, $clientIp, false);
        if ($failure !== null) {
            return VerifyOutcome::invalid($failure);
        }

        // Argon2id admission still applies: the resumed derivation is as
        // expensive as the original, so the gate bounds it exactly the
        // same way — exhaustion rejects WITHOUT committing (the record
        // stays consumed-without-result, and a later retry can resume
        // again once capacity is available).
        $lease = null;
        if ($record->algorithm === PoWAlgorithm::Argon2id && $this->argonGate !== null) {
            try {
                $lease = $this->argonGate->acquire();
            } catch (\Throwable) {
                return VerifyOutcome::invalid(VerifyError::AdmissionUnavailable);
            }
            if ($lease === null) {
                return VerifyOutcome::invalid(VerifyError::CapacityExceeded);
            }
        }

        try {
            $hash = $this->deriveHash($record, $token->counter);
            if ($hash === null) {
                // An Argon2id record whose parameters are within the
                // ceilings but cannot be represented by the
                // libsodium-backed verifier (p != 1) is
                // authentic-but-unsupported. A SHA-256 null can only be a
                // salt-decode failure (already shape-validated) —
                // malformed.
                return VerifyOutcome::invalid($record->algorithm === PoWAlgorithm::Argon2id
                    ? VerifyError::UnsupportedArgon2Params
                    : VerifyError::MalformedRecord);
            }
            $valid = self::leadingZeroBits($hash) >= $record->targetBits;

            // POST-DERIVE FINAL REVALIDATION — the same CURRENT-
            // expectation re-check the ordinary verify() runs after its
            // derivation ({@see self::verify()}, step 10), mirrored for
            // the policy epoch / region / issuer: a rotation that lands
            // between the pre-derive revalidation and the commit refuses
            // the resumed derivation (the values read here are the
            // CURRENT ones, never a snapshot from the cheap phase) and
            // nothing is committed — the retained record stays
            // consumed-without-result for a later same-identity resume.
            // The signed expiry and the minimum-duration floor remain
            // EXEMPT: the operation already won atomic consumption.
            if ($valid) {
                if ($this->expectedPolicyVersion !== null && ($record->policyVersion ?? 1) !== $this->expectedPolicyVersion) {
                    return VerifyOutcome::invalid(VerifyError::WrongPolicyVersion);
                }
                if ($this->region !== null && $record->region !== $this->region) {
                    return VerifyOutcome::invalid(VerifyError::WrongRegion);
                }
                if ($this->expectedIssuer !== null && $record->issuer !== $this->expectedIssuer) {
                    return VerifyOutcome::invalid(VerifyError::WrongIssuer);
                }
            }

            // Commit the resumed deterministic outcome — NOT best-effort:
            // the resume must persist what it derived (a retry of the
            // consumed record without a stored result would degrade to
            // ConsumeIndeterminate forever). A failed commit reads the
            // state back: a concurrent recovery may have won the commit —
            // the winner's stored result is then authoritative (the same
            // logical operation derives the same outcome either way).
            $binding = $record->requestBinding;
            try {
                $committed = $this->storage->commitResult($record->nonce, $valid, $binding);
            } catch (\Throwable) {
                $committed = false;
            }
            if (!$committed) {
                try {
                    $after = $this->storage->consumedState($record->nonce);
                } catch (\Throwable) {
                    $after = null;
                }
                if ($after?->consumedResult !== null) {
                    return $after->consumedResult->valid
                        ? VerifyOutcome::valid($after->record->nonce, $after->consumedResult->binding, true)
                        : VerifyOutcome::invalid(VerifyError::InsufficientWork);
                }

                return VerifyOutcome::invalid(VerifyError::StorageUnavailable);
            }

            return $valid
                ? VerifyOutcome::valid($record->nonce, $binding)
                : VerifyOutcome::invalid(VerifyError::InsufficientWork);
        } finally {
            if ($lease !== null) {
                try {
                    $this->argonGate?->release($lease);
                } catch (\Throwable) {
                    // Best-effort: a failed release must NEVER override the
                    // resumed verification result. A leaked lease is
                    // recovered by its TTL.
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
     * The difficulty guard is the protocol floor/ceiling pair
     * MIN_DIFFICULTY..MAX_DIFFICULTY (1..20) applied to BOTH algorithms:
     * the leading-zero comparison only ever runs against a validated
     * difficulty, so the stored value cannot drive an unbounded comparison
     * (0, 21, 256, 65535 … are all rejected here, before any hash is
     * computed). Issuance keeps the narrower per-algorithm ceilings.
     *
     * The scope check enforces the narrow identifier alphabet
     * — `[A-Za-z0-9._:-]+`, 1..128 bytes — the alphabet itself makes the
     * legacy '|' separator rejection unnecessary.
     *
     * Argon2id memory/time/parallelism are NOT bounded here: the
     * absolute process ceilings apply to the SIGNED parameters
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
        if (
            $scopeLen < 1
            || $scopeLen > 128
            || \preg_match('/^[A-Za-z0-9._:-]+$/D', $record->scope) !== 1
        ) {
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
        // The uniform protocol difficulty bounds (1..20) guard
        // the leading-zero comparison for BOTH algorithms — a stored value
        // outside the bounds is rejected here, before any hash computation.
        if ($record->targetBits < Config::MIN_DIFFICULTY || $record->targetBits > Config::MAX_DIFFICULTY) {
            return false;
        }

        return true;
    }

    /**
     * The cheap-phase security checks shared by the ordinary verify path
     * and the consumed-operation resume path, run in the EXACT order of
     * the ordinary path — the first failing check decides the outcome:
     *
     *   1.  structural validation ({@see self::validateRecord()});
     *   1b. protocol version gate (v1 only during an explicit migration
     *       window);
     *   2.  kid gate: a REVOKED kid fails IMMEDIATELY (UnknownKid) —
     *       compromise revocation overrides the normal rotation grace;
     *   2.  kid resolution: with a secretsByKid set, the signature secret
     *       is selected per the record's kid — an unknown kid, or one
     *       beyond the newest configured kid (the rollback/forward guard),
     *       fails with UnknownKid BEFORE any signature work; an empty set
     *       keeps the legacy single-secret path;
     *   2.  HMAC signature re-check ({@see self::verifyRecordSignature()})
     *       — BadSignature;
     *   2b. absolute Argon2id process ceilings
     *       ({@see self::argon2CeilingsOk()}) AFTER signature
     *       authentication and BEFORE any allocation —
     *       UnsupportedArgon2Params;
     *   3.  TTL (only when $checkTiming): now >= expires_at, or an issuance
     *       more than MAX_CLOCK_SKEW in the future, is Expired;
     *   4.  scope: challenge scope matches the expected flow (WrongScope);
     *   5.  IP binding: the stored record is AUTHORITATIVE — an empty
     *       binding tag disables the check; a NON-EMPTY tag means the
     *       challenge IS bound, so a missing client IP fails closed
     *       (MissingClientIp) and a mismatched tag is IpMismatch. Both are
     *       keyed by the KID-SELECTED secret (K_ip_bind is derived from
     *       the same master secret that signed the challenge);
     *   5b. region binding: a configured expected region rejects any record
     *       whose region does not match EXACTLY — an unbound (NULL) region
     *       fails closed (WrongRegion);
     *   5c. security-policy epoch: a record issued under a different epoch
     *       is WrongPolicyVersion;
     *   5d. deployment issuer: a record issued by a different deployment —
     *       including an unbound (NULL) issuer — is WrongIssuer;
     *   6.  server-measured minimum duration (only when $checkTiming): a
     *       record without issued_at_ns is malformed; a receipt before the
     *       floor is TooFast (a receipt preceding issuance beyond
     *       SKEW_TOLERANCE_US is physically impossible — TooFast; within
     *       the bound the floor check is skipped, the PoW check still
     *       applies).
     *
     * The timing group (TTL and the minimum-duration floor) is EXEMPT on
     * the resume path ($checkTiming = false): the operation already won
     * atomic consumption before the response was lost, so the signed
     * expiry and the floor were both passed by the original attempt.
     *
     * Returns the first failing error, or null when every check passes.
     * The CALLER owns the failure policy: the ordinary verify path deletes
     * the peeked record on every failure except MissingClientIp (a bound
     * challenge without a client IP is rejected but kept — the caller can
     * retry with the IP); the resume path never deletes the retained
     * consumed record (it is the recovery evidence).
     *
     * @param int|null $nowNs server receipt time in epoch MICROSECONDS
     *                        (used by the minimum-duration check only)
     */
    private function cheapPhaseCheck(
        ChallengeRecord $record,
        string $secretKey,
        ?string $expectedScope,
        ?string $clientIp,
        bool $checkTiming,
        ?int $nowNs = null,
    ): ?VerifyError {
        // 1. Structural validation of the stored record.
        if (!$this->validateRecord($record)) {
            return VerifyError::MalformedRecord;
        }

        // 1b. Protocol version gate: v1 (legacy, less comprehensively
        //     signed) is only accepted during an explicit migration window —
        //     v2 has been the issuance format longer than the maximum
        //     challenge lifetime, so any surviving v1 record is stale or
        //     foreign.
        if ($record->protocolVersion === 1 && !$this->acceptLegacyV1) {
            return VerifyError::MalformedRecord;
        }

        // 2. Kid gate: a REVOKED kid is rejected with
        //    UnknownKid IMMEDIATELY — before the signature check and before
        //    the secret selection — so compromise revocation overrides the
        //    normal rotation grace (a perfectly-signed challenge under a
        //    revoked kid still fails). Cheap: a set membership test only.
        if ($this->isRevokedKid($record->kid)) {
            return VerifyError::UnknownKid;
        }

        // 2. Kid resolution: with a secretsByKid set, the
        //    signature secret is selected per the record's kid — an unknown
        //    kid, or one beyond the newest configured kid (the
        //    rollback/forward guard — a future-keyed challenge must never
        //    verify on an older node), fails with UnknownKid BEFORE any
        //    signature work. An empty set keeps the legacy single-secret
        //    path: the verify() $secretKey parameter is used for every
        //    record (kid is then metadata only).
        $signingSecret = $this->secretForKey($record, $secretKey);
        if ($signingSecret === null) {
            return VerifyError::UnknownKid;
        }

        // 2. Signature re-check: reconstruct the payload from the record and
        //    compare against the signature embedded in the challenge string.
        //    Protocol v1 uses the legacy canonical form; protocol v2 uses the
        //    full-parameter canonical payload (kid included). The key is the
        //    kid-selected secret (or the verify() secret in legacy mode).
        if (!$this->verifyRecordSignature($record, $signingSecret)) {
            return VerifyError::BadSignature;
        }

        // 2b. Absolute Argon2id process ceilings: the SIGNED
        //     parameters are validated AFTER signature authentication and
        //     BEFORE any allocation or computation. Out-of-range values are
        //     authentic-but-unsupported — UnsupportedArgon2Params, not
        //     MalformedRecord (the record really came from an issuer holding
        //     the secret, it just violates the hard process limits).
        if (!$this->argon2CeilingsOk($record)) {
            return VerifyError::UnsupportedArgon2Params;
        }

        // 3. TTL. Both bounds use the verifier's clock: a challenge expired
        //    before the check (now >= expires_at) OR claiming to have been
        //    issued more than MAX_CLOCK_SKEW in the future (a
        //    signed record cannot legitimately come from a host clock that
        //    far ahead) is rejected.
        if ($checkTiming) {
            $now = $this->now !== null ? (int) ($this->now)() : time();
            if ($now >= $record->expiresAt) {
                return VerifyError::Expired;
            }
            if ($record->issuedAt > $now + self::MAX_CLOCK_SKEW) {
                return VerifyError::Expired;
            }
        }

        // 4. Scope validation.
        if ($expectedScope !== null && $record->scope !== $expectedScope) {
            return VerifyError::WrongScope;
        }

        // 5. IP binding. The stored record is AUTHORITATIVE: an empty
        //    binding tag means binding is disabled (BindingMode::None);
        //    a NON-EMPTY tag means the challenge IS bound, so a missing
        //    client IP fails closed (MissingClientIp) instead of silently
        //    skipping the check — the caller must provide the IP it would
        //    have passed to issuance. Protocol v2 records carry a nonce-bound
        //    binding tag (recomputed here); v1 records carry the legacy
        //    stable IP hash. Both are keyed by the KID-SELECTED secret
        //    (K_ip_bind is derived from the same master secret
        //    that signed the challenge).
        if ($record->bindingTag !== '') {
            if ($clientIp === null) {
                return VerifyError::MissingClientIp;
            }
            $expectedTag = $record->protocolVersion === 1
                ? Issuer::hashIp($clientIp, $signingSecret)
                : Issuer::bindingTag($record->nonce, $clientIp, $signingSecret);
            if (!hash_equals($expectedTag, $record->bindingTag)) {
                return VerifyError::IpMismatch;
            }
        }

        // 5b. Region binding: a verifier configured
        //     with an expected region rejects any record whose region does
        //     not match EXACTLY — an unbound (NULL) record region fails
        //     closed (a region-unbound record satisfies no region-bound
        //     verifier); with no expected region, region is unenforced.
        if ($this->region !== null && $record->region !== $this->region) {
            return VerifyError::WrongRegion;
        }

        // 5c. Security-policy epoch: the policy that authorized
        //     this challenge must still be in force — the verifier rejects
        //     records issued under a different epoch (WrongPolicyVersion).
        if ($this->expectedPolicyVersion !== null && ($record->policyVersion ?? 1) !== $this->expectedPolicyVersion) {
            return VerifyError::WrongPolicyVersion;
        }

        // 5d. Deployment issuer: a verifier configured with an
        //     expected issuer rejects any record whose issuer does not match
        //     EXACTLY — an unbound (NULL) record issuer fails closed, because
        //     an unbound record is redeemable by every deployment and must
        //     not satisfy an issuer-bound verifier.
        if ($this->expectedIssuer !== null && $record->issuer !== $this->expectedIssuer) {
            return VerifyError::WrongIssuer;
        }

        // 6. Minimum duration, measured on the SERVER: elapsed_us is the gap
        //    between the record's high-resolution issuance timestamp (epoch
        //    microseconds) and the verification receipt time. The
        //    client-reported durationMs is forgeable, so it no longer drives
        //    the TooFast check and there is no legacy fallback — a record
        //    without issued_at_ns cannot be timed and is malformed.
        if ($checkTiming) {
            if ($record->issuedAtNs <= 0) {
                return VerifyError::MalformedRecord;
            }
            $floor = max(0, $record->minDurationMs);
            if ($floor > 0) {
                $receiptNs = $nowNs ?? (int) (microtime(true) * 1_000_000);
                if ($receiptNs >= $record->issuedAtNs) {
                    if ($receiptNs - $record->issuedAtNs < $floor * 1_000) {
                        return VerifyError::TooFast;
                    }
                } elseif ($record->issuedAtNs - $receiptNs > self::SKEW_TOLERANCE_US) {
                    // Receipt before issuance by more than the skew bound is
                    // physically impossible — reject as TooFast. Within the
                    // bound the two hosts' clocks are unsynced, so the
                    // elapsed time cannot be measured reliably and the floor
                    // check is skipped for this verification — the
                    // proof-of-work check still applies, so no attacker
                    // advantage is gained.
                    return VerifyError::TooFast;
                }
            }
        }

        return null;
    }

    /**
     * Absolute process ceilings for Argon2id parameters — the
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
     * Terminal result commit for a consumed record. Best-effort
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
     * Public per-verification seam for the bounded-revocation-latency
     * monitor: sets the CURRENT security-policy epoch the
     * verifier enforces. The monitor refreshes this from the central
     * security-policy state with a short cache and a monotonic guard — a
     * stale/regressed value must never be applied. Cheap; safe to call
     * before every verification.
     */
    public function setExpectedPolicyVersion(int $policyVersion): void
    {
        $this->expectedPolicyVersion = $policyVersion;
    }

    /**
     * @internal Test seam: rotate the CURRENT deployment
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
     * immutable parameter (kid included), a valid signature
     * proves the whole record is authentic — used in the cheap phase AND
     * re-applied to the CONSUMED instance (TOCTOU guard).
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
                $record->kid ?? 1,
            ), $secretKey);

        return hash_equals($expected, self::signatureFromChallenge($record->challenge));
    }

    /**
     * Select the signature secret for a record.
     *
     * With an EMPTY secretsByKid set the legacy single-secret path stays:
     * the verify() $secretKey parameter is used for every record. With a
     * NON-EMPTY set the secret is looked up by the record's kid, and null is
     * returned — yielding UnknownKid — when the kid is unknown, or when it
     * EXCEEDS the newest configured kid: the rollback/forward guard that
     * ensures a future-keyed challenge never verifies on an older node.
     */
    private function secretForKey(ChallengeRecord $record, string $legacySecret): ?string
    {
        if ($this->secretsByKid === []) {
            return $legacySecret;
        }
        if ($record->kid > max(array_keys($this->secretsByKid))) {
            return null;
        }
        if (!\array_key_exists($record->kid, $this->secretsByKid)) {
            return null;
        }

        return $this->secretsByKid[$record->kid];
    }

    /**
     * Compromise-revocation gate: true when the record's kid is
     * in the verifier's revokedKids set. The check is a cheap set-membership
     * test that runs BEFORE any signature work — revocation overrides the
     * normal rotation grace, so a revoked kid fails with UnknownKid even
     * when its secret is still present in secretsByKid and the challenge is
     * perfectly signed.
     */
    private function isRevokedKid(?int $kid): bool
    {
        return $kid !== null && \in_array($kid, $this->revokedKids, true);
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
