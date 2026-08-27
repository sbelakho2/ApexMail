<?php

declare(strict_types=1);

namespace KiwiCaptcha;

/**
 * Verifies client-submitted solutions, byte-for-byte compatible with the
 * Rust crate's `verify_solution`.
 *
 * Verification is one-shot: any attempt burns the challenge record. The
 * cheap checks (record structure, signature, TTL, scope, binding, server
 * timing, telemetry) run against a peeked record and delete it on
 * failure. A consumed record is an exception: its retained consumed
 * state — the deterministic result and the operation identity — is
 * crash-recovery evidence that survives to its retention TTL. A
 * consumed record that fails a cheap check resolves through the
 * consumed branch instead, but only for the narrow exempt set of the
 * replay-exemption split below. The
 * proof phase consumes the record before re-deriving the hash, so a
 * wrong candidate costs at most one Argon2id (or SHA-256) hash. Replay
 * protection is the consumed marker: the record survives until its TTL
 * carrying the deterministic verification result. The consumed outcome
 * replays without re-deriving, but a stored success is an authorization
 * grant. It replays only to the exact logical operation that consumed
 * the record, which the caller proves by passing the same operation
 * identity the pending-to-consumed transition recorded. Any other retry
 * of a consumed record whose stored result is valid, such as a replay
 * without an identity or one presenting a different operation's
 * identity, is refused as AlreadyConsumed. The safe default is that an
 * already-consumed token is refused unless the caller proves the exact
 * logical operation, which makes the operation identity an
 * authorization boundary for ordinary replay, not only the specialized
 * recovery API. A stored invalid result (InsufficientWork) replays
 * deterministically to any caller; a consumed record without a
 * committed result (crash between consume and commit) is reported as
 * ConsumeIndeterminate. There is no maxAttempts parameter: the
 * one-shot model is the attempt bound.
 *
 * Strict single-use under concurrency requires an AtomicStorageInterface
 * backend (e.g. Redis): the load-and-transition is fused, so two racing
 * requests cannot both win the consume transition. PSR-6-backed consume()
 * is best-effort: the read and the transition cannot be fused, so racing
 * requests may both observe the pending record. The proof-phase re-check
 * makes a swapped record fail closed (MalformedRecord) either way.
 *
 * Check order: structural validation of the stored record (scope shape,
 * nonce/salt sizes, TTL ceiling, prefix binding, per-algorithm
 * difficulty range 1..20). The kid gate and secret selection follow: a
 * revoked kid fails immediately, a kid beyond the newest configured kid
 * fails the rollback/forward guard. Then comes the HMAC signature
 * re-check. Next come the absolute Argon2id process ceilings after
 * signature authentication and before any allocation, and the TTL
 * (including a signed issuance more than 60s in the future). Then the
 * scope and the IP binding run: a null IP never skips a nonempty
 * binding tag. Then the region check runs (an unbound record fails
 * closed against an expected region), followed by the
 * security-policy epoch, the deployment issuer, and the
 * server-measured minimum duration. Records without issued_at_ns are
 * malformed; receipt preceding issuance beyond the skew tolerance is
 * rejected as TooFast. Then the optional telemetry gate runs, and the
 * optional Argon2id admission gate (exhaustion yields CapacityExceeded
 * without burning the record). The consume-and-re-derive proof phase
 * follows, and a post-derive final revalidation against the current
 * server clock and the current expectations precedes the commit of the
 * deterministic result.
 *
 * The cheap-phase checks are shared with the narrowly authorized
 * consumed-operation resume path. See {@see self::resumeConsumedOperation()}.
 * a caller that has proven the retained consumed record's exact
 * operation identity belongs to this logical operation may resume and
 * commit the interrupted derivation. A resultless resume re-checks the
 * signed expiry against the current clock both before deriving and
 * again post-derive before the commit (no durable success marker
 * exists). The committed-result recovery stays expiry-exempt: its
 * result was durably recorded only after the original final expiry
 * check passed. Ordinary replays of a consumed-without-result record
 * still report ConsumeIndeterminate.
 *
 * A cancelled record (the terminal marker of
 * {@see \KiwiCaptcha\CancellableStorageInterface::cancel()}) fails
 * verification closed. The pending→cancelled flip is the write the
 * storage refuses to undo.
 *
 * The consume transition reports the cancelled record as missing, so it
 * is never consumable. The retained-state reads never surface it.
 *
 * A cheap-failure cleanup never deletes it; the record is retained
 * until its TTL.
 *
 * A well-formed token for a cancelled record resolves to the pinned
 * deterministic failure {@see VerifyError::RecordNotFound}, the
 * verifier's equivalent of an unavailable or non-consumable record. A
 * cheap-phase failure keeps its own verdict. In every interleaving a
 * cancelled record is never redeemable and can never produce a
 * successful outcome.
 */
final class Verifier
{
    /**
     * Host-clock skew tolerance for the server-measured minimum-duration
     * check, in microseconds.
     *
     * issued_at_ns is a wall-clock timestamp written by whichever host
     * issued the challenge; verification may run on a different host whose
     * clock is slightly behind. A receipt time that precedes issuance by
     * less than the tolerance is treated as unmeasurable elapsed time.
     * The floor check is skipped for that verification, while the PoW
     * check still applies. A receipt time preceding issuance by more
     * than the tolerance is physically impossible and rejected as
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
     * Maximum tolerated future skew for a record's issuance timestamp:
     * a signed challenge claiming issued_at > now + 60s cannot
     * have come from a real issuer host and is rejected by the TTL check
     * as Expired.
     */
    public const MAX_CLOCK_SKEW = 60;

    /**
     * Absolute process ceilings for Argon2id parameters.
     *
     * After the challenge signature is authenticated, the signed parameters
     * are validated against these hard bounds before any memory allocation
     * or computation: out-of-range values yield UnsupportedArgon2Params.
     * The issuance side never mints outside the browser-solvable profile
     * (Config/ChallengeProfile), so a signed record violating a ceiling is
     * foreign or corrupt. The process ceiling is 16 passes; the browser
     * solver caps at 6 (Config, issuance-side).
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

    /**
     * @var bool whether the one-time non-atomic-storage warning already
     *            fired in this process (the misconfiguration is a
     *            deployment property, not a per-verification event)
     */
    private static bool $nonAtomicStorageWarned = false;

    public function __construct(
        private readonly StorageInterface $storage,
        $argonGate = null,
        ?\Closure $now = null,
        /**
         * Accept protocol-v1 (legacy) challenges. v2 has been the issuance
         * format for longer than the maximum challenge lifetime (300 s), so
         * no legitimate v1 record can still exist; v1 is rejected by
         * default. Set this only during a coordinated migration window.
         */
        private readonly bool $acceptLegacyV1 = false,
        /**
         * Expected deployment region (e.g. "eu"). When non-null, a record
         * whose region does not match exactly, including a null (unbound)
         * record region, is rejected with WrongRegion: a region-bound
         * challenge is never redeemable elsewhere or on an unbound record.
         * Null (default) disables the check entirely.
         */
        private ?string $region = null,
        /**
         * The current security-policy epoch. When non-null, a record
         * whose policy_version differs is rejected with
         * WrongPolicyVersion: outstanding challenges die immediately on
         * policy revocation (origin/action-policy changes, emergency
         * revocation, compromised tenant). Null (default) disables the check.
         */
        private ?int $expectedPolicyVersion = null,
        /**
         * Expected deployment issuer. When non-null, a record
         * whose issuer does not match exactly, including a null (unbound)
         * record issuer, is rejected with WrongIssuer: the
         * dev/staging/prod compartment holds even when deployments share
         * secret keys. Null (default) disables the check.
         */
        private ?string $expectedIssuer = null,
        /**
         * Secret set keyed by signing key id. When non-empty,
         * the secret for the record's kid is selected for the signature
         * re-check (and the IP-binding re-derivation). A record whose kid
         * is unknown, or whose kid exceeds the newest configured kid, is
         * rejected with UnknownKid; the rollback/forward guard keeps a
         * future-keyed challenge from verifying on an older node. Keys
         * are the monotonic kid sequence 1..N (positive integers). When
         * empty, the legacy single-secret path stays: the verify()
         * $secretKey parameter is used for every record.
         */
        private readonly array $secretsByKid = [],
        /**
         * Compromised signing key ids. A record whose kid
         * appears here is rejected with UnknownKid before any signature
         * work, even when the kid's secret is present in secretsByKid:
         * compromise revocation overrides the normal rotation grace.
         * Values are kid ids (positive integers). Empty (default)
         * disables the revocation set.
         */
        private readonly array $revokedKids = [],
    ) {
        // Backward-compatibility shim: callers may pass the clock override
        // positionally in the second slot. A Closure there is $now, not an
        // admission gate (the parameter is intentionally untyped so the
        // Closure can reach this branch; the type check happens below).
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
        // A non-atomic storage (the {@see NonAtomicStorageInterface}
        // capability marker, e.g. the PSR-6 backend) keeps best-effort
        // single-use only: two racing requests can both win the consume.
        // Verification still works (the proof-phase re-check fails a
        // swapped record closed), but replay protection that must hold
        // under concurrency — any authorization-grade redemption — needs
        // an {@see AtomicStorageInterface} backend. The warning is loud
        // and one-time per process so a misconfiguration cannot stay
        // silent, without spamming every verification.
        if ($storage instanceof NonAtomicStorageInterface && !self::$nonAtomicStorageWarned) {
            self::$nonAtomicStorageWarned = true;
            trigger_error(
                'KiwiCaptcha: the Verifier was constructed with a non-atomic storage ('
                .$storage::class
                .'); single-use is best-effort under concurrency — use an AtomicStorageInterface backend (e.g. RedisStorage) when replay protection matters',
                \E_USER_DEPRECATED,
            );
        }
        $this->argonGate = $argonGate;
        $this->now = $now;
    }

    /**
     * @param string      $rawToken        base64 solution token from the widget.
     * @param string      $secretKey       HMAC secret key.
     * @param string|null $expectedScope   required challenge scope (null = any).
     * @param string|null $clientIp        client IP for the optional IP binding.
     * @param int|null    $nowNs           server receipt time in epoch
     *                                     microseconds (defaults to
     *                                     microtime(true) * 1e6); used for
     *                                     the server-measured minimum-duration
     *                                     check. Test hook.
     * @param bool        $enforceTelemetry when true, bot-signal telemetry is
     *                                     rejected with TelemetryRejected.
     *                                     Legacy hard gate kept only for
     *                                     explicit compatibility; new
     *                                     heuristics belong in the risk
     *                                     layer. Telemetry is
     *                                     client-controlled, so enforcement is
     *                                     opt-in defense-in-depth only.
     * @param string|null $operationIdentity the logical-operation identity
     *                                     to record with the pending→consumed
     *                                     transition. See
     *                                     {@see OperationIdentityAwareStorageInterface::consumeWithOperationIdentity()}.
     *                                     Null (the default; every native
     *                                     caller) records no identity and is
     *                                     byte-identical to the plain consume.
     *                                     A storage without the identity
     *                                     capability verifies normally but
     *                                     records no identity. The identity is
     *                                     also the replay gate: a retry of a
     *                                     consumed record whose stored result
     *                                     is valid is returned unchanged only
     *                                     when this identity matches the one
     *                                     the pending-to-consumed transition
     *                                     recorded. A retry with a null or
     *                                     different identity is
     *                                     AlreadyConsumed.
     * @param string|null $expectedRequestBinding the application transaction
     *                                     binding a bound record's signed
     *                                     request_binding must equal, enforced
     *                                     before the consume. An explicitly
     *                                     unbound record (request_binding
     *                                     null, BindingMode::None) is
     *                                     permitted regardless of the
     *                                     expected binding; a record with a
     *                                     different one is rejected with
     *                                     RequestBindingMismatch. Null
     *                                     (the default) under the exact
     *                                     semantics refuses a bound
     *                                     record that does not present
     *                                     its binding; the legacy
     *                                     unenforced behavior is
     *                                     available only through the
     *                                     explicitly named
     *                                     RequestBindingExpectation::legacy().
     *
     * One-shot model: cheap-check failures delete the peeked record —
     * never an already-consumed retained record, whose consumed state is
     * crash-recovery evidence that survives to its retention TTL (a
     * consumed record that fails a cheap check resolves through the
     * consumed branch below). The proof phase consumes the record before
     * the hash is re-derived. A failed verification burns the challenge;
     * there is no maxAttempts parameter.
     */
    public function verify(
        string $rawToken,
        string $secretKey,
        ?string $expectedScope = null,
        ?string $clientIp = null,
        ?int $nowNs = null,
        bool $enforceTelemetry = false,
        ?string $operationIdentity = null,
        ?string $expectedRequestBinding = null,
        ?RequestBindingExpectation $bindingExpectation = null,
    ): VerifyOutcome {
        // The explicit enforcement policy: the legacy nullable argument
        // maps to the temporary compatibility mode unless the caller
        // supplies an exact/unenforced expectation.
        // The default binding semantics are exact: `expectedRequestBinding`
        // means "require the challenge to be bound to this transaction",
        // so an unbound record fails closed. The legacy compatibility
        // mode, where an unbound record passes regardless of the expected
        // binding and null disables enforcement entirely, remains
        // available only through the explicitly named
        // RequestBindingExpectation::legacy() value; it is never silently
        // chosen by the plain parameter.
        $expectation = $bindingExpectation ?? RequestBindingExpectation::exact($expectedRequestBinding);
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
        // expected request binding, region, policy epoch, issuer,
        // server-measured minimum duration — run in the order of the
        // original path inside one shared helper
        // {@see self::cheapPhaseCheck()}. The first failing check decides
        // the outcome through the replay-exemption split of
        // {@see VerifyError::isReplayExempt()}:
        //
        //  - the narrow exempt set (Expired, IpMismatch, MissingClientIp,
        //    later the telemetry gate) describes the original
        //    redemption's circumstances rather than this request's
        //    authorization. A consumed record failing one of them is
        //    never deleted: its consumed state — the deterministic result
        //    and the operation identity — is crash-recovery evidence that
        //    must survive to its retention TTL, and it falls through to
        //    the consume transition below, where the consumed branch
        //    decides between identity-gated replay, AlreadyConsumed and
        //    ConsumeIndeterminate with the record preserved — but only
        //    after the compositional replay gate below has confirmed
        //    that no hard invariant fails on the same request. A pending
        //    or capability-absent record keeps the one-shot
        //    cheap-failure delete, except the missing-client-IP failure:
        //    a bound challenge without a client IP is rejected but the
        //    record is kept, so the caller can retry with the IP.
        //
        //  - every other failure is a security verdict (wrong scope,
        //    request-binding mismatch, policy epoch, region, issuer, kid
        //    revocation/resolution, signature, record shape, the
        //    unsupported protocol/profile, the receipt-timing floor): it
        //    stands even when the operation identity matches a consumed
        //    record's committed success. The stored success never
        //    replays around it — the record is kept intact and the
        //    failure is returned; only a pending record is deleted.
        //
        // A retained-state read failure is fail-closed for both classes:
        // the consumed marker cannot be established, so the record may
        // be consumed evidence and is never deleted — the outcome is the
        // retryable StorageUnavailable, never the cheap failure
        // (mirrors the Rust core's evidence preservation; only a storage
        // without the consumed-state capability keeps the legacy
        // one-shot delete, since such backends carry no retained state
        // to preserve). The same helper revalidates the retained
        // consumed record on the consumed-operation resume path
        // {@see self::resumeConsumedOperation()}.
        $failure = $this->cheapPhaseCheck($peek, $secretKey, $expectedScope, $clientIp, true, $nowNs, $expectation);
        if ($failure !== null) {
            // The cleanup runs through the fused atomic transition when
            // the storage offers it ({@see AtomicDeleteIfPendingInterface}):
            // the delete decision and the delete itself are one script,
            // so a record a concurrent redeemer consumes (and commits)
            // between this failure and the cleanup is observed in its
            // consumed state and never erased. The missing-client-IP
            // retry path is the exception — it never deletes, so the
            // fused transition must not run at all.
            if ($this->storage instanceof AtomicDeleteIfPendingInterface && $failure !== VerifyError::MissingClientIp) {
                try {
                    $cleanup = $this->storage->deleteIfPending($token->nonce);
                } catch (\Throwable) {
                    // The fused read+delete failed: the record may be
                    // consumed evidence, so the fail-closed retryable
                    // storage outcome answers instead.
                    return VerifyOutcome::invalid(VerifyError::StorageUnavailable);
                }
                if (!$cleanup->wasConsumed()) {
                    // Missing, or the pending record was atomically
                    // deleted: the one-shot verdict stands.
                    return VerifyOutcome::invalid($failure);
                }
                if (!$failure->isReplayExempt()) {
                    // A hard security verdict on a consumed record: the
                    // fused transition kept the evidence and the failure
                    // stands — the identity-gated replay never overrides it.
                    return VerifyOutcome::invalid($failure);
                }
                // Consumed + exempt: the exempt circumstance may not mask
                // a hard verdict that also applies to this request. The
                // compositional replay gate re-evaluates every hard
                // invariant on the same peeked record; any failure wins,
                // the evidence stays preserved by the fused transition,
                // and only a clean pass falls through to the consumed
                // branch.
                $hard = $this->replaySecurityCheck($peek, $secretKey, $expectedScope, $expectation);
                if ($hard !== null) {
                    return VerifyOutcome::invalid($hard);
                }
                // Consumed + exempt with every hard invariant intact:
                // fall through to the consume branch.
            } else {
                $retained = $this->retainedConsumedState($token->nonce);
                if ($retained === 'unreadable') {
                    // The consumed marker cannot be established: the record
                    // may be retained consumed evidence, so it is never
                    // deleted and the caller gets the retryable storage
                    // failure instead of a possibly-wrong cheap verdict.
                    return VerifyOutcome::invalid(VerifyError::StorageUnavailable);
                }
                if ($retained === 'consumed' && !$failure->isReplayExempt()) {
                    // A hard security verdict on a consumed record: the
                    // evidence is preserved and the failure stands — the
                    // identity-gated replay never overrides it.
                    return VerifyOutcome::invalid($failure);
                }
                if ($retained === 'consumed') {
                    // Consumed + exempt: the compositional replay gate —
                    // the exempt circumstance may not mask a hard verdict
                    // that also applies to this request. Any hard failure
                    // wins with the evidence preserved; only a clean pass
                    // falls through to the consume branch below.
                    $hard = $this->replaySecurityCheck($peek, $secretKey, $expectedScope, $expectation);
                    if ($hard !== null) {
                        return VerifyOutcome::invalid($hard);
                    }
                } else {
                    if ($failure !== VerifyError::MissingClientIp) {
                        $this->bestEffortDelete($token->nonce);
                    }

                    return VerifyOutcome::invalid($failure);
                }
            }
        }

        // 7. Telemetry scoring (opt-in). The telemetry is client-controlled,
        //    so this is a defense-in-depth signal, not a hard gate: it only
        //    runs when the caller explicitly opts in. An empty telemetry
        //    payload ({} or []) is itself a bot signal (a real widget always
        //    reports fields) and must not bypass strict mode. The gate is
        //    replay-exempt per {@see VerifyError::isReplayExempt()} — it
        //    is client-side evidence about the original solve — so the
        //    deletion applies only to a not-yet-consumed record. A consumed
        //    record with failing telemetry falls through to the consumed
        //    branch with its retained state preserved, and an unreadable
        //    retained state is the fail-closed StorageUnavailable with the
        //    record kept.
        if ($enforceTelemetry && (empty($token->telemetry) || Telemetry::score($token->telemetry, $token->durationMs))) {
            if ($this->storage instanceof AtomicDeleteIfPendingInterface) {
                try {
                    $cleanup = $this->storage->deleteIfPending($token->nonce);
                } catch (\Throwable) {
                    return VerifyOutcome::invalid(VerifyError::StorageUnavailable);
                }
                if (!$cleanup->wasConsumed()) {
                    return VerifyOutcome::invalid(VerifyError::TelemetryRejected);
                }
                // Consumed: fall through to the consumed branch (the
                // gate is exempt — client-side solve evidence).
            } else {
                $retained = $this->retainedConsumedState($token->nonce);
                if ($retained === 'unreadable') {
                    return VerifyOutcome::invalid(VerifyError::StorageUnavailable);
                }
                if ($retained !== 'consumed') {
                    $this->bestEffortDelete($token->nonce);

                    return VerifyOutcome::invalid(VerifyError::TelemetryRejected);
                }
            }
        }

        // 8. Argon2id admission: the memory-hard hash is expensive, so an
        //    optional gate bounds concurrency. Exhaustion rejects without
        //    consuming or deleting the record; the client can retry.
        $lease = null;
        if ($peek->algorithm === PoWAlgorithm::Argon2id && $this->argonGate !== null) {
            try {
                $lease = $this->argonGate->acquire();
            } catch (\Throwable) {
                // Backend failure: report a typed, non-consuming result so
                // the challenge stays intact and can be retried after the
                // admission backend recovers.
                return VerifyOutcome::invalid(VerifyError::AdmissionUnavailable);
            }
            if ($lease === null) {
                return VerifyOutcome::invalid(VerifyError::CapacityExceeded);
            }
        }

        try {
            // 9. Consume (one-shot transition) and re-derive the
            //    proof. The record is marked consumed and kept until its TTL.
            //    An identity-bearing consume records the logical-operation
            //    identity atomically with the state flip (a storage without
            //    the identity capability verifies normally but records no
            //    identity).
            try {
                $consumed = $operationIdentity !== null && $this->storage instanceof OperationIdentityAwareStorageInterface
                    ? $this->storage->consumeWithOperationIdentity($token->nonce, $operationIdentity)
                    : $this->storage->consume($token->nonce);
            } catch (\Throwable) {
                // A lost transition response is ambiguous: the challenge may
                // or may not have been consumed. Report the indeterminate
                // state instead of RecordNotFound.
                return VerifyOutcome::invalid(VerifyError::ConsumeIndeterminate);
            }
            if ($consumed === null) {
                return VerifyOutcome::invalid(VerifyError::RecordNotFound);
            }

            // Consumed-state retry: an already-consumed record replays its
            // committed deterministic result without re-deriving the proof;
            // a retry sees exactly what the consuming attempt saw. A stored
            // invalid outcome is deterministic and replays to any caller.
            // A stored success is an authorization grant: it replays only
            // when the caller proves the exact logical operation — the
            // operation identity recorded atomically with the
            // pending→consumed transition — so one solved token can never
            // fund a different operation. A retry with a null identity, or
            // with a different operation's identity, is refused as
            // AlreadyConsumed: the safe default is that an already-consumed
            // token is refused unless the caller proves the exact logical
            // operation. A consumed record without a committed result
            // (crash between consume and commit) is ambiguous, and the
            // caller treats it as such.
            if ($consumed->consumedBefore) {
                if ($consumed->consumedResult !== null) {
                    if (!$consumed->consumedResult->valid) {
                        return VerifyOutcome::invalid(VerifyError::InsufficientWork);
                    }
                    if (
                        $operationIdentity !== null
                        && $consumed->operationIdentity !== null
                        && hash_equals($consumed->operationIdentity, $operationIdentity)
                    ) {
                        // Failed-barrier replay guard: the consume/commit
                        // mutations that produced this stored success may
                        // have landed on the primary with their WAIT
                        // failing. Accepting the stored result read-only
                        // would return a success that a promotion could
                        // lose — the barrier is re-established before the
                        // acceptance (a shortfall fails closed).
                        if ($this->storage instanceof \KiwiCaptcha\ReplicationBarrierInterface) {
                            $this->storage->establishReplicationFence('the stored-result replay acceptance');
                        }

                        return VerifyOutcome::valid($consumed->record->nonce, $consumed->consumedResult->binding, true);
                    }

                    return VerifyOutcome::invalid(VerifyError::AlreadyConsumed);
                }

                return VerifyOutcome::invalid(VerifyError::ConsumeIndeterminate);
            }
            $record = $consumed->record;

            // The consumed instance must be the same challenge that was
            // validated and HMAC-checked via peek. The v2 HMAC signs every
            // immutable parameter (kid included), so full re-validation and
            // signature re-verification on the consumed instance is the
            // check that holds: a swapped or racing record fails closed
            // instead of verifying against bytes that were never
            // validated. The signature secret is re-resolved for the
            // consumed record's kid; an instance whose kid is unknown (or
            // ahead of the newest configured kid) cannot be authenticated
            // and fails closed as MalformedRecord.
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

            // Security-policy epoch on the consumed instance: a
            // racing swap that replaced the record between peek and consume
            // must fail closed here too, so the instance that actually
            // proves the PoW is from the current policy epoch.
            if ($this->expectedPolicyVersion !== null && ($record->policyVersion ?? 1) !== $this->expectedPolicyVersion) {
                return VerifyOutcome::invalid(VerifyError::WrongPolicyVersion);
            }

            // Deployment issuer on the consumed instance: the
            // same racing-swap fail-closed guarantee as the policy check.
            if ($this->expectedIssuer !== null && $record->issuer !== $this->expectedIssuer) {
                return VerifyOutcome::invalid(VerifyError::WrongIssuer);
            }

            $hash = $this->deriveHash($record, $token->counter);
            if ($hash === null) {
                // An Argon2id record whose parameters are within the ceilings
                // but cannot be represented by the libsodium-backed verifier
                // (p != 1) is authentic but unsupported. A SHA-256 null can
                // only be a salt-decode failure (already shape-validated),
                // hence malformed.
                return VerifyOutcome::invalid($record->algorithm === PoWAlgorithm::Argon2id
                    ? VerifyError::UnsupportedArgon2Params
                    : VerifyError::MalformedRecord);
            }
            if (self::leadingZeroBits($hash) < $record->targetBits) {
                // Commit the deterministic invalid outcome (best-effort) so
                // a retry sees the same InsufficientWork without re-deriving.
                $this->bestEffortCommit($record->nonce, false, $record->requestBinding);

                return VerifyOutcome::invalid(VerifyError::InsufficientWork);
            }

            // 10. Post-derive final revalidation: the expensive
            //     derivation succeeded, so re-check against the current
            //     server clock and the current expectations before
            //     accepting. The challenge may have expired during the
            //     derivation (the clock read here is the verifier's now
            //     closure, so tests can drive it), and the policy epoch,
            //     region and issuer may have rotated mid-derivation. The
            //     expectation values read here are the current ones, not a
            //     snapshot from the cheap phase.
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

            // Commit the deterministic valid outcome (best-effort: a
            // storage failure must not change the outcome) so a retry
            // replays it without re-deriving.
            $this->bestEffortCommit($record->nonce, true, $record->requestBinding);

            return VerifyOutcome::valid($record->nonce, $record->requestBinding);
        } finally {
            if ($lease !== null) {
                try {
                    $this->argonGate?->release($lease);
                } catch (\Throwable) {
                    // Best-effort: a failed release must not override the
                    // verification result (the challenge is already
                    // consumed). A leaked lease is recovered by its TTL.
                }
            }
        }
    }

    /**
     * Resume a consumed logical operation's derivation: the narrowly
     * authorized crash-recovery path for the Siteverify takeover.
     *
     * Only a caller that has independently proven the retained consumed
     * record's exact operation identity may call it. The Siteverify
     * takeover gate proves the identity by comparing the consumed record's
     * own operation identity, written atomically with the pending→consumed
     * transition, against the claim fingerprint: same backend, same
     * idempotency key, same response hash, same remote-IP fingerprint.
     * The record must be consumed and carry exactly the given identity.
     * Any mismatch, a missing record, a not-yet-consumed record, or a
     * null identity (e.g. a no-key first redemption) is refused with
     * ConsumeIndeterminate. The identity must match exactly; the same
     * response hash, the same backend, or the same nonce without the
     * exact fingerprint is refused.
     *
     * When the retained record already carries a committed deterministic
     * result, that result is returned unchanged (the ordinary
     * committed-outcome semantics). Otherwise the resultless derivation
     * is resumed and committed only after the signed expiry is re-checked
     * against the current clock twice, the same acceptance boundary as
     * the ordinary verify path. Before the resumed derivation, past the
     * signed deadline the resume fails closed with invalid(Expired),
     * nothing is derived and nothing is committed. After it, a derivation
     * that starts before the signed deadline but finishes after it
     * commits Expired, never a post-deadline Valid. Then every immutable
     * security property is revalidated exactly like the ordinary verify
     * path via {@see self::cheapPhaseCheck()}. The revalidation covers
     * record structural validity, the protocol version gate, kid
     * validity/revocation, the HMAC signature, the Argon2id process
     * ceilings, expected scope, IP binding when enabled, region, policy
     * epoch, issuer, and token counter bounds. Argon2id admission still
     * applies to the resumed derivation.
     *
     * Before the commit, the current clock and the current expectations
     * are re-checked like the ordinary post-derive final revalidation:
     * the expiry re-read, then the policy epoch, region and issuer. A
     * deadline crossing or a rotation landing mid-derivation refuses the
     * resume. The minimum-duration floor is exempt (it was passed before
     * the consume; it is not a security deadline). The signed expiry is
     * exempt only on the committed-result recovery: that result was
     * durably recorded only after the original final expiry check
     * passed, so recovering it after expiry remains correct. No durable
     * success marker exists for a resultless resume; the original
     * attempt's Expired outcome was deliberately not committed. The
     * commit is not best-effort: a failed commit reads the state back,
     * returning a concurrent recovery's committed result (the winner's
     * stored outcome), and only a genuinely missing result yields
     * StorageUnavailable.
     *
     * Native replay security is aligned: {@see self::verify()} gates a
     * stored success on the exact operation identity the same way, and
     * it still returns ConsumeIndeterminate for a consumed record
     * without a committed result. The identity gate here therefore
     * cannot be satisfied by a different logical operation.
     *
     * @param string      $rawToken          base64 solution token from the widget.
     * @param string      $secretKey         HMAC secret key.
     * @param string      $operationIdentity the logical-operation identity the
     *                                       caller proved the retained consumed
     *                                       record carries; its exact match is
     *                                       the sole authorization to resume.
     * @param string|null $expectedScope     required challenge scope (null = any).
     * @param string|null $clientIp          client IP for the optional IP binding.
     * @param string|null $expectedRequestBinding the application transaction
     *                                       binding a bound record's signed
     *                                       request_binding must equal,
     *                                       enforced before the resumed
     *                                       derivation and the
     *                                       committed-result fast path.
     *                                       The default semantics are
     *                                       exact Option-equality: an
     *                                       explicitly unbound record
     *                                       under a presented expected
     *                                       binding is
     *                                       RequestBindingMismatch (fail
     *                                       closed), and a bound record
     *                                       under null is refused too.
     *                                       The legacy compatibility mode
     *                                       is available only through the
     *                                       explicitly named
     *                                       RequestBindingExpectation::legacy();
     *                                       null with the legacy
     *                                       expectation keeps the binding
     *                                       unenforced.
     */
    public function resumeConsumedOperation(
        string $rawToken,
        string $secretKey,
        string $operationIdentity,
        ?string $expectedScope = null,
        ?string $clientIp = null,
        ?string $expectedRequestBinding = null,
        ?RequestBindingExpectation $bindingExpectation = null,
    ): VerifyOutcome {
        // The default binding semantics are exact, as on the verify()
        // path: expectedRequestBinding requires the challenge to be bound
        // to this transaction. The legacy compatibility mode is available
        // only through the explicitly named
        // RequestBindingExpectation::legacy() value.
        $expectation = $bindingExpectation ?? RequestBindingExpectation::exact($expectedRequestBinding);
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

        // The identity gate: only a consumed record carrying exactly this
        // operation identity may have its derivation resumed. The identity
        // was written atomically with the pending→consumed transition, so
        // it is provably the actual atomic consume winner's. Anything else
        // is ambiguous for this caller and refused as ConsumeIndeterminate
        // (retryable; the caller should not have reached this path).
        if (
            $consumed === null
            || $consumed->operationIdentity === null
            || !hash_equals($consumed->operationIdentity, $operationIdentity)
        ) {
            return VerifyOutcome::invalid(VerifyError::ConsumeIndeterminate);
        }

        // 4b. Application transaction binding, enforced before the resumed
        //     derivation AND the committed-result fast path, through the
        //     same canonical helper as every other binding check (exact
        //     Option-equality under RequestBindingExpectation::exact(),
        //     the legacy compatibility mode, or unenforced) — there is NO
        //     separate nullable interpretation left that a committed
        //     result could bypass.
        if (($e = $this->checkRequestBinding($consumed->record, $expectation)) !== null) {
            return VerifyOutcome::invalid($e);
        }

        // Committed-result fast path: the deterministic outcome already
        // stored by this logical operation (or a concurrent recovery of it)
        // is returned unchanged, exactly the committed-outcome semantics of
        // the ordinary verify path.
        if ($consumed->consumedResult !== null) {
            // Failed-barrier replay guard: the committed result's writes
            // may have landed with their WAIT failing; accepting the
            // stored success read-only would return a success a promotion
            // could lose — the barrier is re-established before the
            // acceptance (a shortfall fails closed).
            if ($this->storage instanceof \KiwiCaptcha\ReplicationBarrierInterface) {
                $this->storage->establishReplicationFence('the resumed committed-result acceptance');
            }

            return $consumed->consumedResult->valid
                ? VerifyOutcome::valid($consumed->record->nonce, $consumed->consumedResult->binding, true)
                : VerifyOutcome::invalid(VerifyError::InsufficientWork);
        }
        $record = $consumed->record;

        // The resultless-resume expiry gate. The committed-result fast
        // path above is the only expiry-exempt recovery: a committed
        // result was durably recorded only after the original final
        // expiry check passed, step 10 of {@see self::verify()}, so
        // recovering it after expiry remains correct. A resultless
        // resume has no durable success marker: the original attempt's
        // derivation crossed the signed deadline and verify() returned
        // Expired without committing, so re-deriving now could turn
        // that same logical redemption into a post-deadline Valid. Re-run
        // the post-derive expiry check of the ordinary verify() before
        // the resumed derivation (the record's signed expiresAt vs the
        // current clock, read via the same now closure). Expired fails
        // closed: nothing derived, nothing committed, deterministic on
        // every retry. The minimum-duration floor stays exempt: it was
        // passed before the consume; it is not a security deadline.
        $now = $this->now !== null ? (int) ($this->now)() : time();
        if ($now >= $record->expiresAt) {
            return VerifyOutcome::invalid(VerifyError::Expired);
        }

        // Revalidate every immutable security property exactly like the
        // ordinary verify path (the shared cheap-phase helper; timing
        // exempted per the contract above). The retained record is not
        // deleted on a failure: it is the recovery evidence and must
        // survive for a later retry (it is already consumed; deletion
        // buys nothing). An exempt failure runs the compositional replay
        // gate first — the same rule as the ordinary path: the exempt
        // circumstance may not mask a hard verdict that also applies.
        $failure = $this->cheapPhaseCheck($record, $secretKey, $expectedScope, $clientIp, false, 0, $expectation);
        if ($failure !== null) {
            if ($failure->isReplayExempt()
                && ($hard = $this->replaySecurityCheck($record, $secretKey, $expectedScope, $expectation)) !== null
            ) {
                return VerifyOutcome::invalid($hard);
            }

            return VerifyOutcome::invalid($failure);
        }

        // Argon2id admission still applies: the resumed derivation is as
        // expensive as the original, so the gate bounds it the same way.
        // Exhaustion rejects without committing (the record stays
        // consumed-without-result, and a later retry can resume again
        // once capacity is available).
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
                // authentic but unsupported. A SHA-256 null can only be a
                // salt-decode failure (already shape-validated), hence
                // malformed.
                return VerifyOutcome::invalid($record->algorithm === PoWAlgorithm::Argon2id
                    ? VerifyError::UnsupportedArgon2Params
                    : VerifyError::MalformedRecord);
            }
            $valid = self::leadingZeroBits($hash) >= $record->targetBits;

            // Post-derive final revalidation: the same current-clock and
            // current-expectation re-check the ordinary verify() runs
            // after its derivation, step 10 of {@see self::verify()}.
            // First the expiry is re-read against the current clock: a
            // derivation that started before the signed deadline but
            // finished after it commits Expired, exactly the ordinary
            // acceptance boundary. Then the policy epoch, region and
            // issuer are re-checked so a rotation that lands between the
            // pre-derive revalidation and the commit refuses the resumed
            // derivation; the values read here are current, never a
            // snapshot from the cheap phase. Nothing is committed on
            // failure, so the retained record stays
            // consumed-without-result for a later same-identity resume.
            // The minimum-duration floor remains exempt (it was passed
            // before the consume; it is not a security deadline).
            if ($valid) {
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
            }

            // Commit the resumed deterministic outcome, not best-effort:
            // the resume must persist what it derived (a retry of the
            // consumed record without a stored result would degrade to
            // ConsumeIndeterminate forever). A failed commit reads the
            // state back: a concurrent recovery may have won the commit,
            // and the winner's stored result is then authoritative (the
            // same logical operation derives the same outcome either way).
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
                    // Failed-barrier replay guard: both mutations of this
                    // resume, the original consume and the commitResult,
                    // may have landed on the primary with their WAIT
                    // failing, leaving the replica still holding the
                    // pending challenge. Accepting the read-back success
                    // would return a Valid a stale-replica promotion could
                    // resurrect into a second redemption. The causal
                    // fence is re-established on this accepting connection
                    // before the acceptance, and a shortfall fails closed
                    // to StorageUnavailable, never Valid.
                    try {
                        if ($this->storage instanceof \KiwiCaptcha\ReplicationBarrierInterface) {
                            $this->storage->establishReplicationFence('the resumed post-commit read acceptance');
                        }
                    } catch (\Throwable $fenceFailure) {
                        return VerifyOutcome::invalid(VerifyError::StorageUnavailable);
                    }

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
                    // Best-effort: a failed release must not override the
                    // resumed verification result. A leaked lease is
                    // recovered by its TTL.
                }
            }
        }
    }

    /**
     * Structural validation of a stored record before any crypto or timing
     * work: scope shape, nonce/salt sizes, TTL ceiling, the prefix binding,
     * and the per-algorithm difficulty range. A record failing any check is
     * malformed; it cannot have come from a KiwiCaptcha issuer.
     *
     * The difficulty guard is the protocol floor/ceiling pair 1..20 applied
     * to both algorithms. The leading-zero comparison only ever runs against
     * a validated difficulty, so the stored value cannot drive an unbounded
     * comparison; 0, 21, 256, 65535 and similar are all rejected here,
     * before any hash is computed. Issuance keeps the narrower
     * per-algorithm ceilings.
     *
     * The scope check enforces the narrow identifier alphabet
     * `[A-Za-z0-9._:-]+`, 1..128 bytes; the alphabet itself makes the
     * legacy '|' separator rejection unnecessary.
     *
     * Argon2id memory/time/parallelism are not bounded here: the
     * absolute process ceilings apply to the signed parameters after
     * signature authentication, see {@see self::argon2CeilingsOk()}. A
     * validly signed out-of-range record is reported as
     * UnsupportedArgon2Params rather than MalformedRecord, while unsigned
     * foreign records fail the signature check.
     */
    private function validateRecord(ChallengeRecord $record): bool
    {
        // Protocol version is part of the wire contract: only 1 (legacy,
        // migration window) and 2 (current) exist. Anything else is a
        // corrupt or foreign record.
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
        // the leading-zero comparison for both algorithms; a stored value
        // outside the bounds is rejected here, before any hash computation.
        if ($record->targetBits < Config::MIN_DIFFICULTY || $record->targetBits > Config::MAX_DIFFICULTY) {
            return false;
        }

        return true;
    }

    /**
     * The cheap-phase security checks shared by the ordinary verify path
     * and the consumed-operation resume path, run in the order of the
     * ordinary path; the first failing check decides the outcome:
     *
     *   1.  structural validation, see {@see self::validateRecord()}.
     *   1b. protocol version gate (v1 only during an explicit migration
     *       window).
     *   2.  kid gate: a revoked kid fails immediately (UnknownKid);
     *       compromise revocation overrides the normal rotation grace.
     *   2.  kid resolution: with a secretsByKid set, the signature secret
     *       is selected per the record's kid. An unknown kid, or one
     *       beyond the newest configured kid (the rollback/forward guard),
     *       fails with UnknownKid before any signature work; an empty set
     *       keeps the legacy single-secret path.
     *   2.  HMAC signature re-check, see {@see self::verifyRecordSignature()}.
     *       BadSignature.
     *   2b. absolute Argon2id process ceilings (see
     *       {@see self::argon2CeilingsOk()}) after signature
     *       authentication and before any allocation:
     *       UnsupportedArgon2Params.
     *   3.  TTL (only when $checkTiming): expired, or an issuance more
     *       than the future-skew bound ahead, is Expired.
     *   4.  scope: challenge scope matches the expected flow (WrongScope).
     *   4b. application transaction binding: the default expectation is
     *       exact Option-equality — a bound record must present its
     *       binding (RequestBindingMismatch otherwise) and an explicitly
     *       unbound record under a presented expected binding is refused
     *       too. The legacy mode, where an unbound record is permitted
     *       regardless of the expected binding, is available only
     *       through the explicitly named
     *       RequestBindingExpectation::legacy().
     *   5.  IP binding: the stored record is authoritative. An empty
     *       binding tag disables the check; a nonempty tag means the
     *       challenge is bound, so a missing client IP fails closed
     *       (MissingClientIp) and a mismatched tag is IpMismatch. Both
     *       are keyed by the kid-selected secret (K_ip_bind is derived
     *       from the same master secret that signed the challenge).
     *   5b. region binding: a configured expected region rejects any record
     *       whose region does not match exactly; an unbound (null) region
     *       fails closed (WrongRegion).
     *   5c. security-policy epoch: a record issued under a different epoch
     *       is WrongPolicyVersion.
     *   5d. deployment issuer: a record issued by a different deployment,
     *       including an unbound (null) issuer, is WrongIssuer.
     *   6.  server-measured minimum duration (only when $checkTiming).
     *       A record without issued_at_ns is malformed; a receipt before
     *       the floor is TooFast. A receipt preceding issuance beyond the
     *       skew tolerance is physically impossible; within the bound the
     *       floor check is skipped and the PoW check still applies.
     *
     * The timing group is not uniformly exempt on the resume path
     * ($checkTiming = false). The TTL and the minimum-duration floor are
     * skipped here, but the resultless resume re-checks the signed expiry
     * against the current clock both before and after the resumed
     * derivation. The signed deadline is therefore enforced fail closed
     * on both sides of the expensive work; a resultless resume can never
     * acquire success after it, because no durable success marker exists.
     * The minimum-duration floor stays exempt (it was passed before the
     * consume; it is not a security deadline). The committed-result
     * recovery is fully timing-exempt: its result was durably recorded
     * only after the original final expiry check passed.
     *
     * Returns the first failing error, or null when every check passes.
     * The caller owns the failure policy. The ordinary verify path
     * deletes the peeked record on every failure except MissingClientIp:
     * a bound challenge without a client IP is rejected but kept, so the
     * caller can retry with the IP. A retained consumed record is never
     * deleted by a cheap failure; it is the recovery evidence and the
     * consumed branch decides its outcome. The resume path also never
     * deletes the retained consumed record.
     *
     * @param int|null $nowNs server receipt time in epoch microseconds
     *                        (used by the minimum-duration check only)
     * @param string|null $expectedRequestBinding the application transaction
     *                        binding the record's signed request_binding must
     *                        equal, or null to keep the binding unenforced
     */
    private function cheapPhaseCheck(
        ChallengeRecord $record,
        string $secretKey,
        ?string $expectedScope,
        ?string $clientIp,
        bool $checkTiming,
        ?int $nowNs,
        RequestBindingExpectation $expectation,
    ): ?VerifyError {
        // 1-2b. The authenticated hard core: structure, protocol gate,
        //       kid revocation/resolution, signature, Argon ceilings.
        if (($e = $this->checkAuthenticatedShape($record, $secretKey)) !== null) {
            return $e;
        }
        // The signing secret for the IP-binding re-derivation; the shape
        // group above has already established it resolves.
        $signingSecret = $this->secretForKey($record, $secretKey);

        // 3. TTL (the exempt expiry circumstance).
        if ($checkTiming && ($e = $this->checkTtl($record)) !== null) {
            return $e;
        }

        // 4-4b. Scope and the expected request binding (hard).
        if (($e = $this->checkScopeAndBinding($record, $expectedScope, $expectation)) !== null) {
            return $e;
        }

        // 5. IP binding (the exempt network circumstances).
        if (($e = $this->checkIpBinding($record, $clientIp, $signingSecret ?? '')) !== null) {
            return $e;
        }

        // 5b-5d. Region, policy epoch, issuer (hard expectations).
        if (($e = $this->checkDeploymentExpectations($record)) !== null) {
            return $e;
        }

        // 6. Server-measured minimum duration (timing).
        if ($checkTiming && ($e = $this->checkMinDuration($record, $nowNs)) !== null) {
            return $e;
        }

        return null;
    }

    /**
     * The compositional replay gate: every non-exempt hard invariant,
     * evaluated with the exempt circumstances (the TTL and the IP
     * binding) left out. Those circumstances may have caused the cheap
     * phase's first failure on a consumed record.
     *
     * A first-error routing lets an exempt failure that sits early in
     * the cheap-phase order shadow every later hard verdict. The expiry
     * sits before scope, binding, region, policy and issuer; the IP
     * binding sits before region, policy and issuer. The shadowed
     * verdict would then never run, and the retry would route into the
     * identity-gated consumed branch, replaying the stored success
     * around a security failure.
     *
     * This gate closes that. When the cheap phase fails with a
     * replay-exempt error on a consumed record, this check re-evaluates
     * the full hard set on the same record. The set covers the
     * authenticated shape core (structure, protocol, kid, signature,
     * ceilings), scope, the expected request binding, the deployment
     * expectations and the receipt-timing floor. Any failure wins
     * outright with the consumed evidence preserved. Only a clean pass
     * lets the exempt circumstance route into the consumed branch. The
     * check functions are the same ones {@see self::cheapPhaseCheck()}
     * composes, so the two paths can never diverge on what an
     * invariant means.
     *
     * Returns the failing hard error, or null when every hard replay
     * invariant passes. The fresh-challenge path never calls this: the
     * public first-error precedence for pending records is unchanged.
     */
    private function replaySecurityCheck(
        ChallengeRecord $record,
        string $secretKey,
        ?string $expectedScope,
        RequestBindingExpectation $expectation,
    ): ?VerifyError {
        if (($e = $this->checkAuthenticatedShape($record, $secretKey)) !== null) {
            return $e;
        }
        if (($e = $this->checkScopeAndBinding($record, $expectedScope, $expectation)) !== null) {
            return $e;
        }
        if (($e = $this->checkDeploymentExpectations($record)) !== null) {
            return $e;
        }
        if (($e = $this->checkMinDuration($record, null)) !== null) {
            return $e;
        }

        return null;
    }

    /**
     * The authenticated hard core of the cheap phase: structural
     * validation, the protocol version gate, kid revocation and
     * resolution, the HMAC signature re-check, and the Argon2id process
     * ceilings — every invariant that authenticates the record before
     * any circumstance is evaluated. Shared by the cheap phase and the
     * compositional replay gate.
     */
    private function checkAuthenticatedShape(ChallengeRecord $record, string $legacySecret): ?VerifyError
    {
        // 1. Structural validation of the stored record.
        if (!$this->validateRecord($record)) {
            return VerifyError::MalformedRecord;
        }

        // 1b. Protocol version gate: v1 (legacy, less comprehensively
        //     signed) is only accepted during an explicit migration window;
        //     v2 has been the issuance format longer than the maximum
        //     challenge lifetime, so any surviving v1 record is stale or
        //     foreign.
        if ($record->protocolVersion === 1 && !$this->acceptLegacyV1) {
            return VerifyError::MalformedRecord;
        }

        // 2. Kid gate: a revoked kid is rejected with
        //    UnknownKid immediately — before the signature check and before
        //    the secret selection — so compromise revocation overrides the
        //    normal rotation grace (a perfectly signed challenge under a
        //    revoked kid still fails). Cheap: a set membership test only.
        if ($this->isRevokedKid($record->kid)) {
            return VerifyError::UnknownKid;
        }

        // 2. Kid resolution: with a secretsByKid set, the
        //    signature secret is selected per the record's kid; an unknown
        //    kid, or one beyond the newest configured kid (the
        //    rollback/forward guard: a future-keyed challenge must not
        //    verify on an older node), fails with UnknownKid before any
        //    signature work. An empty set keeps the legacy single-secret
        //    path: the verify() $secretKey parameter is used for every
        //    record (kid is then metadata only).
        $signingSecret = $this->secretForKey($record, $legacySecret);
        if ($signingSecret === null) {
            return VerifyError::UnknownKid;
        }

        // 2. Signature re-check: reconstruct the payload from the record and
        //    compare against the signature embedded in the challenge string.
        //    Protocol v1 uses the legacy canonical form; protocol v2 uses the
        //    full-parameter canonical payload (kid included). The key is the
        //    kid-selected secret, or the verify() secret in legacy mode.
        if (!$this->verifyRecordSignature($record, $signingSecret)) {
            return VerifyError::BadSignature;
        }

        // 2b. Absolute Argon2id process ceilings: the signed
        //     parameters are validated after signature authentication and
        //     before any allocation or computation. Out-of-range values are
        //     authentic but unsupported — UnsupportedArgon2Params, not
        //     MalformedRecord (the record really came from an issuer holding
        //     the secret; it just violates the hard process limits).
        if (!$this->argon2CeilingsOk($record)) {
            return VerifyError::UnsupportedArgon2Params;
        }

        return null;
    }

    /**
     * The TTL window on the verifier's clock: expired, or an issuance
     * more than the future-skew bound ahead, is Expired. The exempt
     * expiry circumstance — deliberately excluded from the compositional
     * replay gate.
     */
    private function checkTtl(ChallengeRecord $record): ?VerifyError
    {
        $now = $this->now !== null ? (int) ($this->now)() : time();
        if ($now >= $record->expiresAt) {
            return VerifyError::Expired;
        }
        if ($record->issuedAt > $now + self::MAX_CLOCK_SKEW) {
            return VerifyError::Expired;
        }

        return null;
    }

    /**
     * Scope validation and the expected request binding — hard
     * authorization invariants, in cheap-phase order. Shared by the
     * cheap phase and the compositional replay gate.
     */
    private function checkScopeAndBinding(ChallengeRecord $record, ?string $expectedScope, RequestBindingExpectation $expectation): ?VerifyError
    {
        // 4. Scope validation.
        if ($expectedScope !== null && $record->scope !== $expectedScope) {
            return VerifyError::WrongScope;
        }

        // 4b. Application transaction binding through the ONE shared
        //     helper used by every binding check in the verifier (the
        //     cheap phase, the replay gate, the final revalidation and
        //     the resumed-operation path): exact Option-equality under
        //     RequestBindingExpectation::exact(), the legacy
        //     compatibility mode for the historical nullable argument,
        //     or no enforcement under unenforced().
        return $this->checkRequestBinding($record, $expectation);
    }

    /**
     * The single request-binding check: exact Option-equality between the
     * record's signed request_binding and the expectation's authoritative
     * binding — null == explicitly unbound, a string == the same bound
     * transaction — compared in constant time when both sides carry a
     * string. Under the legacy compatibility mode a null expected binding
     * disables enforcement entirely.
     */
    private function checkRequestBinding(ChallengeRecord $record, RequestBindingExpectation $expectation): ?VerifyError
    {
        if (!$expectation->enforced) {
            return null;
        }
        if ($record->requestBinding === null || $expectation->expected === null) {
            // The legacy compatibility mode does not require binding
            // presence: an explicitly unbound record passes regardless of
            // the expected binding (the historical behavior). The exact
            // mode requires Option-equality: null == explicitly unbound,
            // a string == the same bound transaction.
            if ($record->requestBinding === null && !$expectation->requireBindingPresence) {
                return null;
            }

            return $record->requestBinding === $expectation->expected
                ? null
                : VerifyError::RequestBindingMismatch;
        }

        return hash_equals($record->requestBinding, $expectation->expected)
            ? null
            : VerifyError::RequestBindingMismatch;
    }

    /**
     * IP binding. The stored record is authoritative. An empty
     * binding tag means binding is disabled (BindingMode::None). A
     * nonempty tag means the challenge is bound, so a missing
     * client IP fails closed (MissingClientIp) instead of silently
     * skipping the check. The caller must provide the IP it would
     * have passed to issuance. Protocol v2 records carry a nonce-bound
     * binding tag (recomputed here); v1 records carry the legacy
     * stable IP hash. Both are keyed by the kid-selected secret
     * (K_ip_bind is derived from the same master secret
     * that signed the challenge). The exempt network circumstances —
     * deliberately excluded from the compositional replay gate.
     */
    private function checkIpBinding(ChallengeRecord $record, ?string $clientIp, string $signingSecret): ?VerifyError
    {
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

        return null;
    }

    /**
     * The deployment expectations — region, security-policy epoch and
     * issuer — hard invariants in cheap-phase order. Shared by the
     * cheap phase and the compositional replay gate.
     */
    private function checkDeploymentExpectations(ChallengeRecord $record): ?VerifyError
    {
        // 5b. Region binding: a verifier configured
        //     with an expected region rejects any record whose region does
        //     not match exactly; an unbound (null) record region fails
        //     closed (a region-unbound record satisfies no region-bound
        //     verifier). With no expected region, region is unenforced.
        if ($this->region !== null && $record->region !== $this->region) {
            return VerifyError::WrongRegion;
        }

        // 5c. Security-policy epoch: the policy that authorized
        //     this challenge must still be in force; the verifier rejects
        //     records issued under a different epoch (WrongPolicyVersion).
        if ($this->expectedPolicyVersion !== null && ($record->policyVersion ?? 1) !== $this->expectedPolicyVersion) {
            return VerifyError::WrongPolicyVersion;
        }

        // 5d. Deployment issuer: a verifier configured with an
        //     expected issuer rejects any record whose issuer does not match
        //     exactly; an unbound (null) record issuer fails closed, because
        //     an unbound record is redeemable by every deployment and must
        //     not satisfy an issuer-bound verifier.
        if ($this->expectedIssuer !== null && $record->issuer !== $this->expectedIssuer) {
            return VerifyError::WrongIssuer;
        }

        return null;
    }

    /**
     * Server-measured minimum duration: elapsed_us is the gap between
     * the record's high-resolution issuance timestamp (epoch
     * microseconds) and the verification receipt time. The
     * client-reported durationMs is forgeable, so it never drives the
     * TooFast check and there is no legacy fallback; a record without
     * issued_at_ns cannot be timed and is malformed.
     */
    private function checkMinDuration(ChallengeRecord $record, ?int $nowNs): ?VerifyError
    {
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
                // physically impossible: reject as TooFast. Within the
                // bound the two hosts' clocks are unsynced, so the
                // elapsed time cannot be measured reliably and the floor
                // check is skipped for this verification; the
                // proof-of-work check still applies.
                return VerifyError::TooFast;
            }
        }

        return null;
    }

    /**
     * Absolute process ceilings for Argon2id parameters: the
     * signed record's memory/time/parallelism must sit within the
     * process ceilings before any allocation or computation. Runs after
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
     * Terminal cheap-failure cleanup. Deletion is not security-critical
     * once the challenge has been rejected, and a storage outage must not
     * turn a cheap invalid submission into an application exception; the
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
     * The retained consumed-state tri-state, best-effort read. The
     * storage seam is the retained consumed-state read
     * ({@see ConsumedStateReadableInterface}, implemented by the Redis
     * and array backends; the plain {@see StorageInterface::find()}
     * record carries no runtime state).
     *
     * @return 'consumed'    readable and present. Consumed evidence,
     *                       never deleted by a cheap failure; the
     *                       consumed branch decides instead.
     * @return 'pending'     readable and absent. Not yet consumed, so
     *                       the one-shot cheap-failure delete applies.
     * @return 'unknown'     no consumed-state capability. No retained
     *                       state to preserve, so the legacy one-shot
     *                       delete policy stays.
     * @return 'unreadable'  the retained-state read itself failed: the
     *                       consumed marker cannot be established, so the
     *                       record may be consumed evidence — it is never
     *                       deleted, and the caller gets the retryable
     *                       StorageUnavailable instead of a possibly
     *                       wrong cheap verdict. This is the same
     *                       fail-closed evidence preservation as the
     *                       Rust core.
     */
    private function retainedConsumedState(string $nonce): string
    {
        if (!$this->storage instanceof ConsumedStateReadableInterface) {
            return 'unknown';
        }
        try {
            return $this->storage->consumedState($nonce) !== null ? 'consumed' : 'pending';
        } catch (\Throwable) {
            return 'unreadable';
        }
    }

    /**
     * Terminal result commit for a consumed record. Best-effort by
     * design: a failed commit must not override the already-determined
     * verification outcome; without the stored result a retry of the
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
     * monitor: sets the current security-policy epoch the
     * verifier enforces. The monitor refreshes this from the central
     * security-policy state with a short cache and a monotonic guard, so a
     * stale or regressed value is never applied. Cheap; safe to call
     * before every verification.
     */
    public function setExpectedPolicyVersion(int $policyVersion): void
    {
        $this->expectedPolicyVersion = $policyVersion;
    }

    /**
     * @internal Test seam: rotate the current deployment
     * expectations (policy epoch, region, issuer) to model a rotation that
     * lands between the cheap checks and the post-derive final revalidation.
     * The final re-check always reads the current values, so a rotation
     * performed at any point before it (e.g. by a stateful clock/storage
     * stub mid-verification) is observed. All three parameters are applied
     * as given. Not part of the public verification contract; production
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
     * SHA-256: sha256(prefix || counter || salt_bytes), the counter in
     * decimal form. Argon2id: argon2id(password = prefix||counter, salt =
     * salt_bytes, m_cost = m_kib KiB, t_cost = t, p_cost = p, output =
     * 32 bytes).
     *
     * Returns null when the record is malformed or the algorithm cannot be
     * computed (e.g. Argon2id parameters outside KiwiCaptcha's protocol
     * profile: t < 3 or p != 1).
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
        // intentional, not a libsodium limit; libsodium accepts t >= 1).
        // Parameters outside the profile cannot be reproduced by the
        // libsodium-backed verifier, so fail closed with a distinguishable
        // error instead of silently verifying wrong bytes.
        if ($record->p !== 1 || $record->t < 3) {
            return null;
        }
        // Protocol unit: m_kib is kibibytes (65536 = 64 MiB). sodium's
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
     * in the challenge string. The v2 canonical payload covers every
     * immutable parameter (kid included), so a valid signature proves the
     * whole record is authentic; used in the cheap phase and re-applied to
     * the consumed instance (the proof-phase re-check).
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
     * With an empty secretsByKid set the legacy single-secret path stays:
     * the verify() $secretKey parameter is used for every record. With a
     * non-empty set the secret is looked up by the record's kid. Null is
     * returned, yielding UnknownKid, when the kid is unknown or exceeds
     * the newest configured kid: the rollback/forward guard that keeps a
     * future-keyed challenge from verifying on an older node.
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
     * test that runs before any signature work. Revocation overrides the
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
     * Count the leading zero bits of a 32-byte hash (big-endian bit order),
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
