<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Controller;

use BelConsulting\KiwiCaptchaBundle\SiteVerify\ArraySiteVerifyRedemptionGuard;
use BelConsulting\KiwiCaptchaBundle\SiteVerify\IdempotencyClaim;
use BelConsulting\KiwiCaptchaBundle\SiteVerify\RedisEval;
use BelConsulting\KiwiCaptchaBundle\SiteVerify\SiteVerifyIdempotencyStore;
use BelConsulting\KiwiCaptchaBundle\SiteVerify\SiteVerifyRedemptionGuard;
use KiwiCaptcha\DecodeError;
use KiwiCaptcha\SolutionToken;
use KiwiCaptcha\AtomicStorageInterface;
use KiwiCaptcha\Verifier;
use KiwiCaptcha\VerifyError;
use KiwiCaptcha\VerifyOutcome;
use Psr\Log\LoggerInterface;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * Provider-compatible Siteverify endpoint: accepts the incumbent backend
 * shape — `response`, `secret`, optional `remoteip` — as form or JSON,
 * and returns the provider-shaped verification JSON (`success`,
 * `challenge_ts`, `hostname`, `error-codes`). It calls the EXACT SAME
 * atomic Kiwi verifier as the native integration — there is no second
 * verification implementation, and the deterministic consumed-result
 * machinery makes safe verification retries free (a replayed `response`
 * resolves to the stored deterministic outcome instead of re-deriving).
 *
 * Security model:
 *  - The endpoint is DISABLED unless `kiwi_captcha.siteverify_secret` is
 *    configured. The compatibility secret authenticates SERVER-TO-SERVER
 *    use: an application backend (which holds the end-user IP) calls this
 *    endpoint with `remoteip`; a browser never sees the secret, so
 *    `remoteip` can never be supplied by an unauthenticated client.
 *  - The comparison is constant-time (`hash_equals`).
 *  - The request body is read with a hard byte cap (16 KiB) BEFORE any
 *    JSON decoding or business verification: the application-level
 *    accepted input is bounded and oversized bodies are refused early.
 *    Allocation-level request-body ceilings are a deployment concern —
 *    mirror the bound in the reverse proxy (client_max_body_size etc.)
 *    and in PHP (post_max_size) so oversized bytes never reach PHP at
 *    all.
 *  - The underlying verifier remains authoritative: TTL, scope/region/
 *    issuer/policy expectations, nonce-bound IP binding, timing floor,
 *    Argon ceilings and atomic single-use consumption all apply exactly as
 *    in the native path.
 *  - Verification idempotency ownership is protected by a LEASE WINDOW,
 *    not a process-global timer: the store's FIXED ownership lease
 *    (default 60s) exceeds the maximum supported verification / request
 *    execution window plus a safety margin, so a live owner is never
 *    overtaken mid-verify — no process-global signal state is touched.
 *    The strict ordering is enforced at construction (waiter bound >
 *    owner lease) and at container compile time (retention margin):
 *
 *      max verification runtime  <  fixed owner lease (60)
 *                                 <  waiter deadline (90)
 *                                 <= retained-state recovery retention (>=90)
 *
 *    Signed token expiry affects only FRESH redemptions, never the
 *    retained-state reconstruction: the consumed record outlives the
 *    takeover/retry horizon (risk.redis.ttl_margin_secs), so a
 *    late-lifetime crash still reproduces the original committed
 *    outcome.
 *  - A NONCE-LEVEL redemption guard records which logical operation
 *    originally redeemed a token (first-write-wins): a takeover under a
 *    DIFFERENT-UUID claim for an already-redeemed nonce is a DIFFERENT
 *    logical operation and can never reconstruct the original success —
 *    a consumed token can never become successful again through another
 *    idempotency UUID. The claim additionally binds the canonicalized
 *    remoteip fingerprint, so the same idempotency key with a changed
 *    remoteip CONFLICTS instead of reusing an outcome derived under
 *    another IP.
 */
final class SiteVerifyController
{
    /** Documented bounded maximum for the `response` token. */
    private const MAX_RESPONSE_BYTES = 8192;

    /**
     * The hard bound on the PENDING_SAME wait. A waiter that reaches this
     * bound without a stored result and without winning the atomic
     * takeover is answered with the retryable provider `internal-error`
     * error — it NEVER enters the verifier without holding the current
     * owner token. The ordering invariant is strict and enforced at
     * construction (waiter bound > the store's FIXED owner lease) and at
     * container compile time (waiter bound <= retained-state recovery
     * retention):
     *
     *   max verification runtime  <  fixed owner lease (60)
     *                              <  this bound (90)
     *                              <= recovery retention (>= 90)
     *
     * This bound is the absolute tail of the takeover/retry horizon;
     * signed token expiry never shortens it (expiry affects only fresh
     * redemptions, never the retained-state reconstruction).
     */
    public const IDEMPOTENCY_WAIT_SECS = 90.0;

    /**
     * Hard ceiling for the whole verification request body: 16 KiB covers
     * every legitimate provider envelope (response+secret+remoteip).
     */
    private const MAX_BODY_BYTES = 16 * 1024;

    /**
     * The redemption guard's retention horizon: the default challenge
     * lifetime (120s) plus a margin, so the guard outlives the retained
     * consumed-state evidence (token validity + the >= 90s recovery
     * margin) for every supported configuration. The guard is the
     * structural backstop of the duplicate-finalize path: it must stay
     * authoritative at least as long as the window in which a
     * different-UUID replay could otherwise be mis-recovered.
     */
    private const REDEMPTION_GUARD_TTL_SECS = 300;

    /**
     * The retained consumed-state recovery used on the takeover path. It
     * reconstructs ONLY when the storage is recovery-capable (the
     * SiteVerifyRecoveryCapableStorageInterface compile-time check in the
     * extension closes the silent-null gap of ConsumedOutcomeRecovery)
     * AND the redemption guard certifies this claim as the nonce's
     * original logical operation.
     */
    private ?\KiwiCaptcha\ConsumedOutcomeRecovery $recovery;

    /**
     * The NONCE-LEVEL redemption guard (see {@see SiteVerifyRedemptionGuard}):
     * records which logical operation originally redeemed a token, so a
     * takeover under a different-UUID claim can never reconstruct an
     * outcome it did not produce.
     */
    private readonly SiteVerifyRedemptionGuard $redemptionGuard;

    /**
     * @param array<string, string> $siteverifySecrets map of
     *        server-to-server secret -> expected scope; EMPTY disables the
     *        endpoint. A per-secret expected scope is REQUIRED — there is
     *        no global-secret + expectedScope=null combination, so a
     *        weaker token can never satisfy a stronger backend's secret.
     */
    public function __construct(
        private readonly Verifier $verifier,
        private readonly string $secretKey,
        private readonly array $siteverifySecrets,
        private readonly ?AtomicStorageInterface $storage = null,
        private readonly ?LoggerInterface $logger = null,
        // Server-owned compatibility metadata (action/cData bound at
        // challenge issuance) and provider-style verification idempotency
        // (idempotency_key). Null disables the respective feature:
        // metadata never appears in the response, and an idempotency_key
        // on the request is rejected (the operator must wire the stores
        // for provider-style retries).
        private readonly ?\BelConsulting\KiwiCaptchaBundle\SiteVerify\SiteVerifyMetadataStore $metadataStore = null,
        private readonly ?\BelConsulting\KiwiCaptchaBundle\SiteVerify\SiteVerifyIdempotencyStore $idempotencyStore = null,
        /** Shared Redis log gate (optional): flood-bounded invalid-secret diagnostics. */
        private readonly \Predis\Client|\Redis|null $logGate = null,
        /** Hard bound on the PENDING_SAME wait in seconds (see {@see self::IDEMPOTENCY_WAIT_SECS}). */
        private readonly float $idempotencyWaitSecs = self::IDEMPOTENCY_WAIT_SECS,
        /**
         * The security-policy epoch (risk.policy_version): part of the
         * idempotency backend identity, so a same-key request after a
         * policy change is a NEW logical operation (a conflict), never a
         * replay of the pre-change outcome.
         */
        private readonly int $policyVersion = 0,
        ?\KiwiCaptcha\ConsumedOutcomeRecovery $recovery = null,
        ?SiteVerifyRedemptionGuard $redemptionGuard = null,
    ) {
        $this->recovery = $recovery ?? (new \KiwiCaptcha\ConsumedOutcomeRecovery($this->storage ?? new \KiwiCaptcha\Storage\ArrayStorage()));
        $this->redemptionGuard = $redemptionGuard ?? new ArraySiteVerifyRedemptionGuard();
        // The lease-ordering invariant is ENFORCED at construction: the
        // waiter bound must exceed the FIXED owner lease (the store's
        // configured lease — never derived from a token's remaining
        // validity), otherwise the crash-recovery takeover is
        // unreachable (a waiter would give up before the lease ever
        // expires). The default ordering is
        // lease (60) < waiter bound (90) < challenge lifetime (120),
        // with the retained-state recovery retention (>= the waiter
        // bound) enforced at container compile time.
        if ($idempotencyStore !== null && $this->idempotencyWaitSecs <= $idempotencyStore->leaseSeconds()) {
            throw new \LogicException(sprintf(
                'KiwiCaptcha: the idempotency PENDING_SAME wait bound (%ss) must exceed the owner lease (%ss) — otherwise a crashed owner can never be taken over (the crash-recovery path is unreachable).',
                $this->idempotencyWaitSecs,
                $idempotencyStore->leaseSeconds(),
            ));
        }
    }

    /**
     * The owner's post-verify ownership confirmation. Ownership is
     * protected by the LEASE WINDOW alone (the store's lease comfortably
     * exceeds the maximum supported verification window), so the owner
     * confirms ownership AFTER the verification by attempting an atomic
     * renewal: it succeeds only while this request still holds the
     * current owner token. When it fails, ownership was taken over after
     * the lease expired mid-verification — the caller must then NOT
     * return its own local result as authoritative.
     */
    private function confirmOwnership(string $backendId, string $idempotencyKey, string $owner): bool
    {
        return $this->idempotencyStore?->renew($backendId, $idempotencyKey, $owner) ?? false;
    }

    /**
     * The idempotency fingerprint of the request remoteip: 'no-ip' when
     * absent (or whitespace-only), otherwise 'ip:' + the canonicalized
     * address — IPv4/IPv6 are normalized via inet_pton/inet_ntop so
     * equivalent spellings of one address collide, and IPv4-mapped IPv6
     * (`::ffff:a.b.c.d`) is folded to its 4-byte IPv4 form to mirror the
     * verifier's binding identity EXACTLY (the core's
     * Issuer::canonicalIpFamily() applies the same normalization), so
     * the two spellings of one address that are deliberately equivalent
     * for verification binding also collide at the idempotency layer;
     * anything else keeps its raw trimmed form. The claim binds this
     * fingerprint, so verification-affecting remoteip changes cannot
     * reuse a stored outcome derived under another IP.
     */
    private function remoteipFingerprint(?string $remoteIp): string
    {
        $trimmed = $remoteIp !== null ? trim($remoteIp) : '';
        if ($trimmed === '') {
            return 'no-ip';
        }
        $binary = @inet_pton($trimmed);
        $canonical = null;
        if ($binary !== false) {
            if (\strlen($binary) === 16 && str_starts_with($binary, "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff")) {
                $binary = substr($binary, 12);
            }
            $canonical = (string) inet_ntop($binary);
        }
        $canonical ??= $trimmed;

        return 'ip:'.$canonical;
    }

    private function logGateKey(): string
    {
        return '{kiwicaptcha}:log-gate:siteverify-invalid-secret:'.(string) floor(time() / self::INVALID_SECRET_LOG_INTERVAL);
    }

    public function siteverify(Request $request): Response
    {
        if ($this->siteverifySecrets === []) {
            return new JsonResponse(['success' => false, 'error-codes' => ['siteverify-not-configured']], Response::HTTP_NOT_FOUND);
        }

        // The body is read with a hard byte cap: at most MAX_BODY_BYTES + 1
        // bytes are ever materialized from the request stream, so an
        // oversized chunked body is refused (413) BEFORE it reaches the
        // JSON parser or the verifier. The ACTUAL body is measured, not
        // the client-settable Content-Length header. A form request is
        // parsed by the framework before the controller runs, so the
        // already-materialized content is length-guarded directly too.
        $requestBody = $this->readBoundedBody($request);
        if (\strlen($requestBody) > self::MAX_BODY_BYTES) {
            return new JsonResponse(['success' => false, 'error-codes' => ['bad-request']], Response::HTTP_REQUEST_ENTITY_TOO_LARGE);
        }

        $body = $this->parseBody($request, $requestBody);
        if ($body === null) {
            return new JsonResponse(['success' => false, 'error-codes' => ['bad-request']], Response::HTTP_BAD_REQUEST);
        }
        $response = $body['response'] ?? null;
        $secret = $body['secret'] ?? null;
        $remoteIp = \is_string($body['remoteip'] ?? null) ? $body['remoteip'] : null;
        // action / cData are NEVER accepted on the verification request —
        // that would let a backend request tell Kiwi "this token's action
        // was checkout", reversing the trust direction. They are captured
        // at CHALLENGE ISSUANCE (widget data-action/data-cdata) and
        // returned from the server-side metadata store.
        $idempotencyKey = \is_string($body['idempotency_key'] ?? null) ? $body['idempotency_key'] : null;
        // The token length is bounded BEFORE decoding — provider
        // contracts document a 2048-char maximum; Kiwi's own legitimate
        // encoding fits comfortably under 8192, which is the documented
        // bound here (the 16 KiB whole-body ceiling stays as the outer
        // envelope).
        if (!\is_string($response) || $response === '') {
            return new JsonResponse(['success' => false, 'error-codes' => ['missing-input-response']]);
        }
        if (\strlen($response) > self::MAX_RESPONSE_BYTES) {
            return new JsonResponse(['success' => false, 'error-codes' => ['invalid-input-response']]);
        }

        // The remoteip is validated EARLY — BEFORE any idempotency claim
        // or verifier invocation: a malformed value (e.g. a forwarding-
        // header list like "203.0.113.4, 10.0.0.4") must be rejected as a
        // normal provider bad-request, never allowed to reach the core's
        // IP canonicalization, which would throw past the boundary as a
        // 500. Whitespace-only is treated as ABSENT (the provider 'no-ip'
        // semantics); a NULL remoteip is unchanged.
        if ($remoteIp !== null) {
            $remoteIp = trim($remoteIp);
            if ($remoteIp === '') {
                $remoteIp = null;
            } elseif (@inet_pton($remoteIp) === false) {
                return new JsonResponse(['success' => false, 'error-codes' => ['bad-request']], Response::HTTP_BAD_REQUEST);
            }
        }

        // A UUID-shaped idempotency_key only — arbitrary short strings
        // are rejected BEFORE the verifier (bounded cardinality, no
        // attacker-controlled shapes).
        if ($idempotencyKey !== null) {
            if (!\preg_match('/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i', $idempotencyKey)) {
                return new JsonResponse(['success' => false, 'error-codes' => ['bad-request']], Response::HTTP_BAD_REQUEST);
            }
            if ($this->idempotencyStore === null) {
                return new JsonResponse(['success' => false, 'error-codes' => ['bad-request']], Response::HTTP_BAD_REQUEST);
            }
        }

        // The presented secret authenticates the backend AND resolves the
        // EXPECTED SCOPE the verifier must enforce. Constant-time
        // comparisons; the detail goes to the log only. A secret not in
        // the server-owned map is rejected — an attacker-invented secret
        // can never reach the verifier. MISSING vs INVALID are distinct
        // provider codes.
        $expectedScope = null;
        if (!\is_string($secret) || $secret === '') {
            $this->noteInvalidSecret('missing', $this->logGateKey());

            return new JsonResponse(['success' => false, 'error-codes' => ['missing-input-secret']]);
        }
        foreach ($this->siteverifySecrets as $configuredSecret => $scope) {
            if (hash_equals($configuredSecret, $secret)) {
                $expectedScope = $scope;
                break;
            }
        }
        if ($expectedScope === null) {
            $this->noteInvalidSecret('invalid', $this->logGateKey());

            return new JsonResponse(['success' => false, 'error-codes' => ['invalid-input-secret']]);
        }

        // The idempotency backend identity binds the secret, the
        // SERVER-RESOLVED expected scope and the security-policy epoch:
        // a same-key request after a scope remap or policy bump is a NEW
        // logical operation (a conflict), never a replay of the
        // pre-change outcome.
        $backendId = hash('sha256', $secret.'|'.$expectedScope.'|'.$this->policyVersion);

        // The token is decoded BEFORE the claim so a MALFORMED token is
        // a DETERMINISTIC failure — the claiming request FINALIZES it so
        // a same-key retry reproduces the identical canonical response
        // instead of leaving the entry pending until TTL. The claim
        // outcomes follow the decoded branch's conflict semantics: a
        // same-key entry bound to a DIFFERENT malformed response is a
        // CONFLICT (the response hash is part of the claim identity),
        // and a COMPLETE_SAME entry (same malformed hash) returns the
        // stored canonical result instead of re-finalizing. The owner
        // lease is the store's FIXED configured lease (default 60s) and
        // the waiter bound the configured PENDING_SAME bound (default
        // 90s): neither is derived from THIS token's remaining signed
        // validity — signed expiry affects only FRESH redemptions, never
        // the retained-state reconstruction (the consumed record outlives
        // the takeover/retry horizon via risk.redis.ttl_margin_secs,
        // enforced at container compile time when Siteverify is
        // enabled).
        try {
            $token = SolutionToken::decode($response);
        } catch (DecodeError) {
            // A malformed token is a DETERMINISTIC failure — the claiming
            // request FINALIZES it so a same-key retry reproduces the
            // identical canonical response instead of leaving the entry
            // pending until TTL. The claim outcomes follow the decoded
            // branch's conflict semantics: a same-key entry bound to a
            // DIFFERENT malformed response is a CONFLICT (the response
            // hash is part of the claim identity), and a COMPLETE_SAME
            // entry (same malformed hash) returns the stored canonical
            // result instead of re-finalizing.
            $claim = IdempotencyClaim::Claimed;
            $claimOwner = null;
            if ($idempotencyKey !== null && $this->idempotencyStore !== null) {
                try {
                    [$claim, $claimOwner] = $this->idempotencyStore->claim($backendId, $idempotencyKey, hash('sha256', $response), 300, $this->remoteipFingerprint($remoteIp));
                } catch (\Throwable) {
                    // The malformed-token claim is a raw store operation:
                    // NOTHING has been consumed (the decode failed), so a
                    // same-key retry is safe — map to the retryable
                    // provider error, never a 500.
                    return $this->internalErrorResponse();
                }
            }
            if ($claim === IdempotencyClaim::Conflict) {
                return new JsonResponse(['success' => false, 'error-codes' => ['bad-request']], Response::HTTP_BAD_REQUEST);
            }
            if ($claim === IdempotencyClaim::CompleteSame) {
                try {
                    $stored = $this->idempotencyStore->stored($backendId, $idempotencyKey);
                } catch (\Throwable) {
                    return $this->internalErrorResponse();
                }

                return new JsonResponse($stored !== null ? $this->canonicalizeResponse($stored) : ['success' => false, 'error-codes' => ['timeout-or-duplicate']]);
            }
            $canonical = $this->canonicalizeResponse([
                'success' => false,
                'challenge_ts' => null,
                'hostname' => null,
                'error-codes' => ['invalid-input-response'],
            ]);
            if ($claimOwner !== null) {
                $failed = $this->finalizeSafely($backendId, $idempotencyKey, hash('sha256', $response), $claimOwner, $canonical, null);
                if ($failed !== null) {
                    return $failed;
                }
            }

            return new JsonResponse($canonical);
        }

        // Provider-style verification idempotency. The claim is atomic;
        // only the OWNING request verifies the token. A same-key retry
        // either returns the stored canonical response or (crash window)
        // reconstructs the original outcome via the core's retained
        // consumed-result machinery — ordinary replays WITHOUT a matching
        // key stay timeout-or-duplicate. The idempotency fingerprint
        // binds backend identity + response hash + canonicalized remoteip
        // into the claim: the same UUID with a CHANGED remoteip is a
        // CONFLICT, never a join or a reuse. The first CLAIMED request
        // additionally registers this (backend, nonce) pair's response
        // hash in the NONCE-LEVEL redemption guard (first write wins), so
        // a different UUID for the same nonce is a DIFFERENT logical
        // operation and can never reconstruct this outcome.
        $claim = IdempotencyClaim::Claimed;
        $claimOwner = null;
        $claimedAt = null;
        $idempotent = false;
        if ($idempotencyKey !== null) {
            $idempotent = true;
            try {
                [$claim, $claimOwner] = $this->idempotencyStore->claim($backendId, $idempotencyKey, hash('sha256', $response), 300, $this->remoteipFingerprint($remoteIp));
            } catch (\Throwable) {
                // The claim is a raw store operation (a Redis outage):
                // NOTHING has been consumed yet, so a same-key retry is
                // safe — map to the retryable provider internal-error,
                // never a 500.
                return $this->internalErrorResponse();
            }
            if ($claim === IdempotencyClaim::Conflict) {
                return new JsonResponse(['success' => false, 'error-codes' => ['bad-request']], Response::HTTP_BAD_REQUEST);
            }
            if ($claim === IdempotencyClaim::CompleteSame) {
                try {
                    $stored = $this->idempotencyStore->stored($backendId, $idempotencyKey);
                } catch (\Throwable) {
                    return $this->internalErrorResponse();
                }

                return new JsonResponse($stored !== null ? $this->canonicalizeResponse($stored) : ['success' => false, 'error-codes' => ['timeout-or-duplicate']]);
            }
            if ($claim === IdempotencyClaim::Claimed) {
                $claimedAt = microtime(true);
                try {
                    // The first logical Siteverify operation for this
                    // (backend, nonce) pair registers its response hash
                    // BEFORE the verifier (first write wins — concurrent
                    // firsts are serialized by the atomic set-if-absent).
                    // The guard is therefore populated even when this
                    // request crashes mid-verification, and any later
                    // UUID for the same nonce is provably a DIFFERENT
                    // logical operation.
                    $this->redemptionGuard->register($backendId, $token->nonce, hash('sha256', $response), self::REDEMPTION_GUARD_TTL_SECS);
                } catch (\Throwable) {
                    // A guard outage fails the request closed: NOTHING
                    // has been consumed yet, so the same-key retry is
                    // safe.
                    return $this->internalErrorResponse();
                }
            }
        }

        // PENDING_SAME — another request with the SAME key + hash owns
        // verification. This request WAITS on the store ONLY: it polls
        // stored() for completion and attempts an atomic takeover once the
        // owner's lease has expired. It NEVER invokes the verifier without
        // winning the takeover — a deliberately slow Argon solve can
        // legitimately take tens of seconds, so the entry stays owned by
        // whoever holds the owner token. Verification happens strictly
        // while holding the current owner token; at the hard bound below
        // the request is answered with a retryable error instead, leaving
        // the entry pending for a later retry.
        if ($idempotent && $claim === IdempotencyClaim::PendingSame) {
            $stored = null;
            $waitDeadline = microtime(true) + $this->idempotencyWaitSecs;
            while (true) {
                try {
                    $stored = $this->idempotencyStore->stored($backendId, $idempotencyKey);
                } catch (\Throwable) {
                    // The wait-loop reads are raw store operations: a
                    // failure maps to the retryable provider error (the
                    // entry stays pending for a later retry), never a
                    // 500.
                    return $this->internalErrorResponse();
                }
                if ($stored !== null) {
                    break;
                }
                if (microtime(true) >= $waitDeadline) {
                    // Hard bound without ownership: no stored result and no
                    // takeover — another owner is still working the entry.
                    // NOTHING is verified here: the client receives a
                    // RETRYABLE provider error (the claim entry remains
                    // pending, so a later retry can still take over or read
                    // the stored result).
                    return $this->internalErrorResponse();
                }
                // The lease gate is inside the store's Lua: before expiry
                // this attempt is an atomic no-op (StillPending). The
                // remoteip fingerprint is bound in the record, so the
                // takeover enforces the COMPLETE claim identity (the
                // claim() pass already checked it — defense-in-depth).
                // The takeover refreshes the lease with the store's FIXED
                // configured lease — the owner lease is never derived
                // from the token's remaining validity (the fixed 60s
                // lease exceeds any supported verification window, so a
                // live owner is never overtaken mid-verify).
                try {
                    [$takeover, $takeoverOwner] = $this->idempotencyStore->takeover($backendId, $idempotencyKey, hash('sha256', $response), 300, $this->remoteipFingerprint($remoteIp));
                } catch (\Throwable) {
                    // A failed takeover attempt (a transient store
                    // outage) maps to the retryable provider error — the
                    // entry stays pending and a later retry can still
                    // take over or read the stored result.
                    return $this->internalErrorResponse();
                }
                if ($takeover === IdempotencyClaim::TookOver) {
                    // This request now OWNS the entry — it will verify
                    // below and finalize with the takeover owner token.
                    $claim = IdempotencyClaim::TookOver;
                    $claimOwner = $takeoverOwner;
                    $claimedAt = microtime(true);
                    break;
                }
                usleep(100_000);
            }
            if ($stored !== null) {
                return new JsonResponse($this->canonicalizeResponse($stored));
            }
        }

        // Crash recovery FIRST: this request now OWNS the claim (claim or
        // takeover) — if the token was already consumed and a
        // deterministic outcome was committed, reconstruct it directly.
        // This works even when the signed challenge has expired in the
        // meantime (a token submitted late in its lifetime): the retained
        // outcome is the original logical result, not a fresh redemption.
        // Reconstruction runs ONLY on the takeover path — the request has
        // PROVEN the idempotency identity against the pre-existing entry
        // (same backend + key + response hash + remote-IP fingerprint)
        // AND the redemption guard certifies that THIS response hash is
        // the nonce's ORIGINAL redemption: a takeover under a
        // different-UUID claim for the same nonce is a DIFFERENT logical
        // operation and must never reconstruct the original success. A
        // freshly claimed entry (an ordinary replay under a different or
        // new key) must NOT reconstruct: the compatibility boundary keeps
        // mapping a consumed token to timeout-or-duplicate via the
        // verifier's own replay path.
        $reconstructed = null;
        if ($idempotent && $claim === IdempotencyClaim::TookOver) {
            try {
                if ($this->redemptionGuard->originalHash($backendId, $token->nonce) === hash('sha256', $response)) {
                    $reconstructed = $this->recovery->recover($response);
                }
            } catch (\Throwable) {
                // A guard/recovery-store outage on the takeover path maps
                // to the retryable provider error: the entry stays
                // pending and the same-key retry can try again once the
                // store is back.
                return $this->internalErrorResponse();
            }
        }
        if ($reconstructed !== null) {
            $canonical = $this->canonicalizeResponse($this->outcomeToCanonical($reconstructed));
            if ($claimOwner !== null) {
                $failed = $this->finalizeSafely($backendId, $idempotencyKey, hash('sha256', $response), $claimOwner, $canonical, $claimedAt);
                if ($failed !== null) {
                    return $failed;
                }
            }

            return new JsonResponse($canonical);
        }

        // The SAME atomic verifier as the native path, WITH the expected
        // scope resolved from the secret: a weaker login token presented
        // to the financial secret is rejected (WrongScope) — the
        // sitekey-allowlist mapping is enforced end to end. `remoteip` is
        // only honored because the caller proved possession of a valid
        // secret above; it is REQUIRED whenever IP binding is enabled
        // (the default) — a bound challenge without it fails closed.
        // Owner protection is the lease window: the store's ownership
        // lease (default 60s) comfortably exceeds the maximum supported
        // verification window plus a safety margin, so a live-but-slow
        // owner is never overtaken mid-verify — no process-global signal
        // state is touched.
        try {
            $outcome = $this->verifier->verify(
                $response,
                $this->secretKey,
                $expectedScope,
                $remoteIp,
                null,            // region expectation is application policy
                false,           // telemetry is never authoritative here
            );
        } catch (\InvalidArgumentException) {
            // Defensive boundary: the remoteip was validated above, so
            // the core's IP canonicalization cannot throw here — an
            // unexpected InvalidArgumentException from the IP path maps
            // to the provider bad-request JSON; exceptions must not
            // cross the HTTP compatibility boundary.
            return new JsonResponse(['success' => false, 'error-codes' => ['bad-request']], Response::HTTP_BAD_REQUEST);
        } catch (\Throwable) {
            // Hardened boundary tail: anything else escaping the
            // verifier (a storage failure past its own internal
            // handling) maps to the retryable provider error — an
            // exception must never cross the HTTP compatibility
            // boundary as a 500.
            return $this->internalErrorResponse();
        }
        if ($claimOwner !== null) {
            try {
                $stillOwns = $this->confirmOwnership($backendId, $idempotencyKey, $claimOwner);
            } catch (\Throwable) {
                // The ownership-confirmation renewal is a raw store
                // operation: a failure must not cross the boundary as a
                // 500 — the request is answered with the retryable
                // provider error (a same-key retry re-verifies or reads
                // the stored outcome).
                return $this->internalErrorResponse();
            }
            if (!$stillOwns) {
                // Ownership was lost while verifying (the lease window expired
                // mid-verification): the local result is NOT authoritative.
                // Return the stored authoritative result, or a retryable
                // provider error when none exists yet.
                try {
                    $stored = $this->idempotencyStore?->stored($backendId, $idempotencyKey);
                } catch (\Throwable) {
                    return $this->internalErrorResponse();
                }
                if ($stored !== null) {
                    return new JsonResponse($this->canonicalizeResponse($stored));
                }

                return $this->internalErrorResponse();
            }
        }

        // The compatibility boundary distinguishes the FIRST redemption
        // from replays. The native deterministic-result retry machinery
        // stays inside the verifier, but a REPEATED Siteverify redemption
        // of the same nonce must NOT report success again — it returns the
        // provider vocabulary for a consumed token. An idempotent retry
        // that has PROVEN the same key+hash against a pending claim may
        // interpret the stored result as the original outcome (crash
        // recovery) — it is the SAME logical redemption, not a second one.
        // A DIFFERENT logical operation that observes the consumed result
        // (a different UUID for the same nonce, or a takeover the
        // redemption guard refused) FINALIZES its claim with the canonical
        // duplicate response: the entry becomes COMPLETE_SAME, a
        // same-UUID retry returns the stored duplicate immediately, and
        // the redemption guard is the structural backstop for the
        // crash-between-detect-and-finalize window.
        if ($outcome->isOk() && $outcome->fromStoredResult) {
            // A same-key + same-hash retry whose claim is STILL pending
            // reconstructs the ORIGINAL success from the retained consumed
            // state (crash recovery — the key+hash pair was proven against
            // the pending claim, so this is the SAME logical redemption).
            // This path is only reachable while holding the current owner
            // token (the takeover winner finalizes the reconstructed
            // outcome).
            if ($idempotent && $claim === IdempotencyClaim::PendingSame) {
                $canonical = $this->canonicalizeResponse($this->canonicalSuccess($outcome));
                if ($claimOwner !== null) {
                    $failed = $this->finalizeSafely($backendId, $idempotencyKey, hash('sha256', $response), $claimOwner, $canonical, $claimedAt);
                    if ($failed !== null) {
                        return $failed;
                    }
                }

                return new JsonResponse($canonical);
            }

            // The consumed token is a DETERMINISTIC duplicate for THIS
            // claim: finalize it with the canonical duplicate response so
            // the claim is COMPLETE_SAME and a same-UUID retry returns the
            // stored bytes immediately — the entry can never be taken over
            // and reconstructed as a success.
            $canonical = $this->canonicalizeResponse([
                'success' => false,
                'challenge_ts' => null,
                'hostname' => null,
                'error-codes' => ['timeout-or-duplicate'],
            ]);
            if ($claimOwner !== null) {
                $failed = $this->finalizeSafely($backendId, $idempotencyKey, hash('sha256', $response), $claimOwner, $canonical, $claimedAt);
                if ($failed !== null) {
                    return $failed;
                }
            }

            return new JsonResponse($canonical);
        }

        if ($outcome->isOk()) {
            $canonical = $this->canonicalizeResponse($this->canonicalSuccess($outcome));
            if ($claimOwner !== null) {
                $failed = $this->finalizeSafely($backendId, $idempotencyKey, hash('sha256', $response), $claimOwner, $canonical, $claimedAt);
                if ($failed !== null) {
                    return $failed;
                }
            }

            return new JsonResponse($canonical);
        }

        $error = $outcome->error();
        $canonical = [
            'success' => false,
            'challenge_ts' => null,
            'hostname' => null,
            'error-codes' => [$this->mapError($error)],
        ];
        $canonical = $this->canonicalizeResponse($canonical);
        if ($claimOwner !== null) {
            // A failed verification is ALSO finalized: a same-key retry
            // must reproduce the SAME canonical failure.
            $failed = $this->finalizeSafely($backendId, $idempotencyKey, hash('sha256', $response), $claimOwner, $canonical, $claimedAt);
            if ($failed !== null) {
                return $failed;
            }
        }

        return new JsonResponse($canonical);
    }

    /**
     * The owner's finalize: extend the lease first when this request's
     * ownership (claim or takeover) has outlasted the lease window, so a
     * slow-but-alive owner is not overtaken and the finalize cannot be
     * rejected by a concurrent takeover. A failed renewal means ownership
     * was already lost — the finalize is then an atomic no-op and the
     * new owner's outcome stays authoritative. The lease window is the
     * store's FIXED configured lease (never derived from the token's
     * remaining validity).
     */
    private function finalizeAsOwner(string $backendId, string $idempotencyKey, string $responseHash, string $owner, array $canonical, ?float $claimedAt): void
    {
        if ($claimedAt !== null && microtime(true) - $claimedAt >= SiteVerifyIdempotencyStore::LEASE_SECONDS) {
            $this->idempotencyStore?->renew($backendId, $idempotencyKey, $owner);
        }
        $this->idempotencyStore?->finalize($backendId, $idempotencyKey, $responseHash, $owner, $canonical);
    }

    /**
     * The owner's finalize hardened against the HTTP boundary: the raw
     * store operations (renew + finalize) can throw, and the failure
     * must NOT become a 500. The token may ALREADY be consumed+committed
     * by the core: the entry stays pending, and a same-key retry takes
     * over and reconstructs (or reads) the committed outcome —
     * retryability is preserved. BEFORE consumption the same failure is
     * equally safe: the claim was never finalized and the retry re-runs
     * the ordinary verify.
     *
     * @return JsonResponse|null the 503 internal-error response when the
     *         store failed, null when the finalize completed (or was an
     *         atomic no-op)
     */
    private function finalizeSafely(string $backendId, string $idempotencyKey, string $responseHash, string $owner, array $canonical, ?float $claimedAt): ?JsonResponse
    {
        try {
            $this->finalizeAsOwner($backendId, $idempotencyKey, $responseHash, $owner, $canonical, $claimedAt);
        } catch (\Throwable) {
            return $this->internalErrorResponse();
        }

        return null;
    }

    /**
     * The retryable provider internal-error response (503): a transient
     * store failure inside the idempotency machinery — nothing has been
     * consumed, or the committed outcome stays recoverable — so the
     * caller may safely retry with the same key. An exception must never
     * cross the HTTP compatibility boundary as a 500.
     */
    private function internalErrorResponse(): JsonResponse
    {
        return new JsonResponse(['success' => false, 'error-codes' => ['internal-error']], Response::HTTP_SERVICE_UNAVAILABLE);
    }

    /**
     * Canonicalize a provider response for storage/comparison: sorted keys
     * make the stored round-trip byte-deterministic, so a same-key retry
     * returns the IDENTICAL JSON bytes (the concurrency contract).
     */
    private function canonicalizeResponse(array $response): array
    {
        ksort($response);

        return $response;
    }

    /**
     * The provider-shaped success response, including the SERVER-STORED
     * challenge metadata (action/cData bound at issuance — never echoed
     * from the request) and the retained record's challenge_ts/hostname.
     */
    /**
     * The canonical provider response for an outcome: the success shape
     * with server-bound metadata, or the mapped failure shape.
     */
    private function outcomeToCanonical(VerifyOutcome $outcome): array
    {
        if ($outcome->isOk()) {
            return $this->canonicalSuccess($outcome);
        }

        return [
            'success' => false,
            'challenge_ts' => null,
            'hostname' => null,
            'error-codes' => [$this->mapError($outcome->error())],
        ];
    }

    private function canonicalSuccess(VerifyOutcome $outcome): array
    {
        $issuedAt = null;
        $hostname = null;
        if ($this->storage !== null && $outcome->nonce() !== null) {
            $record = $this->storage->find($outcome->nonce());
            if ($record !== null) {
                $issuedAt = $record->issuedAt;
                $hostname = $record->hostname;
            }
        }
        $action = null;
        $cdata = null;
        if ($this->metadataStore !== null && $outcome->nonce() !== null) {
            $metadata = $this->metadataStore->find($outcome->nonce());
            if ($metadata !== null) {
                $action = $metadata->action;
                $cdata = $metadata->cdata;
            }
        }

        return [
            'success' => true,
            'challenge_ts' => $issuedAt !== null ? gmdate('Y-m-d\TH:i:s\Z', $issuedAt) : null,
            'hostname' => $hostname,
            'action' => $action,
            'cdata' => $cdata,
            'error-codes' => [],
        ];
    }

    private function mapError(VerifyError $error): string
    {
        // Provider-style error codes (reCAPTCHA-compatible vocabulary);
        // the precise core reason stays in the application logs.
        return match ($error) {
            VerifyError::Expired,
            VerifyError::ConsumeIndeterminate => 'timeout-or-duplicate',
            VerifyError::BadSignature,
            VerifyError::MalformedRecord,
            VerifyError::MalformedToken,
            VerifyError::RecordNotFound,
            VerifyError::UnknownKid,
            VerifyError::WrongScope,
            VerifyError::IpMismatch,
            VerifyError::MissingClientIp,
            VerifyError::WrongRegion,
            VerifyError::WrongIssuer,
            VerifyError::WrongPolicyVersion => 'invalid-input-response',
            default => 'bad-request',
        };
    }

    /**
     * Invalid-secret diagnostics are gated by a SHARED log gate (Redis
     * INCR + EXPIRE) so the aggregation is deployment-wide — counters
     * held per controller instance are meaningless across PHP-FPM workers
     * (a fresh controller per request). Logging is logarithmic (1, 2, 4,
     * 8...): early visibility + bounded flood amplification. Log-gate
     * failure NEVER affects verification: on Redis errors the detailed
     * log is suppressed (requests are still rejected).
     */
    private const INVALID_SECRET_LOG_GATE_TTL_SECS = 5;
    private const INVALID_SECRET_LOG_INTERVAL = 5.0;

    private function noteInvalidSecret(string $kind, string $gateKey): void
    {
        $count = null;
        if ($this->logGate !== null) {
            try {
                $count = RedisEval::eval($this->logGate, self::LOG_GATE_LUA, $gateKey, [self::INVALID_SECRET_LOG_GATE_TTL_SECS]);
            } catch (\Throwable) {
                $count = null; // telemetry failure must not affect verification
            }
        }
        $count = $count !== null ? (int) $count : null;
        // Log on the powers of two (1, 2, 4, 8...) and never per-request.
        $isLogStep = $count !== null && ($count === 1 || ($count & ($count - 1)) === 0);
        if ($isLogStep) {
            $this->logger?->warning(sprintf('kiwicaptcha siteverify: invalid-secret attempts (%s) — %s secret', $kind, $count));
        }
    }

    private const LOG_GATE_LUA = <<<'LUA'
local key = KEYS[1]
local ttl = tonumber(ARGV[1])
local n = redis.call('INCR', key)
if n == 1 then
  redis.call('EXPIRE', key, ttl)
end
return n
LUA;

    /**
     * Read the request body with a hard byte cap: the input stream is
     * consumed for at most MAX_BODY_BYTES + 1 bytes, so an oversized
     * chunked body is refused by the caller's length check WITHOUT ever
     * being materialized in full — the bounded read is the authoritative
     * protection. When Symfony hands back a buffered stream (tests,
     * already-consumed input) the read is still bounded.
     */
    private function readBoundedBody(Request $request): string
    {
        $stream = $request->getContent(true);
        if (\is_resource($stream)) {
            return (string) stream_get_contents($stream, self::MAX_BODY_BYTES + 1);
        }

        return (string) $request->getContent();
    }

    /**
     * @return array<string, mixed>|null
     */
    private function parseBody(Request $request, string $requestBody): ?array
    {
        $contentType = strtolower(trim(explode(';', (string) $request->headers->get('Content-Type', ''), 2)[0]));
        if ($contentType === 'application/json') {
            try {
                $decoded = json_decode($requestBody, true, 32, JSON_THROW_ON_ERROR);

                return \is_array($decoded) ? $decoded : null;
            } catch (\JsonException) {
                return null;
            }
        }

        return $request->request->all();
    }
}
