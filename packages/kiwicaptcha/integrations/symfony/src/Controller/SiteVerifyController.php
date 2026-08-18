<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Controller;

use BelConsulting\KiwiCaptchaBundle\SiteVerify\IdempotencyClaim;
use BelConsulting\KiwiCaptchaBundle\SiteVerify\RedisEval;
use BelConsulting\KiwiCaptchaBundle\SiteVerify\SiteVerifyIdempotencyStore;
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
 *    not a process-global timer: the store's ownership lease (default
 *    60s) exceeds the maximum supported verification /
 *    request execution window plus a safety margin, so a live owner is
 *    never overtaken mid-verify — no process-global signal state is
 *    touched. The claim additionally binds the canonicalized remoteip
 *    fingerprint, so the same idempotency key with a changed remoteip
 *    CONFLICTS instead of reusing an outcome derived under another IP.
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
     * owner token. The owner's lease (60s) comfortably exceeds the
     * maximum supported verification window, so this bound is the
     * absolute tail.
     */
    public const IDEMPOTENCY_WAIT_SECS = 90.0;

    /**
     * Hard ceiling for the whole verification request body: 16 KiB covers
     * every legitimate provider envelope (response+secret+remoteip).
     */
    private const MAX_BODY_BYTES = 16 * 1024;

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
    ) {
        // The lease-ordering invariant is ENFORCED at construction: the
        // waiter bound must exceed the owner lease, otherwise the
        // crash-recovery takeover is unreachable (a waiter would give up
        // before the lease ever expires). The default ordering is
        // lease (60) < waiter bound (90) < challenge lifetime (120).
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

        // Provider-style verification idempotency. The claim is atomic;
        // only the OWNING request verifies the token. A same-key retry
        // either returns the stored canonical response or (crash window)
        // reconstructs the original outcome via the core's retained
        // consumed-result machinery — ordinary replays WITHOUT a matching
        // key stay timeout-or-duplicate. The idempotency fingerprint
        // binds backend identity + response hash + canonicalized remoteip
        // into the claim: the same UUID with a CHANGED remoteip is a
        // CONFLICT, never a join or a reuse.
        $backendId = hash('sha256', $secret);
        $claim = IdempotencyClaim::Claimed;
        $claimOwner = null;
        $claimedAt = null;
        $remoteipFingerprint = null;
        $idempotent = false;
        if ($idempotencyKey !== null) {
            $idempotent = true;
            $remoteipFingerprint = $this->remoteipFingerprint($remoteIp);
            [$claim, $claimOwner] = $this->idempotencyStore->claim($backendId, $idempotencyKey, hash('sha256', $response), 300, $remoteipFingerprint);
            if ($claim === IdempotencyClaim::Conflict) {
                return new JsonResponse(['success' => false, 'error-codes' => ['bad-request']], Response::HTTP_BAD_REQUEST);
            }
            if ($claim === IdempotencyClaim::CompleteSame) {
                $stored = $this->idempotencyStore->stored($backendId, $idempotencyKey);

                return new JsonResponse($stored !== null ? $this->canonicalizeResponse($stored) : ['success' => false, 'error-codes' => ['timeout-or-duplicate']]);
            }
            if ($claim === IdempotencyClaim::Claimed) {
                $claimedAt = microtime(true);
            }
        }

        try {
            $token = SolutionToken::decode($response);
        } catch (DecodeError) {
            // A malformed token is a DETERMINISTIC failure — the claiming
            // request FINALIZES it so a same-key retry reproduces the
            // identical canonical response instead of leaving the entry
            // pending until TTL.
            $canonical = $this->canonicalizeResponse([
                'success' => false,
                'challenge_ts' => null,
                'hostname' => null,
                'error-codes' => ['invalid-input-response'],
            ]);
            if ($claimOwner !== null) {
                $this->finalizeAsOwner($backendId, $idempotencyKey, hash('sha256', $response), $claimOwner, $canonical, $claimedAt);
            }

            return new JsonResponse($canonical);
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
                $stored = $this->idempotencyStore->stored($backendId, $idempotencyKey);
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
                    return new JsonResponse(['success' => false, 'error-codes' => ['internal-error']], Response::HTTP_SERVICE_UNAVAILABLE);
                }
                // The lease gate is inside the store's Lua: before expiry
                // this attempt is an atomic no-op (StillPending). The
                // remoteip fingerprint is bound in the record, so the
                // takeover enforces the COMPLETE claim identity (the
                // claim() pass already checked it — defense-in-depth).
                [$takeover, $takeoverOwner] = $this->idempotencyStore->takeover($backendId, $idempotencyKey, hash('sha256', $response), 300, $remoteipFingerprint);
                if ($takeover === IdempotencyClaim::TookOver) {
                    // This request now OWNS the entry — it will verify
                    // below and finalize with the takeover owner token.
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
            // the core's IP canonicalization cannot throw here — but a
            // future core change must never reopen the 500 escape, so an
            // unexpected InvalidArgumentException from the IP path maps
            // to the provider bad-request JSON instead.
            return new JsonResponse(['success' => false, 'error-codes' => ['bad-request']], Response::HTTP_BAD_REQUEST);
        }
        if ($claimOwner !== null && !$this->confirmOwnership($backendId, $idempotencyKey, $claimOwner)) {
            // Ownership was lost while verifying (the lease window expired
            // mid-verification): the local result is NOT authoritative.
            // Return the stored authoritative result, or a retryable
            // provider error when none exists yet.
            $stored = $this->idempotencyStore?->stored($backendId, $idempotencyKey);
            if ($stored !== null) {
                return new JsonResponse($this->canonicalizeResponse($stored));
            }

            return new JsonResponse(['success' => false, 'error-codes' => ['internal-error']], Response::HTTP_SERVICE_UNAVAILABLE);
        }

        // The compatibility boundary distinguishes the FIRST redemption
        // from replays. The native deterministic-result retry machinery
        // stays inside the verifier, but a REPEATED Siteverify redemption
        // of the same nonce must NOT report success again — it returns the
        // provider vocabulary for a consumed token. An idempotent retry
        // that has PROVEN the same key+hash against a pending claim may
        // interpret the stored result as the original outcome (crash
        // recovery) — it is the SAME logical redemption, not a second one.
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
                    $this->finalizeAsOwner($backendId, $idempotencyKey, hash('sha256', $response), $claimOwner, $canonical, $claimedAt);
                }

                return new JsonResponse($canonical);
            }

            return new JsonResponse([
                'success' => false,
                'challenge_ts' => null,
                'hostname' => null,
                'error-codes' => ['timeout-or-duplicate'],
            ]);
        }

        if ($outcome->isOk()) {
            $canonical = $this->canonicalizeResponse($this->canonicalSuccess($outcome));
            if ($claimOwner !== null) {
                $this->finalizeAsOwner($backendId, $idempotencyKey, hash('sha256', $response), $claimOwner, $canonical, $claimedAt);
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
            $this->finalizeAsOwner($backendId, $idempotencyKey, hash('sha256', $response), $claimOwner, $canonical, $claimedAt);
        }

        return new JsonResponse($canonical);
    }

    /**
     * The owner's finalize: extend the lease first when this request's
     * ownership (claim or takeover) has outlasted the lease window, so a
     * slow-but-alive owner is not overtaken and the finalize cannot be
     * rejected by a concurrent takeover. A failed renewal means ownership
     * was already lost — the finalize is then an atomic no-op and the
     * new owner's outcome stays authoritative.
     */
    private function finalizeAsOwner(string $backendId, string $idempotencyKey, string $responseHash, string $owner, array $canonical, ?float $claimedAt): void
    {
        if ($claimedAt !== null && microtime(true) - $claimedAt >= SiteVerifyIdempotencyStore::LEASE_SECONDS) {
            $this->idempotencyStore?->renew($backendId, $idempotencyKey, $owner);
        }
        $this->idempotencyStore?->finalize($backendId, $idempotencyKey, $responseHash, $owner, $canonical);
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
