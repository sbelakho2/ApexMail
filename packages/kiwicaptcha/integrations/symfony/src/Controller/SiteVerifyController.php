<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Controller;

use BelConsulting\KiwiCaptchaBundle\Risk\SecurityEpochMonitor;
use BelConsulting\KiwiCaptchaBundle\Http\JsonDuplicateKeyScanner;
use BelConsulting\KiwiCaptchaBundle\Validator\Constraints\KiwiCaptchaValidator;
use BelConsulting\KiwiCaptchaBundle\Security\RequestScopeAdmissionGate;
use BelConsulting\KiwiCaptchaBundle\SiteVerify\IdempotencyClaim;
use BelConsulting\KiwiCaptchaBundle\SiteVerify\RedisEval;
use BelConsulting\KiwiCaptchaBundle\SiteVerify\SiteVerifyIdempotencyStore;
use KiwiCaptcha\ConsumedStateReadableInterface;
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
 * shape (`response`, `secret`, optional `remoteip`) as form or JSON and
 * returns the provider-shaped verification JSON (`success`, `challenge_ts`,
 * `hostname`, `error-codes`). It calls the same atomic Kiwi verifier as the
 * native integration, so safe verification retries are free: a replayed
 * `response` resolves to the stored deterministic outcome instead of
 * re-deriving.
 *
 * Security model:
 *  - The endpoint is disabled unless `kiwi_captcha.siteverify_secret` is
 *    configured. The compatibility secret authenticates server-to-server
 *    use; a browser never sees the secret, so `remoteip` can never be
 *    supplied by an unauthenticated client. The comparison is constant
 *    time (hash_equals).
 *  - The request body is read with a hard byte cap (16 KiB) before any
 *    JSON decoding or business verification. Allocation-level ceilings are
 *    a deployment concern: mirror the bound in the reverse proxy
 *    (client_max_body_size) and in PHP (post_max_size).
 *  - The underlying verifier remains authoritative: TTL, scope/region/
 *    issuer/policy expectations, nonce-bound IP binding, timing floor,
 *    Argon ceilings and atomic single-use consumption all apply exactly as
 *    in the native path.
 *  - Verification idempotency ownership is protected by a lease window,
 *    not a process-global timer: the store's fixed ownership lease
 *    (default 60s) exceeds the maximum supported verification window, so a
 *    live owner is never overtaken mid-verify. The strict ordering is
 *    enforced at construction and at container compile time. It requires
 *
 *      max verification runtime  <  fixed owner lease (60)
 *                                 <  waiter deadline (90)
 *                                 <= retained-state recovery retention (>=90)
 *
 *    Signed token expiry affects only fresh redemptions, never the
 *    retained-state reconstruction, so a late-lifetime crash still
 *    reproduces the original committed outcome.
 *  - The logical-operation identity rides in the consumed runtime state
 *    itself: the idempotent claim computes a bounded fingerprint of
 *    (backend identity, idempotency key, response hash, canonicalized
 *    remoteip fingerprint). It passes that fingerprint as the operation
 *    identity into the verifier's atomic pending->consumed transition.
 *    Crash recovery reconstructs only when the consumed record's own
 *    operation identity equals this claim's fingerprint. A different-UUID
 *    claim, a no-key first redemption, or a different backend secret can
 *    never reconstruct the original success: a consumed token can never
 *    become successful again through another idempotency UUID. The claim
 *    binds the canonicalized remoteip fingerprint, so the same
 *    idempotency key with a changed remoteip conflicts instead of reusing
 *    an outcome derived under another IP. When the original attempt
 *    consumed the token but lost its reply before the
 *    derivation/commit, the same identity proof authorizes a narrowly
 *    scoped resume of the interrupted derivation,
 *    {@see Verifier::resumeConsumedOperation()}.
 */
final class SiteVerifyController
{
    /** Documented bounded maximum for the `response` token. */
    private const MAX_RESPONSE_BYTES = 8192;

    /**
     * The hard bound on the `PENDING_SAME` wait. A waiter that reaches this
     * bound without a stored result and without winning the atomic
     * takeover is answered with the retryable provider `internal-error`;
     * it never enters the verifier without holding the current owner
     * token. The ordering invariant is strict and enforced at construction
     * (waiter bound > the store's fixed owner lease) and at container
     * compile time (waiter bound <= retained-state recovery retention).
     * It requires
     *
     *   max verification runtime  <  fixed owner lease (60)
     *                              <  this bound (90)
     *                              <= recovery retention (>= 90)
     */
    public const IDEMPOTENCY_WAIT_SECS = 90.0;

    /**
     * Hard ceiling for the whole verification request body: 16 KiB covers
     * every legitimate provider envelope (response+secret+remoteip).
     */
    private const MAX_BODY_BYTES = 16 * 1024;

    /**
     * The base interval of the `PENDING_SAME` poll backoff in
     * milliseconds: the first stored-result poll after the wait starts.
     * The interval doubles on every poll up to
     * {@see self::PENDING_SAME_POLL_MAX_MS}. A duplicate idempotency
     * request that has to wait for the full 90 s bound issues roughly
     * 90 polls (one per second at the ceiling), instead of ~900 at a
     * fixed 100 ms cadence.
     */
    private const PENDING_SAME_POLL_BASE_MS = 100;

    /**
     * The maximum interval of the `PENDING_SAME` poll backoff in
     * milliseconds (the growth ceiling; the schedule is 100, 200, 400,
     * 800, then 1000 ms).
     */
    private const PENDING_SAME_POLL_MAX_MS = 1000;

    /**
     * The retained consumed-state recovery used on the takeover path. It
     * reconstructs only when the storage is recovery-capable (the
     * SiteVerifyRecoveryCapableStorageInterface compile-time check in the
     * extension). It then checks that the consumed record's own operation
     * identity equals this claim's fingerprint, which was written
     * atomically with the pending->consumed transition, so a different
     * logical operation can never match.
     */
    private ?\KiwiCaptcha\ConsumedOutcomeRecovery $recovery;

    /**
     * @param array<string, string> $siteverifySecrets map of
     *        server-to-server secret -> expected scope; empty disables the
     *        endpoint. A per-secret expected scope is required, so a
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
        /** Hard bound on the ``PENDING_SAME`` wait in seconds (see {@see self::IDEMPOTENCY_WAIT_SECS}). */
        private readonly float $idempotencyWaitSecs = self::IDEMPOTENCY_WAIT_SECS,
        /**
         * The security-policy epoch (risk.policy_version): part of the
         * idempotency backend identity, so a same-key request after a
         * policy change is a new logical operation (a conflict), never a
         * replay of the pre-change outcome.
         */
        private readonly int $policyVersion = 0,
        ?\KiwiCaptcha\ConsumedOutcomeRecovery $recovery = null,
        /**
         * Anti-stockpiling accounting (wired when the risk layer is
         * enabled): every successful Siteverify redemption releases the
         * solved nonce's ORIGINAL source slot and its live-outstanding
         * membership, exactly like native verification. The release is
         * one-shot and nonce-authoritative, so recovery and retry paths
         * are safe to call it too. Null (risk disabled, fixtures) keeps
         * the provider surface free of accounting.
         */
        private readonly ?\BelConsulting\KiwiCaptchaBundle\Security\OutstandingChallenges $outstanding = null,
        /**
         * The security-epoch monitor (wired by the container, mirroring
         * the native controller): refreshed at the start of every
         * authenticated verification, so a worker that only serves
         * Siteverify traffic still observes a central policy bump within
         * the monitor's cache window. The max-stale fail-closed check
         * applies here too: a stale central policy state answers the
         * retryable provider internal-error, with nothing claimed and
         * nothing verified. Null (fixtures, direct construction) keeps
         * the static `$policyVersion` behavior exactly.
         */
        private readonly ?SecurityEpochMonitor $epochMonitor = null,
        /**
         * The authoritative transaction-binding resolver
         * (risk.request_binding_authority). When configured, EVERY
         * Siteverify redemption enforces the same pre-consume binding
         * contract as the native path: the resolved binding is passed to
         * the core verifier (and the resumed-operation path) as the
         * expected request binding AND bound into the idempotency
         * identity, so a proof anchored to one transaction can never
         * succeed for another and an idempotency entry can never be
         * reused across transaction contexts. Null when no authority is
         * configured; the extension refuses the siteverify-secrets +
         * request-binding-capable issuance combination without one at
         * compile time.
         */
        private readonly ?\BelConsulting\KiwiCaptchaBundle\Risk\RequestBindingAuthorityInterface $bindingAuthority = null,
        /**
         * The static server-side transaction binding
         * (risk.request_binding): the fallback transaction input when no
         * authority is configured. A deployment that mints bound
         * challenges without an authority must answer the Siteverify
         * surface with this same server-side value, never silently
         * turning request binding off.
         */
        private readonly ?string $defaultRequestBinding = null,
    ) {
    $this->jsonDuplicateKeyScanner = new JsonDuplicateKeyScanner();
    $this->recovery = $recovery ?? (new \KiwiCaptcha\ConsumedOutcomeRecovery($this->storage ?? new \KiwiCaptcha\Storage\ArrayStorage()));
        // The lease-ordering invariant is enforced at construction: the
        // waiter bound must exceed the fixed owner lease (the store's
        // configured lease, never derived from a token's remaining
        // validity), otherwise the crash-recovery takeover is unreachable
        // (a waiter would give up before the lease ever expires). The
        // default ordering is lease (60) < waiter bound (90) <= recovery
        // retention (>= 90), with the retained-state recovery retention
        // enforced at container compile time.
        if ($idempotencyStore !== null && $this->idempotencyWaitSecs <= $idempotencyStore->leaseSeconds()) {
            throw new \LogicException(sprintf(
                'KiwiCaptcha: the idempotency `PENDING_SAME` wait bound (%ss) must exceed the owner lease (%ss) — otherwise a crashed owner can never be taken over (the crash-recovery path is unreachable).',
                $this->idempotencyWaitSecs,
                $idempotencyStore->leaseSeconds(),
            ));
        }
    }

    /**
     * The owner's post-verify ownership confirmation. Ownership is
     * protected by the lease window alone, which comfortably exceeds the
     * maximum supported verification window. The owner confirms ownership
     * after the verification by attempting an atomic renewal: it succeeds
     * only while this request still holds the current owner token. When
     * it fails, ownership was taken over after the lease expired
     * mid-verification, and the caller must not return its own local
     * result as authoritative.
     */
    private function confirmOwnership(string $backendId, string $idempotencyKey, string $owner): bool
    {
        return $this->idempotencyStore?->renew($backendId, $idempotencyKey, $owner) ?? false;
    }

    /**
     * The idempotency fingerprint of the request remoteip: 'no-ip' when
     * absent (or whitespace-only), otherwise 'ip:' + the canonicalized
     * address. IPv4/IPv6 are normalized via inet_pton/inet_ntop so
     * equivalent spellings of one address collide, and IPv4-mapped IPv6
     * (`::ffff:a.b.c.d`) is folded to its 4-byte IPv4 form, mirroring
     * the verifier's binding identity (the core's
     * Issuer::canonicalIpFamily() applies the same normalization).
     * Anything else keeps its raw trimmed form. The claim binds this
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

    private JsonDuplicateKeyScanner $jsonDuplicateKeyScanner;

    public function siteverify(Request $request): Response
    {
        if ($this->siteverifySecrets === []) {
            return new JsonResponse(['success' => false, 'error-codes' => ['siteverify-not-configured']], Response::HTTP_NOT_FOUND);
        }

        // Framing rigor before anything is read: POST only; a duplicate
        // Content-Length header is refused (header smuggling); Content-
        // Length + Transfer-Encoding together is refused (smuggling);
        // a Content-Encoding other than identity is refused (the provider
        // contract never compresses).
        if (!$request->isMethod('POST')) {
            return new JsonResponse(['success' => false, 'error-codes' => ['bad-request']], Response::HTTP_BAD_REQUEST);
        }
        $contentLengths = $request->headers->all('Content-Length');
        if (\count($contentLengths) > 1) {
            return new JsonResponse(['success' => false, 'error-codes' => ['bad-request']], Response::HTTP_BAD_REQUEST);
        }
        if ($request->headers->has('Content-Length') && $request->headers->has('Transfer-Encoding')) {
            return new JsonResponse(['success' => false, 'error-codes' => ['bad-request']], Response::HTTP_BAD_REQUEST);
        }
        // Content-Encoding and Content-Type are enforced SINGULAR too: a
        // duplicated header (two different values) is the kind of
        // ambiguity different proxies and application layers interpret
        // differently, so it is refused rather than silently collapsed.
        if (\count($request->headers->all('Content-Encoding')) > 1) {
            return new JsonResponse(['success' => false, 'error-codes' => ['bad-request']], Response::HTTP_BAD_REQUEST);
        }
        if (\count($request->headers->all('Content-Type')) > 1) {
            return new JsonResponse(['success' => false, 'error-codes' => ['bad-request']], Response::HTTP_BAD_REQUEST);
        }
        $contentEncoding = strtolower(trim((string) $request->headers->get('Content-Encoding', '')));
        if ($contentEncoding !== '' && $contentEncoding !== 'identity') {
            return new JsonResponse(['success' => false, 'error-codes' => ['bad-request']], Response::HTTP_BAD_REQUEST);
        }

        // The body is read with a hard byte cap: at most MAX_BODY_BYTES +
        // 1 bytes are ever materialized from the request stream, so an
        // oversized chunked body is refused (413) before it reaches the
        // JSON parser or the verifier. The actual body is measured, not
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
        // action and cdata are never accepted on the verification request,
        // which would let a backend request tell Kiwi this token's action
        // was something else, reversing the trust direction. They are
        // captured at challenge issuance (widget data-action/data-cdata)
        // and returned from the server-side metadata store.
        $idempotencyKey = \is_string($body['idempotency_key'] ?? null) ? $body['idempotency_key'] : null;
        // The token length is bounded before decoding: provider contracts
        // document a 2048-char maximum, and Kiwi's own legitimate encoding
        // fits comfortably under 8192, the documented bound here (the
        // 16 KiB whole-body ceiling stays as the outer envelope).
        if (!\is_string($response) || $response === '') {
            return new JsonResponse(['success' => false, 'error-codes' => ['missing-input-response']]);
        }
        if (\strlen($response) > self::MAX_RESPONSE_BYTES) {
            return new JsonResponse(['success' => false, 'error-codes' => ['invalid-input-response']]);
        }

        // The remoteip is validated early, before any idempotency claim or
        // verifier invocation: a malformed value (e.g. a forwarding-header
        // list like "203.0.113.4, 10.0.0.4") must be rejected as a normal
        // provider bad-request, never allowed to reach the core's IP
        // canonicalization, which would throw past the boundary as a 500.
        // Whitespace-only is treated as absent (the provider 'no-ip'
        // semantics); a null remoteip is unchanged.
        if ($remoteIp !== null) {
            $remoteIp = trim($remoteIp);
            if ($remoteIp === '') {
                $remoteIp = null;
            } elseif (@inet_pton($remoteIp) === false) {
                return new JsonResponse(['success' => false, 'error-codes' => ['bad-request']], Response::HTTP_BAD_REQUEST);
            }
        }

        // A UUID-shaped idempotency_key only: arbitrary short strings are
        // rejected before the verifier (bounded cardinality, no
        // attacker-controlled shapes).
        if ($idempotencyKey !== null) {
            if (!\preg_match('/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i', $idempotencyKey)) {
                return new JsonResponse(['success' => false, 'error-codes' => ['bad-request']], Response::HTTP_BAD_REQUEST);
            }
            if ($this->idempotencyStore === null) {
                return new JsonResponse(['success' => false, 'error-codes' => ['bad-request']], Response::HTTP_BAD_REQUEST);
            }
        }

        // The presented secret authenticates the backend and resolves the
        // expected scope the verifier must enforce. Constant-time
        // comparisons; the detail goes to the log only. A secret not in
        // the server-owned map is rejected, so an attacker-invented secret
        // can never reach the verifier; missing and invalid are distinct
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

        // The security-policy epoch is refreshed at the start of every
        // authenticated verification, before any idempotency work: a
        // worker that only serves Siteverify traffic never refreshes the
        // monitor through native paths, so the endpoint pulls the current
        // effective epoch itself, and a central policy bump then revokes
        // outstanding challenges within the monitor's cache window. The
        // max-stale fail-closed check applies here too: past the
        // configured window the central policy state can no longer be
        // confirmed (an emergency revocation could have landed while this
        // node could not read), so the endpoint answers the retryable
        // provider internal-error, with nothing claimed and nothing
        // verified; a later retry (with the documented idempotency_key)
        // can still run once the state is confirmable again. Without a
        // monitor the configured epoch is the effective one and the check
        // never fires.
        $effectiveEpoch = $this->epochMonitor?->refresh() ?? $this->policyVersion;
        if ($this->epochMonitor?->isStale()) {
            return $this->internalErrorResponse();
        }

        // The idempotency backend identity binds the secret, the
        // server-resolved expected scope and the effective security-policy
        // epoch (the monitor-refreshed value when wired, the static
        // configured epoch otherwise): a same-key request after a scope
        // remap or policy bump is a new logical operation (a conflict),
        // never a replay of the pre-change outcome.
        $backendId = hash('sha256', $secret.'|'.$expectedScope.'|'.$effectiveEpoch);

        // The authoritative transaction binding, resolved BEFORE any
        // claim or verification: when a request-binding authority is
        // configured (risk.request_binding_authority), the endpoint
        // enforces the same pre-consume transaction-binding contract as
        // the native path — a challenge cryptographically anchored to one
        // transaction is never redeemable for another through the
        // provider-compatible surface either. The authority resolves from
        // its own trusted inputs (session, cookies, server-attested
        // headers); the request's `request_binding` field (native or
        // provider vocabulary) is only a hint. An authority that cannot
        // attribute the transaction refuses the request before anything
        // is claimed or verified. Without an authority there is no
        // server-side transaction input and the endpoint cannot enforce a
        // binding: the configured combination is refused at container
        // compile time (see the extension) rather than silently turning
        // request binding off on this surface.
        // The presented binding comes from the ONE parsed-body object,
        // regardless of whether the transport was JSON or form: the
        // manually decoded JSON branch never populates the framework's
        // parameter bag, so a JSON caller's request_binding must be read
        // from $body itself — otherwise the two encodings would not have
        // equivalent binding behavior. The request attribute (the native
        // validator's transport) remains the precedence input.
        $presentedBinding = $request->attributes->get(KiwiCaptchaValidator::REQUEST_BINDING_ATTRIBUTE);
        if (!\is_string($presentedBinding) || $presentedBinding === '') {
            $posted = $body['request_binding'] ?? null;
            $presentedBinding = \is_string($posted) && $posted !== '' ? $posted : null;
        }
        $canonicalBinding = null;
        if ($this->bindingAuthority !== null) {
            // The authority's result is authoritative: a resolved binding
            // is the transaction's binding, a resolved null is an
            // explicitly UNBOUND transaction (the core's exact expectation
            // then refuses any bound record). An InvalidArgumentException
            // is a transaction mismatch (the 400 provider bad-request);
            // any infrastructure failure is the retryable internal-error,
            // never a client 400.
            try {
                $resolved = $this->bindingAuthority->resolve($request, $expectedScope, $presentedBinding);
            } catch (\InvalidArgumentException) {
                return new JsonResponse(['success' => false, 'error-codes' => ['bad-request']], Response::HTTP_BAD_REQUEST);
            } catch (\Throwable) {
                return $this->internalErrorResponse();
            }
            if (\is_string($resolved) && $resolved !== '') {
            // The authority's returned binding must satisfy the same
            // identifier shape the issuance side enforces — a value
            // outside it is refused at the trust boundary, never allowed
            // into the idempotency fingerprint/store.
            if (preg_match('/^[A-Za-z0-9._:-]{1,128}$/D', $resolved) !== 1) {
                return new JsonResponse(['success' => false, 'error-codes' => ['bad-request']], Response::HTTP_BAD_REQUEST);
            }
            $canonicalBinding = $resolved;
        } else {
            $canonicalBinding = null;
        }
        } elseif ($this->defaultRequestBinding !== null) {
            // The configured static server-side binding is authoritative
            // when no authority exists.
            $canonicalBinding = $this->defaultRequestBinding;
        } elseif (\is_string($presentedBinding) && $presentedBinding !== '') {
            // The authenticated backend's own request_binding field is
            // accepted only after identifier validation (the siteverify
            // secret is the authentication gate; a browser cannot reach
            // this path).
            if (preg_match('/^[A-Za-z0-9._:-]{1,128}$/', $presentedBinding) !== 1) {
                return new JsonResponse(['success' => false, 'error-codes' => ['bad-request']], Response::HTTP_BAD_REQUEST);
            }
            $canonicalBinding = $presentedBinding;
        }

        // The logical-operation identity of this claim: a single bounded
        // hex fingerprint of (backend identity, idempotency key, response
        // hash, canonicalized remoteip fingerprint, canonical transaction
        // binding) computed before the verify. The binding is part of the
        // identity, so an idempotency entry can never be reused across
        // different transaction contexts: the same key under a different
        // authoritative binding is a conflict, never a cached success.
        // The same value is recorded as the operation identity in the
        // verifier's atomic pending->consumed transition by every owner
        // that performs a fresh verification (the Claimed path and the
        // TookOver path alike; a non-idempotent request records nothing),
        // and compared against the consumed record's own stored identity
        // on the takeover path: reconstruction is recovery-eligible only
        // when the record's identity equals this claim's fingerprint,
        // written atomically with the state flip.
        $operationFingerprint = hash('sha256', $backendId."\0".($idempotencyKey ?? "\0no-key")."\0".hash('sha256', $response)."\0".$this->remoteipFingerprint($remoteIp)."\0".($canonicalBinding ?? "\0no-binding"));

        // The token is decoded before the claim so a malformed token is a
        // deterministic failure: the claiming request finalizes it, so a
        // same-key retry reproduces the identical canonical response
        // instead of leaving the entry pending until TTL. The claim
        // outcomes follow the decoded branch's conflict semantics: a
        // same-key entry bound to a different malformed response is a
        // conflict (the response hash is part of the claim identity), and
        // a `COMPLETE_SAME` entry (same malformed hash) returns the stored
        // canonical result instead of re-finalizing. The owner lease is
        // the store's fixed configured lease (default 60s) and the waiter
        // bound the configured `PENDING_SAME` bound (default 90s); neither
        // is derived from this token's remaining signed validity, so
        // signed expiry affects only fresh redemptions, never the
        // retained-state reconstruction.
        try {
            $token = SolutionToken::decode($response);
        } catch (DecodeError) {
            // A malformed token is a deterministic failure: the claiming
            // request finalizes it so a same-key retry reproduces the
            // identical canonical response instead of leaving the entry
            // pending until TTL. A same-key entry bound to a different
            // malformed response is a conflict; a matching entry returns
            // the stored canonical result instead of re-finalizing.
            $claim = IdempotencyClaim::Claimed;
            $claimOwner = null;
            if ($idempotencyKey !== null && $this->idempotencyStore !== null) {
                try {
                    [$claim, $claimOwner] = $this->idempotencyStore->claim($backendId, $idempotencyKey, hash('sha256', $response), 300, $this->remoteipFingerprint($remoteIp), null, $canonicalBinding);
                } catch (\Throwable) {
                    // The malformed-token claim is a raw store operation:
                    // nothing has been consumed (the decode failed), so a
                    // same-key retry is safe. Map to the retryable
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
                } catch (SiteVerifyIdempotencyCorruptException $e) {
                    // Corrupt security state is never "nothing here": the
                    // typed fail-closed 503, never a fresh claim.
                    error_log(sprintf('kiwicaptcha: corrupt siteverify idempotency record: %s', $e->getMessage()));

                    return $this->internalErrorResponse();
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
        // only the owning request verifies the token. A same-key retry
        // either returns the stored canonical response or, in the crash
        // window, reconstructs the original outcome via the core's
        // retained consumed-result machinery; ordinary replays without a
        // matching key stay timeout-or-duplicate. The idempotency
        // fingerprint binds backend identity, response hash and
        // canonicalized remoteip into the claim, so the same UUID with a
        // changed remoteip is a conflict, never a join or a reuse. The
        // logical-operation identity is passed into the verifier's atomic
        // consume whenever this request owns the pending claim and
        // performs a fresh verification (the Claimed path and the TookOver
        // first-verification path alike), so the retained consumed record
        // always carries the identity of the owner that performed the
        // actual atomic consume, for its whole lifetime.
        $claim = IdempotencyClaim::Claimed;
        $claimOwner = null;
        $claimedAt = null;
        $idempotent = false;
        if ($idempotencyKey !== null) {
            $idempotent = true;
            try {
                [$claim, $claimOwner] = $this->idempotencyStore->claim($backendId, $idempotencyKey, hash('sha256', $response), 300, $this->remoteipFingerprint($remoteIp), null, $canonicalBinding);
            } catch (\Throwable) {
                // The claim is a raw store operation (a Redis outage):
                // nothing has been consumed yet, so a same-key retry is
                // safe. Map to the retryable provider internal-error,
                // never a 500.
                return $this->internalErrorResponse();
            }
            if ($claim === IdempotencyClaim::Conflict) {
                return new JsonResponse(['success' => false, 'error-codes' => ['bad-request']], Response::HTTP_BAD_REQUEST);
            }
            if ($claim === IdempotencyClaim::CompleteSame) {
                try {
                    $stored = $this->idempotencyStore->stored($backendId, $idempotencyKey);
                } catch (SiteVerifyIdempotencyCorruptException $e) {
                    // Corrupt security state is never "nothing here": the
                    // typed fail-closed 503, never a fresh claim.
                    error_log(sprintf('kiwicaptcha: corrupt siteverify idempotency record: %s', $e->getMessage()));

                    return $this->internalErrorResponse();
                } catch (\Throwable) {
                    return $this->internalErrorResponse();
                }
                if ($stored !== null) {
                    if (($stored['success'] ?? false) === true) {
                        return $this->releaseAndJsonResponse($token->nonce, $this->canonicalizeResponse($stored));
                    }

                    return new JsonResponse($this->canonicalizeResponse($stored));
                }

                return new JsonResponse(['success' => false, 'error-codes' => ['timeout-or-duplicate']]);
            }
            if ($claim === IdempotencyClaim::Claimed) {
                $claimedAt = microtime(true);
            }
        }

        // `PENDING_SAME`: another request with the same key and hash owns
        // verification. This request waits on the store only. The stored
        // result is polled with an exponential backoff (100 ms, 200 ms,
        // 400 ms, 800 ms, then 1 s, jittered), so a retry storm never
        // hammers the store at a fixed 100 ms cadence. The atomic
        // takeover is attempted only when the owner lease is at/expired
        // from this waiter's perspective: the lease state is probed once
        // up front (a single atomic takeover attempt — an owner whose
        // lease already expired is taken over promptly, the displaced-
        // owner contract), and after a StillPending probe the takeover is
        // re-attempted only once a full fixed lease window has elapsed
        // since the pending entry was first observed (the owner claimed
        // no earlier than that observation, so the lease is then
        // guaranteed to have expired). This request never invokes the
        // verifier without winning the takeover, since a deliberately
        // slow Argon solve can legitimately take tens of seconds.
        // Verification happens strictly while holding the current owner
        // token; at the hard bound below the request is answered with a
        // retryable error instead, leaving the entry pending for a later
        // retry.
        if ($idempotent && $claim === IdempotencyClaim::PendingSame) {
            $stored = null;
            $waitDeadline = microtime(true) + $this->idempotencyWaitSecs;
            $leaseSeconds = $this->idempotencyStore->leaseSeconds();
            // The pending entry was first observed now; the owner claimed
            // no earlier than this moment, so the fixed lease expires at
            // the latest one full window from here.
            $pendingSince = microtime(true);
            $backoffMs = self::PENDING_SAME_POLL_BASE_MS;
            $leaseProbed = false;
            $takeoverArmed = false;
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
                    // Hard bound without ownership: no stored result and
                    // no takeover, so another owner is still working the
                    // entry. Nothing is verified here: the client receives
                    // a retryable provider error, and the claim entry
                    // remains pending for a later retry.
                    return $this->internalErrorResponse();
                }
                if (!$leaseProbed) {
                    // The one-time lease probe: the owner may have claimed
                    // long before this waiter observed the pending entry,
                    // so the lease may already be expired — a prompt
                    // takeover honors the displaced-owner contract (the
                    // entry must not wait a full window for an owner whose
                    // lease is already gone). A StillPending probe means
                    // the lease is still held: no further takeover attempt
                    // happens until the lease is at/expired from this
                    // waiter's perspective.
                    $leaseProbed = true;
                    $attempt = $this->attemptTakeover($backendId, $idempotencyKey, $response, $remoteIp, $claimOwner, $claimedAt, $canonicalBinding);
                    if ($attempt instanceof JsonResponse) {
                        return $attempt;
                    }
                    if ($attempt === true) {
                        $claim = IdempotencyClaim::TookOver;
                        break;
                    }
                } else {
                    if (!$takeoverArmed && microtime(true) - $pendingSince >= $leaseSeconds) {
                        // The owner's lease is at/expired from this
                        // waiter's perspective: the takeover is now
                        // worthwhile. The cadence resets to the short
                        // base so the attempt lands promptly at the
                        // boundary.
                        $takeoverArmed = true;
                        $backoffMs = self::PENDING_SAME_POLL_BASE_MS;
                    }
                    if ($takeoverArmed) {
                        $attempt = $this->attemptTakeover($backendId, $idempotencyKey, $response, $remoteIp, $claimOwner, $claimedAt, $canonicalBinding);
                        if ($attempt instanceof JsonResponse) {
                            return $attempt;
                        }
                        if ($attempt === true) {
                            $claim = IdempotencyClaim::TookOver;
                            break;
                        }
                    }
                }
                usleep(self::jitteredBackoffMs($backoffMs) * 1000);
                $backoffMs = min($backoffMs * 2, self::PENDING_SAME_POLL_MAX_MS);
            }
            if ($stored !== null) {
                if (($stored['success'] ?? false) === true) {
                    // The waiter observes the owner's committed success:
                    // the release is retried here too, so a transient
                    // release failure on the original verification is
                    // repaired by this same-logical-operation observation.
                    return $this->releaseAndJsonResponse($token->nonce, $this->canonicalizeResponse($stored));
                }

                return new JsonResponse($this->canonicalizeResponse($stored));
            }
        }

        // Crash recovery first: this request now owns the claim (claim or
        // takeover), so if the token was already consumed, reconstruct the
        // original deterministic outcome. This works even when the signed
        // challenge has expired in the meantime (a token submitted late in
        // its lifetime): the retained outcome is the original logical
        // result, not a fresh redemption. Reconstruction runs only on the
        // takeover path, where the request has proven the idempotency
        // identity against the pre-existing entry (same backend, key,
        // response hash and remote-IP fingerprint) and the consumed
        // record's own operation identity equals this claim's fingerprint,
        // written atomically with the pending->consumed transition. A
        // missing identity (a no-key first redemption, a storage without
        // identity support, or a different-UUID claim) refuses
        // reconstruction, so an ordinary replay under a different or new
        // key must not reconstruct: the compatibility boundary keeps
        // mapping a consumed token to timeout-or-duplicate via the
        // verifier's own replay path.
        //
        // Two sub-cases of the identity-proven takeover:
        //  - Committed-result reconstruction: the original attempt
        //    consumed and committed its deterministic outcome, and the
        //    retained consumed_result reproduces it without re-deriving
        //    (ConsumedOutcomeRecovery).
        //  - Uncommitted-result resume: the original attempt consumed (the
        //    atomic transition landed and recorded this claim's identity)
        //    but the response was lost before the derivation/commit, so
        //    consumed_result stays null forever for the ordinary verifier
        //    (ConsumeIndeterminate). The resume path is authorized only by
        //    the exact operation-identity match just proven: the caller
        //    has shown that this logical operation won the atomic consume,
        //    so the derivation can be re-run and committed, producing the
        //    same deterministic outcome the original attempt would have
        //    committed.
        $reconstructed = null;
        $resumeOutcome = null;
        if ($idempotent && $claim === IdempotencyClaim::TookOver) {
            try {
                $consumed = $this->storage instanceof ConsumedStateReadableInterface
                    ? $this->storage->consumedState($token->nonce)
                    : null;
                if ($consumed?->operationIdentity === $operationFingerprint) {
                    if ($consumed->consumedResult !== null) {
                        // The identity travels into the recovery call: the
                        // stored valid outcome is released only to the
                        // exact logical operation (constant-time compare
                        // inside the recovery; the equality above already
                        // proved it, and the inner gate keeps the recovery
                        // API itself from being a replay oracle).
                        $reconstructed = $this->recovery->recover($response, $operationFingerprint);
                    } else {
                        $resumeOutcome = $this->withScopeAttribute($request, $expectedScope, fn () => $this->verifier->resumeConsumedOperation(
                            $response,
                            $this->secretKey,
                            $operationFingerprint,
                            $expectedScope,
                            $remoteIp,
                            $canonicalBinding,
                            \KiwiCaptcha\RequestBindingExpectation::exact($canonicalBinding),
                        ));
                    }
                }
            } catch (\Throwable) {
                // A consumed-state or recovery-store outage on the
                // takeover path maps to the retryable provider error: the
                // entry stays pending and the same-key retry can try
                // again once the store is back.
                return $this->internalErrorResponse();
            }
        }
        if ($reconstructed !== null) {
            $canonicalResponse = $this->outcomeToCanonical($reconstructed);
            if ($canonicalResponse instanceof JsonResponse) {
                return $canonicalResponse;
            }
            $canonical = $this->canonicalizeResponse($canonicalResponse);
            if ($claimOwner !== null) {
                $failed = $this->finalizeSafely($backendId, $idempotencyKey, hash('sha256', $response), $claimOwner, $canonical, $claimedAt);
                if ($failed !== null) {
                    return $failed;
                }
            }
            if ($reconstructed->isOk()) {
                // The crash-recovery success releases too: a crash
                // between the original consume/commit and its release is
                // repaired by the first later successful reconstruction.
                return $this->releaseAndJsonResponse($reconstructed->nonce(), $canonical);
            }

            return new JsonResponse($canonical);
        }
        if ($resumeOutcome !== null) {
            // The resumed outcome maps through the same canonicalization
            // as a fresh verification: success to canonical success,
            // InsufficientWork or other invalid to the mapped provider
            // error, and StorageUnavailable or ConsumeIndeterminate to the
            // retryable 503 internal-error without any finalize (the claim
            // stays pending, so a later same-key retry can resume again
            // once the backend recovers).
            $canonicalResponse = $this->outcomeToCanonical($resumeOutcome);
            if ($canonicalResponse instanceof JsonResponse) {
                return $canonicalResponse;
            }
            $canonical = $this->canonicalizeResponse($canonicalResponse);
            if (($canonical['error-codes'][0] ?? null) === 'internal-error') {
                return $this->internalErrorResponse();
            }
            if ($claimOwner !== null) {
                $failed = $this->finalizeSafely($backendId, $idempotencyKey, hash('sha256', $response), $claimOwner, $canonical, $claimedAt);
                if ($failed !== null) {
                    return $failed;
                }
            }
            if ($resumeOutcome->isOk()) {
                return $this->releaseAndJsonResponse($resumeOutcome->nonce(), $canonical);
            }

            return new JsonResponse($canonical);
        }

        // The same atomic verifier as the native path, with the expected
        // scope resolved from the secret: a weaker login token presented
        // to the financial secret is rejected (WrongScope), so the
        // sitekey-allowlist mapping is enforced end to end. `remoteip` is
        // honored only because the caller proved possession of a valid
        // secret above; it is required whenever IP binding is enabled
        // (the default), and a bound challenge without it fails closed.
        // Owner protection is the lease window: the store's ownership
        // lease (default 60s) comfortably exceeds the maximum supported
        // verification window, so a live-but-slow owner is never
        // overtaken mid-verify. The operation identity is passed on every
        // idempotent path that performs a fresh verification (the Claimed
        // path and the TookOver first-verification path alike); a
        // non-idempotent request passes null and records no identity, so
        // a later keyed replay can never reconstruct.
        try {
            $outcome = $this->withScopeAttribute($request, $expectedScope, function () use ($response, $expectedScope, $remoteIp, $idempotent, $claim, $operationFingerprint, $canonicalBinding): \KiwiCaptcha\VerifyOutcome {
                // The scope attribute drives the Argon per-scope admission
                // budget (RequestScopeAdmissionGate): without it, every
                // Siteverify redemption would fall into the unscoped
                // global-only path and one busy scope could starve the
                // others. The expected binding is enforced by the core
                // BEFORE the consume, exactly like the native path.
                return $this->verifier->verify(
                    $response,
                    $this->secretKey,
                    $expectedScope,
                    $remoteIp,
                    null,            // region expectation is application policy
                    false,           // telemetry is never authoritative here
                    $idempotent && ($claim === IdempotencyClaim::Claimed || $claim === IdempotencyClaim::TookOver) ? $operationFingerprint : null,
                    $canonicalBinding,
                    \KiwiCaptcha\RequestBindingExpectation::exact($canonicalBinding),
                );
            });
        } catch (\InvalidArgumentException) {
            // Defensive boundary: the remoteip was validated above, so
            // the core's IP canonicalization cannot throw here. An
            // unexpected InvalidArgumentException maps to the provider
            // bad-request JSON; exceptions must not cross the HTTP
            // compatibility boundary.
            return new JsonResponse(['success' => false, 'error-codes' => ['bad-request']], Response::HTTP_BAD_REQUEST);
        } catch (\Throwable) {
            // Hardened boundary tail: anything else escaping the verifier
            // (a storage failure past its own internal handling) maps to
            // the retryable provider error; an exception must never cross
            // the HTTP compatibility boundary as a 500.
            return $this->internalErrorResponse();
        }
        if ($claimOwner !== null) {
            try {
                $stillOwns = $this->confirmOwnership($backendId, $idempotencyKey, $claimOwner);
            } catch (\Throwable) {
                // The ownership-confirmation renewal is a raw store
                // operation: a failure must not cross the boundary as a
                // 500. The request is answered with the retryable
                // provider error; a same-key retry re-verifies or reads
                // the stored outcome.
                return $this->internalErrorResponse();
            }
            if (!$stillOwns) {
                // Ownership was lost while verifying (the lease window
                // expired mid-verification): the local result is not
                // authoritative. Return the stored authoritative result,
                // or a retryable provider error when none exists yet.
                try {
                    $stored = $this->idempotencyStore?->stored($backendId, $idempotencyKey);
                } catch (\Throwable) {
                    return $this->internalErrorResponse();
                }
                if ($stored !== null) {
                    if (($stored['success'] ?? false) === true) {
                        return $this->releaseAndJsonResponse($token->nonce, $this->canonicalizeResponse($stored));
                    }

                    return new JsonResponse($this->canonicalizeResponse($stored));
                }

                return $this->internalErrorResponse();
            }
        }

        // The compatibility boundary distinguishes the first redemption
        // from replays. The native deterministic-result retry machinery
        // stays inside the verifier, but a repeated Siteverify redemption
        // of the same nonce must not report success again: it returns the
        // provider vocabulary for a consumed token. An idempotent retry
        // that has proven the same key and hash against a pending claim
        // may interpret the stored result as the original outcome (crash
        // recovery), since it is the same logical redemption, not a
        // second one. A different logical operation that observes the
        // consumed result (a different UUID for the same nonce, or a
        // takeover the consumed-record identity gate refused) finalizes
        // its claim with the canonical duplicate response: the entry is
        // finalized, a same-UUID retry returns the stored duplicate
        // immediately, and the record's own operation identity is the
        // structural backstop for the crash-between-detect-and-finalize
        // window.
        if ($outcome->isOk() && $outcome->fromStoredResult) {
            // The consumed token is a deterministic duplicate for this
            // claim: finalize it with the canonical duplicate response so
            // a same-UUID retry returns the stored bytes immediately; the
            // entry can never be taken over and reconstructed as a
            // success.
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

            return $this->releaseAndJsonResponse($outcome->nonce(), $canonical);
        }

        if ($outcome->isOk()) {
            $success = $this->canonicalSuccess($outcome);
            if ($success instanceof JsonResponse) {
                return $success;
            }
            $canonical = $this->canonicalizeResponse($success);
            if ($claimOwner !== null) {
                $failed = $this->finalizeSafely($backendId, $idempotencyKey, hash('sha256', $response), $claimOwner, $canonical, $claimedAt);
                if ($failed !== null) {
                    return $failed;
                }
            }

            return $this->releaseAndJsonResponse($outcome->nonce(), $canonical);
        }

        $error = $outcome->error();
        $mapped = $this->mapError($error);
        if ($mapped === 'internal-error') {
            // A retryable server-side failure (storage, admission or
            // capacity outage): the 503 internal-error shape, never a 200
            // with a bad-request code. The claim stays pending, so a
            // same-key retry can re-verify once the backend recovers.
            return $this->internalErrorResponse();
        }
        $canonical = [
            'success' => false,
            'challenge_ts' => null,
            'hostname' => null,
            'error-codes' => [$mapped],
        ];
        $canonical = $this->canonicalizeResponse($canonical);
        if ($claimOwner !== null) {
            // A failed verification is also finalized: a same-key retry
            // must reproduce the same canonical failure.
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
     * was already lost: the finalize is then an atomic no-op and the new
     * owner's outcome stays authoritative. The lease window is the
     * store's fixed configured lease, never derived from the token's
     * remaining validity.
     */
    private function finalizeAsOwner(string $backendId, string $idempotencyKey, string $responseHash, string $owner, array $canonical, ?float $claimedAt): bool
    {
        if ($claimedAt !== null && microtime(true) - $claimedAt >= $this->idempotencyStore->leaseSeconds()) {
            $this->idempotencyStore?->renew($backendId, $idempotencyKey, $owner);
        }

        return $this->idempotencyStore?->finalize($backendId, $idempotencyKey, $responseHash, $owner, $canonical) ?? false;
    }

    /**
     * The owner's finalize hardened against the HTTP boundary: the raw
     * store operations (renew + finalize) can throw, and the failure
     * must not become a 500. The token may already be consumed and
     * committed by the core: the entry stays pending, and a same-key
     * retry takes over and reconstructs (or reads) the committed
     * outcome, so retryability is preserved. Before consumption the same
     * failure is equally safe: the claim was never finalized and the
     * retry re-runs the ordinary verify.
     *
     * @return JsonResponse|null the 503 internal-error response when the
     *         store failed, null when the finalize completed (or was an
     *         atomic no-op)
     */
    private function finalizeSafely(string $backendId, string $idempotencyKey, string $responseHash, string $owner, array $canonical, ?float $claimedAt): ?JsonResponse
    {
        try {
            $finalized = $this->finalizeAsOwner($backendId, $idempotencyKey, $responseHash, $owner, $canonical, $claimedAt);
        } catch (\Throwable) {
            return $this->internalErrorResponse();
        }
        if (!$finalized) {
            // A REFUSED finalize is exactly an ownership loss: the claim
            // was taken over (or the key vanished, or the state moved), so
            // this request's locally computed result is NEVER returned as
            // authoritative — the authoritative completed state was not
            // established. The retryable 503.
            return $this->internalErrorResponse();
        }

        return null;
    }

    /**
     * The retryable provider internal-error response (503): a transient
     * store failure inside the idempotency machinery, where nothing has
     * been consumed or the committed outcome stays recoverable, so the
     * caller may safely retry with the same key. An exception must never
     * cross the HTTP compatibility boundary as a 500.
     */
    private function internalErrorResponse(): JsonResponse
    {
        return new JsonResponse(['success' => false, 'error-codes' => ['internal-error']], Response::HTTP_SERVICE_UNAVAILABLE);
    }

    /**
     * The `PENDING_SAME` poll sleep in milliseconds: the backoff interval
     * plus a bounded jitter (at most a quarter of the interval), so a
     * storm of duplicate waiters desynchronizes instead of polling the
     * store in lockstep. The jitter is capped below the doubling step, so
     * the poll intervals still grow monotonically.
     */
    private static function jitteredBackoffMs(int $backoffMs): int
    {
        return $backoffMs + random_int(0, max(1, intdiv($backoffMs, 4)));
    }

    /**
     * The atomic takeover attempt of a `PENDING_SAME` entry. The lease
     * gate is inside the store's Lua: before expiry this attempt is an
     * atomic no-op (StillPending). The remoteip fingerprint is bound in
     * the record, so the takeover enforces the complete claim identity
     * (the claim pass already checked it; defense in depth). The
     * takeover refreshes the lease with the store's fixed configured
     * lease, never derived from the token's remaining validity; the
     * fixed 60s lease exceeds any supported verification window, so a
     * live owner is never overtaken mid-verify. On success the caller
     * becomes the owner and must finalize with the returned owner token.
     *
     * @return bool|JsonResponse true when the takeover was won (the
     *         caller is now the owner, {@see $claimOwner} /
     *         {@see $claimedAt} are set). False when the attempt was an
     *         atomic no-op (StillPending, keep waiting). The retryable
     *         503 internal-error response is returned when the store
     *         failed: a transient takeover outage maps to the provider
     *         error, the entry stays pending, and a later retry can
     *         still take over or read the stored result.
     */
    private function attemptTakeover(string $backendId, string $idempotencyKey, string $response, ?string $remoteIp, ?string &$claimOwner, ?float &$claimedAt, ?string $canonicalBinding): bool|JsonResponse
    {
        try {
            [$takeover, $takeoverOwner] = $this->idempotencyStore->takeover($backendId, $idempotencyKey, hash('sha256', $response), 300, $this->remoteipFingerprint($remoteIp), null, $canonicalBinding);
        } catch (\Throwable) {
            return $this->internalErrorResponse();
        }
        if ($takeover !== IdempotencyClaim::TookOver) {
            return false;
        }
        // This request now owns the entry: it will verify below and
        // finalize with the takeover owner token.
        $claimOwner = $takeoverOwner;
        $claimedAt = microtime(true);

        return true;
    }

    /**
     * Canonicalize a provider response for storage and comparison: sorted
     * keys make the stored round-trip byte-deterministic, so a same-key
     * retry returns the identical JSON bytes (the concurrency contract).
     */
    private function canonicalizeResponse(array $response): array
    {
        ksort($response);

        return $response;
    }

    /**
     * The canonical provider response for an outcome: the success shape
     * with server-bound metadata, or the mapped failure shape. The
     * retryable 503 internal-error response is returned instead of a
     * canonical array when the success-shape reads hit a storage outage,
     * since a storage failure after consumption must never 500.
     */
    /**
     * Run a callable with the request scope attribute stamped for the
     * Argon per-scope admission budget (RequestScopeAdmissionGate reads
     * the scope from the request attribute; without it every Siteverify
     * redemption would fall into the unscoped global-only path and one
     * busy scope could starve the others). The previous attribute value
     * is restored afterwards.
     *
     * @template T
     *
     * @param callable(): T $fn
     *
     * @return T
     */
    private function withScopeAttribute(Request $request, string $scope, callable $fn): mixed
    {
        $previous = $request->attributes->get(RequestScopeAdmissionGate::SCOPE_ATTRIBUTE);
        $request->attributes->set(RequestScopeAdmissionGate::SCOPE_ATTRIBUTE, $scope);
        try {
            return $fn();
        } finally {
            if ($previous === null) {
                $request->attributes->remove(RequestScopeAdmissionGate::SCOPE_ATTRIBUTE);
            } else {
                $request->attributes->set(RequestScopeAdmissionGate::SCOPE_ATTRIBUTE, $previous);
            }
        }
    }

    /**
     * The single successful-outcome return path: releases the solved
     * nonce's ORIGINAL outstanding slot and its live-outstanding
     * membership (idempotent, nonce-authoritative, best-effort — a
     * transient release failure is repaired by the same logical
     * operation's later successful observation, since the ZREM-gated
     * release is a no-op once released) and returns the canonical
     * response. EVERY accepted successful outcome routes through here —
     * the fresh verification, a reconstruction, a resume, a stored-result
     * duplicate, and every cached stored success a same-operation retry
     * observes (CompleteSame, PendingSame waiter, ownership-lost fallback
     * alike, with the already-decoded token's nonce) — so the ordinary
     * fresh-success path can never bypass the release and the
     * crash-recovery and waiter paths repair a failed one.
     */
    private function releaseAndJsonResponse(string $nonce, array $canonical): JsonResponse
    {
        $this->outstanding?->solved($nonce);

        return new JsonResponse($canonical);
    }

    private function outcomeToCanonical(VerifyOutcome $outcome): array|JsonResponse
    {
        if ($outcome->isOk()) {
            // The release happens once, at the single lifecycle hook in
            // siteverify(), before any response construction.
            return $this->canonicalSuccess($outcome);
        }

        return [
            'success' => false,
            'challenge_ts' => null,
            'hostname' => null,
            'error-codes' => [$this->mapError($outcome->error())],
        ];
    }

    /**
     * The provider-shaped success response, including the server-stored
     * challenge metadata (action/cData bound at issuance, never echoed
     * from the request) and the retained record's challenge_ts/hostname.
     * Both reads sit inside a hard Throwable boundary: a storage or
     * metadata outage after the token was consumed maps to the retryable
     * 503 internal-error response, never a raw 500.
     */
    private function canonicalSuccess(VerifyOutcome $outcome): array|JsonResponse
    {
        try {
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
        } catch (\Throwable) {
            // A storage or metadata outage after the token was consumed
            // must never 500: return the retryable internal-error
            // response (worst for non-idempotent requests, but the
            // consumed outcome stays retained and the caller can retry
            // once the store recovers).
            return $this->internalErrorResponse();
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
        // the precise core reason stays in the application logs. The
        // provider contract: bad-request is a malformed request (enforced
        // at the request-shape layer), timeout-or-duplicate is an
        // already-validated token, invalid-input-response is a token that
        // fails validation (wrong work, wrong profile, wrong identity,
        // bad signature), and internal-error is a retryable server-side
        // condition (outage, admission rejection, capacity). A too-fast or
        // wrong-solution token is an invalid response, never a malformed
        // request. A token already consumed by a different logical
        // operation (AlreadyConsumed) is the duplicate vocabulary, and a
        // token not bound to the expected application transaction
        // (RequestBindingMismatch) is an invalid response.
        //
        // ConsumeIndeterminate is a retryable server-side condition, never
        // an asserted duplicate: the atomic consume's response was lost,
        // so the storage may or may not have executed the transition. The
        // internal-error arm returns before any finalize, so the claim
        // stays pending and a same-key retry can re-verify a challenge
        // the transition never executed, or reconstruct the retained
        // outcome of one it did. Mapping it to timeout-or-duplicate would
        // finalize the claim and permanently destroy the idempotency_key
        // retry contract for a challenge that may still be perfectly
        // redeemable.
        return match ($error) {
            VerifyError::Expired,
            VerifyError::AlreadyConsumed => 'timeout-or-duplicate',
            VerifyError::StorageUnavailable,
            VerifyError::AdmissionUnavailable,
            VerifyError::CapacityExceeded,
            VerifyError::TooManyAttempts,
            VerifyError::ConsumeIndeterminate => 'internal-error',
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
            VerifyError::WrongPolicyVersion,
            VerifyError::RequestBindingMismatch,
            VerifyError::TooFast,
            VerifyError::InsufficientWork,
            VerifyError::UnsupportedArgon2Params,
            VerifyError::TelemetryRejected => 'invalid-input-response',
            // Defensive fallback for future error classes: an unknown
            // outcome is never a retryable server failure and never a
            // request-shape violation, so it maps to the
            // invalid-response vocabulary.
            default => 'invalid-input-response',
        };
    }

    /**
     * Invalid-secret diagnostics are gated by a shared Redis log gate
     * (INCR + EXPIRE) so the aggregation is deployment-wide; counters
     * held per controller instance are meaningless across PHP-FPM workers
     * (a fresh controller per request). Logging is logarithmic (1, 2, 4,
     * 8...): early visibility with bounded flood amplification. Log-gate
     * failure never affects verification: on Redis errors the detailed
     * log is suppressed while requests are still rejected.
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
            try {
                $this->logger?->warning(sprintf('kiwicaptcha siteverify: invalid-secret attempts (%s) — %s secret', $kind, $count));
            } catch (\Throwable) {
                // A raising logger must never turn an invalid-secret
                // rejection into a 500.
            }
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
     * chunked body is refused by the caller's length check without ever
     * being materialized in full. When Symfony hands back a buffered
     * stream (tests, already-consumed input), the read is still bounded.
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
    /**
     * Strict form-urlencoded decoder: rejects duplicate parameter names
     * and PHP bracket syntax, so the form transport has the same
     * parser-ambiguity rigor as the JSON transport. Returns the decoded
     * name=>value map, or null when the body is not strictly decodable.
     */
    private function decodeStrictFormBody(string $body): ?array
    {
        if ($body === '') {
            return null;
        }
        $decoded = [];
        foreach (explode('&', $body) as $pair) {
            if ($pair === '') {
                continue;
            }
            $parts = explode('=', $pair, 2);
            // Canonical application/x-www-form-urlencoded: '+' means a
            // space (rawurldecode would disagree with a standards-compliant
            // intermediary), every '%' must be followed by exactly two hex
            // digits (a malformed %ZZ is not canonical and is refused),
            // and the decoded names must be non-empty, bracket-free and
            // duplicate-free.
            $name = $this->canonicalFormDecode($parts[0]);
            if ($name === null || $name === '' || str_contains($name, '[') || str_contains($name, ']')) {
                return null;
            }
            if (\array_key_exists($name, $decoded)) {
                return null;
            }
            $value = $this->canonicalFormDecode($parts[1] ?? '');
            if ($value === null) {
                return null;
            }
            $decoded[$name] = $value;
        }

        return $decoded;
    }

    /**
     * The canonical form-urlencoded decode of one component: '+' -> space,
     * then percent-decode with strict '%'-escape validation. Returns null
     * for a malformed escape (the strict decoder refuses it, never
     * admitting a non-canonical body).
     */
    private function canonicalFormDecode(string $component): ?string
    {
        $length = \strlen($component);
        $out = '';
        for ($i = 0; $i < $length; ++$i) {
            $ch = $component[$i];
            if ($ch === '+') {
                $out .= ' ';

                continue;
            }
            if ($ch !== '%') {
                $out .= $ch;

                continue;
            }
            if ($i + 2 >= $length || !ctype_xdigit($component[$i + 1]) || !ctype_xdigit($component[$i + 2])) {
                return null;
            }
            $out .= chr(hexdec(substr($component, $i + 1, 2)));
            $i += 2;
        }

        return $out;
    }

    private function parseBody(Request $request, string $requestBody): ?array
    {
        // Framing rigor: only POST with an explicit identity content type
        // is accepted — the provider contract is application/json and
        // application/x-www-form-urlencoded, and the parameter source is
        // the BODY only (query parameters never create a second input
        // namespace, and multipart/text/plain are refused rather than
        // silently parsed).
        if (!$request->isMethod('POST')) {
            return null;
        }
        if ($request->query->count() > 0) {
            return null;
        }
        $contentType = strtolower(trim(explode(';', (string) $request->headers->get('Content-Type', ''), 2)[0]));
        if ($contentType === 'application/json') {
            // The shared raw-document duplicate-key scanner:
            // {"secret":"A","secret":"B"} is refused, never silently
            // last-wins. A document the scanner cannot walk (depth bomb or
            // malformed string) is refused too — "could not establish
            // cleanliness" is never treated as clean.
            try {
                $scan = $this->scanJsonDuplicateKeys($requestBody);
                if ($scan !== null) {
                    return null;
                }
                $decoded = json_decode($requestBody, true, 32, JSON_THROW_ON_ERROR);

                return \is_array($decoded) ? $decoded : null;
            } catch (\JsonException) {
                return null;
            } catch (\BelConsulting\KiwiCaptchaBundle\Http\MalformedJsonWalkException) {
                return null;
            }
        }
        if ($contentType === 'application/x-www-form-urlencoded') {
            // The strict form decoder rejects duplicate parameter names
            // and PHP bracket syntax, so the form transport has the same
            // parser-ambiguity rigor as the JSON transport (a
            // secret=A&secret=B request must never be silently collapsed
            // into whichever interpretation the framework chose). An
            // EMPTY raw body falls back to the framework-parsed bag (the
            // framework's own form parser runs the same normalization; a
            // real empty-body POST yields an empty bag, so the fallback
            // cannot smuggle parameters past the strict decoder).
            $strict = $this->decodeStrictFormBody($requestBody);
            if ($strict !== null) {
                return $strict;
            }
            if ($requestBody === '' && $request->request->count() === 0) {
                // An empty body with an empty framework bag: the strict
                // decoder found nothing — the empty request proceeds (the
                // field validation then refuses the missing parameters).
                return $request->request->all();
            }

            // A non-empty body that failed the strict decode, OR an empty
            // raw body with a POPULATED framework bag (the parameters were
            // parsed upstream by a different parser, so the duplicate-name
            // and bracket-syntax evidence is lost): fail closed rather
            // than silently switching parsers.
            return null;
        }

        return null;
    }

    /**
     * Recursive duplicate-key scanner for the JSON body (the same rule as
     * the challenge endpoint): returns the first duplicated key, or null
     * when the document has no duplicate keys. Bounded by the 16 KiB body
     * ceiling plus a recursion cap, so a depth bomb cannot exhaust the
     * stack.
     */
    /**
     * The RAW-document duplicate-key scanner — the single shared
     * implementation used by every security-sensitive endpoint
     * ({@see JsonDuplicateKeyScanner}). A decode-then-scan can NEVER see
     * a duplicate: json_decode has already collapsed the object members
     * ({"secret":"A","secret":"B"} arrives as one secret), which is
     * exactly the parser ambiguity that must be refused. The walker
     * inspects the raw bytes, so the first duplicated key is found before
     * any interpretation happens.
     */
    private function scanJsonDuplicateKeys(string $json): ?string
    {
        return $this->jsonDuplicateKeyScanner->scanForDuplicateJsonKey($json);
    }
}
