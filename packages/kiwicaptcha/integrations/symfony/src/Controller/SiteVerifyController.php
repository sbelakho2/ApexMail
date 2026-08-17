<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Controller;

use BelConsulting\KiwiCaptchaBundle\SiteVerify\IdempotencyClaim;
use BelConsulting\KiwiCaptchaBundle\SiteVerify\RedisEval;
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
 * Provider-compatible Siteverify endpoint (round 24): accepts the incumbent
 * backend shape — `response`, `secret`, optional `remoteip` — as form or
 * JSON, and returns the provider-shaped verification JSON
 * (`success`, `challenge_ts`, `hostname`, `error-codes`). It calls the
 * EXACT SAME atomic Kiwi verifier as the native integration — there is no
 * second verification implementation, and the deterministic consumed-result
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
 *  - The underlying verifier remains authoritative: TTL, scope/region/
 *    issuer/policy expectations, nonce-bound IP binding, timing floor,
 *    Argon ceilings and atomic single-use consumption all apply exactly as
 *    in the native path.
 */
final class SiteVerifyController
{
    /** Round 30 (P1): documented bounded maximum for the `response` token. */
    private const MAX_RESPONSE_BYTES = 8192;

    /**
     * Round 31 (P2): the hard bound on the PENDING_SAME wait. Only after
     * this (the catastrophic path) does a waiter fall through to the
     * verifier; the owner's lease (30s) is refreshed by an atomic takeover
     * long before, so this bound is the absolute tail.
     */
    private const IDEMPOTENCY_WAIT_SECS = 90.0;

    /**
     * @param array<string, string> $siteverifySecrets map of
     *        server-to-server secret -> expected scope; EMPTY disables the
     *        endpoint (round 26: a per-secret expected scope is REQUIRED —
     *        no global-secret + expectedScope=null for multi-scope
     *        deployments, so a weaker token can never satisfy a stronger
     *        backend's secret)
     */
    public function __construct(
        private readonly Verifier $verifier,
        private readonly string $secretKey,
        private readonly array $siteverifySecrets,
        private readonly ?AtomicStorageInterface $storage = null,
        private readonly ?LoggerInterface $logger = null,
        // Round 30 (P1): server-owned compatibility metadata (action/cData
        // bound at challenge issuance) and provider-style verification
        // idempotency (idempotency_key). Null disables the respective
        // feature: metadata never appears in the response, and an
        // idempotency_key on the request is rejected (the operator must
        // wire the stores for provider-style retries).
        private readonly ?\BelConsulting\KiwiCaptchaBundle\SiteVerify\SiteVerifyMetadataStore $metadataStore = null,
        private readonly ?\BelConsulting\KiwiCaptchaBundle\SiteVerify\SiteVerifyIdempotencyStore $idempotencyStore = null,
        /** Round 30 (item 16): shared Redis log gate (optional). */
        private readonly \Predis\Client|\Redis|null $logGate = null,
    ) {
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

        // Round 28 (P3): the endpoint is PUBLIC until the secret check —
        // a narrow body ceiling (16 KiB covers every legitimate provider
        // envelope: response+secret+remoteip) keeps an oversized-body
        // flood from ever reaching the parser or the verifier. The ACTUAL
        // body is measured (getContent() is cached by Symfony), not the
        // client-settable Content-Length header.
        if (\strlen((string) $request->getContent()) > self::MAX_BODY_BYTES) {
            return new JsonResponse(['success' => false, 'error-codes' => ['bad-request']], Response::HTTP_REQUEST_ENTITY_TOO_LARGE);
        }

        $body = $this->parseBody($request);
        if ($body === null) {
            return new JsonResponse(['success' => false, 'error-codes' => ['bad-request']], Response::HTTP_BAD_REQUEST);
        }
        $response = $body['response'] ?? null;
        $secret = $body['secret'] ?? null;
        $remoteIp = \is_string($body['remoteip'] ?? null) ? $body['remoteip'] : null;
        // Round 30 (P1): action / cData are NEVER accepted on the
        // verification request — that would let a backend request tell
        // Kiwi "this token's action was checkout", reversing the trust
        // direction. They are captured at CHALLENGE ISSUANCE (widget
        // data-action/data-cdata) and returned from the server-side
        // metadata store.
        $idempotencyKey = \is_string($body['idempotency_key'] ?? null) ? $body['idempotency_key'] : null;
        // Round 30 (P1): the token length is bounded BEFORE decoding —
        // provider contracts document a 2048-char maximum; Kiwi's own
        // legitimate encoding fits comfortably under 8192, which is the
        // documented bound here (the 16 KiB whole-body ceiling stays as
        // the outer envelope).
        if (!\is_string($response) || $response === '') {
            return new JsonResponse(['success' => false, 'error-codes' => ['missing-input-response']]);
        }
        if (\strlen($response) > self::MAX_RESPONSE_BYTES) {
            return new JsonResponse(['success' => false, 'error-codes' => ['invalid-input-response']]);
        }

        // Round 30 (P1): a UUID-shaped idempotency_key only — arbitrary
        // short strings are rejected BEFORE the verifier (bounded
        // cardinality, no attacker-controlled shapes).
        if ($idempotencyKey !== null) {
            if (!\preg_match('/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i', $idempotencyKey)) {
                return new JsonResponse(['success' => false, 'error-codes' => ['bad-request']], Response::HTTP_BAD_REQUEST);
            }
            if ($this->idempotencyStore === null) {
                return new JsonResponse(['success' => false, 'error-codes' => ['bad-request']], Response::HTTP_BAD_REQUEST);
            }
        }

        // Round 26: the presented secret authenticates the backend AND
        // resolves the EXPECTED SCOPE the verifier must enforce. Constant-
        // time comparisons; the detail goes to the log only. A secret not
        // in the server-owned map is rejected — an attacker-invented
        // secret can never reach the verifier. Round 30 (P1): MISSING vs
        // INVALID are distinct provider codes.
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

        // Round 30 (P1): provider-style verification idempotency. The
        // claim is atomic; only the OWNING request verifies the token.
        // A same-key retry either returns the stored canonical response or
        // (crash window) reconstructs the original outcome via the core's
        // retained consumed-result machinery — ordinary replays WITHOUT a
        // matching key stay timeout-or-duplicate.
        $backendId = hash('sha256', $secret);
        $claim = IdempotencyClaim::Claimed;
        $claimOwner = null;
        $idempotent = false;
        if ($idempotencyKey !== null) {
            $idempotent = true;
            [$claim, $claimOwner] = $this->idempotencyStore->claim($backendId, $idempotencyKey, hash('sha256', $response), 300);
            if ($claim === IdempotencyClaim::Conflict) {
                return new JsonResponse(['success' => false, 'error-codes' => ['bad-request']], Response::HTTP_BAD_REQUEST);
            }
            if ($claim === IdempotencyClaim::CompleteSame) {
                $stored = $this->idempotencyStore->stored($backendId, $idempotencyKey);

                return new JsonResponse($stored !== null ? $this->canonicalizeResponse($stored) : ['success' => false, 'error-codes' => ['timeout-or-duplicate']]);
            }
        }

        try {
            $token = SolutionToken::decode($response);
        } catch (DecodeError) {
            // Round 31 (P2): a malformed token is a DETERMINISTIC failure —
            // the claiming request FINALIZES it so a same-key retry
            // reproduces the identical canonical response instead of
            // leaving the entry pending until TTL.
            $canonical = $this->canonicalizeResponse([
                'success' => false,
                'challenge_ts' => null,
                'hostname' => null,
                'error-codes' => ['invalid-input-response'],
            ]);
            if ($claimOwner !== null) {
                $this->idempotencyStore->finalize($backendId, $idempotencyKey, hash('sha256', $response), $claimOwner, $canonical);
            }

            return new JsonResponse($canonical);
        }

        // Round 31 (P2): PENDING_SAME — another request with the SAME key
        // + hash owns verification. This request WAITS on the store ONLY —
        // polling stored() for completion and, once the owner's lease has
        // expired, attempting an atomic takeover. It NEVER invokes the
        // verifier while the owner may still be running (a deliberately
        // slow Argon solve can legitimately take tens of seconds) — the
        // round-31 wait-then-verify order caused waiters to race the owner
        // for the token's consume and finalize failures. Verification
        // happens strictly AFTER this wait.
        if ($idempotent && $claim === IdempotencyClaim::PendingSame) {
            $stored = null;
            $waitDeadline = microtime(true) + self::IDEMPOTENCY_WAIT_SECS;
            while (true) {
                $stored = $this->idempotencyStore->stored($backendId, $idempotencyKey);
                if ($stored !== null || microtime(true) >= $waitDeadline) {
                    break;
                }
                // The lease gate is inside the store's Lua: before expiry
                // this attempt is an atomic no-op (StillPending).
                [$takeover, $takeoverOwner] = $this->idempotencyStore->takeover($backendId, $idempotencyKey, hash('sha256', $response), 300);
                if ($takeover === IdempotencyClaim::TookOver) {
                    // This request now OWNS the entry — it will verify below
                    // and finalize with the takeover owner token.
                    $claimOwner = $takeoverOwner;
                    break;
                }
                usleep(100_000);
            }
            if ($stored !== null) {
                return new JsonResponse($this->canonicalizeResponse($stored));
            }
        }

        // The SAME atomic verifier as the native path, WITH the expected
        // scope resolved from the secret (round 26): a weaker login token
        // presented to the financial secret is rejected (WrongScope) — the
        // sitekey-allowlist mapping is enforced end to end. `remoteip` is
        // only honored because the caller proved possession of a valid
        // secret above; it is REQUIRED whenever IP binding is enabled
        // (the default) — a bound challenge without it fails closed.
        $outcome = $this->verifier->verify(
            $response,
            $this->secretKey,
            $expectedScope,
            $remoteIp,
            null,            // region expectation is application policy
            false,           // telemetry is never authoritative here
        );

        // Round 26 (P1): the compatibility boundary distinguishes the FIRST
        // redemption from replays. The native deterministic-result retry
        // machinery stays inside the verifier, but a REPEATED Siteverify
        // redemption of the same nonce must NOT report success again — it
        // returns the provider vocabulary for a consumed token. The
        // Round-30 exception: an idempotent retry that has PROVEN the
        // same key+hash against a pending claim may interpret the stored
        // result as the original outcome (crash recovery) — it is the
        // SAME logical redemption, not a second one.
        if ($outcome->isOk() && $outcome->fromStoredResult) {
            // Round 30 (P1): a same-key + same-hash retry whose claim is
            // STILL pending reconstructs the ORIGINAL success from the
            // retained consumed state (crash recovery — the key+hash pair
            // was proven against the pending claim, so this is the SAME
            // logical redemption). Round 31 (P2): a TAKEOVER winner holds
            // the owner token, so it finalizes the reconstructed outcome —
            // the catastrophic deadline fall-through cannot and leaves the
            // entry to expire on TTL.
            if ($idempotent && $claim === IdempotencyClaim::PendingSame) {
                $canonical = $this->canonicalizeResponse($this->canonicalSuccess($outcome));
                if ($claimOwner !== null) {
                    $this->idempotencyStore->finalize($backendId, $idempotencyKey, hash('sha256', $response), $claimOwner, $canonical);
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
                $this->idempotencyStore->finalize($backendId, $idempotencyKey, hash('sha256', $response), $claimOwner, $canonical);
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
            $this->idempotencyStore->finalize($backendId, $idempotencyKey, hash('sha256', $response), $claimOwner, $canonical);
        }

        return new JsonResponse($canonical);
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
     * @return array<string, mixed>|null
     */
    private const MAX_BODY_BYTES = 16 * 1024;

    /**
     * Round 30 (item 16): invalid-secret diagnostics are gated by a SHARED
     * log gate (Redis INCR + EXPIRE) so the aggregation is deployment-wide
     * — the round-28 per-controller-instance counters were useless across
     * PHP-FPM workers (a fresh controller per request). Logging is
     * logarithmic (1, 2, 4, 8...): early visibility + bounded flood
     * amplification. Log-gate failure NEVER affects verification: on
     * Redis errors the detailed log is suppressed (requests are still
     * rejected).
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

    private function parseBody(Request $request): ?array
    {
        $contentType = strtolower(trim(explode(';', (string) $request->headers->get('Content-Type', ''), 2)[0]));
        if ($contentType === 'application/json') {
            try {
                $decoded = json_decode((string) $request->getContent(), true, 32, JSON_THROW_ON_ERROR);

                return \is_array($decoded) ? $decoded : null;
            } catch (\JsonException) {
                return null;
            }
        }

        return $request->request->all();
    }
}
