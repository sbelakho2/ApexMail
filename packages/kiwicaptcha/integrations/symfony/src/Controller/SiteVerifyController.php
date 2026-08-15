<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Controller;

use KiwiCaptcha\DecodeError;
use KiwiCaptcha\SolutionToken;
use KiwiCaptcha\StorageInterface;
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
    public function __construct(
        private readonly Verifier $verifier,
        private readonly string $secretKey,
        private readonly ?string $siteverifySecret,
        private readonly ?StorageInterface $storage = null,
        private readonly ?LoggerInterface $logger = null,
    ) {
    }

    public function siteverify(Request $request): Response
    {
        if ($this->siteverifySecret === null || $this->siteverifySecret === '') {
            return new JsonResponse(['success' => false, 'error-codes' => ['siteverify-not-configured']], Response::HTTP_NOT_FOUND);
        }

        $body = $this->parseBody($request);
        if ($body === null) {
            return new JsonResponse(['success' => false, 'error-codes' => ['bad-request']], Response::HTTP_BAD_REQUEST);
        }
        $response = $body['response'] ?? null;
        $secret = $body['secret'] ?? null;
        $remoteIp = \is_string($body['remoteip'] ?? null) ? $body['remoteip'] : null;

        if (!\is_string($response) || $response === '') {
            return new JsonResponse(['success' => false, 'error-codes' => ['missing-input-response']]);
        }
        if (!\is_string($secret) || !hash_equals($this->siteverifySecret, $secret)) {
            // Constant-time comparison; the detail goes to the log only.
            $this->logger?->warning('kiwicaptcha siteverify: invalid secret');

            return new JsonResponse(['success' => false, 'error-codes' => ['invalid-input-secret']]);
        }

        $token = SolutionToken::decode($response);
        if ($token instanceof DecodeError) {
            return new JsonResponse(['success' => false, 'error-codes' => ['invalid-input-response']]);
        }

        // The SAME atomic verifier as the native path. `remoteip` is only
        // honored because the caller proved possession of the compatibility
        // secret above; when absent, bound challenges still fail closed
        // (the verifier reports MissingClientIp) — mirroring the incumbent
        // providers, which also require the end-user IP for bound tokens.
        $outcome = $this->verifier->verify(
            $response,
            $this->secretKey,
            null,            // siteverify accepts any issued scope
            $remoteIp,       // end-user IP supplied by the trusted backend
            null,            // region expectation is application policy
            false,           // telemetry is never authoritative here
        );

        if ($outcome->isOk()) {
            // The consumed record is RETAINED until TTL (the consumed-state
            // design), so the deterministic outcome's record metadata is
            // available for the provider-shaped response.
            $issuedAt = null;
            $hostname = null;
            if ($this->storage !== null && $outcome->nonce() !== null) {
                $record = $this->storage->find($outcome->nonce());
                if ($record !== null) {
                    $issuedAt = $record->issuedAt;
                    $hostname = $record->hostname;
                }
            }

            return new JsonResponse([
                'success' => true,
                'challenge_ts' => $issuedAt !== null ? gmdate('Y-m-d\TH:i:s\Z', $issuedAt) : null,
                'hostname' => $hostname,
                'error-codes' => [],
            ]);
        }

        $error = $outcome->error();

        return new JsonResponse([
            'success' => false,
            'challenge_ts' => null,
            'hostname' => null,
            'error-codes' => [$this->mapError($error)],
        ]);
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
