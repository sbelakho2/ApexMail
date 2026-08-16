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
        private readonly ?StorageInterface $storage = null,
        private readonly ?LoggerInterface $logger = null,
    ) {
    }

    public function siteverify(Request $request): Response
    {
        if ($this->siteverifySecrets === []) {
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

        // Round 26: the presented secret authenticates the backend AND
        // resolves the EXPECTED SCOPE the verifier must enforce. Constant-
        // time comparisons; the detail goes to the log only. A secret not
        // in the server-owned map is rejected — an attacker-invented
        // secret can never reach the verifier.
        $expectedScope = null;
        if (!\is_string($secret)) {
            $this->logger?->warning('kiwicaptcha siteverify: missing secret');

            return new JsonResponse(['success' => false, 'error-codes' => ['invalid-input-secret']]);
        }
        foreach ($this->siteverifySecrets as $configuredSecret => $scope) {
            if (hash_equals($configuredSecret, $secret)) {
                $expectedScope = $scope;
                break;
            }
        }
        if ($expectedScope === null) {
            $this->logger?->warning('kiwicaptcha siteverify: invalid secret');

            return new JsonResponse(['success' => false, 'error-codes' => ['invalid-input-secret']]);
        }

        $token = SolutionToken::decode($response);
        if ($token instanceof DecodeError) {
            return new JsonResponse(['success' => false, 'error-codes' => ['invalid-input-response']]);
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
        // returns the provider vocabulary for a consumed token.
        if ($outcome->isOk() && $outcome->fromStoredResult) {
            return new JsonResponse([
                'success' => false,
                'challenge_ts' => null,
                'hostname' => null,
                'error-codes' => ['timeout-or-duplicate'],
            ]);
        }

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
