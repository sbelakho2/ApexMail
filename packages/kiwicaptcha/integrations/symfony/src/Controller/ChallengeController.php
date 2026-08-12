<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Controller;

use BelConsulting\KiwiCaptchaBundle\Risk\ContinuityCookie;
use BelConsulting\KiwiCaptchaBundle\Risk\RiskGateway;
use BelConsulting\KiwiCaptchaBundle\Risk\UnknownScopeException;
use BelConsulting\KiwiCaptchaBundle\Security\IssuanceCounter;
use BelConsulting\KiwiCaptchaBundle\Security\IssuanceRateLimiter;
use KiwiCaptcha\Issuer;
use KiwiCaptcha\Risk\RiskAction;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * Issues a new captcha challenge for the widget.
 *
 * The route is NOT declared via a #[Route] attribute on this class — bundle
 * controllers are never scanned for attribute routes. It is registered by
 * {@see \BelConsulting\KiwiCaptchaBundle\Routing\KiwiCaptchaRouteLoader} with
 * the bundle's configured `route_prefix` (auto-registered by the extension,
 * or imported from the bundle's routes resource).
 *
 * The widget fetches this endpoint, solves the proof-of-work locally in the
 * browser, and submits the token in the hidden input. Challenges are issued
 * and stored locally — no external service is involved.
 *
 * Every response (success, error, 422, 429, 403) is a private JSON document:
 * Cache-Control no-store, Pragma no-cache, Referrer-Policy no-referrer and
 * X-Content-Type-Options nosniff — challenge bytes and client identity must
 * never be cached, mirrored, or sniffed (see {@see self::privateJson()}).
 *
 * Hardening order: same-origin check first (cheap, no state written), scope
 * read, then issuance rate limiting (per-client and deployment-global; a 429
 * here records RateLimitHit feedback), then — when the adaptive risk engine
 * is enabled — the PRE-ISSUE risk assessment (a Deny decision returns 429
 * RISK_DENIED before any challenge is minted, an escalated action raises the
 * difficulty of the issued challenge, an unknown scope in 'reject' mode
 * returns 429 RISK_DENIED without issuing), then issuance. Every 429 path
 * records RateLimitHit against the risk engine BEFORE responding; every
 * minted challenge increments the atomic issuance-rate counter used by the
 * resource-pressure provider.
 */
final class ChallengeController
{
    public function __construct(
        private readonly Issuer $issuer,
        private readonly ?IssuanceRateLimiter $rateLimiter = null,
        private readonly bool $sameOriginOnly = true,
        private readonly ?RiskGateway $risk = null,
        private readonly ?ContinuityCookie $continuityCookie = null,
        private readonly ?IssuanceCounter $issuanceCounter = null,
    ) {
    }

    public function challenge(Request $request): JsonResponse
    {
        if ($this->sameOriginOnly && !$this->isSameOrigin($request)) {
            return $this->privateJson(
                ['error' => ['code' => 'CROSS_ORIGIN_DENIED', 'message' => 'Cross-origin challenge requests are not allowed.']],
                Response::HTTP_FORBIDDEN,
            );
        }

        $clientIp = (string) ($request->getClientIp() ?? '');
        $payload = json_decode((string) $request->getContent(), true);
        $scope = \is_array($payload) && isset($payload['scope']) ? (string) $payload['scope'] : 'default';

        // The continuity session is read up front (pure, no side effects) so
        // the rate-limit-hit feedback can attribute the refusal to the same
        // session signal the risk engine would key on. Minting stays in the
        // risk block — a rate-limited request never receives a cookie.
        $riskSession = $this->continuityCookie?->read($request);
        $mintedCookie = false;

        if ($this->rateLimiter !== null) {
            $rate = $this->rateLimiter->check($clientIp);
            if ($rate !== 1) {
                $this->risk?->rateLimitHit($scope, $clientIp, $riskSession);

                $code = $rate === -1 ? 'GLOBAL_RATE_LIMITED' : 'RATE_LIMITED';
                $message = $rate === -1
                    ? 'The global captcha issuance limit has been reached. Try again later.'
                    : 'Too many captcha challenges requested from this address. Try again later.';

                return $this->privateJson(
                    ['error' => ['code' => $code, 'message' => $message]],
                    Response::HTTP_TOO_MANY_REQUESTS,
                );
            }
        }

        // Adaptive risk: read (or mint) the continuity session, assess the
        // source BEFORE any challenge is written, and act on the decision.
        // An invalid client IP (no risk signal available) or a store outage
        // (the engine degrades internally) never blocks issuance — the
        // default profile is issued and the baseline Kiwi verification still
        // applies. An unknown scope depends on unknown_scope.mode:
        // 'baseline' (default) issues the default profile, 'reject' returns
        // the risk-denied 429 without issuing.
        $profile = null;
        $riskAssessed = false;
        if ($this->risk !== null) {
            if ($riskSession === null) {
                $riskSession = $this->continuityCookie?->mint();
                $mintedCookie = $riskSession !== null;
            }

            try {
                $decision = $this->risk->preIssue($scope, $clientIp, $riskSession);
                $riskAssessed = true;
            } catch (UnknownScopeException) {
                if ($this->risk->unknownScopeMode() === 'reject') {
                    // TRUE rejection: no challenge, same response as a Deny
                    // decision (429 RISK_DENIED), no baseline fallback.
                    $this->risk->rateLimitHit($scope, $clientIp, $riskSession);

                    return $this->privateJson(
                        ['error' => ['code' => 'RISK_DENIED', 'message' => 'Challenge issuance denied by the adaptive risk engine. Try again later.']],
                        Response::HTTP_TOO_MANY_REQUESTS,
                        $request,
                        $riskSession,
                        $mintedCookie,
                    );
                }
                // 'baseline' mode: the adaptive engine declines — issue the
                // default profile.
                $decision = null;
            } catch (\InvalidArgumentException) {
                $decision = null;
            }

            if ($decision !== null) {
                if ($decision->action === RiskAction::StepUp) {
                    // Step-up is application-defined (verified email link,
                    // passkey, existing session, TOTP...): KiwiCaptcha only
                    // says "PoW alone is insufficient for this request".
                    return $this->privateJson(
                        ['error' => ['code' => 'STEP_UP_REQUIRED', 'message' => 'Additional verification is required for this request.']],
                        Response::HTTP_FORBIDDEN,
                        $request,
                        $riskSession,
                        $mintedCookie,
                    );
                }

                if ($decision->action === RiskAction::Deny) {
                    $this->risk->rateLimitHit($scope, $clientIp, $riskSession);

                    $body = ['error' => ['code' => 'RISK_DENIED', 'message' => 'Challenge issuance denied by the adaptive risk engine. Try again later.']];
                    if ($decision->retryAfterMs !== null) {
                        $body['error']['retry_after_ms'] = $decision->retryAfterMs;
                    }

                    return $this->privateJson($body, Response::HTTP_TOO_MANY_REQUESTS, $request, $riskSession, $mintedCookie);
                }
                $profile = $this->risk->decisionProfile($decision);
            }
        }

        try {
            $challenge = $profile !== null
                ? $this->issuer->issueWithProfile($scope, $clientIp, $profile)
                : $this->issuer->issue($scope, $clientIp);
        } catch (\InvalidArgumentException $e) {
            return $this->privateJson(
                ['error' => ['code' => 'INVALID_SCOPE', 'message' => $e->getMessage()]],
                Response::HTTP_UNPROCESSABLE_ENTITY,
                $request,
                $riskSession,
                $mintedCookie,
            );
        }

        // A challenge was actually minted: feed the atomic issuance-rate
        // signal (resource-pressure headroom) and the risk issue-debt signal.
        $this->issuanceCounter?->record();
        if ($this->risk !== null && $riskAssessed && $decision !== null) {
            $this->risk->challengeIssued($scope, $clientIp, $riskSession, $decision->decisionId);
        }

        return $this->privateJson($challenge->toArray(), Response::HTTP_OK, $request, $riskSession, $mintedCookie);
    }

    /**
     * Same-origin check for the challenge endpoint.
     *
     * Requests WITHOUT an Origin header (same-origin navigation, curl,
     * non-browser clients) are allowed — a browser cross-site POST always
     * carries one. When present, the Origin must match the request's own
     * scheme://host[:port] (constant-time compare; trailing slashes
     * normalized). Cross-origin requests are rejected BEFORE any state is
     * written, so they consume no rate-limit budget.
     */
    private function isSameOrigin(Request $request): bool
    {
        $origin = $request->headers->get('Origin');
        if ($origin === null || $origin === '') {
            return true;
        }
        $expected = rtrim($request->getScheme().'://'.$request->getHttpHost(), '/');

        return hash_equals($expected, rtrim($origin, '/'));
    }

    /**
     * All challenge responses share the private-document headers:
     *   Cache-Control: no-store, private, max-age=0   (never cache, never mirror)
     *   Pragma: no-cache                              (legacy proxies)
     *   Referrer-Policy: no-referrer                  (no referrer leakage from
     *                                                 an embedded widget context)
     *   X-Content-Type-Options: nosniff               (JSON must never be
     *                                                 re-sniffed as HTML)
     *
     * When a NEW risk continuity session was minted for this request, the
     * cookie is attached here — on every response path (success, deny, 422),
     * so the session the assessment keyed on is what the client carries.
     *
     * @param array<string, mixed> $data
     */
    private function privateJson(array $data, int $status = Response::HTTP_OK, ?Request $request = null, ?string $riskSession = null, bool $mintedCookie = false): JsonResponse
    {
        $response = new JsonResponse($data, $status);
        $response->headers->set('Cache-Control', 'no-store, private, max-age=0');
        $response->headers->set('Pragma', 'no-cache');
        $response->headers->set('Referrer-Policy', 'no-referrer');
        $response->headers->set('X-Content-Type-Options', 'nosniff');

        if ($mintedCookie && $request !== null && $riskSession !== null && $this->continuityCookie !== null) {
            $response->headers->setCookie($this->continuityCookie->cookie($request, $riskSession));
        }

        return $response;
    }
}
