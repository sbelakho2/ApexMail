<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Controller;

use BelConsulting\KiwiCaptchaBundle\Security\IssuanceRateLimiter;
use KiwiCaptcha\Issuer;
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
 * Hardening order: same-origin check first (cheap, no state written), then
 * issuance rate limiting (per-client and deployment-global), then scope
 * validation.
 */
final class ChallengeController
{
    public function __construct(
        private readonly Issuer $issuer,
        private readonly ?IssuanceRateLimiter $rateLimiter = null,
        private readonly bool $sameOriginOnly = true,
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
        if ($this->rateLimiter !== null) {
            $rate = $this->rateLimiter->check($clientIp);
            if ($rate !== 1) {
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

        $payload = json_decode((string) $request->getContent(), true);
        $scope = \is_array($payload) && isset($payload['scope']) ? (string) $payload['scope'] : 'default';

        try {
            $challenge = $this->issuer->issue($scope, $clientIp);
        } catch (\InvalidArgumentException $e) {
            return $this->privateJson(
                ['error' => ['code' => 'INVALID_SCOPE', 'message' => $e->getMessage()]],
                Response::HTTP_UNPROCESSABLE_ENTITY,
            );
        }

        return $this->privateJson($challenge->toArray(), Response::HTTP_OK);
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
     * @param array<string, mixed> $data
     */
    private function privateJson(array $data, int $status = Response::HTTP_OK): JsonResponse
    {
        $response = new JsonResponse($data, $status);
        $response->headers->set('Cache-Control', 'no-store, private, max-age=0');
        $response->headers->set('Pragma', 'no-cache');
        $response->headers->set('Referrer-Policy', 'no-referrer');
        $response->headers->set('X-Content-Type-Options', 'nosniff');

        return $response;
    }
}
