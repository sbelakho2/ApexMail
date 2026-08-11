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
 */
final class ChallengeController
{
    public function __construct(
        private readonly Issuer $issuer,
        private readonly ?IssuanceRateLimiter $rateLimiter = null,
    ) {
    }

    public function challenge(Request $request): JsonResponse
    {
        $clientIp = (string) ($request->getClientIp() ?? '');

        if ($this->rateLimiter !== null && !$this->rateLimiter->allow($clientIp)) {
            return new JsonResponse(
                ['error' => ['code' => 'RATE_LIMITED', 'message' => 'Too many captcha challenges requested from this address. Try again later.']],
                Response::HTTP_TOO_MANY_REQUESTS,
            );
        }

        $payload = json_decode((string) $request->getContent(), true);
        $scope = \is_array($payload) && isset($payload['scope']) ? (string) $payload['scope'] : 'default';

        try {
            $challenge = $this->issuer->issue($scope, $clientIp);
        } catch (\InvalidArgumentException $e) {
            return new JsonResponse(
                ['error' => ['code' => 'INVALID_SCOPE', 'message' => $e->getMessage()]],
                Response::HTTP_UNPROCESSABLE_ENTITY,
            );
        }

        return new JsonResponse($challenge->toArray(), Response::HTTP_OK);
    }
}
