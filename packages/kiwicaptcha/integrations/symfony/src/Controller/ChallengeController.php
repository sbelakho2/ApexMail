<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Controller;

use KiwiCaptcha\Issuer;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;

/**
 * Issues a new captcha challenge for the widget.
 *
 * The widget fetches this endpoint (configurable via the bundle's route
 * prefix, or per-widget via data-kiwi-endpoint), solves the proof-of-work
 * locally in the browser, and submits the token in the hidden input.
 *
 * Challenges are issued and stored locally — no external service is involved.
 */
final class ChallengeController
{
    public function __construct(private readonly Issuer $issuer)
    {
    }

    #[Route(path: '/kiwi-captcha/challenge', name: 'kiwicaptcha_challenge', methods: ['POST'])]
    public function challenge(Request $request): JsonResponse
    {
        $payload = json_decode((string) $request->getContent(), true);
        $scope = \is_array($payload) && isset($payload['scope']) ? (string) $payload['scope'] : 'default';

        $clientIp = (string) ($request->getClientIp() ?? '');

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
