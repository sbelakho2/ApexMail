<?php

declare(strict_types=1);

namespace KiwiCaptcha\Symfony\Controller;

use KiwiCaptcha\Issuer;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Attribute\AsController;
use Symfony\Component\Routing\Attribute\Route;

#[AsController]
final class ChallengeController
{
    public function __construct(private readonly Issuer $issuer)
    {
    }

    /**
     * Issues a new captcha challenge for the widget.
     *
     * The widget fetches this endpoint (configurable via data-kiwi-endpoint),
     * solves the proof-of-work, and submits the token in the hidden input.
     */
    #[Route(path: '/kiwi-captcha/challenge', name: 'kiwicaptcha_challenge', methods: ['POST'])]
    public function challenge(Request $request): JsonResponse
    {
        $payload = json_decode((string) $request->getContent(), true);
        $scope = \is_array($payload) && isset($payload['scope']) ? (string) $payload['scope'] : 'default';

        $clientIp = (string) $request->getClientIp();

        try {
            $challenge = $this->issuer->issue($scope, $clientIp);
        } catch (\InvalidArgumentException $e) {
            return new JsonResponse(['error' => ['code' => 'INVALID_SCOPE', 'message' => $e->getMessage()]], Response::HTTP_UNPROCESSABLE_ENTITY);
        }

        return new JsonResponse($challenge->toArray(), Response::HTTP_OK);
    }
}
