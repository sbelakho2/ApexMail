<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Risk;

use Symfony\Component\HttpFoundation\Request;

/**
 * Resolves the raw principal (e.g. authenticated user id) of the current
 * request for the risk engine's principal-reputation signal.
 *
 * The raw principal is used only in process memory: the engine's
 * RiskIdentityFactory HMAC-pseudonymizes it before anything is stored in
 * Redis, so the raw value never reaches storage or logs. Returning null
 * (e.g. an anonymous request) simply disables the principal signal for
 * that request.
 *
 * Wire an implementation by registering a service for this interface: the
 * bundle's DI automatically injects it into the RiskGateway when present.
 */
interface PrincipalResolverInterface
{
    /**
     * @return string|null the raw principal (e.g. user id) of the request,
     *                     or null when the request carries no principal
     */
    public function resolve(Request $request, string $scope): ?string;
}
