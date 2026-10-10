<?php

declare(strict_types=1);

namespace KiwiCaptcha\Risk\Pricing;

/**
 * The request identity picture the engine hands a price-context source:
 * the scope, the source address and the session and principal pseudonyms
 * the engine derived (the same picture the marks reader receives).
 */
final class PriceRequest
{
    public function __construct(
        public readonly int $scope,
        public readonly string $sourceIp,
        /** The session pseudonym (32 hex chars), null without a session. */
        public readonly ?string $session,
        /** The principal pseudonym (32 hex chars), null when the request is unauthenticated. */
        public readonly ?string $principal,
    ) {
    }
}
