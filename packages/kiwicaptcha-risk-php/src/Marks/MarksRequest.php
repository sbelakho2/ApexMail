<?php

declare(strict_types=1);

namespace KiwiCaptcha\Risk\Marks;

/**
 * The request identity picture the engine hands a marks reader: the
 * scope, the source address and the session and principal pseudonyms
 * the engine derived. The reader's implementation adds the dimensions
 * only the deployment resolves (the agent name, the ASN bucket); the
 * engine resolves the login target itself beside the frozen observation
 * wire when a target resolver is wired.
 */
final class MarksRequest
{
    /**
     * @param string|null $session the session pseudonym (32 hex chars),
     *                             or null without a session.
     *
     * @param string|null $principal the principal pseudonym (32 hex
     *                             chars), or null when the request is
     *                             unauthenticated.
     *
     * @param string|null $target the request's resolved target
     *                            pseudonym, or null without a target.
     */
    public function __construct(
        public readonly int $scope,
        public readonly string $sourceIp,
        public readonly ?string $session,
        public readonly ?string $principal,
        public readonly ?string $target = null,
    ) {
    }
}
