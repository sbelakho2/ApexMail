<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests\Fixtures;

use KiwiCaptcha\Risk\Storage\PrincipalNetworkTagStoreInterface;

/**
 * In-memory principal network tag store: the established-network record
 * the step-up session restore writes and the engine's novel-network gate
 * reads. SET NX semantics: the first record for a (principal, network)
 * pair wins, later writes never move it.
 */
final class InMemoryPrincipalNetworkTagStore implements PrincipalNetworkTagStoreInterface
{
    /** @var array<string, array<string, true>> principal => network tag => true */
    private array $tags = [];

    /** @var list<array{0: string, 1: string}> every write, for assertions */
    public array $writes = [];

    public function principalNetworkSeen(string $principalId, string $network): ?bool
    {
        return isset($this->tags[$principalId][$network]);
    }

    public function recordPrincipalNetworkTag(string $principalId, string $network): bool
    {
        $this->writes[] = [$principalId, $network];
        if (isset($this->tags[$principalId][$network])) {
            return false;
        }
        $this->tags[$principalId][$network] = true;

        return true;
    }

    public function principalHasTrustedNetwork(string $principalId): ?bool
    {
        return isset($this->tags[$principalId]) && $this->tags[$principalId] !== [];
    }
}
