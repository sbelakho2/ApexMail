<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests\Fixtures;

use KiwiCaptcha\Risk\Storage\PrincipalNetworkTagStoreInterface;

/**
 * In-memory principal network tag store (test fake — never wired into
 * the production container). The established-network record the
 * step-up session restore writes and the engine's novel-network gate
 * reads. SET NX semantics: the first record for a (principal, tag)
 * pair wins, later writes never move it.
 */
final class InMemoryPrincipalNetworkTagStore implements PrincipalNetworkTagStoreInterface
{
    /** @var array<string, array<string, true>> principal => tag => true */
    private array $tags = [];
    /** @var array<string, array<string, true>> principal => trusted tag => true */
    private array $trusted = [];

    /** @var list<array{0: string, 1: string}> every write, for assertions */
    public array $writes = [];

    public function principalNetworkSeen(string $principalId, string $network): ?bool
    {
        return isset($this->tags[$principalId][$network]);
    }

    public function recordPrincipalNetworkTag(string $principalId, string $network, bool $trusted = false): bool
    {
        $this->writes[] = [$principalId, $network];
        if (isset($this->tags[$principalId][$network])) {
            return false;
        }
        $this->tags[$principalId][$network] = true;
        if ($trusted) {
            $this->trusted[$principalId][$network] = true;
        }

        return true;
    }

    public function principalHasTrustedNetwork(string $principalId): ?bool
    {
        return isset($this->tags[$principalId]) && $this->tags[$principalId] !== [];
    }

    public function tagIsTrusted(string $principalId, string $network): ?bool
    {
        return isset($this->trusted[$principalId][$network]);
    }

    public function forgetDevices(string $principalId): void
    {
        foreach (array_keys($this->tags[$principalId] ?? []) as $tag) {
            if (str_starts_with($tag, 'session:') || str_starts_with($tag, 'device:')) {
                unset($this->tags[$principalId][$tag], $this->trusted[$principalId][$tag]);
            }
        }
    }
}
