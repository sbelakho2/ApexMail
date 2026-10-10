<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Security\Agents;

/**
 * The configured agents of the deployment, addressable by name and
 * by key id. Built from the processed risk.agents configuration
 * through {@see self::fromConfig()}. The container wiring builds it
 * through that factory so env-resolved key material is validated
 * when the service is constructed, while literal misconfigurations
 * are additionally refused eagerly at container build time by the
 * extension.
 *
 * The key-id index is the verification entry point (the RFC 9421
 * keyid parameter addresses one agent); the config tree already
 * refuses two agents sharing a key id, so the index is injective by
 * the time it is built.
 */
final class AgentRegistry
{
    /** @var array<string, AgentDefinition> */
    private array $byKeyId;

    /** @param array<string, AgentDefinition> $agents keyed by name */
    private function __construct(
        private readonly array $agents,
    ) {
        $byKeyId = [];
        foreach ($agents as $agent) {
            if (isset($byKeyId[$agent->keyId])) {
                throw new \InvalidArgumentException(sprintf(
                    'risk.agents: two agents must never share one key_id ("%s" is claimed by "%s" and "%s")',
                    $agent->keyId,
                    $byKeyId[$agent->keyId]->name,
                    $agent->name,
                ));
            }
            $byKeyId[$agent->keyId] = $agent;
        }
        $this->byKeyId = $byKeyId;
    }

    /**
     * @param array<string, array<string,mixed>> $config the processed
     *                                                   risk.agents map
     *                                                   (name => entry)
     */
    public static function fromConfig(array $config): self
    {
        $agents = [];
        foreach ($config as $name => $entry) {
            $agents[(string) $name] = AgentDefinition::fromConfig((string) $name, \is_array($entry) ? $entry : []);
        }

        return new self($agents);
    }

    public function agentByKeyId(string $keyId): ?AgentDefinition
    {
        return $this->byKeyId[$keyId] ?? null;
    }

    /** @return array<string, AgentDefinition> the agents keyed by key id */
    public function byKeyId(): array
    {
        return $this->byKeyId;
    }

    /** @return array<string, AgentDefinition> the agents keyed by name */
    public function byName(): array
    {
        return $this->agents;
    }
}
