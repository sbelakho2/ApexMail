<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Security\Agents;

use KiwiCaptcha\Risk\Outcomes\OutcomeHandle;

/**
 * One configured verified agent (risk.agents.<name>): the key id, the
 * rotation-capable Ed25519 public key set, the allowed scopes, the
 * per-minute and per-day quotas, the price tier and the contact.
 *
 * The name is the attribution identity: every outcome and mark of a
 * verified request addresses the agent through
 * {@see self::outcomeHandle()}, the agent dimension of the typed
 * outcomes plane. The name charset therefore excludes the bytes the
 * risk store's key-safety rule refuses (":" and "}"), so a configured
 * name can always become a mark key segment.
 */
final class AgentDefinition
{
    /**
     * The agent-name grammar: 1..64 characters of [A-Za-z0-9._-]. The
     * set is inside the risk store's key-safety rule for mark keys,
     * and the bound keeps the Redis quota keys short.
     */
    public const NAME_PATTERN = '/^[A-Za-z0-9._-]{1,64}$/D';

    /**
     * The key-id grammar: the shared identifier charset and ceiling
     * of the bundle (the same shape as scopes and request bindings),
     * minus the ":" the nonce-store key grammar must refuse.
     */
    public const KEY_ID_PATTERN = '/^[A-Za-z0-9._-]{1,128}$/D';

    /**
     * @param list<string> $publicKeys   the raw 32-byte Ed25519 public
     *                                   keys, in configured order; more
     *                                   than one entry is the rotation
     *                                   window (every key verifies)
     * @param list<string> $allowedScopes the scopes this agent may
     *                                   request challenges for
     */
    private function __construct(
        public readonly string $name,
        public readonly string $keyId,
        public readonly array $publicKeys,
        public readonly array $allowedScopes,
        public readonly int $perMinute,
        public readonly int $perDay,
        public readonly AgentPriceTier $priceTier,
        public readonly string $contact,
    ) {
    }

    /**
     * Builds the definition from the processed configuration array of
     * one risk.agents.<name> entry, decoding the base64 public keys.
     *
     * @param array<string,mixed> $config
     *
     * @throws \InvalidArgumentException when any shape is invalid (a
     *                                   literal misconfiguration fails
     *                                   at container build time here)
     */
    public static function fromConfig(string $name, array $config): self
    {
        if (preg_match(self::NAME_PATTERN, $name) !== 1) {
            throw new \InvalidArgumentException(sprintf(
                'risk.agents.<name> must be an agent name of 1-64 characters of [A-Za-z0-9._-] (got "%s")',
                $name,
            ));
        }
        $keyId = (string) ($config['key_id'] ?? '');
        if (preg_match(self::KEY_ID_PATTERN, $keyId) !== 1) {
            throw new \InvalidArgumentException(sprintf(
                'risk.agents.%s.key_id must be 1-128 characters of [A-Za-z0-9._-]',
                $name,
            ));
        }
        $rawKeys = $config['public_keys'] ?? [];
        if (!\is_array($rawKeys) || $rawKeys === []) {
            throw new \InvalidArgumentException(sprintf(
                'risk.agents.%s.public_keys must be a non-empty list of base64 Ed25519 public keys',
                $name,
            ));
        }
        $publicKeys = [];
        foreach (array_values($rawKeys) as $encoded) {
            $decoded = base64_decode((string) $encoded, true);
            if ($decoded === false || \strlen($decoded) !== SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES) {
                throw new \InvalidArgumentException(sprintf(
                    'risk.agents.%s.public_keys entries must be base64 of exactly %d raw Ed25519 public-key bytes',
                    $name,
                    SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES,
                ));
            }
            $publicKeys[] = $decoded;
        }
        $allowedScopes = [];
        foreach ((array) ($config['allowed_scopes'] ?? []) as $scope) {
            $allowedScopes[] = (string) $scope;
        }

        return new self(
            $name,
            $keyId,
            $publicKeys,
            $allowedScopes,
            (int) ($config['per_minute'] ?? 0),
            (int) ($config['per_day'] ?? 0),
            AgentPriceTier::from((string) ($config['price_tier'] ?? AgentPriceTier::Standard->value)),
            (string) ($config['contact'] ?? ''),
        );
    }

    /** Whether the scope is inside this agent's allowed set. */
    public function allowsScope(string $scope): bool
    {
        return \in_array($scope, $this->allowedScopes, true);
    }

    /** The attribution handle of this agent (the agent outcome dimension). */
    public function outcomeHandle(): OutcomeHandle
    {
        return OutcomeHandle::agent($this->name);
    }
}
