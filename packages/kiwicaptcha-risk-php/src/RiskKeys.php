<?php

declare(strict_types=1);

namespace KiwiCaptcha\Risk;

/**
 * hkdf-sha256 identity keys, derived exactly per the risk-v1 contract:
 *
 *   key = hash_hkdf('sha256', master, 32, info, 'kiwicaptcha-risk-v1')
 *
 * for info in {source, subnet, session, principal, event, target}. The
 * Rust side derives the same keys with `Hkdf::<Sha256>` using salt
 * `kiwicaptcha-risk-v1`, master, and expand(32).
 */
final class RiskKeys
{
    public const SALT = 'kiwicaptcha-risk-v1';
    public const INFO_SOURCE = 'source';
    public const INFO_SUBNET = 'subnet';
    public const INFO_SESSION = 'session';
    public const INFO_PRINCIPAL = 'principal';
    public const INFO_EVENT = 'event';
    public const INFO_TARGET = 'target';

    public function __construct(
        public readonly string $source,
        public readonly string $subnet,
        public readonly string $session,
        public readonly string $principal,
        public readonly string $event,
        public readonly string $target,
    ) {
        foreach (get_object_vars($this) as $value) {
            if (strlen($value) !== 32) {
                throw new \InvalidArgumentException('Risk identity keys must be 32 raw bytes');
            }
        }
    }

    /**
     * Derives the six keys from a master secret. The master must carry
     * at least 16 bytes (the core Config contract): a shorter or empty
     * secret deterministically derives predictable pseudonyms, so the
     * derivation boundary refuses it instead of accepting it silently.
     *
     * @throws \InvalidArgumentException when the master is shorter than
     *                                   16 bytes
     */
    public static function fromMaster(string $master): self
    {
        if (\strlen($master) < 16) {
            throw new \InvalidArgumentException(sprintf(
                'The risk master secret must be at least 16 bytes (got %d)',
                \strlen($master),
            ));
        }
        return new self(
            source: hash_hkdf('sha256', $master, 32, self::INFO_SOURCE, self::SALT),
            subnet: hash_hkdf('sha256', $master, 32, self::INFO_SUBNET, self::SALT),
            session: hash_hkdf('sha256', $master, 32, self::INFO_SESSION, self::SALT),
            principal: hash_hkdf('sha256', $master, 32, self::INFO_PRINCIPAL, self::SALT),
            event: hash_hkdf('sha256', $master, 32, self::INFO_EVENT, self::SALT),
            target: hash_hkdf('sha256', $master, 32, self::INFO_TARGET, self::SALT),
        );
    }
}
