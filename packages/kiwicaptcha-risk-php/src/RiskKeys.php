<?php

declare(strict_types=1);

namespace KiwiCaptcha\Risk;

/**
 * HKDF-SHA256 identity keys, derived exactly per the risk-v1 contract:
 *
 *   key = hash_hkdf('sha256', master, 32, info, 'kiwicaptcha-risk-v1')
 *
 * for info in {source, subnet, session, principal}. The Rust side derives
 * the same keys with Hkdf::<Sha256>::new(Some(b"kiwicaptcha-risk-v1"), master)
 * and expand(32).
 */
final class RiskKeys
{
    public const SALT = 'kiwicaptcha-risk-v1';
    public const INFO_SOURCE = 'source';
    public const INFO_SUBNET = 'subnet';
    public const INFO_SESSION = 'session';
    public const INFO_PRINCIPAL = 'principal';

    public function __construct(
        public readonly string $source,
        public readonly string $subnet,
        public readonly string $session,
        public readonly string $principal,
    ) {
        foreach (get_object_vars($this) as $value) {
            if (strlen($value) !== 32) {
                throw new \InvalidArgumentException('Risk identity keys must be 32 raw bytes');
            }
        }
    }

    public static function fromMaster(string $master): self
    {
        return new self(
            source: hash_hkdf('sha256', $master, 32, self::INFO_SOURCE, self::SALT),
            subnet: hash_hkdf('sha256', $master, 32, self::INFO_SUBNET, self::SALT),
            session: hash_hkdf('sha256', $master, 32, self::INFO_SESSION, self::SALT),
            principal: hash_hkdf('sha256', $master, 32, self::INFO_PRINCIPAL, self::SALT),
        );
    }
}
