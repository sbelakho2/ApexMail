<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests;

use KiwiCaptcha\Risk\RiskIdentityFactory;
use KiwiCaptcha\Risk\RiskKeys;
use PHPUnit\Framework\TestCase;

/**
 * Risk-pseudonym compartment fuzzing: the HMAC-derived identities that
 * anchor the adaptive-risk memory must never collide across tenants,
 * identity dimensions or epochs.
 *
 * Each tenant derives its identity keys from its own master secret
 * (keyed with the kiwicaptcha-risk-v1 salt), and the factory HMACs
 * the context name, the epoch and the material into a 128-bit
 * pseudonym.
 *
 * The properties under test: pseudonyms across tenants are pairwise
 * distinct for identical material, and the source, subnet, session
 * and principal contexts stay pairwise distinct dimensions for
 * identical material. Same-tenant derivations are deterministic, and
 * the epoch boundary rotates the source and subnet pseudonyms.
 *
 * Deterministic: one fixed seed, bounded corpus.
 */
final class TenantIsolationRiskPseudonymFuzzTest extends TestCase
{
    private const SEED = 0x515B;

    private const WIDE_ALPHABET = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=[]{}|;:,.<>?/~`';

    /** @return list<string> fuzzed master secrets across the accepted shapes */
    private function tenantSecrets(): array
    {
        mt_srand(self::SEED);
        $secrets = [];
        foreach ([16, 32, 64] as $length) {
            $out = '';
            for ($i = 0; $i < $length; $i++) {
                $out .= self::WIDE_ALPHABET[mt_rand(0, \strlen(self::WIDE_ALPHABET) - 1)];
            }
            $secrets[] = $out;
        }
        $secrets[] = str_repeat('0', 32);
        $secrets[] = str_repeat('f', 32);
        $secrets[] = '租户主密钥0123456789ab';
        $secrets[] = "tenant-a\x00master\x001234567890";
        $secrets[] = 'tenant-a|master|0123456789';

        return $secrets;
    }

    /**
     * The bounded material corpus: IPs in distinct /24 and /56 blocks
     * (so subnet pseudonyms stay distinct), session cookie values,
     * principal ids, unicode and delimiter-bearing values.
     *
     * @return list<string>
     */
    private function materialCorpus(): array
    {
        mt_srand(self::SEED + 1);
        $materials = [];
        for ($i = 0; $i < 32; $i++) {
            $materials[] = sprintf('203.0.%d.%d', $i, mt_rand(1, 254));
        }
        for ($i = 0; $i < 8; $i++) {
            $materials[] = sprintf('2001:db8:%x::%x', $i, mt_rand(1, 65535));
        }
        $materials[] = 'sess-0123456789abcdef';
        $materials[] = 'sess-0123456789abcdefg';
        $materials[] = 'user-42';
        $materials[] = 'user_42';
        $materials[] = '会话cookie值0123456789';
        $materials[] = "material\x00with\x00nulls";
        $materials[] = 'material|with|pipes';
        $materials[] = '';

        return $materials;
    }

    public function testPseudonymsAcrossTenantsAndContextsArePairwiseDistinct(): void
    {
        $tenants = $this->tenantSecrets();
        $materials = $this->materialCorpus();
        $epochs = [0, 1, 899, 900, 123456];

        $collected = [];
        foreach ($tenants as $tenant) {
            $keys = RiskKeys::fromMaster($tenant);
            $factory = new RiskIdentityFactory($keys);
            foreach ($materials as $material) {
                // The source and subnet derivations need a canonical IP;
                // the session and principal derivations accept any raw
                // material, so every corpus entry drives those two.
                try {
                    $isIp = inet_pton($material) !== false;
                } catch (\ValueError) {
                    $isIp = false;
                }
                foreach ($epochs as $epoch) {
                    if ($isIp) {
                        $collected[] = $factory->pseudonym($keys->source, 'src', $epoch, $factory->canonicalIp($material));
                        $collected[] = $factory->pseudonym($keys->subnet, 'net', $epoch, $factory->maskIp($material));
                    }
                    $collected[] = $factory->pseudonym($keys->session, 'sess', $epoch, $material);
                    $collected[] = $factory->pseudonym($keys->principal, 'prin', $epoch, $material);
                }
            }
        }

        self::assertSame(
            \count($collected),
            \count(array_unique($collected)),
            'no two pseudonyms across tenants, contexts, epochs or materials may collide',
        );
        self::assertGreaterThanOrEqual(4000, \count($collected), 'the bounded corpus must stay broad');
    }

    public function testSameTenantSameContextSameMaterialIsDeterministic(): void
    {
        mt_srand(self::SEED + 2);
        $factory = new RiskIdentityFactory(RiskKeys::fromMaster(str_repeat('m', 32)));

        foreach ($this->materialCorpus() as $material) {
            self::assertSame(
                $factory->pseudonym('k', 'src', 7, $material),
                $factory->pseudonym('k', 'src', 7, $material),
                'identical inputs must derive the identical pseudonym',
            );
        }
    }

    public function testEpochRotationChangesSourceAndSubnetPseudonyms(): void
    {
        mt_srand(self::SEED + 3);
        $factory = new RiskIdentityFactory(RiskKeys::fromMaster(str_repeat('e', 32)));

        foreach (['203.0.113.27', '2001:db8::1'] as $ip) {
            self::assertNotSame(
                $factory->sourceId($ip, 899),
                $factory->sourceId($ip, 900),
                'the epoch boundary must rotate the source pseudonym',
            );
            self::assertNotSame(
                $factory->subnetId($ip, 899),
                $factory->subnetId($ip, 900),
                'the epoch boundary must rotate the subnet pseudonym',
            );
            self::assertSame(
                $factory->sourceId($ip, 899),
                $factory->sourceId($ip, 0),
                'pseudonyms within one epoch stay stable',
            );
        }
    }

    public function testContextsAreSeparateIdentityDimensions(): void
    {
        mt_srand(self::SEED + 4);
        $factory = new RiskIdentityFactory(RiskKeys::fromMaster(str_repeat('c', 32)));

        foreach ($this->materialCorpus() as $material) {
            $ids = [
                $factory->pseudonym('k', 'src', 0, $material),
                $factory->pseudonym('k', 'net', 0, $material),
                $factory->pseudonym('k', 'sess', 0, $material),
                $factory->pseudonym('k', 'prin', 0, $material),
            ];
            self::assertSame(
                \count($ids),
                \count(array_unique($ids)),
                'the four identity dimensions must stay distinct for identical material',
            );
        }
    }
}
