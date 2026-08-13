<?php

declare(strict_types=1);

namespace KiwiCaptcha\Tests;

use KiwiCaptcha\DerivedKeys;
use KiwiCaptcha\Tests\Fixtures\Vectors;
use PHPUnit\Framework\TestCase;

/**
 * HKDF purpose-key separation (audit #21).
 *
 * Byte-exact lock-in against the Rust crate's reference vectors
 * (packages/kiwicaptcha/src/keys.rs): the SAME master derives the SAME
 * purpose keys in both languages — any deviation breaks the cross-language
 * verify/issue interop.
 */
final class DerivedKeysTest extends TestCase
{
    /** Reference vectors locked by the Rust crate (hex). */
    private const K_CHALLENGE_HEX = '1d5be54d8682c4a6951c62306dd2f3b910366fddd48c45e5a4cc57222565c7bb';
    private const K_IP_BIND_HEX = '48018b185abd85485fe9a6b61820b6da00043ef0ac38d0930abd3f55fbe0384d';
    private const K_RESULT_HEX = '097f7a8e5189ac814299617c976c89a84301e2425bdf2761eb104ede8b8870eb';
    private const TENANT_T1_ROOT_HEX = 'd60ccd304be02092056c28dd5e25673063e3bb37018feec239166d5fd501b917';

    /**
     * hash_hkdf returned lowercase hex before PHP 8.4 and raw bytes since;
     * normalize so the reference construction is version-independent.
     */
    private static function hkdf(string $ikm, string $info, string $salt): string
    {
        $key = hash_hkdf('sha256', $ikm, 32, $info, $salt);

        return \strlen($key) === 64 ? (string) hex2bin($key) : $key;
    }

    public function testPurposeKeysMatchTheRustReferenceVectors(): void
    {
        $keys = DerivedKeys::fromMaster(Vectors::SECRET);

        self::assertSame(self::K_CHALLENGE_HEX, bin2hex($keys->challengeKey()));
        self::assertSame(self::K_IP_BIND_HEX, bin2hex($keys->ipBindKey()));
        self::assertSame(self::K_RESULT_HEX, bin2hex($keys->resultKey()));
    }

    public function testPurposeKeysAre32RawBytes(): void
    {
        $keys = DerivedKeys::fromMaster(Vectors::SECRET);

        foreach ([$keys->challengeKey(), $keys->ipBindKey(), $keys->resultKey()] as $key) {
            self::assertSame(32, \strlen($key));
        }
    }

    public function testPurposeKeysDifferFromEachOtherAndFromTheMaster(): void
    {
        $keys = DerivedKeys::fromMaster(Vectors::SECRET);

        self::assertNotSame($keys->challengeKey(), $keys->ipBindKey());
        self::assertNotSame($keys->challengeKey(), $keys->resultKey());
        self::assertNotSame($keys->ipBindKey(), $keys->resultKey());
        // Purpose keys must never equal the raw master secret (the whole
        // point of the separation).
        self::assertNotSame(Vectors::SECRET, $keys->challengeKey());
        self::assertNotSame(Vectors::SECRET, $keys->ipBindKey());
        self::assertNotSame(Vectors::SECRET, $keys->resultKey());
    }

    public function testTenantRootMatchesTheRustReferenceVector(): void
    {
        // The tenant root itself is not exposed; re-derive it with the
        // documented construction (keys.rs) and lock it to the Rust vector.
        $root = self::hkdf(
            Vectors::SECRET,
            DerivedKeys::INFO_TENANT_ROOT_PREFIX.'t1',
            DerivedKeys::HKDF_DEPLOY_SALT,
        );
        self::assertSame(self::TENANT_T1_ROOT_HEX, bin2hex($root));

        // The t1 purpose keys are derived UNDER the tenant root (empty-salt
        // re-extract, exactly like the Rust from_master(Some("t1")) path).
        $t1 = DerivedKeys::fromMaster(Vectors::SECRET, 't1');
        self::assertSame(
            self::hkdf($root, DerivedKeys::INFO_CHALLENGE_SIGN, ''),
            $t1->challengeKey(),
        );
        self::assertSame(
            self::hkdf($root, DerivedKeys::INFO_IP_BIND, ''),
            $t1->ipBindKey(),
        );
        self::assertSame(
            self::hkdf($root, DerivedKeys::INFO_RESULT_TOKEN, ''),
            $t1->resultKey(),
        );
    }

    public function testTenantKeysDifferAndDifferFromGlobalKeys(): void
    {
        $global = DerivedKeys::fromMaster(Vectors::SECRET);
        $t1 = DerivedKeys::fromMaster(Vectors::SECRET, 't1');
        $t2 = DerivedKeys::fromMaster(Vectors::SECRET, 't2');

        self::assertNotSame($t1->challengeKey(), $t2->challengeKey());
        self::assertNotSame($t1->ipBindKey(), $t2->ipBindKey());
        self::assertNotSame($t1->resultKey(), $t2->resultKey());
        self::assertNotSame($t1->challengeKey(), $global->challengeKey());
        self::assertNotSame($t1->ipBindKey(), $global->ipBindKey());
        self::assertNotSame($t1->resultKey(), $global->resultKey());
    }

    public function testDerivationIsDeterministic(): void
    {
        $a = DerivedKeys::fromMaster(Vectors::SECRET);
        $b = DerivedKeys::fromMaster(Vectors::SECRET);

        self::assertSame($a->challengeKey(), $b->challengeKey());
        self::assertSame($a->ipBindKey(), $b->ipBindKey());
        self::assertSame($a->resultKey(), $b->resultKey());

        $c = DerivedKeys::fromMaster(str_repeat('a', 32));
        self::assertNotSame($a->challengeKey(), $c->challengeKey(), 'a different master must derive different keys');
    }

    public function testTenantIdBindingIsExact(): void
    {
        // "kiwi/v2/tenant/" + tenant_id verbatim: a prefixed id must not
        // collide with the exact id.
        $exact = DerivedKeys::fromMaster(Vectors::SECRET, 'acme');
        $prefixed = DerivedKeys::fromMaster(Vectors::SECRET, 'acme-prod');

        self::assertNotSame($exact->challengeKey(), $prefixed->challengeKey());
        self::assertSame($exact->challengeKey(), DerivedKeys::fromMaster(Vectors::SECRET, 'acme')->challengeKey());
    }
}
