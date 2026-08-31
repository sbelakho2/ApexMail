<?php

declare(strict_types=1);

namespace KiwiCaptcha\Tests;

use KiwiCaptcha\DerivedKeys;
use KiwiCaptcha\Tests\Fixtures\Vectors;
use PHPUnit\Framework\TestCase;

/**
 * Purpose-key separation.
 *
 * Byte-exact lock-in against the Rust crate's reference vectors
 * (packages/kiwicaptcha/src/keys.rs): the same master derives the same
 * purpose keys in both languages; any deviation breaks the
 * cross-language verify/issue interop.
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
        // documented construction (keys.rs) and lock it to the Rust
        // vector.
        $root = self::hkdf(
            Vectors::SECRET,
            DerivedKeys::INFO_TENANT_ROOT_PREFIX.'t1',
            DerivedKeys::HKDF_DEPLOY_SALT,
        );
        self::assertSame(self::TENANT_T1_ROOT_HEX, bin2hex($root));

        // The t1 purpose keys are derived under the tenant root
        // (empty-salt re-extract, exactly like Rust's t1 tenant path).
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

    public function testNullTenantAndEmptyStringTenantAreDistinctMemoEntries(): void
    {
        // The memo key must be structurally unambiguous: (null, M) derives
        // the global root, ("", M) the tenant root with info
        // "kiwi/v2/tenant/" + "" — different derivations that the earlier
        // "(\0-joined)" key collapsed onto one entry. Both the memo keys
        // and the derived keys must differ.
        $global = DerivedKeys::fromMaster(Vectors::SECRET, null);
        $emptyTenant = DerivedKeys::fromMaster(Vectors::SECRET, '');

        self::assertNotSame($global->challengeKey(), $emptyTenant->challengeKey());
        self::assertNotSame($global->ipBindKey(), $emptyTenant->ipBindKey());
        self::assertNotSame($global->resultKey(), $emptyTenant->resultKey());

        $keys = self::memoKeys();
        self::assertNotSame(
            $keys[hash('sha256', "\x00".pack('N', 0).pack('N', \strlen(Vectors::SECRET)).Vectors::SECRET)] ?? null,
            $keys[hash('sha256', "\x01".pack('N', 0).pack('N', \strlen(Vectors::SECRET)).Vectors::SECRET)] ?? null,
            'the null-tenant and empty-string-tenant derivations must occupy distinct memo entries',
        );
    }

    public function testTenantMasterBoundarySmugglingCannotCollideMemoEntries(): void
    {
        // ("a", "b\0c") vs ("a\0b", "c"): the length prefixes keep the
        // tenant/master boundary unambiguous, so the two distinct inputs
        // derive and memoize separately.
        $a = DerivedKeys::fromMaster("b\0c", 'a');
        $b = DerivedKeys::fromMaster('c', "a\0b");

        self::assertNotSame($a->challengeKey(), $b->challengeKey());
        self::assertNotSame($a->ipBindKey(), $b->ipBindKey());
        self::assertNotSame($a->resultKey(), $b->resultKey());

        $keys = self::memoKeys();
        self::assertCount(2, array_intersect_key($keys, [
            hash('sha256', "\x01".pack('N', 1).'a'.pack('N', 3)."b\0c") => true,
            hash('sha256', "\x01".pack('N', 3)."a\0b".pack('N', 1).'c') => true,
        ]), 'the boundary-smuggling inputs must occupy two distinct memo entries');
    }

    public function testIdenticalInputsHitTheSameMemoEntry(): void
    {
        $first = DerivedKeys::fromMaster(Vectors::SECRET, 't1');
        $second = DerivedKeys::fromMaster(Vectors::SECRET, 't1');

        self::assertSame($first, $second, 'the memo returns the same derived instance for identical inputs');

        $keys = self::memoKeys();
        $expected = hash('sha256', "\x01".pack('N', 2).'t1'.pack('N', \strlen(Vectors::SECRET)).Vectors::SECRET);
        self::assertArrayHasKey($expected, $keys, 'the memo key is the sha256 of the unambiguous encoding');
        self::assertCount(1, array_intersect_key($keys, [$expected => true]));
    }

    /**
     * The per-process memo keys, read reflectively so the collision-free
     * encoding itself is pinned, not only its derivational consequences.
     *
     * @return array<string, DerivedKeys>
     */
    private static function memoKeys(): array
    {
        // ReflectionProperty is constructor-based accessible since PHP
        // 8.1: getValue()/setValue() need no setAccessible() call (which
        // is deprecated on PHP 8.5), so the accessor stays 8.1-clean.
        $property = new \ReflectionProperty(DerivedKeys::class, 'cache');

        /** @var array<string, DerivedKeys> $cache */
        $cache = $property->getValue();

        return $cache;
    }
}
