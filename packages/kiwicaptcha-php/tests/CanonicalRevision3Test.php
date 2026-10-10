<?php

declare(strict_types=1);

namespace KiwiCaptcha\Tests;

use KiwiCaptcha\Issuer;
use KiwiCaptcha\PoWAlgorithm;
use PHPUnit\Framework\TestCase;

/**
 * The revision-3 canonical is injective across capability shapes.
 *
 * Revision 2 signed `v2|...` for every protocol version and appended
 * the decoy, execution pair and rsw identity as bare positional
 * segments. A stored-record attacker could therefore reshape a signed
 * record: a v5 rsw record with identity H and no decoy signed the bytes
 * of a v3 decoy record. Revision 3 signs protocol_version and tags
 * every extension, so those shapes stay distinct. This test pins them
 * apart; the Rust twin is
 * `canonical_revision3_is_injective_across_capability_shapes`.
 */
final class CanonicalRevision3Test extends TestCase
{
    private const NONCE = 'bm9uY2UtcmV2aXNpb24tMy10ZXN0LXZlY3Rvcg==';
    private const SALT = 'c2FsdC1yZXZpc2lvbi0z';

    /** @return list<mixed> */
    private function baseArgs(): array
    {
        return [
            self::NONCE,
            'login',
            'tag456',
            111,
            222,
            PoWAlgorithm::Sha256,
            0,
            1,
            1,
            8,
            self::SALT,
            5,
        ];
    }

    public function testDecoyNameNeverCollidesWithRswIdentity(): void
    {
        $name = 'billing_address_line_a3f9c21d8e5b7401';
        $v3decoy = Issuer::canonicalPayload(3, ...array_merge($this->baseArgs(), [null, 1, null, null, 1, $name]));
        $v5identity = Issuer::canonicalPayload(5, ...array_merge($this->baseArgs(), [null, 1, null, null, 1, null, null, null, $name]));
        self::assertNotSame($v3decoy, $v5identity, 'a decoy name must never collide with an rsw identity');
        self::assertStringEndsWith('|d='.$name, $v3decoy);
        self::assertStringEndsWith('|r='.$name, $v5identity);
    }

    public function testExecutionPairNeverCollidesWithDecoyPlusIdentity(): void
    {
        $commitment = str_repeat('a', 64);
        $v4execution = Issuer::canonicalPayload(4, ...array_merge($this->baseArgs(), [null, 1, null, null, 1, null, 1, $commitment]));
        $v5decoyIdentity = Issuer::canonicalPayload(5, ...array_merge($this->baseArgs(), [null, 1, null, null, 1, '1', null, null, $commitment]));
        self::assertNotSame($v4execution, $v5decoyIdentity, 'an execution pair must never collide with decoy+identity');
        self::assertStringEndsWith('|e=1,'.$commitment, $v4execution);
        self::assertStringEndsWith('|d=1|r='.$commitment, $v5decoyIdentity);
    }

    public function testProtocolVersionFlipChangesTheSignedCanonical(): void
    {
        $v5 = Issuer::canonicalPayload(5, ...array_merge($this->baseArgs(), [null, 1, null, null, 1, null, null, null, str_repeat('b', 64)]));
        $v3 = Issuer::canonicalPayload(3, ...array_merge($this->baseArgs(), [null, 1, null, null, 1, 'b'.str_repeat('b', 63)]));
        self::assertNotSame($v5, $v3, 'the signed protocol_version must change the canonical bytes');
        self::assertStringStartsWith('v4|5|', $v5);
        self::assertStringStartsWith('v4|3|', $v3);
    }
}
