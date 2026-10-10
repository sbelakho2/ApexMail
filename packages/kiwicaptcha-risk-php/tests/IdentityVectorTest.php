<?php

declare(strict_types=1);

namespace KiwiCaptcha\Risk\Tests;

use KiwiCaptcha\Risk\Asn\AsnDataset;
use KiwiCaptcha\Risk\IdentityVector;
use KiwiCaptcha\Risk\IdentityVectorInput;
use KiwiCaptcha\Risk\RiskIdentityFactory;
use KiwiCaptcha\Risk\RiskKeys;
use PHPUnit\Framework\TestCase;

/**
 * The identity vector value object (change.md 3.1.1): absent optional
 * dimensions, canonical spellings, the per-process derive memo and the
 * contract-vocabulary surface. The shared corpus parity and the
 * contract-file re-derivation live in IdentityVectorsParityTest; this
 * file pins the object's own behavior.
 */
final class IdentityVectorTest extends TestCase
{
    private function dataset(): AsnDataset
    {
        return AsnDataset::open(dirname(__DIR__) . '/../../protocol/asn/sample-asn.tsv');
    }

    private function factory(): RiskIdentityFactory
    {
        return new RiskIdentityFactory(RiskKeys::fromMaster(str_repeat('k', 32)));
    }

    private function input(string $ip, int $now, ?AsnDataset $dataset = null): IdentityVectorInput
    {
        return new IdentityVectorInput(
            clientIp: $ip,
            sessionCookieHex: null,
            principalId: null,
            agentKeyId: null,
            targetNormalized: null,
            asnDataset: $dataset ?? $this->dataset(),
            nowUnixSecs: $now,
        );
    }

    public function testAbsentOptionalDimensionsAreNull(): void
    {
        $vector = IdentityVector::derive($this->input('203.0.113.27', 1700000000), $this->factory());
        self::assertNull($vector->session);
        self::assertNull($vector->principal);
        self::assertNull($vector->target);
        self::assertNull($vector->agent);
        self::assertSame(['source', 'subnet', 'asn'], $vector->presentDimensions());
        foreach (['source', 'subnet', 'asn'] as $name) {
            self::assertMatchesRegularExpression('/\A[0-9a-f]{32}\z/', $vector->dimension($name));
        }
        self::assertNull($vector->dimension('device'));
    }

    public function testEmptyOptionalMaterialIsAbsent(): void
    {
        $input = new IdentityVectorInput(
            clientIp: '203.0.113.27',
            sessionCookieHex: null,
            principalId: '',
            agentKeyId: '',
            targetNormalized: '',
            asnDataset: $this->dataset(),
            nowUnixSecs: 1700000000,
        );
        $vector = IdentityVector::derive($input, $this->factory());
        self::assertNull($vector->principal);
        self::assertNull($vector->agent);
        self::assertNull($vector->target);
    }

    public function testEveryPresentDimensionReportsByName(): void
    {
        $input = new IdentityVectorInput(
            clientIp: '192.0.2.44',
            sessionCookieHex: '5ae1a4b8c0d1e2f30011223344556677',
            principalId: 'principal-42',
            agentKeyId: 'agent-key-7',
            targetNormalized: 'user@example.com',
            asnDataset: $this->dataset(),
            nowUnixSecs: 1700000000,
        );
        $vector = IdentityVector::derive($input, $this->factory());
        self::assertSame(IdentityVector::DIMENSIONS, $vector->presentDimensions());
        self::assertMatchesRegularExpression('/\A[0-9a-f]{64}\z/', $vector->target);
    }

    public function testMappedAndCompatibleSpellingsMatchPlainV4(): void
    {
        $factory = $this->factory();
        $plain = IdentityVector::derive($this->input('203.0.113.27', 1700000000), $factory);
        $mapped = IdentityVector::derive($this->input('::ffff:203.0.113.27', 1700000000), $factory);
        $compatible = IdentityVector::derive($this->input('::203.0.113.27', 1700000000), $factory);
        self::assertSame($plain->source, $mapped->source);
        self::assertSame($plain->subnet, $mapped->subnet);
        self::assertSame($plain->asn, $mapped->asn);
        self::assertSame($plain->source, $compatible->source);
        self::assertSame($plain->subnet, $compatible->subnet);
        self::assertSame($plain->asn, $compatible->asn);
    }

    public function testRotatedDimensionsFollowTheEpochWindow(): void
    {
        $factory = $this->factory();
        $epoch0a = IdentityVector::derive($this->input('192.0.2.44', 0), $factory);
        $epoch0b = IdentityVector::derive($this->input('192.0.2.44', 899), $factory);
        $epoch1 = IdentityVector::derive($this->input('192.0.2.44', 900), $factory);
        self::assertSame($epoch0a->source, $epoch0b->source);
        self::assertSame($epoch0a->subnet, $epoch0b->subnet);
        self::assertNotSame($epoch0a->source, $epoch1->source);
        self::assertNotSame($epoch0a->subnet, $epoch1->subnet);
        // A 900 s step stays inside the six-hour asn window.
        self::assertSame($epoch0a->asn, $epoch1->asn);
        $asnLater = IdentityVector::derive($this->input('192.0.2.44', 21600), $factory);
        self::assertNotSame($epoch0a->asn, $asnLater->asn);
    }

    public function testTheMemoReturnsTheSameObjectForTheSameDescriptor(): void
    {
        $factory = $this->factory();
        $input = $this->input('203.0.113.27', 1700000000);
        $first = IdentityVector::derive($input, $factory);
        $second = IdentityVector::derive($input, $factory);
        self::assertSame($first, $second, 'a repeated descriptor hits the derive memo');

        // A different time or a different dataset derives freshly.
        $otherTime = IdentityVector::derive($this->input('203.0.113.27', 1700000900), $factory);
        self::assertNotSame($first, $otherTime);
        $otherDataset = IdentityVector::derive($this->input('203.0.113.27', 1700000000, AsnDataset::open(dirname(__DIR__) . '/../../protocol/asn/sample-asn.tsv')), $factory);
        self::assertNotSame($first, $otherDataset, 'a different dataset handle never shares a memo entry');
        self::assertEquals($first, $otherDataset, 'identical inputs still derive the identical vector');

        // A different factory (different keys) never serves a stale
        // memo entry even when object ids happen to repeat.
        $otherFactory = new RiskIdentityFactory(RiskKeys::fromMaster(str_repeat('z', 32)));
        $rekeyed = IdentityVector::derive($input, $otherFactory);
        self::assertNotEquals($first->source, $rekeyed->source);
    }

    public function testDimensionNamesAreTheContractOrder(): void
    {
        self::assertSame(
            ['source', 'subnet', 'asn', 'session', 'principal', 'target', 'agent'],
            IdentityVector::DIMENSIONS,
        );
    }
}
