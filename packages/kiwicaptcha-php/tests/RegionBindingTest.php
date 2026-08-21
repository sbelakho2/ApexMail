<?php

declare(strict_types=1);

namespace KiwiCaptcha\Tests;

use KiwiCaptcha\ChallengeProfile;
use KiwiCaptcha\ChallengeRecord;
use KiwiCaptcha\Issuer;
use KiwiCaptcha\SolutionToken;
use KiwiCaptcha\Storage\ArrayStorage;
use KiwiCaptcha\Verifier;
use KiwiCaptcha\VerifyError;
use KiwiCaptcha\Tests\Fixtures\Vectors;
use PHPUnit\Framework\TestCase;

/**
 * Region binding: the issued record carries an optional region (null =
 * unbound), and the record JSON always includes the `region` key (byte
 * parity with the Rust serde schema, 21 keys). A verifier configured
 * with an expected region rejects any record whose region does not
 * match exactly (WrongRegion), including unbound records.
 */
final class RegionBindingTest extends TestCase
{
    private function solve(string $prefix, string $salt, int $targetBits): int
    {
        $saltBytes = base64_decode($salt, true);
        $counter = 0;
        do {
            $hash = hash('sha256', $prefix.$counter.$saltBytes, true);
            $counter++;
        } while (Verifier::leadingZeroBits($hash) < $targetBits);

        return $counter - 1;
    }

    /** @return array{0: ArrayStorage, 1: ChallengeRecord, 2: string} */
    private function issue(?string $region): array
    {
        $storage = new ArrayStorage();
        $issuer = new Issuer(
            new \KiwiCaptcha\Config(secretKey: Vectors::SECRET, targetBits: 8),
            $storage,
            region: $region,
        );
        $challenge = $issuer->issue('login', '198.51.100.7');
        $record = $storage->find($challenge->nonce);
        self::assertNotNull($record);
        $counter = $this->solve($challenge->prefix, $challenge->salt, $challenge->targetBits);

        return [$storage, $record, SolutionToken::create($challenge->nonce, $counter, 5000, [])->encode()];
    }

    public function testIssuedRecordCarriesRegionAndWireKeyIsAlwaysPresent(): void
    {
        [, $record] = $this->issue('eu');

        self::assertSame('eu', $record->region);
        $data = $record->toArray();
        self::assertSame('eu', $data['region']);
        self::assertSame('eu', ChallengeRecord::fromArray($data)->region);
    }

    public function testUnboundRecordCarriesNullRegionInTheWire(): void
    {
        [, $record] = $this->issue(null);

        self::assertNull($record->region);
        self::assertArrayHasKey('region', $record->toArray());
        self::assertNull($record->toArray()['region']);
        self::assertNull(ChallengeRecord::fromArray($record->toArray())->region);
    }

    public function testFromArrayAcceptsAbsentRegionAsNull(): void
    {
        // Legacy records (or records written before the region field) have
        // no region key at all — must decode as unbound.
        $data = $this->issue('eu')[1]->toArray();
        unset($data['region']);

        self::assertNull(ChallengeRecord::fromArray($data)->region);
    }

    public function testVerifierWithMatchingRegionVerifies(): void
    {
        [$storage, $record, $token] = $this->issue('eu');

        $verifier = new Verifier($storage, region: 'eu');
        $outcome = $verifier->verify(
            $token,
            Vectors::SECRET,
            'login',
            '198.51.100.7',
            nowNs: $record->issuedAtNs + 1_000_000,
        );

        self::assertTrue($outcome->isOk(), sprintf('matching region must verify, got %s', $outcome->code()));
    }

    public function testVerifierWithDifferentRegionRejectsAndBurns(): void
    {
        [$storage, $record, $token] = $this->issue('eu');

        $verifier = new Verifier($storage, region: 'us');
        $outcome = $verifier->verify($token, Vectors::SECRET, 'login', '198.51.100.7');

        self::assertSame(VerifyError::WrongRegion, $outcome->error);
        self::assertNull($storage->find($record->nonce), 'a wrong-region verification burns the record');
    }

    public function testVerifierRegionRejectsUnboundRecordFailClosed(): void
    {
        // A null record region is redeemable in every region, so a
        // region-configured verifier must fail closed on it.
        [$storage, , $token] = $this->issue(null);

        $verifier = new Verifier($storage, region: 'eu');
        $outcome = $verifier->verify($token, Vectors::SECRET, 'login', '198.51.100.7');

        self::assertSame(VerifyError::WrongRegion, $outcome->error);
    }

    public function testVerifierWithoutRegionAcceptsBoundRecord(): void
    {
        [$storage, $record, $token] = $this->issue('eu');

        $verifier = new Verifier($storage);
        $outcome = $verifier->verify(
            $token,
            Vectors::SECRET,
            'login',
            '198.51.100.7',
            nowNs: $record->issuedAtNs + 1_000_000,
        );

        self::assertTrue($outcome->isOk(), sprintf('unconfigured verifier must accept bound records, got %s', $outcome->code()));
    }

    public function testWrongRegionErrorValue(): void
    {
        self::assertSame('wrong_region', VerifyError::WrongRegion->value);
    }

    public function testRegionIsPartOfTheSignedCanonicalPayload(): void
    {
        // region, policy_version, and request_binding are part of the
        // signed canonical payload: the v2 signature covers the full
        // canonical (`...|min_duration_ms|region|policy_version|
        // request_binding`), so a record's embedded signature must equal
        // the v2 signature over its canonical including the region. Two
        // records issued for different regions carry different
        // signatures.
        [, $recordA] = $this->issue('eu');
        [, $recordB] = $this->issue('us');

        self::assertNotSame($recordA->region, $recordB->region);

        $canonicalA = Issuer::canonicalPayload(
            $recordA->nonce,
            $recordA->scope,
            $recordA->bindingTag,
            $recordA->issuedAt,
            $recordA->expiresAt,
            $recordA->algorithm,
            $recordA->mKib,
            $recordA->t,
            $recordA->p,
            $recordA->targetBits,
            $recordA->salt,
            $recordA->minDurationMs,
            $recordA->region,
            $recordA->policyVersion ?? 1,
            $recordA->requestBinding,
        );
        $canonicalB = Issuer::canonicalPayload(
            $recordB->nonce,
            $recordB->scope,
            $recordB->bindingTag,
            $recordB->issuedAt,
            $recordB->expiresAt,
            $recordB->algorithm,
            $recordB->mKib,
            $recordB->t,
            $recordB->p,
            $recordB->targetBits,
            $recordB->salt,
            $recordB->minDurationMs,
            $recordB->region,
            $recordB->policyVersion ?? 1,
            $recordB->requestBinding,
        );
        foreach ([[$recordA, $canonicalA, 'eu'], [$recordB, $canonicalB, 'us']] as [$record, $canonical, $region]) {
            self::assertStringContainsString('|'.$region.'|1|', $canonical, 'the canonical must carry region then policy_version');
            $signature = substr($record->challenge, strrpos($record->challenge, '.') + 1);
            self::assertSame(
                Issuer::signPayloadV2($canonical, Vectors::SECRET),
                $signature,
                'the v2 signature covers the full canonical — region, policy_version, and request_binding included',
            );
        }
    }

    public function testIssueWithProfileCarriesTheIssuerRegion(): void
    {
        $storage = new ArrayStorage();
        $issuer = new Issuer(
            new \KiwiCaptcha\Config(secretKey: Vectors::SECRET, targetBits: 8),
            $storage,
            region: 'eu',
        );
        $challenge = $issuer->issueWithProfile('login', '198.51.100.7', ChallengeProfile::sha(8));

        self::assertSame('eu', $storage->find($challenge->nonce)?->region);
    }
}
