<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests;

use BelConsulting\KiwiCaptchaBundle\SiteVerify\RedisSiteVerifyMetadataStore;
use BelConsulting\KiwiCaptchaBundle\SiteVerify\RedisSiteVerifyIdempotencyStore;
use BelConsulting\KiwiCaptchaBundle\SiteVerify\SiteVerifyIdempotencyCorruptException;
use BelConsulting\KiwiCaptchaBundle\SiteVerify\SiteVerifyMetadata;
use BelConsulting\KiwiCaptchaBundle\SiteVerify\SiteVerifyMetadataCorruptException;
use BelConsulting\KiwiCaptchaBundle\SiteVerify\IdempotencyClaim;
use BelConsulting\KiwiCaptchaBundle\SiteVerify\StoredLookupKind;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\SiteVerifyStoreAssert;
use BelConsulting\KiwiCaptchaBundle\SiteVerify\SiteVerifyResult;
use PHPUnit\Framework\TestCase;

/**
 * The corrupt-persisted-state contract of the siteverify metadata.
 * A present value of the wrong type, a value outside its request
 * grammar, or an impossible chain-coordinate pair is corrupt stored
 * state and throws at decode: never silently normalized into an
 * absent field that would answer replays with emptied metadata.
 * Absent or null keys keep their legacy defaults. The Redis-backed
 * matrix proves the same verdicts hold through the real store round
 * trip, surfacing as the store's documented corrupt exception (the
 * controller's catch-all answers its retryable internal-error
 * response).
 */
final class SiteVerifyMetadataCorruptionTest extends TestCase
{
    /** @return list<array{0: string, 1: array<string, mixed>}> */
    public static function provideCorruptShapes(): array
    {
        return [
            'action as int' => ['action', ['v' => 1, 'action' => 123, 'chainId' => 123, 'chainDepth' => '2']],
            'chainId as int' => ['chainId', ['v' => 1, 'chainId' => 123]],
            'chainDepth as string' => ['chainDepth', ['v' => 1, 'chainDepth' => '2']],
            'cdata as float' => ['cdata', ['v' => 1, 'cdata' => 1.5]],
            'scope as bool' => ['scope', ['v' => 1, 'scope' => true]],
            'sitekey as array' => ['sitekey', ['v' => 1, 'sitekey' => ['x']]],
            'action outside its grammar' => ['action', ['v' => 1, 'action' => str_repeat('x', 33)]],
            'action with spaces' => ['action', ['v' => 1, 'action' => 'log in']],
            'cdata outside its grammar' => ['cdata', ['v' => 1, 'cdata' => str_repeat('x', 256)]],
            'scope outside the identifier grammar' => ['scope', ['v' => 1, 'scope' => 'not a scope!']],
            'chainDepth one' => ['chainDepth', ['v' => 1, 'chainDepth' => 1]],
            'chainDepth three' => ['chainDepth', ['v' => 1, 'chainDepth' => 3]],
            'depth without an id' => ['pair', ['v' => 1, 'chainDepth' => 2]],
            'id without depth two' => ['pair', ['v' => 1, 'chainId' => 'chain-1', 'chainDepth' => 0]],
            'chainId with identifier-only characters' => ['chainId', ['v' => 1, 'chainId' => 'abc:def', 'chainDepth' => 2]],
            'over-long chainId' => ['chainId', ['v' => 1, 'chainId' => str_repeat('x', 100), 'chainDepth' => 2]],
        ];
    }

    /**
     * @dataProvider provideCorruptShapes
     */
    public function testWrongTypeOrImpossibleCombinationThrowsAtDecode(string $label, array $data): void
    {
        try {
            SiteVerifyMetadata::fromArray($data);
            self::fail("the corrupt shape '{$label}' must throw at decode");
        } catch (SiteVerifyMetadataCorruptException $e) {
            self::assertStringContainsString('metadata', $e->getMessage());
        }
    }

    public function testAbsentAndNullKeysKeepTheirLegacyDefaults(): void
    {
        // Records persisted before a field existed parse unchanged.
        $meta = SiteVerifyMetadata::fromArray(['v' => 1]);
        self::assertNull($meta);

        $withNulls = SiteVerifyMetadata::fromArray(['v' => 1, 'action' => null, 'chainId' => null, 'chainDepth' => null]);
        self::assertNull($withNulls);

        $legacy = SiteVerifyMetadata::fromArray(['action' => 'login-action', 'cdata' => 'order-77']);
        self::assertNotNull($legacy);
        self::assertSame('login-action', $legacy->action);
        self::assertSame('order-77', $legacy->cdata);
        self::assertNull($legacy->chainId);
        self::assertSame(0, $legacy->chainDepth);

        $chained = SiteVerifyMetadata::fromArray(['v' => 1, 'chainId' => 'chain-1', 'chainDepth' => 2]);
        self::assertSame('chain-1', $chained->chainId);
        self::assertSame(2, $chained->chainDepth);
    }

    public function testACachedCompletedResultIsStrictlyValidated(): void
    {
        // A completed idempotency result is authorization-bearing
        // cached state: shapes no conforming finalize could write
        // (bare success objects, unknown keys, impossible combinations,
        // unknown error codes) fail closed at read, and finalize
        // refuses them at write.
        $corrupt = [
            ['success' => true],
            ['success' => 'true'],
            ['success' => 1],
            ['success' => true, 'hostname' => 'h', 'unknown' => 'x'],
            ['success' => true, 'challenge_ts' => 'ts', 'hostname' => 5],
            ['success' => false, 'challenge_ts' => 'ts', 'hostname' => null, 'error-codes' => ['internal-error']],
            ['success' => false, 'challenge_ts' => null, 'hostname' => null, 'error-codes' => []],
            ['success' => false, 'challenge_ts' => null, 'hostname' => null, 'error-codes' => ['not-a-code']],
            ['success' => false, 'challenge_ts' => null, 'hostname' => null, 'error-codes' => ['internal-error', 'bad-request']],
            [],
        ];
        foreach ($corrupt as $shape) {
            try {
                SiteVerifyResult::validate($shape);
                self::fail('the corrupt cached shape must fail closed: '.json_encode($shape));
            } catch (SiteVerifyIdempotencyCorruptException) {
            }
        }
        // The canonical shapes pass: the full success form, the minimal
        // success form, and the canonical failure form.
        SiteVerifyResult::validate(['success' => true, 'challenge_ts' => null, 'hostname' => null, 'action' => null, 'cdata' => null, 'error-codes' => []]);
        SiteVerifyResult::validate(['success' => true, 'challenge_ts' => null, 'hostname' => null]);
        SiteVerifyResult::validate(['success' => false, 'challenge_ts' => null, 'hostname' => null, 'error-codes' => ['invalid-input-response']]);
        $this->addToAssertionCount(3);
    }

    public function testARealRedisCompletedRecordWithACorruptResultFailsClosed(): void
    {
        $url = getenv('KC_REDIS_URL');
        if (!\is_string($url) || $url === '') {
            $flag = getenv('KIWI_REQUIRE_REAL_REDIS_TESTS');
            if (\is_string($flag) && $flag !== '' && $flag !== '0') {
                self::fail('KIWI_REQUIRE_REAL_REDIS_TESTS is set but KC_REDIS_URL is absent');
            }
            self::markTestSkipped('KC_REDIS_URL is not set');
        }
        $client = new \Predis\Client(['host' => parse_url($url, PHP_URL_HOST) ?: '127.0.0.1', 'port' => parse_url($url, PHP_URL_PORT) ?: 6379]);
        $store = new RedisSiteVerifyIdempotencyStore($client, 'kiwitest:result-corrupt:'.getmypid());
        $backendId = hash_hmac('sha256', 'login|0|', 'secret');
        $uuid = 'eeeeeeee-cach-4b2c-8c3d-000000000c05';
        $hash = hash('sha256', 'response');
        // Seed a legitimate completed record directly (the exact
        // envelope a conforming finalize writes) so the read-side
        // validation runs against genuine stored bytes.
        $key = '{kiwi:kiwitest_result-corrupt_'.getmypid().'}:siteverify-idem:'.$backendId.':'.$uuid;
        $fingerprint = hash('sha256', 'ip-fingerprint');
        $client->set($key, json_encode([
            'v' => 2,
            'response_hash' => $hash,
            'remoteip_fingerprint' => $fingerprint,
            'binding' => '',
            'state' => 'complete',
            'owner' => null,
            'lease_expires_at' => null,
            'result' => ['success' => false, 'challenge_ts' => null, 'hostname' => null, 'error-codes' => ['internal-error']],
        ], JSON_THROW_ON_ERROR), 'EX', 300);
        self::assertSame(
            ['success' => false, 'challenge_ts' => null, 'hostname' => null, 'error-codes' => ['internal-error']],
            SiteVerifyStoreAssert::completed($store->storedForOperation($backendId, $uuid, $hash, $fingerprint, '')),
            'the legitimate completed record reads back',
        );

        // Corrupt the persisted completed result in place: the cached
        // read must fail closed as the typed corrupt exception.
        foreach ([
            ['state' => 'complete', 'result' => ['success' => true]],
            ['state' => 'complete', 'result' => ['success' => true, 'evil' => 'extra']],
            ['state' => 'complete', 'result' => ['success' => 'true']],
        ] as $corrupt) {
            $client->set($key, json_encode($corrupt, JSON_THROW_ON_ERROR));
            self::assertSame(
                StoredLookupKind::Corrupt,
                $store->storedForOperation($backendId, $uuid, $hash, 'ip-fingerprint', '')->kind,
                'the corrupt completed result must fail closed',
            );
        }

        // Raw semantic duplicate spellings (escaped aliases), in both
        // member orders: the strict decoder refuses the document before
        // json_decode collapses it, so a forged success can never be read
        // from an ambiguous record.
        $clean = (string) json_encode([
            'state' => 'complete',
            'response_hash' => $hash,
            'remoteip_fingerprint' => 'ip-fingerprint',
            'result' => ['success' => true, 'challenge_ts' => null, 'hostname' => null],
        ], JSON_THROW_ON_ERROR);
        $ambiguousRows = [
            'state literal-first' => str_replace('"state":"complete"', '"state":"complete","st\\u0061te":"pending"', $clean),
            'state alias-first' => str_replace('"state":"complete"', '"st\\u0061te":"pending","state":"complete"', $clean),
            'success literal-first' => str_replace('"success":true', '"success":true,"success":"forged"', $clean),
            'success alias-first' => str_replace('"success":true', '"success\\u005ffalse":false,"success":true', $clean),
        ];
        foreach ($ambiguousRows as $label => $ambiguous) {
            self::assertNotSame($clean, $ambiguous, $label.': the duplicate is injected');
            $client->set($key, $ambiguous);
            self::assertSame(
                StoredLookupKind::Corrupt,
                $store->storedForOperation($backendId, $uuid, $hash, 'ip-fingerprint', '')->kind,
                $label.': an ambiguous idempotency record must fail closed',
            );
        }

        // Unique-key structural corruption: JSON-clean records no
        // conforming writer could produce (a complete record that still
        // owns a lease, a pending record carrying a result, an unknown
        // authority field, a non-boolean success). Both the read and the
        // claim refuse them with the typed fail-closed exception — never
        // a cached success, never a client conflict.
        $structural = [
            ['response_hash' => $hash, 'state' => 'complete', 'owner' => 'stale-owner', 'lease_expires_at' => 123, 'result' => ['success' => true, 'challenge_ts' => null, 'hostname' => null]],
            ['response_hash' => $hash, 'state' => 'pending', 'owner' => 'owner-a', 'lease_expires_at' => 123, 'result' => ['success' => true, 'challenge_ts' => null, 'hostname' => null]],
            ['response_hash' => $hash, 'state' => 'complete', 'owner' => null, 'lease_expires_at' => null, 'result' => ['success' => true, 'challenge_ts' => null, 'hostname' => null], 'unexpected_authority_field' => 'x'],
            ['response_hash' => $hash, 'state' => 'complete', 'owner' => null, 'lease_expires_at' => null, 'result' => ['success' => 'true', 'challenge_ts' => null, 'hostname' => null]],
            ['response_hash' => $hash, 'state' => 'quantum', 'owner' => null, 'lease_expires_at' => null, 'result' => ['success' => true, 'challenge_ts' => null, 'hostname' => null]],
        ];
        foreach ($structural as $index => $bad) {
            $client->set($key, json_encode($bad, JSON_THROW_ON_ERROR), 'EX', 300);
            self::assertSame(
                StoredLookupKind::Corrupt,
                $store->storedForOperation($backendId, $uuid, $hash, 'ip-fingerprint', '')->kind,
                'structural #'.$index.': the read must fail closed',
            );
            try {
                $store->claim($backendId, $uuid, $hash, 300, hash('sha256', 'ip-fingerprint'));
                self::fail('structural #'.$index.': the claim must answer the typed 503, never a client conflict');
            } catch (SiteVerifyIdempotencyCorruptException) {
            }
        }
        $client->del([$key]);
    }

    public function testTheRedisRoundTripThrowsTheSameVerdictsOnRealRedis(): void
    {
        $url = getenv('KC_REDIS_URL');
        if (!\is_string($url) || $url === '') {
            $flag = getenv('KIWI_REQUIRE_REAL_REDIS_TESTS');
            if (\is_string($flag) && $flag !== '' && $flag !== '0') {
                self::fail('KIWI_REQUIRE_REAL_REDIS_TESTS is set but KC_REDIS_URL is absent');
            }
            self::markTestSkipped('KC_REDIS_URL is not set');
        }
        $client = new \Predis\Client(['host' => parse_url($url, PHP_URL_HOST) ?: '127.0.0.1', 'port' => parse_url($url, PHP_URL_PORT) ?: 6379]);
        $store = new RedisSiteVerifyMetadataStore($client, 'kiwitest:meta-corrupt:'.getmypid());
        $nonce = base64_encode(random_bytes(32));

        $store->store($nonce, new SiteVerifyMetadata('login-action', 'order-77', null, null, 0, 'login'), 120);
        $read = $store->find($nonce);
        self::assertNotNull($read);
        self::assertSame('login-action', $read->action);

        // Corrupt the persisted JSON in place: wrong types and an
        // impossible chain pair both surface as the store's corrupt
        // exception, never as emptied metadata.
        $key = '{kiwi:kiwitest_meta-corrupt_'.getmypid().'}:siteverify-meta:'.$nonce;
        foreach ([
            ['v' => 1, 'action' => 123, 'chainId' => 123, 'chainDepth' => '2'],
            ['v' => 1, 'chainDepth' => 2],
            ['v' => 1, 'chainId' => 'chain-9', 'chainDepth' => 0],
            ['v' => 1, 'action' => str_repeat('x', 33)],
        ] as $corrupt) {
            $client->set($key, json_encode($corrupt, JSON_THROW_ON_ERROR));
            try {
                $store->find($nonce);
                self::fail('the corrupt persisted shape must surface as the corrupt exception');
            } catch (SiteVerifyMetadataCorruptException) {
            }
        }

        // A raw semantic duplicate (escaped alias) is ambiguous state:
        // the strict decoder refuses the bytes before json_decode
        // collapses them.
        $cleanMeta = (string) json_encode(['v' => 1, 'action' => 'login-action', 'cdata' => null, 'sitekey' => null, 'scope' => 'login', 'chainId' => null, 'chainDepth' => null], JSON_THROW_ON_ERROR);
        $ambiguousMeta = str_replace('"action":"login-action"', '"action":"login-action","act\\u0069on":"forged"', $cleanMeta);
        self::assertNotSame($cleanMeta, $ambiguousMeta);
        $client->set($key, $ambiguousMeta);
        try {
            $store->find($nonce);
            self::fail('an ambiguous metadata record must surface as the corrupt exception');
        } catch (SiteVerifyMetadataCorruptException) {
        }
        $client->del([$key]);
    }
}
