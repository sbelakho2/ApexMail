<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests;

use BelConsulting\KiwiCaptchaBundle\Controller\ChallengeController;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\JsonRequest;
use KiwiCaptcha\Config;
use KiwiCaptcha\Issuer;
use KiwiCaptcha\PoWAlgorithm;
use KiwiCaptcha\Storage\ArrayStorage;
use KiwiCaptcha\Tests\Support\RswFixture;
use PHPUnit\Framework\TestCase;

/**
 * The client-facing response must carry every algorithm-specific public
 * field the solver needs. The stored-record handoff used by the
 * production controller (storage wired) recreated the response by hand
 * and silently dropped rsw_modulus, so an rsw deployment minted a
 * challenge the widget could not solve. The issuer's canonical
 * reconstruction is the only serializer.
 */
final class RswResponseHandoffTest extends TestCase
{
    private const SECRET = '0123456789abcdef0123456789abcdef';

    private function rswIssuer(ArrayStorage $storage): Issuer
    {
        return new Issuer(new Config(
            secretKey: self::SECRET,
            algorithm: PoWAlgorithm::Rsw,
            targetBits: 8,
            ttlSecs: 300,
            rswModulusN: RswFixture::MODULUS_N_B64,
            rswLambda: RswFixture::LAMBDA_B64,
            rswT: 10_000,
        ), $storage);
    }

    public function testTheStoredRecordHandoffCarriesTheExactConfiguredRswModulus(): void
    {
        $storage = new ArrayStorage();
        $issuer = $this->rswIssuer($storage);
        $controller = new ChallengeController($issuer, null, false, null, null, storage: $storage);

        $response = $controller->challenge(JsonRequest::create(
            '/challenge',
            'POST',
            [],
            [],
            [],
            ['REMOTE_ADDR' => '198.51.100.7'],
            '{"scope":"login"}',
        ));
        self::assertSame(200, $response->getStatusCode(), (string) $response->getContent());
        $data = json_decode((string) $response->getContent(), true, flags: JSON_THROW_ON_ERROR);

        // The production path serializes from the stored record; the
        // modulus must survive it.
        self::assertArrayHasKey('rsw_modulus', $data, 'the stored-record handoff carries the modulus');
        self::assertSame(RswFixture::MODULUS_N_B64, $data['rsw_modulus'], 'the exact configured modulus');
        self::assertSame('rsw', $data['algorithm']);
        self::assertSame(10_000, $data['t'], 'the sequential-squaring cost rides the signed time-cost slot');
        self::assertArrayNotHasKey('rsw_lambda', $data, 'the trapdoor lambda never leaves the server');

        // The handoff is the canonical Challenge::toArray() surface: same
        // keys, same order, byte-identical values for the stored record.
        $record = $storage->find((string) $data['nonce']);
        self::assertNotNull($record);
        self::assertSame(
            $issuer->responseFromRecord($record)?->toArray(),
            $data,
            'the controller emits exactly the canonical reconstruction',
        );
        self::assertSame(
            array_keys($issuer->issue('login', '198.51.100.7')->toArray()),
            array_keys($data),
            'the handoff key set and order match a fresh issuance',
        );
    }

    public function testShaAndArgonResponsesKeepOmittingTheRswModulus(): void
    {
        foreach (['sha256', 'argon2id'] as $algorithm) {
            $storage = new ArrayStorage();
            $config = $algorithm === 'rsw'
                ? null
                : new Config(
                    secretKey: self::SECRET,
                    algorithm: $algorithm === 'argon2id' ? PoWAlgorithm::Argon2id : PoWAlgorithm::Sha256,
                    targetBits: 8,
                    ttlSecs: 300,
                    mKib: $algorithm === 'argon2id' ? 64 : 0,
                    t: 3,
                    p: 1,
                    argon2TargetBits: 2,
                );
            self::assertNotNull($config);
            $issuer = new Issuer($config, $storage);
            $controller = new ChallengeController($issuer, null, false, null, null, storage: $storage);

            $response = $controller->challenge(JsonRequest::create(
                '/challenge',
                'POST',
                [],
                [],
                [],
                ['REMOTE_ADDR' => '198.51.100.7'],
                '{"scope":"login"}',
            ));
            self::assertSame(200, $response->getStatusCode(), $algorithm.': '.(string) $response->getContent());
            $data = json_decode((string) $response->getContent(), true, flags: JSON_THROW_ON_ERROR);
            self::assertSame($algorithm, $data['algorithm']);
            self::assertArrayNotHasKey('rsw_modulus', $data, $algorithm.' responses never carry the rsw modulus');
        }
    }
}
