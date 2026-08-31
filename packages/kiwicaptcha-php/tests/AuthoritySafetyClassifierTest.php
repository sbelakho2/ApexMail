<?php

declare(strict_types=1);

namespace KiwiCaptcha\Tests;

use KiwiCaptcha\AuthoritySafety;
use KiwiCaptcha\AuthoritySafetyClassifier;
use KiwiCaptcha\Tests\Fixtures\FakePredisClient;
use KiwiCaptcha\Tests\Fixtures\RetryEnabledPhpRedisStub;
use PHPUnit\Framework\TestCase;

/**
 * The canonical authority-safety classifier
 * ({@see AuthoritySafetyClassifier}): the one classification every
 * authority decision shares. A Predis replication or cluster aggregate
 * is Unsafe; a direct connection with retries enabled is Unsafe; a
 * direct connection with retries disabled is Safe; an uninspectable
 * client is Unknown. The same verdicts feed the verified-WAIT guard
 * (Unsafe refuses), the bundle's fail_closed runtime classifier and
 * the pinned-primary authority guard (Unsafe and Unknown refuse).
 */
final class AuthoritySafetyClassifierTest extends TestCase
{
    private const RUN_ID_A = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';

    public function testAnAggregateIsUnsafe(): void
    {
        if (!\class_exists(\Predis\Client::class)) {
            self::markTestSkipped('predis/predis is not installed');
        }
        $sentinel = new \Predis\Client([
            ['scheme' => 'tcp', 'host' => '127.0.0.1', 'port' => 6398],
        ], [
            'replication' => 'sentinel',
            'service' => 'mymaster',
        ]);
        $cluster = new \Predis\Client([
            'tcp://127.0.0.1:7001',
            'tcp://127.0.0.1:7002',
        ], [
            'cluster' => 'redis',
        ]);

        self::assertSame(AuthoritySafety::Unsafe, AuthoritySafetyClassifier::classify($sentinel), 'a Sentinel replication aggregate is a proven authority-change topology');
        self::assertSame(AuthoritySafety::Unsafe, AuthoritySafetyClassifier::classify($cluster), 'a Redis Cluster aggregate is a proven authority-change topology');
    }

    public function testARetryEnabledDirectPredisClientIsUnsafe(): void
    {
        if (!\class_exists(\Predis\Client::class)) {
            self::markTestSkipped('predis/predis is not installed');
        }
        $client = new \Predis\Client([
            'host' => '127.0.0.1',
            'retry' => new \Predis\Retry\Retry(new \Predis\Retry\Strategy\ExponentialBackoff(), 3),
        ]);
        self::assertFalse($client->getConnection()->getParameters()->isDisabledRetry(), 'an explicit retry connection parameter must report retries enabled');

        self::assertSame(AuthoritySafety::Unsafe, AuthoritySafetyClassifier::classify($client), 'a direct client with retries enabled can re-execute a mutation on a replacement connection');
    }

    public function testARetryDisabledDirectPredisClientIsSafe(): void
    {
        if (!\class_exists(\Predis\Client::class)) {
            self::markTestSkipped('predis/predis is not installed');
        }
        $client = new \Predis\Client('tcp://127.0.0.1:6399');
        self::assertTrue($client->getConnection()->getParameters()->isDisabledRetry(), 'the default connection parameters must report retries disabled');

        self::assertSame(AuthoritySafety::Safe, AuthoritySafetyClassifier::classify($client), 'a single-node direct connection with retries disabled is the one authority');
    }

    public function testAnUninspectableClientIsUnknown(): void
    {
        if (!\class_exists(\Predis\Client::class)) {
            self::markTestSkipped('predis/predis is not installed');
        }
        self::assertSame(AuthoritySafety::Unknown, AuthoritySafetyClassifier::classify(new FakePredisClient()), 'a Predis client without an inspectable connection is uninspectable');
        self::assertSame(AuthoritySafety::Unknown, AuthoritySafetyClassifier::classify(new \stdClass()), 'an opaque non-Redis object cannot be classified');
        self::assertSame(AuthoritySafety::Unknown, AuthoritySafetyClassifier::classify('not-a-client'), 'a non-object is uninspectable');
    }

    public function testPhpRedisRetryStateIsClassified(): void
    {
        if (!\extension_loaded('redis')) {
            self::markTestSkipped('phpredis is not installed');
        }
        $retryEnabled = new RetryEnabledPhpRedisStub(10);
        $retryDisabled = new RetryEnabledPhpRedisStub(0);

        self::assertSame(AuthoritySafety::Unsafe, AuthoritySafetyClassifier::classify($retryEnabled), 'phpredis reconnects automatically with OPT_MAX_RETRIES != 0');
        self::assertSame(AuthoritySafety::Safe, AuthoritySafetyClassifier::classify($retryDisabled), 'phpredis with OPT_MAX_RETRIES = 0 is a single authority');
    }
}
