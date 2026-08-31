<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests;

use BelConsulting\KiwiCaptchaBundle\Controller\SiteVerifyController;
use BelConsulting\KiwiCaptchaBundle\SiteVerify\RedisSiteVerifyIdempotencyStore;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\RedisTestUrl;
use KiwiCaptcha\Config;
use KiwiCaptcha\Issuer;
use KiwiCaptcha\PoWAlgorithm;
use KiwiCaptcha\SolutionToken;
use KiwiCaptcha\Storage\RedisStorage;
use KiwiCaptcha\Verifier;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;

/**
 * SiteVerify idempotency under concurrent identical retries at scale.
 *
 * The fault-injection suite races one token with a fixed idempotency
 * key. This suite extends the contract to a population: thirty
 * challenges, each raced by ten workers with that challenge's own
 * idempotency key. Every retry of a key must converge on the identical
 * canonical provider response, and every challenge must see exactly one
 * logical redemption, the atomic consume winner's committed result.
 * No worker may answer an error status: the same-key contract is a 200
 * for every retry.
 *
 * Runs in the real-Redis CI lane (`KC_REDIS_URL` / `TEST_REDIS_URL`).
 */
final class RealRedisSiteVerifyIdempotencyScaleTest extends TestCase
{
    private const SECRET = '0123456789abcdef0123456789abcdef';

    private const SITEVERIFY_SECRET = 'compat-secret-42';

    private const CHALLENGES = 30;

    private const WORKERS = 10;

    private static function redisUrl(): string
    {
        $url = RedisTestUrl::resolve();
        if ($url === null) {
            self::markTestSkipped('KC_REDIS_URL/TEST_REDIS_URL not set — the real-Redis suites run in the CI Redis-service job');
        }

        return $url;
    }

    /** @return \Predis\Client|null the probed, flushed client, or null when skipped */
    private function redisOrSkip(): ?\Predis\Client
    {
        if (!\function_exists('pcntl_fork')) {
            self::markTestSkipped('pcntl is not installed; cannot fork concurrent workers');
        }
        if (!\class_exists(\Predis\Client::class)) {
            self::markTestSkipped('predis/predis is not installed');
        }
        try {
            $probe = new \Predis\Client(self::redisUrl(), ['timeout' => 5.0, 'read_write_timeout' => 5.0]);
            $probe->ping();
        } catch (\Throwable) {
            self::markTestSkipped('no Redis at the configured URL — start one for the idempotency scale suite');
        }
        $probe->flushdb();

        return $probe;
    }

    private function siteverifyRequest(array $fields): Request
    {
        return Request::create(
            '/kiwi-captcha/siteverify',
            'POST',
            [],
            [],
            [],
            ['CONTENT_TYPE' => 'application/x-www-form-urlencoded'],
            (string) http_build_query($fields),
        );
    }

    private function solveCounter(string $prefix, string $salt, int $targetBits): int
    {
        $saltBytes = base64_decode($salt, true);
        $counter = 0;
        do {
            $hash = hash('sha256', $prefix.$counter.$saltBytes, true);
            $counter++;
        } while (Verifier::leadingZeroBits($hash) < $targetBits);

        return $counter - 1;
    }

    /** @return list<string> non-empty result lines */
    private function readLines(string $outFile): array
    {
        $raw = (string) file_get_contents($outFile);
        @unlink($outFile);

        return array_values(array_filter(explode("\n", $raw), static fn (string $l): bool => $l !== ''));
    }

    public function testTenWorkersThirtyChallengesIdenticalOutcomesOneRedemptionEach(): void
    {
        $probe = $this->redisOrSkip();
        if ($probe === null) {
            return;
        }

        // The parent issues and solves the whole population, then hands
        // every worker the same token list and the same per-challenge
        // idempotency keys.
        $issuer = new Issuer(
            new Config(secretKey: self::SECRET, algorithm: PoWAlgorithm::Sha256, targetBits: 8, ttlSecs: 120),
            new RedisStorage($probe),
        );
        $tokensFile = tempnam(sys_get_temp_dir(), 'kiwi-idem-scale-tokens-');
        $lines = [];
        $minDuration = 0;
        for ($i = 0; $i < self::CHALLENGES; $i++) {
            $challenge = $issuer->issue('login', '127.0.0.1');
            $solution = $this->solveCounter($challenge->prefix, $challenge->salt, $challenge->targetBits);
            $token = SolutionToken::create($challenge->nonce, $solution, 5000, [])->encode();
            $lines[] = json_encode([
                'token' => $token,
                'uuid' => sprintf('f47ac10b-58cc-4372-a567-%012d', $i),
            ], JSON_THROW_ON_ERROR);
            $minDuration = max($minDuration, $challenge->minDurationMs);
        }
        file_put_contents($tokensFile, implode("\n", $lines)."\n");
        usleep(($minDuration + 10) * 1000);
        $probe->disconnect();

        // Ten workers, every worker races the whole population, each
        // challenge under its own key.
        $base = tempnam(sys_get_temp_dir(), 'kiwi-idem-scale-');
        $startBarrier = tempnam(sys_get_temp_dir(), 'kiwi-idem-scale-start-');
        $children = [];
        $outFiles = [];
        for ($w = 0; $w < self::WORKERS; $w++) {
            $outFiles[$w] = $base.'.'.$w;
            $pid = pcntl_fork();
            if ($pid === -1) {
                self::markTestSkipped('pcntl_fork failed; concurrency test not run');
            }
            if ($pid === 0) {
                $fp = @fopen($startBarrier, 'r');
                if ($fp !== false) {
                    flock($fp, LOCK_SH);
                    fread($fp, 1);
                    fclose($fp);
                }
                $entries = array_values(array_filter(explode("\n", (string) file_get_contents($tokensFile)), static fn (string $l): bool => $l !== ''));
                $client = new \Predis\Client(self::redisUrl(), ['timeout' => 30.0, 'read_write_timeout' => 30.0]);
                $storage = new RedisStorage($client);
                $controller = new SiteVerifyController(
                    new Verifier($storage),
                    self::SECRET,
                    [self::SITEVERIFY_SECRET => 'login'],
                    $storage,
                    null,
                    null,
                    new RedisSiteVerifyIdempotencyStore($client),
                    null,
                    10.0,
                );
                $buffer = [];
                foreach ($entries as $entryLine) {
                    $entry = json_decode($entryLine, true);
                    try {
                        $response = $controller->siteverify($this->siteverifyRequest([
                            'secret' => self::SITEVERIFY_SECRET,
                            'response' => $entry['token'],
                            'remoteip' => '127.0.0.1',
                            'idempotency_key' => $entry['uuid'],
                        ]));
                        $buffer[] = $response->getStatusCode().':'.$response->getContent();
                    } catch (\Throwable $e) {
                        $buffer[] = 'error:'.$e->getMessage();
                    }
                }
                $client->disconnect();
                file_put_contents($base.'.'.$w, implode("\n", $buffer)."\n");
                exit(0);
            }
            $children[] = $pid;
        }
        $barrierFile = fopen($startBarrier, 'w');
        fwrite($barrierFile, 'go');
        fclose($barrierFile);
        $crashed = false;
        foreach ($children as $pid) {
            pcntl_waitpid($pid, $status);
            if (pcntl_wexitstatus($status) !== 0) {
                $crashed = true;
            }
        }
        self::assertFalse($crashed, 'every idempotency worker must exit cleanly');
        @unlink($startBarrier);
        @unlink($base);
        @unlink($tokensFile);

        // Worker files keep the challenge order, so line j of every worker
        // answers challenge j. Every retry of a key is a 200 and every
        // worker's line for a challenge is byte-identical.
        $perWorker = [];
        foreach ($outFiles as $outFile) {
            $lines = $this->readLines($outFile);
            self::assertCount(self::CHALLENGES, $lines, 'every worker must report every challenge');
            $perWorker[] = $lines;
        }
        for ($j = 0; $j < self::CHALLENGES; $j++) {
            $outcomes = [];
            foreach ($perWorker as $lines) {
                $line = $lines[$j];
                self::assertMatchesRegularExpression('/^200:/', $line, 'a same-key retry must never answer an error status: '.$line);
                $outcomes[] = $line;
            }
            self::assertSame(1, \count(array_unique($outcomes)), 'all ten retries of a key must converge on the identical canonical response');
            $body = json_decode(substr($outcomes[0], 4), true);
            self::assertSame(true, $body['success'] ?? null, 'the deterministic outcome of a valid token is success: '.$outcomes[0]);
            self::assertSame([], $body['error-codes'] ?? null, 'the canonical success carries no error codes');
        }

        // Exactly one logical redemption per challenge: the retained
        // consumed record carries the winner's committed valid result,
        // and every idempotency entry is complete under the canonical
        // bytes.
        $check = new \Predis\Client(self::redisUrl(), ['timeout' => 15.0, 'read_write_timeout' => 15.0]);
        $checkStorage = new RedisStorage($check);
        $store = new RedisSiteVerifyIdempotencyStore($check);
        $backendId = hash('sha256', self::SITEVERIFY_SECRET.'|login|0|');
        try {
            $keys = $check->keys('kiwicaptcha:*');
            self::assertCount(self::CHALLENGES, $keys, 'the store must hold exactly the raced population');
            foreach ($keys as $key) {
                if (str_contains($key, ':siteverify-idem:')) {
                    continue;
                }
                $consumed = $checkStorage->consumedState(substr($key, strlen('kiwicaptcha:')));
                self::assertNotNull($consumed, 'every raced challenge must end in the retained consumed state');
                self::assertNotNull($consumed->consumedResult, 'every winner must commit the deterministic result');
                self::assertTrue($consumed->consumedResult->valid, 'every committed result is the valid success');
            }
            for ($j = 0; $j < self::CHALLENGES; $j++) {
                $uuid = sprintf('f47ac10b-58cc-4372-a567-%012d', $j);
                $stored = $store->stored($backendId, $uuid);
                self::assertIsArray($stored, 'every idempotency entry must be complete');
                ksort($stored);
                self::assertSame(true, $stored['success'] ?? null, 'the stored outcome is the canonical success');
            }
        } finally {
            $check->disconnect();
        }
    }
}
