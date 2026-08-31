<?php

declare(strict_types=1);

namespace KiwiCaptcha\Tests;

use KiwiCaptcha\Config;
use KiwiCaptcha\Issuer;
use KiwiCaptcha\SolutionToken;
use KiwiCaptcha\Storage\RedisStorage;
use KiwiCaptcha\Verifier;
use PHPUnit\Framework\TestCase;

/**
 * Correctness under concurrent verification load against a real Redis.
 *
 * A pool of 25 SHA-256 challenges is issued once, and 4 forked worker
 * processes each verify every token of the pool at the same time, so
 * each nonce is contested by 4 concurrent requests. The suite asserts
 * the one-shot contract under that contention: exactly one worker wins
 * the atomic consume per challenge, one success and never two. Every
 * loser resolves through the typed deterministic codes, never a 500
 * and never an exception escaping the verifier, and the winner's
 * deterministic result commit survives the race in the stored
 * envelope. The worker count and pool size stay small (4 x 25 = 100
 * verifications) so the suite is bounded and deterministic on any CI
 * runner. The atomic consume transition is a single Lua script, so
 * Redis serializes the racing calls and exactly one caller observes
 * consumedNow; this suite is the evidence that the production contract
 * holds under real load.
 *
 * The Redis command budget per lifecycle is spot-checked with a
 * counting client on a sequential sample. Issuance is one SET, and the
 * happy-path verification is three commands: one GET for the runtime
 * snapshot, one `EVALSHA` for the atomic consume and one `EVALSHA` for
 * the deterministic result commit, with the script bodies cached and
 * never re-shipped.
 *
 * Runs when `KC_REDIS_URL` or `TEST_REDIS_URL` is set (the shared
 * real-Redis env of the monorepo CI); skips otherwise, like every other
 * real-Redis suite. Requires the pcntl extension for the workers; the
 * suite skips when it is missing.
 */
final class RedisConcurrencyLoadTest extends TestCase
{
    private const SECRET = '0123456789abcdef0123456789abcdef';

    private const POOL_SIZE = 25;

    private const WORKERS = 4;

    /** @return \Predis\Client|null null when Redis is unreachable */
    private function redisOrSkip(): ?\Predis\Client
    {
        if (!\class_exists(\Predis\Client::class)) {
            self::markTestSkipped('predis/predis is not installed');
        }
        if (!\function_exists('pcntl_fork') || !\function_exists('pcntl_waitpid')) {
            self::markTestSkipped('the pcntl extension is required for the concurrent workers');
        }
        $url = getenv('KC_REDIS_URL');
        if (!\is_string($url) || $url === '') {
            $url = getenv('TEST_REDIS_URL');
        }
        if (!\is_string($url) || $url === '') {
            self::markTestSkipped('KC_REDIS_URL/TEST_REDIS_URL not set — the real-Redis concurrency-load suite runs in the Redis-service env');
        }
        try {
            $probe = new \Predis\Client($url, ['timeout' => 5.0, 'read_write_timeout' => 5.0]);
            $probe->ping();

            return $probe;
        } catch (\Throwable) {
            self::markTestSkipped('no Redis at the configured KC_REDIS_URL/TEST_REDIS_URL');
        }
    }

    /** @return array{0: string, 1: string} [nonce, solved token] */
    private function issueAndSolve(\Predis\Client $client, string $prefix): array
    {
        $issuer = new Issuer(new Config(secretKey: self::SECRET, targetBits: 8, ttlSecs: 120, minDurationMs: 0), new RedisStorage($client, $prefix));
        $challenge = $issuer->issue('login', '198.51.100.7');
        $saltBytes = base64_decode($challenge->salt, true);
        $counter = 0;
        do {
            $hash = hash('sha256', $challenge->prefix.$counter.$saltBytes, true);
            $counter++;
        } while (Verifier::leadingZeroBits($hash) < $challenge->targetBits);
        --$counter;
        $token = SolutionToken::create($challenge->nonce, $counter, 5000, [])->encode();

        return [$challenge->nonce, $token];
    }

    /**
     * The pool file the workers read: one JSON line per challenge with
     * the nonce and the solved token.
     */
    private function writePool(string $path, \Predis\Client $client, string $prefix): void
    {
        $fh = fopen($path, 'wb');
        self::assertNotFalse($fh);
        for ($i = 0; $i < self::POOL_SIZE; $i++) {
            [$nonce, $token] = $this->issueAndSolve($client, $prefix);
            fwrite($fh, json_encode(['nonce' => $nonce, 'token' => $token], JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR)."\n");
        }
        fclose($fh);
    }

    /**
     * One worker: a fresh Redis connection, then verify every pool
     * token and append one JSON result line per token. The child never
     * runs PHPUnit; it writes and exits, so the parent collects the
     * outcomes and asserts on them.
     */
    private function runWorker(string $poolPath, string $resultPath, string $prefix): void
    {
        $client = new \Predis\Client($this->redisUrl(), ['timeout' => 5.0, 'read_write_timeout' => 5.0]);
        $verifier = new Verifier(new RedisStorage($client, $prefix));
        $fh = fopen($resultPath, 'wb');
        if ($fh === false) {
            exit(1);
        }
        foreach (file($poolPath, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) as $line) {
            $row = json_decode($line, true, flags: JSON_THROW_ON_ERROR);
            try {
                $outcome = $verifier->verify($row['token'], self::SECRET, 'login', '198.51.100.7');
                $result = ['nonce' => $row['nonce'], 'ok' => $outcome->isOk(), 'code' => $outcome->code()];
            } catch (\Throwable $e) {
                $result = ['nonce' => $row['nonce'], 'ok' => false, 'code' => 'exception', 'msg' => $e->getMessage()];
            }
            fwrite($fh, json_encode($result, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR)."\n");
        }
        fclose($fh);
        exit(0);
    }

    private function redisUrl(): string
    {
        $url = getenv('KC_REDIS_URL');
        if (!\is_string($url) || $url === '') {
            $url = getenv('TEST_REDIS_URL');
        }

        return (string) $url;
    }

    /**
     * The stored envelope of a nonce, decoded from the raw bytes the
     * client holds, to assert the atomicity of the committed outcome.
     *
     * @return array<string, mixed>
     */
    private function envelope(\Predis\Client $client, string $prefix, string $nonce): array
    {
        $raw = $client->get($prefix.$nonce);
        self::assertIsString($raw, 'the record must still be stored after the race');
        $data = json_decode($raw, true, flags: JSON_THROW_ON_ERROR);
        self::assertIsArray($data);

        return $data;
    }

    public function testConcurrentVerificationOverASharedPoolYieldsExactlyOneSuccessPerChallenge(): void
    {
        $client = $this->redisOrSkip();
        self::assertNotNull($client);
        $prefix = 'concurrency-load-'.bin2hex(random_bytes(4)).'-';

        $tmp = sys_get_temp_dir().'/kiwicaptcha-concurrency-'.bin2hex(random_bytes(4));
        self::assertTrue(mkdir($tmp));
        $poolPath = "$tmp/pool.jsonl";
        $this->writePool($poolPath, $client, $prefix);

        $children = [];
        for ($worker = 0; $worker < self::WORKERS; $worker++) {
            $resultPath = "$tmp/worker-$worker.jsonl";
            $pid = pcntl_fork();
            self::assertNotSame(-1, $pid, 'the worker fork must succeed');
            if ($pid === 0) {
                $this->runWorker($poolPath, $resultPath, $prefix);
            }
            $children[$pid] = $resultPath;
        }
        foreach ($children as $pid => $resultPath) {
            pcntl_waitpid($pid, $status);
            self::assertTrue(pcntl_wifexited($status) && pcntl_wexitstatus($status) === 0, "worker $pid must exit cleanly");
        }

        $successCount = [];
        $outcomes = [];
        foreach ($children as $resultPath) {
            foreach (file($resultPath, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) as $line) {
                $row = json_decode($line, true, flags: JSON_THROW_ON_ERROR);
                self::assertArrayHasKey('nonce', $row);
                self::assertArrayHasKey('ok', $row);
                self::assertArrayHasKey('code', $row);
                $successCount[$row['nonce']] = ($successCount[$row['nonce']] ?? 0) + ($row['ok'] ? 1 : 0);
                $outcomes[] = $row['code'];
            }
        }
        self::assertCount(self::WORKERS * self::POOL_SIZE, $outcomes, 'every worker must report one outcome per pool token');
        self::assertCount(self::POOL_SIZE, $successCount, 'every pool nonce must be contested');

        $unknownCodes = array_values(array_diff($outcomes, ['', 'already_consumed', 'consume_indeterminate']));
        self::assertSame([], $unknownCodes, 'every contested outcome must be a typed code, never an exception or a 500');
        foreach ($successCount as $nonce => $count) {
            self::assertSame(1, $count, "challenge $nonce must succeed exactly once under 4-way contention");
        }

        // The consume and the commit are atomic under the race: the
        // winner's deterministic result landed in the stored envelope,
        // and no claim fields or partial state survived.
        foreach (array_keys($successCount) as $nonce) {
            $data = $this->envelope($client, $prefix, $nonce);
            self::assertSame('consumed', $data['state'] ?? null, 'the record must be consumed after the race');
            self::assertIsArray($data['consumed_result'] ?? null, 'the winner must have committed the result');
            self::assertTrue($data['consumed_result']['valid'], 'the committed result must be the valid outcome');
            self::assertArrayNotHasKey('resume_owner', $data, 'no resume claim may survive the race');
            self::assertArrayNotHasKey('resume_until', $data, 'no claim expiry may survive the race');
        }
    }

    public function testLifecycleRedisCommandCountIsBoundedOnASequentialSample(): void
    {
        $client = $this->redisOrSkip();
        self::assertNotNull($client);
        $url = $this->redisUrl();
        $prefix = 'concurrency-count-'.bin2hex(random_bytes(4)).'-';

        $counting = new class($url, ['timeout' => 5.0, 'read_write_timeout' => 5.0]) extends \Predis\Client {
            /** @var list<string> */
            public array $commands = [];

            public function __call($commandID, $arguments)
            {
                $this->commands[] = strtoupper((string) $commandID);

                return parent::__call($commandID, $arguments);
            }
        };

        // Warm the per-process sha cache with one full lifecycle, so the
        // measured lifecycle never pays a `SCRIPT` `LOAD`.
        $storage = new RedisStorage($counting, $prefix);
        $config = new Config(secretKey: self::SECRET, targetBits: 8, ttlSecs: 120, minDurationMs: 0);
        $issuer = new Issuer($config, $storage);
        $warmChallenge = $issuer->issue('login', '198.51.100.7');
        $warmSalt = base64_decode($warmChallenge->salt, true);
        $warmCounter = 0;
        do {
            $warmHash = hash('sha256', $warmChallenge->prefix.$warmCounter.$warmSalt, true);
            $warmCounter++;
        } while (Verifier::leadingZeroBits($warmHash) < $warmChallenge->targetBits);
        --$warmCounter;
        $warmToken = SolutionToken::create($warmChallenge->nonce, $warmCounter, 5000, [])->encode();
        $warmOutcome = (new Verifier($storage))->verify($warmToken, self::SECRET, 'login', '198.51.100.7');
        self::assertTrue($warmOutcome->isOk(), 'the warmup lifecycle must verify');
        $counting->commands = [];

        $challenge = $issuer->issue('login', '198.51.100.7');
        self::assertSame(['SET'], $counting->commands, 'issuance must be exactly one SET with the TTL riding along');
        $counting->commands = [];

        $saltBytes = base64_decode($challenge->salt, true);
        $counter = 0;
        do {
            $hash = hash('sha256', $challenge->prefix.$counter.$saltBytes, true);
            $counter++;
        } while (Verifier::leadingZeroBits($hash) < $challenge->targetBits);
        --$counter;
        $token = SolutionToken::create($challenge->nonce, $counter, 5000, [])->encode();

        $outcome = (new Verifier($storage))->verify($token, self::SECRET, 'login', '198.51.100.7');
        self::assertTrue($outcome->isOk(), 'the sequential sample must verify');
        $commands = $counting->commands;
        self::assertCount(3, $commands, 'the happy-path verification must cost exactly three Redis round trips');
        self::assertSame(['GET', 'EVALSHA', 'EVALSHA'], $commands, 'the snapshot read, the atomic consume and the result commit');
        self::assertArrayNotHasKey('EVAL', $commands, 'the script body is never shipped on the steady-state path');
        self::assertArrayNotHasKey('SCRIPT', $commands, 'the cached sha serves the measured lifecycle');
    }
}
