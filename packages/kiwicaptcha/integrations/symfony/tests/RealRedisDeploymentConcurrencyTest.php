<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests;

use BelConsulting\KiwiCaptchaBundle\Controller\SiteVerifyController;
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
 * The deployment concurrency invariants over a shared real-Redis store.
 *
 * Issuance workers and verification workers run as separate processes,
 * all against one Redis. Every concurrently issued challenge survives
 * the race, so no update is lost. Every challenge answers exactly one
 * success under concurrent verification, the atomic consume winner.
 * No worker ever answers a 500.
 *
 * The loser vocabulary is the documented one: the timeout-or-duplicate
 * provider error on a settled replay, or the retryable internal-error
 * 503 in the atomic window.
 *
 * Runs in the real-Redis CI lane (`KC_REDIS_URL` / `TEST_REDIS_URL`).
 */
final class RealRedisDeploymentConcurrencyTest extends TestCase
{
    private const SECRET = '0123456789abcdef0123456789abcdef';

    private const SITEVERIFY_SECRET = 'compat-secret-42';

    private const ISSUERS = 4;

    private const PER_ISSUER = 6;

    private const VERIFIERS = 4;

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
            self::markTestSkipped('no Redis at the configured URL — start one for the concurrency suite');
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

    /**
     * Fork the given number of children parked on the start barrier, run
     * the child body, and wait for every child to exit. Each child writes
     * to its own result file, so a per-worker line order is preserved
     * (the barrier only staggers the start, it never interleaves files).
     *
     * @param callable(int, resource): void $body
     *
     * @return array{outFiles: list<string>, startBarrier: string}
     */
    private function forkWorkers(int $count, string $tag, callable $body): array
    {
        $base = tempnam(sys_get_temp_dir(), 'kiwi-'.$tag.'-');
        $startBarrier = tempnam(sys_get_temp_dir(), 'kiwi-'.$tag.'-start-');
        $children = [];
        $outFiles = [];
        for ($i = 0; $i < $count; $i++) {
            $outFiles[$i] = $base.'.'.$i;
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
                $out = fopen($base.'.'.$i, 'w');
                $body($i, $out);
                fclose($out);
                exit(0);
            }
            $children[] = $pid;
        }
        $barrierFile = fopen($startBarrier, 'w');
        fwrite($barrierFile, 'go');
        fclose($barrierFile);
        $crashed = $this->waitForChildren($children);
        self::assertFalse($crashed, 'every worker must exit cleanly');
        @unlink($startBarrier);
        @unlink($base);

        return ['outFiles' => $outFiles, 'startBarrier' => $startBarrier];
    }

    private function waitForChildren(array $children): bool
    {
        $crashed = false;
        foreach ($children as $pid) {
            pcntl_waitpid($pid, $status);
            if (pcntl_wexitstatus($status) !== 0) {
                $crashed = true;
            }
        }

        return $crashed;
    }

    /**
     * @return list<string> non-empty result lines
     */
    private function readLines(string $outFile): array
    {
        $raw = (string) file_get_contents($outFile);
        @unlink($outFile);

        return array_values(array_filter(explode("\n", $raw), static fn (string $l): bool => $l !== ''));
    }

    public function testConcurrentIssuanceAndVerificationWorkersOverASharedStore(): void
    {
        $probe = $this->redisOrSkip();
        if ($probe === null) {
            return;
        }

        // Phase one: concurrent issuance workers. Each worker issues its
        // own batch through its own RedisStorage over the shared server.
        $issuance = $this->forkWorkers(self::ISSUERS, 'iss', function (int $i, $out): void {
            $line = 'error';
            try {
                $client = new \Predis\Client(self::redisUrl(), ['timeout' => 10.0, 'read_write_timeout' => 10.0]);
                $storage = new RedisStorage($client);
                $issuer = new Issuer(
                    new Config(secretKey: self::SECRET, algorithm: PoWAlgorithm::Sha256, targetBits: 8, ttlSecs: 120),
                    $storage,
                );
                $lines = [];
                for ($k = 0; $k < self::PER_ISSUER; $k++) {
                    $challenge = $issuer->issue('login', '127.0.0.1');
                    $lines[] = json_encode([
                        'nonce' => $challenge->nonce,
                        'prefix' => $challenge->prefix,
                        'salt' => $challenge->salt,
                        'targetBits' => $challenge->targetBits,
                        'minDurationMs' => $challenge->minDurationMs,
                    ], JSON_THROW_ON_ERROR);
                }
                $line = implode("\n", $lines);
                $client->disconnect();
            } catch (\Throwable $e) {
                fwrite(STDERR, 'ISSUEERR: '.$e->getMessage()."\n");
            }
            fwrite($out, $line."\n");
        });

        // No lost updates: every issued nonce survives the race, distinct,
        // pending, protocol v2, and the store holds exactly the issued
        // population.
        $nonces = [];
        foreach ($issuance['outFiles'] as $outFile) {
            $issueLines = $this->readLines($outFile);
            self::assertCount(self::PER_ISSUER, $issueLines, 'an issuance worker must report its whole batch');
            foreach ($issueLines as $line) {
                $entry = json_decode($line, true);
                self::assertIsArray($entry, 'an issuance worker must report a challenge, got: '.$line);
                $nonces[] = $entry['nonce'];
            }
        }
        self::assertCount(self::ISSUERS * self::PER_ISSUER, $nonces, 'the issuance population must be complete');
        self::assertCount(self::ISSUERS * self::PER_ISSUER, array_unique($nonces), 'the issued nonces must be distinct');
        self::assertCount(self::ISSUERS * self::PER_ISSUER, $probe->keys('kiwicaptcha:*'), 'the store must hold exactly the issued population, nothing lost, nothing extra');

        // Solve every challenge in the parent (the worker tokens share one
        // fixed cost, so the race timing is deterministic).
        $tokensFile = tempnam(sys_get_temp_dir(), 'kiwi-tokens-');
        $tokens = [];
        $minDuration = 0;
        foreach ($nonces as $nonce) {
            $record = $probe->get('kiwicaptcha:'.$nonce);
            self::assertIsString($record, 'the record must survive the issuance race');
            self::assertStringContainsString('"state":"pending"', $record, 'a fresh issuance is pending, never half-written');
            self::assertStringContainsString('"protocol_version":2', $record, 'the concurrent issuance is protocol v2');
            $entry = json_decode($record, true, 8, JSON_THROW_ON_ERROR);
            $solution = $this->solveCounter($entry['prefix'], $entry['salt'], $entry['target_bits']);
            $tokens[] = SolutionToken::create($nonce, $solution, 5000, [])->encode();
            $minDuration = max($minDuration, (int) $entry['min_duration_ms']);
        }
        file_put_contents($tokensFile, implode("\n", $tokens)."\n");
        usleep(($minDuration + 10) * 1000);
        $probe->disconnect();

        // Phase two: concurrent verification workers. Every worker
        // siteverifies every token without an idempotency key, so each
        // challenge races self::VERIFIERS simultaneous redemptions.
        $verification = $this->forkWorkers(self::VERIFIERS, 'verify', function (int $i, $out) use ($tokensFile): void {
            $tokens = array_values(array_filter(explode("\n", (string) file_get_contents($tokensFile)), static fn (string $l): bool => $l !== ''));
            $client = new \Predis\Client(self::redisUrl(), ['timeout' => 30.0, 'read_write_timeout' => 30.0]);
            $storage = new RedisStorage($client);
            $controller = new SiteVerifyController(
                new Verifier($storage),
                self::SECRET,
                [self::SITEVERIFY_SECRET => 'login'],
                $storage,
            );
            $buffer = [];
            foreach ($tokens as $token) {
                try {
                    $response = $controller->siteverify($this->siteverifyRequest([
                        'secret' => self::SITEVERIFY_SECRET,
                        'response' => $token,
                        'remoteip' => '127.0.0.1',
                    ]));
                    $buffer[] = $response->getStatusCode().':'.$response->getContent();
                } catch (\Throwable $e) {
                    $buffer[] = 'error:'.$e->getMessage();
                }
            }
            $client->disconnect();
            fwrite($out, implode("\n", $buffer)."\n");
        });
        @unlink($tokensFile);

        // Worker files keep the token order, so line j of every worker
        // answers challenge j. Exactly one success per challenge, the
        // atomic consume winner, and the documented loser vocabulary.
        $perWorker = [];
        foreach ($verification['outFiles'] as $outFile) {
            $lines = $this->readLines($outFile);
            self::assertCount(self::ISSUERS * self::PER_ISSUER, $lines, 'every verification worker must report every challenge');
            $perWorker[] = $lines;
        }
        $challengeCount = self::ISSUERS * self::PER_ISSUER;
        for ($j = 0; $j < $challengeCount; $j++) {
            $outcomes = [];
            foreach ($perWorker as $lines) {
                $line = $lines[$j];
                self::assertMatchesRegularExpression('/^(200|503|error):/', $line, 'an outcome line must be a status line, got: '.$line);
                self::assertFalse(str_starts_with($line, '500'), 'a 500 must never escape the concurrent deployment: '.$line);
                [$status, $body] = explode(':', $line, 2);
                $outcomes[] = [$status, $body];
            }
            $successes = \count(array_filter($outcomes, static fn (array $o): bool => $o[0] === '200' && str_contains($o[1], '"success":true')));
            self::assertSame(
                1,
                $successes,
                sprintf('exactly one success per challenge; challenge %d had %d of %d (outcomes %s)', $j, $successes, \count($outcomes), implode(' || ', array_column($outcomes, 1))),
            );
            foreach ($outcomes as [$status, $body]) {
                if ($status === '200' && str_contains($body, '"success":true')) {
                    continue;
                }
                if ($status === '503') {
                    self::assertStringContainsString('internal-error', $body, 'the atomic-window loser is the retryable internal-error');
                } else {
                    self::assertStringContainsString('timeout-or-duplicate', $body, 'the settled replay loser is the timeout-or-duplicate provider error');
                }
            }
        }

        // Every challenge ends consumed exactly once with the committed
        // valid result: one logical redemption per challenge.
        $check = new \Predis\Client(self::redisUrl(), ['timeout' => 10.0, 'read_write_timeout' => 10.0]);
        $checkStorage = new RedisStorage($check);
        foreach ($nonces as $nonce) {
            $consumed = $checkStorage->consumedState($nonce);
            self::assertNotNull($consumed, 'every raced challenge must end in the retained consumed state');
            self::assertNotNull($consumed->consumedResult, 'every winner must commit the deterministic result');
            self::assertTrue($consumed->consumedResult->valid, 'every committed result is the valid success');
        }
        $check->disconnect();
    }
}
