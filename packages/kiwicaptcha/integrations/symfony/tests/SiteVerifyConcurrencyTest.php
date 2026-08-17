<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests;

use BelConsulting\KiwiCaptchaBundle\Controller\SiteVerifyController;
use BelConsulting\KiwiCaptchaBundle\SiteVerify\RedisSiteVerifyIdempotencyStore;
use KiwiCaptcha\Challenge;
use KiwiCaptcha\Config;
use KiwiCaptcha\Issuer;
use KiwiCaptcha\PoWAlgorithm;
use KiwiCaptcha\SolutionToken;
use KiwiCaptcha\Storage\RedisStorage;
use KiwiCaptcha\Verifier;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;

/**
 * Round 28 (P1): strict single-use under concurrency. Siteverify's
 * one-success contract is only as strong as the storage's consume()
 * transition. On a NON-ATOMIC backend (e.g. a PSR-6 pool) two racing
 * requests can both observe pending, both win `consumedNow`, and both
 * return success:true — the container refuses that combination at compile
 * time. On RedisStorage the Lua transition guarantees exactly one
 * `consumedNow` winner; this test proves it end-to-end with 100 REAL
 * concurrent processes hammering the SAME valid token.
 */
final class SiteVerifyConcurrencyTest extends TestCase
{
    private const SECRET = '0123456789abcdef0123456789abcdef';
    private const SITEVERIFY_SECRET = 'compat-secret-42';

    public function testOneHundredSimultaneousSiteverifyCallsSameTokenYieldsExactlyOneSuccess(): void
    {
        if (!\function_exists('pcntl_fork')) {
            self::markTestSkipped('pcntl is not installed; cannot fork concurrent verifications');
        }
        if (!\class_exists(\Predis\Client::class)) {
            self::markTestSkipped('predis/predis is not installed');
        }
        try {
            $probe = new \Predis\Client('tcp://127.0.0.1:6399', ['timeout' => 1.0, 'read_write_timeout' => 1.0]);
            $probe->ping();
        } catch (\Throwable) {
            self::markTestSkipped('no Redis at 127.0.0.1:6399 — start one for the concurrency test');
        }

        // One shared valid token, solved once, reused by all 100 racers.
        $issuer = new Issuer(
            new Config(secretKey: self::SECRET, algorithm: PoWAlgorithm::Sha256, targetBits: 8, ttlSecs: 120),
            new RedisStorage($probe),
        );
        $challenge = $issuer->issue('login', '127.0.0.1');
        $solution = $this->solveSolution($challenge);
        $token = SolutionToken::create($challenge->nonce, $solution, 5000, [])->encode();
        $probe->disconnect();

        $outFile = tempnam(sys_get_temp_dir(), 'kiwi-race-');
        $startBarrier = tempnam(sys_get_temp_dir(), 'kiwi-race-start-');

        $workers = 100;
        $children = [];
        for ($i = 0; $i < $workers; $i++) {
            $pid = pcntl_fork();
            if ($pid === -1) {
                self::markTestSkipped('pcntl_fork failed; concurrency test not run');
            }
            if ($pid === 0) {
                // Child: park on the barrier so all 100 hit Redis together.
                $fp = @fopen($startBarrier, 'r');
                if ($fp !== false) {
                    flock($fp, LOCK_SH);
                    fread($fp, 1);
                    fclose($fp);
                }
                $success = '0';
                try {
                    $client = new \Predis\Client('tcp://127.0.0.1:6399', ['timeout' => 2.0, 'read_write_timeout' => 2.0]);
                    $storage = new RedisStorage($client);
                    $controller = new SiteVerifyController(
                        new Verifier($storage),
                        self::SECRET,
                        [self::SITEVERIFY_SECRET => 'login'],
                        $storage,
                    );
                    $response = $controller->siteverify(Request::create('/kiwi-captcha/siteverify', 'POST', [
                        'secret' => self::SITEVERIFY_SECRET,
                        'response' => $token,
                        'remoteip' => '127.0.0.1',
                    ]));
                    $body = json_decode($response->getContent() ?: '{}', true);
                    $success = ($body['success'] ?? false) === true ? '1' : '0';
                    $client->disconnect();
                } catch (\Throwable $e) {
                    fwrite(STDERR, 'CHILDERR: '.$e->getMessage()."\n");
                }
                $out = fopen($outFile, 'a');
                flock($out, LOCK_EX);
                fwrite($out, $success."\n");
                fclose($out);
                exit(0);
            }
            $children[] = $pid;
        }

        // Release the barrier once every child is parked on it.
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
        self::assertFalse($crashed, 'every worker must exit cleanly');

        $raw = (string) file_get_contents($outFile);
        $results = array_values(array_filter(explode("\n", $raw), static fn (string $l): bool => $l !== ''));
        @unlink($outFile);
        @unlink($startBarrier);

        self::assertCount($workers, $results, 'all 100 workers must report an outcome');
        $successes = \count(array_filter($results, static fn (string $r): bool => $r === '1'));
        self::assertSame(
            1,
            $successes,
            sprintf('exactly ONE success expected; got %d of %d (results: %s)', $successes, \count($results), implode(',', $results)),
        );
        self::assertSame($workers - 1, \count($results) - $successes, 'the other 99 must be timeout-or-duplicate / indeterminate');
    }

    private function solveSolution(Challenge $challenge): int
    {
        $saltBytes = base64_decode($challenge->salt, true);
        $counter = 0;
        do {
            $hash = hash('sha256', $challenge->prefix.$counter.$saltBytes, true);
            $counter++;
        } while (Verifier::leadingZeroBits($hash) < $challenge->targetBits);

        return $counter - 1;
    }

    /**
     * Round 30 (P1): provider retry contract — 100 CONCURRENT requests with
     * the SAME valid token and the SAME idempotency UUID must ALL receive
     * the IDENTICAL canonical success response, with only ONE logical
     * redemption. This is a SEPARATE contract from the native single-use
     * race above: ordinary replays (no key) still produce exactly one
     * success.
     */
    public function testOneHundredConcurrentSameIdempotencyKeyYieldsIdenticalResponses(): void
    {
        if (!\function_exists('pcntl_fork')) {
            self::markTestSkipped('pcntl is not installed; cannot fork concurrent verifications');
        }
        if (!\class_exists(\Predis\Client::class)) {
            self::markTestSkipped('predis/predis is not installed');
        }
        try {
            $probe = new \Predis\Client('tcp://127.0.0.1:6399', ['timeout' => 1.0, 'read_write_timeout' => 1.0]);
            $probe->ping();
        } catch (\Throwable) {
            self::markTestSkipped('no Redis at 127.0.0.1:6399 — start one for the concurrency test');
        }

        $issuer = new Issuer(
            new Config(secretKey: self::SECRET, algorithm: PoWAlgorithm::Sha256, targetBits: 8, ttlSecs: 120),
            new RedisStorage($probe),
        );
        $challenge = $issuer->issue('login', '127.0.0.1');
        $solution = $this->solveSolution($challenge);
        $token = SolutionToken::create($challenge->nonce, $solution, 5000, [])->encode();
        $uuid = 'f47ac10b-58cc-4372-a567-0e02b2c3d479';
        // Flush any leftover idempotency entry from a previous run (the
        // UUID + backend namespace must start clean for the race).
        $backendId = hash('sha256', self::SITEVERIFY_SECRET);
        $probe->del('{kiwicaptcha}:siteverify-idem:'.$backendId.':'.$uuid);
        $probe->disconnect();

        $outFile = tempnam(sys_get_temp_dir(), 'kiwi-idem-');
        $startBarrier = tempnam(sys_get_temp_dir(), 'kiwi-idem-start-');

        $workers = 100;
        $children = [];
        for ($i = 0; $i < $workers; $i++) {
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
                $line = 'error';
                try {
                    $client = new \Predis\Client('tcp://127.0.0.1:6399', ['timeout' => 15.0, 'read_write_timeout' => 15.0]);
                    $storage = new RedisStorage($client);
                    $controller = new SiteVerifyController(
                        new Verifier($storage),
                        self::SECRET,
                        [self::SITEVERIFY_SECRET => 'login'],
                        $storage,
                        null,
                        null,
                        new RedisSiteVerifyIdempotencyStore($client),
                    );
                    $response = $controller->siteverify(Request::create('/kiwi-captcha/siteverify', 'POST', [
                        'secret' => self::SITEVERIFY_SECRET,
                        'response' => $token,
                        'remoteip' => '127.0.0.1',
                        'idempotency_key' => $uuid,
                    ]));
                    $line = (string) $response->getContent();
                    $client->disconnect();
                } catch (\Throwable $e) {
                    fwrite(STDERR, 'child error: '.$e->getMessage()."\n");
                }
                $out = fopen($outFile, 'a');
                flock($out, LOCK_EX);
                fwrite($out, $line."\n");
                fclose($out);
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
        self::assertFalse($crashed, 'every worker must exit cleanly');

        $raw = (string) file_get_contents($outFile);
        $responses = array_values(array_filter(explode("\n", $raw), static fn (string $l): bool => $l !== ''));
        @unlink($outFile);
        @unlink($startBarrier);

        self::assertCount($workers, $responses, 'all 100 workers must report an outcome');
        $successes = \count(array_filter($responses, static fn (string $r): bool => str_contains($r, '"success":true')));
        self::assertSame($workers, $successes, 'with the SAME idempotency key every retry must succeed: '.implode(' || ', array_slice($responses, 0, 5)));
        // ALL responses byte-identical (canonical provider response).
        $unique = \count(array_unique($responses));
        self::assertSame(1, $unique, 'all 100 responses must be the IDENTICAL canonical JSON: '.implode(' || ', array_slice($responses, 0, 3)));
        $first = json_decode($responses[0], true);
        self::assertSame([], $first['error-codes'] ?? null);
    }


    /**
     * Round 31 (item 12): provider retry contract under a DELIBERATELY
     * SLOW Argon solve — 20 concurrent requests with the same token and
     * the same UUID must ALL receive the identical canonical response
     * (the PENDING_SAME wait follows the owner to completion instead of
     * re-deriving) with exactly one redemption.
     */
    public function testSlowArgonSameIdempotencyKeyYieldsIdenticalResponses(): void
    {
        if (!\function_exists('pcntl_fork') || !\class_exists(\Predis\Client::class)) {
            self::markTestSkipped('pcntl/predis not available');
        }
        try {
            $probe = new \Predis\Client('tcp://127.0.0.1:6399', ['timeout' => 2.0, 'read_write_timeout' => 2.0]);
            $probe->ping();
        } catch (\Throwable) {
            self::markTestSkipped('no Redis at 127.0.0.1:6399');
        }

        // Argon2id with a deliberately high verification cost: the winner's
        // verification takes seconds — exactly the window where a short
        // PENDING_SAME wait would fall through.
        $config = new Config(
            secretKey: self::SECRET,
            algorithm: PoWAlgorithm::Argon2id,
            ttlSecs: 180,
            mKib: 64,
            t: 3,
            p: 1,
            targetBits: 8,
            argon2TargetBits: 10,
        );
        $issuer = new Issuer($config, new RedisStorage($probe));
        $challenge = $issuer->issue('login', '127.0.0.1');
        $saltBytes = base64_decode($challenge->salt, true);
        $counter = 0;
        do {
            $h = sodium_crypto_pwhash(32, $challenge->prefix.$counter, $saltBytes, 3, 64 * 1024, SODIUM_CRYPTO_PWHASH_ALG_ARGON2ID13);
            $counter++;
        } while (Verifier::leadingZeroBits($h) < $challenge->targetBits);
        usleep(($challenge->minDurationMs + 10) * 1000);
        $token = SolutionToken::create($challenge->nonce, $counter - 1, 5000, [])->encode();
        $uuid = 'a7c2c4a0-9f4b-4d1e-9c8a-0f3d5e7b1a2b';
        $backendId = hash('sha256', self::SITEVERIFY_SECRET);
        $probe->del('{kiwicaptcha}:siteverify-idem:'.$backendId.':'.$uuid);
        $probe->disconnect();

        $outFile = tempnam(sys_get_temp_dir(), 'kiwi-idem-slow-');
        $startBarrier = tempnam(sys_get_temp_dir(), 'kiwi-idem-slow-start-');
        $workers = 20;
        $children = [];
        for ($i = 0; $i < $workers; $i++) {
            $pid = pcntl_fork();
            if ($pid === -1) {
                self::markTestSkipped('pcntl_fork failed');
            }
            if ($pid === 0) {
                $fp = @fopen($startBarrier, 'r');
                if ($fp !== false) {
                    flock($fp, LOCK_SH);
                    fread($fp, 1);
                    fclose($fp);
                }
                $line = 'error';
                try {
                    $client = new \Predis\Client('tcp://127.0.0.1:6399', ['timeout' => 60.0, 'read_write_timeout' => 60.0]);
                    $storage = new RedisStorage($client);
                    $controller = new SiteVerifyController(
                        new Verifier($storage),
                        self::SECRET,
                        [self::SITEVERIFY_SECRET => 'login'],
                        $storage,
                        null,
                        null,
                        new RedisSiteVerifyIdempotencyStore($client),
                    );
                    $response = $controller->siteverify(Request::create('/kiwi-captcha/siteverify', 'POST', [
                        'secret' => self::SITEVERIFY_SECRET,
                        'response' => $token,
                        'remoteip' => '127.0.0.1',
                        'idempotency_key' => $uuid,
                    ]));
                    $line = (string) $response->getContent();
                    $client->disconnect();
                } catch (\Throwable $e) {
                    fwrite(STDERR, 'CHILDERR: '.$e->getMessage()."\n");
                }
                $out = fopen($outFile, 'a');
                flock($out, LOCK_EX);
                fwrite($out, $line."\n");
                fclose($out);
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
        self::assertFalse($crashed, 'every worker must exit cleanly');
        $raw = (string) file_get_contents($outFile);
        $responses = array_values(array_filter(explode("\n", $raw), static fn (string $l): bool => $l !== ''));
        @unlink($outFile);
        @unlink($startBarrier);

        self::assertCount($workers, $responses, 'all workers must report an outcome');
        $successes = \count(array_filter($responses, static fn (string $r): bool => str_contains($r, '"success":true')));
        self::assertSame($workers, $successes, 'same-key retries must all succeed: '.implode(' || ', array_slice($responses, 0, 3)));
        self::assertSame(1, \count(array_unique($responses)), 'all responses must be byte-identical');
    }
}

