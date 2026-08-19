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
use KiwiCaptcha\Storage\ArrayStorage;
use KiwiCaptcha\Storage\RedisStorage;
use KiwiCaptcha\Verifier;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;

/**
 * Strict single-use under concurrency. Siteverify's one-success contract
 * is only as strong as the storage's consume() transition. On a
 * NON-ATOMIC backend (e.g. a PSR-6 pool) two racing requests can both
 * observe pending, both win `consumedNow`, and both return success:true —
 * the container refuses that combination at compile time. On RedisStorage
 * the Lua transition guarantees exactly one `consumedNow` winner; this
 * test proves it end-to-end with 100 REAL concurrent processes hammering
 * the SAME valid token.
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
     * Provider retry contract — 100 CONCURRENT requests with
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
        $backendId = hash('sha256', self::SITEVERIFY_SECRET.'|login|0');
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
     * Provider retry contract under a DELIBERATELY
     * SLOW Argon solve — 20 concurrent requests with the same token and
     * the same UUID must ALL receive the identical canonical response
     * (the PENDING_SAME wait follows the owner to completion instead of
     * re-deriving) with exactly one redemption. The lease
     * loop makes the wait structural: the test's elapsed time stays under
     * the bound because the waiters POLL the store instead of each
     * re-deriving the Argon proof (20 re-derivations at ~5-15s each would
     * blow the bound), and the challenge record ends consumed exactly once
     * with the winner's committed result.
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
        $backendId = hash('sha256', self::SITEVERIFY_SECRET.'|login|0');
        $probe->del('{kiwicaptcha}:siteverify-idem:'.$backendId.':'.$uuid);
        $probe->disconnect();

        $outFile = tempnam(sys_get_temp_dir(), 'kiwi-idem-slow-');
        $startBarrier = tempnam(sys_get_temp_dir(), 'kiwi-idem-slow-start-');
        $workers = 20;
        $children = [];
        $startedAt = microtime(true);
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
        $elapsed = microtime(true) - $startedAt;
        self::assertFalse($crashed, 'every worker must exit cleanly');
        $raw = (string) file_get_contents($outFile);
        $responses = array_values(array_filter(explode("\n", $raw), static fn (string $l): bool => $l !== ''));
        @unlink($outFile);
        @unlink($startBarrier);

        self::assertCount($workers, $responses, 'all workers must report an outcome');
        $successes = \count(array_filter($responses, static fn (string $r): bool => str_contains($r, '"success":true')));
        self::assertSame($workers, $successes, 'same-key retries must all succeed: '.implode(' || ', array_slice($responses, 0, 3)));
        self::assertSame(1, \count(array_unique($responses)), 'all responses must be byte-identical');
        // The waiters must NOT re-derive the Argon proof —
        // 20 re-derivations at ~5-15s each would take ~100-300s. Bounded
        // elapsed time is the proof they polled the store instead.
        self::assertLessThan(
            90.0,
            $elapsed,
            sprintf('waiters must wait on the store instead of each re-deriving the Argon proof; elapsed %.1fs', $elapsed),
        );
        // Exactly ONE redemption: the winner's consume left the record
        // consumed with its committed valid result.
        $check = new \Predis\Client('tcp://127.0.0.1:6399', ['timeout' => 2.0, 'read_write_timeout' => 2.0]);
        $record = $check->get('kiwicaptcha:'.$challenge->nonce);
        $check->disconnect();
        self::assertIsString($record, 'the winner must leave the challenge record in place (consumed, not deleted)');
        self::assertStringContainsString('"state":"consumed"', $record, 'the winner must consume the token exactly once');
        self::assertStringContainsString('"consumed_result":{"valid":true', $record, 'the winner must commit its valid result for replay safety');
    }


    /**
     * The lease WINDOW covers the verification window without any
     * process-global timer: the owner verifies with a consume() that
     * sleeps 6s under the DEFAULT lease (60s), and a second request
     * fired mid-verification must wait for the stored result
     * (PendingSame — the takeover gate inside the lease stays closed)
     * instead of taking over or verifying itself. Both responses are
     * byte-identical and the token is consumed exactly once.
     */
    public function testOwnershipLeaseCoversTheVerificationWindow(): void
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
        $uuid = 'b1c2d3e4-5f6a-4b7c-8d9e-0f1a2b3c4d5e';
        $backendId = hash('sha256', self::SITEVERIFY_SECRET.'|login|0');
        $probe->del('{kiwicaptcha}:siteverify-idem:'.$backendId.':'.$uuid);

        // A storage whose consume() blocks 6s inside the verifier — a
        // window far inside the DEFAULT 60s lease, during which the
        // takeover gate must stay closed.
        $issuer = new Issuer(new Config(secretKey: self::SECRET, algorithm: PoWAlgorithm::Sha256, targetBits: 8, ttlSecs: 120), new RedisStorage($probe));
        $challenge = $issuer->issue('login', '127.0.0.1');
        $solution = $this->solveSolution($challenge);
        usleep(($challenge->minDurationMs + 10) * 1000);
        $token = SolutionToken::create($challenge->nonce, $solution, 5000, [])->encode();
        $probe->disconnect();

        $outFile = tempnam(sys_get_temp_dir(), 'kiwi-lease-');
        $startBarrier = tempnam(sys_get_temp_dir(), 'kiwi-lease-start-');
        $owner = pcntl_fork();
        self::assertNotSame(-1, $owner);
        if ($owner === 0) {
            $fp = @fopen($startBarrier, 'r');
            if ($fp !== false) {
                flock($fp, LOCK_SH);
                fread($fp, 1);
                fclose($fp);
            }
            $line = 'error';
            try {
                $client = new \Predis\Client('tcp://127.0.0.1:6399', ['timeout' => 20.0, 'read_write_timeout' => 20.0]);
                $sleepy = new class(new RedisStorage($client)) implements \KiwiCaptcha\AtomicStorageInterface {
                    public function __construct(private readonly \KiwiCaptcha\AtomicStorageInterface $inner)
                    {
                    }

                    public function store(\KiwiCaptcha\ChallengeRecord $record): void
                    {
                        $this->inner->store($record);
                    }

                    public function find(string $nonce): ?\KiwiCaptcha\ChallengeRecord
                    {
                        return $this->inner->find($nonce);
                    }

                                public function consumedState(string $nonce): ?\KiwiCaptcha\ConsumedRecord
            {
                return null;
            }

public function consume(string $nonce): ?\KiwiCaptcha\ConsumedRecord
                    {
                        sleep(6); // the blocked-verification window
                        return $this->inner->consume($nonce);
                    }

                    public function commitResult(string $nonce, bool $valid, ?string $binding): bool
                    {
                        return $this->inner->commitResult($nonce, $valid, $binding);
                    }

                    public function delete(string $nonce): void
                    {
                        $this->inner->delete($nonce);
                    }
                };
                $controller = new SiteVerifyController(
                    new Verifier($sleepy),
                    self::SECRET,
                    [self::SITEVERIFY_SECRET => 'login'],
                    $sleepy,
                    null,
                    null,
                    new RedisSiteVerifyIdempotencyStore($client), // DEFAULT 60s lease
                );
                $response = $controller->siteverify(Request::create('/kiwi-captcha/siteverify', 'POST', [
                    'secret' => self::SITEVERIFY_SECRET, 'response' => $token, 'remoteip' => '127.0.0.1', 'idempotency_key' => $uuid,
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

        $barrierFile = fopen($startBarrier, 'w');
        fwrite($barrierFile, 'go');
        fclose($barrierFile);
        // The second request fires while the owner is INSIDE the verifier.
        sleep(3);
        $client = new \Predis\Client('tcp://127.0.0.1:6399', ['timeout' => 20.0, 'read_write_timeout' => 20.0]);
        $storage = new RedisStorage($client);
        $counting = new class($storage) implements \KiwiCaptcha\AtomicStorageInterface {
            public int $consumes = 0;

            public function __construct(private readonly \KiwiCaptcha\AtomicStorageInterface $inner)
            {
            }

            public function store(\KiwiCaptcha\ChallengeRecord $record): void
            {
                $this->inner->store($record);
            }

            public function find(string $nonce): ?\KiwiCaptcha\ChallengeRecord
            {
                return $this->inner->find($nonce);
            }

                        public function consumedState(string $nonce): ?\KiwiCaptcha\ConsumedRecord
            {
                return null;
            }

public function consume(string $nonce): ?\KiwiCaptcha\ConsumedRecord
            {
                $this->consumes++;

                return $this->inner->consume($nonce);
            }

            public function commitResult(string $nonce, bool $valid, ?string $binding): bool
            {
                return $this->inner->commitResult($nonce, $valid, $binding);
            }

            public function delete(string $nonce): void
            {
                $this->inner->delete($nonce);
            }
        };
        $waiter = new SiteVerifyController(
            new Verifier($counting),
            self::SECRET,
            [self::SITEVERIFY_SECRET => 'login'],
            $counting,
            null,
            null,
            new RedisSiteVerifyIdempotencyStore($client),
        );
        $waiterResponse = $waiter->siteverify(Request::create('/kiwi-captcha/siteverify', 'POST', [
            'secret' => self::SITEVERIFY_SECRET, 'response' => $token, 'remoteip' => '127.0.0.1', 'idempotency_key' => $uuid,
        ]));
        $client->disconnect();

        pcntl_waitpid($owner, $status);
        self::assertSame(0, pcntl_wexitstatus($status), 'the owner must exit cleanly');
        $raw = (string) file_get_contents($outFile);
        $ownerLine = trim($raw);
        @unlink($outFile);
        @unlink($startBarrier);

        $waiterBody = json_decode((string) $waiterResponse->getContent(), true);
        $ownerBody = json_decode($ownerLine, true);
        self::assertSame(true, $ownerBody['success'] ?? null, 'the owner verifies successfully: '.$ownerLine);
        self::assertSame(true, $waiterBody['success'] ?? null, 'the waiter must receive the stored canonical success, not take over');
        self::assertSame($waiterBody, $ownerBody, 'both requests observe the identical canonical result');
        self::assertSame(0, $counting->consumes, 'the waiter never entered the verifier — the 60s lease kept the takeover gate closed');

        // Exactly ONE consumption (the owner's): the challenge record
        // stays in place, consumed, with the committed valid result.
        $check = new \Predis\Client('tcp://127.0.0.1:6399', ['timeout' => 2.0, 'read_write_timeout' => 2.0]);
        $record = $check->get('kiwicaptcha:'.$challenge->nonce);
        $check->disconnect();
        self::assertIsString($record, 'the owner must leave the challenge record in place (consumed, not deleted)');
        self::assertStringContainsString('"state":"consumed"', $record, 'the token must be consumed exactly once');
        self::assertStringContainsString('"consumed_result":{"valid":true', $record, 'the owner must commit its valid result for replay safety');
    }

    /**
     * A DISPLACED owner must never return its own locally computed result:
     * with a CONFIGURABLE SHORT lease (3s) the owner's lease expires while
     * it is still inside the verifier (its consume() sleeps 6s and returns
     * null — so its LOCAL outcome is a failure), the taker wins the atomic
     * takeover and finalizes its canonical SUCCESS, and the displaced
     * owner returns the taker's stored bytes, not its local failure. The
     * taker reuses the owner's remoteip: the idempotency fingerprint
     * binds remoteip into the claim, so a different remoteip is a
     * CONFLICT by design (covered by the SiteVerifyTest fingerprint
     * cases).
     */
    public function testDisplacedOwnerReturnsAuthoritativeResultNotItsOwn(): void
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
        $uuid = 'c2d3e4f5-6a7b-4c8d-9e0f-1a2b3c4d5e6f';
        $backendId = hash('sha256', self::SITEVERIFY_SECRET.'|login|0');
        $probe->del('{kiwicaptcha}:siteverify-idem:'.$backendId.':'.$uuid);

        $issuer = new Issuer(new Config(secretKey: self::SECRET, algorithm: PoWAlgorithm::Sha256, targetBits: 8, ttlSecs: 180), new RedisStorage($probe));
        $challenge = $issuer->issue('login', '127.0.0.1');
        $solution = $this->solveSolution($challenge);
        usleep(($challenge->minDurationMs + 10) * 1000);
        $token = SolutionToken::create($challenge->nonce, $solution, 5000, [])->encode();
        $probe->disconnect();

        $outFile = tempnam(sys_get_temp_dir(), 'kiwi-disp-');
        $startBarrier = tempnam(sys_get_temp_dir(), 'kiwi-disp-start-');
        $owner = pcntl_fork();
        self::assertNotSame(-1, $owner);
        if ($owner === 0) {
            $fp = @fopen($startBarrier, 'r');
            if ($fp !== false) {
                flock($fp, LOCK_SH);
                fread($fp, 1);
                fclose($fp);
            }
            $line = 'error';
            try {
                $client = new \Predis\Client('tcp://127.0.0.1:6399', ['timeout' => 15.0, 'read_write_timeout' => 15.0]);
                $sleepy = new class(new RedisStorage($client)) implements \KiwiCaptcha\AtomicStorageInterface {
                    public function __construct(private readonly \KiwiCaptcha\AtomicStorageInterface $inner)
                    {
                    }

                    public function store(\KiwiCaptcha\ChallengeRecord $record): void
                    {
                        $this->inner->store($record);
                    }

                    public function find(string $nonce): ?\KiwiCaptcha\ChallengeRecord
                    {
                        return $this->inner->find($nonce);
                    }

                                public function consumedState(string $nonce): ?\KiwiCaptcha\ConsumedRecord
            {
                return null;
            }

public function consume(string $nonce): ?\KiwiCaptcha\ConsumedRecord
                    {
                        sleep(6); // outlasts the 3s lease
                        return null; // the owner's LOCAL outcome is a failure
                    }

                    public function commitResult(string $nonce, bool $valid, ?string $binding): bool
                    {
                        return $this->inner->commitResult($nonce, $valid, $binding);
                    }

                    public function delete(string $nonce): void
                    {
                        $this->inner->delete($nonce);
                    }
                };
                $controller = new SiteVerifyController(
                    new Verifier($sleepy),
                    self::SECRET,
                    [self::SITEVERIFY_SECRET => 'login'],
                    $sleepy,
                    null,
                    null,
                    new RedisSiteVerifyIdempotencyStore($client, 'kiwicaptcha', 3), // 3s lease
                );
                $response = $controller->siteverify(Request::create('/kiwi-captcha/siteverify', 'POST', [
                    'secret' => self::SITEVERIFY_SECRET, 'response' => $token, 'remoteip' => '127.0.0.1', 'idempotency_key' => $uuid,
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

        $barrierFile = fopen($startBarrier, 'w');
        fwrite($barrierFile, 'go');
        fclose($barrierFile);
        // After the owner's 3s lease expires (its verification sleeps 6s),
        // the taker — SAME key + token + remoteip, so the fingerprint
        // matches — wins the atomic takeover, verifies (the record is
        // still unconsumed; the owner's consume never delegated) and
        // finalizes its canonical SUCCESS.
        sleep(4);
        $client = new \Predis\Client('tcp://127.0.0.1:6399', ['timeout' => 15.0, 'read_write_timeout' => 15.0]);
        $storage = new RedisStorage($client);
        $taker = new SiteVerifyController(
            new Verifier($storage),
            self::SECRET,
            [self::SITEVERIFY_SECRET => 'login'],
            $storage,
            null,
            null,
            new RedisSiteVerifyIdempotencyStore($client, 'kiwicaptcha', 3),
        );
        $takerResponse = $taker->siteverify(Request::create('/kiwi-captcha/siteverify', 'POST', [
            'secret' => self::SITEVERIFY_SECRET, 'response' => $token, 'remoteip' => '127.0.0.1', 'idempotency_key' => $uuid,
        ]));
        $client->disconnect();

        pcntl_waitpid($owner, $status);
        self::assertSame(0, pcntl_wexitstatus($status), 'the owner must exit cleanly');
        $raw = (string) file_get_contents($outFile);
        $ownerLine = trim($raw);
        @unlink($outFile);
        @unlink($startBarrier);

        $takerBody = json_decode((string) $takerResponse->getContent(), true);
        $ownerBody = json_decode($ownerLine, true);
        self::assertSame(true, $takerBody['success'] ?? null, 'the taker verifies and finalizes its canonical success: '.(string) $takerResponse->getContent());
        self::assertSame(true, $ownerBody['success'] ?? null, 'the displaced owner must return the STORED authoritative success, not its local failure: '.$ownerLine);
        self::assertSame($takerBody, $ownerBody, "the displaced owner returns the taker's canonical result byte-for-byte");
    }

    // ── The complete finalize / takeover identity (Redis-backed) ───────

    public function testRedisFinalizeWithWrongResponseHashIsANoOp(): void
    {
        if (!\class_exists(\Predis\Client::class)) {
            self::markTestSkipped('predis/predis is not installed');
        }
        try {
            $probe = new \Predis\Client('tcp://127.0.0.1:6399', ['timeout' => 1.0, 'read_write_timeout' => 1.0]);
            $probe->ping();
        } catch (\Throwable) {
            self::markTestSkipped('no Redis at 127.0.0.1:6399');
        }
        $store = new RedisSiteVerifyIdempotencyStore($probe);
        $backendId = hash('sha256', self::SITEVERIFY_SECRET.'|login|0');
        $uuid = 'd1e2f3a4-5b6c-4d7e-8f90-a1b2c3d4e5f6';
        $key = '{kiwicaptcha}:siteverify-idem:'.$backendId.':'.$uuid;
        $probe->del($key);
        try {
            [$claim, $owner] = $store->claim($backendId, $uuid, 'hash-a', 300, 'ip:127.0.0.1');
            self::assertSame(\BelConsulting\KiwiCaptchaBundle\SiteVerify\IdempotencyClaim::Claimed, $claim);
            self::assertNotNull($owner);

            // The correct owner with a WRONG response hash: atomic no-op,
            // the entry stays pending.
            $store->finalize($backendId, $uuid, 'hash-b', $owner, ['success' => true]);
            self::assertNull($store->stored($backendId, $uuid), 'a wrong-hash finalize must not complete the entry');

            // The correct owner WITH the correct hash completes the entry.
            $store->finalize($backendId, $uuid, 'hash-a', $owner, ['success' => true]);
            self::assertSame(['success' => true], $store->stored($backendId, $uuid));
        } finally {
            $probe->del($key);
        }
    }

    public function testRedisTakeoverWithWrongRemoteipFingerprintIsRefused(): void
    {
        if (!\class_exists(\Predis\Client::class)) {
            self::markTestSkipped('predis/predis is not installed');
        }
        try {
            $probe = new \Predis\Client('tcp://127.0.0.1:6399', ['timeout' => 1.0, 'read_write_timeout' => 1.0]);
            $probe->ping();
        } catch (\Throwable) {
            self::markTestSkipped('no Redis at 127.0.0.1:6399');
        }
        // A 1-second lease makes the expiry instant in the test.
        $store = new RedisSiteVerifyIdempotencyStore($probe, 'kiwicaptcha', 1);
        $backendId = hash('sha256', self::SITEVERIFY_SECRET.'|login|0');
        $uuid = 'e2f3a4b5-6c7d-4e8f-90a1-b2c3d4e5f6a7';
        $key = '{kiwicaptcha}:siteverify-idem:'.$backendId.':'.$uuid;
        $probe->del($key);
        try {
            [$claim] = $store->claim($backendId, $uuid, 'hash-a', 300, 'ip:127.0.0.1');
            self::assertSame(\BelConsulting\KiwiCaptchaBundle\SiteVerify\IdempotencyClaim::Claimed, $claim);

            // Wait out the 1s lease (redis TIME is the lease clock; the
            // integer-second `>=` boundary keeps the lease held through
            // the second after expiry).
            usleep(2_500_000);
            [$wrong] = $store->takeover($backendId, $uuid, 'hash-a', 300, 'ip:203.0.113.9');
            self::assertSame(\BelConsulting\KiwiCaptchaBundle\SiteVerify\IdempotencyClaim::StillPending, $wrong, 'a different remoteip fingerprint must never take over');

            [$right] = $store->takeover($backendId, $uuid, 'hash-a', 300, 'ip:127.0.0.1');
            self::assertSame(\BelConsulting\KiwiCaptchaBundle\SiteVerify\IdempotencyClaim::TookOver, $right);
        } finally {
            $probe->del($key);
        }
    }

    /**
     * THE decisive production-retention test: the late-token crash-recovery
     * sequence on REAL Redis. The retained consumed-state record expires at
     * token expiry with the DEFAULT ttl_margin_secs (0), so a token
     * submitted late in its lifetime has nothing to reconstruct once the
     * signed challenge expires — the production sequence fails. This test
     * constructs the RedisStorage with the retention margin EXPLICITLY
     * (>= the Siteverify PENDING_SAME waiter bound; the margin is a
     * deployment setting enforced at container compile time), issues a
     * 5-second-TTL token, lets the owner verify (committed success) and
     * "die" before the Siteverify finalize, waits past the signed expiry —
     * the record must STILL be readable — and proves the same-UUID retry
     * takes over (the FIXED owner lease is the store's configured SHORT
     * lease: 3s, with the waiter bound above it) and returns the
     * IDENTICAL canonical success via the consumed-state reconstruction.
     */
    public function testLateExpiryCrashRecoveryOnRealRedis(): void
    {
        if (!\class_exists(\Predis\Client::class)) {
            self::markTestSkipped('predis/predis is not installed');
        }
        try {
            $probe = new \Predis\Client('tcp://127.0.0.1:6399', ['timeout' => 2.0, 'read_write_timeout' => 2.0]);
            $probe->ping();
        } catch (\Throwable) {
            self::markTestSkipped('no Redis at 127.0.0.1:6399 — start one for the late-expiry crash-recovery test');
        }

        // The retention margin is constructed EXPLICITLY (ttlMarginSecs =
        // the waiter bound) so the test proves the retention behavior
        // independent of the deployment default — the local Redis has no
        // margin configured, exactly like the production default the
        // compile-time check refuses.
        $storage = new RedisStorage($probe, 'kiwicaptcha:', 0, 100, (int) SiteVerifyController::IDEMPOTENCY_WAIT_SECS);
        $issuer = new Issuer(new Config(secretKey: self::SECRET, algorithm: PoWAlgorithm::Sha256, targetBits: 8, ttlSecs: 5), $storage);
        $challenge = $issuer->issue('login', '127.0.0.1');
        $solution = $this->solveSolution($challenge);
        usleep(($challenge->minDurationMs + 10) * 1000);
        $token = SolutionToken::create($challenge->nonce, $solution, 5000, [])->encode();
        $uuid = 'f5a6b7c8-9d0e-4f1a-b234-5c6d7e8f90a1';
        $backendId = hash('sha256', self::SITEVERIFY_SECRET.'|login|0');
        $idemKey = '{kiwicaptcha}:siteverify-idem:'.$backendId.':'.$uuid;
        $probe->del([$idemKey]);

        // The "crash" seam: finalize() is a no-op for the owner, exactly
        // like a process dying between the core commit and the Siteverify
        // finalize (mirrors the ArrayStorage late-token test); everything
        // else delegates to the real Redis store.
        // A SHORT fixed store lease (3s) makes the takeover quick; the
        // waiter bound (5s) exceeds it (the construction invariant).
        $idempotencyStore = new RedisSiteVerifyIdempotencyStore($probe, 'kiwicaptcha', 3);
        $crashingStore = new class($idempotencyStore) implements \BelConsulting\KiwiCaptchaBundle\SiteVerify\SiteVerifyIdempotencyStore {
            public function __construct(private readonly \BelConsulting\KiwiCaptchaBundle\SiteVerify\SiteVerifyIdempotencyStore $inner)
            {
            }

            public function leaseSeconds(): int
            {
                return $this->inner->leaseSeconds();
            }

            public function claim(string $backendId, string $idempotencyKey, string $responseHash, int $ttlSeconds, string $remoteipFingerprint, ?int $leaseSeconds = null): array
            {
                return $this->inner->claim($backendId, $idempotencyKey, $responseHash, $ttlSeconds, $remoteipFingerprint, $leaseSeconds);
            }

            public function takeover(string $backendId, string $idempotencyKey, string $responseHash, int $ttlSeconds, string $remoteipFingerprint, ?int $leaseSeconds = null): array
            {
                return $this->inner->takeover($backendId, $idempotencyKey, $responseHash, $ttlSeconds, $remoteipFingerprint, $leaseSeconds);
            }

            public function renew(string $backendId, string $idempotencyKey, string $owner): bool
            {
                return $this->inner->renew($backendId, $idempotencyKey, $owner);
            }

            public function finalize(string $backendId, string $idempotencyKey, string $responseHash, string $owner, array $canonicalResponse): void
            {
                // The owner's finalize never lands (process death).
            }

            public function stored(string $backendId, string $idempotencyKey): ?array
            {
                return $this->inner->stored($backendId, $idempotencyKey);
            }
        };

        try {
            // The owner claims, verifies (committed success — the Claimed
            // path records the owner's fingerprint as the consumed record's
            // operation identity) and "dies" WITHOUT finalizing.
            $owner = new SiteVerifyController(new Verifier($storage), self::SECRET, [self::SITEVERIFY_SECRET => 'login'], $storage, null, null, $crashingStore, null, 5.0);
            $ownerResponse = $owner->siteverify(Request::create('/kiwi-captcha/siteverify', 'POST', [
                'secret' => self::SITEVERIFY_SECRET, 'response' => $token, 'remoteip' => '127.0.0.1', 'idempotency_key' => $uuid,
            ]));
            $ownerBody = json_decode((string) $ownerResponse->getContent(), true);
            self::assertSame(true, $ownerBody['success'] ?? null, 'the owner verifies the token and commits its success: '.(string) $ownerResponse->getContent());
            self::assertNull($crashingStore->stored($backendId, $uuid), 'the owner crashed before the Siteverify finalize');

            // Wait past the signed expiry (ttl 5s) and the fixed 3s lease.
            sleep(7);

            // The retained consumed-state record must STILL exist: the
            // explicit retention margin keeps it readable through the
            // recovery path AFTER the signed expiry.
            $consumed = $storage->consumedState($challenge->nonce);
            self::assertNotNull($consumed, 'the consumed-state record must still be readable after the signed expiry (ttl_margin_secs retention)');
            self::assertNotNull($consumed->consumedResult, 'the committed outcome must be readable');
            self::assertSame(true, $consumed->consumedResult->valid, 'the committed outcome must be the owner success');
            self::assertSame(
                hash('sha256', $backendId."\0".$uuid."\0".hash('sha256', $token)."\0"."ip:127.0.0.1"),
                $consumed->operationIdentity,
                'the consumed record carries the ACTUAL atomic consume winner\'s identity on real Redis',
            );

            // The same-UUID retry takes over the expired lease and returns
            // the IDENTICAL canonical success via reconstruction — a fresh
            // verification would now answer Expired (timeout-or-duplicate).
            // The retry's fingerprint equals the consumed record's identity
            // (the SAME logical operation), so the takeover is
            // recovery-eligible.
            $retry = new SiteVerifyController(new Verifier($storage), self::SECRET, [self::SITEVERIFY_SECRET => 'login'], $storage, null, null, $crashingStore, null, 5.0);
            $retryResponse = $retry->siteverify(Request::create('/kiwi-captcha/siteverify', 'POST', [
                'secret' => self::SITEVERIFY_SECRET, 'response' => $token, 'remoteip' => '127.0.0.1', 'idempotency_key' => $uuid,
            ]));
            $retryBody = json_decode((string) $retryResponse->getContent(), true);
            self::assertSame(true, $retryBody['success'] ?? null, 'the retry must reconstruct the ORIGINAL committed success after the signed expiry: '.(string) $retryResponse->getContent());
            self::assertSame($ownerBody, $retryBody, 'the retry returns the IDENTICAL canonical success via reconstruction');
        } finally {
            $probe->del([$idemKey]);
        }
    }

    /**
     * A Redis outage on the idempotency CLAIM (a raw store operation) must
     * degrade to the retryable provider error (503 internal-error), never
     * escape as a 500. The storage is pointed at a CLOSED port with a short
     * connection timeout, so the failure is fast and deterministic; when
     * the local environment cannot open the closed-port scenario (the port
     * is occupied), the test is skipped.
     */
    public function testDisconnectedRedisIdempotentSiteverifyReturnsInternalError(): void
    {
        $probe = @fsockopen('127.0.0.1', 6398, $errno, $errstr, 0.2);
        if (\is_resource($probe)) {
            fclose($probe);
            self::markTestSkipped('port 6398 is occupied — the closed-port scenario is unavailable; nothing to connect-refuse');
        }
        if (!\class_exists(\Predis\Client::class)) {
            self::markTestSkipped('predis/predis is not installed');
        }

        // The token is issued against an in-memory storage (the token is
        // self-contained and decodes with the secret key alone); the
        // Siteverify storage is then a Redis client pointed at the CLOSED
        // port, so the idempotency claim hits the outage deterministically.
        $array = new ArrayStorage();
        $issuer = new Issuer(new Config(secretKey: self::SECRET, algorithm: PoWAlgorithm::Sha256, targetBits: 8, ttlSecs: 120), $array);
        $challenge = $issuer->issue('login', '127.0.0.1');
        $solution = $this->solveSolution($challenge);
        usleep(($challenge->minDurationMs + 10) * 1000);
        $token = SolutionToken::create($challenge->nonce, $solution, 5000, [])->encode();

        $dead = new \Predis\Client('tcp://127.0.0.1:6398', ['timeout' => 0.2, 'read_write_timeout' => 0.2]);
        $deadStorage = new RedisStorage($dead);
        $controller = new SiteVerifyController(
            new Verifier($deadStorage),
            self::SECRET,
            [self::SITEVERIFY_SECRET => 'login'],
            $deadStorage,
            null,
            null,
            new RedisSiteVerifyIdempotencyStore($dead),
        );

        $response = $controller->siteverify(Request::create('/kiwi-captcha/siteverify', 'POST', [
            'secret' => self::SITEVERIFY_SECRET,
            'response' => $token,
            'remoteip' => '127.0.0.1',
            'idempotency_key' => '6a7b8c9d-0e1f-4a2b-8c3d-4e5f6a7b8c9d',
        ]));
        self::assertSame(503, $response->getStatusCode(), 'a Redis outage on the idempotency claim must map to 503, never a 500');
        self::assertSame(['internal-error'], json_decode((string) $response->getContent(), true)['error-codes']);
    }

    /**
     * THE decisive regression on REAL Redis (mirror of the Array-store
     * decisive test): a used token must NEVER become successful again
     * through a different idempotency UUID. UUID A redeems the token and
     * its fingerprint is recorded in the consumed record ATOMICALLY with
     * the pending→consumed transition; a replay under UUID B is
     * timeout-or-duplicate and its claim is FINALIZED as CompleteSame;
     * after B's owner lease expires (a SHORT 3s configured lease + a real
     * sleep), the retry with B must STILL be timeout-or-duplicate — the
     * stored duplicate is returned immediately and the entry can never be
     * reconstructed as a success.
     */
    public function testRealRedisDifferentUuidForAConsumedTokenCanNeverBecomeSuccessfulAgain(): void
    {
        if (!\class_exists(\Predis\Client::class)) {
            self::markTestSkipped('predis/predis is not installed');
        }
        try {
            $probe = new \Predis\Client('tcp://127.0.0.1:6399', ['timeout' => 2.0, 'read_write_timeout' => 2.0]);
            $probe->ping();
        } catch (\Throwable) {
            self::markTestSkipped('no Redis at 127.0.0.1:6399 — start one for the consumed-record identity regression test');
        }

        $storage = new RedisStorage($probe);
        $issuer = new Issuer(new Config(secretKey: self::SECRET, algorithm: PoWAlgorithm::Sha256, targetBits: 8, ttlSecs: 120), $storage);
        $challenge = $issuer->issue('login', '127.0.0.1');
        $solution = $this->solveSolution($challenge);
        usleep(($challenge->minDurationMs + 10) * 1000);
        $token = SolutionToken::create($challenge->nonce, $solution, 5000, [])->encode();
        $uuidA = 'b8c9d0e1-2f3a-4b5c-8d9e-0f1a2b3c4d5e';
        $uuidB = 'c9d0e1f2-3a4b-4c5d-9e0f-1a2b3c4d5e6f';
        $backendId = hash('sha256', self::SITEVERIFY_SECRET.'|login|0');
        $idemKeyA = '{kiwicaptcha}:siteverify-idem:'.$backendId.':'.$uuidA;
        $idemKeyB = '{kiwicaptcha}:siteverify-idem:'.$backendId.':'.$uuidB;
        $probe->del([$idemKeyA, $idemKeyB]);

        try {
            // A SHORT fixed store lease (3s) with a waiter bound above it
            // (5s — the construction invariant) keeps the lease-expiry
            // step fast. The operation identity rides in the consumed
            // runtime state on the SAME real Redis.
            $store = new RedisSiteVerifyIdempotencyStore($probe, 'kiwicaptcha', 3);
            $controller = new SiteVerifyController(new Verifier($storage), self::SECRET, [self::SITEVERIFY_SECRET => 'login'], $storage, null, null, $store, null, 5.0);

            // 1. The ORIGINAL logical operation: UUID A redeems the token.
            $first = json_decode((string) $controller->siteverify(Request::create('/kiwi-captcha/siteverify', 'POST', [
                'secret' => self::SITEVERIFY_SECRET, 'response' => $token, 'remoteip' => '127.0.0.1', 'idempotency_key' => $uuidA,
            ]))->getContent(), true);
            self::assertSame(true, $first['success'] ?? null);
            $consumed = $storage->consumedState($challenge->nonce);
            self::assertNotNull($consumed);
            self::assertSame(
                hash('sha256', $backendId."\0".$uuidA."\0".hash('sha256', $token)."\0"."ip:127.0.0.1"),
                $consumed->operationIdentity,
                'the consumed record must carry A\'s operation identity (the ACTUAL atomic consume winner)',
            );

            // 2. UUID B is a DIFFERENT logical operation: timeout-or-
            // duplicate, AND its claim is FINALIZED as CompleteSame.
            $second = json_decode((string) $controller->siteverify(Request::create('/kiwi-captcha/siteverify', 'POST', [
                'secret' => self::SITEVERIFY_SECRET, 'response' => $token, 'remoteip' => '127.0.0.1', 'idempotency_key' => $uuidB,
            ]))->getContent(), true);
            self::assertSame(false, $second['success'] ?? null);
            self::assertSame(['timeout-or-duplicate'], $second['error-codes'] ?? null);
            $storedB = $store->stored($backendId, $uuidB);
            self::assertIsArray($storedB, 'the duplicate-detecting claim must be finalized as CompleteSame');
            self::assertSame(['timeout-or-duplicate'], $storedB['error-codes'] ?? null);

            // 3. B's owner lease expires (the defect window: a pending
            // entry could otherwise be taken over and reconstructed).
            sleep(4);

            // 4. The retry with UUID B must STILL be timeout-or-duplicate.
            $retry = json_decode((string) $controller->siteverify(Request::create('/kiwi-captcha/siteverify', 'POST', [
                'secret' => self::SITEVERIFY_SECRET, 'response' => $token, 'remoteip' => '127.0.0.1', 'idempotency_key' => $uuidB,
            ]))->getContent(), true);
            self::assertSame(false, $retry['success'] ?? null, 'a consumed token must NEVER become successful again through a different idempotency UUID');
            self::assertSame(['timeout-or-duplicate'], $retry['error-codes'] ?? null);
        } finally {
            $probe->del([$idemKeyA, $idemKeyB]);
        }
    }

    // ── The consumed-record identity gate: decisive tails (real Redis) ──

    /**
     * REAL-REDIS tail of the no-key-first-redemption regression: the
     * token is validated with NO idempotency key (the consumed record's
     * identity stays null); a later keyed replay under UUID B claims a
     * FRESH entry and cannot register itself as the original (the record
     * is already consumed, so B's identity-bearing consume is a no-op).
     * After B's lease expires and B takes over, the record's identity
     * (null) can never equal B's fingerprint — timeout-or-duplicate.
     */
    public function testRealRedisFirstRedemptionWithoutAKeyThenKeyedReplayCanNeverReconstruct(): void
    {
        if (!\class_exists(\Predis\Client::class)) {
            self::markTestSkipped('predis/predis is not installed');
        }
        try {
            $probe = new \Predis\Client('tcp://127.0.0.1:6399', ['timeout' => 2.0, 'read_write_timeout' => 2.0]);
            $probe->ping();
        } catch (\Throwable) {
            self::markTestSkipped('no Redis at 127.0.0.1:6399');
        }

        $storage = new RedisStorage($probe);
        $issuer = new Issuer(new Config(secretKey: self::SECRET, algorithm: PoWAlgorithm::Sha256, targetBits: 8, ttlSecs: 120), $storage);
        $challenge = $issuer->issue('login', '127.0.0.1');
        $solution = $this->solveSolution($challenge);
        usleep(($challenge->minDurationMs + 10) * 1000);
        $token = SolutionToken::create($challenge->nonce, $solution, 5000, [])->encode();
        $uuidB = 'd0e1f2a3-4b5c-4d6e-9f0a-1b2c3d4e5f6a';
        $backendId = hash('sha256', self::SITEVERIFY_SECRET.'|login|0');
        $idemKeyB = '{kiwicaptcha}:siteverify-idem:'.$backendId.':'.$uuidB;
        $probe->del([$idemKeyB]);

        try {
            $idempotencyStore = new RedisSiteVerifyIdempotencyStore($probe, 'kiwicaptcha', 3);
            // The "crash" seam: finalize() never lands, so the keyed
            // replay's claim stays PENDING (the takeover window stays
            // open).
            $crashingStore = new class($idempotencyStore) implements \BelConsulting\KiwiCaptchaBundle\SiteVerify\SiteVerifyIdempotencyStore {
                public function __construct(private readonly \BelConsulting\KiwiCaptchaBundle\SiteVerify\SiteVerifyIdempotencyStore $inner)
                {
                }

                public function leaseSeconds(): int
                {
                    return $this->inner->leaseSeconds();
                }

                public function claim(string $backendId, string $idempotencyKey, string $responseHash, int $ttlSeconds, string $remoteipFingerprint, ?int $leaseSeconds = null): array
                {
                    return $this->inner->claim($backendId, $idempotencyKey, $responseHash, $ttlSeconds, $remoteipFingerprint, $leaseSeconds);
                }

                public function takeover(string $backendId, string $idempotencyKey, string $responseHash, int $ttlSeconds, string $remoteipFingerprint, ?int $leaseSeconds = null): array
                {
                    return $this->inner->takeover($backendId, $idempotencyKey, $responseHash, $ttlSeconds, $remoteipFingerprint, $leaseSeconds);
                }

                public function renew(string $backendId, string $idempotencyKey, string $owner): bool
                {
                    return $this->inner->renew($backendId, $idempotencyKey, $owner);
                }

                public function finalize(string $backendId, string $idempotencyKey, string $responseHash, string $owner, array $canonicalResponse): void
                {
                    // The finalize never lands (crash window).
                }

                public function stored(string $backendId, string $idempotencyKey): ?array
                {
                    return $this->inner->stored($backendId, $idempotencyKey);
                }
            };
            $controller = new SiteVerifyController(new Verifier($storage), self::SECRET, [self::SITEVERIFY_SECRET => 'login'], $storage, null, null, $crashingStore, null, 5.0);

            // 1. The FIRST redemption has NO idempotency key: success, and
            //    NO identity is recorded.
            $first = json_decode((string) $controller->siteverify(Request::create('/kiwi-captcha/siteverify', 'POST', [
                'secret' => self::SITEVERIFY_SECRET, 'response' => $token, 'remoteip' => '127.0.0.1',
            ]))->getContent(), true);
            self::assertSame(true, $first['success'] ?? null);
            $consumed = $storage->consumedState($challenge->nonce);
            self::assertNotNull($consumed);
            self::assertNull($consumed->operationIdentity, 'a no-key first redemption records NO operation identity');

            // 2. The keyed replay under UUID B: fresh claim, duplicate,
            //    finalize crashed -> claim B stays PENDING.
            $second = json_decode((string) $controller->siteverify(Request::create('/kiwi-captcha/siteverify', 'POST', [
                'secret' => self::SITEVERIFY_SECRET, 'response' => $token, 'remoteip' => '127.0.0.1', 'idempotency_key' => $uuidB,
            ]))->getContent(), true);
            self::assertSame(false, $second['success'] ?? null);
            self::assertSame(['timeout-or-duplicate'], $second['error-codes'] ?? null);
            self::assertNull($idempotencyStore->stored($backendId, $uuidB), 'the replay finalize crashed — claim B stays pending');

            // 3. B's lease expires (the SHORT 3s configured lease).
            sleep(4);

            // 4. The retry with B takes over its own pending claim — the
            //    consumed record's identity is NULL, never B's fingerprint:
            //    no reconstruction, timeout-or-duplicate.
            $retry = json_decode((string) $controller->siteverify(Request::create('/kiwi-captcha/siteverify', 'POST', [
                'secret' => self::SITEVERIFY_SECRET, 'response' => $token, 'remoteip' => '127.0.0.1', 'idempotency_key' => $uuidB,
            ]))->getContent(), true);
            self::assertSame(false, $retry['success'] ?? null, 'a keyed replay of a no-key redemption must NEVER reconstruct a success');
            self::assertSame(['timeout-or-duplicate'], $retry['error-codes'] ?? null);
        } finally {
            $probe->del([$idemKeyB]);
        }
    }

    /**
     * REAL-REDIS tail of the same-scope-backend-secrets regression: the
     * ORIGINAL redemption runs via secret 1 (same scope 'login'); a retry
     * with the SAME token + SAME UUID via secret 2 claims a FRESH entry
     * (the idempotency store is namespaced by backendId), detects the
     * duplicate, and its finalize crashes. After the lease expires the
     * retry takes over — but the backendId is inside the fingerprint, so
     * secret-2's fingerprint differs from the consumed record's identity
     * (secret 1's): the takeover MUST NOT reconstruct.
     */
    public function testRealRedisTwoSameScopeBackendSecretsCanNeverReconstruct(): void
    {
        if (!\class_exists(\Predis\Client::class)) {
            self::markTestSkipped('predis/predis is not installed');
        }
        try {
            $probe = new \Predis\Client('tcp://127.0.0.1:6399', ['timeout' => 2.0, 'read_write_timeout' => 2.0]);
            $probe->ping();
        } catch (\Throwable) {
            self::markTestSkipped('no Redis at 127.0.0.1:6399');
        }

        $storage = new RedisStorage($probe);
        $issuer = new Issuer(new Config(secretKey: self::SECRET, algorithm: PoWAlgorithm::Sha256, targetBits: 8, ttlSecs: 120), $storage);
        $challenge = $issuer->issue('login', '127.0.0.1');
        $solution = $this->solveSolution($challenge);
        usleep(($challenge->minDurationMs + 10) * 1000);
        $token = SolutionToken::create($challenge->nonce, $solution, 5000, [])->encode();
        $secret1 = 'secret-one-'.str_repeat('a', 16);
        $secret2 = 'secret-two-'.str_repeat('b', 16);
        $uuid = 'e1f2a3b4-5c6d-4e7f-8a90-1b2c3d4e5f6b';
        $backendId1 = hash('sha256', $secret1.'|login|0');
        $backendId2 = hash('sha256', $secret2.'|login|0');
        $idemKey1 = '{kiwicaptcha}:siteverify-idem:'.$backendId1.':'.$uuid;
        $idemKey2 = '{kiwicaptcha}:siteverify-idem:'.$backendId2.':'.$uuid;
        $probe->del([$idemKey1, $idemKey2]);

        try {
            $idempotencyStore = new RedisSiteVerifyIdempotencyStore($probe, 'kiwicaptcha', 3);
            $crashingStore = new class($idempotencyStore) implements \BelConsulting\KiwiCaptchaBundle\SiteVerify\SiteVerifyIdempotencyStore {
                public function __construct(private readonly \BelConsulting\KiwiCaptchaBundle\SiteVerify\SiteVerifyIdempotencyStore $inner)
                {
                }

                public function leaseSeconds(): int
                {
                    return $this->inner->leaseSeconds();
                }

                public function claim(string $backendId, string $idempotencyKey, string $responseHash, int $ttlSeconds, string $remoteipFingerprint, ?int $leaseSeconds = null): array
                {
                    return $this->inner->claim($backendId, $idempotencyKey, $responseHash, $ttlSeconds, $remoteipFingerprint, $leaseSeconds);
                }

                public function takeover(string $backendId, string $idempotencyKey, string $responseHash, int $ttlSeconds, string $remoteipFingerprint, ?int $leaseSeconds = null): array
                {
                    return $this->inner->takeover($backendId, $idempotencyKey, $responseHash, $ttlSeconds, $remoteipFingerprint, $leaseSeconds);
                }

                public function renew(string $backendId, string $idempotencyKey, string $owner): bool
                {
                    return $this->inner->renew($backendId, $idempotencyKey, $owner);
                }

                public function finalize(string $backendId, string $idempotencyKey, string $responseHash, string $owner, array $canonicalResponse): void
                {
                    // The finalize never lands (crash window).
                }

                public function stored(string $backendId, string $idempotencyKey): ?array
                {
                    return $this->inner->stored($backendId, $idempotencyKey);
                }
            };
            $controller1 = new SiteVerifyController(new Verifier($storage), self::SECRET, [$secret1 => 'login'], $storage, null, null, $crashingStore, null, 5.0);
            $controller2 = new SiteVerifyController(new Verifier($storage), self::SECRET, [$secret2 => 'login'], $storage, null, null, $crashingStore, null, 5.0);

            // 1. The ORIGINAL redemption via secret 1: the identity-bearing
            //    consume records secret-1's fingerprint.
            $first = json_decode((string) $controller1->siteverify(Request::create('/kiwi-captcha/siteverify', 'POST', [
                'secret' => $secret1, 'response' => $token, 'remoteip' => '127.0.0.1', 'idempotency_key' => $uuid,
            ]))->getContent(), true);
            self::assertSame(true, $first['success'] ?? null);
            $consumed = $storage->consumedState($challenge->nonce);
            self::assertNotNull($consumed);
            self::assertSame(
                hash('sha256', $backendId1."\0".$uuid."\0".hash('sha256', $token)."\0"."ip:127.0.0.1"),
                $consumed->operationIdentity,
                'the consumed record carries secret-1\'s fingerprint (the backendId is inside it)',
            );

            // 2. The SAME token + SAME UUID via secret 2: fresh entry in
            //    secret-2's namespace, duplicate, finalize crashed.
            $second = json_decode((string) $controller2->siteverify(Request::create('/kiwi-captcha/siteverify', 'POST', [
                'secret' => $secret2, 'response' => $token, 'remoteip' => '127.0.0.1', 'idempotency_key' => $uuid,
            ]))->getContent(), true);
            self::assertSame(false, $second['success'] ?? null);
            self::assertSame(['timeout-or-duplicate'], $second['error-codes'] ?? null);
            self::assertNull($idempotencyStore->stored($backendId2, $uuid), 'the secret-2 finalize crashed — its claim stays pending');

            // 3. The lease expires while secret-2's entry is pending.
            sleep(4);

            // 4. The retry via secret 2 takes over its own pending claim —
            //    the fingerprint binds the backendId, so it differs from
            //    the consumed record's identity: MUST NOT reconstruct.
            $retry = json_decode((string) $controller2->siteverify(Request::create('/kiwi-captcha/siteverify', 'POST', [
                'secret' => $secret2, 'response' => $token, 'remoteip' => '127.0.0.1', 'idempotency_key' => $uuid,
            ]))->getContent(), true);
            self::assertSame(false, $retry['success'] ?? null, 'a same-scope backend secret can never reconstruct another backend\'s redemption');
            self::assertSame(['timeout-or-duplicate'], $retry['error-codes'] ?? null);
        } finally {
            $probe->del([$idemKey1, $idemKey2]);
        }
    }

    /**
     * THE decisive concurrency tail on REAL Redis: TWO CONCURRENT
     * DIFFERENT UUIDs race the same token (50 workers each, forked).
     * Only ONE wins the atomic pending→consumed transition — the
     * consumed record's operation identity MUST equal the WINNER's
     * fingerprint (the identity is written in the SAME Lua splice as the
     * state flip). The loser's takeover (after the lease expires) MUST
     * NOT reconstruct: its fingerprint differs from the record's identity
     * → timeout-or-duplicate.
     */
    public function testRealRedisTwoConcurrentDifferentUuidsOnlyTheAtomicWinnerRecordsItsIdentity(): void
    {
        if (!\function_exists('pcntl_fork')) {
            self::markTestSkipped('pcntl is not installed; cannot fork concurrent verifications');
        }
        if (!\class_exists(\Predis\Client::class)) {
            self::markTestSkipped('predis/predis is not installed');
        }
        try {
            $probe = new \Predis\Client('tcp://127.0.0.1:6399', ['timeout' => 2.0, 'read_write_timeout' => 2.0]);
            $probe->ping();
        } catch (\Throwable) {
            self::markTestSkipped('no Redis at 127.0.0.1:6399');
        }

        $issuer = new Issuer(
            new Config(secretKey: self::SECRET, algorithm: PoWAlgorithm::Sha256, targetBits: 8, ttlSecs: 120),
            new RedisStorage($probe),
        );
        $challenge = $issuer->issue('login', '127.0.0.1');
        $solution = $this->solveSolution($challenge);
        usleep(($challenge->minDurationMs + 10) * 1000);
        $token = SolutionToken::create($challenge->nonce, $solution, 5000, [])->encode();
        $uuidA = 'a1b2c3d4-5e6f-4a7b-8c9d-0e1f2a3b4c5d';
        $uuidB = 'b2c3d4e5-6f7a-4b8c-9d0e-1f2a3b4c5d6e';
        $backendId = hash('sha256', self::SITEVERIFY_SECRET.'|login|0');
        $idemKeyA = '{kiwicaptcha}:siteverify-idem:'.$backendId.':'.$uuidA;
        $idemKeyB = '{kiwicaptcha}:siteverify-idem:'.$backendId.':'.$uuidB;
        $probe->del([$idemKeyA, $idemKeyB]);
        $probe->disconnect();

        $outFile = tempnam(sys_get_temp_dir(), 'kiwi-two-uuid-');
        $startBarrier = tempnam(sys_get_temp_dir(), 'kiwi-two-uuid-start-');

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
                    $client = new \Predis\Client('tcp://127.0.0.1:6399', ['timeout' => 5.0, 'read_write_timeout' => 5.0]);
                    $storage = new RedisStorage($client);
                    $idempotencyStore = new RedisSiteVerifyIdempotencyStore($client, 'kiwicaptcha', 3);
                    // The "crash" seam: finalize() never lands, so the
                    // LOSER's claim stays PENDING — the takeover window
                    // stays open for the decisive tail below.
                    $crashingStore = new class($idempotencyStore) implements \BelConsulting\KiwiCaptchaBundle\SiteVerify\SiteVerifyIdempotencyStore {
                        public function __construct(private readonly \BelConsulting\KiwiCaptchaBundle\SiteVerify\SiteVerifyIdempotencyStore $inner)
                        {
                        }

                        public function leaseSeconds(): int
                        {
                            return $this->inner->leaseSeconds();
                        }

                        public function claim(string $backendId, string $idempotencyKey, string $responseHash, int $ttlSeconds, string $remoteipFingerprint, ?int $leaseSeconds = null): array
                        {
                            return $this->inner->claim($backendId, $idempotencyKey, $responseHash, $ttlSeconds, $remoteipFingerprint, $leaseSeconds);
                        }

                        public function takeover(string $backendId, string $idempotencyKey, string $responseHash, int $ttlSeconds, string $remoteipFingerprint, ?int $leaseSeconds = null): array
                        {
                            return $this->inner->takeover($backendId, $idempotencyKey, $responseHash, $ttlSeconds, $remoteipFingerprint, $leaseSeconds);
                        }

                        public function renew(string $backendId, string $idempotencyKey, string $owner): bool
                        {
                            return $this->inner->renew($backendId, $idempotencyKey, $owner);
                        }

                        public function finalize(string $backendId, string $idempotencyKey, string $responseHash, string $owner, array $canonicalResponse): void
                        {
                            // The finalize never lands (crash window).
                        }

                        public function stored(string $backendId, string $idempotencyKey): ?array
                        {
                            return $this->inner->stored($backendId, $idempotencyKey);
                        }
                    };
                    $controller = new SiteVerifyController(
                        new Verifier($storage),
                        self::SECRET,
                        [self::SITEVERIFY_SECRET => 'login'],
                        $storage,
                        null,
                        null,
                        $crashingStore,
                        null,
                        5.0,
                    );
                    // Split the workers between TWO different UUIDs.
                    $uuid = ($i % 2 === 0) ? $uuidA : $uuidB;
                    $response = $controller->siteverify(Request::create('/kiwi-captcha/siteverify', 'POST', [
                        'secret' => self::SITEVERIFY_SECRET,
                        'response' => $token,
                        'remoteip' => '127.0.0.1',
                        'idempotency_key' => $uuid,
                    ]));
                    $body = json_decode($response->getContent() ?: '{}', true);
                    $line = (($body['success'] ?? false) === true ? 'success:'.$uuid : ($body['error-codes'][0] ?? 'error'));
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
        $results = array_values(array_filter(explode("\n", $raw), static fn (string $l): bool => $l !== ''));
        @unlink($outFile);
        @unlink($startBarrier);

        self::assertCount($workers, $results, 'all 100 workers must report an outcome');
        // EXACTLY ONE logical redemption wins the atomic consume; a
        // same-UUID waiter may additionally RECONSTRUCT that success via
        // the identity gate (the crash seam never finalizes, so its
        // takeover is the intended recovery path) — but EVERY success
        // must belong to the SAME UUID (the atomic consume winner's
        // logical operation), and the OTHER UUID must have ZERO
        // successes.
        $successLines = array_values(array_filter($results, static fn (string $r): bool => str_starts_with($r, 'success:')));
        self::assertGreaterThanOrEqual(1, \count($successLines), 'the atomic consume winner must succeed: '.implode(',', array_slice($results, 0, 10)));
        self::assertLessThanOrEqual(2, \count($successLines), 'only the fresh winner + at most one same-UUID reconstruction may succeed: '.implode(',', $results));
        $successUuids = array_values(array_unique(array_map(static fn (string $r): string => substr($r, 8), $successLines)));
        self::assertCount(1, $successUuids, 'all successes must belong to ONE UUID — the loser UUID can never succeed: '.implode(',', $results));

        // The consumed record's identity MUST equal the WINNER's
        // fingerprint — the identity is written atomically with the
        // pending→consumed transition, so the pre-verification claim
        // winner cannot claim an identity it did not win.
        $check = new \Predis\Client('tcp://127.0.0.1:6399', ['timeout' => 2.0, 'read_write_timeout' => 2.0]);
        $storage = new RedisStorage($check);
        $consumed = $storage->consumedState($challenge->nonce);
        self::assertNotNull($consumed, 'the winner must leave the challenge record in place (consumed, not deleted)');
        self::assertNotNull($consumed->consumedResult, 'the winner must commit its result');
        $fingerprintA = hash('sha256', $backendId."\0".$uuidA."\0".hash('sha256', $token)."\0"."ip:127.0.0.1");
        $fingerprintB = hash('sha256', $backendId."\0".$uuidB."\0".hash('sha256', $token)."\0"."ip:127.0.0.1");
        self::assertContains($consumed->operationIdentity, [$fingerprintA, $fingerprintB], 'the consumed record must carry the WINNER\'s fingerprint');
        $winnerUuid = $consumed->operationIdentity === $fingerprintA ? $uuidA : $uuidB;
        $loserUuid = $winnerUuid === $uuidA ? $uuidB : $uuidA;
        self::assertSame($winnerUuid, $successUuids[0], 'the successful UUID must be the record\'s identity owner (the ACTUAL atomic consume winner)');

        // The lease expires while BOTH entries are STILL PENDING (the
        // crash seam never finalizes): each retry takes over its own
        // claim. The WINNER's retry reconstructs (its fingerprint equals
        // the record's identity); the LOSER's retry MUST NOT reconstruct
        // (its fingerprint differs) — timeout-or-duplicate.
        sleep(4);
        $idempotencyStore = new RedisSiteVerifyIdempotencyStore($check, 'kiwicaptcha', 3);
        $retryController = new SiteVerifyController(new Verifier($storage), self::SECRET, [self::SITEVERIFY_SECRET => 'login'], $storage, null, null, $idempotencyStore, null, 5.0);
        $winnerRetry = json_decode((string) $retryController->siteverify(Request::create('/kiwi-captcha/siteverify', 'POST', [
            'secret' => self::SITEVERIFY_SECRET, 'response' => $token, 'remoteip' => '127.0.0.1', 'idempotency_key' => $winnerUuid,
        ]))->getContent(), true);
        self::assertSame(true, $winnerRetry['success'] ?? null, 'the WINNER\'s takeover reconstructs its own committed outcome');
        $loserRetry = json_decode((string) $retryController->siteverify(Request::create('/kiwi-captcha/siteverify', 'POST', [
            'secret' => self::SITEVERIFY_SECRET, 'response' => $token, 'remoteip' => '127.0.0.1', 'idempotency_key' => $loserUuid,
        ]))->getContent(), true);
        self::assertSame(false, $loserRetry['success'] ?? null, 'the LOSER\'s takeover must NEVER reconstruct the winner\'s success: '.(string) json_encode($loserRetry));
        self::assertSame(['timeout-or-duplicate'], $loserRetry['error-codes'] ?? null);

        $check->del([$idemKeyA, $idemKeyB]);
        $check->disconnect();
    }
}

