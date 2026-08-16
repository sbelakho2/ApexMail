<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests;

use BelConsulting\KiwiCaptchaBundle\Controller\SiteVerifyController;
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
                    fwrite(STDERR, 'child error: '.$e->getMessage()."\n");
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
}
