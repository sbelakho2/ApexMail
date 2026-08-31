<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests;

use BelConsulting\KiwiCaptchaBundle\Risk\ChainedChallengeTicketService;
use BelConsulting\KiwiCaptchaBundle\Risk\RedisChainedChallengeStateStore;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\RedisTestUrl;
use KiwiCaptcha\Risk\RiskAction;
use PHPUnit\Framework\TestCase;

/**
 * Chained-challenge state under concurrent redemption over real Redis.
 *
 * One ticket, one stage-2 nonce, and many concurrent redeemers: the
 * reservation, the mint and the Pass are three separate Lua
 * transitions, so only the atomic store can decide the winner. The
 * invariant under the race: exactly one fresh mint, exactly one
 * verified Pass, every other outcome from the documented transition
 * vocabulary, and the terminal state verified with the obligation
 * cleared. The sequential model-walk harness cannot express
 * concurrency, so this is a targeted real-Redis process race.
 *
 * Runs in the real-Redis CI lane (`KC_REDIS_URL` / `TEST_REDIS_URL`).
 */
final class RealRedisChainedConcurrencyTest extends TestCase
{
    private const SECRET = '0123456789abcdef0123456789abcdef';

    private const NAMESPACE = 'ci-chain-concurrency';

    private const REDEEMERS = 8;

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
            self::markTestSkipped('pcntl is not installed; cannot fork concurrent redeemers');
        }
        if (!\class_exists(\Predis\Client::class)) {
            self::markTestSkipped('predis/predis is not installed');
        }
        try {
            $probe = new \Predis\Client(self::redisUrl(), ['timeout' => 5.0, 'read_write_timeout' => 5.0]);
            $probe->ping();
        } catch (\Throwable) {
            self::markTestSkipped('no Redis at the configured URL — start one for the chained concurrency suite');
        }
        $probe->flushdb();

        return $probe;
    }

    /** A deterministic Kiwi-shaped stage-2 nonce for a seed. */
    private function stageNonce(string $seed): string
    {
        return base64_encode(hash('sha256', 'chain-race:'.$seed, true));
    }

    public function testOneTicketManyConcurrentRedeemersExactlyOneSuccess(): void
    {
        $probe = $this->redisOrSkip();
        if ($probe === null) {
            return;
        }

        // The parent creates the obligation and the chain, then hands the
        // chain id and the single stage-2 nonce to every redeemer.
        $store = new RedisChainedChallengeStateStore($probe, self::NAMESPACE);
        $service = new ChainedChallengeTicketService($store, self::SECRET, 300, 15);
        $stage1 = $this->stageNonce('stage1');
        $stage2 = $this->stageNonce('stage2');
        $requirement = $service->requireStage2($stage1, 'login', 'txn-race', 1, RiskAction::Sha16, time() + 300);
        $obligationId = $service->obligationIdFor('login', 'txn-race', 1);
        $paramsFile = tempnam(sys_get_temp_dir(), 'kiwi-chain-race-');
        file_put_contents($paramsFile, json_encode([
            'chainId' => $requirement->chainId,
            'stage2' => $stage2,
            'obligationId' => $obligationId,
        ], JSON_THROW_ON_ERROR)."\n");
        $probe->disconnect();

        $base = tempnam(sys_get_temp_dir(), 'kiwi-chain-out-');
        $startBarrier = tempnam(sys_get_temp_dir(), 'kiwi-chain-start-');
        $children = [];
        $outFiles = [];
        for ($w = 0; $w < self::REDEEMERS; $w++) {
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
                $params = json_decode(trim((string) file_get_contents($paramsFile)), true, 8, JSON_THROW_ON_ERROR);
                $line = 'error';
                try {
                    $client = new \Predis\Client(self::redisUrl(), ['timeout' => 15.0, 'read_write_timeout' => 15.0]);
                    $raceStore = new RedisChainedChallengeStateStore($client, self::NAMESPACE);
                    $owner = 'owner-race-'.$w;
                    $reserved = $raceStore->reserve($params['chainId'], $owner, 15);
                    $issued = $raceStore->markIssued($params['chainId'], $owner, $params['stage2']);
                    $verified = $raceStore->markVerified($params['chainId'], $params['stage2']);
                    $line = 'r='.$reserved.'|i='.$issued.'|v='.$verified;
                    $client->disconnect();
                } catch (\Throwable $e) {
                    fwrite(STDERR, 'CHAINRACEERR: '.$e->getMessage()."\n");
                }
                file_put_contents($base.'.'.$w, $line."\n");
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
        self::assertFalse($crashed, 'every redeemer must exit cleanly');
        @unlink($startBarrier);
        @unlink($base);
        @unlink($paramsFile);

        // The outcome vocabulary is the documented transition set; the
        // race never produces an error, a corrupt reply, or a second
        // winner.
        $reserveVocabulary = ['available', 'retry', 'busy', 'taken_over', 'issued', 'verified', 'completed', 'step_up_required', 'denied', 'missing'];
        $issueVocabulary = ['issued_new', 'issued_same', 'verified_same', 'conflict', 'not_owner', 'missing'];
        $verifyVocabulary = ['verified_new', 'verified_same', 'conflict', 'missing'];
        $issuedNew = 0;
        $verifiedNew = 0;
        foreach ($outFiles as $outFile) {
            $line = trim((string) file_get_contents($outFile));
            @unlink($outFile);
            self::assertMatchesRegularExpression('/^r=(\w+)\|i=(\w+)\|v=(\w+)$/D', $line, 'a redeemer must report its transition outcomes, got: '.$line);
            preg_match('/^r=(\w+)\|i=(\w+)\|v=(\w+)$/D', $line, $m);
            self::assertContains($m[1], $reserveVocabulary, 'the reservation outcome is from the documented set: '.$line);
            self::assertContains($m[2], $issueVocabulary, 'the issuance outcome is from the documented set: '.$line);
            self::assertContains($m[3], $verifyVocabulary, 'the verification outcome is from the documented set: '.$line);
            if ($m[2] === 'issued_new') {
                $issuedNew++;
            }
            if ($m[3] === 'verified_new') {
                $verifiedNew++;
            }
        }
        self::assertSame(1, $issuedNew, 'exactly one fresh mint under the race');
        self::assertSame(1, $verifiedNew, 'exactly one verified Pass under the race');

        // The terminal consistency: the chain ends verified and the
        // obligation mapping is gone, exactly once.
        $check = new \Predis\Client(self::redisUrl(), ['timeout' => 10.0, 'read_write_timeout' => 10.0]);
        try {
            $checkStore = new RedisChainedChallengeStateStore($check, self::NAMESPACE);
            $state = $checkStore->read($requirement->chainId);
            self::assertIsArray($state, 'the chain record must survive the race');
            self::assertSame('verified', $state['state'], 'the terminal state after the race is verified');
            self::assertSame($stage2, $state['stage2Nonce'], 'the verified record carries the single stage-2 nonce');
            self::assertNull($checkStore->obligationChainId($obligationId), 'the Pass cleared the obligation exactly once');
            $checkService = new ChainedChallengeTicketService($checkStore, self::SECRET, 300, 15);
            self::assertNull($checkService->findOpenRequirement('login', 'txn-race', 1), 'no open obligation remains after the race');
        } finally {
            $check->disconnect();
        }
    }
}
