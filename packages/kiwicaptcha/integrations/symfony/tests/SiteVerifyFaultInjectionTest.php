<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests;

use BelConsulting\KiwiCaptchaBundle\Controller\SiteVerifyController;
use BelConsulting\KiwiCaptchaBundle\Risk\RiskGateway;
use BelConsulting\KiwiCaptchaBundle\Risk\RiskProfileResolver;
use BelConsulting\KiwiCaptchaBundle\Risk\SecurityEpochMonitor;
use BelConsulting\KiwiCaptchaBundle\SiteVerify\ArraySiteVerifyIdempotencyStore;
use BelConsulting\KiwiCaptchaBundle\SiteVerify\IdempotencyClaim;
use BelConsulting\KiwiCaptchaBundle\SiteVerify\RedisSiteVerifyIdempotencyStore;
use BelConsulting\KiwiCaptchaBundle\SiteVerify\SiteVerifyRecoveryCapableStorageInterface;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\FakePredisClient;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\FakeRiskStateStore;
use KiwiCaptcha\BindingMode;
use KiwiCaptcha\Config;
use KiwiCaptcha\Issuer;
use KiwiCaptcha\PoWAlgorithm;
use KiwiCaptcha\Risk\AdaptiveRiskEngine;
use KiwiCaptcha\Risk\Network\CidrNetworkClassifier;
use KiwiCaptcha\Risk\RiskEventKind;
use KiwiCaptcha\Risk\RiskIdentityFactory;
use KiwiCaptcha\Risk\RiskKeys;
use KiwiCaptcha\Risk\RiskPolicy;
use KiwiCaptcha\Risk\RiskScorer;
use KiwiCaptcha\SolutionToken;
use KiwiCaptcha\Storage\ArrayStorage;
use KiwiCaptcha\Storage\RedisStorage;
use KiwiCaptcha\Verifier;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;

/**
 * Fault-injection matrix for the Siteverify authorization chain: every
 * scenario injects a failure or an authorization-state change exactly at
 * the seam between two links of the chain and asserts the fail-closed
 * contract of the whole chain, not of any single component.
 *
 *  - concurrent same-token redemptions: with a shared idempotency key
 *    exactly one logical redemption happens, and every racer converges
 *    on the identical deterministic canonical outcome, never a 5xx.
 *    Without a key exactly one success answers; the rest map to the
 *    duplicate vocabulary (AlreadyConsumed -> timeout-or-duplicate, or
 *    the retryable ConsumeIndeterminate inside the atomic commit
 *    window), never a 500.
 *  - idempotency key reuse across different tokens is refused at the
 *    store (Conflict) and at the core (operation-identity mismatch),
 *    never a stale success.
 *  - a secret or security-context rotation between the claim and the
 *    finalize/recovery moves the namespace: the rotated retry can never
 *    reconstruct, and the original context's recovery still works after
 *    the rotation (isolation, never corruption).
 *  - a policy-epoch bump between two identical retries fails closed: the
 *    cached outcome never survives the bump.
 *  - the no-IP identity (binding_mode: none, remoteip omitted) is a
 *    stable claim pseudonym: the duplicate retry is recognized and an IP
 *    change conflicts.
 *  - a malformed token with an idempotency key finalizes a deterministic
 *    invalid response with the unattributable risk feedback skipped
 *    (never a 503).
 *  - an idempotent retry racing the original completion resolves to the
 *    same final outcome: the displaced owner discards its own result and
 *    returns the stored authoritative bytes, byte-identical to the
 *    takeover winner and every later observer.
 */
final class SiteVerifyFaultInjectionTest extends TestCase
{
    private const SECRET = '0123456789abcdef0123456789abcdef';
    private const SITEVERIFY_SECRET = 'compat-secret-42';

    // ── helpers ─────────────────────────────────────────────────────────

    private function controller(
        ?\BelConsulting\KiwiCaptchaBundle\SiteVerify\SiteVerifyIdempotencyStore $idempotencyStore = null,
        ?ArrayStorage $storage = null,
        float $waitSecs = 2.0,
        int $policyVersion = 0,
        ?string $securityContextDigest = null,
        ?SecurityEpochMonitor $epochMonitor = null,
        ?RiskGateway $riskGateway = null,
        array $secrets = [self::SITEVERIFY_SECRET => 'login'],
    ): SiteVerifyController {
        $storage ??= new ArrayStorage();

        return new SiteVerifyController(
            new Verifier($storage),
            self::SECRET,
            $secrets,
            $storage,
            null,
            null,
            $idempotencyStore,
            null,
            $waitSecs,
            $policyVersion,
            $securityContextDigest,
            null,
            $epochMonitor,
            null,
            null,
            null,
            riskGateway: $riskGateway,
        );
    }

    private function siteverifyRequest(array $fields, string $contentType = 'application/x-www-form-urlencoded'): Request
    {
        $body = $contentType === 'application/json' ? json_encode($fields, JSON_THROW_ON_ERROR) : http_build_query($fields);

        return Request::create('/kiwi-captcha/siteverify', 'POST', [], [], [], ['CONTENT_TYPE' => $contentType], (string) $body);
    }

    private function remoteipFingerprint(?string $remoteIp): string
    {
        $trimmed = $remoteIp !== null ? trim($remoteIp) : '';
        if ($trimmed === '') {
            return 'no-ip';
        }
        $binary = @inet_pton($trimmed);
        $canonical = null;
        if ($binary !== false) {
            if (\strlen($binary) === 16 && str_starts_with($binary, "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff")) {
                $binary = substr($binary, 12);
            }
            $canonical = (string) inet_ntop($binary);
        }
        $canonical ??= $trimmed;

        return hash_hmac('sha256', 'siteverify-idem-ip-v1|'.$canonical, self::SECRET);
    }

    /** @return array{0: string, 1: string} [solved token, nonce] */
    private function issuedToken(ArrayStorage $storage, string $scope = 'login', string $remoteIp = '127.0.0.1', ?int $policyVersion = null): array
    {
        $issuer = new Issuer(new Config(secretKey: self::SECRET, algorithm: PoWAlgorithm::Sha256, targetBits: 8, ttlSecs: 120, policyVersion: $policyVersion ?? 1, bindingMode: BindingMode::Bound), $storage);
        $challenge = $issuer->issue($scope, $remoteIp);
        $solution = $this->solve($challenge->prefix, $challenge->salt, $challenge->targetBits);
        usleep(($challenge->minDurationMs + 10) * 1000);

        return [SolutionToken::create($challenge->nonce, $solution, 5000, [])->encode(), $challenge->nonce];
    }

    private function solve(string $prefix, string $salt, int $targetBits): int
    {
        $saltBytes = base64_decode($salt, true);
        $counter = 0;
        do {
            $hash = hash('sha256', $prefix.$counter.$saltBytes, true);
            $counter++;
        } while (Verifier::leadingZeroBits($hash) < $targetBits);

        return $counter - 1;
    }

    private function solveSolution(\KiwiCaptcha\ChallengeRecord $record): string
    {
        $saltBytes = base64_decode($record->salt, true);
        $counter = 0;
        do {
            $hash = hash('sha256', $record->prefix.$counter.$saltBytes, true);
            $counter++;
        } while (Verifier::leadingZeroBits($hash) < $record->targetBits);

        return \KiwiCaptcha\SolutionToken::create($record->nonce, $counter - 1, 5000, [])->encode();
    }

    /**
     * The bundle risk stack with an in-memory fake store (the same
     * wiring as RiskIntegrationTest / SiteVerifyTest::riskStack()).
     *
     * @return array{gateway: RiskGateway, store: FakeRiskStateStore}
     */
    private function riskStack(): array
    {
        $keys = RiskKeys::fromMaster(self::SECRET);
        $identityFactory = new RiskIdentityFactory($keys);
        $classifier = new CidrNetworkClassifier([]);
        $scorer = new RiskScorer();
        $policy = RiskPolicy::fromConfig([
            'version' => RiskPolicy::CONTRACT_VERSION,
            'weights' => [],
            'scopes' => [
                1 => ['base_risk' => 100, 'minimum' => 'allow', 'post_solve_check' => false, 'degraded' => 'allow'],
            ],
        ]);
        $store = new FakeRiskStateStore();
        $engine = new AdaptiveRiskEngine($store, $classifier, $identityFactory, $scorer, $policy, $keys);
        $gateway = new RiskGateway($engine, $classifier, new RiskProfileResolver(PoWAlgorithm::Sha256, 8), ['login' => 1], policy: $policy);

        return ['gateway' => $gateway, 'store' => $store];
    }

    /** @return \Predis\Client|null null when Redis is unreachable */
    private function redisOrSkip(): ?\Predis\Client
    {
        if (!\class_exists(\Predis\Client::class)) {
            self::markTestSkipped('predis/predis is not installed');
        }
        try {
            $probe = new \Predis\Client(self::redisTestUrl(), ['timeout' => 10.0, 'read_write_timeout' => 10.0]);
            $probe->ping();

            return $probe;
        } catch (\Throwable) {
            self::markTestSkipped('no Redis at 127.0.0.1:6399 — start one for the fault-injection matrix');
        }
    }

    private static function redisTestUrl(): string
    {
        $url = \BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\RedisTestUrl::resolve();
        if ($url === null) {
            self::markTestSkipped('KC_REDIS_URL/TEST_REDIS_URL not set — the real-Redis suites run in the CI Redis-service job');
        }

        return $url;
    }

    /** @return array{0: string, 1: \KiwiCaptcha\Challenge, 2: string} [token, challenge, nonce] */
    private function issueSha(RedisStorage $storage, int $ttlSecs = 120): array
    {
        $issuer = new Issuer(new Config(secretKey: self::SECRET, algorithm: PoWAlgorithm::Sha256, targetBits: 8, ttlSecs: $ttlSecs), $storage);
        $challenge = $issuer->issue('login', '127.0.0.1');
        $saltBytes = base64_decode($challenge->salt, true);
        $counter = 0;
        do {
            $hash = hash('sha256', $challenge->prefix.$counter.$saltBytes, true);
            $counter++;
        } while (Verifier::leadingZeroBits($hash) < $challenge->targetBits);
        --$counter;
        usleep(($challenge->minDurationMs + 10) * 1000);

        return [SolutionToken::create($challenge->nonce, $counter, 5000, [])->encode(), $challenge, $challenge->nonce];
    }

    private function expectedCanonicalSuccess(RedisStorage $storage, string $nonce): string
    {
        $record = $storage->find($nonce);
        self::assertNotNull($record);

        return (string) json_encode([
            'action' => null,
            'cdata' => null,
            'challenge_ts' => gmdate('Y-m-d\TH:i:s\Z', $record->issuedAt),
            'error-codes' => [],
            'hostname' => $record->hostname,
            'success' => true,
        ], JsonResponse::DEFAULT_ENCODING_OPTIONS);
    }

    /**
     * The "lost reply" seam: consumeWithOperationIdentity() delegates to
     * the real storage — the transition executes and the identity lands
     * atomically with the state flip — and the response is then lost.
     * Everything else delegates.
     */
    private function lostConsumeReplyStorage(\KiwiCaptcha\AtomicStorageInterface $inner): SiteVerifyRecoveryCapableStorageInterface
    {
        return new class($inner) implements SiteVerifyRecoveryCapableStorageInterface {
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
                return $this->inner->consumedState($nonce);
            }

            public function consume(string $nonce): ?\KiwiCaptcha\ConsumedRecord
            {
                return $this->inner->consume($nonce);
            }

            public function consumeWithOperationIdentity(string $nonce, ?string $operationIdentity): ?\KiwiCaptcha\ConsumedRecord
            {
                // The transition executes (the identity lands atomically
                // with the state flip) — and the response is then lost.
                $this->inner->consumeWithOperationIdentity($nonce, $operationIdentity);

                throw new \RuntimeException('consume reply lost after the transition');
            }

            public function commitResult(string $nonce, bool $valid, ?string $binding): bool
            {
                return $this->inner->commitResult($nonce, $valid, $binding);
            }

            public function delete(string $nonce): void
            {
                $this->inner->delete($nonce);
            }

            public function deleteIfPending(string $nonce): \KiwiCaptcha\DeleteIfPendingResult
            {
                return $this->inner->deleteIfPending($nonce);
            }
        };
    }

    // ── 1. concurrent redemptions: same token ──────────────────────────────

    /**
     * Concurrent redemptions of the same token with the same idempotency
     * key: exactly one logical redemption happens (the atomic claim and
     * consume winners are unique). Every racer converges on the identical
     * deterministic canonical outcome — the stored bytes, never a
     * re-derivation — while no racer ever answers a 5xx or 4xx. This is
     * the keyed retry contract: the losers observe the stored result
     * through the CompleteSame/PendingSame wait, so "the others" receive
     * the deterministic duplicate outcome (the stored canonical success),
     * never a stale re-derivation and never an error status.
     */
    public function testConcurrentSameTokenSameIdempotencyKeyExactlyOneRedemptionAndDeterministicReplay(): void
    {
        if (!\function_exists('pcntl_fork')) {
            self::markTestSkipped('pcntl is not installed; cannot fork concurrent verifications');
        }
        $probe = $this->redisOrSkip();
        if ($probe === null) {
            return;
        }
        $issuer = new Issuer(
            new Config(secretKey: self::SECRET, algorithm: PoWAlgorithm::Sha256, targetBits: 8, ttlSecs: 120),
            new RedisStorage($probe),
        );
        $challenge = $issuer->issue('login', '127.0.0.1');
        $solution = $this->solve($challenge->prefix, $challenge->salt, $challenge->targetBits);
        $token = SolutionToken::create($challenge->nonce, $solution, 5000, [])->encode();
        usleep(($challenge->minDurationMs + 10) * 1000);
        $uuid = 'a1b2c3d4-1111-4a2b-8c3d-000000000001';
        $backendId = hash('sha256', self::SITEVERIFY_SECRET.'|login|0|');
        $idemKey = '{kiwicaptcha}:siteverify-idem:'.$backendId.':'.$uuid;
        $probe->del([$idemKey]);
        $probe->disconnect();

        $outFile = tempnam(sys_get_temp_dir(), 'kiwi-fi-samekey-');
        $startBarrier = tempnam(sys_get_temp_dir(), 'kiwi-fi-samekey-start-');

        $workers = 20;
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
                    $client = new \Predis\Client(self::redisTestUrl(), ['timeout' => 30.0, 'read_write_timeout' => 30.0]);
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
                        // A generous per-request waiter bound: the
                        // waiters must observe the owner's finalized
                        // outcome even when the loaded suite slows the
                        // owner's verify+finalize.
                        10.0,
                    );
                    $response = $controller->siteverify($this->siteverifyRequest([
                        'secret' => self::SITEVERIFY_SECRET,
                        'response' => $token,
                        'remoteip' => '127.0.0.1',
                        'idempotency_key' => $uuid,
                    ]));
                    $line = $response->getStatusCode().':'.$response->getContent();
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
        $lines = array_values(array_filter(explode("\n", $raw), static fn (string $l): bool => $l !== ''));
        @unlink($outFile);
        @unlink($startBarrier);

        self::assertCount($workers, $lines, 'all workers must report an outcome');
        foreach ($lines as $line) {
            self::assertMatchesRegularExpression('/^\d+:/', $line, 'a worker must report a status:content line, got: '.$line);
            self::assertStringStartsWith('200:', $line, 'a same-key racer must never answer an error status: '.$line);
        }
        $bodies = array_map(static fn (string $l): string => substr($l, 4), $lines);
        $unique = \count(array_unique($bodies));
        self::assertSame(1, $unique, 'all racers must converge on the IDENTICAL deterministic canonical outcome: '.implode(' || ', array_slice($bodies, 0, 3)));
        $body = json_decode($bodies[0], true);
        self::assertSame(true, $body['success'] ?? null, 'the deterministic outcome of a valid token is success: '.$bodies[0]);
        self::assertSame([], $body['error-codes'] ?? null);

        try {
            // Exactly ONE logical redemption: the consumed record is
            // committed once with the winner's operation identity, and the
            // idempotency entry is complete under the canonical bytes.
            $check = new \Predis\Client(self::redisTestUrl(), ['timeout' => 10.0, 'read_write_timeout' => 10.0]);
            $checkStorage = new RedisStorage($check);
            $consumed = $checkStorage->consumedState($challenge->nonce);
            self::assertNotNull($consumed, 'the token must be consumed exactly once');
            self::assertNotNull($consumed->consumedResult, 'the winner must commit the deterministic result');
            self::assertSame(true, $consumed->consumedResult->valid);
            $store = new RedisSiteVerifyIdempotencyStore($check, 'kiwicaptcha');
            $stored = $store->stored($backendId, $uuid);
            self::assertIsArray($stored, 'the idempotency entry must be complete');
            // The store's Lua round-trip (cjson decode/encode) does not
            // preserve the canonical key ordering of the stored result;
            // the wire contract is preserved by the controller, which
            // re-canonicalizes (ksort) on every stored read. Compare the
            // values order-insensitively.
            $storedSorted = $stored;
            ksort($storedSorted);
            self::assertSame($body, $storedSorted, 'the stored result must be the identical canonical outcome');
            $check->disconnect();
        } finally {
            $probe->connect();
            $probe->del([$idemKey, 'kiwicaptcha:'.$challenge->nonce]);
            $probe->disconnect();
        }
    }

    /**
     * Concurrent redemptions of the same token with NO idempotency key:
     * exactly one 200 success answers. Every other racer gets the
     * deterministic duplicate vocabulary (the core's AlreadyConsumed ->
     * provider timeout-or-duplicate). The documented atomic window is
     * the exception: a loser resolving the consumed record before the
     * winner's commit sees ConsumeIndeterminate -> the retryable 503
     * internal-error. A 500 never escapes, and a settled replay after
     * the race is timeout-or-duplicate.
     */
    public function testConcurrentSameTokenWithoutKeyExactlyOneSuccessRestTimeoutOrDuplicateNever500(): void
    {
        if (!\function_exists('pcntl_fork')) {
            self::markTestSkipped('pcntl is not installed; cannot fork concurrent verifications');
        }
        $probe = $this->redisOrSkip();
        if ($probe === null) {
            return;
        }
        $issuer = new Issuer(
            new Config(secretKey: self::SECRET, algorithm: PoWAlgorithm::Sha256, targetBits: 8, ttlSecs: 120),
            new RedisStorage($probe),
        );
        $challenge = $issuer->issue('login', '127.0.0.1');
        $solution = $this->solve($challenge->prefix, $challenge->salt, $challenge->targetBits);
        $token = SolutionToken::create($challenge->nonce, $solution, 5000, [])->encode();
        usleep(($challenge->minDurationMs + 10) * 1000);
        $probe->disconnect();

        $outFile = tempnam(sys_get_temp_dir(), 'kiwi-fi-nokey-');
        $startBarrier = tempnam(sys_get_temp_dir(), 'kiwi-fi-nokey-start-');

        $workers = 20;
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
                    $client = new \Predis\Client(self::redisTestUrl(), ['timeout' => 30.0, 'read_write_timeout' => 30.0]);
                    $storage = new RedisStorage($client);
                    $controller = new SiteVerifyController(
                        new Verifier($storage),
                        self::SECRET,
                        [self::SITEVERIFY_SECRET => 'login'],
                        $storage,
                    );
                    $response = $controller->siteverify($this->siteverifyRequest([
                        'secret' => self::SITEVERIFY_SECRET,
                        'response' => $token,
                        'remoteip' => '127.0.0.1',
                    ]));
                    $line = $response->getStatusCode().':'.$response->getContent();
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
        $lines = array_values(array_filter(explode("\n", $raw), static fn (string $l): bool => $l !== ''));
        @unlink($outFile);
        @unlink($startBarrier);

        self::assertCount($workers, $lines, 'all workers must report an outcome');
        $successes = 0;
        foreach ($lines as $line) {
            self::assertMatchesRegularExpression('/^\d+:/', $line, 'a worker must report a status:content line, got: '.$line);
            [$status, $content] = explode(':', $line, 2);
            self::assertNotSame('500', $status, 'a 500 must never escape the compatibility boundary: '.$line);
            $body = json_decode($content, true);
            if (($body['success'] ?? false) === true) {
                $successes++;
                self::assertSame('200', $status, 'the success must be a 200: '.$line);
            } else {
                // A duplicate is a deterministic 200 timeout-or-duplicate
                // (AlreadyConsumed), or — only inside the atomic
                // consume->commit window — the retryable 503
                // ConsumeIndeterminate. A duplicate must never report
                // success, and never a 500.
                self::assertFalse($body['success'] ?? null, 'a duplicate must never report success: '.$line);
                if ($status === '503') {
                    self::assertSame(['internal-error'], $body['error-codes'] ?? null, 'the only allowed 5xx is the retryable ConsumeIndeterminate internal-error: '.$line);
                } else {
                    self::assertSame('200', $status, 'a duplicate is either the deterministic 200 timeout-or-duplicate or the retryable 503: '.$line);
                    self::assertSame(['timeout-or-duplicate'], $body['error-codes'] ?? null, 'the duplicate vocabulary must be deterministic: '.$line);
                }
            }
        }
        self::assertSame(1, $successes, 'exactly ONE success must answer the no-key race');

        // A settled replay after the race answers the deterministic
        // duplicate vocabulary, never success again.
        $client = new \Predis\Client(self::redisTestUrl(), ['timeout' => 10.0, 'read_write_timeout' => 10.0]);
        $storage = new RedisStorage($client);
        $replay = (new SiteVerifyController(new Verifier($storage), self::SECRET, [self::SITEVERIFY_SECRET => 'login'], $storage))
            ->siteverify($this->siteverifyRequest([
                'secret' => self::SITEVERIFY_SECRET,
                'response' => $token,
                'remoteip' => '127.0.0.1',
            ]));
        $replayBody = json_decode((string) $replay->getContent(), true);
        self::assertSame(200, $replay->getStatusCode());
        self::assertFalse($replayBody['success'] ?? null);
        self::assertSame(['timeout-or-duplicate'], $replayBody['error-codes'] ?? null);
        $client->del(['kiwicaptcha:'.$challenge->nonce]);
        $client->disconnect();
    }

    // ── 2. idempotency key reuse across different tokens ────────────────────

    /**
     * The same idempotency key funded by token A and then presented with
     * token B is refused at the store (Conflict -> 400) — token B stays
     * untouched, the stored success of A is never returned. When token B
     * was already consumed under a different key, a fresh key presenting
     * it is refused at the core instead: the consumed record's own
     * operation identity does not match the new fingerprint, so the
     * duplicate vocabulary answers. A stale success never surfaces.
     */
    public function testIdempotencyKeyReuseAcrossDifferentTokensIsRefusedNeverAStaleSuccess(): void
    {
        $probe = $this->redisOrSkip();
        if ($probe === null) {
            return;
        }
        $storage = new RedisStorage($probe);
        [$tokenA, , $nonceA] = $this->issueSha($storage);
        [$tokenB, , $nonceB] = $this->issueSha($storage);
        $uuidK = 'b2c3d4e5-2222-4b3c-9d4e-111111111111';
        $uuidK2 = 'c3d4e5f6-3333-4c4d-ae5f-222222222222';
        $uuidK3 = 'd4e5f6a7-4444-4d5e-bf6a-333333333333';
        $backendId = hash('sha256', self::SITEVERIFY_SECRET.'|login|0|');
        $idemK = '{kiwicaptcha}:siteverify-idem:'.$backendId.':'.$uuidK;
        $idemK2 = '{kiwicaptcha}:siteverify-idem:'.$backendId.':'.$uuidK2;
        $idemK3 = '{kiwicaptcha}:siteverify-idem:'.$backendId.':'.$uuidK3;
        $probe->del([$idemK, $idemK2, $idemK3]);
        $store = new RedisSiteVerifyIdempotencyStore($probe, 'kiwicaptcha', 3);

        try {
            $controller = new SiteVerifyController(new Verifier($storage), self::SECRET, [self::SITEVERIFY_SECRET => 'login'], $storage, null, null, $store, null, 2.0);

            // 1. Key K funded by token A: success.
            $first = $controller->siteverify($this->siteverifyRequest([
                'secret' => self::SITEVERIFY_SECRET, 'response' => $tokenA, 'remoteip' => '127.0.0.1', 'idempotency_key' => $uuidK,
            ]));
            self::assertSame(200, $first->getStatusCode());
            self::assertSame(true, json_decode((string) $first->getContent(), true)['success']);
            $storedK = $store->stored($backendId, $uuidK);
            self::assertIsArray($storedK);
            self::assertSame(true, $storedK['success'] ?? false);

            // 2. The same key K with a different token: the store refuses
            //    the claim (the entry is bound to token A's hash) — 400,
            //    token B never reaches the verifier and stays pending.
            $second = $controller->siteverify($this->siteverifyRequest([
                'secret' => self::SITEVERIFY_SECRET, 'response' => $tokenB, 'remoteip' => '127.0.0.1', 'idempotency_key' => $uuidK,
            ]));
            self::assertSame(400, $second->getStatusCode(), 'key reuse across a different token must be refused');
            self::assertSame(['bad-request'], json_decode((string) $second->getContent(), true)['error-codes']);
            self::assertNull($storage->consumedState($nonceB), 'the refused claim must not touch token B');
            self::assertSame(true, ($store->stored($backendId, $uuidK)['success'] ?? false) === true, "token A's stored success stays untouched");

            // 3. Token B redeemed under its own key K2: fresh success.
            $third = $controller->siteverify($this->siteverifyRequest([
                'secret' => self::SITEVERIFY_SECRET, 'response' => $tokenB, 'remoteip' => '127.0.0.1', 'idempotency_key' => $uuidK2,
            ]));
            self::assertSame(200, $third->getStatusCode());
            self::assertSame(true, json_decode((string) $third->getContent(), true)['success']);
            $consumedB = $storage->consumedState($nonceB);
            self::assertNotNull($consumedB, 'token B must now be consumed');

            // 4. Key K with token B again: still the store-level refusal,
            //    never the stale success of token A.
            $fourth = $controller->siteverify($this->siteverifyRequest([
                'secret' => self::SITEVERIFY_SECRET, 'response' => $tokenB, 'remoteip' => '127.0.0.1', 'idempotency_key' => $uuidK,
            ]));
            self::assertSame(400, $fourth->getStatusCode());
            self::assertSame(['bad-request'], json_decode((string) $fourth->getContent(), true)['error-codes']);

            // 5. A fresh key K3 with the already-consumed token B: the
            //    core's operation-identity gate refuses the replay — the
            //    consumed record's identity is K2's fingerprint, never
            //    K3's — and the duplicate vocabulary answers.
            $fifth = $controller->siteverify($this->siteverifyRequest([
                'secret' => self::SITEVERIFY_SECRET, 'response' => $tokenB, 'remoteip' => '127.0.0.1', 'idempotency_key' => $uuidK3,
            ]));
            $fifthBody = json_decode((string) $fifth->getContent(), true);
            self::assertSame(200, $fifth->getStatusCode());
            self::assertFalse($fifthBody['success'] ?? null, 'a different logical operation presenting the consumed token must never succeed');
            self::assertSame(['timeout-or-duplicate'], $fifthBody['error-codes'] ?? null, 'the operation-identity mismatch answers the duplicate vocabulary');
            $storedK3 = $store->stored($backendId, $uuidK3);
            self::assertIsArray($storedK3, 'the mismatch verdict is finalized deterministically under K3');
            self::assertSame(['timeout-or-duplicate'], $storedK3['error-codes'] ?? null);

            // 6. A K3 retry reproduces the identical deterministic bytes.
            $sixth = $controller->siteverify($this->siteverifyRequest([
                'secret' => self::SITEVERIFY_SECRET, 'response' => $tokenB, 'remoteip' => '127.0.0.1', 'idempotency_key' => $uuidK3,
            ]));
            self::assertSame((string) $fifth->getContent(), (string) $sixth->getContent(), 'the finalized mismatch is byte-deterministic on retry');
        } finally {
            $probe->del([$idemK, $idemK2, $idemK3, 'kiwicaptcha:'.$nonceA, 'kiwicaptcha:'.$nonceB]);
        }
    }

    // ── 3. rotation between the claim and the finalize/recovery ─────────────

    /**
     * A backend-secret rotation between the claim and the finalize: the
     * owner's consume executed and recorded the identity under secret 1,
     * but the reply was lost (claim pending under backend-1). A retry
     * with the same key through secret 2 claims a fresh entry in the
     * secret-2 namespace; the resultless consumed record refuses the
     * reconstruction (the identity gate), so the retry answers the
     * retryable internal-error — never the original success. After the
     * lease expires, the same-context retry (secret 1) still takes over
     * and resumes the original success: the rotation isolated the
     * namespaces, it never corrupted the recovery evidence.
     */
    public function testSecretRotationBetweenClaimAndFinalizeNeverSurvivesAsAResult(): void
    {
        $probe = $this->redisOrSkip();
        if ($probe === null) {
            return;
        }
        $storage = new RedisStorage($probe);
        [$token, , $nonce] = $this->issueSha($storage);
        $secret1 = 'secret-one-'.str_repeat('a', 16);
        $secret2 = 'secret-two-'.str_repeat('b', 16);
        $uuid = 'e5f6a7b8-5555-4e6f-ca7b-444444444444';
        $backendId1 = hash('sha256', $secret1.'|login|0|');
        $backendId2 = hash('sha256', $secret2.'|login|0|');
        $idemKey1 = '{kiwicaptcha}:siteverify-idem:'.$backendId1.':'.$uuid;
        $idemKey2 = '{kiwicaptcha}:siteverify-idem:'.$backendId2.':'.$uuid;
        $probe->del([$idemKey1, $idemKey2]);

        // A short fixed store lease (1s) keeps the takeover instant; the
        // waiter bound (0.5s) stays below it.
        $store = new RedisSiteVerifyIdempotencyStore($probe, 'kiwicaptcha', 1);
        $lost = $this->lostConsumeReplyStorage($storage);

        try {
            // The owner under secret 1: consume executed, reply lost.
            $owner = new SiteVerifyController(new Verifier($lost), self::SECRET, [$secret1 => 'login'], $lost, null, null, $store, null, 0.5);
            $ownerResponse = $owner->siteverify($this->siteverifyRequest([
                'secret' => $secret1, 'response' => $token, 'remoteip' => '127.0.0.1', 'idempotency_key' => $uuid,
            ]));
            self::assertSame(503, $ownerResponse->getStatusCode());
            $consumed = $storage->consumedState($nonce);
            self::assertNotNull($consumed, 'the transition EXECUTED on real Redis');
            self::assertSame(
                hash('sha256', $backendId1."\0".$uuid."\0".hash('sha256', $token)."\0".$this->remoteipFingerprint('127.0.0.1')."\0"."\0no-binding"),
                $consumed->operationIdentity,
                'the identity lands atomically with the state flip under secret-1',
            );
            self::assertNull($consumed->consumedResult);
            self::assertNull($store->stored($backendId1, $uuid), 'the lost reply must NOT finalize the secret-1 claim');

            // The rotated retry (secret 2, same key): a fresh claim in the
            // secret-2 namespace. The resultless consumed record refuses
            // reconstruction through the rotated context — the retryable
            // internal-error, never the original success.
            $rotated = new SiteVerifyController(new Verifier($storage), self::SECRET, [$secret2 => 'login'], $storage, null, null, $store, null, 0.5);
            $rotatedResponse = $rotated->siteverify($this->siteverifyRequest([
                'secret' => $secret2, 'response' => $token, 'remoteip' => '127.0.0.1', 'idempotency_key' => $uuid,
            ]));
            self::assertSame(503, $rotatedResponse->getStatusCode(), 'the rotated context must fail closed, never reconstruct');
            self::assertSame(['internal-error'], json_decode((string) $rotatedResponse->getContent(), true)['error-codes']);
            self::assertNull($store->stored($backendId2, $uuid), 'the rotated retry finalizes nothing');
            self::assertNull($storage->consumedState($nonce)?->consumedResult, 'the record stays resultless');

            // Wait out the 1s lease (Redis time is the lease clock).
            usleep(2_500_000);

            // The same-context retry (secret 1) takes over its own pending
            // claim and resumes the original success: the rotation did not
            // destroy the recovery evidence.
            $recovery = new SiteVerifyController(new Verifier($storage), self::SECRET, [$secret1 => 'login'], $storage, null, null, $store, null, 0.5);
            $recoveryResponse = $recovery->siteverify($this->siteverifyRequest([
                'secret' => $secret1, 'response' => $token, 'remoteip' => '127.0.0.1', 'idempotency_key' => $uuid,
            ]));
            $recoveryBody = json_decode((string) $recoveryResponse->getContent(), true);
            self::assertSame(true, $recoveryBody['success'] ?? null, 'the secret-1 context must still recover its original success: '.(string) $recoveryResponse->getContent());
            self::assertSame($this->expectedCanonicalSuccess($storage, $nonce), (string) $recoveryResponse->getContent());
            self::assertNotNull($storage->consumedState($nonce)?->consumedResult, 'the resumed derivation must be committed');
            self::assertNull($store->stored($backendId2, $uuid), 'the secret-2 namespace stays untouched');
        } finally {
            $probe->del([$idemKey1, $idemKey2, 'kiwicaptcha:'.$nonce]);
        }
    }

    /**
     * The same rotation fault injected on the security-context digest
     * (issuer/region/keyring state) instead of the secret. The digest is
     * bound into the backend identity, so a rotation between the claim
     * and the recovery moves the namespace. The rotated retry can never
     * reconstruct the original success.
     */
    public function testSecurityContextDigestRotationBetweenClaimAndFinalizeNeverSurvivesAsAResult(): void
    {
        $probe = $this->redisOrSkip();
        if ($probe === null) {
            return;
        }
        $storage = new RedisStorage($probe);
        [$token, , $nonce] = $this->issueSha($storage);
        $digestA = hash('sha256', 'issuer-a|region-a|[]|[]');
        $digestB = hash('sha256', 'issuer-b|region-a|[]|[]');
        $uuid = 'f6a7b8c9-6666-4f7a-db8c-555555555555';
        $backendIdA = hash('sha256', self::SITEVERIFY_SECRET.'|login|0|'.$digestA);
        $backendIdB = hash('sha256', self::SITEVERIFY_SECRET.'|login|0|'.$digestB);
        $idemKeyA = '{kiwicaptcha}:siteverify-idem:'.$backendIdA.':'.$uuid;
        $idemKeyB = '{kiwicaptcha}:siteverify-idem:'.$backendIdB.':'.$uuid;
        $probe->del([$idemKeyA, $idemKeyB]);
        $store = new RedisSiteVerifyIdempotencyStore($probe, 'kiwicaptcha', 1);
        $lost = $this->lostConsumeReplyStorage($storage);

        try {
            $owner = new SiteVerifyController(new Verifier($lost), self::SECRET, [self::SITEVERIFY_SECRET => 'login'], $lost, null, null, $store, null, 0.5, 0, $digestA);
            $ownerResponse = $owner->siteverify($this->siteverifyRequest([
                'secret' => self::SITEVERIFY_SECRET, 'response' => $token, 'remoteip' => '127.0.0.1', 'idempotency_key' => $uuid,
            ]));
            self::assertSame(503, $ownerResponse->getStatusCode());
            $consumed = $storage->consumedState($nonce);
            self::assertNotNull($consumed);
            self::assertSame(
                hash('sha256', $backendIdA."\0".$uuid."\0".hash('sha256', $token)."\0".$this->remoteipFingerprint('127.0.0.1')."\0"."\0no-binding"),
                $consumed->operationIdentity,
                'the identity lands under the digest-A backend identity',
            );

            // The rotated retry (digest B): fresh namespace, the
            // resultless consumed record refuses the reconstruction.
            $rotated = new SiteVerifyController(new Verifier($storage), self::SECRET, [self::SITEVERIFY_SECRET => 'login'], $storage, null, null, $store, null, 0.5, 0, $digestB);
            $rotatedResponse = $rotated->siteverify($this->siteverifyRequest([
                'secret' => self::SITEVERIFY_SECRET, 'response' => $token, 'remoteip' => '127.0.0.1', 'idempotency_key' => $uuid,
            ]));
            self::assertSame(503, $rotatedResponse->getStatusCode(), 'the digest-rotated retry must fail closed');
            self::assertSame(['internal-error'], json_decode((string) $rotatedResponse->getContent(), true)['error-codes']);
            self::assertNull($store->stored($backendIdB, $uuid));

            usleep(2_500_000);

            // The digest-A context still recovers its own pending claim.
            $recovery = new SiteVerifyController(new Verifier($storage), self::SECRET, [self::SITEVERIFY_SECRET => 'login'], $storage, null, null, $store, null, 0.5, 0, $digestA);
            $recoveryResponse = $recovery->siteverify($this->siteverifyRequest([
                'secret' => self::SITEVERIFY_SECRET, 'response' => $token, 'remoteip' => '127.0.0.1', 'idempotency_key' => $uuid,
            ]));
            $recoveryBody = json_decode((string) $recoveryResponse->getContent(), true);
            self::assertSame(true, $recoveryBody['success'] ?? null, 'the digest-A context must still recover: '.(string) $recoveryResponse->getContent());
            self::assertSame($this->expectedCanonicalSuccess($storage, $nonce), (string) $recoveryResponse->getContent());
        } finally {
            $probe->del([$idemKeyA, $idemKeyB, 'kiwicaptcha:'.$nonce]);
        }
    }

    // ── 4. policy-epoch bump between two identical retries ──────────────────

    /**
     * A policy-epoch bump between two identical retries (same token, same
     * key, same remoteip). The second retry is a new logical operation in
     * the bumped-epoch namespace, and the rotated verifier fails the
     * record's signed epoch. The retry fails closed with the
     * invalid-response vocabulary, never the cached success.
     */
    public function testPolicyEpochBumpBetweenIdenticalRetriesFailsClosed(): void
    {
        $storage = new ArrayStorage();
        [$token] = $this->issuedToken($storage, policyVersion: 0);
        $store = new ArraySiteVerifyIdempotencyStore();
        $uuid = 'a7b8c9d0-7777-4a8b-ec9d-666666666666';
        $backendId0 = hash('sha256', self::SITEVERIFY_SECRET.'|login|0|');
        $backendId1 = hash('sha256', self::SITEVERIFY_SECRET.'|login|1|');

        $verifier0 = new Verifier($storage);
        $verifier0->setExpectedPolicyVersion(0);
        $before = new SiteVerifyController($verifier0, self::SECRET, [self::SITEVERIFY_SECRET => 'login'], $storage, null, null, $store, null, 2.0, 0);
        $first = $before->siteverify($this->siteverifyRequest([
            'secret' => self::SITEVERIFY_SECRET, 'response' => $token, 'remoteip' => '127.0.0.1', 'idempotency_key' => $uuid,
        ]));
        self::assertSame(200, $first->getStatusCode());
        self::assertSame(true, json_decode((string) $first->getContent(), true)['success']);
        self::assertSame(true, ($store->stored($backendId0, $uuid)['success'] ?? false) === true, 'the epoch-0 namespace caches the success');

        // The policy epoch bumps to 1 (the verifier expectation rotates
        // with it): the identical retry claims the epoch-1 namespace and
        // the signed epoch-0 record fails closed.
        $verifier1 = new Verifier($storage);
        $verifier1->setExpectedPolicyVersion(1);
        $after = new SiteVerifyController($verifier1, self::SECRET, [self::SITEVERIFY_SECRET => 'login'], $storage, null, null, $store, null, 2.0, 1);
        $second = $after->siteverify($this->siteverifyRequest([
            'secret' => self::SITEVERIFY_SECRET, 'response' => $token, 'remoteip' => '127.0.0.1', 'idempotency_key' => $uuid,
        ]));
        $secondBody = json_decode((string) $second->getContent(), true);
        self::assertSame(200, $second->getStatusCode());
        self::assertFalse($secondBody['success'] ?? null, 'the epoch-bumped retry must NEVER return the cached success');
        self::assertSame(['invalid-input-response'], $secondBody['error-codes'] ?? null, 'the signed-epoch mismatch is a hard verdict: invalid-input-response');
        $stored1 = $store->stored($backendId1, $uuid);
        self::assertIsArray($stored1, 'the bumped retry finalizes its own deterministic failure');
        self::assertFalse($stored1['success'] ?? true);
        self::assertTrue(($store->stored($backendId0, $uuid)['success'] ?? false) === true, 'the epoch-0 cached success stays untouched');
    }

    /**
     * The same bump injected through the central security-epoch monitor.
     * The controller refreshes the monitor per authenticated request, so
     * a central bump between two identical retries moves the idempotency
     * namespace to the effective epoch and rotates the shared verifier's
     * expectation. The retry fails closed instead of replaying the
     * pre-change outcome.
     */
    public function testPolicyEpochBumpViaCentralMonitorBetweenIdenticalRetriesFailsClosed(): void
    {
        $storage = new ArrayStorage();
        [$token] = $this->issuedToken($storage, policyVersion: 0);
        $store = new ArraySiteVerifyIdempotencyStore();
        $uuid = 'b8c9d0e1-8888-4b9c-fd0e-777777777777';
        $backendId0 = hash('sha256', self::SITEVERIFY_SECRET.'|login|0|');
        $backendId1 = hash('sha256', self::SITEVERIFY_SECRET.'|login|1|');

        $redisA = new FakePredisClient();
        $redisA->hset('{kiwi:test-ns}:security-policy', SecurityEpochMonitor::MIN_POLICY_EPOCH_FIELD, '0');
        $redisB = new FakePredisClient();
        $redisB->hset('{kiwi:test-ns}:security-policy', SecurityEpochMonitor::MIN_POLICY_EPOCH_FIELD, '1');

        $verifier = new Verifier($storage);
        $monitorA = new SecurityEpochMonitor($verifier, $redisA, 'test-ns', 0, 1, static fn (): float => 0.0, 60);
        $before = new SiteVerifyController($verifier, self::SECRET, [self::SITEVERIFY_SECRET => 'login'], $storage, null, null, $store, null, 2.0, 0, null, null, $monitorA);
        $first = $before->siteverify($this->siteverifyRequest([
            'secret' => self::SITEVERIFY_SECRET, 'response' => $token, 'remoteip' => '127.0.0.1', 'idempotency_key' => $uuid,
        ]));
        self::assertSame(200, $first->getStatusCode());
        self::assertSame(true, json_decode((string) $first->getContent(), true)['success']);
        self::assertSame(true, ($store->stored($backendId0, $uuid)['success'] ?? false) === true, 'the epoch-0 namespace caches the success');

        // The central state bumps to 1; the retry's monitor observes it
        // and rotates the shared verifier's expectation.
        $monitorB = new SecurityEpochMonitor($verifier, $redisB, 'test-ns', 0, 1, static fn (): float => 0.0, 60);
        $after = new SiteVerifyController($verifier, self::SECRET, [self::SITEVERIFY_SECRET => 'login'], $storage, null, null, $store, null, 2.0, 0, null, null, $monitorB);
        $second = $after->siteverify($this->siteverifyRequest([
            'secret' => self::SITEVERIFY_SECRET, 'response' => $token, 'remoteip' => '127.0.0.1', 'idempotency_key' => $uuid,
        ]));
        $secondBody = json_decode((string) $second->getContent(), true);
        self::assertSame(200, $second->getStatusCode());
        self::assertFalse($secondBody['success'] ?? null, 'the centrally bumped retry must NEVER return the cached success');
        self::assertSame(['invalid-input-response'], $secondBody['error-codes'] ?? null, 'the rotated expectation fails the signed epoch-0 record closed');
        $stored1 = $store->stored($backendId1, $uuid);
        self::assertIsArray($stored1, 'the bumped retry finalizes its own deterministic failure under the effective-epoch namespace');
        self::assertTrue(($store->stored($backendId0, $uuid)['success'] ?? false) === true, 'the epoch-0 cached success stays untouched');
    }

    // ── 5. the no-IP identity ───────────────────────────────────────────────

    /**
     * binding_mode: none with remoteip omitted and an idempotency key:
     * the claim identity is the stable 'no-ip' pseudonym, so the
     * duplicate retry (also without a remoteip) is recognized and returns
     * the stored canonical bytes. An IP appearing on a later request is a
     * different pseudonym — a conflict, never a join of the no-IP
     * outcome.
     */
    public function testNoIpIdentityWithBindingModeNoneRecognizesTheDuplicateRetryAndConflictsOnIpChange(): void
    {
        $storage = new ArrayStorage();
        $issuer = new Issuer(new Config(secretKey: self::SECRET, algorithm: PoWAlgorithm::Sha256, targetBits: 8, ttlSecs: 120, bindingMode: BindingMode::None), $storage);
        $challenge = $issuer->issue('login', '127.0.0.1');
        $token = $this->solveSolution($storage->find($challenge->nonce));
        usleep(($challenge->minDurationMs + 10) * 1000);
        $store = new ArraySiteVerifyIdempotencyStore();
        $controller = $this->controller(idempotencyStore: $store, storage: $storage);
        $uuid = 'c9d0e1f2-9999-4cad-ae1f-888888888888';
        $backendId = hash('sha256', self::SITEVERIFY_SECRET.'|login|0|');

        $first = (string) $controller->siteverify($this->siteverifyRequest([
            'secret' => self::SITEVERIFY_SECRET, 'response' => $token, 'idempotency_key' => $uuid,
        ]))->getContent();
        self::assertSame(true, json_decode($first, true)['success'] ?? null, 'a valid token under binding_mode: none must succeed with remoteip omitted');

        // The duplicate retry with the same no-IP identity: recognized and
        // byte-identical (the stored canonical outcome).
        $second = (string) $controller->siteverify($this->siteverifyRequest([
            'secret' => self::SITEVERIFY_SECRET, 'response' => $token, 'idempotency_key' => $uuid,
        ]))->getContent();
        self::assertSame($first, $second, 'the no-IP duplicate retry must return the identical canonical success');

        // An IP appearing now is a different pseudonym: conflict, never a
        // join of the no-IP outcome.
        $third = $controller->siteverify($this->siteverifyRequest([
            'secret' => self::SITEVERIFY_SECRET, 'response' => $token, 'remoteip' => '127.0.0.1', 'idempotency_key' => $uuid,
        ]));
        self::assertSame(400, $third->getStatusCode(), 'an IP change away from the no-IP identity must conflict');
        self::assertSame(['bad-request'], json_decode((string) $third->getContent(), true)['error-codes']);

        // A different token under the same key + no-IP identity: conflict
        // too (the entry is bound to the first token's hash).
        [$tokenB] = $this->issuedToken($storage, remoteIp: '127.0.0.1');
        $fourth = $controller->siteverify($this->siteverifyRequest([
            'secret' => self::SITEVERIFY_SECRET, 'response' => $tokenB, 'idempotency_key' => $uuid,
        ]));
        self::assertSame(400, $fourth->getStatusCode(), 'a different token under the same no-IP identity must conflict');

        // The stored success is intact under the no-IP identity.
        $stored = $store->stored($backendId, $uuid);
        self::assertIsArray($stored);
        self::assertSame(true, $stored['success'] ?? null);
    }

    // ── 6. malformed token + idempotency key ────────────────────────────────

    /**
     * A malformed/undecodable token with an idempotency key finalizes a
     * deterministic invalid-input-response (a same-key retry reproduces
     * the identical bytes), the unattributable risk feedback (no source
     * IP) is skipped, and a 503 never escapes. With a source IP the
     * MalformedToken evidence IS recorded — per request, exactly like the
     * native validator — while the provider response stays the
     * deterministic duplicate.
     */
    public function testMalformedTokenWithIdempotencyKeyIsDeterministicAndRiskFeedbackSkippedWithoutSource(): void
    {
        ['gateway' => $gateway, 'store' => $store] = $this->riskStack();
        $idemStore = new ArraySiteVerifyIdempotencyStore();
        $controller = $this->controller(idempotencyStore: $idemStore, riskGateway: $gateway);
        $uuid = 'd0e1f2a3-aaaa-4dbe-bf2a-999999999999';
        $backendId = hash('sha256', self::SITEVERIFY_SECRET.'|login|0|');
        $malformed = 'not-a-kiwi-solution-token';

        // No remoteip: the MalformedToken feedback has no source to
        // attribute — skipped, never thrown — and the deterministic
        // invalid response finalizes the claim.
        $firstResponse = $controller->siteverify($this->siteverifyRequest([
            'secret' => self::SITEVERIFY_SECRET, 'response' => $malformed, 'idempotency_key' => $uuid,
        ]));
        self::assertSame(200, $firstResponse->getStatusCode(), 'a malformed token must never answer the retryable 503');
        $first = (string) $firstResponse->getContent();
        $firstBody = json_decode($first, true);
        self::assertFalse($firstBody['success'] ?? true);
        self::assertSame(['invalid-input-response'], $firstBody['error-codes'] ?? null);
        self::assertSame([], $store->observations, 'the unattributable MalformedToken feedback must be skipped, never thrown');

        // The same-key retry: identical canonical bytes (deterministic
        // finalize, never a re-derivation).
        $second = (string) $controller->siteverify($this->siteverifyRequest([
            'secret' => self::SITEVERIFY_SECRET, 'response' => $malformed, 'idempotency_key' => $uuid,
        ]))->getContent();
        self::assertSame($first, $second, 'a same-key malformed retry must return the identical canonical failure');
        self::assertSame([], $store->observations, 'the no-source retry keeps skipping the feedback');
        $stored = $idemStore->stored($backendId, $uuid);
        self::assertIsArray($stored);
        self::assertSame(['invalid-input-response'], $stored['error-codes'] ?? null);

        // With a source IP the evidence IS recorded (per request, the
        // native parity), while the provider response stays the
        // deterministic invalid response — never a 503.
        $uuid2 = 'e1f2a3b4-bbbb-4ecf-ca3b-aaaaaaaabbbb';
        $firstIp = (string) $controller->siteverify($this->siteverifyRequest([
            'secret' => self::SITEVERIFY_SECRET, 'response' => $malformed, 'remoteip' => '203.0.113.7', 'idempotency_key' => $uuid2,
        ]))->getContent();
        self::assertSame(['invalid-input-response'], json_decode($firstIp, true)['error-codes'] ?? null);
        $events = array_map(static fn ($o): RiskEventKind => $o->event, $store->observations);
        self::assertSame([RiskEventKind::MalformedToken], $events, 'the attributable MalformedToken evidence is recorded exactly once per request');
        $retryIp = (string) $controller->siteverify($this->siteverifyRequest([
            'secret' => self::SITEVERIFY_SECRET, 'response' => $malformed, 'remoteip' => '203.0.113.7', 'idempotency_key' => $uuid2,
        ]))->getContent();
        self::assertSame($firstIp, $retryIp, 'the attributable retry still returns the identical canonical failure');
        self::assertCount(2, $store->observations, 'the per-request MalformedToken evidence is recorded on the retry too, exactly like the native validator');
    }

    // ── 7. the ownership confirmation race ──────────────────────────────────

    /**
     * An idempotent retry racing the original completion: the owner
     * claims and consumes (recording the operation identity) and then stalls
     * inside its commit; its lease expires and the retry takes over,
     * resumes the identity-proven derivation and finalizes. The owner's
     * post-verify ownership confirmation (renew) then fails, so the
     * owner discards its own locally-derived success and returns the
     * stored authoritative outcome — byte-identical to the takeover
     * winner and to a later observer. The deterministic finalize
     * converges every racer on the same bytes.
     */
    public function testIdempotentRetryRacingTheOriginalCompletionResolvesToTheSameFinalOutcome(): void
    {
        if (!\function_exists('pcntl_fork')) {
            self::markTestSkipped('pcntl is not installed; cannot fork concurrent verifications');
        }
        $probe = $this->redisOrSkip();
        if ($probe === null) {
            return;
        }
        $storage = new RedisStorage($probe);
        [$token, , $nonce] = $this->issueSha($storage, 180);
        $uuid = 'f2a3b4c5-cccc-4fd0-db4c-bbbbbbbbcccc';
        $backendId = hash('sha256', self::SITEVERIFY_SECRET.'|login|0|');
        $idemKey = '{kiwicaptcha}:siteverify-idem:'.$backendId.':'.$uuid;
        $probe->del([$idemKey]);
        $probe->disconnect();

        $outFile = tempnam(sys_get_temp_dir(), 'kiwi-fi-race-');
        $startBarrier = tempnam(sys_get_temp_dir(), 'kiwi-fi-race-start-');
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
                // The owner's storage stalls the first commit for 12s
                // (outlasting the 3s lease by a wide margin, even under
                // suite load): the consume already executed and recorded
                // the identity, so the record is resultless while the
                // lease expires. The wide margin guarantees the takeover
                // retry (started 4s after the barrier) has finalized the
                // entry long before the owner wakes.
                $client = new \Predis\Client(self::redisTestUrl(), ['timeout' => 30.0, 'read_write_timeout' => 30.0]);
                $inner = new RedisStorage($client);
                $sleepy = new class($inner) implements SiteVerifyRecoveryCapableStorageInterface {
                    private int $commits = 0;

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
                        return $this->inner->consumedState($nonce);
                    }

                    public function consume(string $nonce): ?\KiwiCaptcha\ConsumedRecord
                    {
                        return $this->inner->consume($nonce);
                    }

                    public function consumeWithOperationIdentity(string $nonce, ?string $operationIdentity): ?\KiwiCaptcha\ConsumedRecord
                    {
                        return $this->inner->consumeWithOperationIdentity($nonce, $operationIdentity);
                    }

                    public function commitResult(string $nonce, bool $valid, ?string $binding): bool
                    {
                        if ($this->commits++ === 0) {
                            sleep(12); // outlasts the 3s lease with a wide margin
                        }

                        return $this->inner->commitResult($nonce, $valid, $binding);
                    }

                    public function delete(string $nonce): void
                    {
                        $this->inner->delete($nonce);
                    }

                    public function deleteIfPending(string $nonce): \KiwiCaptcha\DeleteIfPendingResult
                    {
                        return $this->inner->deleteIfPending($nonce);
                    }
                };
                $controller = new SiteVerifyController(
                    new Verifier($sleepy),
                    self::SECRET,
                    [self::SITEVERIFY_SECRET => 'login'],
                    $sleepy,
                    null,
                    null,
                    new RedisSiteVerifyIdempotencyStore($client, 'kiwicaptcha', 3),
                );
                $response = $controller->siteverify($this->siteverifyRequest([
                    'secret' => self::SITEVERIFY_SECRET, 'response' => $token, 'remoteip' => '127.0.0.1', 'idempotency_key' => $uuid,
                ]));
                $line = $response->getStatusCode().':'.$response->getContent();
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

        try {
            // Deterministic takeover window: the parent polls the claim
            // record until the owner's fixed 3s lease has expired in
            // Redis time (the owner's claim may land late under suite
            // load, so a fixed wall-clock sleep would make the takeover a
            // race). The taker then wins the takeover on its first lease
            // probe, well inside its per-request wait bound.
            $waitClient = new \Predis\Client(self::redisTestUrl(), ['timeout' => 10.0, 'read_write_timeout' => 10.0]);
            $waitDeadline = microtime(true) + 45;
            while (true) {
                $raw = $waitClient->get($idemKey);
                if ($raw !== null) {
                    $rec = json_decode((string) $raw, true);
                    $leaseExpiresAt = (int) ($rec['lease_expires_at'] ?? 0);
                    $redisSec = (int) ($waitClient->time()[0]);
                    if ($redisSec > $leaseExpiresAt) {
                        break;
                    }
                }
                if (microtime(true) >= $waitDeadline) {
                    self::fail('the owner never claimed the entry (or the lease never expired) — the takeover window was not established');
                }
                usleep(50_000);
            }
            $waitClient->disconnect();

            // The retry — same key + token + remoteip — wins the atomic
            // takeover, resumes the identity-proven derivation and
            // finalizes its canonical success.
            $client = new \Predis\Client(self::redisTestUrl(), ['timeout' => 30.0, 'read_write_timeout' => 30.0]);
            $takerStorage = new RedisStorage($client);
            $taker = new SiteVerifyController(
                new Verifier($takerStorage),
                self::SECRET,
                [self::SITEVERIFY_SECRET => 'login'],
                $takerStorage,
                null,
                null,
                new RedisSiteVerifyIdempotencyStore($client, 'kiwicaptcha', 3),
            );
            $takerResponse = $taker->siteverify($this->siteverifyRequest([
                'secret' => self::SITEVERIFY_SECRET, 'response' => $token, 'remoteip' => '127.0.0.1', 'idempotency_key' => $uuid,
            ]));
            self::assertSame(200, $takerResponse->getStatusCode(), 'the takeover retry must succeed: '.(string) $takerResponse->getContent());
            self::assertSame(true, json_decode((string) $takerResponse->getContent(), true)['success'] ?? null);
            $client->disconnect();

            // A later observer (CompleteSame) returns the stored bytes.
            $observer = new \Predis\Client(self::redisTestUrl(), ['timeout' => 30.0, 'read_write_timeout' => 30.0]);
            $observerStorage = new RedisStorage($observer);
            $observerResponse = (new SiteVerifyController(new Verifier($observerStorage), self::SECRET, [self::SITEVERIFY_SECRET => 'login'], $observerStorage, null, null, new RedisSiteVerifyIdempotencyStore($observer, 'kiwicaptcha', 3)))
                ->siteverify($this->siteverifyRequest([
                    'secret' => self::SITEVERIFY_SECRET, 'response' => $token, 'remoteip' => '127.0.0.1', 'idempotency_key' => $uuid,
                ]));
            $observer->disconnect();

            pcntl_waitpid($owner, $status);
            self::assertSame(0, pcntl_wexitstatus($status), 'the owner must exit cleanly');
            $raw = (string) file_get_contents($outFile);
            $ownerLine = trim($raw);
            @unlink($outFile);
            @unlink($startBarrier);

            $ownerBody = json_decode(substr($ownerLine, 4), true);
            self::assertSame('200', substr($ownerLine, 0, 3), 'the displaced owner must answer 200 with the stored outcome, never the retryable 503: '.$ownerLine);
            self::assertSame(true, $ownerBody['success'] ?? null, 'the displaced owner returns the stored authoritative success, not its own: '.$ownerLine);
            self::assertSame((string) $takerResponse->getContent(), substr($ownerLine, 4), "the displaced owner's outcome must equal the takeover winner's byte-for-byte");
            self::assertSame((string) $takerResponse->getContent(), (string) $observerResponse->getContent(), 'every observer resolves to the SAME final outcome bytes');

            $final = new \Predis\Client(self::redisTestUrl(), ['timeout' => 10.0, 'read_write_timeout' => 10.0]);
            self::assertSame($this->expectedCanonicalSuccess(new RedisStorage($final), $nonce), (string) $takerResponse->getContent());
            $final->disconnect();
        } finally {
            @unlink($outFile);
            @unlink($startBarrier);
            $probe->connect();
            $probe->del([$idemKey, 'kiwicaptcha:'.$nonce]);
            $probe->disconnect();
        }
    }
}
