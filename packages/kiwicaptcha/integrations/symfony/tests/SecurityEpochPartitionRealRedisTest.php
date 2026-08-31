<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests;

use BelConsulting\KiwiCaptchaBundle\Controller\ChallengeController;
use BelConsulting\KiwiCaptchaBundle\Controller\SiteVerifyController;
use BelConsulting\KiwiCaptchaBundle\Risk\ContinuityCookie;
use BelConsulting\KiwiCaptchaBundle\Risk\RiskGateway;
use BelConsulting\KiwiCaptchaBundle\Risk\RiskProfileResolver;
use BelConsulting\KiwiCaptchaBundle\Risk\SecurityEpochMonitor;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\FakeRiskStateStore;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\JsonRequest;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\RedisTestUrl;
use BelConsulting\KiwiCaptchaBundle\Validator\Constraints\KiwiCaptcha as KiwiCaptchaConstraint;
use BelConsulting\KiwiCaptchaBundle\Validator\Constraints\KiwiCaptchaValidator;
use KiwiCaptcha\Config;
use KiwiCaptcha\Issuer;
use KiwiCaptcha\PoWAlgorithm;
use KiwiCaptcha\Risk\AdaptiveRiskEngine;
use KiwiCaptcha\Risk\Network\CidrNetworkClassifier;
use KiwiCaptcha\Risk\RiskIdentityFactory;
use KiwiCaptcha\Risk\RiskKeys;
use KiwiCaptcha\Risk\RiskPolicy;
use KiwiCaptcha\Risk\RiskScorer;
use KiwiCaptcha\SolutionToken;
use KiwiCaptcha\Storage\RedisStorage;
use KiwiCaptcha\Verifier;
use PHPUnit\Framework\TestCase;
use Psr\Log\LoggerInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Component\Validator\ConstraintValidatorFactory;
use Symfony\Component\Validator\Validation;

/**
 * The security-policy authority split contract, exercised against the
 * real Redis of the dedicated lane.
 *
 * The SecurityEpochMonitor owns the central security-policy state.
 * This suite pins the fail-closed contract at the two surfaces that
 * consume it: issuance (the challenge controller) and verification
 * (the native validator and the provider SiteVerify surface). The
 * policy Redis is made unreachable through a fail-injecting client
 * over the real server, so every other leg of the stack stays real:
 * the challenge records, the policy hash, the reads and the retries
 * all run against Redis. One scenario kills a real redis-server and
 * restarts it on the same port, so the same monitor process observes
 * a genuine connection failure and a genuine recovery.
 *
 * The pinned contracts: within the max-stale window the last-known
 * policy keeps serving, and past the window issuance fails closed
 * with 503 and verification fails closed, never a success under a
 * lost policy. A recovering authority with a lower protocol floor
 * than last-known re-evaluates the emission gate on the next read,
 * while the epoch stays monotonic. A split brain in either direction
 * yields only the typed fail-closed outcomes.
 *
 * Runs in the dedicated "Real-Redis concurrency" CI lane, which
 * publishes `KC_REDIS_URL` / `TEST_REDIS_URL` and sets
 * `KIWI_REQUIRE_REAL_REDIS_TESTS=1`; with the flag on, a missing or
 * unreachable Redis fails the suite instead of skipping. With the
 * flag off the suite skips like every other real-Redis suite.
 */
final class SecurityEpochPartitionRealRedisTest extends TestCase
{
    private const SECRET = '0123456789abcdef0123456789abcdef';

    private const SITEVERIFY_SECRET = 'compat-secret-42';

    private const NAMESPACE = 'test-ns';

    private const PREFIX = 'ci:epoch-partition:';

    private const POLICY_KEY = '{kiwi:test-ns}:security-policy';

    private const MAX_STALE_SECS = 60;

    /** @var array<int, resource> */
    private array $procs = [];

    private string $tmpDir = '';

    private int $clockMs = 0;

    private function clock(): float
    {
        return (float) $this->clockMs;
    }

    protected function setUp(): void
    {
        $url = RedisTestUrl::resolve();
        if ($url === null) {
            self::markTestSkipped('KC_REDIS_URL/TEST_REDIS_URL not set — the real-Redis suites run in the dedicated Redis-service lane');
        }
        if (!class_exists(\Predis\Client::class)) {
            self::markTestSkipped('predis/predis not installed');
        }
        $probe = new \Predis\Client($url, ['timeout' => 5.0, 'read_write_timeout' => 5.0]);
        try {
            $probe->ping();
        } catch (\Throwable $e) {
            $this->failIfRealRedisRequired('no Redis is reachable at the configured KC_REDIS_URL/TEST_REDIS_URL ('.$e->getMessage().')');
            self::markTestSkipped('no Redis at the configured KC_REDIS_URL/TEST_REDIS_URL');
        }
        $probe->flushdb();
    }

    protected function tearDown(): void
    {
        foreach ($this->procs as $proc) {
            $status = proc_get_status($proc);
            if ($status !== false && $status['running']) {
                proc_terminate($proc, 9);
                proc_close($proc);
            }
        }
        $this->procs = [];
        if ($this->tmpDir !== '' && is_dir($this->tmpDir)) {
            $this->removeDir($this->tmpDir);
        }
        $this->tmpDir = '';
        $this->clockMs = 0;
    }

    private function removeDir(string $dir): void
    {
        $items = scandir($dir);
        if ($items === false) {
            return;
        }
        foreach ($items as $item) {
            if ($item === '.' || $item === '..') {
                continue;
            }
            $path = $dir.'/'.$item;
            if (is_dir($path)) {
                $this->removeDir($path);
            } else {
                @unlink($path);
            }
        }
        @rmdir($dir);
    }

    private function failIfRealRedisRequired(string $why): void
    {
        $flag = getenv('KIWI_REQUIRE_REAL_REDIS_TESTS');
        if (\is_string($flag) && $flag !== '' && $flag !== '0') {
            self::fail('KIWI_REQUIRE_REAL_REDIS_TESTS is set but '.$why.' — the security-epoch partition suite must run in the real-Redis CI lane');
        }
    }

    private function redisClient(): \Predis\Client
    {
        return new \Predis\Client(RedisTestUrl::resolve(), ['timeout' => 5.0, 'read_write_timeout' => 5.0]);
    }

    /**
     * A fail-injecting client over a real connection: when armed, every
     * command raises the typed server exception a lost authority would
     * produce. The rest of the stack stays on real Redis.
     */
    private function failingClient(\Predis\Client $inner): \Predis\Client
    {
        return new class($inner) extends \Predis\Client {
            public \Predis\Client $inner;

            public bool $failAll = false;

            public function __construct(\Predis\Client $inner)
            {
                $this->inner = $inner;
            }

            public function __call($commandID, $arguments)
            {
                if ($this->failAll) {
                    throw new \Predis\Response\ServerException('connection refused (partitioned)');
                }

                return $this->inner->__call($commandID, $arguments);
            }
        };
    }

    private function seedPolicy(\Predis\Client $client, int $epoch, int $floor): void
    {
        $client->hset(self::POLICY_KEY, SecurityEpochMonitor::MIN_POLICY_EPOCH_FIELD, (string) $epoch);
        $client->hset(self::POLICY_KEY, SecurityEpochMonitor::MIN_PROTOCOL_VERSION_FIELD, (string) $floor);
    }

    private function issuer(RedisStorage $storage): Issuer
    {
        return new Issuer(new Config(secretKey: self::SECRET, algorithm: PoWAlgorithm::Sha256, targetBits: 8, ttlSecs: 120, minDurationMs: 0), $storage);
    }

    private function challengeRequest(): Request
    {
        return JsonRequest::create(
            '/kiwi-captcha/challenge',
            'POST',
            [],
            [],
            [],
            ['REMOTE_ADDR' => '198.51.100.7'],
            '{"scope":"login"}',
        );
    }

    private function siteverifyRequest(array $fields): Request
    {
        $body = http_build_query($fields);

        return Request::create('/kiwi-captcha/siteverify', 'POST', [], [], [], ['CONTENT_TYPE' => 'application/x-www-form-urlencoded'], (string) $body);
    }

    /** @return array{status: int, data: array<string, mixed>} */
    private function issue(ChallengeController $controller): array
    {
        $response = $controller->challenge($this->challengeRequest());

        return [$response->getStatusCode(), json_decode((string) $response->getContent(), true)];
    }

    private function solve(\KiwiCaptcha\ChallengeRecord $record): string
    {
        $saltBytes = base64_decode($record->salt, true);
        $counter = 0;
        do {
            $hash = hash('sha256', $record->prefix.$counter.$saltBytes, true);
            $counter++;
        } while (Verifier::leadingZeroBits($hash) < $record->targetBits);
        --$counter;

        return SolutionToken::create($record->nonce, $counter, 5000, [])->encode();
    }

    /** @return list<\Symfony\Component\Validator\ConstraintViolationInterface> */
    private function validate(KiwiCaptchaValidator $validator, string $token): array
    {
        $factory = new ConstraintValidatorFactory([KiwiCaptchaValidator::class => $validator]);
        $engineValidator = Validation::createValidatorBuilder()->setConstraintValidatorFactory($factory)->getValidator();
        $dto = new class {
            public ?string $captcha = null;
        };
        $dto->captcha = $token;
        $meta = $engineValidator->getMetadataFor($dto::class);
        $meta->addPropertyConstraint('captcha', new KiwiCaptchaConstraint(['scope' => 'login']));

        return iterator_to_array($engineValidator->validate($dto));
    }

    private function validatorStack(Verifier $verifier, SecurityEpochMonitor $monitor): KiwiCaptchaValidator
    {
        $stack = new RequestStack();
        $stack->push(JsonRequest::create('/', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7']));

        return new KiwiCaptchaValidator($verifier, $stack, self::SECRET, epochMonitor: $monitor);
    }

    /**
     * The v3-wired issuance stack: the writer switch on, the risk
     * gateway wired, the monitor reading the real policy Redis. The
     * emission gate arms only on a confirmed central floor.
     *
     * @return array{0: ChallengeController, 1: PartitionLoggerSpy}
     */
    private function v3Stack(Issuer $issuer, SecurityEpochMonitor $monitor): array
    {
        $keys = RiskKeys::fromMaster(self::SECRET);
        $classifier = new CidrNetworkClassifier([]);
        $policy = RiskPolicy::fromConfig([
            'version' => RiskPolicy::CONTRACT_VERSION,
            'weights' => [],
            'scopes' => [
                1 => ['base_risk' => 100, 'minimum' => 'allow', 'post_solve_check' => false, 'degraded' => 'allow'],
            ],
        ]);
        $store = new FakeRiskStateStore();
        $engine = new AdaptiveRiskEngine($store, $classifier, new RiskIdentityFactory($keys), new RiskScorer(), $policy, $keys);
        $gateway = new RiskGateway($engine, $classifier, new RiskProfileResolver(PoWAlgorithm::Sha256, 8), ['login' => 1], policy: $policy);
        $logger = new PartitionLoggerSpy();
        $controller = new ChallengeController(
            $issuer,
            null,
            true,
            $gateway,
            new ContinuityCookie(),
            epochMonitor: $monitor,
            decoyV3Enabled: true,
            logger: $logger,
        );

        return [$controller, $logger];
    }

    private function siteverify(RedisStorage $storage, SecurityEpochMonitor $monitor, string $token): \Symfony\Component\HttpFoundation\Response
    {
        $controller = new SiteVerifyController(
            new Verifier($storage),
            self::SECRET,
            [self::SITEVERIFY_SECRET => 'login'],
            $storage,
            null,
            null,
            null,
            null,
            0.5,
            0,
            null,
            null,
            $monitor,
        );

        return $controller->siteverify($this->siteverifyRequest([
            'secret' => self::SITEVERIFY_SECRET,
            'response' => $token,
            'remoteip' => '127.0.0.1',
        ]));
    }

    public function testIssuanceFailsClosedWhenThePolicyRedisIsUnreachablePastTheMaxStaleWindow(): void
    {
        $client = $this->redisClient();
        $this->seedPolicy($client, 1, 1);
        $storage = new RedisStorage($client, self::PREFIX);
        $policy = $this->failingClient($this->redisClient());
        $monitor = new SecurityEpochMonitor(new Verifier($storage), $policy, self::NAMESPACE, 1, 1, $this->clock(...), self::MAX_STALE_SECS);
        $controller = new ChallengeController($this->issuer($storage), epochMonitor: $monitor);

        $this->clockMs = 0;
        [$status, $data] = $this->issue($controller);
        self::assertSame(200, $status, 'a fresh central policy read serves issuance');
        self::assertIsString($data['nonce'] ?? null);

        // The policy side goes dark within the max-stale window: the
        // last-known policy keeps serving, the bounded outage tolerance.
        $policy->failAll = true;
        $this->clockMs = 5_000;
        [$status] = $this->issue($controller);
        self::assertSame(200, $status, 'within the max-stale window the last-known policy keeps serving');
        self::assertFalse($monitor->isStale(), 'within the window the outage is not stale');

        // Past the window issuance fails closed: 503, never a minted
        // challenge under a policy the node can no longer confirm.
        $this->clockMs = 90_000;
        [$status, $data] = $this->issue($controller);
        self::assertSame(503, $status, 'past the max-stale window issuance refuses with 503');
        self::assertSame('SERVICE_UNAVAILABLE', $data['error']['code'] ?? null);
        self::assertTrue($monitor->isStale(), 'past last_success + max_stale the monitor is stale');

        // The policy side recovers: the next refresh confirms the
        // central state and issuance serves again.
        $policy->failAll = false;
        $this->clockMs = 91_000;
        [$status] = $this->issue($controller);
        self::assertSame(200, $status, 'a recovered central read refreshes the max-stale deadline');
        self::assertFalse($monitor->isStale());
    }

    public function testSiteVerifyFailsClosedWhenThePolicyRedisIsUnreachablePastTheMaxStaleWindow(): void
    {
        $client = $this->redisClient();
        $this->seedPolicy($client, 1, 1);
        $storage = new RedisStorage($client, self::PREFIX);
        $issuer = $this->issuer($storage);
        $policy = $this->failingClient($this->redisClient());
        $monitor = new SecurityEpochMonitor(new Verifier($storage), $policy, self::NAMESPACE, 1, 1, $this->clock(...), self::MAX_STALE_SECS);

        // Three tokens: one per phase, so each phase starts with a
        // pending record and the phase outcome is attributable.
        $tokenHealthy = $this->solveRecord($storage, $issuer);
        $tokenWindow = $this->solveRecord($storage, $issuer);
        $tokenStale = $this->solveRecord($storage, $issuer);

        $this->clockMs = 0;
        $response = $this->siteverify($storage, $monitor, $tokenHealthy);
        self::assertSame(200, $response->getStatusCode(), 'a fresh central policy read serves verification');
        self::assertTrue(json_decode((string) $response->getContent(), true)['success']);

        // Within the window the cached policy keeps serving.
        $policy->failAll = true;
        $this->clockMs = 5_000;
        $response = $this->siteverify($storage, $monitor, $tokenWindow);
        self::assertSame(200, $response->getStatusCode(), 'within the max-stale window the last-known policy keeps serving verification');

        // Past the window verification fails closed: the retryable
        // provider internal-error, with nothing claimed and nothing
        // verified — the token is not burned.
        $this->clockMs = 90_000;
        $response = $this->siteverify($storage, $monitor, $tokenStale);
        self::assertSame(503, $response->getStatusCode(), 'past the max-stale window SiteVerify refuses with the retryable 503');
        self::assertSame(['internal-error'], json_decode((string) $response->getContent(), true)['error-codes']);
        self::assertTrue($monitor->isStale());
        self::assertNull($storage->consumedState($this->nonceOf($tokenStale)), 'the stale refusal claims nothing and verifies nothing');

        // The documented retry: once the state is confirmable again the
        // same token verifies.
        $policy->failAll = false;
        $this->clockMs = 91_000;
        $response = $this->siteverify($storage, $monitor, $tokenStale);
        self::assertSame(200, $response->getStatusCode(), 'the retry succeeds once the central state is confirmable again');
        self::assertFalse($monitor->isStale());
    }

    public function testRecoveringAuthorityWithALowerProtocolFloorReEvaluatesTheEmissionGate(): void
    {
        $client = $this->redisClient();
        $this->seedPolicy($client, 2, 3);
        $storage = new RedisStorage($client, self::PREFIX);
        $policy = $this->failingClient($this->redisClient());
        $monitor = new SecurityEpochMonitor(new Verifier($storage), $policy, self::NAMESPACE, 1, 1, $this->clock(...), self::MAX_STALE_SECS);
        [$controller, $logger] = $this->v3Stack($this->issuer($storage), $monitor);

        // Confirmed floor 3 arms protocol v3.
        $this->clockMs = 0;
        [$status, $data] = $this->issue($controller);
        self::assertSame(200, $status);
        $nonce1 = $data['nonce'];
        self::assertSame(3, $storage->find($nonce1)?->protocolVersion, 'a confirmed central floor 3 arms protocol v3');
        self::assertSame(3, $monitor->minProtocolVersion());

        // The policy side goes dark: the floor becomes unconfirmed and
        // issuance falls back to v2 within the max-stale window. The
        // gate never arms on uncertainty.
        $policy->failAll = true;
        $this->clockMs = 1_500;
        [$status, $data] = $this->issue($controller);
        self::assertSame(200, $status, 'the outage within the window keeps issuance available');
        self::assertSame(2, $storage->find($data['nonce'])?->protocolVersion, 'an unreadable central policy emits v2, never a stale 3');
        self::assertNull($monitor->minProtocolVersion(), 'the floor stays unconfirmed during the outage');

        // The authority recovers with a lower floor (2) and a regressed
        // epoch (1). The floor is non-monotonic: it takes effect on the
        // next read and the emission gate re-evaluates. The epoch stays
        // monotonic: the observed max 2 is never weakened.
        $policy->failAll = false;
        $this->seedPolicy($client, 1, 2);
        $this->clockMs = 3_000;
        [$status, $data] = $this->issue($controller);
        self::assertSame(200, $status);
        self::assertSame(2, $monitor->minProtocolVersion(), 'a regressed floor is observed on the next read, never a sticky 3');
        self::assertSame(2, $storage->find($data['nonce'])?->protocolVersion, 'the emission gate re-evaluates: a floor of 2 keeps v2');
        self::assertSame(2, $monitor->currentEpoch(), 'the regressed central epoch is ignored by the monotonic max');
        self::assertSame(2, $monitor->observedMax());
        self::assertNotEmpty($logger->warnings, 'the gate logged the v2 fallback warning at least once');
    }

    public function testSplitBrainNeverServesASuccessUnderALostPolicy(): void
    {
        $client = $this->redisClient();
        $this->seedPolicy($client, 1, 1);
        $challengeInner = $this->redisClient();
        $storage = new RedisStorage($challengeInner, self::PREFIX);
        $challenge = $this->failingClient($challengeInner);
        $wiredStorage = new RedisStorage($challenge, self::PREFIX);
        $issuer = $this->issuer($wiredStorage);
        $policy = $this->failingClient($this->redisClient());
        $monitor = new SecurityEpochMonitor(new Verifier($wiredStorage), $policy, self::NAMESPACE, 1, 1, $this->clock(...), self::MAX_STALE_SECS);
        $controller = new ChallengeController($issuer, epochMonitor: $monitor);

        // Phase 1, the healthy control: issuance, native validation and
        // SiteVerify all succeed.
        $this->clockMs = 0;
        [$status, $data] = $this->issue($controller);
        self::assertSame(200, $status, 'the healthy control issuance succeeds');
        $token1 = $this->solveRecordFromNonce($storage, $data['nonce']);
        self::assertSame([], $this->validate($this->validatorStack(new Verifier($wiredStorage), $monitor), $token1), 'the healthy control validation is clean');
        $tokenSite1 = $this->solveRecord($storage, $issuer, '127.0.0.1');
        self::assertSame(200, $this->siteverify($wiredStorage, $monitor, $tokenSite1)->getStatusCode(), 'the healthy control SiteVerify succeeds');

        // Phase 2: the policy authority is lost while the challenge
        // authority stays reachable. Issuance and verification both fail
        // closed; the valid tokens are never granted.
        $tokenNative2 = $this->solveRecord($storage, $issuer, '198.51.100.7');
        $tokenSite2 = $this->solveRecord($storage, $issuer, '127.0.0.1');
        $policy->failAll = true;
        $this->clockMs = 90_000;
        [$status] = $this->issue($controller);
        self::assertSame(503, $status, 'issuance fails closed under a lost policy');
        self::assertTrue($monitor->isStale(), 'the failure is attributed to the stale policy');
        $violations = $this->validate($this->validatorStack(new Verifier($wiredStorage), $monitor), $tokenNative2);
        self::assertCount(1, $violations);
        self::assertSame(KiwiCaptchaConstraint::TEMPORARY_UNAVAILABLE_ERROR, $violations[0]->getCode(), 'a stale policy fails native verification closed');
        $response = $this->siteverify($wiredStorage, $monitor, $tokenSite2);
        self::assertSame(503, $response->getStatusCode(), 'SiteVerify fails closed under a lost policy');
        self::assertSame(['internal-error'], json_decode((string) $response->getContent(), true)['error-codes']);
        self::assertNull($storage->consumedState($this->nonceOf($tokenNative2)), 'the lost-policy refusal never consumes the token');
        self::assertNull($storage->consumedState($this->nonceOf($tokenSite2)), 'the lost-policy refusal never consumes the SiteVerify token either');

        // Phase 3: the policy authority recovers and the challenge
        // authority is lost. The monitor is fresh again, and the typed
        // fail-closed outcomes now come from the storage side.
        $policy->failAll = false;
        $challenge->failAll = true;
        $this->clockMs = 91_000;
        [$status] = $this->issue($controller);
        self::assertSame(503, $status, 'issuance fails closed when the challenge authority is lost');
        self::assertFalse($monitor->isStale(), 'the failure is attributed to the challenge storage, not the policy');
        $violations = $this->validate($this->validatorStack(new Verifier($wiredStorage), $monitor), $tokenNative2);
        self::assertCount(1, $violations);
        self::assertSame(KiwiCaptchaConstraint::TEMPORARY_UNAVAILABLE_ERROR, $violations[0]->getCode(), 'a storage outage fails native verification closed');
        $response = $this->siteverify($wiredStorage, $monitor, $tokenSite2);
        self::assertSame(503, $response->getStatusCode(), 'SiteVerify fails closed when the challenge authority is lost');

        // Phase 4: recovery. The fail-closed refusals never burned the
        // token: the same verification succeeds once both authorities
        // answer again.
        $challenge->failAll = false;
        $this->clockMs = 92_000;
        self::assertSame([], $this->validate($this->validatorStack(new Verifier($wiredStorage), $monitor), $tokenNative2), 'the recovered validation of the same token is clean');
    }

    public function testRealPolicyServerKillAndRestartDrivesTheSameFailClosedContract(): void
    {
        if (trim((string) shell_exec('command -v redis-server')) === '') {
            self::markTestSkipped('redis-server not on PATH — the real-kill variant needs a local redis-server build');
        }
        $client = $this->redisClient();
        $storage = new RedisStorage($client, self::PREFIX);
        $issuer = $this->issuer($storage);
        $this->tmpDir = sys_get_temp_dir().'/kiwicaptcha-policy-'.bin2hex(random_bytes(6));
        if (!mkdir($this->tmpDir, 0o700, true) && !is_dir($this->tmpDir)) {
            self::markTestSkipped('cannot create the policy-kill scratch directory');
        }
        $port = $this->freePort();
        $this->spawnPolicyServer($port);
        $policy = new \Predis\Client('tcp://127.0.0.1:'.$port, ['timeout' => 3.0]);
        $this->seedPolicy($policy, 1, 1);
        $monitor = new SecurityEpochMonitor(new Verifier($storage), $policy, self::NAMESPACE, 1, 1, $this->clock(...), self::MAX_STALE_SECS);
        $controller = new ChallengeController($issuer, epochMonitor: $monitor);
        $token = $this->solveRecord($storage, $issuer);

        $this->clockMs = 0;
        [$status] = $this->issue($controller);
        self::assertSame(200, $status, 'the real policy server serves issuance at T0');

        // The real server is killed: the monitor's next read hits a
        // genuine connection failure.
        $this->killPolicyServer();
        $this->clockMs = 90_000;
        [$status] = $this->issue($controller);
        self::assertSame(503, $status, 'a dead policy server refuses issuance past the window');
        self::assertTrue($monitor->isStale());
        $response = $this->siteverify($storage, $monitor, $token);
        self::assertSame(503, $response->getStatusCode(), 'a dead policy server refuses SiteVerify past the window');
        self::assertSame(['internal-error'], json_decode((string) $response->getContent(), true)['error-codes']);

        // The same port is bound again and the authority recovers with
        // the same state: the very same monitor process reconnects, the
        // next read confirms the central policy and both surfaces serve.
        $this->spawnPolicyServer($port);
        $this->seedPolicy($policy, 1, 1);
        $this->clockMs = 91_000;
        [$status] = $this->issue($controller);
        self::assertSame(200, $status, 'issuance recovers once the policy server answers again');
        self::assertFalse($monitor->isStale(), 'the recovered read refreshes the max-stale deadline');
        $response = $this->siteverify($storage, $monitor, $token);
        self::assertSame(200, $response->getStatusCode(), 'SiteVerify recovers with the same monitor and the same token');
    }

    private function solveRecord(RedisStorage $storage, Issuer $issuer, string $clientIp = '127.0.0.1'): string
    {
        $challenge = $issuer->issue('login', $clientIp);
        $record = $storage->find($challenge->nonce);
        self::assertNotNull($record);

        return $this->solve($record);
    }

    private function solveRecordFromNonce(RedisStorage $storage, string $nonce): string
    {
        $record = $storage->find($nonce);
        self::assertNotNull($record);

        return $this->solve($record);
    }

    private function nonceOf(string $token): string
    {
        $decoded = SolutionToken::decode($token);

        return $decoded->nonce;
    }

    private function freePort(): int
    {
        for ($attempt = 0; $attempt < 50; $attempt++) {
            $candidate = 20_000 + random_int(0, 25_000);
            $sock = @stream_socket_server('tcp://127.0.0.1:'.$candidate, $errno, $errstr);
            if ($sock !== false) {
                fclose($sock);

                return $candidate;
            }
        }
        self::markTestSkipped('no free local port available for the policy-kill variant: '.$errstr);
    }

    private function spawnPolicyServer(int $port): void
    {
        $log = $this->tmpDir.'/policy-'.$port.'.log';
        $args = ['redis-server', '--port', (string) $port, '--dir', $this->tmpDir, '--save', '', '--appendonly', 'no', '--logfile', $log];
        $proc = proc_open($args, [
            0 => ['pipe', 'r'],
            1 => ['file', $log, 'a'],
            2 => ['file', $log, 'a'],
        ], $pipes);
        if (!\is_resource($proc)) {
            self::markTestSkipped('failed to start the policy server (see '.$log.')');
        }
        fclose($pipes[0]);
        $this->procs[] = $proc;
        $deadline = microtime(true) + 10;
        while (microtime(true) < $deadline) {
            if (str_contains((string) @shell_exec('redis-cli -p '.$port.' ping 2>/dev/null'), 'PONG')) {
                return;
            }
            usleep(150_000);
        }
        self::fail('timed out waiting for the policy server on port '.$port);
    }

    private function killPolicyServer(): void
    {
        foreach ($this->procs as $index => $proc) {
            $status = proc_get_status($proc);
            if ($status !== false && $status['running']) {
                proc_terminate($proc, 9);
            }
            proc_close($proc);
            unset($this->procs[$index]);
        }
    }
}

/**
 * The once-per-process warning spy for the v3 emission gate: when the
 * writer switch is on but the confirmed central floor is below 3 (or
 * unconfirmed), the controller logs an actionable warning and keeps
 * emitting v2. The spy records the warnings for the assertion.
 */
final class PartitionLoggerSpy implements LoggerInterface
{
    /** @var list<string> */
    public array $warnings = [];

    public function warning(string|\Stringable $message, array $context = []): void
    {
        $this->warnings[] = (string) $message;
    }

    public function emergency(string|\Stringable $message, array $context = []): void
    {
    }

    public function alert(string|\Stringable $message, array $context = []): void
    {
    }

    public function critical(string|\Stringable $message, array $context = []): void
    {
    }

    public function error(string|\Stringable $message, array $context = []): void
    {
    }

    public function notice(string|\Stringable $message, array $context = []): void
    {
    }

    public function info(string|\Stringable $message, array $context = []): void
    {
    }

    public function debug(string|\Stringable $message, array $context = []): void
    {
    }

    public function log($level, string|\Stringable $message, array $context = []): void
    {
    }
}
