<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests;

use BelConsulting\KiwiCaptchaBundle\Command\KiwiCaptchaDoctorCommand;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\RedisTestUrl;
use BelConsulting\KiwiCaptchaBundle\Tests\Kernel\NewIntegratorSmokeKernel;
use BelConsulting\KiwiCaptchaBundle\Tests\Kernel\TestKernel;
use KiwiCaptcha\Challenge;
use KiwiCaptcha\PoWAlgorithm;
use KiwiCaptcha\SolutionToken;
use KiwiCaptcha\Storage\ArrayStorage;
use KiwiCaptcha\Storage\RedisStorage;
use KiwiCaptcha\StorageInterface;
use KiwiCaptcha\Verifier;
use PHPUnit\Framework\TestCase;
use Symfony\Bundle\FrameworkBundle\KernelBrowser;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Tester\CommandTester;
use Symfony\Component\DependencyInjection\ContainerInterface;

/**
 * The new-integrator smoke harness: simulates the minimal-configuration
 * user experience end to end. A fresh kernel wired with only
 * `protection_profile`, `secret_key`, `public_base_url` and `redis_dsn`
 * must boot, pass `kiwicaptcha:doctor` with the DSN-backed Redis rows,
 * and serve a full HTTP challenge issuance, solve and verification
 * round trip through the DSN-built services. The `high_abuse` variant
 * boots on the same DSN with the risk state store, the widget include
 * ships its public assets, and the advanced escape hatch (an explicit
 * storage service id) still wins over the DSN.
 *
 * Runs only when a real Redis is published (`TEST_REDIS_URL` /
 * `KC_REDIS_URL`), like every real-Redis test in this suite.
 */
final class NewIntegratorSmokeTest extends TestCase
{
    private function redisUrl(): string
    {
        $url = RedisTestUrl::resolve();
        if ($url === null) {
            self::markTestSkipped('TEST_REDIS_URL / KC_REDIS_URL not set — the new-integrator smoke test needs a real Redis');
        }

        return $url;
    }

    private function kernel(string $profile, string $dsn, ?string $storageServiceId = null): NewIntegratorSmokeKernel
    {
        return new NewIntegratorSmokeKernel('test', true, $profile, $dsn, $storageServiceId);
    }

    private function container(NewIntegratorSmokeKernel $kernel): ContainerInterface
    {
        $kernel->boot();

        return $kernel->getContainer()->get('test.service_container');
    }

    /**
     * The suite shares one Redis database; wipe it before each leg so a
     * leftover counter or consumed record can never skew the outcome.
     */
    private function flushRedis(ContainerInterface $container): void
    {
        $client = $container->get('kiwi_captcha.redis.dsn');
        self::assertInstanceOf(\Predis\Client::class, $client, 'the DSN-built client is a Predis client');
        $client->flushdb();
    }

    public function testMinimalBalancedConfigBootsAndDoctorPassesWithTheDsnBackedRedisRows(): void
    {
        $kernel = $this->kernel('balanced', $this->redisUrl());
        $container = $this->container($kernel);

        try {
            $this->flushRedis($container);

            // The minimal config builds the DSN-backed storage itself:
            // the StorageInterface alias resolves to a RedisStorage over
            // the DSN client, with no storage service wiring anywhere.
            $storage = $container->get(StorageInterface::class);
            self::assertInstanceOf(RedisStorage::class, $storage, 'the DSN-built challenge storage is the atomic RedisStorage');

            // A fresh integrator gets the recommended files asset tier by
            // default (asset_mode default flip): the theme emits versioned
            // immutable asset URLs, and the driver fetches the runtime and
            // the worker only when a memory-hard challenge arrives.
            self::assertSame(
                'files',
                $container->get(\BelConsulting\KiwiCaptchaBundle\Twig\KiwiCaptchaRuntime::class)->assetMode(),
                'the minimal-configuration contract must default to the files asset tier',
            );

            $tester = new CommandTester($container->get(KiwiCaptchaDoctorCommand::class));
            $tester->execute([]);

            self::assertSame(Command::SUCCESS, $tester->getStatusCode(), 'no FAIL means exit 0');
            $display = $tester->getDisplay();
            self::assertStringContainsString('[PASS] Redis reachability', $display, 'the DSN-backed client answers PING');
            self::assertStringContainsString('[PASS] Storage atomicity', $display, 'the DSN-built RedisStorage is atomic');
            self::assertStringContainsString('[PASS] Risk Redis', $display, 'risk is disabled, so the check passes');
            self::assertStringNotContainsString('[FAIL]', $display, 'the minimal balanced config must not FAIL any check');
        } finally {
            $kernel->shutdown();
        }
    }

    public function testHttpChallengeRoundTripThroughTheDsnBuiltServices(): void
    {
        $kernel = $this->kernel('balanced', $this->redisUrl());
        $container = $this->container($kernel);

        try {
            $this->flushRedis($container);

            // HTTP issuance through the real router: the extension
            // auto-registered the challenge route on this fresh kernel
            // (the same out-of-the-box behavior a recipe install gets).
            $browser = new KernelBrowser($kernel);
            $browser->request('POST', '/kiwi-captcha/challenge', server: ['CONTENT_TYPE' => 'application/json'], content: '{"scope":"login"}');
            $response = $browser->getResponse();
            self::assertSame(200, $response->getStatusCode(), 'the minimal config must serve the challenge endpoint');

            $data = json_decode($response->getContent(), true);
            self::assertSame('sha256', $data['algorithm'], 'the balanced profile issues sha256');
            self::assertSame(18, $data['targetBits'], 'the profile default difficulty (18 bits) applies with no explicit knob');
            self::assertNotEmpty($data['nonce']);

            // Solve the proof-of-work in pure PHP and verify through the
            // same DSN-built verifier service the validator uses.
            $challenge = $this->challengeFromData($data);
            $this->waitOutMinDuration($challenge);
            $token = $this->solveToken($challenge);

            $verifier = $container->get('kiwi_captcha.verifier');
            $nowNs = (int) (microtime(true) * 1_000_000) + 1_000_000;
            $outcome = $verifier->verify($token, TestKernel::SECRET, 'login', '127.0.0.1', $nowNs);
            self::assertTrue($outcome->isOk(), sprintf('the HTTP-issued challenge must verify through the DSN-built services, got %s', $outcome->code()));
        } finally {
            $kernel->shutdown();
        }
    }

    public function testHighAbuseProfileBootsOnTheSameDsnWithRiskAndDoctorPass(): void
    {
        $kernel = $this->kernel('high_abuse', $this->redisUrl());
        $container = $this->container($kernel);

        try {
            $this->flushRedis($container);

            // high_abuse enables the adaptive risk engine; the DSN client
            // is a Predis client, so it must drive the risk state store.
            self::assertTrue($container->has(\BelConsulting\KiwiCaptchaBundle\Risk\RiskGateway::class), 'high_abuse wires the risk gateway');
            $riskStore = $container->get('kiwi_captcha.risk.store');
            self::assertInstanceOf(\KiwiCaptcha\Risk\Storage\RedisRiskStateStore::class, $riskStore, 'the risk state store is the canonical Redis-backed store');
            $storeClient = (new \ReflectionProperty($riskStore, 'client'))->getValue($riskStore);
            self::assertSame($container->get('kiwi_captcha.redis.dsn'), $storeClient, 'the risk state store runs on the DSN client');

            // high_abuse promises the decoy surface AND the execution
            // surface (the profile turns the execution gate on), so the
            // doctor FAILs the protocol-writer check until the two-phase
            // rollout confirms the fleet floor at v4 (see operations.md
            // "Protocol v4 execution rollout"). Complete step 2 of the
            // rollout (raise the central floor) before the doctor run: a
            // high_abuse deployment with a confirmed v4 floor must pass
            // every check.
            $dsnClient = $container->get('kiwi_captcha.redis.dsn');
            $monitor = $container->get(\BelConsulting\KiwiCaptchaBundle\Risk\SecurityEpochMonitor::class);
            $dsnClient->hset($monitor->policyKey(), 'min_protocol_version', 4);

            $tester = new CommandTester($container->get(KiwiCaptchaDoctorCommand::class));
            $tester->execute([]);

            self::assertSame(Command::SUCCESS, $tester->getStatusCode(), 'no FAIL means exit 0');
            $display = $tester->getDisplay();
            self::assertStringContainsString('[PASS] Risk Redis', $display, 'the risk Redis (the DSN client) answers PING');
            self::assertStringContainsString('[PASS] Storage atomicity', $display);
            self::assertStringContainsString('[PASS] Protocol-v3 writer', $display, 'the confirmed v4 floor satisfies the high_abuse decoy + execution contract');
            self::assertStringNotContainsString('[FAIL]', $display, 'the high_abuse config on the DSN must not FAIL any check');

            // The live risk engine must not break issuance: an ordinary
            // scope is assessed against real Redis state and a challenge
            // is issued.
            $browser = new KernelBrowser($kernel);
            $browser->request('POST', '/kiwi-captcha/challenge', server: ['CONTENT_TYPE' => 'application/json'], content: '{"scope":"login"}');
            self::assertSame(200, $browser->getResponse()->getStatusCode(), 'the risk-enabled high_abuse profile still issues challenges');
            self::assertNotEmpty(json_decode($browser->getResponse()->getContent(), true)['nonce']);
        } finally {
            $kernel->shutdown();
        }
    }

    public function testWidgetIncludeAssetsExistAndTheApiJsRouteServesThem(): void
    {
        $kernel = $this->kernel('balanced', $this->redisUrl());
        $this->container($kernel);

        try {
            // The Resources public assets the widget include (the form
            // theme, the driver core, its lazy widget modules and the
            // api.js compatibility loader) ship and serve.
            $assetsDir = \dirname(__DIR__).'/Resources/public';
            foreach (['kiwicaptcha-wasm.js', 'widget-driver.js', 'widget.css', 'widget-risk.js', 'widget-telemetry.js', 'widget-locales.js', 'widget-compat.js', 'kiwi-worker.js', 'execution-interpreter.js'] as $asset) {
                self::assertFileExists($assetsDir.'/'.$asset, 'the widget asset '.$asset.' must ship in Resources/public');
                self::assertGreaterThan(0, \strlen((string) file_get_contents($assetsDir.'/'.$asset)), $asset.' must not be empty');
            }

            $browser = new KernelBrowser($kernel);
            $browser->request('GET', '/kiwi-captcha/api.js?compat=recaptcha');
            $response = $browser->getResponse();
            self::assertSame(200, $response->getStatusCode(), 'the widget include must be servable through the route');
            self::assertSame('application/javascript; charset=UTF-8', $response->headers->get('Content-Type'));
            $body = (string) $response->getContent();
            self::assertStringContainsString('KIWI_WASM_B64', $body, 'the served loader carries the embedded WASM solver');
            self::assertStringContainsString('solver_protocol_version', $body, 'the served loader carries the solver driver');
        } finally {
            $kernel->shutdown();
        }
    }

    public function testExplicitStorageServiceWinsOverTheDsn(): void
    {
        // The advanced escape hatch: an explicit storage service id must
        // win over the DSN-built storage, while the DSN client keeps
        // filling the knobs the integrator did not set (limiter and
        // Argon admission).
        $kernel = $this->kernel('balanced', $this->redisUrl(), 'app.custom_captcha_storage');
        $container = $this->container($kernel);

        try {
            $this->flushRedis($container);

            self::assertFalse($container->has('kiwi_captcha.storage.redis_dsn'), 'the explicit storage service replaces the DSN-built storage');

            $custom = $container->get('app.custom_captcha_storage');
            self::assertInstanceOf(ArrayStorage::class, $custom, 'the custom ArrayStorage-based service is the one wired');
            self::assertSame($custom, $container->get(StorageInterface::class), 'the issuer/verifier consume the exact custom service instance');

            // The DSN client still drives the unset knobs.
            $dsnClient = $container->get('kiwi_captcha.redis.dsn');
            self::assertInstanceOf(\Predis\Client::class, $dsnClient, 'the DSN client is still built for the unset knobs');
            $limiterRedis = (new \ReflectionProperty($container->get('kiwi_captcha.rate_limiter'), 'redis'))->getValue($container->get('kiwi_captcha.rate_limiter'));
            self::assertSame($dsnClient, $limiterRedis, 'the rate limiter still runs on the DSN client');

            // The round trip through the custom storage: the issued
            // challenge lives in the custom ArrayStorage, and the
            // verification consumes the same record.
            $issuer = $container->get('kiwi_captcha.issuer');
            $challenge = $issuer->issue('login', '198.51.100.7');
            self::assertNotNull($custom->find($challenge->nonce), 'the issued challenge record lives in the custom storage, not Redis');

            $this->waitOutMinDuration($challenge);
            $token = $this->solveToken($challenge);
            $verifier = $container->get('kiwi_captcha.verifier');
            $nowNs = (int) (microtime(true) * 1_000_000) + 1_000_000;
            $outcome = $verifier->verify($token, TestKernel::SECRET, 'login', '198.51.100.7', $nowNs);
            self::assertTrue($outcome->isOk(), sprintf('the custom-storage round trip must verify, got %s', $outcome->code()));

            // The doctor stays green on the escape-hatch kernel: the
            // custom storage is atomic and the DSN still answers PING.
            $tester = new CommandTester($container->get(KiwiCaptchaDoctorCommand::class));
            $tester->execute([]);
            self::assertSame(Command::SUCCESS, $tester->getStatusCode());
            self::assertStringContainsString('[PASS] Redis reachability', $tester->getDisplay());
            self::assertStringNotContainsString('[FAIL]', $tester->getDisplay());
        } finally {
            $kernel->shutdown();
        }
    }

    /**
     * The wire shape of an issued challenge (the controller JSON, the
     * same shape the widget receives) reconstructs directly into the
     * core Challenge value.
     *
     * @param array<string, mixed> $data
     */
    private function challengeFromData(array $data): Challenge
    {
        return new Challenge(
            nonce: (string) $data['nonce'],
            challenge: (string) $data['challenge'],
            salt: (string) $data['salt'],
            algorithm: PoWAlgorithm::from((string) $data['algorithm']),
            mKib: (int) $data['mKib'],
            t: (int) $data['t'],
            p: (int) $data['p'],
            targetBits: (int) $data['targetBits'],
            ttlSecs: (int) $data['ttlSecs'],
            minDurationMs: (int) $data['minDurationMs'],
            prefix: (string) $data['prefix'],
        );
    }

    private function solveToken(Challenge $challenge): string
    {
        $counter = 0;
        $saltBytes = base64_decode($challenge->salt, true);
        do {
            $hash = hash('sha256', $challenge->prefix.$counter.$saltBytes, true);
            $counter++;
        } while (Verifier::leadingZeroBits($hash) < $challenge->targetBits);
        --$counter;

        return SolutionToken::create($challenge->nonce, $counter, 5000, [])->encode();
    }

    /**
     * The core enforces the minimum solve duration with a server-measured
     * clock; tests issue and verify in the same process, so wait out the
     * floor before submitting.
     */
    private function waitOutMinDuration(Challenge $challenge): void
    {
        usleep(($challenge->minDurationMs + 10) * 1000);
    }
}
