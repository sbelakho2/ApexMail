<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests;

use BelConsulting\KiwiCaptchaBundle\Command\KiwiCaptchaDoctorCommand;
use BelConsulting\KiwiCaptchaBundle\DependencyInjection\Configuration;
use BelConsulting\KiwiCaptchaBundle\DependencyInjection\KiwiCaptchaExtension;
use BelConsulting\KiwiCaptchaBundle\DependencyInjection\ProtectionProfileDefaults;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\RedisTestUrl;
use BelConsulting\KiwiCaptchaBundle\Tests\Kernel\RecipeConfigTestKernel;
use BelConsulting\KiwiCaptchaBundle\Tests\Kernel\TestKernel;
use KiwiCaptcha\Challenge;
use KiwiCaptcha\PoWAlgorithm;
use KiwiCaptcha\SolutionToken;
use KiwiCaptcha\Storage\RedisStorage;
use KiwiCaptcha\StorageInterface;
use KiwiCaptcha\Verifier;
use PHPUnit\Framework\TestCase;
use Symfony\Bundle\FrameworkBundle\KernelBrowser;
use Symfony\Component\Config\Definition\Processor;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Tester\CommandTester;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\ContainerInterface;
use Symfony\Component\Yaml\Yaml;

/**
 * Validation of the recipes-contrib package
 * (recipes-contrib/bel-consulting/kiwicaptcha-symfony/1.0/): the
 * manifest, the copied config/routes files and the fixture skeleton
 * must be coherent with each other and with the bundle's Configuration.
 * The recipe's config/packages/kiwicaptcha.yaml is processed through
 * the bundle's `Configuration` with the `%env()` placeholders resolved
 * to test values, exactly like a container resolves them at runtime.
 * A kernel booted with the recipe's exact config values proves the
 * install experience end to end.
 */
final class RecipePackageValidationTest extends TestCase
{
    private const SECRET = '0123456789abcdef0123456789abcdef';

    private function recipeDir(): string
    {
        return \dirname(__DIR__, 5).'/recipes-contrib/bel-consulting/kiwicaptcha-symfony/1.0';
    }

    private function recipeFile(string $relative): string
    {
        $path = $this->recipeDir().'/'.$relative;
        if (!is_file($path)) {
            self::markTestSkipped(sprintf('the recipe package is not present at %s', $path));
        }

        return $path;
    }

    /**
     * @return array<string, mixed> the decoded recipe manifest
     */
    private function manifest(): array
    {
        $manifest = json_decode((string) file_get_contents($this->recipeFile('manifest.json')), true);
        self::assertIsArray($manifest, 'manifest.json must be valid JSON');

        return $manifest;
    }

    /**
     * The recipe's config/packages/kiwicaptcha.yaml with every %env()%
     * placeholder resolved to the manifest-declared value. The
     * container resolves the same placeholders at compile time; Flex
     * writes the manifest defaults into .env, with the generated
     * secret replaced by a test value.
     *
     * @return array<string, mixed>
     */
    private function recipeConfigResolved(): array
    {
        $raw = Yaml::parseFile($this->recipeFile('config/packages/kiwicaptcha.yaml'));
        self::assertIsArray($raw, 'the recipe config must parse as YAML');
        $config = $raw['kiwi_captcha'] ?? null;
        self::assertIsArray($config, 'the recipe config must carry the kiwi_captcha root key');
        $manifest = $this->manifest();
        $envValues = [];
        foreach ($manifest['env'] ?? [] as $key => $default) {
            $envValues[$key] = \is_string($default) ? $default : 'recipe-test-value-'.$key;
        }
        $envValues['KIWI_SECRET_KEY'] = self::SECRET;
        foreach ($config as $k => $v) {
            if (\is_string($v)) {
                $config[$k] = preg_replace_callback('/%env\(([A-Z0-9_]+)\)%/', static function (array $m) use ($envValues): string {
                    return $envValues[$m[1]];
                }, $v);
            }
        }

        return $config;
    }

    /**
     * @param array<string, mixed> $config
     *
     * @return array<string, mixed>
     */
    private function process(array $config, array $overlay = []): array
    {
        $layers = $overlay === [] ? [$config] : [$config, $overlay];
        $processed = (new Processor())->processConfiguration(
            new Configuration(),
            ProtectionProfileDefaults::stack($layers),
        );

        return ProtectionProfileDefaults::finalize($processed, $layers);
    }

    public function testManifestJsonIsValidAndDeclaresTheRecipeContract(): void
    {
        $manifest = $this->manifest();

        self::assertSame(
            ['BelConsulting\\KiwiCaptchaBundle\\KiwiCaptchaBundle' => ['all']],
            $manifest['bundles'],
            'the manifest must register the bundle for every environment',
        );
        self::assertSame(['config/' => '%CONFIG_DIR%/'], $manifest['copy-from-recipe'], 'the manifest copies the config directory');
        self::assertSame(
            ['KIWI_SECRET_KEY', 'KIWI_REDIS_DSN', 'KIWI_PUBLIC_URL'],
            array_keys($manifest['env']),
            'the manifest declares the secret, the Redis DSN and the public origin the config references',
        );
        self::assertSame('redis://127.0.0.1:6379/0', $manifest['env']['KIWI_REDIS_DSN'], 'the manifest ships a localhost DSN default');
        self::assertSame('https://captcha.example.com', $manifest['env']['KIWI_PUBLIC_URL'], 'the manifest ships a placeholder origin default');
    }

    public function testEveryConfigEnvPlaceholderIsDeclaredInTheManifest(): void
    {
        $yaml = (string) file_get_contents($this->recipeFile('config/packages/kiwicaptcha.yaml'));
        preg_match_all('/%env\(([A-Z0-9_]+)\)%/', $yaml, $matches);
        $used = array_values(array_unique($matches[1]));

        self::assertSame(
            ['KIWI_SECRET_KEY', 'KIWI_PUBLIC_URL', 'KIWI_REDIS_DSN'],
            $used,
            'the recipe config references exactly the manifest-declared env keys',
        );
    }

    public function testRecipeConfigProcessesCleanlyThroughTheBundleConfiguration(): void
    {
        $processed = $this->process($this->recipeConfigResolved());

        self::assertSame('balanced', $processed['protection_profile']);
        self::assertSame(self::SECRET, $processed['secret_key'], 'the %env()% secret placeholder resolves into the processed config');
        self::assertSame('https://captcha.example.com', $processed['public_base_url'], 'the manifest-declared public origin processes cleanly');
        self::assertSame('redis://127.0.0.1:6379/0', $processed['redis_dsn'], 'the manifest-declared DSN processes cleanly');
        self::assertSame(18, $processed['difficulty_bits'], 'the balanced profile defaults apply');
        self::assertFalse($processed['risk']['enabled'], 'balanced keeps risk off');
    }

    public function testRecipeConfigWithAProdProfileOverlayProcessesCleanly(): void
    {
        // The recipe file plus a prod overlay that switches the profile:
        // the same layered processing a real app performs with
        // config/packages/prod/kiwicaptcha.yaml.
        $processed = $this->process($this->recipeConfigResolved(), ['protection_profile' => 'high_abuse']);

        self::assertSame('high_abuse', $processed['protection_profile'], 'the later profile layer wins');
        self::assertSame(self::SECRET, $processed['secret_key'], 'the recipe values survive the overlay');
        self::assertSame('redis://127.0.0.1:6379/0', $processed['redis_dsn']);
        self::assertTrue($processed['risk']['enabled'], 'high_abuse enables the risk engine');
        self::assertSame(5, $processed['rate_limit'], 'high_abuse derives the tightened per-source limit');
    }

    public function testRoutesYamlParsesAsTheBundleRouteImport(): void
    {
        $routes = Yaml::parseFile($this->recipeFile('config/routes/kiwicaptcha.yaml'));
        self::assertSame(
            ['kiwi_captcha' => ['resource' => '@KiwiCaptchaBundle/Resources/config/routes.php']],
            $routes,
            'the recipe routes import the bundle route file',
        );
    }

    public function testFixtureComposerJsonIsValid(): void
    {
        $fixture = json_decode((string) file_get_contents($this->recipeFile('tests/Fixtures/composer.json')), true);
        self::assertIsArray($fixture, 'the fixture composer.json must be valid JSON');
        self::assertSame('project', $fixture['type']);
        foreach (['symfony/flex', 'predis/predis', 'bel-consulting/kiwicaptcha-symfony'] as $required) {
            self::assertArrayHasKey($required, $fixture['require'], 'the fixture must require '.$required);
        }
    }

    public function testRecipeShapedConfigBootsAKernelAndPassesDoctorWithTheDsn(): void
    {
        $url = RedisTestUrl::resolve();
        if ($url === null) {
            self::markTestSkipped('TEST_REDIS_URL / KC_REDIS_URL not set — the recipe-shaped boot test needs a real Redis');
        }

        // The manifest generates the secret and declares the DSN and
        // origin defaults into .env; the real container resolves the
        // %env()% placeholders from the process environment.
        putenv(RecipeConfigTestKernel::SECRET_ENV.'='.self::SECRET);
        putenv(RecipeConfigTestKernel::REDIS_DSN_ENV.'='.$url);
        putenv(RecipeConfigTestKernel::PUBLIC_URL_ENV.'=https://captcha.example.com');
        $kernel = new RecipeConfigTestKernel('test', true);
        $kernel->boot();
        $container = $kernel->getContainer()->get('test.service_container');

        try {
            // The %env()% secret resolved end to end: the core Config the
            // extension built carries the real secret, not the
            // placeholder string.
            $config = $container->get('kiwi_captcha.config');
            self::assertSame(self::SECRET, $config->secretKey, 'the recipe %env()% secret resolves into the wired core config');

            // The %env()% DSN resolved end to end: the runtime guard
            // validated the resolved shape and the client is a real
            // Predis client over the environment-managed connection.
            $client = $container->get('kiwi_captcha.redis.dsn');
            self::assertInstanceOf(\Predis\Client::class, $client);
            $params = $client->getConnection()->getParameters()->toArray();
            self::assertSame((string) parse_url($url, PHP_URL_HOST), $params['host'], 'the env-resolved DSN drives the connection host');
            self::assertSame((int) (parse_url($url, PHP_URL_PORT) ?? 6379), $params['port'], 'the env-resolved DSN drives the connection port');
            $client->flushdb();

            $storage = $container->get(StorageInterface::class);
            self::assertInstanceOf(RedisStorage::class, $storage, 'the recipe DSN builds the atomic challenge storage');

            $tester = new CommandTester($container->get(KiwiCaptchaDoctorCommand::class));
            $tester->execute([]);
            self::assertSame(Command::SUCCESS, $tester->getStatusCode(), 'no FAIL means exit 0');
            $display = $tester->getDisplay();
            self::assertStringContainsString('[PASS] Redis reachability', $display, 'the recipe DSN client answers PING');
            self::assertStringContainsString('[PASS] Storage atomicity', $display);
            self::assertStringNotContainsString('[FAIL]', $display);

            // The full install experience: an HTTP challenge issued by
            // the recipe-shaped kernel solves and verifies.
            $browser = new KernelBrowser($kernel);
            $browser->request('POST', '/kiwi-captcha/challenge', server: ['CONTENT_TYPE' => 'application/json'], content: '{"scope":"login"}');
            self::assertSame(200, $browser->getResponse()->getStatusCode(), 'the recipe-shaped kernel serves the challenge endpoint');
            $data = json_decode($browser->getResponse()->getContent(), true);
            $challenge = $this->challengeFromData($data);
            $this->waitOutMinDuration($challenge);

            $verifier = $container->get('kiwi_captcha.verifier');
            $nowNs = (int) (microtime(true) * 1_000_000) + 1_000_000;
            $outcome = $verifier->verify($this->solveToken($challenge), self::SECRET, 'login', '127.0.0.1', $nowNs);
            self::assertTrue($outcome->isOk(), sprintf('the recipe-shaped round trip must verify, got %s', $outcome->code()));
        } finally {
            $kernel->shutdown();
            putenv(RecipeConfigTestKernel::SECRET_ENV);
            putenv(RecipeConfigTestKernel::REDIS_DSN_ENV);
            putenv(RecipeConfigTestKernel::PUBLIC_URL_ENV);
        }
    }

    /**
     * The bundle contract that shaped the recipe: the %env()% DSN form
     * is accepted at container build time, since the value flows
     * through the container's parameter bag and the runtime guard
     * validates the resolved shape when the client is constructed. The
     * recipe therefore ships the env-managed DSN and origin.
     */
    public function testEnvPlaceholderDsnIsAcceptedAtContainerBuild(): void
    {
        $container = new ContainerBuilder();
        $container->setParameter('kernel.environment', 'dev');
        (new KiwiCaptchaExtension())->load([[
            'secret_key' => self::SECRET,
            'redis_dsn' => '%env(KIWI_REDIS_DSN)%',
        ]], $container);

        // The build succeeds with the placeholder; the env-managed
        // client is constructed through the runtime validation guard.
        $client = $container->getDefinition('kiwi_captcha.redis.dsn');
        self::assertSame(\Predis\Client::class, $client->getClass(), 'the env-managed client stays typed Predis\Client');
        self::assertSame(
            [KiwiCaptchaExtension::class, 'createDsnClient'],
            $client->getFactory(),
            'the env-managed client is constructed through the runtime validation guard',
        );
        self::assertSame(['%env(KIWI_REDIS_DSN)%'], $client->getArguments(), 'the placeholder flows through the container parameter bag untouched');
        self::assertTrue($container->hasDefinition('kiwi_captcha.storage.redis_dsn'), 'the env DSN still builds the challenge storage');
    }

    /**
     * An env placeholder whose variable is never set must fail at
     * runtime (when the client is constructed), never at container
     * build time: the boot succeeds and the failure names the missing
     * environment variable.
     */
    public function testUnresolvedEnvDsnFailsAtRuntimeNotAtContainerBuild(): void
    {
        putenv(RecipeConfigTestKernel::PUBLIC_URL_ENV.'=https://captcha.example.com');
        putenv(RecipeConfigTestKernel::REDIS_DSN_ENV);
        $kernel = new RecipeConfigTestKernel('test', true);
        $kernel->boot();
        $container = $kernel->getContainer()->get('test.service_container');

        try {
            try {
                $container->get('kiwi_captcha.redis.dsn');
                self::fail('an unset env DSN must fail when the client is constructed, not at container build time');
            } catch (\Symfony\Component\DependencyInjection\Exception\EnvNotFoundException $e) {
                self::assertStringContainsString('KIWI_REDIS_DSN', $e->getMessage(), 'the runtime failure names the missing environment variable');
            }
        } finally {
            $kernel->shutdown();
            putenv(RecipeConfigTestKernel::PUBLIC_URL_ENV);
            putenv(RecipeConfigTestKernel::REDIS_DSN_ENV);
        }
    }

    /**
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

    private function waitOutMinDuration(Challenge $challenge): void
    {
        usleep(($challenge->minDurationMs + 10) * 1000);
    }
}
