<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests;

use BelConsulting\KiwiCaptchaBundle\Controller\ApiJsController;
use BelConsulting\KiwiCaptchaBundle\Controller\AssetController;
use BelConsulting\KiwiCaptchaBundle\Controller\ChallengeController;
use BelConsulting\KiwiCaptchaBundle\DependencyInjection\KiwiCaptchaExtension;
use BelConsulting\KiwiCaptchaBundle\Risk\SecurityEpochMonitor;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\FakePredisClient;
use BelConsulting\KiwiCaptchaBundle\Tests\Kernel\PrefixedTestKernel;
use PHPUnit\Framework\TestCase;
use Symfony\Bundle\FrameworkBundle\KernelBrowser;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\RequestStack;

/**
 * The compat loader's content-addressed descriptor table carries the
 * locales, telemetry and execution assets. Each digest is computed from
 * the exact asset bytes, so a compat page can lazy-fetch the execution
 * interpreter and the telemetry module under the configured route
 * prefix. The informational runtime and worker entries describe the
 * assets the compat loader already embeds. The legacy locales marker
 * stays byte-identical for the widget's existing locales path.
 *
 * The execution-armed test drives the real extension wiring, issues an
 * armed challenge through the controller and checks that the same
 * deployment publishes and serves the pinned interpreter descriptor.
 * Executing the interpreter in a browser stays with the Playwright
 * harness: the PHP harness has no script engine.
 */
final class CompatAssetDescriptorTest extends TestCase
{
    private const ASSETS_DIR = __DIR__.'/../Resources/public';

    private const SECRET = '0123456789abcdef0123456789abcdef';

    private const EXECUTION_KEY = 'fedcba9876543210fedcba9876543210';

    /** kind => [asset file, extension], the expected descriptor table shape. */
    private const COMPAT_FILES = [
        'locales' => ['widget-locales.js', 'js'],
        'telemetry' => ['widget-telemetry.js', 'js'],
        'execution' => ['execution-interpreter.js', 'js'],
        'runtime' => ['kiwicaptcha-wasm.js', 'js'],
        'worker' => ['kiwi-worker.js', 'js'],
    ];

    private static ?KernelBrowser $prefixedBrowser = null;

    protected function tearDown(): void
    {
        // The loader body is a per-process static cache: reset it so a
        // test that swapped the asset dir never leaks into the next one.
        (new \ReflectionClass(ApiJsController::class))->setStaticPropertyValue('cachedBody', null);
    }

    private function prefixedBrowser(): KernelBrowser
    {
        return self::$prefixedBrowser ??= new KernelBrowser(new PrefixedTestKernel('test', true));
    }

    /**
     * @return array<string, array{name: string, hash: string, sri: string, src: string, url: string}>
     */
    private function descriptorTable(string $body): array
    {
        self::assertSame(
            1,
            preg_match('~window\.__kiwiCaptchaCompatAssets=(\{[^\n]*\});~', $body, $matches),
            'the loader response carries the compat descriptor table',
        );
        $table = json_decode((string) $matches[1], true, 512, JSON_THROW_ON_ERROR);
        self::assertIsArray($table);

        return $table;
    }

    /**
     * The bytes and the two content digests of one shipped asset.
     *
     * @return array{0: string, 1: string, 2: string}
     */
    private function assetDigests(string $kind): array
    {
        [$file] = self::COMPAT_FILES[$kind];
        $bytes = (string) file_get_contents(self::ASSETS_DIR.'/'.$file);
        self::assertNotSame('', $bytes, $file.' must ship non-empty bytes');

        return [$bytes, hash('sha256', $bytes), 'sha256-'.base64_encode(hash('sha256', $bytes, true))];
    }

    public function testTheCompatLoaderUnderACustomPrefixPinsExecutionAndTelemetryToTheServedBytes(): void
    {
        $browser = $this->prefixedBrowser();
        $browser->request('GET', '/security/captcha/api.js?compat=recaptcha');
        $response = $browser->getResponse();
        self::assertSame(200, $response->getStatusCode());
        $table = $this->descriptorTable((string) $response->getContent());
        self::assertSame(array_keys(self::COMPAT_FILES), array_keys($table), 'the prefixed response carries every compat kind');

        foreach (['locales', 'telemetry', 'execution'] as $kind) {
            [$bytes, $hash, $sri] = $this->assetDigests($kind);
            $descriptor = $table[$kind];
            self::assertSame($hash, $descriptor['hash'], $kind.' hash equals the sha256 of the asset bytes');
            self::assertSame($sri, $descriptor['sri'], $kind.' integrity equals the SRI digest of the asset bytes');
            self::assertSame('assets/'.$kind.'.'.$hash.'.js', $descriptor['src'], $kind.' src is the script-relative content-addressed path');
            self::assertSame('/security/captcha/assets/'.$kind.'.'.$hash.'.js', $descriptor['url'], $kind.' url follows the configured route_prefix');

            $browser->request('GET', $descriptor['url']);
            $served = $browser->getResponse();
            self::assertSame(200, $served->getStatusCode(), $kind.' content-addressed URL routes');
            $servedBytes = (string) $served->getContent();
            self::assertSame($bytes, $servedBytes, $kind.' URL serves the exact shipped bytes');
            self::assertSame($hash, hash('sha256', $servedBytes), $kind.' URL hash is the full sha256 of the served bytes');
            self::assertSame('sha256-'.base64_encode(hash('sha256', $servedBytes, true)), $descriptor['sri'], $kind.' descriptor digest equals the digest of the served bytes');
        }
    }

    public function testTheLocalesDescriptorStillMatchesTheLegacyCompatMarker(): void
    {
        $body = (string) (new ApiJsController(self::ASSETS_DIR))
            ->apiJs(Request::create('/kiwi-captcha/api.js'))
            ->getContent();
        [, $hash, $sri] = $this->assetDigests('locales');
        self::assertStringContainsString(
            'window.__kiwiCaptchaCompatLocales={name:"locales",hash:"'.$hash.'",sri:"'.$sri.'"}',
            $body,
            'the legacy locales marker keeps its exact shape and pins the real asset bytes',
        );
        $table = $this->descriptorTable($body);
        self::assertSame($hash, $table['locales']['hash']);
        self::assertSame($sri, $table['locales']['sri']);
        self::assertSame('/kiwi-captcha/assets/locales.'.$hash.'.js', $table['locales']['url']);
    }

    public function testEveryCompatDescriptorDigestMatchesTheAssetBytesOnDisk(): void
    {
        $body = (string) (new ApiJsController(self::ASSETS_DIR))
            ->apiJs(Request::create('/security/captcha/api.js'))
            ->getContent();
        $table = $this->descriptorTable($body);
        self::assertSame(array_keys(self::COMPAT_FILES), array_keys($table), 'the descriptor table carries exactly the compat kinds');

        foreach (self::COMPAT_FILES as $kind => [$file, $ext]) {
            [, $hash, $sri] = $this->assetDigests($kind);
            self::assertSame($hash, $table[$kind]['hash'], $kind.' hash is derived from '.$file);
            self::assertSame($sri, $table[$kind]['sri'], $kind.' integrity is derived from '.$file);
            self::assertSame('assets/'.$kind.'.'.$hash.'.'.$ext, $table[$kind]['src']);
            self::assertSame('/security/captcha/assets/'.$kind.'.'.$hash.'.'.$ext, $table[$kind]['url']);
        }
    }

    public function testTheDescriptorBearingLoaderKeepsTheEtagRevalidationContract(): void
    {
        $controller = new ApiJsController(self::ASSETS_DIR);
        $response = $controller->apiJs(Request::create('/kiwi-captcha/api.js'));
        $body = (string) $response->getContent();
        self::assertSame('"'.hash('sha256', $body).'"', $response->headers->get('ETag'), 'the ETag pins the exact descriptor-bearing response bytes');
        $cacheControl = (string) $response->headers->get('Cache-Control');
        self::assertStringContainsString('public', $cacheControl);
        self::assertStringContainsString('no-cache', $cacheControl);

        $revalidation = Request::create('/kiwi-captcha/api.js');
        $revalidation->headers->set('If-None-Match', (string) $response->headers->get('ETag'));
        $notModified = $controller->apiJs($revalidation);
        self::assertSame(304, $notModified->getStatusCode());
        self::assertSame('', (string) $notModified->getContent());
    }

    public function testAnExecutionArmedDeploymentIssuesAndServesTheInterpreterDescriptor(): void
    {
        $container = new ContainerBuilder();
        $container->setParameter('kernel.environment', 'test');
        $container->setParameter('kernel.project_dir', sys_get_temp_dir());
        $container->register('fake_redis', FakePredisClient::class);
        $container->register('request_stack', RequestStack::class);
        (new KiwiCaptchaExtension())->load([[
            'secret_key' => self::SECRET,
            'execution_key' => self::EXECUTION_KEY,
            // The storage/limiter Redis carries the central
            // security-policy read the arming gate confirms.
            'redis_service' => 'fake_redis',
            'difficulty_bits' => 8,
            'storage' => 'kiwi_captcha.storage.array',
            'risk' => ['enabled' => true, 'redis_service' => 'fake_redis', 'execution_challenge' => 'on'],
        ]], $container);

        // The two-phase protocol-v4 rollout gate: arming requires the
        // confirmed central floor >= 4, seeded into the fake security
        // Redis exactly as the existing dimension test does.
        $redis = $container->get('fake_redis');
        $monitor = $container->get(SecurityEpochMonitor::class);
        $redis->hset($monitor->policyKey(), 'min_protocol_version', 4);

        $issued = $container->get(ChallengeController::class)->challenge(Request::create('/kiwi-captcha/challenge', 'POST', [], [], [], [
            'CONTENT_TYPE' => 'application/json',
            'REMOTE_ADDR' => '127.0.0.1',
            'HTTP_ORIGIN' => 'http://localhost',
        ], '{"scope":"login"}'));
        self::assertSame(200, $issued->getStatusCode(), (string) $issued->getContent());
        $payload = json_decode((string) $issued->getContent(), true);
        self::assertIsArray($payload);
        self::assertArrayHasKey('execution_program', $payload, 'the armed issuance carries the execution program the compat page must run');

        $body = (string) $container->get(ApiJsController::class)
            ->apiJs(Request::create('/kiwi-captcha/api.js'))
            ->getContent();
        $table = $this->descriptorTable($body);
        [$interpreter, $hash, $sri] = $this->assetDigests('execution');
        self::assertSame($hash, $table['execution']['hash']);
        self::assertSame($sri, $table['execution']['sri']);

        // The same content-addressed route the browser fetches on the
        // armed lifecycle serves the pinned interpreter bytes.
        $served = $container->get(AssetController::class)->asset(
            Request::create($table['execution']['url']),
            'execution',
            $hash,
            'js',
        );
        self::assertSame(200, $served->getStatusCode());
        self::assertSame($interpreter, (string) $served->getContent(), 'the descriptor URL serves the exact execution interpreter bytes');
    }
}
