<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests;

use BelConsulting\KiwiCaptchaBundle\Command\KiwiCaptchaMigrateCommand;
use BelConsulting\KiwiCaptchaBundle\DependencyInjection\KiwiCaptchaExtension;
use BelConsulting\KiwiCaptchaBundle\Migration\IncumbentScanner;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Tester\CommandTester;
use Symfony\Component\DependencyInjection\ContainerBuilder;

/**
 * Tests of kiwicaptcha:migrate against fixture trees shaped like real
 * incumbent integrations. Every provider pattern matches, the emitted
 * shim config carries the client block, the scope mapping table and
 * the server swap steps. Kiwi's own markers produce no false
 * positives, the dependency trees stay out of the report, and the
 * path and output handling is safe.
 */
final class KiwiCaptchaMigrateCommandTest extends TestCase
{
    private const PROJECT = __DIR__.'/Fixtures/Migrate/project';
    private const MIGRATED = __DIR__.'/Fixtures/Migrate/project/migrated';

    public function testEveryProviderPatternMatchesTheFixtures(): void
    {
        $scanner = new IncumbentScanner();
        $findings = $scanner->scan(self::PROJECT);

        self::assertSame(
            ['recaptcha', 'hcaptcha', 'turnstile', 'altcha', 'friendly'],
            $scanner->providersOf($findings),
            'every incumbent provider surface is detected',
        );
        $byProvider = [];
        foreach ($findings as $finding) {
            $byProvider[$finding['provider']][$finding['kind']][] = $finding;
        }
        self::assertArrayHasKey('sitekey', $byProvider['recaptcha']);
        self::assertArrayHasKey('markup', $byProvider['recaptcha']);
        self::assertArrayHasKey('script', $byProvider['recaptcha']);
        self::assertArrayHasKey('verify', $byProvider['recaptcha']);
        self::assertArrayHasKey('sitekey', $byProvider['hcaptcha']);
        self::assertArrayHasKey('global', $byProvider['hcaptcha']);
        self::assertArrayHasKey('verify', $byProvider['hcaptcha']);
        self::assertArrayHasKey('sitekey', $byProvider['turnstile']);
        self::assertArrayHasKey('markup', $byProvider['turnstile']);
        self::assertArrayHasKey('script', $byProvider['turnstile']);
        self::assertArrayHasKey('verify', $byProvider['turnstile']);
        self::assertArrayHasKey('markup', $byProvider['altcha']);
        self::assertArrayHasKey('markup', $byProvider['friendly']);
        self::assertArrayHasKey('sitekey', $byProvider['friendly']);
    }

    public function testDetectsTheRealWorldVerifyEndpoints(): void
    {
        $scanner = new IncumbentScanner();
        $findings = $scanner->scan(self::PROJECT);
        $texts = implode("\n", array_map(static fn (array $f): string => $f['text'], $findings));

        self::assertStringContainsString('google.com/recaptcha/api/siteverify', $texts);
        self::assertStringContainsString('api.hcaptcha.com/siteverify', $texts);
        self::assertStringContainsString('challenges.cloudflare.com/turnstile/v0/siteverify', $texts);
    }

    public function testScopeSuggestionsFollowTheProtectedForm(): void
    {
        $scanner = new IncumbentScanner();
        $findings = $scanner->scan(self::PROJECT);
        $scopeByProvider = [];
        foreach ($findings as $finding) {
            $scopeByProvider[$finding['provider']] ??= $finding['scope'];
        }

        self::assertSame('login', $scopeByProvider['recaptcha']);
        self::assertSame('login', $scopeByProvider['hcaptcha'], 'the signup path raises the login scope');
        self::assertSame('checkout', $scopeByProvider['turnstile']);
        self::assertSame('comment', $scopeByProvider['friendly']);
    }

    public function testTheEmittedScopeMapCarriesTheDetectedSitekeys(): void
    {
        $emitter = new \BelConsulting\KiwiCaptchaBundle\Migration\ShimConfigEmitter('/kiwi-captcha');
        $document = $emitter->build((new IncumbentScanner())->scan(self::PROJECT), self::PROJECT);
        $maps = [];
        foreach ($document['providers'] as $provider) {
            $maps[$provider['provider']] = $provider['scope_map'];
        }

        self::assertSame(
            ['6LeIxAcTAAAAAJcZVRqyHh71UMIEGNQ_MXjiZKhI' => 'login', '6LfwKHQUAAAAAG_B4Lk8Ga8g2sS3HkdR2f7qO1Zx' => 'comment'],
            $maps['recaptcha'],
        );
        self::assertSame(['10000000-ffff-ffff-ffff-000000000001' => 'login'], $maps['hcaptcha']);
        self::assertSame(['0x4AAAAAAADnPIDROrmt1Wwj' => 'checkout'], $maps['turnstile']);
        self::assertNull($maps['altcha'], 'no sitekey literal appears on the altcha fixture lines');
        self::assertSame(['FCMGEMUD2KTDSQ5H' => 'comment'], $maps['friendly']);
    }

    public function testKiwiMarkersProduceNoFindings(): void
    {
        $scanner = new IncumbentScanner();
        self::assertSame([], $scanner->scan(self::MIGRATED), 'a migrated tree scans clean');
    }

    public function testVendorTreesStayOutOfTheReport(): void
    {
        $scanner = new IncumbentScanner();
        foreach ($scanner->scan(self::PROJECT) as $finding) {
            self::assertStringNotContainsString('vendor/', $finding['file']);
        }
    }

    public function testTextReportContainsTheShimConfig(): void
    {
        $tester = $this->commandTester();
        $tester->execute(['path' => self::PROJECT]);

        self::assertSame(Command::SUCCESS, $tester->getStatusCode());
        $display = $tester->getDisplay();
        self::assertStringContainsString('KiwiCaptcha migration report', $display);
        self::assertStringContainsString('<script src="/kiwi-captcha/api.js?compat=recaptcha"', $display);
        self::assertStringContainsString('data-kiwi-scope-map=', $display);
        self::assertStringContainsString('<script src="/kiwi-captcha/widget-shims.js"', $display, 'altcha and friendly ride the standalone shim asset');
        self::assertStringContainsString('6LeIxAcTAAAAAJcZVRqyHh71UMIEGNQ_MXjiZKhI -> login', $display);
        self::assertStringContainsString('/kiwi-captcha/siteverify', $display);
        self::assertStringContainsString('login.html', $display);
    }

    public function testJsonReportCarriesTheSameInformation(): void
    {
        $tester = $this->commandTester();
        $tester->execute(['path' => self::PROJECT, '--format' => 'json']);

        self::assertSame(Command::SUCCESS, $tester->getStatusCode());
        $document = json_decode($tester->getDisplay(), true, 512, JSON_THROW_ON_ERROR);
        self::assertSame(self::PROJECT, $document['scanned_root']);
        self::assertCount(5, $document['providers']);
        $recaptcha = null;
        foreach ($document['providers'] as $provider) {
            if ($provider['provider'] === 'recaptcha') {
                $recaptcha = $provider;
            }
        }
        self::assertNotNull($recaptcha);
        self::assertSame('recaptcha', $recaptcha['compat']);
        self::assertContains('g-recaptcha-response', [$recaptcha['response_field']]);
        self::assertSame('/kiwi-captcha/siteverify', $document['siteverify_endpoint']);
        $altcha = null;
        foreach ($document['providers'] as $provider) {
            if ($provider['provider'] === 'altcha') {
                $altcha = $provider;
            }
        }
        self::assertNull($altcha['compat'], 'altcha has no compat tier: the standalone shim asset covers it');
        self::assertSame([], $altcha['sitekeys']);
    }

    public function testOutWritesTheReportToAFile(): void
    {
        $out = sys_get_temp_dir().'/kiwi-migrate-'.bin2hex(random_bytes(4)).'.txt';
        $tester = $this->commandTester();
        $tester->execute(['path' => self::PROJECT, '--out' => $out]);

        self::assertSame(Command::SUCCESS, $tester->getStatusCode());
        self::assertFileExists($out);
        self::assertStringContainsString('KiwiCaptcha migration report', (string) file_get_contents($out));
        self::assertStringContainsString('Report written to '.$out, $tester->getDisplay());
        unlink($out);
    }

    public function testDryRunNeverTouchesTheOutPath(): void
    {
        $out = sys_get_temp_dir().'/kiwi-migrate-'.bin2hex(random_bytes(4)).'.txt';
        $tester = $this->commandTester();
        $tester->execute(['path' => self::PROJECT, '--out' => $out, '--dry-run' => true]);

        self::assertSame(Command::SUCCESS, $tester->getStatusCode());
        self::assertFileDoesNotExist($out);
        self::assertStringContainsString('(dry run: '.$out.' was not written)', $tester->getDisplay());
    }

    public function testMissingPathArgumentFails(): void
    {
        $tester = new CommandTester(new KiwiCaptchaMigrateCommand(null));
        $tester->execute([]);

        self::assertSame(Command::FAILURE, $tester->getStatusCode());
        self::assertStringContainsString('Provide the codebase directory', $tester->getDisplay());
    }

    public function testUnknownFormatFails(): void
    {
        $tester = $this->commandTester();
        $tester->execute(['path' => self::PROJECT, '--format' => 'yaml']);

        self::assertSame(Command::FAILURE, $tester->getStatusCode());
        self::assertStringContainsString('Unknown format', $tester->getDisplay());
    }

    public function testNonexistentPathFailsWithThePathInTheMessage(): void
    {
        $tester = $this->commandTester();
        $tester->execute(['path' => self::PROJECT.'/does-not-exist']);

        self::assertSame(Command::FAILURE, $tester->getStatusCode());
        self::assertStringContainsString('does-not-exist', $tester->getDisplay());
    }

    public function testFileAsScanRootFails(): void
    {
        $tester = $this->commandTester();
        $tester->execute(['path' => self::PROJECT.'/login.html']);

        self::assertSame(Command::FAILURE, $tester->getStatusCode());
    }

    public function testDirectoryAsOutTargetFails(): void
    {
        $tester = $this->commandTester();
        $tester->execute(['path' => self::PROJECT, '--out' => sys_get_temp_dir()]);

        self::assertSame(Command::FAILURE, $tester->getStatusCode());
        self::assertStringContainsString('is a directory', $tester->getDisplay());
    }

    public function testCustomPrefixShapesTheEmittedUrls(): void
    {
        $tester = new CommandTester(new KiwiCaptchaMigrateCommand(null, '/security/captcha'));
        $tester->execute(['path' => self::PROJECT, '--format' => 'json']);
        $document = json_decode($tester->getDisplay(), true, 512, JSON_THROW_ON_ERROR);

        self::assertSame('/security/captcha/siteverify', $document['siteverify_endpoint']);
    }

    public function testTheCommandIsRegisteredAsAConsoleCommand(): void
    {
        $container = new ContainerBuilder();
        $container->setParameter('kernel.environment', 'test');
        $container->setParameter('kernel.project_dir', sys_get_temp_dir());
        (new KiwiCaptchaExtension())->load([['secret_key' => str_repeat('a', 32)]], $container);

        $definition = $container->getDefinition(KiwiCaptchaMigrateCommand::class);
        self::assertTrue($definition->hasTag('console.command'), 'the migrate command must carry the console.command tag');
        self::assertTrue($definition->isPublic());
    }

    public function testSitekeyLiteralExtractionRejectsNonSitekeys(): void
    {
        $scanner = new IncumbentScanner();
        self::assertSame('6LeIxAcTAAAAAJcZVRqyHh71UMIEGNQ_MXjiZKhI', $scanner->sitekeyLiteral('<div class="g-recaptcha" data-sitekey="6LeIxAcTAAAAAJcZVRqyHh71UMIEGNQ_MXjiZKhI">'));
        self::assertNull($scanner->sitekeyLiteral('<script src="https://www.google.com/recaptcha/api.js"></script>'), 'a URL is never a sitekey');
        self::assertNull($scanner->sitekeyLiteral('<form method="post" action="/login">'), 'a path is never a sitekey');
    }

    private function commandTester(): CommandTester
    {
        return new CommandTester(new KiwiCaptchaMigrateCommand(null, '/kiwi-captcha'));
    }
}
