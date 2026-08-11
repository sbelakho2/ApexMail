<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests\Kernel;

use BelConsulting\KiwiCaptchaBundle\Form\Type\KiwiCaptchaType;
use PHPUnit\Framework\TestCase;
use Symfony\Component\DependencyInjection\ContainerInterface;

/**
 * The form widget must follow the configured route_prefix: the default
 * 'endpoint' option of KiwiCaptchaType is derived from the prefix, so the
 * rendered data-kiwi-endpoint points at the ACTUAL registered route (same as
 * the standalone Twig widget). The option stays overridable per form.
 */
final class PrefixFormIntegrationTest extends TestCase
{
    private static ?PrefixedTestKernel $kernel = null;

    protected function setUp(): void
    {
        self::$kernel ??= new PrefixedTestKernel('test', true);
        self::$kernel->boot();
    }

    private function container(): ContainerInterface
    {
        return self::$kernel->getContainer()->get('test.service_container');
    }

    private function render(array $options = []): string
    {
        $factory = $this->container()->get('form.factory');
        $form = $factory->createNamed('captcha', KiwiCaptchaType::class, null, $options);

        return $this->container()->get('twig')->render('@Test/form.html.twig', ['form' => $form->createView()]);
    }

    public function testFormEndpointDerivesFromRoutePrefix(): void
    {
        $html = $this->render(['scope' => 'login']);

        self::assertStringContainsString('data-kiwi-endpoint="/security/captcha/challenge"', $html);
    }

    public function testFormEndpointRemainsOverridable(): void
    {
        $html = $this->render([
            'scope' => 'login',
            'endpoint' => '/custom/challenge',
        ]);

        self::assertStringContainsString('data-kiwi-endpoint="/custom/challenge"', $html);
    }
}
