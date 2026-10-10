<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests\Kernel;

use BelConsulting\KiwiCaptchaBundle\Risk\OutcomeReporterInterface;
use BelConsulting\KiwiCaptchaBundle\Risk\PrincipalResolverInterface;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\EmailOtpStepUpHandler;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\CapturingStepUpCodeSender;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\FakePrincipalResolver;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\SpyOutcomeReporter;
use Symfony\Component\Config\Loader\LoaderInterface;
use Symfony\Component\DependencyInjection\Compiler\CompilerPassInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Definition;
use Symfony\Component\DependencyInjection\Reference;

/**
 * Kernel with the risk engine and the step-up plane armed: both
 * reference handlers enabled, the default handler email_otp, the
 * canary principal resolver, and the application-side routes of the
 * step-up endpoints. Compiler passes swap the reporter seam for the
 * spy and the code sender for the capturing sender, so the real
 * container wiring is observed end to end. The kill-switch variant
 * leaves the plane off.
 */
final class StepUpTestKernel extends TestKernel
{
    public const CANARY_PRINCIPAL = 'canary-user-42@example.com';

    public function __construct(
        string $environment,
        bool $debug,
        private readonly bool $stepUpEnabled = true,
    ) {
        parent::__construct($environment, $debug);
    }

    public function getCacheDir(): string
    {
        return parent::getCacheDir().($this->stepUpEnabled ? '-stepup-on' : '-stepup-off');
    }

    protected function build(ContainerBuilder $container): void
    {
        parent::build($container);
        $container->addCompilerPass(new class implements CompilerPassInterface {
            public function process(ContainerBuilder $container): void
            {
                if ($container->hasDefinition(OutcomeReporterInterface::class)) {
                    $container->setDefinition(OutcomeReporterInterface::class, (new Definition(SpyOutcomeReporter::class))->setPublic(true));
                }
                if ($container->hasDefinition(EmailOtpStepUpHandler::class)) {
                    // Swap the delivery seam for the capturer so the
                    // test can present the delivered code.
                    $container->setDefinition('step_up_code_capturer', (new Definition(CapturingStepUpCodeSender::class))->setPublic(true));
                    $container->getDefinition(EmailOtpStepUpHandler::class)
                        ->replaceArgument(3, new Reference('step_up_code_capturer'));
                }
            }
        });
    }

    public function registerContainerConfiguration(LoaderInterface $loader): void
    {
        $stepUpEnabled = $this->stepUpEnabled;
        $loader->load(function (ContainerBuilder $container) use ($stepUpEnabled): void {
            $container->register('fake_redis', \BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\FakePredisClient::class)
                ->setPublic(true);
            $container->register(PrincipalResolverInterface::class, FakePrincipalResolver::class)
                ->setArgument('$principal', self::CANARY_PRINCIPAL);
            $container->loadFromExtension('framework', [
                'secret' => 'test-secret',
                'test' => true,
                'router' => [
                    'resource' => __DIR__.'/Fixtures/step_up_routes.php',
                ],
            ]);
            $container->loadFromExtension('twig', [
                'form_themes' => ['@KiwiCaptcha/form_div_layout.html.twig'],
                'paths' => [
                    __DIR__.'/templates' => 'Test',
                ],
            ]);
            $container->loadFromExtension('kiwi_captcha', [
                'secret_key' => self::SECRET,
                'difficulty_bits' => 8,
                'public_base_url' => 'https://captcha.example.com',
                'risk' => [
                    'enabled' => true,
                    'redis_service' => 'fake_redis',
                    'scopes' => [
                        'login' => ['id' => 10, 'target_field' => 'username'],
                    ],
                    'step_up' => $stepUpEnabled ? [
                        'enabled' => true,
                        'scope' => 'login',
                        'default_handler' => 'email_otp',
                        'handlers' => [
                            'email_otp' => ['enabled' => true],
                            'totp' => ['enabled' => true],
                        ],
                    ] : ['enabled' => false],
                ],
            ]);
        });
    }
}
