<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests\Kernel;

use BelConsulting\KiwiCaptchaBundle\Security\StepUp\EmailOwnershipCodeSenderInterface;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\EmailOwnershipDeliveryMetadata;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\EmailOwnershipStepUp;
use Symfony\Component\Config\Loader\LoaderInterface;
use Symfony\Component\DependencyInjection\Compiler\CompilerPassInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Definition;
use Symfony\Component\DependencyInjection\Reference;

/**
 * The anonymous email-grant journey on a real compiled container. The
 * signup scope names the step_up_email carrier with a step_up minimum,
 * so its challenge issuance answers the typed 403 with the demand id.
 * The factor delivers against that demand, and the validator honors
 * the completed grant on the carrier scope only. The delivery seam is
 * swapped for a capturer, so the journey presents the real code.
 */
final class EmailGrantJourneyTestKernel extends TestKernel
{
    protected function build(ContainerBuilder $container): void
    {
        parent::build($container);
        $container->addCompilerPass(new class implements CompilerPassInterface {
            public function process(ContainerBuilder $container): void
            {
                foreach ([EmailOwnershipStepUp::class, \BelConsulting\KiwiCaptchaBundle\Validator\Constraints\KiwiCaptchaValidator::class] as $id) {
                    if ($container->hasDefinition($id)) {
                        $container->getDefinition($id)->setPublic(true);
                    }
                }
                if ($container->hasDefinition(EmailOwnershipStepUp::class)) {
                    $container->setDefinition('kiwi.email.code_capturer', (new Definition(EmailJourneyCapturingSender::class))->setPublic(true));
                    $container->getDefinition(EmailOwnershipStepUp::class)
                        ->replaceArgument(2, new Reference('kiwi.email.code_capturer'));
                }
            }
        });
    }

    public function registerContainerConfiguration(LoaderInterface $loader): void
    {
        $loader->load(function (ContainerBuilder $container): void {
            $container->register('fake_redis', \BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\FakePredisClient::class)
                ->setPublic(true);
            $container->loadFromExtension('framework', [
                'secret' => 'test-secret',
                'test' => true,
                'router' => [
                    'resource' => __DIR__.'/Fixtures/email_grant_routes.php',
                ],
            ]);
            $container->loadFromExtension('twig', [
                'form_themes' => ['@KiwiCaptcha/form_div_layout.html.twig'],
            ]);
            $container->loadFromExtension('kiwi_captcha', [
                'secret_key' => self::SECRET,
                'difficulty_bits' => 8,
                'public_base_url' => 'https://captcha.example.com',
                'risk' => [
                    'enabled' => true,
                    'redis_service' => 'fake_redis',
                    'scopes' => [
                        // The carrier scope with a step-up minimum: its
                        // issuance 403 is the demand source of the journey.
                        'signup' => ['id' => 31, 'minimum' => 'step_up', 'degraded' => 'allow', 'carrier' => 'step_up_email'],
                        // A plain scope without the carrier: a grant is
                        // worthless here even when it redeems elsewhere.
                        'login' => ['id' => 10, 'degraded' => 'allow'],
                    ],
                    'step_up' => [
                        'enabled' => true,
                        'handlers' => ['email_otp' => ['enabled' => true]],
                        'email_ownership' => ['enabled' => true],
                    ],
                ],
            ]);
        });
    }
}

/**
 * The capturing delivery seam of the journey: records the code the
 * factor delivered so the test can complete it without a mailer.
 */
final class EmailJourneyCapturingSender implements EmailOwnershipCodeSenderInterface
{
    /** @var list<string> */
    public array $codes = [];

    public function send(string $email, string $code, int $ttlSecs, EmailOwnershipDeliveryMetadata $delivery): void
    {
        $this->codes[] = $code;
    }

    public function lastCode(): ?string
    {
        return $this->codes === [] ? null : $this->codes[\count($this->codes) - 1];
    }
}
