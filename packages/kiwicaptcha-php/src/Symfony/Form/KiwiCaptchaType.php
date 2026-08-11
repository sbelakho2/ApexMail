<?php

declare(strict_types=1);

namespace KiwiCaptcha\Symfony\Form;

use KiwiCaptcha\Verifier;
use Symfony\Component\Form\AbstractType;
use Symfony\Component\Form\Extension\Core\Type\HiddenType;
use Symfony\Component\Form\FormBuilderInterface;
use Symfony\Component\Form\FormError;
use Symfony\Component\Form\FormEvent;
use Symfony\Component\Form\FormEvents;
use Symfony\Component\OptionsResolver\Options;
use Symfony\Component\OptionsResolver\OptionsResolver;
use Symfony\Component\HttpFoundation\RequestStack;

/**
 * Hidden captcha field that validates the proof-of-work token on submit.
 *
 * Usage in a form type:
 *   $builder->add('captcha', KiwiCaptchaType::class, [
 *       'scope' => 'login',
 *       'expected_scope' => 'login',   // validates the challenge scope
 *   ]);
 *
 * The token is verified against the challenge scope and (optionally) the
 * client IP, mirroring the api-server flow.
 */
final class KiwiCaptchaType extends AbstractType
{
    public function __construct(
        private readonly Verifier $verifier,
        private readonly RequestStack $requestStack,
        private readonly string $tokenField = 'kiwi__token',
        private readonly ?string $configuredSecretKey = null,
    ) {
    }

    public function buildForm(FormBuilderInterface $builder, array $options): void
    {
        $builder->add($this->tokenField, HiddenType::class);

        // Validate on PRE_SUBMIT so the form can show a field error.
        $builder->addEventListener(FormEvents::PRE_SUBMIT, function (FormEvent $event) use ($options): void {
            $data = $event->getData();
            $token = \is_array($data) ? ($data[$this->tokenField] ?? null) : null;
            if (!\is_string($token) || $token === '') {
                $event->getForm()->addError(new FormError('The security check is missing. Please retry.'));

                return;
            }

            if (!\is_string($options['secret_key'])) {
                throw new \LogicException('KiwiCaptcha secret key is not configured (set kiwicaptcha.secret or pass secret_key to the form type)');
            }

            // Same IP source as the challenge endpoint: Request::getClientIp().
            $request = $this->requestStack->getMainRequest();
            $clientIp = $request?->getClientIp();

            $outcome = $this->verifier->verify(
                $token,
                $options['secret_key'],
                $options['expected_scope'],
                $options['bind_ip'] ? $clientIp : null,
            );

            if (!$outcome->isOk()) {
                $event->getForm()->addError(new FormError(
                    'The security check failed. Please retry.',
                    null,
                    [],
                    null,
                    $outcome->code(),
                ));
            }
        });
    }

    public function configureOptions(OptionsResolver $resolver): void
    {
        $resolver->setDefaults([
            'scope' => 'default',
            'expected_scope' => null,
            'secret_key' => $this->configuredSecretKey,
            'bind_ip' => true,
            'mapped' => false,
            'compound' => true,
        ]);
        // An explicit null falls back to the secret configured in the bundle.
        $resolver->setNormalizer('secret_key', static fn (Options $options, ?string $value): ?string => $value ?? $options['secret_key']);
        $resolver->setAllowedTypes('scope', 'string');
        $resolver->setAllowedTypes('expected_scope', ['string', 'null']);
        $resolver->setAllowedTypes('secret_key', ['string', 'null']);
        $resolver->setAllowedTypes('bind_ip', 'bool');
    }

    public function getBlockPrefix(): string
    {
        return 'kiwi_captcha';
    }
}
