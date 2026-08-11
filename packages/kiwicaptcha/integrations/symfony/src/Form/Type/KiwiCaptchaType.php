<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Form\Type;

use BelConsulting\KiwiCaptchaBundle\Twig\KiwiCaptchaRuntime;
use BelConsulting\KiwiCaptchaBundle\Validator\Constraints\KiwiCaptcha;
use Symfony\Component\Form\AbstractType;
use Symfony\Component\Form\Extension\Core\Type\HiddenType;
use Symfony\Component\Form\FormInterface;
use Symfony\Component\Form\FormView;
use Symfony\Component\OptionsResolver\Options;
use Symfony\Component\OptionsResolver\OptionsResolver;

/**
 * Hidden captcha field for Symfony forms.
 *
 * The form theme (@KiwiCaptcha/form_div_layout.html.twig) renders the widget
 * (container + hidden token input + inlined CSS/WASM/driver); the
 * KiwiCaptchaValidator constraint verifies the token locally on submit.
 *
 * Usage:
 *   $builder->add('captcha', KiwiCaptchaType::class, [
 *       'scope' => 'login',
 *       'nonce' => $cspNonce, // optional CSP nonce for the inline style/script tags
 *   ]);
 */
class KiwiCaptchaType extends AbstractType
{
    public function __construct(private readonly ?KiwiCaptchaRuntime $runtime = null)
    {
    }

    public function buildView(FormView $view, FormInterface $form, array $options): void
    {
        $view->vars['endpoint'] = $options['endpoint'];
        $view->vars['scope'] = $options['scope'];
        $view->vars['nonce'] = $options['nonce'];

        // The form theme inlines the shared widget assets; provide them from
        // the bundle runtime so the rendered form markup is self-contained.
        $view->vars['kiwi_css'] = $this->runtime?->css() ?? '';
        $view->vars['kiwi_wasm'] = $this->runtime?->wasm() ?? '';
        $view->vars['kiwi_driver'] = $this->runtime?->driver() ?? '';
    }

    public function configureOptions(OptionsResolver $resolver): void
    {
        $resolver->setDefaults([
            'endpoint' => '/kiwi-captcha/challenge',
            'scope' => 'login',
            'nonce' => null,
            // The constraint's expected scope follows the form's scope option.
            'constraints' => static fn (Options $options): array => [
                new KiwiCaptcha(['scope' => $options['scope']]),
            ],
            'mapped' => false,
            'label' => false,
        ]);

        $resolver->setAllowedTypes('endpoint', 'string');
        $resolver->setAllowedTypes('scope', 'string');
        $resolver->setAllowedTypes('nonce', ['string', 'null']);
    }

    public function getParent(): string
    {
        return HiddenType::class;
    }

    public function getBlockPrefix(): string
    {
        return 'kiwi_captcha';
    }
}
