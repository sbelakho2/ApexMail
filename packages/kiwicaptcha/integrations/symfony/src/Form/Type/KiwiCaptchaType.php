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
 * The default 'endpoint' option is derived from the bundle's configured
 * `route_prefix` (the prefix with any trailing slash removed, plus
 * '/challenge'), so the form posts to the actual route. It mirrors the
 * standalone Twig widget, which already derives its endpoint from the
 * same prefix. 'endpoint' remains overridable per form.
 *
 * The default 'telemetry' option follows the bundle's configured telemetry
 * mode ('off' default; forced 'off' under strict privacy mode) and is
 * rendered as data-kiwi-telemetry on the widget container.
 *
 * Usage:
 *   $builder->add('captcha', KiwiCaptchaType::class, [
 *       'scope' => 'login',
 *       'nonce' => $cspNonce, // optional CSP nonce for the inline style/script tags
 *   ]);
 */
class KiwiCaptchaType extends AbstractType
{
    public function __construct(
        private readonly ?KiwiCaptchaRuntime $runtime = null,
        private readonly string $routePrefix = '/kiwi-captcha',
        private readonly string $telemetry = 'off',
        private readonly ?string $requestBinding = null,
    ) {
    }

    public function buildView(FormView $view, FormInterface $form, array $options): void
    {
        $view->vars['endpoint'] = $options['endpoint'];
        $view->vars['scope'] = $options['scope'];
        $view->vars['nonce'] = $options['nonce'];
        $view->vars['telemetry'] = $options['telemetry'];
        $view->vars['request_binding'] = $options['request_binding'];

        // The form theme inlines the shared widget assets; provide them from
        // the bundle runtime so the rendered form markup is self-contained.
        $view->vars['kiwi_css'] = $this->runtime?->css() ?? '';
        $view->vars['kiwi_wasm'] = $this->runtime?->wasm() ?? '';
        $view->vars['kiwi_driver'] = $this->runtime?->driver() ?? '';
    }

    public function configureOptions(OptionsResolver $resolver): void
    {
        $resolver->setDefaults([
            // The bundle's route prefix is injected by the extension; the
            // form endpoint follows the actual registered route.
            'endpoint' => rtrim($this->routePrefix, '/').'/challenge',
            'scope' => 'login',
            'nonce' => null,
            // Telemetry mode rendered into data-kiwi-telemetry; follows the
            // bundle config (forced 'off' under strict privacy mode).
            'telemetry' => $this->telemetry,
            // Transaction binding: rendered into
            // data-kiwi-request-binding; the widget sends it with the
            // challenge POST and carries it in the hidden
            // kiwi_request_binding form field. Defaults to the configured
            // static risk.request_binding; the application may supply a
            // dynamic per-transaction binding per form.
            'request_binding' => $this->requestBinding,
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
        $resolver->setAllowedTypes('request_binding', ['string', 'null']);
        $resolver->setAllowedValues('telemetry', ['off', 'minimal', 'full']);
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
