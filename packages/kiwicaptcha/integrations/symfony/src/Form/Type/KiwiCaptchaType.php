<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Form\Type;

use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpDemandViewRegistry;
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
 * Step-up demand routing: when this field's validation is answered with a
 * step-up demand, the field's finishView() claims exactly its demand from
 * the request-scoped {@see StepUpDemandViewRegistry} and exposes it as the
 * `step_up_demand` view variable. The claim is keyed on this field's own
 * constraint instance, the stable server-side field-instance identity the
 * validator shares. On a page with several captcha fields, each refused
 * form surfaces its own demand id, never a sibling's; a form whose
 * validation minted none renders no demand at all.
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
        private readonly ?StepUpDemandViewRegistry $stepUpDemandViews = null,
    ) {
    }

    public function buildView(FormView $view, FormInterface $form, array $options): void
    {
        $view->vars['endpoint'] = $options['endpoint'];
        $view->vars['scope'] = $options['scope'];
        $view->vars['nonce'] = $options['nonce'];
        $view->vars['telemetry'] = $options['telemetry'];
        $view->vars['request_binding'] = $options['request_binding'];
        $view->vars['algorithm'] = $options['algorithm'];

        // The form theme inlines the shared widget assets; provide them from
        // the bundle runtime so the rendered form markup is self-contained.
        // The lazy widget modules (widget-risk.js / widget-telemetry.js)
        // follow the same delivery: content for the inline tier embeds,
        // versioned URLs + SRI digests for the files tier's container
        // attributes (see the driver-split docs).
        $view->vars['kiwi_css'] = $this->runtime?->css() ?? '';
        $view->vars['kiwi_wasm'] = $this->runtime?->wasm() ?? '';
        $view->vars['kiwi_driver'] = $this->runtime?->driver() ?? '';
        $view->vars['kiwi_risk'] = $this->runtime?->risk() ?? '';
        $view->vars['kiwi_telemetry'] = $this->runtime?->telemetry() ?? '';
        $view->vars['locales_src'] = $this->runtime?->localesSrc() ?? '';
        $view->vars['locales_integrity'] = $this->runtime?->localesIntegrity() ?? '';

        // Files-mode delivery state: the asset_mode tier, the once-per-
        // page asset tags (the request-scoped emission registry lives on
        // the runtime) and the driver's lazy runtime + worker URLs and
        // SRI digests. The 'inline' fallback when no runtime is wired
        // keeps the theme self-contained (it can emit no asset tags).
        $view->vars['asset_mode'] = $this->runtime?->assetMode() ?? 'inline';
        // Once per page: the shared inline assets are emitted by the
        // first widget only (the runtime claims them per request).
        $view->vars['emit_assets'] = $this->runtime?->claimInlineAssets() ?? true;
        $view->vars['asset_tags'] = $this->runtime?->assetTags($options['nonce']) ?? '';
        $view->vars['runtime_src'] = $this->runtime?->runtimeSrc() ?? '';
        $view->vars['runtime_integrity'] = $this->runtime?->runtimeIntegrity() ?? '';
        $view->vars['worker_src'] = $this->runtime?->workerSrc() ?? '';
        $view->vars['worker_integrity'] = $this->runtime?->workerIntegrity() ?? '';
        $view->vars['execution_src'] = $this->runtime?->executionSrc() ?? '';
        $view->vars['execution_integrity'] = $this->runtime?->executionIntegrity() ?? '';
        $view->vars['risk_src'] = $this->runtime?->riskSrc() ?? '';
        $view->vars['risk_integrity'] = $this->runtime?->riskIntegrity() ?? '';
        $view->vars['telemetry_src'] = $this->runtime?->telemetrySrc() ?? '';
        $view->vars['telemetry_integrity'] = $this->runtime?->telemetryIntegrity() ?? '';
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
            // The requested solver profile rendered into
            // data-kiwi-algorithm when set (the server response stays
            // authoritative).
            'algorithm' => null,
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
        $resolver->setAllowedTypes('algorithm', ['string', 'null']);
        $resolver->setAllowedValues('algorithm', [null, 'sha256', 'argon2id']);
        $resolver->setAllowedValues('telemetry', ['off', 'minimal', 'full']);
    }

    public function getParent(): string
    {
        return HiddenType::class;
    }

    /**
     * Claim this field's step-up demand, if its validation minted one.
     * The claim is keyed on the KiwiCaptcha constraint instance this
     * field's config carries: the same instance the validator held when
     * it minted the demand. The entry is therefore exactly this field's.
     * A second form's field (with its own constraint instance) can claim
     * nothing here, and an unclaimed field renders no demand.
     */
    public function finishView(FormView $view, FormInterface $form, array $options): void
    {
        $view->vars['step_up_demand'] = null;
        if ($this->stepUpDemandViews === null) {
            return;
        }
        $constraints = $form->getConfig()->getOption('constraints');
        if (!\is_iterable($constraints)) {
            return;
        }
        foreach ($constraints as $constraint) {
            if ($constraint instanceof KiwiCaptcha) {
                $view->vars['step_up_demand'] = $this->stepUpDemandViews->claim($constraint);

                return;
            }
        }
    }

    public function getBlockPrefix(): string
    {
        return 'kiwi_captcha';
    }
}
