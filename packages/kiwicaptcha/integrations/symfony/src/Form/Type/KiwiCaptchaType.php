<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Form\Type;

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
 * (container + hidden token input); the KiwiCaptchaValidator constraint
 * verifies the token locally on submit.
 *
 * Usage:
 *   $builder->add('captcha', KiwiCaptchaType::class, [
 *       'scope' => 'login',
 *   ]);
 */
class KiwiCaptchaType extends AbstractType
{
    public function buildView(FormView $view, FormInterface $form, array $options): void
    {
        $view->vars['endpoint'] = $options['endpoint'];
        $view->vars['scope'] = $options['scope'];
    }

    public function configureOptions(OptionsResolver $resolver): void
    {
        $resolver->setDefaults([
            'endpoint' => '/kiwi-captcha/challenge',
            'scope' => 'login',
            // The constraint's expected scope follows the form's scope option.
            'constraints' => static fn (Options $options): array => [
                new KiwiCaptcha(['scope' => $options['scope']]),
            ],
            'mapped' => false,
            'label' => false,
        ]);

        $resolver->setAllowedTypes('endpoint', 'string');
        $resolver->setAllowedTypes('scope', 'string');
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
