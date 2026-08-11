<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\DependencyInjection;

use BelConsulting\KiwiCaptchaBundle\Controller\ChallengeController;
use BelConsulting\KiwiCaptchaBundle\Form\Type\KiwiCaptchaType;
use BelConsulting\KiwiCaptchaBundle\Twig\KiwiCaptchaRuntime;
use BelConsulting\KiwiCaptchaBundle\Validator\Constraints\KiwiCaptchaValidator;
use KiwiCaptcha\Config;
use KiwiCaptcha\Issuer;
use KiwiCaptcha\PoWAlgorithm;
use KiwiCaptcha\Storage\ArrayStorage;
use KiwiCaptcha\Storage\Psr6Storage;
use KiwiCaptcha\StorageInterface;
use KiwiCaptcha\Verifier;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Definition;
use Symfony\Component\DependencyInjection\Extension\Extension;
use Symfony\Component\DependencyInjection\Reference;

final class KiwiCaptchaExtension extends Extension
{
    public function load(array $configs, ContainerBuilder $container): void
    {
        $configuration = new Configuration();
        $config = $this->processConfiguration($configuration, $configs);

        $container->setParameter('kiwi_captcha.secret_key', $config['secret_key']);
        $container->setParameter('kiwi_captcha.route_prefix', $config['route_prefix']);

        // ── Verified core (kiwicaptcha/kiwicaptcha-php): Config, Issuer, Verifier ──
        $configDef = (new Definition(Config::class, [
            $config['secret_key'],
            PoWAlgorithm::from($config['algorithm']),
            $config['argon_m_kib'],
            $config['argon_t'],
            $config['argon_p'],
            $config['difficulty_bits'],
            $config['argon2_difficulty_bits'],
            $config['challenge_ttl_secs'],
        ]))->setPublic(true);
        $container->setDefinition('kiwi_captcha.config', $configDef);

        // Storage: default in-memory (single-process); override with any
        // KiwiCaptcha\StorageInterface service for production (e.g. PSR-6).
        if ($config['storage'] === 'kiwi_captcha.storage.array') {
            $container->setDefinition('kiwi_captcha.storage.array', new Definition(ArrayStorage::class));
            $storageRef = new Reference('kiwi_captcha.storage.array');
        } else {
            $storageRef = new Reference($config['storage']);
        }
        $container->setAlias(StorageInterface::class, (string) $storageRef);

        $container->setDefinition('kiwi_captcha.issuer', (new Definition(Issuer::class, [
            new Reference('kiwi_captcha.config'),
            $storageRef,
        ]))->setPublic(true));

        $container->setDefinition('kiwi_captcha.verifier', (new Definition(Verifier::class, [
            $storageRef,
        ]))->setPublic(true));

        // ── Challenge endpoint controller ──
        $container->setDefinition(ChallengeController::class, (new Definition(ChallengeController::class, [
            new Reference('kiwi_captcha.issuer'),
        ]))->addTag('controller.service_arguments')->setPublic(true));

        // ── Form type ──
        $container->setDefinition(KiwiCaptchaType::class, (new Definition(KiwiCaptchaType::class))
            ->addTag('form.type'));

        // ── Validator (local verification, no external calls) ──
        $container->setDefinition(KiwiCaptchaValidator::class, (new Definition(KiwiCaptchaValidator::class, [
            new Reference('kiwi_captcha.verifier'),
            new Reference('request_stack'),
            $config['secret_key'],
        ]))->addTag('validator.constraint_validator'));

        // ── Twig widget runtime (embeds the shared widget assets) ──
        $container->setDefinition(KiwiCaptchaRuntime::class, (new Definition(KiwiCaptchaRuntime::class, [
            $config['route_prefix'],
        ]))->addTag('twig.runtime'));
    }
}
