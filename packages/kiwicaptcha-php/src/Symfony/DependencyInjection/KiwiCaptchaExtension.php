<?php

declare(strict_types=1);

namespace KiwiCaptcha\Symfony\DependencyInjection;

use KiwiCaptcha\Config;
use KiwiCaptcha\Issuer;
use KiwiCaptcha\PoWAlgorithm;
use KiwiCaptcha\Storage\ArrayStorage;
use KiwiCaptcha\Storage\Psr6Storage;
use KiwiCaptcha\StorageInterface;
use KiwiCaptcha\Verifier;
use Symfony\Component\Config\FileLocator;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Definition;
use Symfony\Component\DependencyInjection\Extension\Extension;
use Symfony\Component\DependencyInjection\Loader\YamlFileLoader;
use Symfony\Component\DependencyInjection\Reference;

final class KiwiCaptchaExtension extends Extension
{
    public function load(array $configs, ContainerBuilder $container): void
    {
        $configuration = new Configuration();
        $config = $this->processConfiguration($configuration, $configs);

        $loader = new YamlFileLoader($container, new FileLocator(__DIR__.'/../../Resources/config'));
        $loader->load('services.yaml');

        // Default in-memory storage unless the app supplies its own.
        $storageId = $config['storage'];
        if ($storageId === 'kiwicaptcha.storage.array') {
            $container->setDefinition('kiwicaptcha.storage.array', new Definition(ArrayStorage::class));
            $storageRef = new Reference('kiwicaptcha.storage.array');
        } else {
            $storageRef = new Reference($storageId);
        }

        $configDef = (new Definition(Config::class, [
            $config['secret'],
            PoWAlgorithm::from($config['algorithm']),
            $config['argon_m_kib'],
            $config['argon_t'],
            $config['argon_p'],
            $config['difficulty_bits'],
            $config['argon2_difficulty_bits'],
            $config['challenge_ttl_secs'],
            $config['min_duration_ms'],
        ]))->setPublic(true);
        $container->setDefinition('kiwicaptcha.config', $configDef);

        $container->setDefinition('kiwicaptcha.issuer', (new Definition(Issuer::class, [
            new Reference('kiwicaptcha.config'),
            $storageRef,
        ]))->setPublic(true));

        $container->setDefinition('kiwicaptcha.verifier', (new Definition(Verifier::class, [
            $storageRef,
        ]))->setPublic(true));

        // Expose aliases for convenient injection.
        $container->setAlias(StorageInterface::class, (string) $storageRef);
        $container->setAlias(Issuer::class, 'kiwicaptcha.issuer');
        $container->setAlias(Verifier::class, 'kiwicaptcha.verifier');

        if ($config['twig']['enabled']) {
            $container->getDefinition('kiwicaptcha.twig_runtime')
                ->setArgument(0, new Reference('kiwicaptcha.issuer'))
                ->setArgument(1, $config['route_prefix']);
        }
        if ($config['form']['enabled']) {
            $container->getDefinition('kiwicaptcha.form_type')
                ->setArgument(0, new Reference('kiwicaptcha.verifier'))
                ->setArgument(1, $config['form']['token_field']);
        }
    }
}
