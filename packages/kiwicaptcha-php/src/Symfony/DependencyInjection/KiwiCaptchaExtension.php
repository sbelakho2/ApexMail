<?php

declare(strict_types=1);

namespace KiwiCaptcha\Symfony\DependencyInjection;

use KiwiCaptcha\Config;
use KiwiCaptcha\Issuer;
use KiwiCaptcha\PoWAlgorithm;
use KiwiCaptcha\Storage\ArrayStorage;
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
    private const ARRAY_STORAGE_ID = 'kiwicaptcha.storage.array';

    /**
     * The class-name-derived alias would be "kiwi_captcha"; the documented
     * config root (and Configuration tree root) is "kiwicaptcha".
     */
    public function getAlias(): string
    {
        return 'kiwicaptcha';
    }

    public function load(array $configs, ContainerBuilder $container): void
    {
        $configuration = new Configuration();
        $config = $this->processConfiguration($configuration, $configs);

        $loader = new YamlFileLoader($container, new FileLocator(__DIR__.'/../Resources/config'));
        $loader->load('services.yaml');

        $storageRef = $this->resolveStorage($config['storage'], $this->environment($container), $container);

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
            $container->getDefinition(\KiwiCaptcha\Symfony\Twig\KiwiCaptchaRuntime::class)
                ->setArgument('$routePrefix', $config['route_prefix']);
        }
        if ($config['form']['enabled']) {
            $container->getDefinition(\KiwiCaptcha\Symfony\Form\KiwiCaptchaType::class)
                ->setArgument('$verifier', new Reference('kiwicaptcha.verifier'))
                ->setArgument('$tokenField', $config['form']['token_field'])
                ->setArgument('$configuredSecretKey', $config['secret']);
        }

        // The validator must always receive the configured secret key: a null
        // default would fail Verifier::verify() at runtime with a TypeError.
        $container->getDefinition(\KiwiCaptcha\Symfony\Validator\KiwiCaptchaValidator::class)
            ->setArgument('$configuredSecretKey', $config['secret']);
    }

    /**
     * ArrayStorage is an in-memory, single-process store. A challenge issued
     * in request A is verified in request B, which runs in a different PHP
     * process under PHP-FPM — the record would be lost. Fail hard outside
     * test/dev environments instead of silently breaking every visitor.
     *
     * @throws \LogicException when the in-memory storage is selected for a
     *                         non-test, non-dev environment
     */
    private function resolveStorage(string $storageId, string $environment, ContainerBuilder $container): Reference
    {
        if ($storageId === self::ARRAY_STORAGE_ID) {
            if (!\in_array($environment, ['test', 'dev'], true)) {
                throw new \LogicException(sprintf(
                    'KiwiCaptcha is configured with the in-memory ArrayStorage ("%s"), which cannot persist challenges between requests (challenges are issued in one request and verified in the next; PHP-FPM processes share no memory). This is only allowed in test/dev environments. Configure a shared storage for the "%s" environment, e.g. "storage: kiwicaptcha.storage.redis" using KiwiCaptcha\Storage\RedisStorage (Redis 6.2+, predis or phpredis) or "storage: kiwicaptcha.storage.psr6" backed by a Redis PSR-6 pool (KiwiCaptcha\Storage\Psr6Storage) — or any service implementing KiwiCaptcha\StorageInterface.',
                    self::ARRAY_STORAGE_ID,
                    $environment,
                ));
            }
            $container->setDefinition(self::ARRAY_STORAGE_ID, new Definition(ArrayStorage::class));

            return new Reference(self::ARRAY_STORAGE_ID);
        }

        return new Reference($storageId);
    }

    private function environment(ContainerBuilder $container): string
    {
        if ($container->hasParameter('kernel.environment')) {
            return (string) $container->getParameter('kernel.environment');
        }
        if (isset($_SERVER['APP_ENV'])) {
            return (string) $_SERVER['APP_ENV'];
        }

        return 'dev';
    }
}
