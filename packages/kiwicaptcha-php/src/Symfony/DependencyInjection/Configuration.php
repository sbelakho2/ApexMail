<?php

declare(strict_types=1);

namespace KiwiCaptcha\Symfony\DependencyInjection;

use Symfony\Component\Config\Definition\Builder\TreeBuilder;
use Symfony\Component\Config\Definition\ConfigurationInterface;

final class Configuration implements ConfigurationInterface
{
    public function getConfigTreeBuilder(): TreeBuilder
    {
        $treeBuilder = new TreeBuilder('kiwicaptcha');
        $root = $treeBuilder->getRootNode();

        $root
            ->children()
                ->scalarNode('secret')
                    ->info('HMAC secret key for signing/verifying challenges (min 16 bytes).')
                    ->isRequired()
                    ->cannotBeEmpty()
                ->end()
                ->enumNode('algorithm')
                    ->values(['sha256', 'argon2id'])
                    ->defaultValue('sha256')
                ->end()
                ->integerNode('argon_m_kib')
                    ->info('Argon2id memory cost in KiB (only for argon2id; must be >= 8 * argon_p).')
                    ->defaultValue(0)
                    ->min(0)
                    ->max(65536)
                ->end()
                ->integerNode('argon_t')
                    ->defaultValue(3)
                    ->min(1)
                ->end()
                ->integerNode('argon_p')
                    ->defaultValue(1)
                    ->min(1)
                ->end()
                ->integerNode('difficulty_bits')
                    ->info('Leading zero bits for SHA-256 challenges (default 20).')
                    ->defaultValue(20)
                    ->min(1)
                    ->max(24)
                ->end()
                ->integerNode('argon2_difficulty_bits')
                    ->info('Leading zero bits for Argon2id challenges (default 8, max 10).')
                    ->defaultValue(8)
                    ->min(1)
                    ->max(10)
                ->end()
                ->integerNode('challenge_ttl_secs')
                    ->defaultValue(120)
                    ->min(10)
                ->end()
                ->integerNode('min_duration_ms')
                    ->info('Override the per-challenge minimum solve duration in ms (default: derived from difficulty).')
                    ->defaultNull()
                    ->min(0)
                ->end()
                ->scalarNode('storage')
                    ->info('Service id implementing KiwiCaptcha\StorageInterface. Defaults to the in-memory ArrayStorage, which is only allowed in test/dev environments — in prod a shared storage (e.g. KiwiCaptcha\Storage\RedisStorage or Psr6Storage backed by a Redis PSR-6 pool) is required or the container fails to compile.')
                    ->defaultValue('kiwicaptcha.storage.array')
                ->end()
                ->scalarNode('route_prefix')
                    ->info('Prefix for the challenge endpoint route.')
                    ->defaultValue('/kiwi-captcha')
                ->end()
                ->arrayNode('twig')
                    ->info('Twig widget rendering settings.')
                    ->addDefaultsIfNotSet()
                    ->children()
                        ->booleanNode('enabled')
                            ->defaultValue(true)
                        ->end()
                        ->scalarNode('template')
                            ->defaultValue('@KiwiCaptcha/widget.html.twig')
                        ->end()
                    ->end()
                ->end()
                ->arrayNode('form')
                    ->info('Symfony Form integration settings.')
                    ->addDefaultsIfNotSet()
                    ->children()
                        ->booleanNode('enabled')
                            ->defaultValue(true)
                        ->end()
                        ->scalarNode('token_field')
                            ->info('Form field name that carries the kiwi__token value.')
                            ->defaultValue('kiwi__token')
                        ->end()
                    ->end()
                ->end()
            ->end();

        return $treeBuilder;
    }
}
