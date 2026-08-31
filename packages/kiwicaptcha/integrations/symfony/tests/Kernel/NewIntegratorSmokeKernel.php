<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests\Kernel;

use KiwiCaptcha\Storage\ArrayStorage;
use Symfony\Component\Config\Loader\LoaderInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;

/**
 * The installation-ergonomics kernel: it wires a fresh integrator's
 * minimal configuration exactly as documented — a protection profile,
 * the signing secret, the canonical public origin and the redis_dsn —
 * and nothing else. The extension must build every Redis-backed
 * service (challenge storage, distributed rate limiter, Argon2id
 * admission and, under high_abuse, the risk state store) from the DSN
 * alone, exactly like a fresh app booting the recipe's starter config.
 *
 * The difficulty stays at the profile default (18 bits), so the smoke
 * solve is a genuine proof-of-work rather than a test shortcut.
 */
final class NewIntegratorSmokeKernel extends TestKernel
{
    public function __construct(
        string $environment,
        bool $debug,
        private readonly string $profile,
        private readonly string $redisDsn,
        private readonly ?string $storageServiceId = null,
    ) {
        parent::__construct($environment, $debug);
    }

    public function registerContainerConfiguration(LoaderInterface $loader): void
    {
        $loader->load(function (ContainerBuilder $container): void {
            $container->loadFromExtension('framework', [
                'secret' => 'test-secret',
                'test' => true,
            ]);
            $container->loadFromExtension('twig', [
                'form_themes' => ['@KiwiCaptcha/form_div_layout.html.twig'],
            ]);
            $config = [
                // The minimal-configuration contract:
                // protection_profile + secret_key + public_base_url +
                // redis_dsn. No per-knob settings at all — every
                // safety-relevant knob comes from the profile defaults.
                'protection_profile' => $this->profile,
                'secret_key' => self::SECRET,
                'public_base_url' => 'https://captcha.example.com',
                'redis_dsn' => $this->redisDsn,
            ];
            if ($this->storageServiceId !== null) {
                // The advanced escape hatch: an explicit storage service
                // id must win over the DSN-built storage for its knob.
                $config['storage'] = $this->storageServiceId;
                $container->register($this->storageServiceId, ArrayStorage::class);
            }
            $container->loadFromExtension('kiwi_captcha', $config);
        });
    }

    /**
     * One kernel class serves every smoke variant (profile, DSN,
     * storage service), so the compiled-container cache must be scoped
     * per variant. Symfony keys the container cache on the class name
     * alone, and a stale balanced container must never serve a
     * high_abuse or escape-hatch boot.
     */
    public function getCacheDir(): string
    {
        $variant = md5(sprintf(
            '%s|%s|%s',
            $this->profile,
            $this->redisDsn,
            (string) $this->storageServiceId,
        ));

        return parent::getCacheDir().'-'.$variant;
    }
}
