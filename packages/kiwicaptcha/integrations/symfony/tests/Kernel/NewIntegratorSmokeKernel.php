<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests\Kernel;

use KiwiCaptcha\Storage\ArrayStorage;
use KiwiCaptcha\Tests\Support\RswFixture;
use Symfony\Component\Config\Loader\LoaderInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;

/**
 * The installation-ergonomics kernel: it wires a fresh integrator's
 * minimal configuration exactly as documented: a protection profile,
 * the signing secret, the canonical public origin and the redis_dsn,
 * and nothing else. The extension must build every Redis-backed
 * service (challenge storage, distributed rate limiter, Argon2id
 * admission and, under high_abuse, the risk state store) from the DSN
 * alone, exactly like a fresh app booting the recipe's starter config.
 *
 * The abuse-first posture (the high_abuse spelling) promises a
 * first-class time-lock rung (change.md Part 3, 3.4.1), so the
 * high_abuse variant stages the trapdoor pair the profile demands —
 * generated once by tools/rsw-keygen, the same fixture pair every
 * rsw test embeds. Issuance keeps the profile's sha256 algorithm;
 * the staged pair is the documented pre-armed posture and clears
 * the doctor's abuse-first rsw gate.
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
            if ($this->isAbuseFirstProfile()) {
                // The abuse-first rsw gate (doctor, "RSW time-lock" row):
                // the profile promises the time-lock rung, so a correct
                // deployment configures the trapdoor pair. The smoke
                // fixture stages the shared pair and stays on the
                // profile-default algorithm.
                $config['rsw_modulus_n'] = RswFixture::MODULUS_N_B64;
                $config['rsw_lambda'] = RswFixture::LAMBDA_B64;
            }
            if ($this->storageServiceId !== null) {
                // The advanced escape hatch: an explicit storage service
                // id must win over the DSN-built storage for its knob.
                $config['storage'] = $this->storageServiceId;
                $container->register($this->storageServiceId, ArrayStorage::class);
            }
            $container->loadFromExtension('kiwi_captcha', $config);
        });
    }

    private function isAbuseFirstProfile(): bool
    {
        return $this->profile === 'high_abuse' || $this->profile === 'abuse_first';
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
