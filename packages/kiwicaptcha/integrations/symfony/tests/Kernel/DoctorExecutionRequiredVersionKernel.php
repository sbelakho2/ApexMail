<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests\Kernel;

use Symfony\Component\DependencyInjection\ContainerBuilder;

/**
 * Doctor scenario: a protection profile with the execution dimension
 * fully armed on the node. The execution_key is configured and the
 * execution_version cap is raised to 2 or 3 (whatever the strongest
 * grammar under audit is). The cap can also stay at 1 for the
 * no-capability scenario. The compile-time gate refuses an
 * execution_required_version below the cap under high_abuse unless the
 * deployment accepts the downgrade window, so the mismatch variants
 * (required below the cap) boot with execution_allow_downgrade: true.
 * The doctor's protocol-v3 writer check passes once the test seeds the
 * central policy floors (protocol 4 + execution 2 or 3). The variants
 * differ in the node cap, the execution_required_version knob, the
 * downgrade flag, the protection profile and the protocol_rollout
 * mode, so each variant boots its own cached container.
 */
final class DoctorExecutionRequiredVersionKernel extends DoctorV3WriterTestKernel
{
    public function __construct(
        string $environment,
        bool $debug,
        private readonly int $executionVersion = 1,
        private readonly int $requiredVersion = 1,
        private readonly bool $allowDowngrade = false,
        private readonly string $profile = 'high_abuse',
        private readonly string $rolloutMode = 'normal',
    ) {
        parent::__construct($environment, $debug);
    }

    protected function loadKiwiCaptcha(ContainerBuilder $container): void
    {
        $config = [
            'secret_key' => self::SECRET,
            'difficulty_bits' => 8,
            'public_base_url' => 'https://captcha.example.com',
            'protection_profile' => $this->profile,
            'redis_service' => self::FAKE_REDIS_ID,
            'execution_key' => '0123456789abcdef0123456789abcdef',
            'execution_version' => $this->executionVersion,
            'execution_required_version' => $this->requiredVersion,
            'execution_allow_downgrade' => $this->allowDowngrade,
            'protocol_rollout' => ['mode' => $this->rolloutMode],
            'risk' => [
                'namespace' => 'doctor-v3',
                'redis_service' => self::FAKE_REDIS_ID,
            ],
        ];
        if ($this->profile !== 'high_abuse') {
            // The high_abuse profile arms the execution gate by
            // default; every other profile needs the explicit override.
            $config['risk']['execution_challenge'] = 'on';
        }
        $container->loadFromExtension('kiwi_captcha', $config);
    }

    public function getCacheDir(): string
    {
        // The kernel cache is keyed on the class + environment, so each
        // knob variant must carve its own cache directory or a later
        // variant would reuse the first variant's compiled container.
        return parent::getCacheDir()
            .'-exec-req-'.$this->executionVersion.'-'.$this->requiredVersion
            .'-allow-'.($this->allowDowngrade ? '1' : '0')
            .'-'.$this->profile.'-'.$this->rolloutMode;
    }
}
