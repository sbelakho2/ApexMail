<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\DependencyInjection;

use BelConsulting\KiwiCaptchaBundle\Controller\ChallengeController;
use BelConsulting\KiwiCaptchaBundle\Form\Type\KiwiCaptchaType;
use BelConsulting\KiwiCaptchaBundle\Risk\ContinuityCookie;
use BelConsulting\KiwiCaptchaBundle\Risk\PrincipalResolverInterface;
use BelConsulting\KiwiCaptchaBundle\Risk\RedisRiskHealthProvider;
use BelConsulting\KiwiCaptchaBundle\Risk\RiskGateway;
use BelConsulting\KiwiCaptchaBundle\Risk\RiskProfileResolver;
use BelConsulting\KiwiCaptchaBundle\Routing\KiwiCaptchaRouteLoader;
use BelConsulting\KiwiCaptchaBundle\Security\InProcessArgonGate;
use BelConsulting\KiwiCaptchaBundle\Security\IssuanceCounter;
use BelConsulting\KiwiCaptchaBundle\Security\IssuanceRateLimiter;
use BelConsulting\KiwiCaptchaBundle\Security\RedisAdmissionSemaphore;
use BelConsulting\KiwiCaptchaBundle\Twig\KiwiCaptchaExtension as TwigExtension;
use BelConsulting\KiwiCaptchaBundle\Twig\KiwiCaptchaRuntime;
use BelConsulting\KiwiCaptchaBundle\Validator\Constraints\KiwiCaptchaValidator;
use KiwiCaptcha\BindingMode;
use KiwiCaptcha\Config;
use KiwiCaptcha\Issuer;
use KiwiCaptcha\PoWAlgorithm;
use KiwiCaptcha\Risk\AdaptiveRiskEngine;
use KiwiCaptcha\Risk\Network\CidrNetworkClassifier;
use KiwiCaptcha\Risk\RiskAction;
use KiwiCaptcha\Risk\RiskIdentityFactory;
use KiwiCaptcha\Risk\RiskKeys;
use KiwiCaptcha\Risk\RiskPolicy;
use KiwiCaptcha\Risk\Breaker\CircuitBreaker;
use KiwiCaptcha\Risk\Calibration\AggregateCalibrator;
use KiwiCaptcha\Risk\Metrics\RiskMetrics;
use KiwiCaptcha\Risk\RiskScorer;
use KiwiCaptcha\Risk\Storage\ProcessEmergencyCap;
use KiwiCaptcha\Risk\Storage\RedisRiskStateStore;
use KiwiCaptcha\Storage\ArrayStorage;
use KiwiCaptcha\Storage\RedisStorage;
use KiwiCaptcha\StorageInterface;
use KiwiCaptcha\Verifier;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Definition;
use Symfony\Component\DependencyInjection\Extension\Extension;
use Symfony\Component\DependencyInjection\Extension\PrependExtensionInterface;
use Symfony\Component\DependencyInjection\Reference;

final class KiwiCaptchaExtension extends Extension implements PrependExtensionInterface
{
    private const ARRAY_STORAGE_ID = 'kiwi_captcha.storage.array';

    public function getAlias(): string
    {
        return 'kiwi_captcha';
    }

    /**
     * Auto-register the bundle's challenge route so POST /kiwi-captcha/challenge
     * works out of the box.
     *
     * Bundle controllers are never scanned for #[Route] attributes (the
     * framework only scans the application's src/Controller), so the bundle
     * must contribute its own routing resource. The framework.router.resource
     * option is a single value owned by the application: this prepend only
     * sets it when the application has NOT configured the router at all (a
     * fresh app). Applications that configure framework.router themselves must
     * import the bundle's routes file manually:
     *
     *     # config/routes.yaml
     *     kiwi_captcha:
     *         resource: '@KiwiCaptchaBundle/Resources/config/routes.php'
     */
    public function prepend(ContainerBuilder $container): void
    {
        if (!$container->hasExtension('framework')) {
            return;
        }
        foreach ($container->getExtensionConfig('framework') as $config) {
            if (isset($config['router'])) {
                // The app configures the router itself (own resource or
                // explicitly disabled) — never touch it.
                return;
            }
        }

        $container->prependExtensionConfig('framework', [
            'router' => ['resource' => __DIR__.'/../Resources/config/routes.php'],
        ]);
    }

    public function load(array $configs, ContainerBuilder $container): void
    {
        $configuration = new Configuration();
        $config = $this->processConfiguration($configuration, $configs);

        // ── Privacy posture enforcement ──────────────────────────────────
        // 'strict' (default) forces the privacy-sensitive options OFF/true:
        //   - telemetry: 'off'      (no client signal fields at all)
        //   - enforce_telemetry: false (an off widget sends EMPTY telemetry;
        //                            enforcing it would reject every user)
        //   - same_origin_only: true (cross-origin POSTs rejected)
        //   - min_duration_ms: 0    (the server-side solve-timing floor is a
        //                            timing heuristic and is disabled)
        // binding_mode is NOT forced: IP binding is a relay mitigation and
        // the stored tag is nonce-bound (never a stable IP identifier), so an
        // operator may still disable it under strict. rate_limit /
        // rate_limit_global already default to nonzero.
        if ($config['privacy_mode'] === 'strict') {
            $config['telemetry'] = 'off';
            $config['enforce_telemetry'] = false;
            $config['same_origin_only'] = true;
            $config['min_duration_ms'] = 0;
        } elseif ($config['enforce_telemetry'] && $config['telemetry'] === 'off') {
            // Impossible combination outside strict mode: enforcement rejects
            // clients whose telemetry is EMPTY (which is exactly what an off
            // widget sends), so every legitimate solve would fail. Refuse the
            // configuration instead of accepting a production trap.
            throw new \InvalidArgumentException(
                'kiwi_captcha.enforce_telemetry cannot be true while telemetry is "off": '.
                'an off widget sends empty telemetry and enforcement rejects it. '.
                'Set telemetry to "minimal"/"full", or disable enforcement.'
            );
        }

        // Cross-option invariants (validated here, after the config tree):
        // - a rotation shorter than the sliding window would drop live hits
        //   from epochs older than (current - 1) from the two-epoch
        //   accounting (the limiter constructor enforces the same rule)
        // - a min_duration_ms at or above the TTL leaves no acceptable
        //   submission time (TooFast before expiry, Expired after) — the
        //   core Config validates the same relation.
        if ($config['rate_limit_rotation_secs'] > 0 && $config['rate_limit_rotation_secs'] < $config['rate_limit_window_secs']) {
            throw new \InvalidArgumentException(
                'kiwi_captcha.rate_limit_rotation_secs must be 0 or >= rate_limit_window_secs — '.
                'a rotation shorter than the window would drop live hits from older epochs'
            );
        }
        if ($config['min_duration_ms'] !== null && $config['min_duration_ms'] >= $config['challenge_ttl_secs'] * 1000) {
            throw new \InvalidArgumentException(
                'kiwi_captcha.min_duration_ms must be < challenge_ttl_secs * 1000 — '.
                'a floor at or above the TTL leaves no acceptable submission time'
            );
        }

        $container->setParameter('kiwi_captcha.secret_key', $config['secret_key']);
        $container->setParameter('kiwi_captcha.route_prefix', $config['route_prefix']);
        $container->setParameter('kiwi_captcha.privacy_mode', $config['privacy_mode']);
        $container->setParameter('kiwi_captcha.telemetry', $config['telemetry']);
        $container->setParameter('kiwi_captcha.binding_mode', $config['binding_mode']);
        $container->setParameter('kiwi_captcha.same_origin_only', $config['same_origin_only']);
        $container->setParameter('kiwi_captcha.rate_limit', $config['rate_limit']);
        $container->setParameter('kiwi_captcha.rate_limit_global', $config['rate_limit_global']);
        $container->setParameter('kiwi_captcha.rate_limit_window_secs', $config['rate_limit_window_secs']);
        $container->setParameter('kiwi_captcha.argon2_semaphore_namespace', $config['argon2_semaphore_namespace']);
        $container->setParameter('kiwi_captcha.enforce_telemetry', $config['enforce_telemetry']);
        $container->setParameter('kiwi_captcha.min_duration_ms', $config['min_duration_ms']);

        $storageRef = $this->resolveStorage($config['storage'], $this->environment($container), $container);
        $redisRef = $this->resolveRedisClient((string) $storageRef, $config['redis_service'], $container);

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
            // null = derive the floor from difficulty (standard mode);
            // 0 = timing heuristic off (strict mode / explicit operator choice).
            $config['min_duration_ms'],
            // 10th arg: solver cap (informational, matches the widget).
            5_000_000,
        ]))
            ->setArgument('$bindingMode', $config['binding_mode'] === 'none'
                ? BindingMode::None
                : BindingMode::Bound)
            ->setPublic(true);
        $container->setDefinition('kiwi_captcha.config', $configDef);

        $container->setDefinition('kiwi_captcha.issuer', (new Definition(Issuer::class, [
            new Reference('kiwi_captcha.config'),
            $storageRef,
        ]))->setPublic(true));

        // Verifier: the core now takes the Argon2id admission gate natively
        // (VerificationAdmissionGate — consulted only when the STORED record
        // is Argon2id, only after the cheap checks). Admission is enforced
        // against Redis (across all PHP-FPM workers, tokenized leases) when a
        // Redis client is available — either from the 'redis_service' config
        // option or from the RedisStorage storage definition — and falls back
        // to the in-process token-set gate (per-process only).
        // The gate is created whenever the concurrency cap is > 0 —
        // REGARDLESS of the locally configured issuance algorithm. The core
        // verifier consults the gate based on the STORED record's algorithm,
        // and the project supports Rust/PHP interoperable records in shared
        // storage: a Symfony service issuing SHA challenges may still receive
        // a solution for an Argon record written by a Rust service. There is
        // no cost for SHA verifications — the gate is never consulted unless
        // the record actually says Argon2id.
        $gateRef = null;
        if ($config['argon2_max_concurrent_verifications'] > 0) {
            if ($redisRef !== null) {
                $container->setDefinition(
                    'kiwi_captcha.argon2_redis_semaphore',
                    (new Definition(RedisAdmissionSemaphore::class, [
                        $redisRef,
                        $config['argon2_max_concurrent_verifications'],
                        $config['argon2_semaphore_namespace'],
                        $config['argon2_lease_ms'],
                    ]))->setPublic(true),
                );
                $gateRef = new Reference('kiwi_captcha.argon2_redis_semaphore');
            } else {
                $container->setDefinition('kiwi_captcha.argon2_inprocess_gate', (new Definition(InProcessArgonGate::class, [
                    $config['argon2_max_concurrent_verifications'],
                ]))->setPublic(true));
                $gateRef = new Reference('kiwi_captcha.argon2_inprocess_gate');
            }
        }
        $container->setDefinition('kiwi_captcha.verifier', (new Definition(Verifier::class, [
            $storageRef,
            $gateRef,
        ]))->setPublic(true));
        $container->setAlias(StorageInterface::class, (string) $storageRef);

        // ── Challenge endpoint controller (+ issuance rate limiter) ──
        // The limiter is wired whenever either limit is nonzero (defaults are
        // 10 per-client / 500 global). With a Redis client the ATOMIC
        // sliding-window backend enforces both caps across all workers;
        // without one it falls back to the shared PSR-6 pool (rate_limit_cache)
        // or the in-memory window (best-effort, single worker).
        $rateLimiterRef = null;
        if ($config['rate_limit'] > 0 || $config['rate_limit_global'] > 0) {
            $poolRef = $config['rate_limit_cache'] !== null ? new Reference($config['rate_limit_cache']) : null;
            $container->setDefinition('kiwi_captcha.rate_limiter', (new Definition(IssuanceRateLimiter::class, [
                $config['rate_limit'],
                $config['rate_limit_window_secs'],
                $poolRef,
                null,
                // Pepper for the per-IP rate-limit HMAC keys: raw IPs are
                // never stored (defaults to the bundle secret).
                $config['rate_limit_pepper'] ?? $config['secret_key'],
                $redisRef,
                $config['rate_limit_global'],
                $config['argon2_semaphore_namespace'],
                $config['rate_limit_rotation_secs'],
            ]))->setPublic(true));
            $rateLimiterRef = new Reference('kiwi_captcha.rate_limiter');
        }

        // ── Adaptive risk engine (kiwicaptcha/kiwicaptcha-risk-php) ────────
        // Off by default. When enabled, a Predis\Client is REQUIRED for the
        // canonical risk-v1 state script (risk.redis_service, or the bundle's
        // own Redis client when it is a Predis client) — fail fast at compile
        // time otherwise. The engine runs PRE-ISSUE (decide difficulty or
        // deny), records issuances, and receives POST-SOLVE outcome feedback
        // from the validator.
        $riskConfig = $config['risk'];
        $riskGatewayRef = null;
        $riskCookieRef = null;
        $issuanceCounterRef = null;
        if ($riskConfig['enabled']) {
            [$policyConfig, $scopeIds, $postSolveScopes, $unknownScopeId] = $this->buildRiskPolicy($riskConfig);
            $riskRedis = $this->resolveRiskRedisClient($riskConfig, $redisRef, $container);
            $namespace = preg_replace('/[^A-Za-z0-9_.-]/', '_', (string) $riskConfig['namespace']) ?: 'kiwi';

            $riskMaster = $riskConfig['master_secret'] ?? $config['secret_key'];
            $container->setDefinition('kiwi_captcha.risk.keys', (new Definition(RiskKeys::class))
                ->setFactory([RiskKeys::class, 'fromMaster'])
                ->setArguments([$riskMaster])
                ->setPublic(true));
            $container->setDefinition('kiwi_captcha.risk.identity_factory', new Definition(RiskIdentityFactory::class, [
                new Reference('kiwi_captcha.risk.keys'),
                $riskConfig['source_epoch_secs'],
                $riskConfig['subnet_epoch_secs'],
                $riskConfig['subnet_ipv4_prefix'],
                $riskConfig['subnet_ipv6_prefix'],
            ]));
            if ($riskConfig['network_classifier_file'] !== null) {
                $container->setDefinition('kiwi_captcha.risk.classifier', (new Definition(CidrNetworkClassifier::class))
                    ->setFactory([CidrNetworkClassifier::class, 'fromFile'])
                    ->setArguments([$riskConfig['network_classifier_file']]));
            } else {
                $container->setDefinition('kiwi_captcha.risk.classifier', new Definition(CidrNetworkClassifier::class, [[]]));
            }
            $container->setDefinition('kiwi_captcha.risk.scorer', new Definition(RiskScorer::class));
            $container->setDefinition('kiwi_captcha.risk.policy', (new Definition(RiskPolicy::class))
                ->setFactory([RiskPolicy::class, 'fromConfig'])
                ->setArguments([$policyConfig])
                ->setPublic(true));
            // The risk state store is self-contained in the package (the
            // canonical risk-v1 Lua ships at resources/risk-v1.lua). The
            // session TTL comes from the continuity-cookie lifetime: a
            // session signal must never outlive the cookie that carries it.
            $container->setDefinition('kiwi_captcha.risk.store', (new Definition(RedisRiskStateStore::class, [
                $riskRedis,
                $namespace,
                $riskConfig['source_epoch_secs'],
                $riskConfig['subnet_epoch_secs'],
                $riskConfig['state_ttl_secs'],
            ]))
                ->setArgument('$principalTtlSecs', $riskConfig['principal_ttl_secs'])
                ->setArgument('$sessionTtlSecs', $riskConfig['continuity_cookie']['ttl_secs'])
                ->setArgument('$dedupeTtlSecs', $riskConfig['dedupe_ttl_secs'])
                ->setArgument('$hysteresisMs', $riskConfig['hysteresis_ms'])
                ->setArgument('$saturations', $riskConfig['saturations']));
            $container->setDefinition('kiwi_captcha.risk.metrics', new Definition(RiskMetrics::class));

            // In-process emergency limiter (cheap admission BEFORE the risk
            // engine): fixed per-process windows from hard_limits — source
            // AND global (assess() runs both before any state backend).
            $container->setDefinition('kiwi_captcha.risk.emergency_limiter', new Definition(ProcessEmergencyCap::class, [
                max(1, $riskConfig['hard_limits']['source_per_second']),
                max(1, $riskConfig['hard_limits']['global_per_second']),
            ]));

            // Redis-backed aggregate calibration (score-bucket statistics,
            // no identity): adjusts only the per-scope bias, bounded by the
            // configured min_samples / max_adjustment / max_change_per_minute
            // knobs, with the receipt TTL passed through (also the TTL of the
            // gateway's nonce->decision handles). Receipts are keyed on
            // decision ids, so the same Predis client + namespace as the risk
            // state store keeps every calibration key in one hash-tag family.
            $calibrationRef = null;
            if ($riskConfig['calibration']['enabled']) {
                $container->setDefinition('kiwi_captcha.risk.calibration', new Definition(AggregateCalibrator::class, [
                    $riskRedis,
                    $namespace,
                    $riskConfig['calibration']['min_samples'],
                    $riskConfig['calibration']['max_adjustment'],
                    $riskConfig['calibration']['max_change_per_minute'],
                    $riskConfig['calibration']['receipt_ttl_secs'],
                ]));
                $calibrationRef = new Reference('kiwi_captcha.risk.calibration');
            }

            // Shared circuit breaker: the engine records every store
            // success/failure on it and consumes its state for the DEGRADED
            // mode (backend unavailable -> the policy's degraded action) —
            // no per-request PING, the breaker state IS the last-operation
            // result.
            $container->setDefinition('kiwi_captcha.risk.breaker', new Definition(CircuitBreaker::class));

            // The engine is public so applications can read risk metrics
            // (RiskGateway::metricsSnapshot) or record their own
            // confirmed-legitimate/abuse signals. The trailing parameters
            // are passed BY NAME against the final package contract
            // (principalTtlSecs, saturations, calibration) so their position
            // in the constructor cannot drift from this wiring. The session
            // TTL lives on the state store, the global per-second limit on
            // the emergency limiter — both wired above.
            $container->setDefinition('kiwi_captcha.risk.engine', (new Definition(AdaptiveRiskEngine::class, [
                new Reference('kiwi_captcha.risk.store'),
                new Reference('kiwi_captcha.risk.classifier'),
                new Reference('kiwi_captcha.risk.identity_factory'),
                new Reference('kiwi_captcha.risk.scorer'),
                new Reference('kiwi_captcha.risk.policy'),
                new Reference('kiwi_captcha.risk.keys'),
                $riskConfig['source_epoch_secs'],
                $riskConfig['subnet_epoch_secs'],
                $riskConfig['state_ttl_secs'],
            ]))
                ->setArgument('$principalTtlSecs', $riskConfig['principal_ttl_secs'])
                ->setArgument('$dedupeTtlSecs', $riskConfig['dedupe_ttl_secs'])
                ->setArgument('$saturations', $riskConfig['saturations'])
                ->setArgument('$breaker', new Reference('kiwi_captcha.risk.breaker'))
                ->setArgument('$limiter', new Reference('kiwi_captcha.risk.emergency_limiter'))
                ->setArgument('$metrics', new Reference('kiwi_captcha.risk.metrics'))
                ->setArgument('$calibration', $calibrationRef)
                ->setArgument('$enableGlobalPressure', $riskConfig['global_pressure']['enabled'])
                ->setPublic(true));
            $container->setDefinition('kiwi_captcha.risk.resolver', new Definition(RiskProfileResolver::class, [
                PoWAlgorithm::from($config['algorithm']),
                $config['difficulty_bits'],
            ]));

            // Atomic issuance-rate signal: the controller increments
            // {kiwi:<ns>}:issuance:<second> (INCR + EXPIRE 1) on every minted
            // challenge; the resource-pressure provider reads it for the
            // real issuanceCapacity headroom.
            $issuanceKeyPrefix = sprintf('{kiwi:%s}:issuance:', $namespace);
            $container->setDefinition('kiwi_captcha.risk.issuance_counter', new Definition(IssuanceCounter::class, [
                $riskRedis,
                $issuanceKeyPrefix,
            ]));
            $issuanceCounterRef = new Reference('kiwi_captcha.risk.issuance_counter');

            // Live resource pressure: remaining Redis admission-semaphore
            // slots (argon_capacity.enabled gate) and real per-second
            // issuance headroom as the remaining FRACTION of
            // hard_limits.global_per_second (fixed-point 0..1000). Risk
            // backend health is NOT a snapshot field anymore — the engine's
            // degraded mode consumes the shared circuit breaker directly.
            // Unobservable sources stay nominal (1000).
            $container->setDefinition('kiwi_captcha.risk.resource_pressure', new Definition(RedisRiskHealthProvider::class, [
                $riskConfig['argon_capacity']['enabled']
                    ? ($container->hasDefinition('kiwi_captcha.argon2_redis_semaphore')
                        ? new Reference('kiwi_captcha.argon2_redis_semaphore')
                        : null)
                    : null,
                $riskRedis,
                $issuanceKeyPrefix,
                $riskConfig['hard_limits']['global_per_second'],
            ]));
            $loggerRef = $container->hasDefinition('logger') || $container->hasAlias('logger')
                ? new Reference('logger')
                : null;
            $container->setDefinition(RiskGateway::class, (new Definition(RiskGateway::class, [
                new Reference('kiwi_captcha.risk.engine'),
                new Reference('kiwi_captcha.risk.classifier'),
                new Reference('kiwi_captcha.risk.resolver'),
                $scopeIds,
            ]))
                ->setArgument('$logger', $loggerRef)
                ->setArgument('$resources', new Reference('kiwi_captcha.risk.resource_pressure'))
                ->setArgument('$postSolveScopes', $postSolveScopes)
                ->setArgument('$unknownScopeMode', $riskConfig['unknown_scope']['mode'])
                ->setArgument('$unknownScopeId', $unknownScopeId)
                ->setArgument('$requestStack', new Reference('request_stack'))
                ->setArgument('$decisionRedis', $riskRedis)
                ->setArgument('$decisionKeyPrefix', sprintf('{kiwi:%s}:decision:', $namespace))
                ->setArgument('$decisionTtlSecs', $riskConfig['calibration']['receipt_ttl_secs'])
                ->setArgument('$policy', new Reference('kiwi_captcha.risk.policy'))
                ->setPublic(true));
            if ($container->has(PrincipalResolverInterface::class)) {
                // An application-registered principal resolver is OPT-IN:
                // when a service for the interface exists, the raw principal
                // of each request flows into every engine context (the
                // engine HMAC-pseudonymizes it before Redis storage).
                $container->getDefinition(RiskGateway::class)
                    ->setArgument('$principalResolver', new Reference(PrincipalResolverInterface::class));
            }
            $cookie = $riskConfig['continuity_cookie'];
            $container->setDefinition(ContinuityCookie::class, (new Definition(ContinuityCookie::class, [
                $cookie['name'],
                $cookie['ttl_secs'],
                $cookie['path'],
                $cookie['secure'],
                $cookie['samesite'],
                $cookie['http_only'],
            ]))->setPublic(true));
            $riskGatewayRef = new Reference(RiskGateway::class);
            $riskCookieRef = new Reference(ContinuityCookie::class);
        }
        $container->setDefinition(ChallengeController::class, (new Definition(ChallengeController::class, [
            new Reference('kiwi_captcha.issuer'),
            $rateLimiterRef,
            $config['same_origin_only'],
            $riskGatewayRef,
            $riskCookieRef,
            $issuanceCounterRef,
        ]))->addTag('controller.service_arguments')->setPublic(true));

        // ── Challenge route (configured prefix; see KiwiCaptchaRouteLoader) ──
        $container->setDefinition(KiwiCaptchaRouteLoader::class, (new Definition(KiwiCaptchaRouteLoader::class, [
            '%kiwi_captcha.route_prefix%',
        ]))->addTag('routing.loader'));

        // ── Form type (renders the widget through the form theme) ──
        // The route prefix is injected so the default 'endpoint' option
        // follows the ACTUAL registered route (the standalone Twig widget
        // derives its endpoint from the same prefix); the telemetry mode
        // follows the (strict-enforced) config.
        $container->setDefinition(KiwiCaptchaType::class, (new Definition(KiwiCaptchaType::class, [
            new Reference(KiwiCaptchaRuntime::class),
            '%kiwi_captcha.route_prefix%',
            $config['telemetry'],
        ]))->addTag('form.type'));

        // ── Validator (local verification, no external calls) ──
        $container->setDefinition(KiwiCaptchaValidator::class, (new Definition(KiwiCaptchaValidator::class, [
            new Reference('kiwi_captcha.verifier'),
            new Reference('request_stack'),
            $config['secret_key'],
            $config['enforce_telemetry'],
            $riskGatewayRef,
            $riskCookieRef,
        ]))->addTag('validator.constraint_validator'));

        // ── Twig widget runtime + twig function (embeds the shared widget assets) ──
        $container->setDefinition(KiwiCaptchaRuntime::class, (new Definition(KiwiCaptchaRuntime::class, [
            $config['route_prefix'],
            null,
            KiwiCaptchaRuntime::DEFAULT_TEMPLATE,
            $config['telemetry'],
        ]))->addTag('twig.runtime'));
        $container->setDefinition(TwigExtension::class, (new Definition(TwigExtension::class))
            ->addTag('twig.extension'));
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

    /**
     * Find the Redis client to use for the Argon2 admission gate and the
     * atomic rate limiter.
     *
     * Priority:
     *  1. the `redis_service` config option (explicit client service id);
     *  2. the storage service when it is a KiwiCaptcha\Storage\RedisStorage
     *     definition (its first constructor argument is the client) —
     *     aliases to the storage id are followed;
     *  3. null — the caller falls back to the in-process gate / best-effort
     *     rate limiting.
     */
    private function resolveRedisClient(string $storageId, ?string $redisService, ContainerBuilder $container): ?Reference
    {
        if ($redisService !== null) {
            return new Reference($redisService);
        }

        $id = $storageId;
        if ($container->hasAlias($id)) {
            $id = (string) $container->getAlias($id);
        }
        if (!$container->hasDefinition($id)) {
            return null;
        }
        $definition = $container->getDefinition($id);
        $class = $definition->getClass();
        if ($class === null || !is_a($class, RedisStorage::class, true)) {
            return null;
        }
        $client = $definition->getArgument(0);

        return $client instanceof Reference ? $client : null;
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

    /**
     * Build the risk-v1 policy config (int-keyed scopes) and the
     * scope-name => int-id map from the bundle's string-keyed scopes node.
     *
     * Scope ids must be unique and stable across deploys: an explicit `id`
     * wins, otherwise the id is crc32(scope name) & 0x7fffffff. Two scopes
     * with the same id would silently share risk state — refuse the config.
     *
     * Contract invariants for the policy handed to RiskPolicy::fromConfig:
     *  - global_floors is an array of FIVE entries with index 0 = Allow
     *    (level 0 is the idle level). When global_pressure.enabled is false
     *    every floor is Allow — the global controller is off.
     *  - unknown_scope.mode "minimum" adds a synthetic scope entry
     *    (base_risk 100, minimum/degraded sha20) under a reserved id
     *    (1..u32::MAX, never colliding with a configured id); "reject" and
     *    "baseline" leave the policy without it and the gateway declines
     *    unknown scopes with UnknownScopeException (the controller turns
     *    "reject" into the risk-denied 429 and "baseline" into the default
     *    challenge).
     *
     * @return array{0: array<string, mixed>, 1: array<string, int>, 2: array<string, bool>, 3: ?int}
     *         [policy config, scope-name => scope-id, scope-name => post_solve_check, synthetic unknown-scope id]
     */
    private function buildRiskPolicy(array $riskConfig): array
    {
        // RiskPolicy::fromConfig enforces version equality: the policy
        // config's version must equal the package's contract version
        // (RiskPolicy::CONTRACT_VERSION). The operator's policy_version
        // knob is the value written into decisions — it must agree with the
        // contract the package parses, so refuse a mismatch at compile time.
        if ($riskConfig['policy_version'] !== RiskPolicy::CONTRACT_VERSION) {
            throw new \InvalidArgumentException(sprintf(
                'kiwi_captcha.risk.policy_version must equal the risk package contract version %d (got %d) — '.
                'the risk-v1 policy parser only accepts its current contract version',
                RiskPolicy::CONTRACT_VERSION,
                $riskConfig['policy_version'],
            ));
        }
        $policyConfig = [
            'version' => RiskPolicy::CONTRACT_VERSION,
            'weights' => $riskConfig['weights'],
            'scopes' => [],
            'global_floors' => $riskConfig['global_pressure']['enabled']
                ? [0 => RiskAction::Allow->value] + $riskConfig['global_floors']
                : array_fill(0, 5, RiskAction::Allow->value),
        ];
        $scopeIds = [];
        $postSolveScopes = [];
        foreach ($riskConfig['scopes'] as $name => $spec) {
            $id = $spec['id'] ?? (crc32($name) & 0x7fffffff);
            if ($id < 1) {
                throw new \InvalidArgumentException(sprintf(
                    'kiwi_captcha.risk.scopes[%s].id must be >= 1 (got %d)',
                    $name,
                    $id,
                ));
            }
            if (isset($scopeIds[$name]) || \in_array($id, $scopeIds, true)) {
                throw new \InvalidArgumentException(sprintf(
                    'kiwi_captcha.risk.scopes[%s]: risk scope id %d collides with another scope — set explicit, unique "id" values',
                    $name,
                    $id,
                ));
            }
            $scopeIds[$name] = $id;
            $postSolveScopes[$name] = $spec['post_solve_check'];
            $policyConfig['scopes'][$id] = [
                'base_risk' => $spec['base_risk'],
                'minimum' => $spec['minimum'],
                'post_solve_check' => $spec['post_solve_check'],
                'degraded' => $spec['degraded'],
            ];
        }
        ksort($policyConfig['scopes']);

        $unknownScopeId = null;
        if ($riskConfig['unknown_scope']['mode'] === 'minimum') {
            $unknownScopeId = $this->reserveUnknownScopeId($scopeIds);
            $policyConfig['scopes'][$unknownScopeId] = [
                'base_risk' => 100,
                'minimum' => RiskAction::Sha20->value,
                'post_solve_check' => false,
                'degraded' => RiskAction::Sha20->value,
            ];
        }

        return [$policyConfig, $scopeIds, $postSolveScopes, $unknownScopeId];
    }

    /**
     * A stable synthetic scope id for unknown scopes in 'minimum' mode:
     * starts at u32::MAX and walks down until it collides with no
     * configured scope id (the risk-v1 contract allows ids 1..u32::MAX).
     *
     * @param array<string, int> $scopeIds
     */
    private function reserveUnknownScopeId(array $scopeIds): int
    {
        $used = array_values($scopeIds);
        for ($id = 0xFFFFFFFF; $id >= 1; --$id) {
            if (!\in_array($id, $used, true)) {
                return $id;
            }
        }
        throw new \InvalidArgumentException('Cannot reserve a synthetic scope id for unknown_scope.mode=minimum: every id 1..u32::MAX is taken by a configured scope');
    }

    /**
     * Resolve the Predis\Client for the risk state store.
     *
     * Priority: the explicit risk.redis_service, then the bundle's own Redis
     * client (redis_service / RedisStorage) when it is a Predis client. A
     * phpredis (\Redis) client cannot drive the risk-v1 EVALSHA store (its
     * constructor is typed Predis\Client) — refuse with an actionable
     * message instead of failing at request time.
     *
     * @throws \LogicException when risk is enabled but no Predis client is
     *                         resolvable
     */
    private function resolveRiskRedisClient(array $riskConfig, ?Reference $bundleRedis, ContainerBuilder $container): Reference
    {
        if ($riskConfig['redis_service'] !== null) {
            $ref = new Reference($riskConfig['redis_service']);
            $class = $this->definitionClass((string) $ref, $container);
            if ($class !== null && !is_a($class, \Predis\Client::class, true)) {
                throw new \LogicException(sprintf(
                    'kiwi_captcha.risk.redis_service ("%s", class %s) must be a Predis\Client — '.
                    'the risk-v1 state store is typed Predis\Client (phpredis \Redis is not supported by the risk engine)',
                    $riskConfig['redis_service'],
                    $class,
                ));
            }

            return $ref;
        }

        if ($bundleRedis !== null) {
            $class = $this->definitionClass((string) $bundleRedis, $container);
            if ($class === null) {
                throw new \LogicException(
                    'kiwi_captcha.risk.enabled cannot reuse the bundle Redis client: its service class is not visible to the '.
                    'extension. Set risk.redis_service explicitly to a Predis\Client service id.'
                );
            }
            if (is_a($class, \Predis\Client::class, true)) {
                return $bundleRedis;
            }
            throw new \LogicException(sprintf(
                'kiwi_captcha.risk.enabled requires a Predis\Client, but the bundle Redis client (%s) is %s — '.
                'the risk-v1 state store is typed Predis\Client (phpredis \Redis is not supported by the risk engine). '.
                'Configure risk.redis_service with a Predis\Client service id.',
                (string) $bundleRedis,
                $class,
            ));
        }

        throw new \LogicException(
            'kiwi_captcha.risk.enabled requires a Redis client for the canonical risk-v1 state script. '.
            'Set risk.redis_service to a Predis\Client service id (or configure redis_service / RedisStorage '.
            'with a Predis\Client so the extension can reuse it).'
        );
    }

    /** The class of a service id (following aliases), or null when invisible. */
    private function definitionClass(string $id, ContainerBuilder $container): ?string
    {
        if ($container->hasAlias($id)) {
            $id = (string) $container->getAlias($id);
        }
        if (!$container->hasDefinition($id)) {
            return null;
        }

        return $container->getDefinition($id)->getClass();
    }
}
