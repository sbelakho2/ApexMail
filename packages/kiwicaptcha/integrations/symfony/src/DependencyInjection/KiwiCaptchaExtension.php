<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\DependencyInjection;

use BelConsulting\KiwiCaptchaBundle\Controller\ApiJsController;
use BelConsulting\KiwiCaptchaBundle\Controller\AssetController;
use BelConsulting\KiwiCaptchaBundle\Controller\ChallengeController;
use BelConsulting\KiwiCaptchaBundle\Controller\KiwiHealthController;
use BelConsulting\KiwiCaptchaBundle\Controller\SiteVerifyController;
use BelConsulting\KiwiCaptchaBundle\Command\KiwiCaptchaDoctorCommand;
use BelConsulting\KiwiCaptchaBundle\Command\KiwiCaptchaHaInitializeCommand;
use BelConsulting\KiwiCaptchaBundle\Risk\ArrayChainedChallengeStateStore;
use BelConsulting\KiwiCaptchaBundle\Risk\ArrayPostSolveDispositionStore;
use BelConsulting\KiwiCaptchaBundle\Risk\ChainedChallengeTicketService;
use BelConsulting\KiwiCaptchaBundle\Risk\RedisChainedChallengeStateStore;
use BelConsulting\KiwiCaptchaBundle\Risk\RedisPostSolveDispositionStore;
use BelConsulting\KiwiCaptchaBundle\SiteVerify\ArraySiteVerifyIdempotencyStore;
use BelConsulting\KiwiCaptchaBundle\SiteVerify\ArraySiteVerifyMetadataStore;
use BelConsulting\KiwiCaptchaBundle\SiteVerify\RedisSiteVerifyIdempotencyStore;
use BelConsulting\KiwiCaptchaBundle\SiteVerify\RedisSiteVerifyMetadataStore;
use BelConsulting\KiwiCaptchaBundle\SiteVerify\SiteVerifyIdempotencyStore;
use BelConsulting\KiwiCaptchaBundle\SiteVerify\SiteVerifyRecoveryCapableStorageInterface;
use BelConsulting\KiwiCaptchaBundle\Form\Type\KiwiCaptchaType;
use BelConsulting\KiwiCaptchaBundle\Risk\ClientIpResolver;
use BelConsulting\KiwiCaptchaBundle\Risk\ContinuityCookie;
use BelConsulting\KiwiCaptchaBundle\Risk\PrincipalResolverInterface;
use BelConsulting\KiwiCaptchaBundle\Risk\RedisRiskHealthProvider;
use BelConsulting\KiwiCaptchaBundle\Risk\RiskGateway;
use BelConsulting\KiwiCaptchaBundle\Risk\RiskProfileResolver;
use BelConsulting\KiwiCaptchaBundle\Risk\SecurityEpochMonitor;
use BelConsulting\KiwiCaptchaBundle\Routing\KiwiCaptchaRouteLoader;
use BelConsulting\KiwiCaptchaBundle\Security\ExpectedOrigin;
use BelConsulting\KiwiCaptchaBundle\Security\Authority\AuthorityGuardedPredisClient;
use BelConsulting\KiwiCaptchaBundle\Security\Authority\AuthorityTransitionGuard;
use BelConsulting\KiwiCaptchaBundle\Security\Authority\PinnedPrimaryAuthorityGuard;
use BelConsulting\KiwiCaptchaBundle\Security\Authority\RuntimeAuthorityClassifier;
use BelConsulting\KiwiCaptchaBundle\Security\InProcessArgonGate;
use BelConsulting\KiwiCaptchaBundle\Security\IssuanceCounter;
use BelConsulting\KiwiCaptchaBundle\Security\IssuanceRateLimiter;
use BelConsulting\KiwiCaptchaBundle\Security\OutstandingChallenges;
use BelConsulting\KiwiCaptchaBundle\Security\RedisAdmissionSemaphore;
use BelConsulting\KiwiCaptchaBundle\Security\RequestScopeAdmissionGate;
use BelConsulting\KiwiCaptchaBundle\Security\ResultReceiptSigner;
use BelConsulting\KiwiCaptchaBundle\Security\ScopeIssuanceCap;
use BelConsulting\KiwiCaptchaBundle\Security\VerificationSecurityContext;
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
use KiwiCaptcha\Risk\RiskV2Weights;
use KiwiCaptcha\Risk\Breaker\CircuitBreaker;
use KiwiCaptcha\Risk\Calibration\AggregateCalibrator;
use KiwiCaptcha\Risk\Metrics\RiskMetrics;
use KiwiCaptcha\Risk\RiskScorer;
use KiwiCaptcha\Risk\Storage\ProcessEmergencyCap;
use KiwiCaptcha\Risk\Storage\RedisRiskStateStore;
use KiwiCaptcha\Storage\ArrayStorage;
use KiwiCaptcha\Storage\RedisStorage;
use KiwiCaptcha\AtomicStorageInterface;
use KiwiCaptcha\AtomicDeleteIfPendingInterface;
use KiwiCaptcha\ConsumedStateReadableInterface;
use KiwiCaptcha\OperationIdentityAwareStorageInterface;
use KiwiCaptcha\StorageInterface;
use KiwiCaptcha\Verifier;
use Symfony\Component\Cache\Adapter\ArrayAdapter;
use Symfony\Component\DependencyInjection\ChildDefinition;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Definition;
use Symfony\Component\DependencyInjection\Extension\Extension;
use Symfony\Component\DependencyInjection\Extension\PrependExtensionInterface;
use Symfony\Component\DependencyInjection\Reference;

/**
 * SECURITY-MAINTAINER material: the wiring invariants enforced in this
 * extension are deep design rationale, intentionally not published at
 * the integration layer. See docs/operations.md for the maintainer
 * view and docs/security-hardening.md for the integration actions.
 */
final class KiwiCaptchaExtension extends Extension implements PrependExtensionInterface
{
    private const ARRAY_STORAGE_ID = 'kiwi_captcha.storage.array';
    private const DSN_REDIS_CLIENT_ID = 'kiwi_captcha.redis.dsn';
    private const DSN_STORAGE_ID = 'kiwi_captcha.storage.redis_dsn';
    private const EXPECTED_ORIGIN_ID = 'kiwi_captcha.expected_origin';
    private const AUTHORITY_GUARD_ID = 'kiwi_captcha.authority_transition_guard';
    private const CHECKED_CLIENT_ID = 'kiwi_captcha.redis.checked';

    /**
     * raw service id => checked wrapper id, keyed by container. The
     * memoization is per container because prepend() runs on the real
     * container and load() on the temporary one: the same raw client id
     * must map to one wrapper per container, never across containers.
     *
     * @var array<int, array<string, string>>
     */
    private array $checkedClientIdsByContainer = [];

    /**
     * The SLO safety margin (ms) between the Argon admission lease
     * (argon2_lease_ms) and the deployment's declared maximum verification
     * runtime (argon2_max_verification_runtime_ms): the lease must exceed
     * the declared runtime by at least this margin, or the container
     * refuses to compile. The margin absorbs clock skew and lease
     * bookkeeping so the lease-expiry-before-hash-termination invariant
     * is a deliberate deployment SLO, not a silent operator promise. The
     * declared runtime is not an enforced wall-clock timeout around the
     * blocking Argon hash: on a pathological host a hash can still outlive
     * the lease (fencing keeps correctness, resource concurrency may
     * still be exceeded in the expiry window).
     */
    private const ARGON_LEASE_SAFETY_MARGIN_MS = 5000;

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
     * sets it when the application has not configured the router at all (a
     * fresh app). Applications that configure framework.router themselves must
     * import the bundle's routes file manually:
     *
     *     # config/routes.yaml
     *     kiwi_captcha:
     *         resource: '@KiwiCaptchaBundle/Resources/config/routes.php'
     */
    public function prepend(ContainerBuilder $container): void
    {
        // The fail_closed posture refusal runs here, on the real
        // container, because the extension load() compiles against a
        // temporary container where application-defined client services
        // are invisible. The raw config layers are inspected, so only
        // an explicit replay_durability "fail_closed" engages.
        $this->refuseFailClosedAggregateWiring($container);
        // The runtime authority guard covers the client of an
        // application-defined RedisStorage too: the durability-critical
        // pending->consumed transition lives in RedisStorage, so under
        // fail_closed its client must be classified like every other
        // Redis-backed consumer. The patch runs here, on the real
        // container, where the application's storage definition is
        // visible; the load-time container is temporary and lacks it.
        $this->guardAppDefinedStorageClients($container);
        if (!$container->hasExtension('framework')) {
            return;
        }
        foreach ($container->getExtensionConfig('framework') as $config) {
            if (isset($config['router'])) {
                // The app configures the router itself (own resource or
                // explicitly disabled), so never touch it.
                return;
            }
        }

        $container->prependExtensionConfig('framework', [
            'router' => ['resource' => __DIR__.'/../Resources/config/routes.php'],
        ]);
    }

    /**
     * The posture refusal lanes for the kernel build flow. The
     * extension load() runs inside a temporary container (Symfony
     * compiles every extension in isolation and merges the result), so
     * application-defined client services are invisible at load time.
     * The prepend hook runs on the real container before that, where
     * every definition is visible, so the classification reaches the
     * actual client wiring. The raw config layers carry the posture.
     * An explicit replay_durability "fail_closed" or ha_authority
     * "pinned_primary" in any layer engages the refusal for the client
     * services the effective merge would wire (redis_service,
     * risk.redis_service, and a RedisStorage storage definition's own
     * client), with later layers winning like the merge. An
     * env-resolved posture cannot be classified at build time and
     * skips this lane, exactly like the load-time lane.
     */
    private function refuseFailClosedAggregateWiring(ContainerBuilder $container): void
    {
        $layers = $container->getExtensionConfig('kiwi_captcha');
        $posture = null;
        $haAuthority = null;
        $redisService = null;
        $riskRedisService = null;
        $storage = null;
        foreach ($layers as $layer) {
            if (!\is_array($layer)) {
                continue;
            }
            if (\array_key_exists('replay_durability', $layer)) {
                $posture = $layer['replay_durability'];
            }
            if (\array_key_exists('ha_authority', $layer)) {
                $haAuthority = $layer['ha_authority'];
            }
            if (\array_key_exists('redis_service', $layer)) {
                $redisService = $layer['redis_service'];
            }
            if (isset($layer['risk']) && \is_array($layer['risk']) && \array_key_exists('redis_service', $layer['risk'])) {
                $riskRedisService = $layer['risk']['redis_service'];
            }
            if (\array_key_exists('storage', $layer)) {
                $storage = $layer['storage'];
            }
        }
        $failClosed = $posture === 'fail_closed';
        $pinnedPrimary = $haAuthority === 'pinned_primary';
        if (!$failClosed && !$pinnedPrimary) {
            return;
        }
        foreach ([$redisService, $riskRedisService] as $clientId) {
            if (!\is_string($clientId) || $clientId === '') {
                continue;
            }
            $aggregate = $this->predisAggregateLabel(new Reference($clientId), $container, sprintf('the "%s" Redis client', $clientId));
            if ($aggregate !== null) {
                throw new \LogicException(
                    $failClosed
                        ? self::failClosedRefusalMessage($aggregate)
                        : self::pinnedPrimaryRefusalMessage($aggregate)
                );
            }
            if ($pinnedPrimary) {
                $class = $this->definitionClass($clientId, $container);
                if ($class === null) {
                    throw new \LogicException(self::pinnedPrimaryUnverifiableClientMessage($clientId, 'its class cannot be resolved at build time'));
                }
                if (!is_a($class, \Predis\Client::class, true)) {
                    throw new \LogicException(self::pinnedPrimaryUnverifiableClientMessage($clientId, sprintf('its class %s is not a Predis\Client (phpredis \Redis cannot be mechanically guarded)', $class)));
                }
            }
        }
        if (!\is_string($storage) || $storage === '') {
            return;
        }
        $id = $this->resolveParameterizedServiceId($storage, $container);
        $seenAliases = [];
        while ($id !== null && $container->hasAlias($id)) {
            if (isset($seenAliases[$id]) || \count($seenAliases) >= 32) {
                $id = null;
                break;
            }
            $seenAliases[$id] = true;
            $resolved = $this->resolveParameterizedServiceId((string) $container->getAlias($id), $container);
            if ($resolved === null) {
                $id = null;
                break;
            }
            $id = $resolved;
        }
        if ($id === null || !$container->hasDefinition($id)) {
            return;
        }
        $definition = $container->getDefinition($id);
        $class = $this->resolveParameterizedClass($definition->getClass(), $container);
        if ($class === null || !is_a($class, RedisStorage::class, true)) {
            return;
        }
        $client = $definition->getArgument(0);
        if (!$client instanceof Reference) {
            return;
        }
        $clientId = $this->resolveParameterizedServiceId((string) $client, $container);
        if ($clientId === null) {
            return;
        }
        $aggregate = $this->predisAggregateLabel(new Reference($clientId), $container, sprintf('the storage client of "%s"', $storage));
        if ($aggregate !== null) {
            throw new \LogicException(
                $failClosed
                    ? self::failClosedRefusalMessage($aggregate)
                    : self::pinnedPrimaryRefusalMessage($aggregate)
            );
        }
        if ($pinnedPrimary) {
            $clientClass = $this->definitionClass($clientId, $container);
            if ($clientClass === null) {
                throw new \LogicException(self::pinnedPrimaryUnverifiableClientMessage($clientId, 'its class cannot be resolved at build time'));
            }
            if (!is_a($clientClass, \Predis\Client::class, true)) {
                throw new \LogicException(self::pinnedPrimaryUnverifiableClientMessage($clientId, sprintf('its class %s is not a Predis\Client (phpredis \Redis cannot be mechanically guarded)', $clientClass)));
            }
        }
    }

    /**
     * The shared fail_closed refusal message: names the posture, the
     * aggregate, and the remediation options (a pinned-primary or
     * topology adapter, or the weaker postures). The remediation text
     * is the single source shared with the runtime guard's refusal, so
     * the build-time and runtime lanes name the same options.
     */
    private static function failClosedRefusalMessage(string $aggregate): string
    {
        return sprintf(
            'kiwi_captcha.replay_durability is "fail_closed", but %s — the fail_closed posture refuses to rely on automatic failover, because a stale-replica promotion can re-enable replay of a consumed or burned challenge. %s',
            $aggregate,
            RuntimeAuthorityClassifier::FAIL_CLOSED_REMEDIATION,
        );
    }

    /**
     * The pinned_primary refusal message: names the posture and the
     * remediation. Mirrors the fail_closed message but for the
     * mechanical-authority posture, where the guard exists and the
     * aggregate would defeat it (the guard pins one node; an aggregate
     * can change the serving node under the client).
     */
    private static function pinnedPrimaryRefusalMessage(string $aggregate): string
    {
        return sprintf(
            'kiwi_captcha.ha_authority is "pinned_primary", but %s — the pinned-primary authority guard pins ONE serving node, and an automatic-failover aggregate can change the serving node under the client, which is exactly the change the pin exists to detect at the deployment boundary. Wire a direct single-node Predis client (standalone connection with retries disabled), or set ha_authority: none and choose replay_durability operator_managed / best_effort (see docs/ha-authority.md).',
            $aggregate,
        );
    }

    /**
     * The pinned_primary unguardable-client refusal: names the client
     * and why the mechanical guarantee cannot be wired.
     */
    private static function pinnedPrimaryUnverifiableClientMessage(string $clientId, string $reason): string
    {
        return sprintf(
            'kiwi_captcha.ha_authority is "pinned_primary", but the "%s" Redis client cannot be mechanically guarded (%s). The pinned-primary guard intercepts every command through a Predis\Client wrapper, so a phpredis \Redis client or an unresolvable client would silently serve unguarded — refused instead. Wire a direct single-node Predis\Client (predis/predis is a direct bundle dependency), or set ha_authority: none (see docs/ha-authority.md).',
            $clientId,
            $reason,
        );
    }

    public function load(array $configs, ContainerBuilder $container): void
    {
        $configuration = new Configuration();
        // The protection profile is the LOWEST-precedence configuration
        // layer: its defaults are prepended as the first array of the
        // processing stack, so an explicit value in ANY config file wins
        // (Symfony's Processor normalizes and merges each array in stack
        // order; a later layer carrying only `protection_profile` can
        // therefore never inject profile defaults that override earlier
        // explicit settings). ProtectionProfileDefaults::finalize() then
        // applies the chaining postcondition (the profile-derived
        // chaining default engages only when a request-binding authority
        // exists in the final merged configuration).
        $config = $this->processConfiguration($configuration, ProtectionProfileDefaults::stack($configs));
        $config = ProtectionProfileDefaults::finalize($config, $configs);
        // Canonicalize the historical secrets map once, at configuration
        // processing time: every downstream consumer (the verifier keyring
        // and the Siteverify security-context digest) receives the same
        // array<int, string> keyed by canonical kid, never a mix of
        // textual aliases and ints. The tree already refused non-canonical
        // keys ('02', '0', text) and duplicate canonical kids, so this
        // pass is a pure int-key projection.
        $config['secrets_by_kid'] = self::canonicalHistoricalSecrets($config['secrets_by_kid']);

        // Advisory build notes (never throw): signing-key rotation
        // (kid > 1 or a non-empty historical map) is the documented
        // deployment model, and a routine rotation must not silently
        // reset the abuse-identity secrets. When the rate/risk root keys
        // are left at their derivation default (secret_key), the notes
        // tell the operator to configure dedicated stable keys; the
        // derivation fallbacks stay the compatibility default.
        $rotationConfigured = $config['kid'] > 1 || $config['secrets_by_kid'] !== [];
        if ($rotationConfigured && $config['rate_limit_pepper'] === null) {
            $container->log(new KiwiConfigAdvisoryPass(), 'kiwi_captcha.rate_limit_pepper is not configured, so the per-client rate-limit identities derive from secret_key. A routine signing-key rotation will therefore reset every per-client rate-limit identity (fresh HMAC keys, so every client window restarts empty). Configure a dedicated, stable rate_limit_pepper so routine rotations of the signing key never reset the rate-limit memory; an emergency root compromise may intentionally rotate everything.');
        }
        if ($rotationConfigured && $config['risk']['enabled'] && $config['risk']['master_secret'] === null) {
            $container->log(new KiwiConfigAdvisoryPass(), 'kiwi_captcha.risk.master_secret is not configured, so the risk identity keys derive from secret_key. A routine signing-key rotation will therefore reset every risk pseudonym (fresh derived keys, so every source/subnet/session counter restarts at zero). Configure a dedicated, stable risk.master_secret so routine rotations of the signing key never reset the adaptive-risk memory; an emergency root compromise may intentionally rotate everything.');
        }

        // Privacy posture enforcement: 'strict' (default) forces the
        // privacy-sensitive options off or true:
        //   - telemetry: 'off'      (no client signal fields at all)
        //   - enforce_telemetry: false (an off widget sends empty telemetry;
        //                            enforcing it would reject every user)
        //   - same_origin_only: true (cross-origin POSTs rejected)
        //   - min_duration_ms: 0    (the server-side solve-timing floor is a
        //                            timing heuristic and is disabled)
        // binding_mode is not forced: IP binding is a relay mitigation and
        // the stored tag is nonce-bound (never a stable IP identifier), so
        // an operator may still disable it under strict. rate_limit /
        // rate_limit_global already default to nonzero.
        if ($config['privacy_mode'] === 'strict') {
            $config['telemetry'] = 'off';
            $config['enforce_telemetry'] = false;
            $config['same_origin_only'] = true;
            $config['min_duration_ms'] = 0;
        } elseif ($config['enforce_telemetry'] && $config['telemetry'] === 'off') {
            // Impossible combination outside strict mode: enforcement
            // rejects clients whose telemetry is empty, which is exactly
            // what an off widget sends, so every legitimate solve would
            // fail. Refuse the configuration instead of accepting a
            // production trap.
            throw new \InvalidArgumentException(
                'kiwi_captcha.enforce_telemetry cannot be true while telemetry is "off": '.
                'an off widget sends empty telemetry and enforcement rejects it. '.
                'Set telemetry to "minimal"/"full", or disable enforcement.'
            );
        }
        // The coarse client-context opt-in is a deliberate operator choice:
        // privacy_mode "strict" refuses it at compile time, since under
        // strict the widget must collect no device-capability or screen-size
        // signal. Enabling it requires privacy_mode "standard" plus
        // risk.client_context true. The default (false) is off under every
        // mode.
        if ($config['privacy_mode'] === 'strict' && $config['risk']['client_context']) {
            throw new \InvalidArgumentException(
                'kiwi_captcha.risk.client_context cannot be true under privacy_mode "strict": '.
                'strict mode refuses the coarse client-context opt-in — enabling it requires '.
                'the operator to deliberately enable coarse client context '.
                '(set privacy_mode to "standard" AND risk.client_context to true).'
            );
        }
        // The ExecutionChallengeV1 gate is inert without the
        // execution_key: the controller arms only when the issuer's
        // config carries the key, so a deployment that turns the gate on
        // but configures no key simply never issues execution programs
        // (the dimension is supplementary evidence only, never the sole
        // acceptance boundary — an inert gate is never a security hole).
        // Configuring the key is what engages the dimension.

        // Cross-option invariants (validated here, after the config tree):
        // - a rotation shorter than the sliding window would drop live hits
        //   from epochs older than (current - 1) from the two-epoch
        //   accounting (the limiter constructor enforces the same rule)
        // - a min_duration_ms at or above the TTL leaves no acceptable
        //   submission time (TooFast before expiry, Expired after); the
        //   core Config validates the same relation. The relation is
        //   intrinsic to issuance, not to Siteverify, so it applies to the
        //   global TTL and to every per-sitekey ttl_secs regardless of
        //   whether Siteverify is enabled.
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
        foreach ($config['risk']['sitekeys'] as $sitekey => $spec) {
            if ($config['min_duration_ms'] !== null && $spec['ttl_secs'] !== null && $config['min_duration_ms'] >= $spec['ttl_secs'] * 1000) {
                throw new \LogicException(sprintf(
                    'kiwi_captcha.min_duration_ms %d must be < sitekey %s ttl_secs %d * 1000 — a floor at or above the TTL leaves no acceptable submission time (TooFast before expiry, Expired after)',
                    $config['min_duration_ms'],
                    $sitekey,
                    $spec['ttl_secs'],
                ));
            }
        }
        // Siteverify crash-recovery ordering invariants. The idempotency
        // store's crash recovery rests on the strict ordering
        // (SiteVerifyIdempotencyStore::LEASE_SECONDS):
        //
        //   max verification window  <  lease (60)  <  waiter bound (2 s)
        //                            <= retained-state recovery retention
        //
        // The controller enforces waiter < lease (the per-request waiter
        // bound only caps request-slot occupancy; the takeover is a later
        // retry's job); the Argon admission lease and the retained
        // consumed-state retention margin complete the ordering and are
        // validated here, since a configuration that breaks it makes
        // crash recovery impossible (a `PENDING_SAME` waiter
        // lease-bounded verification outlasts the Siteverify lease and is
        // displaced at takeover). Signed token expiry is irrelevant to the
        // reconstruction: the retained consumed record, kept readable by
        // risk.redis.ttl_margin_secs, reproduces the original outcome
        // after the signed challenge has expired, so short-lived
        // Siteverify profiles (e.g. 30s) are fully supported.
        if ($config['risk']['siteverify_secrets'] !== []) {
            // The provider-compatible surface cannot faithfully enforce
            // the native post-solve final disposition (adaptive
            // reassessment, chain obligations, durable
            // Pass/Deny/StepUp/ChainRequired): a siteverify secret must
            // never map to a scope whose post-solve check is enabled —
            // silently providing weaker semantics than the native path
            // is exactly the control gap the config should refuse.
            foreach ($config['risk']['siteverify_secrets'] as $svScope) {
                $svPostSolve = $config['risk']['scopes'][$svScope]['post_solve_check'] ?? false;
                if ($svPostSolve) {
                    throw new \LogicException(sprintf(
                        'kiwi_captcha.risk.siteverify_secrets: the expected scope "%s" has risk.scopes.%s.post_solve_check=true, but the provider-compatible Siteverify surface cannot faithfully enforce the native post-solve final disposition (adaptive reassessment, chain obligations, durable Pass/Deny/StepUp/ChainRequired). Map the secret to a scope with post_solve_check=false, disable post_solve_check for this scope, or serve the post-solve surface through the native validator instead.',
                        $svScope,
                        $svScope,
                    ));
                }
            }
            $waiterBoundSecs = (int) SiteVerifyController::IDEMPOTENCY_WAIT_SECS;
            if ($config['argon2_lease_ms'] >= SiteVerifyIdempotencyStore::LEASE_SECONDS * 1000) {
                throw new \LogicException(sprintf(
                    'kiwi_captcha.argon2_lease_ms %d must be below the Siteverify ownership lease (%ds) or the Siteverify lease must be raised — a lease-bounded verification could otherwise outlast the Siteverify lease and be displaced at takeover',
                    $config['argon2_lease_ms'],
                    SiteVerifyIdempotencyStore::LEASE_SECONDS,
                ));
            }
            // Retention guarantee: the retained consumed-state record
            // (RedisStorage ttl_margin_secs) must outlive the maximum
            // takeover/retry horizon. With the default margin (0) the
            // record expires exactly at token expiry, so a token submitted
            // late in its lifetime, whose crash-recovery takeover happens
            // after the signed expiry, reads nothing and the reconstruction
            // fails. The margin must therefore cover at least the
            // `PENDING_SAME` waiter bound (the absolute tail of the
            // takeover/retry window).
            if ($config['risk']['redis']['ttl_margin_secs'] < $waiterBoundSecs) {
                throw new \LogicException(sprintf(
                    'kiwi_captcha.risk.redis.ttl_margin_secs %d must be >= the Siteverify PENDING_SAME waiter bound (%ds) when siteverify_secrets is configured — the retained consumed-state evidence must outlive the maximum takeover/retry horizon, otherwise a late-lifetime crash recovery reads an expired record and cannot reconstruct the committed outcome',
                    $config['risk']['redis']['ttl_margin_secs'],
                    $waiterBoundSecs,
                ));
            }
        }

        // The Argon admission lease must outlive any verification: the
        // Redis semaphore stores leases in a ZSET with `ZREMRANGEBYSCORE`
        // pruning and no renewal, so under CPU starvation a lease that
        // expires while the Argon hash still runs admits more derivations
        // than the configured concurrency cap (positive feedback: more
        // contention -> longer hashes -> more expiries). Renewal during
        // the blocking native hash is impractical in PHP, so the
        // deployment declares its SLO: the maximum verification runtime
        // (argon2_max_verification_runtime_ms) and the lease must exceed
        // it by the safety margin, enforced at container compile time in
        // every environment (a misconfiguration is fatal everywhere,
        // exactly like the other argon validations). The declared runtime
        // is a deployment bound only: it is never enforced per-request
        // inside the blocking hash (there is no real execution bound
        // around the blocking Argon call), so the lease-expiry-during-
        // hash remains theoretically possible on a pathological host —
        // fencing keeps correctness, the resource concurrency cap may
        // still be exceeded in that expiry window.
        if ($config['argon2_lease_ms'] <= $config['argon2_max_verification_runtime_ms'] + self::ARGON_LEASE_SAFETY_MARGIN_MS) {
            throw new \LogicException(sprintf(
                'kiwi_captcha.argon2_lease_ms %d must exceed argon2_max_verification_runtime_ms %d by the safety margin of %d ms (%d <= %d + %d = %d): a Redis admission lease that can expire while an Argon2 verification is still running admits more derivations than the configured concurrency cap (ZREMRANGEBYSCORE pruning, no lease renewal), and the positive-feedback cycle (more contention -> longer hashes -> more expiries) amplifies it. Raise argon2_lease_ms or lower argon2_max_verification_runtime_ms; the declared runtime is the deployment SLO that the lease must outlive by the margin (not an enforced wall-clock bound around the blocking hash).',
                $config['argon2_lease_ms'],
                $config['argon2_max_verification_runtime_ms'],
                self::ARGON_LEASE_SAFETY_MARGIN_MS,
                $config['argon2_lease_ms'],
                $config['argon2_max_verification_runtime_ms'],
                self::ARGON_LEASE_SAFETY_MARGIN_MS,
                $config['argon2_max_verification_runtime_ms'] + self::ARGON_LEASE_SAFETY_MARGIN_MS,
            ));
        }
        // A static transaction binding must satisfy the same shape rule
        // the controller enforces per request (1..128 bytes of
        // [A-Za-z0-9._:-]), so a broken static value is refused at compile
        // time instead of 422-ing every challenge request.
        $staticBinding = $config['risk']['request_binding'];
        if ($staticBinding !== null && !preg_match('/^[A-Za-z0-9._:-]{1,128}$/D', $staticBinding)) {
            throw new \InvalidArgumentException(
                'kiwi_captcha.risk.request_binding must be 1-128 characters of [A-Za-z0-9._:-]'
            );
        }

        // The optional Ed25519 receipt-signing seed must be a base64
        // 32-byte Ed25519 seed, refused at compile time instead of failing
        // on the first valid verification.
        $receiptSeed = $config['risk']['result_receipt_signing_key'];
        if ($receiptSeed !== null && $receiptSeed !== '') {
            $decodedSeed = base64_decode($receiptSeed, true);
            if ($decodedSeed === false || \strlen($decodedSeed) !== 32) {
                throw new \InvalidArgumentException(
                    'kiwi_captcha.risk.result_receipt_signing_key must be a base64-encoded 32-byte Ed25519 seed'
                );
            }
        }
        // The trusted TLS header name must be a plain HTTP header name
        // (letters, digits, hyphens); anything else is a broken config
        // refused at compile time instead of a per-request lookup probe.
        $trustedTlsHeader = $config['risk']['trusted_tls_header'];
        if ($trustedTlsHeader !== null && preg_match('/^[A-Za-z0-9-]{1,64}$/D', $trustedTlsHeader) !== 1) {
            throw new \InvalidArgumentException(
                'kiwi_captcha.risk.trusted_tls_header must be a valid HTTP header name (1-64 characters of [A-Za-z0-9-])'
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

        // Production never derives the expected origin from an arbitrary
        // Host header. When same_origin_only (the default) is active in a
        // production environment, public_base_url is required, so the
        // config trap (falling back to request Host) becomes a boot
        // error. A Symfony %env()% placeholder is accepted here: the
        // container resolves it at compile/runtime, and the resolved
        // value receives the identical validation from the runtime lane
        // (ExpectedOrigin::fromPublicBaseUrl) when the controller is
        // constructed — the placeholder itself is opaque at build time.
        $environment = $this->environment($container);
        if (\in_array($environment, ['test', 'dev'], true) === false
            && ($config['same_origin_only'] || $config['risk']['enforce_origin'] || ($config['risk']['siteverify_secrets'] ?? []) !== [])
        ) {
            $this->requireProductionPublicBaseUrl($config['public_base_url'], $environment);
        }
        // The canonical-HTTPS origin contract is one validator with two
        // lanes, both fail-closed. A literal value is validated here at
        // container build time in every environment (test/dev included):
        // the runtime guard would refuse a broken literal at controller
        // construction anyway, so the build fails early with the
        // actionable message. An env-resolved value skips this lane and
        // is validated by the exact same contract
        // (ExpectedOrigin::publicBaseUrlViolation) when the ExpectedOrigin
        // service is constructed at runtime, never reaching the
        // controller unvalidated.
        if ($config['public_base_url'] !== null && !self::isEnvPlaceholder($config['public_base_url'])) {
            $violation = ExpectedOrigin::publicBaseUrlViolation($config['public_base_url']);
            if ($violation !== null) {
                throw new \LogicException(sprintf(
                    'KiwiCaptcha: public_base_url %s — a literal value is validated at container build time; an env-managed value is validated with the same canonical-HTTPS contract when the challenge controller is constructed.',
                    $violation,
                ));
            }
        }

        // The runtime authority-transition guard: the authoritative
        // fail_closed enforcement point (docs/ha-authority.md). The
        // guard is constructed with the replay_durability posture — a
        // %env()% placeholder is resolved by the container when the
        // guard is constructed, so an env-derived posture is enforced
        // here, exactly where the build-time lanes cannot see it. The
        // checked-client wrappers below run this guard on the actual
        // client instance at every Redis-backed service construction.
        // The compile-time lanes stay (early UX) but are explicitly
        // non-authoritative: they inspect definition shapes and cannot
        // classify an env-resolved posture or an opaque construction.
        $container->setDefinition(self::AUTHORITY_GUARD_ID, (new Definition(RuntimeAuthorityClassifier::class, [$config['replay_durability']]))->setPublic(true));

        // redis_dsn is the high-level Redis connection setting: when set
        // (and the corresponding explicit service-id knob is NOT set),
        // the extension constructs the Redis-backed services itself from
        // the DSN — the challenge storage (RedisStorage), the distributed
        // rate limiter, the Argon admission and the risk state. An
        // explicit service id always wins over the DSN for its knob:
        // `storage` (a custom StorageInterface service), `redis_service`
        // (a custom client for the limiter/semaphore) and
        // `risk.redis_service` (a custom Predis client for the risk
        // state) keep their documented precedence. The DSN client is a
        // Predis\Client, the same client family the risk engine requires,
        // so one connection drives every Redis-backed service.
        $dsnClientRef = null;
        if ($config['redis_dsn'] !== null) {
            $dsnClientRef = $this->buildDsnRedisClient((string) $config['redis_dsn'], $container);
        }
        $storageExplicitlySet = self::configLayerDefines($configs, 'storage');
        if ($dsnClientRef !== null && !$storageExplicitlySet) {
            // The DSN-built challenge storage: the ordinary production
            // deployment needs no storage service wiring at all. The
            // client rides the checked-client seam, so the storage's
            // construction runs the runtime guard on the actual client.
            $container->setDefinition(self::DSN_STORAGE_ID, new Definition(RedisStorage::class, [$this->checkedRedisClientRef($dsnClientRef, '', $container)]));
            $storageRef = new Reference(self::DSN_STORAGE_ID);
            $storageId = self::DSN_STORAGE_ID;
        } else {
            $storageRef = $this->resolveStorage($config['storage'], $this->environment($container), $container);
            $storageId = $config['storage'];
        }
        $this->requireAtomicStorageWhenNeeded(
            $storageRef,
            $storageId,
            $this->environment($container),
            (bool) ($config['allow_best_effort_storage'] ?? false),
            $config['risk']['siteverify_secrets'] ?? [],
            $container,
        );
        // The raw client reference feeds the build-time classification
        // lanes (definition-shape checks) and the risk client reuse
        // decision; the checked reference feeds every consumer, so each
        // Redis-backed service construction runs the runtime guard on
        // the actual instance. The two never diverge at runtime: the
        // checked wrapper returns the raw client unchanged after the
        // guard passes.
        $rawRedisRef = null;
        if ($dsnClientRef !== null && $config['redis_service'] === null) {
            // No explicit client service id: the DSN client drives the
            // distributed rate limiter and the Argon admission.
            $rawRedisRef = $dsnClientRef;
            $redisRef = $this->checkedRedisClientRef($dsnClientRef, '', $container);
        } else {
            $rawRedisRef = $this->resolveRedisClient((string) $storageRef, $config['redis_service'], $container);
            $redisRef = $this->checkedRedisClientRef($rawRedisRef, '', $container);
        }

        // Hard distributed-resource semantics (the architectural
        // invariant): a deployment claiming a temporal issuance limit
        // (per-client or global) or a bounded Argon admission ceiling
        // must not silently fall back to a process-local limiter or
        // gate, since the aggregate of N workers could otherwise
        // approach N times the configured ceiling. In production the
        // container refuses the combination unless the operator
        // explicitly names the fallback. A configured rate_limit_cache
        // (a shared PSR-6 pool service id) counts as a cross-request
        // backend, so the temporal-limit guard passes when it is set.
        $environment = $this->environment($container);
        if (!\in_array($environment, ['test', 'dev'], true)) {
            // The non-Redis rate-limit fallback flag now covers ANY
            // temporal issuance limit (per-client and global). The
            // deprecated allow_local_global_limit_fallback alias still
            // enables the same fallback (documented alias).
            $nonRedisRateLimitFallback = (bool) ($config['allow_nonredis_rate_limit_fallback'] ?? false)
                || (bool) ($config['allow_local_global_limit_fallback'] ?? false);
            if (($config['rate_limit'] > 0 || $config['rate_limit_global'] > 0)
                && $redisRef === null
                && ($config['rate_limit_cache'] ?? null) === null
                && !$nonRedisRateLimitFallback
            ) {
                throw new \LogicException(sprintf(
                    'kiwi_captcha: rate_limit=%d and rate_limit_global=%d are temporal issuance limits, but no Redis client is wired and no rate_limit_cache PSR-6 pool is configured — the limiter would enforce them as weaker object-memory windows, not exact distributed gates: the object-memory fallback is long-lived-runtime-only (a persistent worker such as RoadRunner/Swoole/amphp, or a single CLI process) and under conventional PHP-FPM each request rebuilds the limiter, so the per-client and the global window provide no cross-request protection at all; a shared PSR-6 pool is cross-request best-effort but cannot make the windows atomic under concurrent requests, so races may briefly exceed the caps. Production temporal limiting requires Redis (redis_service) or a genuinely persistent or shared PSR-6 pool (rate_limit_cache); to accept the weaker semantics, explicitly set allow_nonredis_rate_limit_fallback: true.',
                    $config['rate_limit'],
                    $config['rate_limit_global'],
                ));
            }
            if ($config['argon2_max_concurrent_verifications'] > 0 && $redisRef === null && !$config['allow_local_argon_admission_fallback']) {
                throw new \LogicException(sprintf(
                    'kiwi_captcha: argon2_max_concurrent_verifications=%d is a deployment-wide Argon admission ceiling, but no Redis client is wired — the admission would silently fall back to the in-process gate, so the aggregate of N workers could approach N x %d concurrent Argon verifications. Wire redis_service or explicitly set allow_local_argon_admission_fallback: true to accept the weaker semantics.',
                    $config['argon2_max_concurrent_verifications'],
                    $config['argon2_max_concurrent_verifications'],
                ));
            }
            // A "configured" rate_limit_cache pool cannot be proven
            // cross-worker: Symfony's in-memory ArrayAdapter keeps its
            // items per process, so under PHP-FPM the guard above would
            // pass while the rate-limit state is request-local. When the
            // pool's class resolves at extension time (through parameter
            // placeholders in the service id, full alias chains and
            // %param%-class definitions — see definitionClass()) and is
            // (a subclass of) ArrayAdapter, refuse in production — but
            // only when the pool is the effective limiter backend: with a
            // Redis client wired the atomic distributed limiter wins and
            // the pool is never selected, and with both temporal limits
            // disabled the limiter is not wired at all, so an
            // in-memory pool is harmless in both cases. A pool id that
            // still cannot be resolved to a class after all that fails
            // closed exactly like the storage path's unresolvable-class
            // refusal: an uninspectable pool cannot be proven shared, so
            // production refuses the combination and asks for a concrete
            // pool service id.
            if (($config['rate_limit_cache'] ?? null) !== null
                && $redisRef === null
                && ($config['rate_limit'] > 0 || $config['rate_limit_global'] > 0)
            ) {
                $poolClass = $this->definitionClass($config['rate_limit_cache'], $container);
                if ($poolClass !== null && \is_a($poolClass, ArrayAdapter::class, true)) {
                    throw new \LogicException(sprintf(
                        'kiwi_captcha.rate_limit_cache ("%s", class %s) is an in-memory adapter (Symfony\Cache\Adapter\ArrayAdapter or a subclass): its items live per process, so it cannot be a shared cross-worker rate-limit pool under PHP-FPM. Use a genuinely shared pool (e.g. a Redis-backed Symfony Cache pool such as RedisAdapter) or leave rate_limit_cache unset and accept the object-memory semantics (long-lived-runtime-only).',
                        $config['rate_limit_cache'],
                        $poolClass,
                    ));
                }
                if ($poolClass === null) {
                    throw new \LogicException(sprintf(
                        'kiwi_captcha.rate_limit_cache ("%s") cannot be resolved to a service class, so the production pool guard fails closed (an uninspectable pool cannot be proven cross-worker, exactly like the storage path\'s unresolvable-class refusal). Reference a concrete pool service id whose class is visible to the extension: the id may carry %%parameter%% placeholders and alias hops, but they must resolve to a real definition whose class (literal or %%param%%) is resolvable here. An external pool service the extension cannot see must be aliased or defined before this bundle loads.',
                        $config['rate_limit_cache'],
                    ));
                }
            }
        }

        // The risk.redis knobs (wait_replicas / wait_timeout_ms /
        // ttl_margin_secs) harden the challenge storage when it is a
        // KiwiCaptcha\Storage\RedisStorage definition: WAIT for replica
        // acknowledgment after storing a challenge (async-replication
        // failover can otherwise lose the record and let a re-solved token
        // replay against a "fresh" record after failback), and extra
        // retention on challenge/replay-security state beyond token
        // validity. Applied only when the knobs are non-default, so
        // deployments on older cores (or without a RedisStorage
        // definition) are untouched.
        $this->applyRedisStorageHardening($storageRef, $config['risk']['redis'], $container);

        // Verified core (kiwicaptcha/kiwicaptcha-php): Config, Issuer, Verifier.
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
            // The security-policy epoch (risk.policy_version) is
            // stamped into every issued challenge record.
            ->setArgument('$policyVersion', $config['risk']['policy_version'])
            // Deployment issuer + signing key id are first-class bundle
            // options (HMAC-key rotation control), so the core's strongest
            // identity and key controls are reachable without replacing
            // services.
            ->setArgument('$issuer', $config['issuer'])
            ->setArgument('$kid', $config['kid'])
            // The ExecutionChallengeV1 keyed-PRF key (null = the
            // dimension is never issued). The gate on without a key is
            // refused below, so an armed deployment always carries the
            // key.
            ->setArgument('$executionKey', $config['execution_key'])
            ->setPublic(true);
        $container->setDefinition('kiwi_captcha.config', $configDef);

        $container->setDefinition('kiwi_captcha.issuer', (new Definition(Issuer::class, [
            new Reference('kiwi_captcha.config'),
            $storageRef,
        ]))->setPublic(true));

        // risk.region is baked into every issued challenge record and
        // enforced at verification, so a result token issued in one region
        // is never redeemable elsewhere. Set only when configured (the
        // core's $region param is optional), so deployments without the
        // parameter are untouched.
        if ($config['risk']['region'] !== null) {
            $container->getDefinition('kiwi_captcha.issuer')
                ->setArgument('$region', $config['risk']['region']);
        }

        // Verifier: the core now takes the Argon2id admission gate natively
        // (VerificationAdmissionGate, consulted only when the stored record
        // is Argon2id and only after the cheap checks). Admission is
        // enforced against Redis (across all PHP-FPM workers, tokenized
        // leases) when a Redis client is available, and falls back to the
        // in-process token-set gate (per-process only).
        // The gate is created whenever the concurrency cap is > 0,
        // regardless of the locally configured issuance algorithm. The
        // core verifier consults the gate based on the stored record's
        // algorithm, and the project supports Rust/PHP interoperable
        // records in shared storage: a Symfony service issuing SHA
        // challenges may still receive a solution for an Argon record
        // written by a Rust service. There is no cost for SHA
        // verifications, since the gate is never consulted unless the
        // record actually says Argon2id.
        $gateRef = null;
        if ($config['argon2_max_concurrent_verifications'] > 0) {
            // Effective per-scope concentration cap: the explicitly
            // configured value, or derived from the global cap when unset
            // as max(1, global - 1), so one scope can never monopolize the
            // shared slots. The config tree refuses explicit values at or
            // above the global cap; with the default global cap of 2 the
            // derived default is 1. The semaphore is only wired when the
            // global cap is positive, so the derived value is always >= 1.
            $perTenantCap = $config['argon2_max_per_tenant']
                ?? ($config['argon2_max_concurrent_verifications'] > 0
                    ? max(1, $config['argon2_max_concurrent_verifications'] - 1)
                    : null);
            // The bounded saturation-pressure counter: the canonical name
            // argon2_saturation_pressure_cap wins, the deprecated
            // argon2_max_waiters alias still wires the same value (OR
            // semantics like the allow_nonredis_rate_limit_fallback flag).
            $saturationPressureCap = $config['argon2_saturation_pressure_cap'] ?? $config['argon2_max_waiters'];
            if ($redisRef !== null) {
                $container->setDefinition(
                    'kiwi_captcha.argon2_redis_semaphore',
                    (new Definition(RedisAdmissionSemaphore::class, [
                        $redisRef,
                        $config['argon2_max_concurrent_verifications'],
                        $config['argon2_semaphore_namespace'],
                        $config['argon2_lease_ms'],
                        $saturationPressureCap,
                        // Per-scope concentration cap (argon2_max_per_tenant,
                        // resolved above): the semaphore checks the scope's
                        // own lease set in addition to the global cap.
                        $perTenantCap,
                    ]))->setPublic(true),
                );
                // The verifier consumes the gate through the
                // request-scope-aware wrapper: the validator stamps the
                // constraint scope into the request and the wrapper
                // forwards it into acquire(), so the per-scope budget
                // engages on top of the global cap. The raw semaphore
                // stays public for the resource-pressure provider (usage
                // is global either way).
                $container->setDefinition('kiwi_captcha.argon2_scope_gate', (new Definition(RequestScopeAdmissionGate::class, [
                    new Reference('kiwi_captcha.argon2_redis_semaphore'),
                    new Reference('request_stack'),
                ]))->setPublic(true));
                $gateRef = new Reference('kiwi_captcha.argon2_scope_gate');
            } else {
                $container->setDefinition('kiwi_captcha.argon2_inprocess_gate', (new Definition(InProcessArgonGate::class, [
                    $config['argon2_max_concurrent_verifications'],
                ]))->setPublic(true));
                $gateRef = new Reference('kiwi_captcha.argon2_inprocess_gate');
            }
        }
        // The effective verification keyring (single source of truth):
        // the historical secrets_by_kid map merged with the current
        // signing key (kid => secret_key), numerically sorted. The core
        // verifier resolves every record's kid against this ring, so an
        // outstanding challenge signed under a superseded kid still
        // verifies (rotation grace), a freshly issued challenge resolves
        // the current secret, and the core's rollback/forward guard
        // (record kid above the newest ring key) still rejects future
        // keys. The same context feeds the Siteverify security-context
        // digest below, so the wired keyring and the digested keyring
        // can never diverge. With an empty historical map the ring stays
        // empty and the core's legacy single-secret path is untouched.
        $securityContext = new VerificationSecurityContext(
            $config['kid'],
            $config['secret_key'],
            $config['secrets_by_kid'],
            $config['revoked_kids'],
            $config['issuer'],
            $config['risk']['region'],
            $config['strict_kid_verification'],
        );

        $container->setDefinition('kiwi_captcha.verifier', (new Definition(Verifier::class, [
            $storageRef,
            $gateRef,
        ]))
            // The verifier's expected security-policy epoch: a record
            // issued under any other epoch is rejected (WrongPolicyVersion),
            // so bumping risk.policy_version invalidates outstanding
            // challenges immediately.
            ->setArgument('$expectedPolicyVersion', $config['risk']['policy_version'])
            // HMAC-key rotation (secretsByKid), emergency revocation
            // (revokedKids) and the expected issuer are first-class bundle
            // options. secretsByKid receives the effective keyring from
            // VerificationSecurityContext: the historical map plus the
            // current signing key, so freshly issued challenges (stamped
            // with the current kid) resolve the current secret even while
            // historical secrets are configured.
            ->setArgument('$expectedIssuer', $config['issuer'])
            ->setArgument('$secretsByKid', $securityContext->acceptedKeys())
            ->setArgument('$revokedKids', $config['revoked_kids'])
            ->setPublic(true));
        // The recovery-claim derivation TTL (resume_claim_ttl_secs) is
        // wired by name ($resumeClaimTtlSecs) when the installed core's
        // Verifier declares the parameter (a core addition);
        // an older core simply keeps its constructor default. The guard
        // exists because Symfony's ResolveNamedArgumentsPass refuses a
        // named argument the class does not declare at container compile
        // time, so the wiring must follow the installed core.
        if (self::coreVerifierAcceptsResumeClaimTtlSecs()) {
            $container->getDefinition('kiwi_captcha.verifier')
                ->setArgument('$resumeClaimTtlSecs', $config['resume_claim_ttl_secs']);
        }
        if ($config['risk']['region'] !== null) {
            $container->getDefinition('kiwi_captcha.verifier')
                ->setArgument('$region', $config['risk']['region']);
        }
        $container->setAlias(StorageInterface::class, (string) $storageRef);

        // Challenge endpoint controller (+ issuance rate limiter). The
        // limiter is wired whenever either limit is nonzero (defaults are
        // 10 per-client / 500 global). With a Redis client the atomic
        // sliding-window backend enforces both caps across all workers;
        // without one it falls back to the shared PSR-6 pool
        // (rate_limit_cache) or the in-memory window (best-effort, single
        // worker).
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

        // Adaptive risk engine (kiwicaptcha/kiwicaptcha-risk-php), off by
        // default. When enabled, a Predis\Client is required for the
        // canonical risk-v1 state script (risk.redis_service, or the
        // bundle's own Redis client when it is a Predis client), failing
        // fast at compile time otherwise. The engine runs pre-issue
        // (decide difficulty or deny), records issuances, and receives
        // post-solve outcome feedback from the validator.
        // A logger (when the app has one) receives the risk gateway's
        // internal diagnostics and the validator's collapsed-verification
        // detail, resolved once and used by both.
        $loggerRef = $container->hasDefinition('logger') || $container->hasAlias('logger')
            ? new Reference('logger')
            : null;
        $riskConfig = $config['risk'];
        $riskGatewayRef = null;
        $riskCookieRef = null;
        $issuanceCounterRef = null;
        $outstandingRef = null;
        $chainServiceRef = null;
        $chainStoreRef = null;
        $bindingAuthorityRef = $riskConfig['request_binding_authority'] !== null
            ? new Reference($riskConfig['request_binding_authority'])
            : null;
        $riskResolverRef = null;
        $riskRedis = null;
        $riskRedisRaw = null;
        if ($riskConfig['enabled']) {
            // Ladder validation (defense in depth; the config tree refuses
            // the same shape at compile time): the argon escalation ladder
            // must satisfy 1 <= rung1 < rung2 < rung3 <=
            // Config::MAX_ARGON2_TARGET_BITS. A non-monotone or
            // out-of-range ladder is a configuration error, never silently
            // accepted.
            $argonLadder = $riskConfig['argon_escalation_target_bits'];
            if (\count($argonLadder) !== 3
                || $argonLadder[0] < 1
                || $argonLadder[0] >= $argonLadder[1]
                || $argonLadder[1] >= $argonLadder[2]
                || $argonLadder[2] > Config::MAX_ARGON2_TARGET_BITS
            ) {
                throw new \InvalidArgumentException(sprintf(
                    'kiwi_captcha.risk.argon_escalation_target_bits must satisfy 1 <= rung1 < rung2 < rung3 <= %d (the Argon16/32/64 ladder, bounded by Config::MAX_ARGON2_TARGET_BITS)',
                    Config::MAX_ARGON2_TARGET_BITS,
                ));
            }
            [$policyConfig, $scopeIds, $postSolveScopes, $unknownScopeId] = $this->buildRiskPolicy($riskConfig);
            // The risk client rides the same checked-client seam: the
            // raw reference feeds the reuse/class decisions (a checked
            // wrapper definition has no inspectable class), the checked
            // reference feeds every risk consumer so their construction
            // runs the runtime guard on the actual client.
            $riskRedisRaw = $this->resolveRiskRedisClient($riskConfig, $rawRedisRef, $container);
            $riskRedis = $this->checkedRedisClientRef($riskRedisRaw, 'risk', $container);
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
            // session signal must never outlive the cookie that carries
            // it.
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
                ->setArgument('$saturations', $riskConfig['saturations'])
                ->setArgument('$outcomeTtlSecs', $riskConfig['calibration']['outcome_receipt_ttl_secs']));
            $container->setDefinition('kiwi_captcha.risk.metrics', new Definition(RiskMetrics::class));

            // In-process emergency limiter (cheap admission before the
            // risk engine): one honest per-process window from
            // hard_limits.process_per_second, checked by
            // assessPreIssue() once before any state backend (per-source
            // throttling belongs to the distributed keyed layer). The
            // controller also consults it via the gateway before the Redis
            // issuance limiter, non-consuming, so the engine stays the
            // single budget consumer.
            $container->setDefinition('kiwi_captcha.risk.emergency_limiter', new Definition(ProcessEmergencyCap::class, [
                $riskConfig['hard_limits']['process_per_second'],
            ]));

            // Redis-backed aggregate calibration (score-bucket statistics,
            // no identity): adjusts only the per-scope bias, bounded by
            // the configured min_samples / max_adjustment /
            // max_change_per_minute knobs. The outcome/calibration
            // receipt and outcome-ledger lifetime is passed through
            // (outcome_receipt_ttl_secs; the short-lived nonce->decision
            // handles use risk.nonce_to_decision_ttl_secs instead), and
            // the label-selection contract (calibration.mode +
            // sampling_probability_ppm) goes to the calibrator's sampling
            // knobs. Receipts are keyed on decision ids, so the same
            // Predis client + namespace as the risk state store keeps
            // every calibration key in one hash-tag family.
            $calibrationRef = null;
            if ($riskConfig['calibration']['enabled']) {
                $container->setDefinition('kiwi_captcha.risk.calibration', (new Definition(AggregateCalibrator::class, [
                    $riskRedis,
                    $namespace,
                    $riskConfig['calibration']['min_samples'],
                    $riskConfig['calibration']['max_adjustment'],
                    $riskConfig['calibration']['max_change_per_minute'],
                    $riskConfig['calibration']['outcome_receipt_ttl_secs'],
                ]))
                    ->setArgument('$samplingMode', $riskConfig['calibration']['mode'])
                    ->setArgument('$samplingProbabilityPpm', $riskConfig['calibration']['sampling_probability_ppm'])
                    ->setArgument('$minimumResolutionRatio', $riskConfig['calibration']['minimum_resolution_ratio'])
                    ->setArgument('$falsePositiveCost', $riskConfig['calibration']['false_positive_cost'])
                    ->setArgument('$falseNegativeCost', $riskConfig['calibration']['false_negative_cost'])
                    ->setArgument('$outcomeTtlSecs', $riskConfig['calibration']['outcome_receipt_ttl_secs'])
                    ->setArgument('$scopeHmacKey', AggregateCalibrator::deriveScopeHmacKey($riskMaster)));
                $calibrationRef = new Reference('kiwi_captcha.risk.calibration');
            }

            // Shared circuit breaker: the engine records every store
            // success/failure on it and consumes its state for the
            // degraded mode (backend unavailable -> the policy's degraded
            // action). No per-request PING; the breaker state is the
            // last-operation result.
            $container->setDefinition('kiwi_captcha.risk.breaker', new Definition(CircuitBreaker::class));

            // The engine is public so applications can read risk metrics
            // (RiskGateway::metricsSnapshot) or record their own
            // confirmed-legitimate/abuse signals. The trailing parameters
            // are passed by name against the final package contract
            // (principalTtlSecs, saturations, calibration) so their
            // position in the constructor cannot drift from this wiring.
            // The session TTL lives on the state store, the per-process
            // emergency cap on the limiter, both wired above.
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
                // The fixed Argon2id verification-memory envelope
                // (risk.argon_verification_memory_kib) and the target-bits
                // escalation ladder: risk escalates the expected nonce
                // search space, never the server verification cost.
                $riskConfig['argon_verification_memory_kib'],
                $riskConfig['argon_escalation_target_bits'],
            ]));
            $riskResolverRef = new Reference('kiwi_captcha.risk.resolver');

            // Atomic issuance-rate signal: the controller increments
            // {kiwi:<ns>}:issuance:<second> (INCR + EXPIRE 1) on every
            // minted challenge; the resource-pressure provider reads it
            // for the real issuanceCapacity headroom.
            $issuanceKeyPrefix = sprintf('{kiwi:%s}:issuance:', $namespace);
            $container->setDefinition('kiwi_captcha.risk.issuance_counter', new Definition(IssuanceCounter::class, [
                $riskRedis,
                $issuanceKeyPrefix,
            ]));
            $issuanceCounterRef = new Reference('kiwi_captcha.risk.issuance_counter');

            // Anti-stockpiling: bounded outstanding unsolved challenges per
            // source + deployment-wide. The accounting is an expiry-aware
            // membership, not a counter: one atomic Lua prunes expired
            // members and checks both caps against the live memberships
            // ({kiwi:<ns>}:outstanding:<hex> — the per-source ZSET, the
            // source identity is HMAC(canonical ip, RiskKeys::event), so
            // the raw IP never appears in Redis — and
            // {kiwi:<ns>}:outstanding:global:live), scores each member at
            // its Redis-clock deadline (Redis TIME + the relative
            // challenge lifetime, which includes the verifier's permitted
            // future-issuance skew), EXPIREATs both keys at the latest
            // member deadline + risk.redis.ttl_margin_secs, and applies
            // the configured replica-durability barrier to a successful
            // admission. The controller refuses issuance with the 429
            // risk-denied response when a cap is reached; a successful
            // verification, a client cancellation or a
            // proven-not-handed-off issuance removes the nonce from both
            // memberships (one-shot, nonce-authoritative).
            $container->setDefinition('kiwi_captcha.risk.outstanding', new Definition(OutstandingChallenges::class, [
                $riskRedis,
                sprintf('{kiwi:%s}:outstanding:', $namespace),
                new Reference('kiwi_captcha.risk.keys'),
                $riskConfig['max_outstanding_challenges'],
                $riskConfig['max_outstanding_challenges_global'],
                $riskConfig['redis']['ttl_margin_secs'],
                // The risk.redis replica-durability knobs
                // (wait_replicas / wait_timeout_ms) flow into the
                // outstanding admission too, the same knobs that harden
                // the challenge storage: a successful admission write
                // (the source/global memberships + the sidecar) WAITs for
                // the configured replica count before the challenge is
                // handed out, so a promotion can never resurrect a
                // valid-but-unaccounted challenge record (asymmetric
                // failover would otherwise let redemptions exceed the
                // hard outstanding caps).
                $riskConfig['redis']['wait_replicas'],
                $riskConfig['redis']['wait_timeout_ms'],
            ]));
            $outstandingRef = new Reference('kiwi_captcha.risk.outstanding');

            // Live resource pressure: remaining Redis admission-semaphore
            // slots (argon_capacity.enabled gate) and real per-second
            // issuance headroom as the remaining fraction of the
            // deployment-wide resource_capacity.issuance_per_second
            // (fixed-point 0..1000). hard_limits.process_per_second is
            // not the denominator: it stays exclusively on the per-process
            // emergency limiter above. Risk backend health is not a
            // snapshot field anymore, since the engine's degraded mode
            // consumes the shared circuit breaker directly. Unobservable
            // sources stay nominal (1000) for issuance, conservative 0
            // for the argon gate.
            $container->setDefinition('kiwi_captcha.risk.resource_pressure', new Definition(RedisRiskHealthProvider::class, [
                $riskConfig['argon_capacity']['enabled']
                    ? ($container->hasDefinition('kiwi_captcha.argon2_redis_semaphore')
                        ? new Reference('kiwi_captcha.argon2_redis_semaphore')
                        : null)
                    : null,
                $riskRedis,
                $issuanceKeyPrefix,
                $config['resource_capacity']['issuance_per_second'],
            ]));
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
                ->setArgument('$decisionTtlSecs', $riskConfig['nonce_to_decision_ttl_secs'])
                ->setArgument('$calibration', $calibrationRef)
                ->setArgument('$policy', new Reference('kiwi_captcha.risk.policy'))
                // The controller's cheap local admission step
                // (RiskGateway::emergencyCapSaturated): the process-local
                // window checked before any Redis issuance limiter.
                ->setArgument('$emergencyCap', new Reference('kiwi_captcha.risk.emergency_limiter'))
                // The operator-tunable risk-v2 additive evidence weights
                // (risk.v2.*; the values default to the contract
                // defaults, so an unset config scores identically).
                ->setArgument('$v2Weights', new Reference('kiwi_captcha.risk.v2_weights'))
                ->setPublic(true));
            $container->setDefinition('kiwi_captcha.risk.v2_weights', (new Definition(RiskV2Weights::class))
                ->setArgument('$honeypot', $riskConfig['v2']['honeypot_weight'])
                ->setArgument('$sessionInconsistency', $riskConfig['v2']['session_consistency_weight'])
                ->setArgument('$tls', $riskConfig['v2']['tls_weight']));
            if ($container->has(PrincipalResolverInterface::class)) {
                // An application-registered principal resolver is opt-in:
                // when a service for the interface exists, the raw
                // principal of each request flows into every engine
                // context (the engine HMAC-pseudonymizes it before Redis
                // storage).
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

            // Selective chained challenges (risk.chaining). The chain
            // ticket service signs the minimal one-shot chain ticket
            // ({version, chainId, expiresAt}; the full server-held state
            // {stage1Nonce, scope, requestBinding, requiredAction,
            // requiredRank, policyVersion, chainDepth} lives in the state
            // store) with the chain HMAC secret (risk.chaining.hmac_secret,
            // falling back to the risk master_secret and then the captcha
            // secret_key, the same secret-generation defaults as the
            // other risk secrets). The chain is a server-side transaction
            // obligation: the server-held chain state rides the risk
            // namespace ({kiwi:<ns>}:chain:<chainId> plus its obligation
            // mapping {kiwi:<ns>}:chain-obligation:<obligationId>, TTL =
            // chain ttl, same hash tag), Redis-backed when a Redis client
            // is available, in-memory otherwise (test/dev semantics,
            // mirroring the idempotency store wiring). The service is
            // wired with the short reservation lease
            // (risk.chaining.reservation_lease_secs) and the deployment's
            // authoritative transaction-binding resolver
            // (risk.request_binding_authority, required for chaining: the
            // chain anchor is the authoritative binding, never an
            // unexamined client string).
            if ($riskConfig['chaining']['enabled']) {
                // Compile-time refusal (defense in depth; the config tree
                // refuses the same combinations): chaining requires the
                // binding authority (a chain without an authoritative
                // binding anchor cannot be a server-side transaction
                // obligation), and the short reservation lease must be
                // strictly smaller than the chain lifetime.
                if ($bindingAuthorityRef === null) {
                    throw new \InvalidArgumentException('kiwi_captcha.risk.chaining.enabled requires risk.enabled=true AND a non-null risk.request_binding_authority (the authoritative transaction-binding resolver)');
                }
                if ($riskConfig['chaining']['reservation_lease_secs'] >= $riskConfig['chaining']['ttl_secs']) {
                    throw new \InvalidArgumentException('kiwi_captcha.risk.chaining.reservation_lease_secs must be strictly smaller than risk.chaining.ttl_secs — the reservation lease is a SHORT claim, never the chain lifetime');
                }
                $chainStoreRedis = $riskRedis ?? $redisRef;
                if ($chainStoreRedis !== null) {
                    // The risk.redis replica-durability knobs
                    // (wait_replicas / wait_timeout_ms) flow into the
                    // Redis chain state store, the same knobs that harden
                    // the challenge storage: every fresh mutating chain
                    // transition WAITs for the configured replica count
                    // before the caller learns success (a returned
                    // Deny/StepUp must survive a promotion).
                    $container->setDefinition(RedisChainedChallengeStateStore::class, new Definition(RedisChainedChallengeStateStore::class, [
                        $chainStoreRedis,
                        $namespace,
                        $riskConfig['redis']['wait_replicas'],
                        $riskConfig['redis']['wait_timeout_ms'],
                    ]));
                    $chainStoreRef = new Reference(RedisChainedChallengeStateStore::class);
                } else {
                    $container->setDefinition(ArrayChainedChallengeStateStore::class, new Definition(ArrayChainedChallengeStateStore::class, []));
                    $chainStoreRef = new Reference(ArrayChainedChallengeStateStore::class);
                }
                $container->setDefinition(ChainedChallengeTicketService::class, (new Definition(ChainedChallengeTicketService::class, [
                    $chainStoreRef,
                    $riskConfig['chaining']['hmac_secret'] ?? $riskConfig['master_secret'] ?? $config['secret_key'],
                    $riskConfig['chaining']['ttl_secs'],
                    $riskConfig['chaining']['reservation_lease_secs'],
                ]))
                    ->setArgument('$bindingAuthority', $bindingAuthorityRef)
                    ->setPublic(true));
                $chainServiceRef = new Reference(ChainedChallengeTicketService::class);
            }
        }
        // The replay_durability posture is the explicit authority-change
        // contract (docs/redis-topologies.md, docs/ha-authority.md). Under
        // fail_closed the deployment refuses to rely on automatic failover:
        // a Predis Sentinel or Cluster aggregate client routes commands
        // through promotion machinery, so the bundle refuses the container
        // build here, with the posture named and the remediation options.
        // Single-node direct clients are fine under every posture.
        //
        // This lane is early UX only, never the boundary: it classifies
        // definition shapes, and an env-resolved posture (which skips
        // the literal comparison) or an opaque client construction
        // (which the shape walk cannot inspect) is invisible to it. The
        // runtime authority-transition guard wired above is the
        // authoritative lane: it runs on the actual constructed client
        // at service construction with the resolved posture, so the
        // invariant holds in every wiring path.
        if ($config['replay_durability'] === 'fail_closed') {
            $aggregate = $this->predisAggregateLabel($rawRedisRef, $container, 'the storage/limiter Redis client')
                ?? $this->predisAggregateLabel($riskRedisRaw, $container, 'the risk Redis client');
            if ($aggregate !== null) {
                throw new \LogicException(self::failClosedRefusalMessage($aggregate));
            }
        }
        // The client of an application-defined RedisStorage rides the
        // checked-client seam too: the durability-critical
        // pending->consumed transition lives in RedisStorage, so under
        // fail_closed its own client must be classified at storage
        // construction. The DSN-built storage already carries the
        // checked client; this patch covers a storage service the
        // application defines (visible in unit containers here, on the
        // real container in prepend()).
        $this->guardStorageClientByStorageValue($config['storage'], $container);
        // The ha_authority posture wires the mechanical pinned-primary
        // guard (docs/ha-authority.md): the storage/limiter/risk client
        // is decorated with the authority guard wrapper, so every
        // durability-critical command is preceded by the pin check —
        // the deployment can choose a mechanically enforced
        // replay-safe HA mode instead of trusting the operator alone.
        // Under "none" (the default) nothing is wired and the current
        // boundary stays byte-identical. One guard and one pin are
        // wired per distinct Redis authority: the storage/limiter
        // authority (`{kiwi:<ns>}:authority:pin:storage`) and a
        // distinct risk authority (`{kiwi:<ns>}:authority:pin:risk`);
        // a risk client that IS the storage client shares the storage
        // guard and pin.
        $authorityGuardRefs = [];
        if ($config['ha_authority'] === 'pinned_primary') {
            $authorityGuardRefs = $this->wirePinnedPrimaryAuthorityGuard($config, $redisRef, $riskRedis, $container);
        }
        // Trusted client-IP policy, wired unconditionally (not gated on
        // risk.enabled): the canonical client IP feeds the challenge
        // binding tag, the rate-limit identity and the risk source
        // pseudonym, so the controller and the validator must agree on it
        // in every deployment mode.
        $container->setDefinition(ClientIpResolver::class, (new Definition(ClientIpResolver::class, [
            $config['risk']['client_ip_mode'],
            $config['risk']['trusted_proxies'],
            $config['risk']['reject_ambiguous_forwarding'],
        ]))
            ->setArgument('$logger', $loggerRef)
            ->setPublic(true));

        // Security-epoch monitor, wired unconditionally (not gated on
        // risk.enabled, since the central security-policy state exists
        // independently of the adaptive engine): reads
        // `{kiwi:<ns>}:security-policy`'s min_policy_epoch with a short
        // cache (risk.security_epoch_cache_secs), keeps a monotonic
        // in-process max (a regressed central value is ignored) and
        // serves the last-observed max when Redis is unavailable. The
        // effective epoch is applied to the shared verifier via
        // setExpectedPolicyVersion(), mutating only the policy epoch: the
        // region and issuer expectations are construction-time verifier
        // settings (wired above with the configured values) and are
        // deliberately never rewritten by the monitor — a central epoch
        // bump must not disable the issuer security boundary. Every
        // verification enforces the current epoch and a central policy
        // bump revokes outstanding challenges within one cache window.
        // Without a Redis client the monitor serves the configured
        // risk.policy_version (no central state to read).
        $namespace = preg_replace('/[^A-Za-z0-9_.-]/', '_', (string) $riskConfig['namespace']) ?: 'kiwi';
        $container->setDefinition(SecurityEpochMonitor::class, (new Definition(SecurityEpochMonitor::class, [
            new Reference('kiwi_captcha.verifier'),
            $redisRef,
            $namespace,
            $config['risk']['policy_version'],
            $riskConfig['security_epoch_cache_secs'],
        ]))
            // The max-stale fail-closed window: past last_success +
            // max_stale the validator fails verification closed
            // (temporary_unavailable) and the controller refuses
            // issuance with 503 `SERVICE_UNAVAILABLE`.
            ->setArgument('$maxStaleSecs', $riskConfig['security_epoch_max_stale_secs'])
            ->setPublic(true));

        // Optional Ed25519 result-receipt signer. The result verification
        // stays central-only (the HMAC secret never leaves the server);
        // this signer only enables exported verification receipts verified
        // with the public key. Null seed = disabled (the validator's
        // receipt accessors stay null).
        $container->setDefinition(ResultReceiptSigner::class, new Definition(ResultReceiptSigner::class, [
            $receiptSeed,
        ]));

        // Per-scope issuance cap: risk.max_challenges_per_scope_per_minute
        // > 0 requires a Redis client for the atomic fixed-window counter,
        // refused at compile time instead of silently minting unbilled
        // challenges. The window key carries the hex form of
        // hmac_sha256(scope, K_scope), so the raw scope string is never
        // a Redis key component; K_scope is derived from the risk
        // master with hash_hkdf info 'kiwi/v2/scope-rate' (the same
        // derivation the risk package uses for its calibration scope
        // keys).
        $scopeCapRef = null;
        if ($riskConfig['max_challenges_per_scope_per_minute'] > 0) {
            $scopeCapRedis = $riskRedis ?? $redisRef;
            if ($scopeCapRedis === null) {
                throw new \LogicException(
                    'kiwi_captcha.risk.max_challenges_per_scope_per_minute requires a Redis client for the atomic '.
                    'fixed-window counter ({kiwi:<ns>}:issuance:<scopeIdentity>:<minute>). Configure '.
                    'redis_service / risk.redis_service (or a RedisStorage client) or set the cap to 0 (unlimited).'
                );
            }
            $scopeHmacKey = ScopeIssuanceCap::deriveScopeHmacKey($riskConfig['master_secret'] ?? $config['secret_key']);
            $container->setDefinition('kiwi_captcha.risk.scope_issuance_cap', new Definition(ScopeIssuanceCap::class, [
                $scopeCapRedis,
                sprintf('{kiwi:%s}:issuance:', $namespace),
                $riskConfig['max_challenges_per_scope_per_minute'],
                $scopeHmacKey,
            ]));
            $scopeCapRef = new Reference('kiwi_captcha.risk.scope_issuance_cap');
        }

        // Server-side provider-compatibility stores: the metadata sidecar
        // (action/cData bound at challenge issuance) and the atomic
        // idempotency store (provider-style idempotency_key). The
        // logical-operation identity of a redemption lives in the consumed
        // runtime state itself (written atomically with the
        // pending->consumed transition), so no separate redemption record
        // is needed. Redis-backed whenever the challenge storage is
        // RedisStorage (the same client), in-memory otherwise (test/dev
        // semantics; the stores are only wired into the controllers, and
        // production deployments with Siteverify use the Redis variants).
        $metadataStoreRef = null;
        $idempotencyStoreRef = null;
        if ($redisRef !== null) {
            $redisNamespace = $riskConfig['redis']['namespace'] ?? 'kiwicaptcha';
            $container->setDefinition(RedisSiteVerifyMetadataStore::class, new Definition(RedisSiteVerifyMetadataStore::class, [
                $redisRef,
                $redisNamespace,
                $riskConfig['redis']['wait_replicas'] ?? 0,
                $riskConfig['redis']['wait_timeout_ms'] ?? 100,
            ]));
            // The verified-WAIT durability knobs flow into the idempotency
            // store like every other durability-critical Redis component
            // (claim/takeover/renew/finalize WAIT; read-only outcomes never
            // do).
            $container->setDefinition(RedisSiteVerifyIdempotencyStore::class, new Definition(RedisSiteVerifyIdempotencyStore::class, [
                $redisRef,
                $redisNamespace,
                RedisSiteVerifyIdempotencyStore::LEASE_SECONDS,
                $riskConfig['redis']['wait_replicas'] ?? 0,
                $riskConfig['redis']['wait_timeout_ms'] ?? 100,
            ]));
            $metadataStoreRef = new Reference(RedisSiteVerifyMetadataStore::class);
            $idempotencyStoreRef = new Reference(RedisSiteVerifyIdempotencyStore::class);
        } else {
            $container->setDefinition(ArraySiteVerifyMetadataStore::class, new Definition(ArraySiteVerifyMetadataStore::class, []));
            $container->setDefinition(ArraySiteVerifyIdempotencyStore::class, new Definition(ArraySiteVerifyIdempotencyStore::class, []));
            $metadataStoreRef = new Reference(ArraySiteVerifyMetadataStore::class);
            $idempotencyStoreRef = new Reference(ArraySiteVerifyIdempotencyStore::class);
        }

        // The core binds issuance by the global binding_mode only: the
        // per-sitekey map carries no binding dimension, so the global
        // server-owned mode is the only binding control.
        $sitekeyPolicy = $riskConfig['sitekeys'] ?? [];
        // The same-origin expected origin comes from server config,
        // never the Host header. The controller receives the validated
        // ExpectedOrigin value object, never the raw string: a literal
        // was validated at build time above, and an env-resolved value
        // is validated by the same factory when the service is
        // constructed, the runtime lane mirroring createDsnClient().
        // A malformed resolved origin therefore fails closed with the
        // typed LogicException naming the option instead of silently
        // weakening the same-origin check.
        $expectedOriginRef = null;
        if ($config['public_base_url'] !== null) {
            $expectedOriginRef = $this->buildExpectedOriginService((string) $config['public_base_url'], $container);
        }
        $container->setDefinition(ChallengeController::class, (new Definition(ChallengeController::class, [
            new Reference('kiwi_captcha.issuer'),
            $rateLimiterRef,
            $config['same_origin_only'],
            $riskGatewayRef,
            $riskCookieRef,
            $issuanceCounterRef,
            $outstandingRef,
            $config['risk']['challenge_origin_allowlist'],
            $config['risk']['enforce_fetch_metadata'],
            $storageRef,
            // Static transaction-binding fallback: the widget sends its
            // own request_binding field when it carries one; this default
            // applies when the request does not.
            $config['risk']['request_binding'],
            // When enforced, a challenge POST without a usable
            // Origin header is rejected with 403 origin_rejected.
            $config['risk']['enforce_origin'],
        ]))
            // The trusted client-IP policy drives the controller's
            // canonical IP (binding tag / rate-limit identity / risk
            // source).
            ->setArgument('$clientIpResolver', new Reference(ClientIpResolver::class))
            // The same-origin expected origin comes from server config,
            // never the Host header: the controller receives the
            // validated ExpectedOrigin object (or null when
            // public_base_url is not configured).
            ->setArgument('$expectedOrigin', $expectedOriginRef)
            // The per-scope issuance cap (fixed-window Redis
            // counter; null when disabled).
            ->setArgument('$scopeIssuanceCap', $scopeCapRef)
            // The server-owned scope allowlist: when non-empty, issuance
            // outside it is refused (422 `SCOPE_NOT_ALLOWED`) before
            // risk/quota, making the per-scope quota namespace
            // server-bounded.
            ->setArgument('$allowedScopes', $riskConfig['allowed_scopes'])
            // Migration sitekey -> scope alias map (server-owned).
            ->setArgument('$sitekeyAllowlist', $riskConfig['sitekey_allowlist'])
            // The provider-metadata sidecar (action/cData
            // bound to the nonce at issuance).
            ->setArgument('$metadataStore', $metadataStoreRef)
            // Server-owned (sitekey, action) -> scope
            // policy map.
            ->setArgument('$sitekeyPolicy', $sitekeyPolicy)
            // The security-epoch monitor drives the issuance-side
            // max-stale fail-closed check: a stale central policy read
            // refuses issuance with 503 `SERVICE_UNAVAILABLE`.
            ->setArgument('$epochMonitor', new Reference(SecurityEpochMonitor::class))
            // The authoritative transaction-binding resolver: when
            // The configured challenge TTL lets the anti-
            // stockpiling admission run before the challenge state is
            // created (the quota checks all precede the storage write).
            ->setArgument('$challengeTtlSecs', $config['challenge_ttl_secs'])
            ->setArgument('$metadataRetentionMarginSecs', $riskConfig['redis']['ttl_margin_secs'] ?? 60)
            // The one-shot chain-ticket gate for stage-2 issuance
            // (risk.chaining; null = chaining disabled, so a ticket-bearing
            // request is then refused).
            ->setArgument('$chainTickets', $chainServiceRef)
            // The authoritative transaction-binding resolver
            // (risk.request_binding_authority; null = the legacy
            // static/attribute binding applies). When configured, the
            // controller resolves the transaction binding only through it,
            // never an unexamined client string.
            ->setArgument('$bindingAuthority', $bindingAuthorityRef)
            // The trusted-edge TLS classification header
            // (risk.trusted_tls_header; null = the feature is off).
            ->setArgument('$trustedTlsHeader', $trustedTlsHeader)
            // The trusted-edge proxies whose TLS classification header is
            // honored (risk.trusted_tls_proxies; the header is read only
            // when the direct peer is inside the list).
            ->setArgument('$trustedTlsProxies', $riskConfig['trusted_tls_proxies'])
            // The security-policy epoch a presented chain ticket must
            // match (a chain from an older epoch is refused).
            ->setArgument('$policyVersion', $config['risk']['policy_version'])
            // The protocol-v3 writer switch (risk.decoy_v3_enabled,
            // default false): issuance arms the authenticated decoy only
            // when this is true AND the SecurityEpochMonitor confirms the
            // central min_protocol_version floor >= 3. The default keeps
            // every deployment emitting protocol v2 — the two-phase
            // rollout gate, see operations.md.
            ->setArgument('$decoyV3Enabled', $config['risk']['decoy_v3_enabled'])
            // The ExecutionChallengeV1 gate (risk.execution_challenge,
            // default off): when on, issuance MAY arm the browser-
            // execution dimension when a risk trigger passes AND the
            // SecurityEpochMonitor confirms the central
            // min_protocol_version floor >= 4 (the protocol-v4 rollout
            // gate). The gate on without execution_key was refused at
            // compile time above.
            ->setArgument('$executionGate', $config['risk']['execution_challenge'] === 'on')
            // The node's execution-program version cap
            // (kiwi_captcha.execution_version, default 1): the effective
            // per-issuance grammar version is 2 only when the client
            // advertised execution_max_version >= 2, this cap is >= 2
            // and the SecurityEpochMonitor confirms the central
            // min_execution_version floor >= 2.
            ->setArgument('$executionVersionCap', $config['execution_version'])
            ->setArgument('$executionRequiredVersion', $config['execution_required_version'])
            // The issuance-side logger (when the app has one) receives
            // the once-per-process decoy_v3_enabled-but-floor-too-low
            // warning.
            ->setArgument('$logger', $loggerRef)
            ->addTag('controller.service_arguments')->setPublic(true));

        // Challenge route (configured prefix; see KiwiCaptchaRouteLoader).
        $container->setDefinition(KiwiCaptchaRouteLoader::class, (new Definition(KiwiCaptchaRouteLoader::class, [
            '%kiwi_captcha.route_prefix%',
            // The /health/live + /health/ready routes follow
            // risk.health.enabled (default true).
            $config['risk']['health']['enabled'],
        ]))->addTag('routing.loader'));

        // Provider-compatible Siteverify, disabled unless siteverify_secret
        // is configured; calls the same atomic verifier service
        // (kiwi_captcha.verifier). The storage is injected so the
        // deterministic consumed-result's record metadata (issued_at,
        // hostname) is available for the provider-shaped JSON.
        $container->setDefinition(SiteVerifyController::class, (new Definition(SiteVerifyController::class, [
            new Reference('kiwi_captcha.verifier'),
            $config['secret_key'],
            // Map of siteverify secret -> expected scope; empty
            // disables the endpoint.
            $riskConfig['siteverify_secrets'],
            // The one-success provider contract requires an atomic
            // backend: requireAtomicStorageWhenNeeded() refuses any
            // non-atomic combination (Psr6Storage included) at compile
            // time.
            $riskConfig['siteverify_secrets'] !== [] ? new Reference(StorageInterface::class) : null,
            null, // logger (autowired position — kept explicit for stability)
            $riskConfig['siteverify_secrets'] !== [] ? $metadataStoreRef : null,
            $riskConfig['siteverify_secrets'] !== [] ? $idempotencyStoreRef : null,
            // The shared Redis log gate for
            // invalid-secret flood suppression (null = suppressed detail).
            $riskConfig['siteverify_secrets'] !== [] ? $redisRef : null,
            (float) SiteVerifyController::IDEMPOTENCY_WAIT_SECS, // idempotency wait bound (the ctor default — never null, the param is float)
            $config['risk']['policy_version'] ?? 1, // security-policy epoch in the idempotency identity
        ]))
            // The static deployment security-context digest, built by
            // the same VerificationSecurityContext that wired the
            // verifier's keyring: version marker, issuer, region, the
            // current kid, a sha256 of the current signing secret, the
            // effective merged keyring (historical + current), and the
            // revoked set. Bound into the idempotency backend identity
            // so a cached SiteVerify provider result can never outlive
            // the signing security context that produced it: a kid,
            // secret, issuer, region, keyring or revocation rotation
            // invalidates the idempotency namespace (a same-key retry
            // becomes a different logical operation), exactly as the
            // core's hard-security verdicts dominate even a
            // same-operation retry.
            ->setArgument('$securityContextDigest', $securityContext->contextDigest())
            ->setArgument('$outstanding', $riskConfig['enabled'] ? new Reference('kiwi_captcha.risk.outstanding') : null)
            // The security-epoch monitor drives the identity and the
            // fail-closed check: the effective epoch (the monitor's
            // per-request refresh) binds the idempotency backend identity,
            // and a stale central policy read answers the retryable
            // provider internal-error, mirroring the native controller's
            // wiring (a Siteverify-only worker must observe policy
            // revocations and the max-stale fail-closed window too).
            ->setArgument('$epochMonitor', new Reference(SecurityEpochMonitor::class))
            // The authoritative transaction-binding resolver
            // (risk.request_binding_authority): when configured, every
            // Siteverify redemption enforces the same pre-consume binding
            // contract as the native path (the resolved binding feeds the
            // core's expected request binding AND the idempotency
            // identity) — the mixed configuration is wired here, on the
            // Siteverify surface, never silently turning request binding
            // off. The static risk.request_binding is the fallback
            // server-side transaction input when no authority exists.
            ->setArgument('$bindingAuthority', $bindingAuthorityRef)
            ->setArgument('$defaultRequestBinding', $staticBinding)
            // Adaptive-risk feedback: the provider surface feeds the same
            // risk evidence as the native path (SolveSuccess repays the
            // issuance debt only; failure classes enrich the model).
            ->setArgument('$riskGateway', $riskConfig['enabled'] ? $riskGatewayRef : null)
            // The logical-operation identity of the redemption rides in
            // the consumed runtime state (written atomically with the
            // pending->consumed transition). The recovery gate on the
            // takeover path compares the consumed record's own identity
            // against the claiming fingerprint, so a consumed token can
            // never become successful again through a different
            // idempotency UUID or backend secret.
            ->addTag('controller.service_arguments')->setPublic(true));

        // Migration compatibility loader:
        // GET {prefix}/api.js[?compat=...] serves the canonical glue and
        // driver as one same-origin external script.
        $assetsDir = \dirname(__DIR__, 2).'/Resources/public';
        $container->setDefinition(ApiJsController::class, (new Definition(ApiJsController::class, [
            $assetsDir,
        ]))->addTag('controller.service_arguments')->setPublic(true));

        // Versioned immutable widget assets (asset_mode "files"):
        // GET {prefix}/assets/{name}.{hash}.{js|css} serves the same
        // bytes the inline mode embeds, with the content hash in the URL,
        // a long immutable cache lifetime, the Content-Length and the
        // content-hash ETag.
        $container->setDefinition(AssetController::class, (new Definition(AssetController::class, [
            $assetsDir,
        ]))->addTag('controller.service_arguments')->setPublic(true));

        // Health endpoints: /health/live is always 200 while the process
        // runs. /health/ready is 200 only when the signing keys are
        // configured, the security Redis answers a (cached) PING and the
        // central security-policy state is compatible
        // ({kiwi:<ns>}:security-policy: min_protocol_version <= 3 and
        // min_policy_epoch <= risk.policy_version; key absent = the
        // binary's own config is authoritative). Argon queue fullness and
        // transient probe timeouts never fail readiness.
        // A finite container budget requires a finite Argon concurrency
        // cap: 0 means "unlimited", and an unlimited memory-hard workload
        // has no finite worst case — the combination is refused at compile
        // time instead of silently modeling unlimited as concurrency 1.
        if ($config['risk']['container_memory_mib'] !== null && $config['argon2_max_concurrent_verifications'] <= 0) {
            throw new \LogicException(
                'A finite risk.container_memory_mib requires a finite argon2_max_concurrent_verifications cap — 0 means "unlimited", and an unlimited memory-hard workload has no finite worst-case concurrency for the memory-budget readiness invariant.'
            );
        }

        $healthNamespace = preg_replace('/[^A-Za-z0-9_.-]/', '_', (string) $riskConfig['namespace']) ?: 'kiwi';
        $container->setDefinition(KiwiHealthController::class, (new Definition(KiwiHealthController::class, [
            $config['secret_key'],
            $redisRef,
            $healthNamespace,
            $config['risk']['policy_version'],
        ]))
            // The memory-budget readiness invariant (concurrency x max
            // adaptive profile + headroom <= container_memory_mib). The
            // max adaptive profile memory is the fixed verification
            // envelope (risk.argon_verification_memory_kib), since risk
            // never escalates the server verification cost; the worst
            // case is the envelope.
            ->setArgument('$argonConcurrency', $config['argon2_max_concurrent_verifications'])
            ->setArgument('$containerMemoryMib', $config['risk']['container_memory_mib'])
            ->setArgument('$argonEnvelopeMemoryKib', $riskConfig['argon_verification_memory_kib'])
            // The pinned-primary authority-eligibility leg: the wired
            // guards (keyed by authority label) and the distinct risk
            // Redis client they verify. Under pinned_primary / ha_safe
            // the readiness probe forces a fresh guard check per
            // authority (never the ordinary verification window), so a
            // pod whose pin is uninitialized or whose authority changed
            // leaves the pool immediately.
            ->setArgument('$authorityGuards', $authorityGuardRefs)
            ->setArgument('$riskRedis', $riskRedis)
            ->addTag('controller.service_arguments')->setPublic(true));

        // Form type (renders the widget through the form theme). The
        // route prefix is injected so the default 'endpoint' option
        // follows the actual registered route (the standalone Twig widget
        // derives its endpoint from the same prefix); the telemetry mode
        // follows the (strict-enforced) config; the request_binding option
        // follows the static risk.request_binding default.
        $container->setDefinition(KiwiCaptchaType::class, (new Definition(KiwiCaptchaType::class, [
            new Reference(KiwiCaptchaRuntime::class),
            '%kiwi_captcha.route_prefix%',
            $config['telemetry'],
            $config['risk']['request_binding'],
        ]))->addTag('form.type'));

        // Post-solve disposition store (final-disposition durability). The
        // validator's one final-disposition path (`PASS` | `DENY` | `STEP_UP` |
        // `CHAIN_REQUIRED`) is persisted per nonce, so a replay of a valid
        // proof reproduces the same disposition; a stored core result can
        // never bypass the post-solve policy (it only answers "was the
        // PoW cryptographically valid?"). Redis-backed whenever a Redis
        // client is available (the risk Redis first, falling back to the
        // bundle client), in-memory otherwise (test/dev semantics,
        // mirroring the chain state store wiring). The record TTL =
        // Config::MAX_TTL_SECS + risk.redis.ttl_margin_secs, so the
        // disposition survives at least as long as the consumed core
        // result can be replayed (the consumed record's own retention is
        // token lifetime + the same margin); the claim lease stays a short
        // fixed bound inside the store.
        $dispositionRedis = $riskRedis ?? $redisRef;
        $dispositionTtlSecs = Config::MAX_TTL_SECS + $riskConfig['redis']['ttl_margin_secs'];
        if ($dispositionRedis !== null) {
            // The risk.redis replica-durability knobs
            // (wait_replicas / wait_timeout_ms) flow into the disposition
            // store too, the same knobs that harden the challenge
            // storage: the claim's record creation and the finalize's
            // completion WAIT for the configured replica count before the
            // caller learns success (a returned Deny/StepUp/ChainRequired
            // must survive a promotion).
            $container->setDefinition(RedisPostSolveDispositionStore::class, new Definition(RedisPostSolveDispositionStore::class, [
                $dispositionRedis,
                $namespace,
                $dispositionTtlSecs,
                $riskConfig['redis']['wait_replicas'],
                $riskConfig['redis']['wait_timeout_ms'],
            ]));
            $dispositionStoreRef = new Reference(RedisPostSolveDispositionStore::class);
        } else {
            $container->setDefinition(ArrayPostSolveDispositionStore::class, new Definition(ArrayPostSolveDispositionStore::class, [
                null,
                $dispositionTtlSecs,
            ]));
            $dispositionStoreRef = new Reference(ArrayPostSolveDispositionStore::class);
        }
        // The challenge controller receives the same disposition store: a
        // consumed-valid stage-2 challenge is not terminal from the core's
        // consumed result alone. The controller reads the nonce's final
        // disposition and transitions the chain by kind (Pass ->
        // markVerified, StepUp -> markStepUpRequired, Deny -> markDenied;
        // missing/pending -> the retryable 503). The disposition store is
        // defined above, so the argument is attached after the controller
        // definition.
        $container->getDefinition(ChallengeController::class)->setArgument('$postSolveDispositionStore', $dispositionStoreRef);

        // The authoritative transaction-binding authority is wired by the
        // chaining region above (risk.request_binding_authority; null when
        // not configured, so chaining never opens and the validator
        // receives null).

        // Validator (local verification, no external calls). The logger
        // receives the internal verification detail on failures; the
        // public violation code is collapsed (invalid_or_expired /
        // rate_limited / temporary_unavailable), and the precise core
        // reason stays in the logs.
        $container->setDefinition(KiwiCaptchaValidator::class, (new Definition(KiwiCaptchaValidator::class, [
            new Reference('kiwi_captcha.verifier'),
            new Reference('request_stack'),
            $config['secret_key'],
            $config['enforce_telemetry'],
            $riskGatewayRef,
            $riskCookieRef,
            $outstandingRef,
        ]))
            ->setArgument('$logger', $loggerRef)
            // The challenge storage resolves ambiguous-consume
            // outcomes from the consumed record (state + consumed_result).
            ->setArgument('$storage', $storageRef)
            // The same canonical client IP the controller bound
            // the challenge to (trusted client-IP policy).
            ->setArgument('$clientIpResolver', new Reference(ClientIpResolver::class))
            // The security-epoch monitor feeds the verifier's
            // expected policy epoch per verification (bounded revocation
            // latency + monotonic max).
            ->setArgument('$epochMonitor', new Reference(SecurityEpochMonitor::class))
            // The optional Ed25519 result-receipt signer for
            // exported verification results (null = disabled).
            ->setArgument('$receiptSigner', new Reference(ResultReceiptSigner::class))
            // The chain ticket service issues the one-shot `CHAIN_REQUIRED`
            // tickets after a valid verification whose reassessment
            // demands a stronger stage (risk.chaining; null = disabled).
            ->setArgument('$chainTickets', $chainServiceRef)
            // The security-policy epoch stamped into issued chain tickets.
            ->setArgument('$policyVersion', $config['risk']['policy_version'])
            // The provider-metadata sidecar: the validator reads a
            // verified challenge's stored metadata chainId (the private
            // server-stamped field) to detect the chain end (stage 2, no
            // third-stage ticket).
            ->setArgument('$metadataStore', $metadataStoreRef)
            // The risk profile resolver: the authoritative stage-strength
            // comparison for chaining (a chain opens only when the
            // reassessed action is not satisfied by the solved challenge
            // under the actual configured ladders).
            ->setArgument('$riskResolver', $riskResolverRef)
            // Post-solve disposition wiring: the durable nonce-keyed
            // final-disposition store (wired above; Redis when a Redis
            // client is available, in-memory otherwise), the authoritative
            // transaction-binding authority (nullable service id
            // risk.request_binding_authority; null = chaining
            // unavailable), the retained disposition margin
            // (risk.redis.ttl_margin_secs; the record TTL is
            // Config::MAX_TTL_SECS + margin) and the chain lifetime
            // (risk.chaining.ttl_secs) for the stage-2
            // requirement/ticket expiry.
            ->setArgument('$dispositionStore', $dispositionStoreRef)
            ->setArgument('$bindingAuthority', $bindingAuthorityRef)
            ->setArgument('$postSolveDispositionTtlMarginSecs', $riskConfig['redis']['ttl_margin_secs'])
            ->setArgument('$chainTtlSecs', $riskConfig['chaining']['ttl_secs'])
            ->addTag('validator.constraint_validator'));

        // Twig widget runtime + twig function (embeds the shared widget
        // assets, or emits the versioned files-mode asset tags).
        $container->setDefinition(KiwiCaptchaRuntime::class, (new Definition(KiwiCaptchaRuntime::class, [
            $config['route_prefix'],
            null,
            KiwiCaptchaRuntime::DEFAULT_TEMPLATE,
            $config['telemetry'],
            // The static transaction binding is the standalone
            // widget's data-kiwi-request-binding default.
            $config['risk']['request_binding'],
            // The widget page's frame-ancestors CSP helper:
            // the space-separated allowlisted origins.
            $config['risk']['challenge_origin_allowlist'],
            // The coarse client-context opt-in: true renders
            // data-kiwi-risk-context="coarse" on the widget container so
            // the driver sends the coarse capability tag (refused under
            // privacy_mode strict). The privacy flag rides alongside so
            // the runtime can also refuse the per-render override.
            $config['risk']['client_context'],
            $config['privacy_mode'] === 'strict',
            // The asset delivery tier: "files" (default) emits versioned
            // immutable first-party asset URLs with SRI + once-per-page
            // dedup and lazily fetches the WASM runtime and the Argon
            // worker only when a memory-hard challenge arrives; "inline"
            // is the compatibility / zero-request tier. The kernel.reset
            // tag clears the request-scoped emission registry between
            // requests in long-lived runtimes.
            $config['asset_mode'],
        ]))
            ->addTag('twig.runtime')
            ->addTag('kernel.reset', ['method' => 'reset']));
        $container->setDefinition(TwigExtension::class, (new Definition(TwigExtension::class))
            ->addTag('twig.extension'));

        // Environment doctor (kiwicaptcha:doctor): validates the
        // production wiring from the same effective configuration and
        // the same services the extension just built, so a check can
        // never drift from the wiring it audits. Redis references and
        // the chain/siteverify stores are passed as resolved, exactly
        // like every other consumer of this extension. The pinned-
        // primary authority guards are passed keyed by authority label
        // (storage / risk), so the HA authority check audits each
        // distinct authority's pin.
        $container->setDefinition(KiwiCaptchaDoctorCommand::class, (new Definition(KiwiCaptchaDoctorCommand::class, [
            $environment,
            $config,
            new Reference(StorageInterface::class),
            new Reference('kiwi_captcha.config'),
            new Reference(SecurityEpochMonitor::class),
            $redisRef,
            $riskRedis,
            $chainStoreRef,
            $idempotencyStoreRef,
            $authorityGuardRefs,
        ]))
            ->addTag('console.command')
            ->setPublic(true));

        // The explicit authority bootstrap (kiwicaptcha:ha-initialize):
        // the operator records the initial authority pin(s) for the
        // pinned-primary authority guard(s), refusing an existing pin
        // unless --force is given after a deliberate quiesce. The
        // production runtime never auto-pins, so this command is the
        // only way a pinned_primary deployment becomes armed.
        $container->setDefinition(KiwiCaptchaHaInitializeCommand::class, (new Definition(KiwiCaptchaHaInitializeCommand::class, [
            $config,
            $authorityGuardRefs,
        ]))
            ->addTag('console.command')
            ->setPublic(true));
    }

    /**
     * ArrayStorage is an in-memory, single-process store. A challenge issued
     * in request A is verified in request B, which runs in a different PHP
     * process under PHP-FPM, so the record would be lost. Fail hard outside
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
     * The production missing-origin rule. The challenge controller's
     * same-origin check must compare against server config
     * (public_base_url), never the request's own scheme+host, otherwise a
     * forged Host header defines the security boundary. Fail closed at
     * boot: prod + same-origin enforcement + missing public_base_url is a
     * configuration error. A Symfony %env(...)% placeholder is accepted
     * here: the container resolves it at compile/runtime, so the
     * literal-shape checks are skipped and the resolved value is
     * validated by the runtime lane (ExpectedOrigin::fromPublicBaseUrl)
     * when the controller is constructed. The literal-shape contract
     * itself lives in ExpectedOrigin::publicBaseUrlViolation and runs
     * for every literal in every environment.
     */
    private function requireProductionPublicBaseUrl(mixed $publicBaseUrl, string $environment): void
    {
        if (self::isEnvPlaceholder($publicBaseUrl)) {
            return;
        }
        if (!\is_string($publicBaseUrl) || $publicBaseUrl === '') {
            throw new \LogicException(sprintf(
                'KiwiCaptcha: production (environment "%s") with same-origin enforcement (or Siteverify configured) REQUIRES public_base_url — the expected origin must come from server config, never the request Host header. Set e.g. public_base_url: "https://captcha.example.com".',
                $environment,
            ));
        }
    }

    /**
     * Define the ExpectedOrigin service for a configured public_base_url.
     * Both lanes construct it through the same runtime factory
     * {@see ExpectedOrigin::fromPublicBaseUrl()}. A literal passed the
     * build-time validation above and the factory re-validates it
     * (idempotent), while an env placeholder is resolved by the
     * container's parameter bag before the factory runs. The
     * fail-closed canonical-origin validation therefore applies to the
     * resolved value unseen by the load-time lane. The controller never
     * receives the raw string.
     */
    private function buildExpectedOriginService(string $publicBaseUrl, ContainerBuilder $container): Reference
    {
        if (!$container->hasDefinition(self::EXPECTED_ORIGIN_ID)) {
            $container->setDefinition(self::EXPECTED_ORIGIN_ID, (new Definition(ExpectedOrigin::class))
                ->setFactory([ExpectedOrigin::class, 'fromPublicBaseUrl'])
                ->setArguments([$publicBaseUrl])
                ->setPublic(true));
        }

        return new Reference(self::EXPECTED_ORIGIN_ID);
    }

    /**
     * Strict single-use requires an atomic storage backend. In production
     * (not test/dev):
     *  - unless allow_best_effort_storage is explicitly true, the resolved
     *    storage must implement KiwiCaptcha\AtomicStorageInterface. A
     *    non-atomic backend (e.g. Psr6Storage) lets two racing requests
     *    both observe pending and both win verification.
     *  - when siteverify_secrets is configured, an atomic backend is
     *    required regardless of the override: the provider one-success
     *    contract cannot exist on a non-atomic backend, so the container
     *    refuses the combination.
     * When siteverify_secrets is configured, the storage must also be
     * Siteverify recovery-capable (SiteVerifyRecoveryCapableStorageInterface;
     * the bundled core storages qualify through AtomicStorageInterface +
     * ConsumedStateReadableInterface + the identity-aware consume
     * capability + the fused delete-if-pending cleanup). Siteverify
     * idempotency crash recovery reads the retained consumed state and
     * compares the consumed record's own operation identity against the
     * claiming fingerprint. A custom atomic storage without the
     * identity-aware consume capability is refused, since the recovery
     * gate would silently refuse everything when no record could ever
     * carry an identity. A store without the atomic cleanup capability
     * is refused too, since its read-then-delete cleanup can erase the
     * committed evidence under concurrency. Ordinary verification
     * remains compatible with any StorageInterface.
     * Fails closed at container compile time (a LogicException names the
     * exact misconfiguration).
     *
     * @param array<string, string> $siteverifySecrets
     */
    private function requireAtomicStorageWhenNeeded(Reference $storageRef, string $storageId, string $environment, bool $allowBestEffort, array $siteverifySecrets, ContainerBuilder $container): void
    {
        $siteverifyEnabled = $siteverifySecrets !== [];
        $production = !\in_array($environment, ['test', 'dev'], true);
        if (!$production && !$siteverifyEnabled) {
            return;
        }
        if ($siteverifyEnabled && $allowBestEffort) {
            throw new \LogicException('KiwiCaptcha: siteverify_secrets requires an ATOMIC storage backend (KiwiCaptcha\AtomicStorageInterface) — the provider one-success contract is impossible on a non-atomic backend, and allow_best_effort_storage cannot override this combination.');
        }

        $id = $storageId;

        if ($container->hasAlias($id)) {
            $id = (string) $container->getAlias($id);
        }
        $class = null;
        if ($container->hasDefinition($id)) {
            $class = $container->getDefinition($id)->getClass();
            if ($class !== null && str_starts_with($class, '%') && $container->hasParameter(trim($class, '%'))) {
                $class = $container->getParameter(trim($class, '%'));
            }
        }
        $isAtomic = $class !== null && \is_string($class) && \is_a($class, AtomicStorageInterface::class, true);
        $isIdentityAware = $class !== null && \is_string($class) && \is_a($class, OperationIdentityAwareStorageInterface::class, true);
        $isRecoveryCapable = $class !== null && \is_string($class) && (
            \is_a($class, SiteVerifyRecoveryCapableStorageInterface::class, true)
            || (\is_a($class, AtomicStorageInterface::class, true) && \is_a($class, ConsumedStateReadableInterface::class, true) && $isIdentityAware && \is_a($class, AtomicDeleteIfPendingInterface::class, true))
        );
        if ($siteverifyEnabled) {
            if (!$isAtomic) {
                throw new \LogicException(sprintf(
                    'KiwiCaptcha: siteverify_secrets requires an ATOMIC storage backend (KiwiCaptcha\AtomicStorageInterface) — the provider one-success contract is impossible on a non-atomic backend. Configure "storage: kiwicaptcha.storage.redis" (RedisStorage) or any service implementing AtomicStorageInterface (resolved class %s).',
                    $class === null ? '(unresolvable)' : $class,
                ));
            }
            if (!$isRecoveryCapable) {
                throw new \LogicException(sprintf(
                    'KiwiCaptcha: siteverify_secrets requires a Siteverify recovery-capable storage backend — the class must implement all four capabilities: KiwiCaptcha\OperationIdentityAwareStorageInterface (which requires KiwiCaptcha\ConsumedStateReadableInterface), KiwiCaptcha\AtomicStorageInterface, AND KiwiCaptcha\AtomicDeleteIfPendingInterface (or BelConsulting\KiwiCaptchaBundle\SiteVerify\SiteVerifyRecoveryCapableStorageInterface, which extends all four; the bundled RedisStorage/ArrayStorage qualify). The resolved class %s lacks one of them: Siteverify idempotency crash recovery reads the retained consumed state, compares the consumed record\'s own operation identity against the claiming fingerprint, and preserves the committed evidence through the cheap-failure cleanup — the identity is written atomically with the pending→consumed transition, and without the fused delete-if-pending transition a concurrent redemption between the retained-state read and the cleanup delete erases the committed recovery evidence (the read-then-delete race).',
                    $class === null ? '(unresolvable)' : $class,
                ));
            }

            return;
        }
        if ($isAtomic) {
            return;
        }
        if ($allowBestEffort) {
            return;
        }
        if ($production) {
            throw new \LogicException(sprintf(
                'KiwiCaptcha: production verification requires an ATOMIC storage backend (KiwiCaptcha\AtomicStorageInterface — e.g. RedisStorage, whose Lua pending→consumed transition guarantees exactly one winner). The configured storage %s resolves to %s. Set the explicitly-named "allow_best_effort_storage: true" only if you deliberately accept weaker concurrency semantics.',
                $storageId,
                $class === null ? '(unresolvable class)' : $class,
            ));
        }
    }

    /**
     * Wire the pinned-primary authority guards (ha_authority
     * "pinned_primary", docs/ha-authority.md): one guard and one pin
     * per distinct Redis authority.
     *
     *  - the storage/limiter authority: one guard service
     *    (`kiwi_captcha.ha_authority_guard.storage`) bound to the raw
     *    storage/limiter Redis client, pinning
     *    `{kiwi:<ns>}:authority:pin:storage`. Its `INFO` reads and
     *    pin-key operations never pass through the guarded wrapper, so
     *    the check cannot recurse into itself.
     *  - a distinct risk authority: a second guard
     *    (`kiwi_captcha.ha_authority_guard.risk`) bound to the raw risk
     *    Redis client, pinning `{kiwi:<ns>}:authority:pin:risk`. When
     *    the risk client IS the storage/limiter client, the storage
     *    guard and pin cover both (one pin per distinct authority).
     *  - the storage/limiter Redis client service decorated with
     *    AuthorityGuardedPredisClient, so every command the bundle
     *    components issue (including the verified-WAIT executeRaw) is
     *    preceded by the pin check. A distinct risk client gets its own
     *    guarded decorator consulting its own guard.
     *
     * The optional `ha_authority_expected` operator-provisioned identity
     * is passed to every guard: the scalar shorthand applies to every
     * authority, and the per-authority map form applies each entry to
     * its own authority (an authority without an entry falls back to
     * the pin key). When the risk client IS the storage client (one
     * shared physical authority), the map form supplying different
     * identities for storage and risk is refused at configuration time:
     * a shared physical authority must have exactly one expected
     * identity.
     *
     * The decoration targets the resolved client service id, so the
     * storage (DSN-built or user RedisStorage), the limiter, the
     * admission semaphore and the risk state all receive the guarded
     * client through their existing references.
     *
     * @return array<string, Reference> the guard services keyed by
     *         authority label ("storage", "risk")
     */
    private function wirePinnedPrimaryAuthorityGuard(array $config, ?Reference $redisRef, ?Reference $riskRedis, ContainerBuilder $container): array
    {
        if ($redisRef === null) {
            throw new \LogicException(
                'kiwi_captcha.ha_authority is "pinned_primary", but no storage/limiter Redis client is wired — the pinned-primary guard pins the serving authority of the security Redis, and without a client there is no authority to pin and nothing to enforce. Configure redis_dsn / redis_service / a RedisStorage storage (a direct single-node Predis client), or set ha_authority: none (see docs/ha-authority.md).'
            );
        }
        $namespace = preg_replace('/[^A-Za-z0-9_.-]/', '_', (string) ($config['risk']['namespace'] ?? 'kiwicaptcha')) ?: 'kiwi';
        $expectedConfig = $config['ha_authority_expected'] ?? null;
        if (\is_string($expectedConfig) && $expectedConfig !== '') {
            // The scalar shorthand: ONE expected identity applies to
            // every authority.
            $expectedShorthand = $expectedConfig;
            $expectedByAuthority = [];
        } elseif (\is_array($expectedConfig)) {
            // The per-authority map: each entry applies to its own
            // authority; an authority without an entry falls back to
            // the pin key (it must be initialized).
            $expectedShorthand = null;
            $expectedByAuthority = $expectedConfig;
        } else {
            $expectedShorthand = null;
            $expectedByAuthority = [];
        }
        $this->assertPinnedPrimaryClientClass($redisRef, 'the storage/limiter Redis client', $container);
        $redisId = $this->resolveClientServiceId((string) $redisRef, $container);
        if ($redisId === null) {
            throw new \LogicException(sprintf(
                'kiwi_captcha.ha_authority is "pinned_primary", but the storage/limiter Redis client ("%s") cannot be resolved to a service the bundle can decorate at build time. Wire a direct single-node Predis\Client service id, or set ha_authority: none (see docs/ha-authority.md).',
                (string) $redisRef,
            ));
        }
        $storageGuardId = 'kiwi_captcha.ha_authority_guard.storage';
        $container->setDefinition($storageGuardId, (new Definition(PinnedPrimaryAuthorityGuard::class, [
            new Reference($redisId.'.inner'),
            $namespace,
            $config['ha_authority_reverify_secs'],
            'storage',
            $expectedByAuthority['storage'] ?? $expectedShorthand,
        ]))
            ->setPublic(true));
        $guardRefs = ['storage' => new Reference($storageGuardId)];
        $this->decorateGuardedClient($storageGuardId, $redisId, 'kiwi_captcha.redis.authority_guarded', $container);
        $decorated = [$redisId => true];
        if ($riskRedis !== null) {
            $riskId = $this->resolveClientServiceId((string) $riskRedis, $container);
            if ($riskId === null) {
                throw new \LogicException(sprintf(
                    'kiwi_captcha.ha_authority is "pinned_primary", but the risk Redis client ("%s") cannot be resolved to a service the bundle can decorate at build time. Wire a direct single-node Predis\Client service id, or set ha_authority: none (see docs/ha-authority.md).',
                    (string) $riskRedis,
                ));
            }
            if (isset($decorated[$riskId])) {
                // The risk client IS the storage/limiter client: one
                // physical authority, so the storage guard and pin
                // cover both. A shared physical authority can have
                // exactly ONE expected identity: the per-authority map
                // supplying different identities for storage and risk
                // on the same Redis is a contradiction that could never
                // both be true, so it is rejected at configuration time
                // (never silently resolved by the storage entry).
                $storageExpected = $expectedByAuthority['storage'] ?? null;
                $riskExpected = $expectedByAuthority['risk'] ?? null;
                if ($storageExpected !== null && $riskExpected !== null && $storageExpected !== $riskExpected) {
                    throw new \LogicException(sprintf(
                        'kiwi_captcha.ha_authority_expected supplies different identities for the storage and risk authorities ("%s" vs "%s"), but risk.redis_service resolves to the same Redis client as the storage/limiter client — one shared physical authority can have exactly one expected identity. Use one identity for the shared authority (the storage entry covers it, the per-authority map may repeat it), or wire a distinct risk.redis_service for a genuinely separate risk authority (see docs/ha-authority.md).',
                        $storageExpected,
                        $riskExpected,
                    ));
                }

                return $guardRefs;
            }
            $this->assertPinnedPrimaryClientClass($riskRedis, 'the risk Redis client', $container);
            $riskGuardId = 'kiwi_captcha.ha_authority_guard.risk';
            $container->setDefinition($riskGuardId, (new Definition(PinnedPrimaryAuthorityGuard::class, [
                new Reference($riskId.'.inner'),
                $namespace,
                $config['ha_authority_reverify_secs'],
                'risk',
                $expectedByAuthority['risk'] ?? $expectedShorthand,
            ]))
                ->setPublic(true));
            $guardRefs['risk'] = new Reference($riskGuardId);
            $this->decorateGuardedClient($riskGuardId, $riskId, 'kiwi_captcha.risk.redis.authority_guarded', $container);
        }

        return $guardRefs;
    }

    /**
     * Register one guarded-client decorator. The named service id is
     * decorated with AuthorityGuardedPredisClient (priority -1000 =
     * outermost, so it guards every other decorator on the client).
     * The raw client is preserved at `<clientId>.inner` for the
     * guard: the renamed id is explicit, so the guard's reference is a
     * stable string, and the decorator's own inner argument uses the
     * `.inner` magic reference the DecoratorServicePass rewrites.
     */
    private function decorateGuardedClient(string $guardId, string $clientId, string $decoratorId, ContainerBuilder $container): void
    {
        $container->setDefinition($decoratorId, (new Definition(AuthorityGuardedPredisClient::class, [
            new Reference($guardId),
            new Reference('.inner'),
        ]))
            ->setDecoratedService($clientId, $clientId.'.inner', -1000)
            ->setPublic(true));
    }

    /**
     * The pinned_primary client-class refusal at load time: aggregates
     * and phpredis/non-Predis clients are refused when their service is
     * visible to the extension (the DSN lane and every bundle-defined
     * client). The checked-client seam is chased to its RAW client so
     * the classification sees the real definition shape, never the
     * checked wrapper. Application-defined services are invisible to
     * load() (the temporary-container merge); the prepend lane
     * classifies those, and the guard's own constructor and checks are
     * the runtime backstop for anything the build could not see.
     */
    private function assertPinnedPrimaryClientClass(?Reference $ref, string $label, ContainerBuilder $container): void
    {
        $raw = $this->rawClientRefOf($ref, $container);
        if ($raw === null) {
            return;
        }
        $aggregate = $this->predisAggregateLabel($raw, $container, $label);
        if ($aggregate !== null) {
            throw new \LogicException(self::pinnedPrimaryRefusalMessage($aggregate));
        }
        $id = $this->resolveParameterizedServiceId((string) $raw, $container);
        if ($id === null) {
            return;
        }
        $class = $this->definitionClass($id, $container);
        if ($class === null) {
            return;
        }
        if (!is_a($class, \Predis\Client::class, true)) {
            throw new \LogicException(self::pinnedPrimaryUnverifiableClientMessage($id, sprintf('its class %s is not a Predis\Client (phpredis \Redis cannot be mechanically guarded)', $class)));
        }
    }

    /**
     * Chase a client reference through the checked-client seam to the
     * RAW client reference: a checked definition (the
     * {@see self::checkedRedisClient()} factory) is transparent, and
     * its first argument is the raw client it wraps. Any other
     * definition is returned unchanged. Unresolvable references are
     * returned as-is (the classification lanes then skip them, and the
     * prepend lane or the runtime backstop covers the path).
     */
    private function rawClientRefOf(?Reference $ref, ContainerBuilder $container): ?Reference
    {
        if ($ref === null) {
            return null;
        }
        $id = $this->resolveParameterizedServiceId((string) $ref, $container);
        if ($id === null || !$container->hasDefinition($id)) {
            return $ref;
        }
        $definition = $container->getDefinition($id);
        $factory = $definition->getFactory();
        if (\is_array($factory) && ($factory[0] ?? null) === self::class && ($factory[1] ?? null) === 'checkedRedisClient') {
            $client = $definition->getArgument(0);
            if ($client instanceof Reference) {
                return $this->rawClientRefOf($client, $container);
            }
        }

        return $ref;
    }

    /**
     * Resolve a client service id to the final definition id: walks
     * %%parameter%% placeholders and alias chains to the END (bounded
     * and cycle-guarded), or null when the id stays unresolvable or
     * has no definition the bundle could decorate.
     */
    private function resolveClientServiceId(string $id, ContainerBuilder $container): ?string
    {
        $seen = [];
        while (true) {
            $resolved = $this->resolveParameterizedServiceId($id, $container);
            if ($resolved === null || isset($seen[$resolved]) || \count($seen) >= 32) {
                return null;
            }
            $seen[$resolved] = true;
            if (!$container->hasAlias($resolved)) {
                return $container->hasDefinition($resolved) ? $resolved : null;
            }
            $id = (string) $container->getAlias($resolved);
        }
    }

    /**
     * Find the Redis client to use for the Argon2 admission gate and the
     * atomic rate limiter.
     *
     * Priority:
     *  1. the `redis_service` config option (explicit client service id);
     *  2. the storage service when it is a KiwiCaptcha\Storage\RedisStorage
     *     definition (its first constructor argument is the client);
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

    /**
     * Build the Predis client defined from the high-level redis_dsn
     * setting (the bundle's DSN-backed client pattern: one
     * Predis\Client constructed from the connection DSN, driving the
     * challenge storage, the distributed rate limiter, the Argon
     * admission and the risk state store).
     *
     * Two validation lanes, both fail-closed. A literal DSN is
     * shape-validated at container build time: it must be a redis://
     * or rediss:// URL with a host, refused with an actionable message
     * instead of failing the first request. A Symfony %env(...)%
     * placeholder skips the load-time shape check, because the value
     * is resolved by the container's parameter bag at compile/runtime.
     * The client is then constructed through the runtime guard
     * {@see self::createDsnClient()}, which runs the same shape
     * validation on the resolved DSN before Predis sees it. Predis
     * alone is not clear enough: a scheme-less string silently
     * defaults to tcp://127.0.0.1, so the guard turns a malformed
     * env-resolved DSN into the typed LogicException naming the
     * option instead of a confusing connection to the wrong host. A
     * reachable-but-absent server stays a runtime error on the
     * first command (Predis connects lazily), exactly like every
     * other wired client.
     */
    private function buildDsnRedisClient(string $dsn, ContainerBuilder $container): Reference
    {
        if (!class_exists(\Predis\Client::class)) {
            throw new \LogicException(
                'kiwi_captcha.redis_dsn requires predis/predis (composer require predis/predis): the DSN-backed Redis client is built as a Predis\Client so the same connection drives the challenge storage, the distributed rate limiter, the Argon admission semaphore and the risk state store (the risk engine is typed Predis\Client).'
            );
        }
        if (self::isEnvPlaceholder($dsn)) {
            if (!$container->hasDefinition(self::DSN_REDIS_CLIENT_ID)) {
                $container->setDefinition(self::DSN_REDIS_CLIENT_ID, (new Definition(\Predis\Client::class))
                    ->setFactory([self::class, 'createDsnClient'])
                    ->setArguments([$dsn])
                    ->setPublic(true));
            }

            return new Reference(self::DSN_REDIS_CLIENT_ID);
        }
        $violation = self::dsnShapeViolation($dsn);
        if ($violation !== null) {
            throw new \LogicException(sprintf(
                'kiwi_captcha.redis_dsn %s — the DSN is handed to Predis\Client verbatim, so a malformed DSN fails closed at container build time instead of failing the first request.',
                $violation,
            ));
        }
        if (!$container->hasDefinition(self::DSN_REDIS_CLIENT_ID)) {
            $container->setDefinition(self::DSN_REDIS_CLIENT_ID, (new Definition(\Predis\Client::class, [$dsn]))->setPublic(true));
        }

        return new Reference(self::DSN_REDIS_CLIENT_ID);
    }

    /**
     * Runtime construction guard for the env-managed DSN client. The
     * container resolves the %env(...)% placeholder to the real DSN
     * before invoking this factory, so the fail-closed shape validation
     * runs on the resolved value (unseen by the load-time lane). The
     * typed LogicException names the option and the accepted shape; the
     * literal lane enforces the identical contract at build time.
     */
    public static function createDsnClient(string $dsn): \Predis\Client
    {
        $violation = self::dsnShapeViolation($dsn);
        if ($violation !== null) {
            throw new \LogicException(sprintf(
                'kiwi_captcha.redis_dsn %s — the value was resolved from the environment at runtime, so the malformed DSN fails closed when the client is constructed instead of connecting to the wrong host.',
                $violation,
            ));
        }

        return new \Predis\Client($dsn);
    }

    /**
     * The fail-closed DSN shape contract shared by the build-time and
     * runtime lanes: a redis:// or rediss:// URL with a host. Returns a
     * description of the violation, or null when the DSN shape is
     * acceptable.
     */
    private static function dsnShapeViolation(mixed $dsn): ?string
    {
        if (!\is_string($dsn)) {
            return 'must be a redis:// or rediss:// URL with a host';
        }
        $parts = parse_url($dsn);
        $scheme = $parts['scheme'] ?? null;
        $host = $parts['host'] ?? null;
        if (!\is_string($scheme) || !\in_array($scheme, ['redis', 'rediss'], true)
            || !\is_string($host) || $host === ''
        ) {
            return sprintf('must be a redis:// or rediss:// URL with a host (got "%s")', $dsn);
        }

        return null;
    }

    /**
     * Whether the value is an env-managed form of a Symfony %env(...)%
     * placeholder. Two shapes reach the extension:
     *  - the raw placeholder '%env(KIWI_REDIS_DSN)%' (plain
     *    ContainerBuilder usage, e.g. unit tests);
     *  - Symfony's env marker (env_<16 hex>_<name>_<32 hex>), the form
     *    MergeExtensionConfigurationPass resolves the placeholder into
     *    before the extension load() runs in a kernel container; the
     *    dumped container resolves the same marker back to the env
     *    value at runtime.
     * Both are opaque at extension time, so the load-time shape
     * validations skip them; the resolved value is validated where it
     * is consumed.
     */
    private static function isEnvPlaceholder(mixed $value): bool
    {
        if (!\is_string($value)) {
            return false;
        }
        if (preg_match('/^%env\([^%]+\)%$/D', $value) === 1) {
            return true;
        }

        return preg_match('/^env_[a-f0-9]{16}_\w+_[a-f0-9]{32}$/iD', $value) === 1;
    }

    /**
     * Whether any raw configuration layer explicitly defines the key
     * (array_key_exists semantics, so an explicit null counts as set).
     * Used to decide whether an explicit service-id knob wins over the
     * high-level redis_dsn setting.
     *
     * @param array<int, array<string, mixed>> $configs
     */
    private static function configLayerDefines(array $configs, string $key): bool
    {
        foreach ($configs as $layer) {
            if (\is_array($layer) && \array_key_exists($key, $layer)) {
                return true;
            }
        }

        return false;
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
     * Apply the risk.redis hardening knobs (wait_replicas / wait_timeout_ms
     * / ttl_margin_secs) to the challenge storage definition when it is a
     * KiwiCaptcha\Storage\RedisStorage.
     *
     * The knobs are only set when they differ from the storage's built-in
     * defaults (wait_replicas > 0 or ttl_margin_secs > 0), so a deployment
     * that never opts in keeps byte-identical behavior and stays compatible
     * with cores predating the parameters.
     *
     * @param array{wait_replicas: int, wait_timeout_ms: int, ttl_margin_secs: int} $redisConfig
     */
    private function applyRedisStorageHardening(Reference $storageRef, array $redisConfig, ContainerBuilder $container): void
    {
        $waitReplicas = $redisConfig['wait_replicas'];
        $ttlMarginSecs = $redisConfig['ttl_margin_secs'];
        if ($waitReplicas <= 0 && $ttlMarginSecs <= 0) {
            return;
        }

        $id = (string) $storageRef;
        if ($container->hasAlias($id)) {
            $id = (string) $container->getAlias($id);
        }
        if (!$container->hasDefinition($id)) {
            return;
        }
        $definition = $container->getDefinition($id);
        $class = $definition->getClass();
        if ($class === null || !is_a($class, RedisStorage::class, true)) {
            return;
        }

        $definition->setArgument('$waitReplicas', $waitReplicas);
        $definition->setArgument('$waitTimeoutMs', $redisConfig['wait_timeout_ms']);
        $definition->setArgument('$ttlMarginSecs', $ttlMarginSecs);
    }

    /**
     * Build the risk-v1 policy config (int-keyed scopes) and the
     * scope-name => int-id map from the bundle's string-keyed scopes node.
     *
     * Scope ids must be unique and stable across deploys: an explicit `id`
     * wins, otherwise the id is crc32(scope name) & 0x7fffffff. Two scopes
     * with the same id would silently share risk state, so the config is
     * refused.
     *
     * Contract invariants for the policy handed to RiskPolicy::fromConfig:
     *  - global_floors is an array of five entries with index 0 = Allow
     *    (level 0 is the idle level). When global_pressure.enabled is
     *    false every floor is Allow, since the global controller is off.
     *  - unknown_scope.mode "minimum" adds a synthetic scope entry
     *    (base_risk 100, minimum/degraded sha20) under a reserved id,
     *    walking down from 1..u32::MAX until it collides with no
     *    configured id. "reject" and "baseline" leave the policy without
     *    it and the gateway declines unknown scopes with
     *    UnknownScopeException (the controller turns "reject" into the
     *    risk-denied 429 and "baseline" into the default challenge).
     *
     * @return array{0: array<string, mixed>, 1: array<string, int>, 2: array<string, bool>, 3: ?int}
     *         [policy config, scope-name => scope-id, scope-name => post_solve_check, synthetic unknown-scope id]
     */
    private function buildRiskPolicy(array $riskConfig): array
    {
        // The risk-v1 policy contract version is internal to the risk
        // package (RiskPolicy::CONTRACT_VERSION): the policy handed to
        // the engine always carries it. The operator's risk.policy_version
        // knob is the challenge security-policy epoch, stamped into
        // issued records and enforced at verification, and completely
        // independent of the risk-v1 contract.
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
     * phpredis (\Redis) client cannot drive the risk-v1 `EVALSHA` store (its
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
                    'kiwi_captcha.risk.enabled cannot reuse the bundle Redis client: its service class stays invisible to the '.
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

    /**
     * Resolve the %%parameter%% placeholders inside a service id (e.g.
     * `rate_limit_cache: '%kiwi.rate_pool%'`), or null when the id carries
     * parameters this container cannot resolve at extension time (a
     * non-existent parameter, an unresolved env var, a non-string value).
     * A plain id without placeholders is returned unchanged.
     */
    private function resolveParameterizedServiceId(string $id, ContainerBuilder $container): ?string
    {
        if (!str_contains($id, '%')) {
            return $id;
        }
        try {
            $resolved = $container->getParameterBag()->resolveValue($id);
        } catch (\Throwable) {
            // ParameterNotFoundException (a missing/env-processed
            // parameter) or any bag refusal: the id is unresolvable here.
            return null;
        }

        return \is_string($resolved) && $resolved !== '' ? $resolved : null;
    }

    /**
     * Resolve the %%parameter%% placeholders inside a definition's class,
     * e.g. `class: '%app.cache.class%'`, to the literal class name, or
     * null when the type stays unresolvable as a string. A missing parameter
     * is NOT silently ignored: the caller's unresolvable path applies,
     * mirroring requireAtomicStorageWhenNeeded()'s %param% class handling
     * but for any placeholder position, not only whole-string params.
     */
    private function resolveParameterizedClass(?string $class, ContainerBuilder $container): ?string
    {
        if ($class === null) {
            return null;
        }
        if (!str_contains($class, '%')) {
            return $class;
        }
        try {
            $resolved = $container->getParameterBag()->resolveValue($class);
        } catch (\Throwable) {
            return null;
        }

        return \is_string($resolved) && $resolved !== '' ? $resolved : null;
    }

    /**
     * The class of a service id, or null when unresolvable. The id is
     * as strict as the storage path's class resolution.
     *  - %%parameter%% placeholders in the service id itself are resolved
     *    through the parameter bag first. A parameter-indirected id such
     *    as `%kiwi.rate_pool%` must not survive unresolved and be treated
     *    as an opaque external id.
     *  - alias chains are followed to the END, bounded and cycle-guarded.
     *    A two-hop alias must resolve to its final target, not exit the
     *    walk after one hop.
     *  - a definition may inherit its class from a parent,
     *    ChildDefinition, exactly what framework.cache.pools generates
     *    for `parent: cache.adapter.array`. The extension loads before
     *    ResolveChildDefinitionsPass flattens those chains, so the
     *    parent chain is walked here.
     *  - a %%param%% class on any definition in the chain is resolved
     *    through the parameter bag. A parameterized class that cannot be
     *    resolved yields null, never a silent pass.
     * The first non-null class in the child->parent chain wins; a chain
     * that ends without a class, an unknown parent, a cycle or an
     * unresolvable parameter yields null, so the service cannot be
     * inspected and the caller's unresolvable-services path applies.
     */
    private function definitionClass(string $id, ContainerBuilder $container): ?string
    {
        $id = $this->resolveParameterizedServiceId($id, $container);
        if ($id === null) {
            return null;
        }
        // Follow alias chains to the end: each hop's target may itself be
        // an alias or a parameter-indirected id. Bounded by a generous
        // hop count and cycle-guarded, so a hostile/self-referential
        // chain terminates with null instead of looping.
        $seenAliases = [];
        while ($container->hasAlias($id)) {
            if (isset($seenAliases[$id]) || \count($seenAliases) >= 32) {
                return null;
            }
            $seenAliases[$id] = true;
            $target = (string) $container->getAlias($id);
            $resolved = $this->resolveParameterizedServiceId($target, $container);
            if ($resolved === null) {
                return null;
            }
            $id = $resolved;
        }
        $seen = [];
        while ($container->hasDefinition($id) && !isset($seen[$id])) {
            $seen[$id] = true;
            $definition = $container->getDefinition($id);
            $class = $this->resolveParameterizedClass($definition->getClass(), $container);
            if ($class !== null) {
                return $class;
            }
            if (!$definition instanceof ChildDefinition) {
                return null;
            }
            $id = $definition->getParent();
        }

        return null;
    }

    /**
     * Whether a wired Redis client is a Predis replication or cluster
     * aggregate, judged from the definition the build can inspect.
     * The classification mirrors the runtime VerifiedWaitGuard and the
     * doctor command. A Predis\Client whose constructor options carry
     * the "replication" (Sentinel or master-slave) or "cluster" option
     * builds a ReplicationInterface or ClusterInterface connection at
     * runtime, so the same topology boundary applies at build time.
     * Returns the aggregate label, null when the client is a single-node
     * direct connection (phpredis, a standalone Predis DSN, a plain tcp
     * parameters array) or when the definition is opaque to the build.
     * An uninspectable client cannot be proven an aggregate and stays
     * allowed, exactly like the runtime guard only refuses what the
     * connection object proves.
     */
    private function predisAggregateLabel(?Reference $ref, ContainerBuilder $container, string $label): ?string
    {
        if ($ref === null) {
            return null;
        }
        $id = $this->resolveParameterizedServiceId((string) $ref, $container);
        if ($id === null) {
            return null;
        }
        $seenAliases = [];
        while ($container->hasAlias($id)) {
            if (isset($seenAliases[$id]) || \count($seenAliases) >= 32) {
                return null;
            }
            $seenAliases[$id] = true;
            $resolved = $this->resolveParameterizedServiceId((string) $container->getAlias($id), $container);
            if ($resolved === null) {
                return null;
            }
            $id = $resolved;
        }
        $seen = [];
        while ($container->hasDefinition($id) && !isset($seen[$id])) {
            $seen[$id] = true;
            $definition = $container->getDefinition($id);
            $class = $this->resolveParameterizedClass($definition->getClass(), $container);
            if ($class !== null && !is_a($class, \Predis\Client::class, true)) {
                // phpredis and every non-Predis client: the runtime
                // guard classifies only Predis aggregates, so the same
                // boundary applies here.
                return null;
            }
            $aggregateOptions = $this->predisAggregateOptions($definition, $container);
            if ($aggregateOptions !== null) {
                if (isset($aggregateOptions['replication'])) {
                    return sprintf('%s is a Predis replication aggregate (Sentinel or master-slave)', $label);
                }
                if (isset($aggregateOptions['cluster'])) {
                    return sprintf('%s is a Predis Redis Cluster aggregate', $label);
                }
            }
            if (!$definition instanceof ChildDefinition) {
                return null;
            }
            $id = $definition->getParent();
        }

        return null;
    }

    /**
     * The constructor-options array of a Predis\Client definition that
     * proves an aggregate topology (a "replication" or "cluster" option
     * key), or null when no argument carries one. Both argument
     * positions are inspected, since the aggregate shape is
     * conventionally options in the second position. %param% values are
     * resolved through the parameter bag. An argument that stays opaque
     * (a Reference, an unresolved parameter) is skipped, never treated
     * as an aggregate.
     */
    private function predisAggregateOptions(Definition $definition, ContainerBuilder $container): ?array
    {
        foreach ($definition->getArguments() as $argument) {
            if (!\is_array($argument)) {
                continue;
            }
            try {
                $resolved = $container->getParameterBag()->resolveValue($argument);
            } catch (\Throwable) {
                continue;
            }
            if (!\is_array($resolved)) {
                continue;
            }
            if (\array_key_exists('replication', $resolved) || \array_key_exists('cluster', $resolved)) {
                return $resolved;
            }
            foreach ($resolved as $entry) {
                if (\is_array($entry) && (\array_key_exists('replication', $entry) || \array_key_exists('cluster', $entry))) {
                    return $entry;
                }
            }
        }

        return null;
    }

    /**
     * Canonicalize the historical secrets map to array<int, string> keys:
     * the single source of truth for the kid-keyed keyring handed to
     * VerificationSecurityContext. The tree has already refused textual
     * aliases and duplicate canonical kids, so this is an int-key
     * projection, deterministically sorted for a stable config value.
     *
     * @param array<int|string, string> $secrets
     *
     * @return array<int, string>
     */
    private static function canonicalHistoricalSecrets(array $secrets): array
    {
        $canonical = [];
        foreach ($secrets as $kid => $secret) {
            $canonical[(int) $kid] = $secret;
        }
        ksort($canonical, SORT_NUMERIC);

        return $canonical;
    }

    /**
     * Whether the installed core's Verifier constructor declares the
     * `$resumeClaimTtlSecs` parameter (the recovery-claim TTL).
     * The bundle wires the named argument only when the parameter exists,
     * because Symfony's ResolveNamedArgumentsPass refuses named arguments
     * the class does not declare, at container compile time.
     */
    private static function coreVerifierAcceptsResumeClaimTtlSecs(): bool
    {
        $constructor = (new \ReflectionClass(Verifier::class))->getConstructor();
        if ($constructor === null) {
            return false;
        }
        foreach ($constructor->getParameters() as $parameter) {
            if ($parameter->getName() === 'resumeClaimTtlSecs') {
                return true;
            }
        }

        return false;
    }

    /**
     * The checked-client factory: constructs the underlying client
     * (lazily, at this wrapper's own construction) and runs the
     * authority-transition guard against the actual instance before any
     * consumer receives it. The guard refuses under fail_closed when
     * the instance is an authority-change aggregate or uninspectable;
     * the same client instance is returned, so the wrapper is
     * transparent to consumers and to later decoration (the
     * pinned-primary guard decorates the raw instance).
     */
    public static function checkedRedisClient(mixed $client, AuthorityTransitionGuard $guard): mixed
    {
        $guard->assertServeEligible($client);

        return $client;
    }

    /**
     * The checked-client seam: wrap a raw client reference in the
     * authority-guard wrapper definition, or return the existing
     * wrapper when this container already checked the same raw client
     * id. The DSN client is shared by the storage, the limiter, the
     * admission and the risk state, so there is one wrapper per raw
     * client per container.
     *
     * The wrapper has no service class (it is a factory definition), so
     * the raw reference MUST be kept for every build-time classification
     * lane; consumers receive the checked reference.
     */
    private function checkedRedisClientRef(?Reference $ref, string $suffix, ContainerBuilder $container): ?Reference
    {
        if ($ref === null) {
            return null;
        }
        $rawId = (string) $ref;
        $containerKey = spl_object_id($container);
        if (isset($this->checkedClientIdsByContainer[$containerKey][$rawId])) {
            return new Reference($this->checkedClientIdsByContainer[$containerKey][$rawId]);
        }
        $base = self::CHECKED_CLIENT_ID.($suffix !== '' ? '.'.$suffix : '');
        $checkedId = $base;
        if ($container->hasDefinition($checkedId) || $container->hasAlias($checkedId)) {
            // A second distinct raw client under the same role label
            // (e.g. a DSN client plus an explicit redis_service): the
            // fallback id carries the sanitized raw id so the wrapper
            // stays deterministic and self-describing.
            $sanitized = preg_replace('/[^A-Za-z0-9_.-]/', '_', $rawId) ?: 'client';
            $checkedId = $base.'.'.$sanitized;
            $i = 1;
            while ($container->hasDefinition($checkedId) || $container->hasAlias($checkedId)) {
                $checkedId = $base.'.'.$sanitized.'.'.(++$i);
            }
        }
        $this->checkedClientIdsByContainer[$containerKey][$rawId] = $checkedId;
        $container->setDefinition($checkedId, (new Definition(\Predis\Client::class))
            ->setFactory([self::class, 'checkedRedisClient'])
            ->setArguments([$ref, new Reference(self::AUTHORITY_GUARD_ID)])
            ->setPublic(true));

        return new Reference($checkedId);
    }

    /**
     * Route the client of a RedisStorage definition through the
     * checked-client seam: the durability-critical pending->consumed
     * transition lives in RedisStorage, so under fail_closed its own
     * client must be classified at storage construction like every
     * other Redis-backed consumer. The definition's client argument (a
     * Reference) is replaced by the checked wrapper; an unresolvable
     * definition, a non-RedisStorage class or a non-Reference client
     * argument stays untouched (the consumers' own seam and the
     * build-time lanes cover the visible paths).
     */
    private function guardStorageClientByStorageValue(string $storage, ContainerBuilder $container): void
    {
        $id = $this->resolveServiceId($storage, $container);
        if ($id === null || !$container->hasDefinition($id)) {
            return;
        }
        $definition = $container->getDefinition($id);
        $class = $this->resolveParameterizedClass($definition->getClass(), $container);
        if ($class === null || !is_a($class, RedisStorage::class, true)) {
            return;
        }
        $client = $definition->getArgument(0);
        if (!$client instanceof Reference) {
            return;
        }
        $definition->setArgument(0, $this->checkedRedisClientRef($client, 'storage', $container));
    }

    /**
     * The prepend-time storage patch: parse the configured storage
     * value from the raw kiwi_captcha config layers and route its
     * client through the checked seam on the real container, where an
     * application-defined storage definition is visible.
     */
    private function guardAppDefinedStorageClients(ContainerBuilder $container): void
    {
        $storage = null;
        foreach ($container->getExtensionConfig('kiwi_captcha') as $layer) {
            if (\is_array($layer) && \array_key_exists('storage', $layer)) {
                $storage = $layer['storage'];
            }
        }
        if (\is_string($storage) && $storage !== '') {
            $this->guardStorageClientByStorageValue($storage, $container);
        }
    }

    /**
     * Resolve a configured service id through %%parameter%% placeholders
     * and alias chains to its final definition id, or null when
     * unresolvable (a missing parameter, an env marker, an alias cycle,
     * an over-long chain).
     */
    private function resolveServiceId(string $id, ContainerBuilder $container): ?string
    {
        $id = $this->resolveParameterizedServiceId($id, $container);
        $seenAliases = [];
        while ($id !== null && $container->hasAlias($id)) {
            if (isset($seenAliases[$id]) || \count($seenAliases) >= 32) {
                return null;
            }
            $seenAliases[$id] = true;
            $id = $this->resolveParameterizedServiceId((string) $container->getAlias($id), $container);
        }

        return $id;
    }
}
