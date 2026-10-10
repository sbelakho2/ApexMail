<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Controller;

use BelConsulting\KiwiCaptchaBundle\Security\Authority\PinnedAuthorityRefusalException;

use BelConsulting\KiwiCaptchaBundle\RedisNamespace;
use BelConsulting\KiwiCaptchaBundle\Security\Authority\PinnedPrimaryAuthorityGuard;
use KiwiCaptcha\ChallengeProfile;
use KiwiCaptcha\ChallengeRecord;
use KiwiCaptcha\ExecutionChallengeGenerator;
use KiwiCaptcha\ExecutionVersionPolicy;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Response;

/**
 * Rollback-resistant liveness/readiness split.
 *
 *  - `/health/live` always 200 while the process runs. Never tied to
 *    saturation, Redis, or any external state: a process that is up is
 *    "live" (the orchestrator only cares that the worker exists and can
 *    answer).
 *
 *  - `/health/ready` is 200 only when all of:
 *      1. the issuer/verifier signing keys are configured (the bundle
 *         secret is required, so this is normally trivially true);
 *      2. the security Redis is reachable: a PING probe, cached ~1 s
 *         in-process. Transient probe timeouts never fail readiness on
 *         their own: the first failure is debounced for one cache window
 *         (a blip that recovers within ~1 s keeps the last healthy
 *         state), and two consecutive failures flip readiness. Argon
 *         queue fullness is never consulted.
 *      3. the central security-policy state is compatible: the Redis key
 *         `{kiwi:<ns>}:security-policy` (a hash with
 *         `min_protocol_version`, `min_policy_epoch` and the optional
 *         `min_execution_version`). When the key is
 *         present, ready requires min_protocol_version <= 5 (this
 *         binary's max protocol version, the identity-bearing rsw
 *         canonical), min_execution_version <=
 *         {@see self::MAX_EXECUTION_VERSION} (an absent field imposes
 *         nothing). A protocol or execution floor above the
 *         binary's maximum (mixed-version rolling deployments,
 *         rollbacks) takes an outdated binary out of the pool before it
 *         serves traffic it cannot honor. A central min_policy_epoch
 *         above the configured risk.policy_version is only a warning:
 *         the node stays in the pool, and issuance and verification
 *         follow the effective epoch max(configured, central); the lag
 *         is logged and never drains the node. When the key is absent
 *         the binary's own configuration is authoritative.
 *      4. when the execution dimension is armed
 *         (risk.execution_challenge on), the required execution tier
 *         must be satisfiable. The effective fleet tier is the policy
 *         minimum of the node cap, the central min_execution_version
 *         floor (absent counts as version 1) and
 *         {@see self::MAX_EXECUTION_VERSION}. A required tier above it
 *         returns 503 with the reason
 *         security_policy_incompatible:execution_required_R_effective_E.
 *         Every armed request would refuse every client, so the node
 *         must not serve until the fleet floor reaches the required
 *         tier. The leg is inert when the gate is off.
 *      5. the memory-budget invariant holds (only when
 *         risk.container_memory_mib is configured):
 *         `argon2_max_concurrent_verifications x the fixed Argon
 *         verification envelope (risk.argon_verification_memory_kib, the
 *         risk ladder's worst-case per-verification memory, default
 *         16384 KiB) + 256 MiB headroom <= container_memory_mib`. A
 *         violated invariant refuses startup (503 memory_budget_invariant).
 *         When container_memory_mib is null (or the concurrency cap is 0
 *         = unlimited) the check is skipped: the invariant is only
 *         meaningful with a finite cap, and an unlimited cap needs an
 *         explicit budget decision.
 *      6. the pinned-primary authority is eligible (only under
 *         `ha_authority: pinned_primary` / the `ha_safe` profile): every
 *         wired authority guard passes a fresh check. The guard's
 *         ordinary verification window is deliberately bypassed. A pod
 *         whose pin is uninitialized or whose authority changed (a
 *         restarted primary with a new run_id, a re-pointed endpoint) is
 *         taken out of the pool immediately, never inside a stale
 *         window. A failing authority returns 503 with the
 *         machine-readable reason ha_authority_uninitialized /
 *         ha_authority_changed / ha_authority_unreachable. When
 *         ha_authority is none (no guards wired) the leg passes
 *         silently.
 *
 * The route paths follow the configured route_prefix (default
 * /kiwi-captcha/health/live + /health/ready) and are registered by
 * {@see \BelConsulting\KiwiCaptchaBundle\Routing\KiwiCaptchaRouteLoader}
 * when risk.health.enabled is true (default).
 *
 * Every response is a private JSON document (never cached by proxies or
 * CDNs).
 */
final class KiwiHealthController
{
    /**
     * The binary's maximum challenge protocol version: 5 since the
     * identity-bearing rsw canonical (protocol v5) landed —
     * identity-armed rsw issuance writes version 5 and the verifier
     * accepts versions 1..5. A central security-policy hash demanding a
     * higher version means this binary cannot verify the challenges the
     * fleet now issues, so it must not be ready. The single shared
     * maximum: the php-core
     * ({@see \KiwiCaptcha\ChallengeRecord::MAX_PROTOCOL_VERSION}), the
     * Rust crate (`challenge::MAX_PROTOCOL_VERSION`) and the
     * kiwicaptcha:doctor deploy gate all pin the same value.
     */
    public const MAX_PROTOCOL_VERSION = ChallengeRecord::MAX_PROTOCOL_VERSION;

    /**
     * The binary's maximum execution-program version, taken from the
     * core generator that emits the programs
     * ({@see ExecutionChallengeGenerator::MAX_EXECUTION_VERSION}), so
     * the readiness max can never drift from the emission max. A
     * central security-policy hash demanding a higher execution
     * version means this binary cannot honor the programs the fleet
     * now writes, so it must not be ready.
     */
    public const MAX_EXECUTION_VERSION = ExecutionChallengeGenerator::MAX_EXECUTION_VERSION;

    /** Fixed headroom of the memory-budget invariant, in MiB. */
    public const MEMORY_HEADROOM_MIB = 256;

    /** In-process probe/state cache window in ms. */
    private const CACHE_MS = 1000;

    /** The readiness-result cache TTL in s (the ~1 s burst-saving window). */
    private const CACHE_TTL_SECS = 1;

    /**
     * The probe-debounce state TTL in s: the consecutive-failure
     * counter must survive the 1 s readiness-result cache expiry. A
     * per-second cache rotation must never reset the debounce — a first
     * failure debounced in one request must still be the first failure
     * for the next one, so the state outlives the cache window by a
     * full minute.
     */
    private const PROBE_STATE_TTL_SECS = 60;

    /**
     * The epoch-lag warning de-dup TTL in s: the last logged lag
     * detail is stored on first log and re-logged only when it
     * changes — once per change, not once per request — and the bound
     * keeps the APCu entry finite.
     */
    private const EPOCH_LAG_DEDUP_TTL_SECS = 3600;

    private ?bool $lastPolicyOk = null;
    private ?string $policyReason = null;
    private ?string $policyEpochLag = null;

    /**
     * The in-process fallback used when the APCu extension is absent or
     * disabled: the last logged epoch-lag detail. With APCu available
     * the de-dup marker lives in APCu keyed per deployment (namespace
     * and secret), so separate workers of one deployment never re-log
     * an unchanged lag; see {@see self::logEpochLagOnce()}.
     */
    private ?string $lastLoggedEpochLag = null;
    private float $policyAtMs = -PHP_FLOAT_MAX;

    /**
     * The in-process fallback used when the APCu extension is absent or
     * disabled: the debounce state. With APCu available it lives in APCu
     * keyed per deployment (namespace and secret), so separate apps
     * sharing one APCu segment cannot read each other's debounce state;
     * see {@see self::readinessStateGet()}.
     */
    private ?array $localReadinessState = null;

    /**
     * @param \Redis|\Predis\Client|null $redis         the security Redis
     *                                                   client. Null = no
     *                                                   external security
     *                                                   state, so the Redis
     *                                                   legs are vacuous.
     * @param string                     $namespace     the raw configured
     *                                                   risk namespace: the
     *                                                   readiness probe
     *                                                   derives the central
     *                                                   policy key through
     *                                                   the one shared
     *                                                   derivation, and on
     *                                                   the digest key
     *                                                   version also reads
     *                                                   the legacy segment
     *                                                   (the migration
     *                                                   safety net).
     * @param int                        $policyVersion the configured
     *                                                   risk.policy_version.
     * @param callable(): float|null     $nowMs         clock override
     *                                                   (tests).
     * @param int                        $argonConcurrency  the configured
     *                                                   argon2_max_concurrent_
     *                                                   verifications (0 =
     *                                                   unlimited; the
     *                                                   invariant treats it
     *                                                   as 1, so at least
     *                                                   one hash must fit).
     * @param int|null                   $containerMemoryMib risk.container_
     *                                                   memory_mib; null
     *                                                   (default) skips the
     *                                                   invariant.
     * @param int                        $argonEnvelopeMemoryKib the fixed
     *                                                   adaptive verification
     *                                                   memory envelope
     *                                                   (risk.argon_verification_
     *                                                   memory_kib), the
     *                                                   worst-case
     *                                                   per-verification
     *                                                   memory of the risk
     *                                                   ladder.
     * @param array<string, PinnedPrimaryAuthorityGuard> $authorityGuards
     *                                                   the wired pinned-
     *                                                   primary authority
     *                                                   guards keyed by
     *                                                   authority label
     *                                                   ("storage", "risk"),
     *                                                   empty when
     *                                                   ha_authority is not
     *                                                   pinned_primary (the
     *                                                   leg then passes
     *                                                   silently).
     * @param \Predis\Client|null        $riskRedis      the distinct risk
     *                                                   Redis client (the
     *                                                   client the risk
     *                                                   authority guard
     *                                                   verifies), null
     *                                                   when absent or when
     *                                                   the risk client IS
     *                                                   the storage client.
     * @param bool                       $executionGate  whether
     *                                                   risk.execution_challenge
     *                                                   is on; the
     *                                                   required-tier leg
     *                                                   applies only when
     *                                                   the dimension is
     *                                                   armed.
     * @param int                        $executionVersionCap the node's
     *                                                   execution_version
     *                                                   cap (1..4).
     * @param int                        $executionRequiredVersion the
     *                                                   server-owned
     *                                                   execution_required_
     *                                                   version tier.
     * @param \Psr\Log\LoggerInterface|null $logger    where the private
     *                                                   readiness detail
     *                                                   and the warnings
     *                                                   go (error_log
     *                                                   otherwise).
     * @param \Closure|null              $apcu         APCu override
     *                                                   (tests): a
     *                                                   two-operation
     *                                                   seam over the
     *                                                   shared segment,
     *                                                   ('fetch', key)
     *                                                   and ('store',
     *                                                   key, value, ttl),
     *                                                   so separate
     *                                                   instances can
     *                                                   simulate separate
     *                                                   workers of one
     *                                                   deployment. Null
     *                                                   uses the real
     *                                                   APCu when loaded.
     */
    public function __construct(
        private readonly string $secretKey,
        private readonly \Redis|\Predis\Client|null $redis,
        private readonly string $namespace,
        private readonly int $policyVersion,
        private $nowMs = null,
        private readonly int $argonConcurrency = 0,
        private readonly ?int $containerMemoryMib = null,
        private readonly int $argonEnvelopeMemoryKib = 16384,
        private readonly array $authorityGuards = [],
        private readonly \Predis\Client|null $riskRedis = null,
        private readonly bool $executionGate = false,
        private readonly int $executionVersionCap = 1,
        private readonly int $executionRequiredVersion = 1,
        private readonly int $namespaceKeyVersion = RedisNamespace::VERSION_LEGACY,
        private readonly bool $readLegacyFallback = true,
        private readonly ?\Psr\Log\LoggerInterface $logger = null,
        private readonly ?\Closure $apcu = null,
    ) {
    }

    /**
     * Liveness: the process is up. Always 200 — never tied to saturation,
     * Redis reachability, or policy state.
     */
    public function live(): JsonResponse
    {
        return $this->json(['status' => 'live']);
    }

    /**
     * Readiness: the process may receive traffic. 503 (not ready) with a
     * generic machine-readable reason when a leg fails; the actionable
     * detail (the failing authority label, the required protocol/policy
     * versions) is logged, never exposed on this unauthenticated route.
     * The route is public by default and belongs behind an internal
     * network or an allowlist; the result is cached for about a second so
     * a burst of probes cannot turn into a Redis/authority check storm
     * (APCu when available, otherwise per-process).
     */
    public function ready(): JsonResponse
    {
        $cached = $this->readinessCacheGet();
        if ($cached !== null) {
            return $this->json($cached['body'], $cached['status']);
        }

        [$status, $body, $detail, $lag] = $this->evaluateReadiness();
        if ($detail !== null) {
            $this->logReadinessDetail($detail);
        }
        if ($lag !== null) {
            // The readiness endpoint is polled: log the lag when it
            // appears or changes, not on every ~1 s evaluation.
            $this->logEpochLagOnce($lag);
        }
        $this->readinessCachePut(['body' => $body, 'status' => $status]);

        return $this->json($body, $status);
    }

    /**
     * The readiness evaluation, returning [http status, public body,
     * optional private detail for the log, optional non-fatal epoch-lag
     * warning for the log].
     *
     * @return array{0: int, 1: array<string, string>, 2: ?string, 3: ?string}
     */
    private function evaluateReadiness(): array
    {
        if ($this->secretKey === '') {
            return [Response::HTTP_SERVICE_UNAVAILABLE, ['status' => 'not_ready', 'reason' => 'signing_keys_not_configured'], null, null];
        }
        if (!$this->securityRedisReachable()) {
            return [Response::HTTP_SERVICE_UNAVAILABLE, ['status' => 'not_ready', 'reason' => 'security_redis_unreachable'], 'security redis unreachable', null];
        }
        [$policyOk, $reason, $lag] = $this->securityPolicyCompatible();
        if (!$policyOk) {
            return [Response::HTTP_SERVICE_UNAVAILABLE, ['status' => 'not_ready', 'reason' => 'security_policy_incompatible'], 'security policy incompatible: '.($reason ?? 'unknown'), $lag];
        }
        if (!$this->memoryBudgetOk()) {
            return [Response::HTTP_SERVICE_UNAVAILABLE, ['status' => 'not_ready', 'reason' => 'memory_budget_invariant'], 'memory budget invariant failed', $lag];
        }
        [$authorityOk, $authorityReason, $authorityLabel] = $this->authorityEligible();
        if (!$authorityOk) {
            return [Response::HTTP_SERVICE_UNAVAILABLE, ['status' => 'not_ready', 'reason' => 'authority_not_eligible'], 'authority not eligible: '.$authorityReason.' ('.($authorityLabel ?? 'unknown').')', $lag];
        }

        return [Response::HTTP_OK, ['status' => 'ready'], null, $lag];
    }

    /**
     * The per-deployment APCu key: namespace and secret keep two apps
     * that share one APCu segment from reading each other's readiness
     * answer or debounce state.
     */
    public static function readinessCacheKey(string $namespace, string $secretKey): string
    {
        return 'kiwicaptcha.health.readiness.'.hash('sha256', $namespace."\0".$secretKey);
    }

    /**
     * The 1 s readiness cache is APCu-backed and per-deployment keyed;
     * without APCu the probe evaluates per request. A process-local
     * fallback would serve a stale answer past an authority change and
     * leak across unrelated requests in long-lived runtimes, and across
     * tests, so correctness beats the burst-saving. The probe debounce
     * state keeps an instance fallback instead, see
     * {@see self::readinessStateGet()}.
     *
     * @return array{body: array<string,string>, status: int}|null
     */
    private function readinessCacheGet(): ?array
    {
        $now = (int) $this->nowMs();
        $hit = $this->apcuGet(self::readinessCacheKey($this->namespace, $this->secretKey));
        if (!\is_array($hit) || !isset($hit['atMs'], $hit['body'], $hit['status'])) {
            return null;
        }
        if ($now - (int) $hit['atMs'] >= self::CACHE_MS) {
            return null;
        }

        return ['body' => $hit['body'], 'status' => (int) $hit['status']];
    }

    /** @param array{body: array<string,string>, status: int} $result */
    private function readinessCachePut(array $result): void
    {
        $this->apcuPut(self::readinessCacheKey($this->namespace, $this->secretKey), [
            'body' => $result['body'],
            'status' => $result['status'],
            'atMs' => (int) $this->nowMs(),
        ], self::CACHE_TTL_SECS);
    }

    /**
     * The security-Redis probe debounce state, kept next to the readiness
     * cache: in APCu when available (shared across workers of one
     * deployment), otherwise per-instance.
     *
     * @return array{probeOk: ?bool, pendingProbeFailure: bool, probeAtMs: float}
     */
    private function readinessStateGet(): array
    {
        $state = $this->apcuGet(self::readinessCacheKey($this->namespace, $this->secretKey).'.state');
        if (!\is_array($state)) {
            $state = $this->localReadinessState;
        }
        if (!\is_array($state)) {
            return ['probeOk' => null, 'pendingProbeFailure' => false, 'probeAtMs' => -PHP_FLOAT_MAX];
        }

        return [
            'probeOk' => \is_bool($state['probeOk'] ?? null) ? $state['probeOk'] : null,
            'pendingProbeFailure' => (bool) ($state['pendingProbeFailure'] ?? false),
            'probeAtMs' => (float) ($state['probeAtMs'] ?? -PHP_FLOAT_MAX),
        ];
    }

    /**
     * @param array{probeOk: ?bool, pendingProbeFailure: bool, probeAtMs: float} $state
     */
    private function readinessStatePut(array $state): void
    {
        $this->apcuPut(self::readinessCacheKey($this->namespace, $this->secretKey).'.state', $state, self::PROBE_STATE_TTL_SECS);
        $this->localReadinessState = $state;
    }

    private function apcuGet(string $key): mixed
    {
        if ($this->apcu !== null) {
            return ($this->apcu)('fetch', $key);
        }
        if (!\function_exists('apcu_fetch')) {
            return null;
        }
        $ok = false;
        $value = @apcu_fetch($key, $ok);
        if (!$ok) {
            return null;
        }

        return $value;
    }

    /**
     * Store with the caller's window ($ttl seconds): the 1 s TTL
     * belongs to the readiness-result cache only, while the debounce
     * state and the log de-dup markers outlive it. A disabled or
     * failing APCu (for example a CLI process without apc.enable_cli)
     * degrades to the instance fallback, so the probe debounce stays
     * correct.
     */
    private function apcuPut(string $key, mixed $value, int $ttl): void
    {
        if ($this->apcu !== null) {
            ($this->apcu)('store', $key, $value, $ttl);

            return;
        }
        if (!\function_exists('apcu_store')) {
            return;
        }
        @apcu_store($key, $value, $ttl);
    }

    private function logReadinessDetail(string $detail): void
    {
        if ($this->logger !== null) {
            $this->logger->warning('KiwiCaptcha readiness failed: {detail}', ['detail' => $detail]);

            return;
        }
        error_log('KiwiCaptcha readiness failed: '.$detail);
    }

    /**
     * Log a non-fatal readiness warning, distinct from a refusal: the
     * public status stays ready.
     */
    private function logReadinessWarning(string $detail): void
    {
        if ($this->logger !== null) {
            $this->logger->warning('KiwiCaptcha readiness warning: {detail}', ['detail' => $detail]);

            return;
        }
        error_log('KiwiCaptcha readiness warning: '.$detail);
    }

    /**
     * Log the epoch-lag warning once per change: the last logged lag
     * detail is an APCu-backed marker (TTL
     * {@see self::EPOCH_LAG_DEDUP_TTL_SECS}) so separate workers of one
     * deployment de-duplicate each other under PHP-FPM. The lag logs
     * once per change, not once per request; the instance-property
     * fallback keeps the de-dup for the APCu-absent CLI case, the same
     * degradation style as {@see self::readinessStateGet()}.
     */
    private function logEpochLagOnce(string $lag): void
    {
        $key = self::readinessCacheKey($this->namespace, $this->secretKey).'.epochLagLogged';
        $last = $this->apcuGet($key);
        if (!\is_string($last)) {
            $last = $this->lastLoggedEpochLag;
        }
        if ($last === $lag) {
            return;
        }
        $this->logReadinessWarning($lag);
        $this->lastLoggedEpochLag = $lag;
        $this->apcuPut($key, $lag, self::EPOCH_LAG_DEDUP_TTL_SECS);
    }

    /**
     * The pinned-primary authority-eligibility leg: under
     * `ha_authority: pinned_primary` (and the `ha_safe` profile) the pod
     * is ready only when every wired authority guard passes a fresh
     * check. The check calls {@see PinnedPrimaryAuthorityGuard::
     * assertServeEligible()} with the security-final lane, which bypasses
     * the guard's ordinary verification window. A readiness probe must
     * never serve on a cached verification from before an authority
     * change. A load balancer would otherwise route traffic to an
     * instance that is no longer security-eligible. When ha_authority is
     * none (no guards wired) the leg passes silently.
     *
     * @return array{0: bool, 1: string, 2: ?string} [ok, machine-readable
     *         reason, the authority label that failed (null when none)]
     */
    private function authorityEligible(): array
    {
        foreach ($this->authorityGuards as $label => $guard) {
            if (!$guard instanceof PinnedPrimaryAuthorityGuard) {
                continue;
            }
            $client = $label === 'risk' ? $this->riskRedis : $this->redis;
            if ($client === null) {
                return [false, 'ha_authority_unreachable', $label];
            }
            try {
                // securityFinal = true: the fresh check bypasses the
                // verification window, exactly like a security-final
                // transition would.
                $guard->assertServeEligible($client, true);
            } catch (PinnedAuthorityRefusalException $e) {
                if ($e->pinnedIdentity() === null) {
                    // No pin and no ha_authority_expected identity: the
                    // deployment never bootstrapped the authority.
                    return [false, 'ha_authority_uninitialized', $label];
                }
                if ($e->observedIdentity() === null) {
                    // The serving identity could not be read at all (the
                    // info probe failed): unverifiable means stale, never
                    // a pass.
                    return [false, 'ha_authority_unreachable', $label];
                }

                // The pinned/expected identity and the serving identity
                // differ: a promotion, a restarted primary, a re-point.
                return [false, 'ha_authority_changed', $label];
            } catch (\Throwable) {
                // The check could not run at all: fail closed, never pass.
                return [false, 'ha_authority_unreachable', $label];
            }
        }

        return [true, 'ha_authority_ok', null];
    }

    /**
     * The memory-budget readiness invariant:
     * `argon_concurrency` x `MAX_PROFILE_MIB` + `MEMORY_HEADROOM_MIB`
     * `<= container_memory_mib`. True when the budget is null (the check is
     * skipped and documented) or the budget is large enough. A container
     * that cannot hold the worst-case verification memory load must not
     * serve traffic, since OOM in the middle of a memory-hard hash is a
     * security failure, not just an availability one.
     *
     * A concurrency cap of 0 means "unlimited". An unlimited memory-hard
     * workload has NO finite worst-case concurrency, so a finite
     * container budget can never prove the invariant: the health check
     * answers not-ready (and the container refuses the combination at
     * compile time), never a silently floored 1.
     */
    public function memoryBudgetOk(): bool
    {
        if ($this->containerMemoryMib === null) {
            return true;
        }
        if ($this->argonConcurrency <= 0) {
            return false;
        }
        $required = $this->argonConcurrency * $this->maxProfileMib() + self::MEMORY_HEADROOM_MIB;

        return $this->containerMemoryMib >= $required;
    }

    /**
     * Max accepted-record memory in MiB, the readiness budget's
     * per-verification worst case. Two distinct ceilings must be kept
     * separate.
     *
     * First, the new adaptive issuance envelope
     * (risk.argon_verification_memory_kib, default 16384 KiB): the risk
     * ladder issues Argon challenges at this fixed memory, escalating
     * only the nonce-search target, the intended operational model.
     *
     * Second, the maximum accepted historical and cross-service record
     * envelope (ChallengeProfile::argon64, 65536 KiB). The verifier's
     * process ceilings still accept pre-rotation or cross-service
     * records up to this ceiling, so a concurrent verification of such
     * a record can reach 64 MiB even though nothing new is issued
     * there.
     *
     * The readiness budget conservatively uses the max of the two: a
     * deployment is only declared healthy when its memory can cover the
     * worst accepted record, not only the new-issuance envelope. When
     * the configured envelope exceeds the classic argon64 ceiling (a
     * raised knob), the configured value wins.
     */
    private function maxProfileMib(): int
    {
        $envelope = max(ChallengeProfile::argon64()->mKib, $this->argonEnvelopeMemoryKib);

        return (int) ceil($envelope / 1024);
    }

    /**
     * Security Redis reachability: a PING probe, cached ~1 s. The
     * debounce state lives next to the readiness cache: in APCu when
     * available so it is shared across the workers of one deployment,
     * otherwise per instance.
     *
     * Transient timeouts never fail readiness on their own: the first
     * failed probe is debounced for one cache window. A blip that recovers
     * within ~1 s keeps the last healthy state; a second consecutive
     * failure, or a failure on a freshly booted process, flips readiness.
     * A probe exception (timeout or refused) is a probe failure, never a
     * propagated error.
     */
    private function securityRedisReachable(): bool
    {
        if ($this->redis === null) {
            // No security Redis configured: there is nothing to probe.
            return true;
        }
        $now = $this->nowMs();
        $state = $this->readinessStateGet();
        if ($now - $state['probeAtMs'] < self::CACHE_MS) {
            return $state['probeOk'] ?? true;
        }

        $ok = false;
        try {
            $result = $this->redis->ping();
            // phpredis: true; Predis: the `PONG` Status response object.
            $ok = $result === true || (string) $result === 'PONG';
        } catch (\Throwable) {
            $ok = false;
        }

        if (!$ok) {
            if ($state['probeOk'] === true && !$state['pendingProbeFailure']) {
                // First failure after a healthy state: debounce, keeping
                // the last healthy result for one more cache window.
                $state['pendingProbeFailure'] = true;
            } else {
                $state['probeOk'] = false;
                $state['pendingProbeFailure'] = false;
            }
        } else {
            $state['probeOk'] = true;
            $state['pendingProbeFailure'] = false;
        }
        $state['probeAtMs'] = $now;
        $this->readinessStatePut($state);

        return $state['probeOk'] ?? true;
    }

    /**
     * Central security-policy compatibility (cached ~1 s):
     * `{kiwi:<ns>}:security-policy` hash. When present, ready requires
     * min_protocol_version <= {@see self::MAX_PROTOCOL_VERSION} and
     * min_execution_version <= {@see self::MAX_EXECUTION_VERSION} (an
     * absent execution floor imposes nothing). When absent (or when no
     * Redis is configured) the binary's own configuration is
     * authoritative.
     *
     * A central min_policy_epoch above the configured risk.policy_version
     * does NOT remove the node: issuance stamps the effective epoch
     * max(configured, central), so the node can follow a central bump.
     * The lag is reported as a non-fatal warning for the log, never a
     * readiness failure.
     *
     * On top of the central state, the execution-gate leg applies
     * whenever risk.execution_challenge is on. The shared
     * {@see ExecutionVersionPolicy} derives the effective fleet tier
     * from the node cap and the central min_execution_version floor
     * (absent or 0 counts as version 1). A configured
     * execution_required_version above the effective tier refuses
     * readiness: every armed request would refuse every client in that
     * state, so the node must not serve until the fleet floor reaches
     * the required tier.
     *
     * @return array{0: bool, 1: ?string, 2: ?string} [compatible,
     *         machine-readable reason, epoch-lag warning detail]
     */
    private function securityPolicyCompatible(): array
    {
        if ($this->redis === null) {
            // No security Redis by design: the central policy legs are
            // vacuous, but the execution-gate leg still applies with an
            // unconfirmed floor (effective tier 1 at best).
            [$ok, $reason] = $this->withExecutionGateLeg(true, null, null);

            return [$ok, $reason, null];
        }
        $now = $this->nowMs();
        if ($now - $this->policyAtMs < self::CACHE_MS) {
            return [$this->lastPolicyOk ?? true, $this->policyReason, $this->policyEpochLag];
        }

        $ok = true;
        $reason = null;
        $minProtocol = null;
        $minEpoch = null;
        $minExecution = null;
        try {
            foreach (RedisNamespace::readNamespaces($this->namespace, 'kiwi', $this->namespaceKeyVersion, $this->readLegacyFallback) as $policyNamespace) {
                $policy = $this->redis->hgetall('{kiwi:'.$policyNamespace.'}:security-policy');
                if (!\is_array($policy) || $policy === []) {
                    continue;
                }
                // Corrupt present policy state must fail closed: a
                // malformed min_protocol_version / min_policy_epoch /
                // min_execution_version (abc, -1, 1.5, 1e3, overflow)
                // makes the node NOT ready — it is never silently
                // collapsed toward zero and interpreted as absent.
                foreach (['min_protocol_version', 'min_policy_epoch', 'min_execution_version'] as $field) {
                    if (\array_key_exists($field, $policy)) {
                        $raw = $policy[$field];
                        if (!\is_string($raw) || preg_match('/^(?:0|[1-9][0-9]*)$/D', $raw) !== 1) {
                            $ok = false;
                            $reason = 'security_policy_state_corrupt:'.$field;
                        } else {
                            $parsedField = (int) $raw;
                            if ((string) $parsedField !== $raw) {
                                $ok = false;
                                $reason = 'security_policy_state_corrupt:'.$field;
                            }
                        }
                    }
                }
                if (!$ok) {
                    break;
                }
                // Conservative merge across the consulted namespaces (the
                // configured derivation plus the legacy one on the digest
                // key version): the strongest declared floor wins, so a
                // legacy revocation stays effective after the namespace
                // cutover.
                $minProtocol = max($minProtocol ?? 0, (int) ($policy['min_protocol_version'] ?? 0));
                $minEpoch = max($minEpoch ?? 0, (int) ($policy['min_policy_epoch'] ?? 0));
                $minExecution = max($minExecution ?? 0, (int) ($policy['min_execution_version'] ?? 0));
            }
            if ($ok && $minEpoch !== null) {
                if ($minProtocol > self::MAX_PROTOCOL_VERSION) {
                    $ok = false;
                    $reason = 'security_policy_incompatible:min_protocol_version_'.$minProtocol;
                } elseif ($minExecution > self::MAX_EXECUTION_VERSION) {
                    $ok = false;
                    $reason = 'security_policy_incompatible:min_execution_version_'.$minExecution;
                }
            }
        } catch (\Throwable) {
            $ok = false;
            $reason = 'security_policy_state_unavailable';
        }
        [$ok, $reason] = $this->withExecutionGateLeg($ok, $reason, $minExecution);
        $lag = $minEpoch !== null && $minEpoch > $this->policyVersion
            ? $this->epochLagDetail($minEpoch)
            : null;
        $this->lastPolicyOk = $ok;
        $this->policyReason = $reason;
        $this->policyEpochLag = $lag;
        $this->policyAtMs = $now;

        return [$ok, $reason, $lag];
    }

    /**
     * The non-fatal epoch-lag warning detail: the central
     * min_policy_epoch is ahead of the configured risk.policy_version,
     * so issuance follows the central value. The node stays ready.
     */
    private function epochLagDetail(int $centralEpoch): string
    {
        return sprintf(
            'security policy epoch lag: the central min_policy_epoch is %d while risk.policy_version is %d. Issuance and verification follow the effective epoch %d, so new challenges verify immediately. Raise risk.policy_version to the central value at the next coordinated deploy to align the configured floor',
            $centralEpoch,
            $this->policyVersion,
            max($centralEpoch, $this->policyVersion),
        );
    }

    /**
     * The execution-gate leg of the central-policy compatibility:
     * derives the effective fleet tier through the shared
     * ExecutionVersionPolicy and refuses readiness when the required
     * execution tier is above it. The fleet floor is the parsed
     * central min_execution_version when above 0, else version 1 (an
     * unconfirmed or undeclared floor confirms nothing). The leg is
     * inert when risk.execution_challenge is off.
     *
     * @param int|null $fleetFloor the parsed central execution floor,
     *                             null when no central policy was read
     *
     * @return array{0: bool, 1: ?string} [compatible, machine-readable reason]
     */
    private function withExecutionGateLeg(bool $ok, ?string $reason, ?int $fleetFloor): array
    {
        if (!$this->executionGate) {
            return [$ok, $reason];
        }
        $floorForPolicy = $fleetFloor === null || $fleetFloor < 1 ? 1 : $fleetFloor;
        $effective = (new ExecutionVersionPolicy($this->executionVersionCap, $floorForPolicy))
            ->effectiveAvailableTier();
        if ($this->executionRequiredVersion > $effective) {
            return [false, sprintf('security_policy_incompatible:execution_required_%d_effective_%d', $this->executionRequiredVersion, $effective)];
        }

        return [$ok, $reason];
    }

    /**
     * @param array<string, mixed> $data
     */
    private function json(array $data, int $status = Response::HTTP_OK): JsonResponse
    {
        $response = new JsonResponse($data, $status);
        // Health status is a dynamic document: never cached or mirrored.
        $response->headers->set('Cache-Control', 'no-store, private, max-age=0');
        $response->headers->set('Pragma', 'no-cache');
        $response->headers->set('X-Content-Type-Options', 'nosniff');

        return $response;
    }

    private function nowMs(): float
    {
        return $this->nowMs !== null ? (float) ($this->nowMs)() : microtime(true) * 1000;
    }
}
