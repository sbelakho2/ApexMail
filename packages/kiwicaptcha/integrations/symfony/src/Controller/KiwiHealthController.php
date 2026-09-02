<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Controller;

use BelConsulting\KiwiCaptchaBundle\Security\Authority\PinnedAuthorityRefusalException;
use BelConsulting\KiwiCaptchaBundle\Security\Authority\PinnedPrimaryAuthorityGuard;
use KiwiCaptcha\ChallengeProfile;
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
 *         `min_protocol_version` and `min_policy_epoch`). When the key is
 *         present, ready requires min_protocol_version <= 4 (this
 *         binary's max protocol version, the execution-capable
 *         canonical) and min_policy_epoch <= the
 *         configured risk.policy_version. A newer central policy
 *         (mixed-version rolling deployments, rollbacks) takes an
 *         outdated binary out of the pool before it serves traffic it
 *         cannot honor. When the key is absent the binary's own
 *         configuration is authoritative.
 *      4. the memory-budget invariant holds (only when
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
 *      5. the pinned-primary authority is eligible (only under
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
     * The binary's maximum challenge protocol version: 4 since the
     * execution-capable canonical (protocol v4) landed — armed issuance
     * writes version 4 and the verifier accepts versions 1..4. A
     * central security-policy hash demanding a higher version means this
     * binary cannot verify the challenges the fleet now issues, so it
     * must not be ready. Mirrored by the php-core
     * (`ChallengeRecord::MAX_PROTOCOL_VERSION`) and the Rust crate
     * (`challenge::MAX_PROTOCOL_VERSION`).
     */
    public const MAX_PROTOCOL_VERSION = 4;

    /** Fixed headroom of the memory-budget invariant, in MiB. */
    public const MEMORY_HEADROOM_MIB = 256;

    /** In-process probe/state cache window in ms. */
    private const CACHE_MS = 1000;

    private ?bool $lastProbeOk = null;
    private bool $pendingProbeFailure = false;
    private float $probeAtMs = -PHP_FLOAT_MAX;

    private ?bool $lastPolicyOk = null;
    private ?string $policyReason = null;
    private float $policyAtMs = -PHP_FLOAT_MAX;

    /**
     * @param \Redis|\Predis\Client|null $redis         the security Redis
     *                                                   client. Null = no
     *                                                   external security
     *                                                   state, so the Redis
     *                                                   legs are vacuous.
     * @param string                     $namespace     the risk namespace
     *                                                   (sanitized) used for
     *                                                   the central policy
     *                                                   key.
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
     * machine-readable reason when a leg fails.
     */
    public function ready(): JsonResponse
    {
        if ($this->secretKey === '') {
            return $this->json(['status' => 'not_ready', 'reason' => 'signing_keys_not_configured'], Response::HTTP_SERVICE_UNAVAILABLE);
        }
        if (!$this->securityRedisReachable()) {
            return $this->json(['status' => 'not_ready', 'reason' => 'security_redis_unreachable'], Response::HTTP_SERVICE_UNAVAILABLE);
        }
        [$policyOk, $reason] = $this->securityPolicyCompatible();
        if (!$policyOk) {
            return $this->json(['status' => 'not_ready', 'reason' => $reason ?? 'security_policy_incompatible'], Response::HTTP_SERVICE_UNAVAILABLE);
        }
        if (!$this->memoryBudgetOk()) {
            return $this->json(['status' => 'not_ready', 'reason' => 'memory_budget_invariant'], Response::HTTP_SERVICE_UNAVAILABLE);
        }
        [$authorityOk, $authorityReason, $authorityLabel] = $this->authorityEligible();
        if (!$authorityOk) {
            $data = ['status' => 'not_ready', 'reason' => $authorityReason];
            if ($authorityLabel !== null) {
                $data['authority'] = $authorityLabel;
            }

            return $this->json($data, Response::HTTP_SERVICE_UNAVAILABLE);
        }

        return $this->json(['status' => 'ready']);
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
     * Security Redis reachability: a PING probe, cached ~1 s.
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
        if ($now - $this->probeAtMs < self::CACHE_MS) {
            return $this->lastProbeOk ?? true;
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
            if ($this->lastProbeOk === true && !$this->pendingProbeFailure) {
                // First failure after a healthy state: debounce, keeping
                // the last healthy result for one more cache window.
                $this->pendingProbeFailure = true;
            } else {
                $this->lastProbeOk = false;
                $this->pendingProbeFailure = false;
            }
        } else {
            $this->lastProbeOk = true;
            $this->pendingProbeFailure = false;
        }
        $this->probeAtMs = $now;

        return $this->lastProbeOk;
    }

    /**
     * Central security-policy compatibility (cached ~1 s):
     * `{kiwi:<ns>}:security-policy` hash. When present, ready requires
     * min_protocol_version <= {@see self::MAX_PROTOCOL_VERSION} and
     * min_policy_epoch <= the configured risk.policy_version. When absent
     * (or when no Redis is configured) the binary's own configuration is
     * authoritative.
     *
     * @return array{0: bool, 1: ?string} [compatible, machine-readable reason]
     */
    private function securityPolicyCompatible(): array
    {
        if ($this->redis === null) {
            return [true, null];
        }
        $now = $this->nowMs();
        if ($now - $this->policyAtMs < self::CACHE_MS) {
            return [$this->lastPolicyOk ?? true, $this->policyReason];
        }

        $ok = true;
        $reason = null;
        try {
            $policy = $this->redis->hgetall('{kiwi:'.$this->namespace.'}:security-policy');
            if (\is_array($policy) && $policy !== []) {
                // Corrupt present policy state must fail closed: a
                // malformed min_protocol_version / min_policy_epoch (abc,
                // -1, 1.5, 1e3, overflow) makes the node NOT ready — it is
                // never silently collapsed toward zero and interpreted as
                // absent.
                foreach (['min_protocol_version', 'min_policy_epoch'] as $field) {
                    if (\array_key_exists($field, $policy)) {
                        $raw = $policy[$field];
                        if (!\is_string($raw) || preg_match('/^(?:0|[1-9][0-9]*)$/D', $raw) !== 1) {
                            $ok = false;
                            $reason = 'security_policy_state_corrupt:'.$field;
                        } else {
                            $parsed = (int) $raw;
                            if ((string) $parsed !== $raw) {
                                $ok = false;
                                $reason = 'security_policy_state_corrupt:'.$field;
                            }
                        }
                    }
                }
                if ($ok) {
                    $minProtocol = (int) ($policy['min_protocol_version'] ?? 0);
                    $minEpoch = (int) ($policy['min_policy_epoch'] ?? 0);
                    if ($minProtocol > self::MAX_PROTOCOL_VERSION) {
                        $ok = false;
                        $reason = 'security_policy_incompatible:min_protocol_version_'.$minProtocol;
                    } elseif ($minEpoch > $this->policyVersion) {
                        $ok = false;
                        $reason = 'security_policy_incompatible:min_policy_epoch_'.$minEpoch;
                    }
                }
            }
        } catch (\Throwable) {
            $ok = false;
            $reason = 'security_policy_state_unavailable';
        }

        $this->lastPolicyOk = $ok;
        $this->policyReason = $reason;
        $this->policyAtMs = $now;

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
