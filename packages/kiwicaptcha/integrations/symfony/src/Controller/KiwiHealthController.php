<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Controller;

use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Response;

/**
 * Rollback-resistant liveness/readiness split (audit #51/#58).
 *
 *  - `/health/live`  — ALWAYS 200 while the process runs. Never tied to
 *    saturation, Redis, or any external state: a process that is up is
 *    "live" (the orchestrator only cares that the worker exists and can
 *    answer).
 *
 *  - `/health/ready` — 200 only when ALL of:
 *      1. the issuer/verifier SIGNING KEYS are configured (the bundle
 *         secret is required, so this is normally trivially true);
 *      2. the SECURITY Redis is reachable: a PING probe, cached ~1 s
 *         (in-process). Transient probe timeouts NEVER fail readiness on
 *         their own: the first failure is debounced for one cache window
 *         (a blip that recovers within ~1 s keeps the last healthy state);
 *         two consecutive failures flip readiness. Argon queue fullness is
 *         NEVER consulted.
 *      3. the CENTRAL security-policy state is compatible: Redis key
 *         `{kiwi:<ns>}:security-policy` (a HASH with
 *         `min_protocol_version` + `min_policy_epoch`). When the key is
 *         present, ready requires min_protocol_version <= 2 (this binary's
 *         max protocol version) AND min_policy_epoch <= the configured
 *         risk.policy_version — a NEWER central policy (mixed-version
 *         rolling deployments, rollbacks) takes the old binary OUT of the
 *         pool BEFORE it serves traffic it cannot honor. When the key is
 *         ABSENT the binary's own configuration is authoritative.
 *
 * The route paths follow the configured route_prefix (default
 * /kiwi-captcha/health/live + /health/ready) and are registered by
 * {@see \BelConsulting\KiwiCaptchaBundle\Routing\KiwiCaptchaRouteLoader}
 * when risk.health.enabled is true (default).
 *
 * Every response is a private JSON document (never cached by proxies/CDNs).
 */
final class KiwiHealthController
{
    /**
     * The binary's MAXIMUM challenge protocol version. A central
     * security-policy hash demanding a higher version means this binary
     * cannot verify the challenges the fleet now issues — it must not be
     * ready.
     */
    public const MAX_PROTOCOL_VERSION = 2;

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
     *                                                   client (null = no
     *                                                   external security
     *                                                   state — the Redis
     *                                                   legs are vacuous)
     * @param string                     $namespace     the risk namespace
     *                                                   (sanitized) used for
     *                                                   the central policy
     *                                                   key
     * @param int                        $policyVersion the configured
     *                                                   risk.policy_version
     * @param callable(): float|null     $nowMs         clock override (tests)
     */
    public function __construct(
        private readonly string $secretKey,
        private readonly \Redis|\Predis\Client|null $redis,
        private readonly string $namespace,
        private readonly int $policyVersion,
        private $nowMs = null,
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

        return $this->json(['status' => 'ready']);
    }

    /**
     * Security Redis reachability: a PING probe, cached ~1 s.
     *
     * Transient timeouts never fail readiness on their own: the FIRST
     * failed probe is debounced for one cache window (a blip that recovers
     * within ~1 s keeps the last healthy state); a second consecutive
     * failure — or a failure on a freshly booted process — flips readiness.
     * A probe exception (timeout/refused) is a probe failure, never a
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
            // phpredis: true; Predis: the 'PONG' Status response object.
            $ok = $result === true || (string) $result === 'PONG';
        } catch (\Throwable) {
            $ok = false;
        }

        if (!$ok) {
            if ($this->lastProbeOk === true && !$this->pendingProbeFailure) {
                // First failure after a healthy state: debounce — keep the
                // last healthy result for one more cache window.
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
     * CENTRAL security-policy compatibility (cached ~1 s):
     * `{kiwi:<ns>}:security-policy` hash — when PRESENT, ready requires
     * min_protocol_version <= {@see self::MAX_PROTOCOL_VERSION} AND
     * min_policy_epoch <= the configured risk.policy_version. When ABSENT
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
