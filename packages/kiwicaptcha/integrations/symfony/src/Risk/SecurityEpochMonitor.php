<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Risk;

use KiwiCaptcha\Verifier;

/**
 * Bounded-revocation-latency security-epoch monitor.
 *
 * Reads the central security-policy state, the `{kiwi:<ns>}:security-policy`
 * hash's `min_policy_epoch` field, the same key the readiness probe
 * consults, with a short cache (risk.security_epoch_cache_secs, default
 * 1 s). It feeds the {@see Verifier}'s expected policy epoch per
 * verification, so a central policy bump revokes outstanding challenges
 * within one cache window instead of waiting for a redeploy.
 *
 * The same cached central read also exposes the `min_protocol_version`
 * field, the fleet-wide writer floor the challenge controller consults
 * before arming protocol-v3 emission (risk.decoy_v3_enabled): v3 is
 * emitted only when the confirmed central floor is >= 3. Unlike the
 * epoch, the protocol floor is deliberately NOT monotonic: the floor is
 * a fleet-capability coordination signal, not a revocation. The
 * readiness gate admits any binary whose max protocol is >= the floor,
 * so a lowered floor means the operator admitted older binaries back
 * into the pool. v3 emission must stop on the next re-read, because a
 * monotonic max would keep emitting v3 challenges those binaries
 * reject. Absent, corrupt or unreadable state yields null (fail-safe:
 * the issuance path falls back to protocol v2).
 *
 * The same read also exposes the optional `min_execution_version`
 * field, the execution-grammar floor the challenge controller consults
 * before emitting any rung above version 1 (version 2, the causal
 * observe grammar, is the first rung above it).
 * The value is null when no confirmed policy exists, 0 when a
 * confirmed policy declares no execution floor, and the parsed floor
 * otherwise. The key is optional and permissive at the read level.
 * Both 0 and null mean no declared floor, so the writer stays at
 * execution version 1 until the operator declares one. A declared
 * floor then admits its rung, capped by the node cap and the
 * generator maximum.
 *
 * Four hardening properties:
 *
 *  1. Monotonic max: once this process has observed epoch N it never
 *     accepts a lower epoch, even if the central value regresses (a
 *     misconfigured rollback of the central hash must not silently
 *     re-validate challenges that were revoked).
 *  2. Fail-safe on Redis failure: when the central read fails (Redis down,
 *     timeout), the monitor serves the last observed max — the verifier
 *     keeps enforcing the newest epoch it ever saw, never a weaker one.
 *     The protocol floor serves null instead (v2 emission), the safe
 *     direction for the writer gate.
 *  3. Bounded latency: the central value is re-read at most once per cache
 *     window, so the revocation latency is one TTL, never unbounded.
 *  4. Max-stale fail-closed: after the last successful central read, once
 *     `now > last_success + risk.security_epoch_max_stale_secs` (default
 *     60 s, min 10 s) the monitor reports {@see isStale()}. A stale monitor
 *     is the deliberate constrained degradation: the cached max may no
 *     longer reflect the central policy, since an emergency revocation
 *     could have landed while the node could not read. The validator
 *     then fails verification closed (temporary_unavailable), and the
 *     challenge controller refuses issuance with 503
 *     `SERVICE_UNAVAILABLE`. Within the
 *     window the cached max keeps serving, so availability is preserved
 *     for a bounded outage. A monitor without a Redis client is never
 *     stale: "no central state by design" is a configured posture, not a
 *     failure.
 *
 * The effective epoch is `max(configuredEpoch, observedMax)`: the local
 * risk.policy_version is the floor, a node never expects less than its own
 * issuance epoch since its own challenges must verify, and the central
 * value only ever raises it. The readiness gate
 * ({@see \BelConsulting\KiwiCaptchaBundle\Controller\KiwiHealthController})
 * keeps a binary whose configured epoch is behind the central epoch out of
 * the pool, so a serving node's configured epoch is always >= the central
 * value.
 *
 * The epoch is applied to the shared {@see Verifier} via its public
 * {@see Verifier::setExpectedPolicyVersion()} seam: this monitor owns
 * only the policy epoch. Region and issuer are static deployment
 * expectations established once at verifier construction (the bundle's
 * `region` and `issuer` options) and are never rewritten here. A
 * policy-epoch refresher has no reason to mutate the deployment
 * compartment; doing so would let a central epoch bump silently disable
 * issuer enforcement.
 */
final class SecurityEpochMonitor
{
    /** The central policy hash key (shared with the readiness probe). */
    private const POLICY_KEY = '{kiwi:%s}:security-policy';

    /** The central hash field carrying the minimum policy epoch. */
    public const MIN_POLICY_EPOCH_FIELD = 'min_policy_epoch';

    /** The central hash field carrying the fleet protocol floor. */
    public const MIN_PROTOCOL_VERSION_FIELD = 'min_protocol_version';

    /**
     * The central hash field carrying the fleet execution-grammar floor
     * (min_execution_version): the writer-side floor the challenge
     * controller consults before emitting any execution grammar rung
     * above version 1, exactly like min_protocol_version gates
     * the protocol rungs. The key is optional: a confirmed policy
     * without it reads as 0 — permissive, no declared execution floor —
     * never null, so a policy-without-the-key is never confused with an
     * unconfirmed policy.
     */
    public const MIN_EXECUTION_VERSION_FIELD = 'min_execution_version';

    private int $observedMax = 0;

    private int $currentEpoch;

    /**
     * The last successfully read central `min_protocol_version` floor,
     * non-monotonic: a lowered floor (the operator admitted older
     * binaries back into the pool) must take effect on the next re-read,
     * so v3 emission stops. Null = no confirmed floor (no Redis client,
     * read failure, absent or corrupt field) — the fail-safe direction
     * for the issuance-side writer gate.
     */
    private ?int $currentMinProtocolVersion = null;

    /**
     * The last successfully read central `min_execution_version` floor,
     * non-monotonic like the protocol floor. Null = no confirmed
     * central policy at all (no Redis client, read failure, absent or
     * unreadable policy); 0 = a confirmed policy without the key (no
     * declared execution floor — permissive at the read level). Both
     * mean no declared floor, so the issuance-side gate emits no rung
     * above version 1 until the operator explicitly declared the floor.
     */
    private ?int $currentMinExecutionVersion = null;

    private float $refreshedAtMs = -PHP_FLOAT_MAX;

    /**
     * The wall-clock ms of the last successful central read (the HGET call
     * itself answered — the field may be absent). -PHP_FLOAT_MAX = never
     * succeeded: with a Redis client configured, that state is immediately
     * stale, fail closed, since an unobserved central policy can never be
     * trusted to be current.
     */
    private float $lastSuccessAtMs = -PHP_FLOAT_MAX;

    /**
     * @param \Redis|\Predis\Client|null $redis         the security Redis
     *                                                   (null = central state
     *                                                   unavailable: the
     *                                                   configured epoch is
     *                                                   authoritative and the
     *                                                   monitor is never
     *                                                   stale).
     * @param string                     $namespace     the sanitized risk
     *                                                   namespace ({kiwi:<ns>}).
     * @param int                        $configuredEpoch the local
     *                                                   risk.policy_version
     *                                                   (the floor and the
     *                                                   issuance-side stamp).
     * @param int                        $cacheSecs     short cache window
     *                                                   (risk.security_epoch_cache_secs).
     * @param callable(): float|null     $nowMs         clock override (tests).
     * @param int                        $maxStaleSecs  max-stale window
     *                                                   (risk.security_epoch_
     *                                                   max_stale_secs, >= 10):
     *                                                   once now exceeds
     *                                                   last_success +
     *                                                   max_stale, the
     *                                                   monitor reports stale.
     *
     * The monitor deliberately does not carry region or issuer: those
     * are construction-time verifier expectations (the bundle's `region`
     * and `issuer` options), and an epoch refresher must never rewrite
     * them. Rotating a null issuer through the shared verifier would
     * silently disable issuer enforcement on every subsequent
     * verification.
     */
    public function __construct(
        private readonly Verifier $verifier,
        private readonly \Redis|\Predis\Client|null $redis,
        private readonly string $namespace,
        private readonly int $configuredEpoch,
        private readonly int $cacheSecs = 1,
        private $nowMs = null,
        private readonly int $maxStaleSecs = 60,
    ) {
        if ($cacheSecs < 1) {
            throw new \InvalidArgumentException('security-epoch cache window must be >= 1 s');
        }
        if ($maxStaleSecs < 10) {
            throw new \InvalidArgumentException('security-epoch max-stale window must be >= 10 s');
        }
        $this->currentEpoch = $configuredEpoch;
    }

    /**
     * Re-read the central policy when the cache window elapsed, apply the
     * monotonic max of the epoch to the verifier, refresh the protocol
     * floor, and return the current effective epoch.
     *
     * Never throws: a central-read failure serves the last-observed max
     * (fail-safe) and the last-confirmed protocol floor (null when none
     * was ever confirmed). The verifier rotation is applied at most once
     * per epoch change and mutates only the expected policy version: the
     * construction-time region/issuer expectations are never rewritten.
     */
    public function currentEpoch(): int
    {
        $now = $this->nowMs();
        if ($now - $this->refreshedAtMs >= $this->cacheSecs * 1000) {
            $this->refreshedAtMs = $now;
            [$central, $centralFloor, $centralExecutionFloor] = $this->readCentralPolicy($now);
            if ($central !== null) {
                $this->observedMax = max($this->observedMax, $central);
            }
            $this->currentMinProtocolVersion = $centralFloor;
            $this->currentMinExecutionVersion = $centralExecutionFloor;
            $this->apply(max($this->configuredEpoch, $this->observedMax));
        }

        return $this->currentEpoch;
    }

    /**
     * Explicit refresh hook for the verification path: the validator calls
     * this before every verification so the verifier's expected epoch is
     * the current one (bounded by the cache window). No-op semantics
     * identical to {@see currentEpoch()}.
     */
    public function refresh(): int
    {
        return $this->currentEpoch();
    }

    /**
     * The central `min_protocol_version` floor from the last successful
     * read within the cache window, or null when no floor is confirmed
     * (no Redis client by design, a failed read, an absent key, or a
     * corrupt field). Non-monotonic and non-sticky: a lowered central
     * value takes effect on the next re-read, because the readiness gate
     * admits any binary whose max protocol is >= the floor — a lowered
     * floor re-admits older binaries, so v3 emission must stop. The
     * issuance path consumes this value to gate decoy-armed (protocol
     * v3) emission: arm only when the floor is >= 3, else emit v2
     * (fail-safe).
     */
    public function minProtocolVersion(): ?int
    {
        return $this->currentMinProtocolVersion;
    }

    /**
     * The central `min_execution_version` floor from the last
     * successful read within the cache window.
     *
     * Returns null when no central policy is confirmed at all: no Redis
     * client by design, a failed read, or an absent or unreadable
     * policy hash. The issuance path then stays at execution version 1,
     * the mirror of the no-confirmed-policy rule for the protocol gate.
     *
     * Returns 0 when a confirmed policy carries no execution floor: the
     * key is optional and permissive at the read level, and it imposes
     * nothing on the readiness gate.
     *
     * Otherwise the parsed floor is returned. The floor is
     * non-monotonic and non-sticky like the protocol floor: a lowered
     * value takes effect on the next re-read. The challenge controller
     * emits the resulting effective grammar rung (version 2, the causal
     * observe grammar, once the floor admits it and the client
     * advertised the capability and the node cap allows it) — see
     * {@see \BelConsulting\KiwiCaptchaBundle\Controller\ChallengeController::effectiveExecutionVersion()}.
     */
    public function minExecutionVersion(): ?int
    {
        return $this->currentMinExecutionVersion;
    }

    /** The highest central epoch this process ever observed (0 = none yet). */
    public function observedMax(): int
    {
        return $this->observedMax;
    }

    /** The central policy hash key (shared with the readiness probe). */
    public function policyKey(): string
    {
        return sprintf(self::POLICY_KEY, $this->namespace);
    }

    /**
     * Max-stale fail-closed: true when the central policy state has not
     * been confirmed successfully for longer than the max-stale window
     * (risk.security_epoch_max_stale_secs). The cached max may then be
     * outdated, since an emergency revocation could have landed while this
     * node could not read, so the caller must fail closed: the validator
     * returns temporary_unavailable and the challenge controller refuses
     * issuance with 503 `SERVICE_UNAVAILABLE`. Within the window the cached
     * max keeps serving (bounded outage tolerance). A monitor without a
     * Redis client is never stale (no central state by design — the
     * configured epoch is authoritative). A monitor that never succeeded a
     * central read (Redis down from boot) is stale immediately: an
     * unobserved central policy is never trusted to be current.
     */
    public function isStale(): bool
    {
        if ($this->redis === null) {
            return false;
        }

        return $this->nowMs() > $this->lastSuccessAtMs + $this->maxStaleSecs * 1000;
    }

    /**
     * The last-observed central epoch, or null when the read failed or the
     * field is absent. A successful read, the hash read itself answered
     * even with an absent field (the "no central policy configured" state
     * is legitimate and confirmed), refreshes the max-stale deadline; a
     * thrown read leaves {@see isStale()} to drift toward true.
     *
     * The second return value is the central `min_protocol_version` floor
     * (null when absent, corrupt or unreadable): the issuance-side writer
     * gate consumes it, and it never touches the max-stale window. A
     * missing or corrupt floor only disables v3/v4 emission, and the
     * older protocol rungs stay served, the safe direction.
     *
     * The third return value is the central `min_execution_version`
     * floor (null when no confirmed policy at all, 0 when a confirmed
     * policy carries no execution floor, the parsed value otherwise):
     * the issuance-side execution-version gate consumes it. A corrupt
     * value stays null (unconfirmed), which only keeps execution
     * version 2 unemitted.
     *
     * @return array{0: ?int, 1: ?int, 2: ?int} [central epoch, central protocol floor, central execution floor]
     */
    private function readCentralPolicy(float $now): array
    {
        if ($this->redis === null) {
            return [null, null, null];
        }
        try {
            $policy = $this->redis->hgetall($this->policyKey());
        } catch (\Throwable) {
            // Fail-safe: serve the last-observed max and the last
            // confirmed floors, never a weaker epoch or an armed
            // v3/v4/execution-v2.
            return [null, null, null];
        }
        if (!\is_array($policy) || $policy === []) {
            // A successful read with no central policy configured (a fresh
            // deployment): the monitor is healthy and the success mark is
            // refreshed — only the last-observed max keeps serving, and
            // the floors stay unconfirmed (older-rung emission).
            $this->lastSuccessAtMs = $now;

            return [null, null, null];
        }
        $epoch = null;
        $floor = null;
        $executionFloor = null;
        if (\array_key_exists(self::MIN_POLICY_EPOCH_FIELD, $policy)) {
            $value = $policy[self::MIN_POLICY_EPOCH_FIELD];
            if (\is_string($value) && preg_match('/^(?:0|[1-9][0-9]*)$/D', $value) === 1) {
                $parsed = (int) $value;
                if ((string) $parsed === $value) {
                    $epoch = $parsed;
                }
            }
            // Corrupt present epoch state must never be indistinguishable
            // from absent state: a malformed value (abc, -1, 1.5, 1e3,
            // integer overflow) is NOT a successful read — the stale
            // window is NOT refreshed (the verification fails closed once
            // the max-stale bound passes) and the last-observed max keeps
            // serving. The protocol/execution floors below are unaffected:
            // a corrupt floor only stays null (older-rung emission).
            if ($epoch === null) {
                return [null, null, null];
            }
        }
        if (\array_key_exists(self::MIN_PROTOCOL_VERSION_FIELD, $policy)) {
            $value = $policy[self::MIN_PROTOCOL_VERSION_FIELD];
            if (\is_string($value) && preg_match('/^(?:0|[1-9][0-9]*)$/D', $value) === 1) {
                $parsed = (int) $value;
                if ((string) $parsed === $value) {
                    $floor = $parsed;
                }
            }
            // A corrupt protocol floor (abc, -1, 1.5, 1e3, overflow) is
            // an unconfirmed floor: null, so the issuance gate emits the
            // older protocol rungs. The stale window is deliberately NOT
            // refreshed by the floor field: the epoch field above owns
            // the freshness deadline.
        }
        if (\array_key_exists(self::MIN_EXECUTION_VERSION_FIELD, $policy)) {
            $value = $policy[self::MIN_EXECUTION_VERSION_FIELD];
            if (\is_string($value) && preg_match('/^(?:0|[1-9][0-9]*)$/D', $value) === 1) {
                $parsed = (int) $value;
                if ((string) $parsed === $value) {
                    $executionFloor = $parsed;
                }
            }
            // A corrupt execution floor (abc, -1, 1.5, 1e3, overflow)
            // stays null — an unconfirmed floor that only keeps every
            // rung above execution version 1 unemitted (the fail-safe
            // direction for the writer gate), never silently collapsed
            // to the permissive 0. The stale window is deliberately NOT
            // refreshed by this field either.
        }
        // A confirmed policy without the min_execution_version key has no
        // declared execution floor and reads 0 — permissive at the read
        // level (it imposes nothing on the readiness gate), but a missing
        // floor keeps every rung above execution version 1 unemitted
        // until the operator explicitly declares one.
        if ($executionFloor === null && !\array_key_exists(self::MIN_EXECUTION_VERSION_FIELD, $policy)) {
            $executionFloor = 0;
        }
        // The epoch field was confirmed (present and canonical) or
        // legitimately absent; either way the central read succeeded.
        $this->lastSuccessAtMs = $now;

        return [$epoch, $floor, $executionFloor];
    }

    private function apply(int $epoch): void
    {
        if ($epoch === $this->currentEpoch) {
            return;
        }
        $this->currentEpoch = $epoch;
        // The rotation mutates only the policy epoch (the one expectation
        // this monitor owns). Region and issuer are static deployment
        // expectations established at verifier construction; rewriting
        // them here — in particular with a null issuer — would silently
        // disable the issuer security boundary after an epoch bump.
        $this->verifier->setExpectedPolicyVersion($epoch);
    }

    private function nowMs(): float
    {
        return $this->nowMs !== null ? (float) ($this->nowMs)() : microtime(true) * 1000;
    }
}
