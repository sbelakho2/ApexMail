<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Security\Authority;

use KiwiCaptcha\AuthoritySafety;
use KiwiCaptcha\AuthoritySafetyClassifier;

/**
 * The default runtime authority-transition guard: classifies the actual
 * constructed Redis client instance through the canonical core
 * classifier ({@see AuthoritySafetyClassifier}) and refuses service
 * under the fail_closed posture when the client's authority-transition
 * semantics cannot be proven safe.
 *
 * The classification reads the live connection object a Predis client
 * built, so every construction path is covered: DSN-built clients,
 * explicit service ids, aliases, decorators, custom factories,
 * env-resolved constructions and opaque products all arrive here as
 * the instance that will serve. A compile-time lane sees only
 * definition shapes and cannot see env-resolved postures at all; this
 * guard runs at service construction on the resolved posture, so it is
 * the authoritative enforcement point.
 *
 * Posture semantics (docs/ha-authority.md):
 *  - fail_closed: Safe serves, Unsafe refuses (an automatic-failover
 *    aggregate OR a retry-enabled direct connection), Unknown refuses.
 *    Under this posture unknown authority-transition semantics are
 *    unsafe until proven safe, and the refusal is the typed
 *    LogicException naming the posture, the classification and the
 *    remediation.
 *  - operator_managed and best_effort: every classification serves.
 *    The refusal surface is deliberately empty here; the doctor's
 *    replication-topology check carries the deployment contract
 *    (operator_managed passes, best_effort warns).
 *
 * A pinned-primary or failover-manager adapter implements
 * {@see AuthorityTransitionGuard} instead of this classifier and is
 * resolved through the same service id, so a deployment that can prove
 * its authority never changes swaps the semantics at one seam.
 */
final class RuntimeAuthorityClassifier implements AuthorityTransitionGuard
{
    /**
     * The remediation shared by every fail_closed refusal, the compile
     * time lane and this runtime lane, so both name the same options.
     */
    public const FAIL_CLOSED_REMEDIATION = 'Provide a pinned-primary/topology adapter (a standalone connection with retries disabled, or a client the deployment can prove never changes authority), or choose operator_managed (the operator owns promotion eligibility) or best_effort (the documented stale-promotion boundary accepted).';

    /**
     * @param string $posture the resolved replay_durability posture
     *        (fail_closed, operator_managed, best_effort). An env
     *        placeholder is resolved by the container before this
     *        constructor runs, so an env-derived posture reaches the
     *        enforcement exactly where the build-time lanes could not
     *        see it.
     */
    public function __construct(private readonly string $posture)
    {
    }

    /**
     * Classify the actual client instance through the canonical core
     * classifier: proven aggregate or retry-enabled -> Unsafe, proven
     * single-node direct with retries disabled -> Safe, uninspectable
     * -> Unknown.
     */
    public function classify(mixed $client): AuthorityClassification
    {
        return match (AuthoritySafetyClassifier::classify($client)) {
            AuthoritySafety::Safe => AuthorityClassification::Safe,
            AuthoritySafety::Unsafe => AuthorityClassification::Unsafe,
            AuthoritySafety::Unknown => AuthorityClassification::Unknown,
        };
    }

    public function assertServeEligible(mixed $client, bool $securityFinal = false): void
    {
        if ($this->posture !== 'fail_closed') {
            return;
        }
        $classification = $this->classify($client);
        if ($classification === AuthorityClassification::Safe) {
            return;
        }
        throw new \LogicException(sprintf(
            'kiwi_captcha.replay_durability is "fail_closed", but %s — %s',
            $this->refusalReason($client, $classification),
            self::FAIL_CLOSED_REMEDIATION,
        ));
    }

    /**
     * The classification detail for the refusal message: the aggregate
     * topology or the retry state when proven, the uninspectable shape
     * when unknown.
     */
    private function refusalReason(mixed $client, AuthorityClassification $classification): string
    {
        if ($classification === AuthorityClassification::Unsafe) {
            if ($client instanceof \Predis\Client) {
                $connection = $client->getConnection();
                if ($connection instanceof \Predis\Connection\Replication\ReplicationInterface) {
                    return sprintf(
                        'the runtime Redis client (%s) is a Predis replication aggregate (Sentinel or master-slave) — automatic failover can promote a stale replica, and the promoted authority may never have received an acknowledged security-final transition',
                        get_debug_type($client),
                    );
                }
                if ($connection instanceof \Predis\Connection\Cluster\ClusterInterface) {
                    return sprintf(
                        'the runtime Redis client (%s) is a Predis Redis Cluster aggregate — automatic failover can promote a stale replica, and the promoted authority may never have received an acknowledged security-final transition',
                        get_debug_type($client),
                    );
                }
                if ($connection instanceof \Predis\Connection\NodeConnectionInterface && !$connection->getParameters()->isDisabledRetry()) {
                    return sprintf(
                        'the runtime Redis client (%s) is a direct connection with client-side reconnect retries ENABLED — the retry wrapper can re-execute a durability-critical transition on a replacement connection whose write offset is empty, exactly the stale-replica-promotion window the fail_closed posture refuses',
                        get_debug_type($client),
                    );
                }
            }

            return sprintf(
                'the runtime Redis client (%s) is unsafe under the canonical authority-safety classification — automatic failover or client-side retries can change the serving authority, and the promoted authority may never have received an acknowledged security-final transition',
                get_debug_type($client),
            );
        }

        return sprintf(
            'the runtime Redis client (%s) cannot be classified as a single-node direct connection — unknown authority-transition semantics are unsafe under fail_closed until proven safe',
            get_debug_type($client),
        );
    }
}
