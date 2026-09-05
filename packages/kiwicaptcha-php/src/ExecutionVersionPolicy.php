<?php

declare(strict_types=1);

namespace KiwiCaptcha;

/**
 * The single execution-version decision procedure shared by every
 * posture surface (issuance, the environment doctor, and the readiness
 * probe), so each surface derives the same tier from the same inputs
 * and can never drift apart. The three inputs mirror the three
 * emission-gate rungs of the execution dimension: the node's
 * execution_version cap, the confirmed central min_execution_version
 * fleet floor (null when nothing is confirmed), and this binary's
 * generator maximum.
 *
 * The effective available tier is the strongest grammar the fleet can
 * confirm today: min(nodeCap, fleetFloor ?? 1, binaryMax). An
 * unconfirmed floor pins the tier at version 1, the grammar every
 * interpreter generation runs, exactly like the protocol-v3/v4 gates
 * pin emission on an unconfirmed floor. A required tier above the node
 * cap can never be satisfied (the config tree refuses it at compile
 * time), so every query method refuses it with an
 * InvalidArgumentException instead of answering.
 */
final class ExecutionVersionPolicy
{
    /**
     * @param int      $nodeCap    the node's execution_version cap
     * @param int|null $fleetFloor the confirmed central
     *                             min_execution_version fleet floor,
     *                             null when absent or unconfirmed
     * @param int      $binaryMax  the maximum execution version this
     *                             binary's generator can emit
     */
    public function __construct(
        private readonly int $nodeCap,
        private readonly ?int $fleetFloor = null,
        private readonly int $binaryMax = ExecutionChallengeGenerator::MAX_EXECUTION_VERSION,
    ) {
        if ($nodeCap < 1) {
            throw new \InvalidArgumentException(sprintf('nodeCap must be at least 1 (got %d)', $nodeCap));
        }
        if ($fleetFloor !== null && $fleetFloor < 1) {
            throw new \InvalidArgumentException(sprintf('fleetFloor must be null or at least 1 (got %d)', $fleetFloor));
        }
        if ($binaryMax < 1) {
            throw new \InvalidArgumentException(sprintf('binaryMax must be at least 1 (got %d)', $binaryMax));
        }
    }

    /**
     * The strongest grammar the deployment can emit or confirm today:
     * the minimum of the node cap, the confirmed fleet floor (an
     * unconfirmed floor counts as version 1) and this binary's
     * generator maximum.
     */
    public function effectiveAvailableTier(): int
    {
        return min($this->nodeCap, $this->fleetFloor ?? 1, $this->binaryMax);
    }

    /**
     * Whether a required tier can be satisfied by an armed request
     * under the current rungs: true when the required tier is at or
     * below the effective available tier.
     *
     * @throws \InvalidArgumentException when the required tier exceeds
     *                                   the node cap (the compile-time
     *                                   invariant, never satisfiable)
     */
    public function requirementSatisfiable(int $required): bool
    {
        $this->assertRequiredWithinCap($required);

        return $required <= $this->effectiveAvailableTier();
    }

    /**
     * Whether a client-downgradeable window exists: the required tier
     * is strictly below the strongest grammar the fleet can confirm,
     * so a client that cannot solve the strongest grammar is handed a
     * weaker one instead of being refused.
     *
     * @throws \InvalidArgumentException when the required tier exceeds
     *                                   the node cap (the compile-time
     *                                   invariant, never satisfiable)
     */
    public function downgradeWindowExists(int $required): bool
    {
        $this->assertRequiredWithinCap($required);

        return $required < $this->effectiveAvailableTier();
    }

    /**
     * @throws \InvalidArgumentException when the required tier is
     *                                   outside 1..nodeCap
     */
    private function assertRequiredWithinCap(int $required): void
    {
        if ($required < 1 || $required > $this->nodeCap) {
            throw new \InvalidArgumentException(sprintf(
                'execution_required_version %d is outside the 1..%d node execution_version cap: a required tier above the node cap can never be satisfied and is refused at configuration time',
                $required,
                $this->nodeCap,
            ));
        }
    }
}
