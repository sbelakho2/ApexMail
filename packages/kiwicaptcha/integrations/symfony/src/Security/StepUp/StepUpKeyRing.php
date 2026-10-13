<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Security\StepUp;

/**
 * The rotation-capable key set of the step-up HMAC plane: one current
 * signing key, a set of historical verification keys and a set of
 * revoked key ids. Every key is a step-up master (the same 32-byte
 * floor as `secret_key`). The ticket HMAC, the stored-code hash and
 * the credit idempotency derive from the selected master through their
 * purpose-separated HKDF derivations exactly as before. The ring only
 * decides which master a `kid` names.
 *
 * Rotation contract:
 *
 *  - `currentKid` is the only kid {@see StepUpTicket::issue()} mints
 *    with. Rotating flips the current kid; older in-flight tickets keep
 *    verifying under their own kid.
 *  - Historical keys stay valid for verification for at least the
 *    maximum demand lifetime (`risk.step_up` TTLs: challenge TTL, email
 *    code TTL, demand TTL). A node that minted a demand with the old
 *    key can therefore be finalized by a node that already rotated (the
 *    cross-node requirement), as long as the old kid is still in
 *    `secretsByKid` and not revoked.
 *  - A revoked kid fails verification even when its secret is still
 *    configured: revocation is the compromise response, and it wins
 *    over presence. Unknown and future kids (beyond the newest
 *    configured kid) also fail, the same rollback/forward guard the
 *    captcha verifier's `secrets_by_kid` set applies.
 *
 * The ring is immutable after construction (the secrets are resolved
 * once per process), mirroring the captcha verifier's kid set.
 */
final class StepUpKeyRing
{
    /** The deployment-wide key-id floor: positive integers 1..N. */
    private readonly int $newestKid;

    /**
     * @param array<int, string> $secretsByKid master secrets keyed by positive kid 1..N
     * @param list<int>          $revokedKids   compromised kid ids, refused even when present
     */
    public function __construct(
        private readonly int $currentKid,
        private readonly array $secretsByKid,
        private readonly array $revokedKids = [],
    ) {
        if ($secretsByKid === []) {
            throw new \InvalidArgumentException('A step-up key ring needs at least one secret');
        }
        $newest = 0;
        foreach ($secretsByKid as $kid => $secret) {
            if (!\is_int($kid) || $kid < 1) {
                throw new \InvalidArgumentException('step-up key ring kids must be positive integer values 1..N');
            }
            if (!\is_string($secret) || \strlen($secret) < 32) {
                throw new \InvalidArgumentException('every step-up key-ring master must be at least 32 bytes (the same floor as secret_key)');
            }
            if ($kid > $newest) {
                $newest = $kid;
            }
        }
        if ($newest < 1) {
            throw new \InvalidArgumentException('A step-up key ring needs at least one secret');
        }
        if (!\is_int($currentKid) || $currentKid < 1 || !\array_key_exists($currentKid, $secretsByKid)) {
            throw new \InvalidArgumentException('the current step-up kid must name a configured secret');
        }
        foreach ($revokedKids as $kid) {
            if (!\is_int($kid) || $kid < 1) {
                throw new \InvalidArgumentException('revoked step-up kids must be positive integer values 1..N');
            }
        }
        if (\in_array($currentKid, $revokedKids, true)) {
            throw new \InvalidArgumentException('the current step-up kid may not be revoked');
        }
        $this->newestKid = $newest;
    }

    /**
     * The single-master ring: kid 1 signs and verifies, no history and
     * no revocations. The legacy shape every existing `StepUpTicket`
     * construction site upgrades from.
     */
    public static function single(string $master): self
    {
        return new self(1, [1 => $master]);
    }

    /** The kid {@see StepUpTicket::issue()} stamps onto fresh tickets. */
    public function currentKid(): int
    {
        return $this->currentKid;
    }

    /** True when the kid is revoked: verification must fail even if the secret is present. */
    public function isRevoked(int $kid): bool
    {
        return \in_array($kid, $this->revokedKids, true);
    }

    /**
     * The master secret a verification attempt under this kid uses, or
     * null when the kid is revoked, unknown or ahead of the newest
     * configured kid (the rollback/forward guard). Historical kids
     * (configured but no longer current) resolve normally: that is the
     * cross-node finalize path after a rotation.
     */
    public function resolve(int $kid): ?string
    {
        if ($this->isRevoked($kid)) {
            return null;
        }
        if ($kid > $this->newestKid) {
            return null;
        }
        if (!\array_key_exists($kid, $this->secretsByKid)) {
            return null;
        }

        return $this->secretsByKid[$kid];
    }

    /**
     * The historical verification kids: every configured kid except the
     * current one. These are the keys that must outlive at least the
     * maximum demand lifetime so a demand minted under an old key can
     * still be finalized after rotation.
     *
     * @return list<int>
     */
    public function historicalKids(): array
    {
        $kids = array_keys($this->secretsByKid);
        $kids = array_values(array_filter($kids, fn (int $kid): bool => $kid !== $this->currentKid));
        sort($kids);

        return $kids;
    }

    /** The revoked kid set (compromised ids, refused even when configured). */
    /** @return list<int> */
    public function revokedKids(): array
    {
        $kids = $this->revokedKids;
        sort($kids);

        return array_values($kids);
    }
}
