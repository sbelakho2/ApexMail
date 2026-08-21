<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Risk;

use KiwiCaptcha\Risk\RiskAction;

/**
 * The open-chain requirement of one transaction, the typed surface the
 * stage-2 issuance and the disposition layer consume. The state is the
 * machine state of the chain: available | reserved | issued | verified |
 * step_up_required | denied. Legacy 'completed' records, the historical
 * name of the terminal-with-nonce state, are reported as 'issued':
 * semantically identical.
 */
final class ChainRequirement
{
    public function __construct(
        public readonly string $chainId,
        public readonly string $stage1Nonce,
        public readonly string $scope,
        /** The authoritative transaction binding ('' = the transaction is unbound). */
        public readonly string $requestBinding,
        public readonly int $policyVersion,
        public readonly RiskAction $requiredAction,
        public readonly int $requiredRank,
        /** Always 2 — the chain is a selective extension of depth 2. */
        public readonly int $chainDepth,
        /** available | reserved | issued | verified | step_up_required | denied. */
        public readonly string $state,
        /** The issued stage-2 challenge nonce (issued/verified/step_up_required/denied). */
        public readonly ?string $stage2Nonce,
        /** The reservation owner (reserved). */
        public readonly ?string $owner,
        /** The reservation lease deadline, unix seconds (reserved). */
        public readonly ?int $leaseUntil,
        public readonly int $expiresAt,
    ) {
    }
}
