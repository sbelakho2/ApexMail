<?php

declare(strict_types=1);

namespace KiwiCaptcha\Risk;

/**
 * Immutable risk decision produced by the policy.
 *
 * Reasons are internal only (never exposed to the client) and capped at 4.
 * decisionId is a fresh random 16-byte hex id (internal handle used to
 * pair later confirmed outcomes back to this decision via calibration
 * receipts). modelRevision is the RiskModel generation the decision was
 * computed under — exposed in the public JSON (bounded, unlike the
 * internal decisionId).
 */
final class RiskDecision implements \JsonSerializable
{
    public readonly string $decisionId;

    /** @param list<RiskReason> $reasons max 4 */
    public function __construct(
        public readonly int $score,
        public readonly RiskAction $action,
        public readonly array $reasons,
        public readonly int $policyVersion,
        public readonly int $globalLevel,
        public readonly ?int $retryAfterMs = null,
        public readonly int $band = 0,
        ?string $decisionId = null,
        public readonly int $modelRevision = RiskModel::REVISION,
    ) {
        $this->decisionId = $decisionId ?? bin2hex(random_bytes(16));
        foreach ($reasons as $reason) {
            if (!$reason instanceof RiskReason) {
                throw new \InvalidArgumentException('RiskDecision reasons must be RiskReason instances');
            }
        }
        if (count($reasons) > 4) {
            throw new \InvalidArgumentException('RiskDecision carries at most 4 reasons');
        }
    }

    public function hasReason(RiskReason $reason): bool
    {
        return in_array($reason, $this->reasons, true);
    }

    public function jsonSerialize(): array
    {
        return [
            'score' => $this->score,
            'action' => $this->action->value,
            'reasons' => array_map(static fn (RiskReason $r): string => $r->value, $this->reasons),
            'policy_version' => $this->policyVersion,
            'model_revision' => $this->modelRevision,
            'global_level' => $this->globalLevel,
            'retry_after_ms' => $this->retryAfterMs,
            'band' => $this->band,
        ];
    }
}
