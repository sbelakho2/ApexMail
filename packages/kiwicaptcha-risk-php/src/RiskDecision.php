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
 *
 * quarantined is the decision-plane quarantine disposition (change.md
 * 1.3 and 3.3.4), never a ladder rung. It is set only on top of the
 * Allow action, only by the marks stage, and only for a server-confirmed
 * spam mark (kind spamReported) inside its TTL. The decision passes as
 * an ordinary allow (same action, same rung, same pricing,
 * byte-identical wire) while the app-facing surfaces carry the flag, so
 * the application withholds the submission from publication. The
 * precedence is severity-monotonic: quarantine never overrides deny,
 * step-up or any stronger plain action, and any later composed stage
 * that raises the action above Allow drops the flag. See
 * Marks\Quarantine for the exact selection rule and the precedence
 * table.
 */
final class RiskDecision implements \JsonSerializable
{
    public readonly string $decisionId;

    /**
     * @param list<RiskReason> $reasons max 4
     */
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
        public readonly bool $quarantined = false,
    ) {
        $this->decisionId = $decisionId ?? bin2hex(random_bytes(16));
        if ($quarantined && $action !== RiskAction::Allow) {
            throw new \InvalidArgumentException('quarantine rides the Allow action only: it is a decision disposition, never a ladder rung');
        }
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

    /**
     * The disposition label of the decision for the metrics plane: the
     * quarantine disposition counts as its own action label, wire
     * decisions keep their ladder name.
     */
    public function dispositionLabel(): string
    {
        return $this->quarantined ? 'quarantine' : $this->action->value;
    }

    /**
     * The decision after a composed stage that raised the action above
     * Allow: the severity-monotonic precedence drops the quarantine
     * disposition (the escalated action wins), everything else passes
     * through untouched.
     */
    public function withoutQuarantine(): self
    {
        if (!$this->quarantined) {
            return $this;
        }

        return new self(
            score: $this->score,
            action: $this->action,
            reasons: $this->reasons,
            policyVersion: $this->policyVersion,
            globalLevel: $this->globalLevel,
            retryAfterMs: $this->retryAfterMs,
            band: $this->band,
            decisionId: $this->decisionId,
            modelRevision: $this->modelRevision,
            quarantined: false,
        );
    }

    public function jsonSerialize(): array
    {
        return [
            'score' => $this->score,
            'action' => $this->action->value,
            'quarantined' => $this->quarantined,
            'reasons' => array_map(static fn (RiskReason $r): string => $r->value, $this->reasons),
            'policy_version' => $this->policyVersion,
            'model_revision' => $this->modelRevision,
            'global_level' => $this->globalLevel,
            'retry_after_ms' => $this->retryAfterMs,
            'band' => $this->band,
        ];
    }
}
