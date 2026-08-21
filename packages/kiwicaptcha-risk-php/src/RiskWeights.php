<?php

declare(strict_types=1);

namespace KiwiCaptcha\Risk;

/**
 * 13 weight fields, same names/order as SignalVector.
 *
 * The default weights are the contract defaults (identical to fixtures.json).
 */
final class RiskWeights
{
    public const DEFAULT_SOURCE_FAST = 190;
    public const DEFAULT_SOURCE_SLOW = 110;
    public const DEFAULT_SUBNET_FAST = 80;
    public const DEFAULT_ISSUE_DEBT = 150;
    public const DEFAULT_BAD_PROOF = 220;
    public const DEFAULT_MALFORMED = 260;
    public const DEFAULT_REPLAY = 320;
    public const DEFAULT_ACTION_FAILURE = 120;
    public const DEFAULT_SCOPE_SWITCH = 60;
    public const DEFAULT_GLOBAL_PRESSURE = 170;
    public const DEFAULT_NETWORK_RISK = 100;
    public const DEFAULT_TRUST_CREDIT = 130;
    public const DEFAULT_PRINCIPAL_CREDIT = 100;

    public function __construct(
        public readonly int $sourceFast = self::DEFAULT_SOURCE_FAST,
        public readonly int $sourceSlow = self::DEFAULT_SOURCE_SLOW,
        public readonly int $subnetFast = self::DEFAULT_SUBNET_FAST,
        public readonly int $issueDebt = self::DEFAULT_ISSUE_DEBT,
        public readonly int $badProof = self::DEFAULT_BAD_PROOF,
        public readonly int $malformed = self::DEFAULT_MALFORMED,
        public readonly int $replay = self::DEFAULT_REPLAY,
        public readonly int $actionFailure = self::DEFAULT_ACTION_FAILURE,
        public readonly int $scopeSwitch = self::DEFAULT_SCOPE_SWITCH,
        public readonly int $globalPressure = self::DEFAULT_GLOBAL_PRESSURE,
        public readonly int $networkRisk = self::DEFAULT_NETWORK_RISK,
        public readonly int $trustCredit = self::DEFAULT_TRUST_CREDIT,
        public readonly int $principalCredit = self::DEFAULT_PRINCIPAL_CREDIT,
    ) {
        foreach (get_object_vars($this) as $value) {
            if ($value < 0 || $value > 1000) {
                throw new \InvalidArgumentException(
                    sprintf('Weight values must be within 0..1000 (got %d)', $value)
                );
            }
        }
    }

    public static function fromArray(array $data): self
    {
        return new self(
            sourceFast: (int) ($data['source_fast'] ?? self::DEFAULT_SOURCE_FAST),
            sourceSlow: (int) ($data['source_slow'] ?? self::DEFAULT_SOURCE_SLOW),
            subnetFast: (int) ($data['subnet_fast'] ?? self::DEFAULT_SUBNET_FAST),
            issueDebt: (int) ($data['issue_debt'] ?? self::DEFAULT_ISSUE_DEBT),
            badProof: (int) ($data['bad_proof'] ?? self::DEFAULT_BAD_PROOF),
            malformed: (int) ($data['malformed'] ?? self::DEFAULT_MALFORMED),
            replay: (int) ($data['replay'] ?? self::DEFAULT_REPLAY),
            actionFailure: (int) ($data['action_failure'] ?? self::DEFAULT_ACTION_FAILURE),
            scopeSwitch: (int) ($data['scope_switch'] ?? self::DEFAULT_SCOPE_SWITCH),
            globalPressure: (int) ($data['global_pressure'] ?? self::DEFAULT_GLOBAL_PRESSURE),
            networkRisk: (int) ($data['network_risk'] ?? self::DEFAULT_NETWORK_RISK),
            trustCredit: (int) ($data['trust_credit'] ?? self::DEFAULT_TRUST_CREDIT),
            principalCredit: (int) ($data['principal_credit'] ?? self::DEFAULT_PRINCIPAL_CREDIT),
        );
    }

    /** Snake_case keys in contract order. */
    public function toArray(): array
    {
        return [
            'source_fast' => $this->sourceFast,
            'source_slow' => $this->sourceSlow,
            'subnet_fast' => $this->subnetFast,
            'issue_debt' => $this->issueDebt,
            'bad_proof' => $this->badProof,
            'malformed' => $this->malformed,
            'replay' => $this->replay,
            'action_failure' => $this->actionFailure,
            'scope_switch' => $this->scopeSwitch,
            'global_pressure' => $this->globalPressure,
            'network_risk' => $this->networkRisk,
            'trust_credit' => $this->trustCredit,
            'principal_credit' => $this->principalCredit,
        ];
    }
}
