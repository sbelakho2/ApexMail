<?php

declare(strict_types=1);

namespace KiwiCaptcha\Risk;

/**
 * Risk reasons, fixed by the cross-language risk-v1 contract.
 *
 * The top 3-4 reasons are attached to an internal RiskDecision; they are
 * never exposed to the client.
 */
enum RiskReason: string
{
    case SourceBurst = 'source_burst';
    case SourceSustained = 'source_sustained';
    case NetworkBurst = 'network_burst';
    case ChallengeDebt = 'challenge_debt';
    case InvalidProofs = 'invalid_proofs';
    case MalformedTraffic = 'malformed_traffic';
    case ReplayTraffic = 'replay_traffic';
    case ActionFailures = 'action_failures';
    case ScopeHopping = 'scope_hopping';
    case GlobalAttack = 'global_attack';
    case LocalNetworkRisk = 'local_network_risk';
    case CapacityPressure = 'capacity_pressure';
    case HardRateLimit = 'hard_rate_limit';
    case Cooldown = 'cooldown';
}
