<?php

declare(strict_types=1);

namespace KiwiCaptcha;

/**
 * Error codes for verification failures.
 *
 * Every case value is a machine-readable snake_case code (stable wire
 * vocabulary, matching ^[a-z0-9_]+$): logs, metrics and cross-service
 * consumers switch on it without parsing prose. The human-readable
 * explanation lives in {@see self::description()}.
 */
enum VerifyError: string
{
    case BadSignature = 'bad_signature';
    case Expired = 'expired';
    case WrongScope = 'wrong_scope';
    case IpMismatch = 'ip_mismatch';
    case MissingClientIp = 'missing_client_ip';
    case WrongRegion = 'wrong_region';
    case WrongIssuer = 'wrong_issuer';
    case WrongPolicyVersion = 'wrong_policy_version';
    case UnknownKid = 'unknown_kid';
    case TooFast = 'too_fast';
    case InsufficientWork = 'insufficient_work';
    case MalformedRecord = 'malformed_record';
    case RecordNotFound = 'record_not_found';
    case MalformedToken = 'malformed_token';
    case UnsupportedArgon2Params = 'unsupported_argon2_params';
    case TooManyAttempts = 'too_many_attempts';
    case TelemetryRejected = 'telemetry_rejected';
    case CapacityExceeded = 'capacity_exceeded';
    case AdmissionUnavailable = 'admission_unavailable';
    case StorageUnavailable = 'storage_unavailable';
    case ConsumeIndeterminate = 'consume_indeterminate';
    case AlreadyConsumed = 'already_consumed';
    case RequestBindingMismatch = 'request_binding_mismatch';
    case ExecutionMismatch = 'execution_mismatch';
    case UnsupportedRswParams = 'unsupported_rsw_params';

    /**
     * Whether this failure is exempt from the one-shot policy on a
     * consumed record. The failure describes the original redemption's
     * circumstances (the signed expiry, the network binding, the
     * missing client IP, the client-side telemetry evidence) rather
     * than this request's authorization. A consumed record whose
     * retained committed success is replayed by the proven operation
     * may therefore resolve through the consumed branch despite it.
     *
     * The exemption is deliberately narrow. Every security verdict —
     * wrong scope, request-binding mismatch, policy epoch, region,
     * issuer, kid revocation and resolution, signature, record shape,
     * the unsupported protocol/profile, and the receipt-timing floor —
     * stands even when the operation identity matches. The stored
     * success never replays around it; the record is kept intact and
     * the failure is returned.
     */
    public function isReplayExempt(): bool
    {
        return match ($this) {
            self::Expired, self::IpMismatch, self::MissingClientIp, self::TelemetryRejected => true,
            default => false,
        };
    }

    /**
     * The human-readable explanation of the failure (operator-facing
     * prose; never a value to switch on — use the case or ->value for
     * that).
     */
    public function description(): string
    {
        return match ($this) {
            self::BadSignature => 'challenge signature is invalid',
            self::Expired => 'challenge has expired',
            self::WrongScope => 'challenge was issued for a different scope',
            self::IpMismatch => 'challenge was issued to a different client IP',
            self::MissingClientIp => 'challenge is IP-bound but no client IP was supplied',
            self::WrongRegion => 'challenge was issued for a different region',
            self::WrongIssuer => 'challenge was issued by a different deployment',
            self::WrongPolicyVersion => 'challenge was issued under a different security-policy epoch',
            self::UnknownKid => 'unknown signing key id',
            self::TooFast => 'solution arrived faster than the theoretical minimum (server-measured)',
            self::InsufficientWork => 'solution does not meet the difficulty target',
            self::MalformedRecord => 'stored challenge record is malformed',
            self::RecordNotFound => 'challenge record not found (unknown or already deleted)',
            self::MalformedToken => 'solution token is malformed',
            self::UnsupportedArgon2Params => 'Argon2id parameters exceed the supported process ceilings',
            self::TooManyAttempts => 'too many verification attempts',
            self::TelemetryRejected => 'bot-signal telemetry rejected the solution',
            self::CapacityExceeded => 'verification capacity exceeded — try again shortly',
            self::AdmissionUnavailable => 'verification admission backend unavailable — try again shortly',
            self::StorageUnavailable => 'verification storage backend unavailable — try again shortly',
            self::ConsumeIndeterminate => 'verification storage response indeterminate — the challenge may or may not have been consumed',
            self::AlreadyConsumed => 'the challenge was already consumed by a different logical operation',
            self::RequestBindingMismatch => 'the challenge is not bound to the expected application transaction',
            self::ExecutionMismatch => 'the execution digest does not match the expected program trace of the challenge',
            self::UnsupportedRswParams => 'the rsw challenge cannot be verified: this verifier is not configured with the matching rsw trapdoor, or the signed sequential cost is outside the supported bounds',
        };
    }
}
