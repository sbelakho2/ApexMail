<?php

declare(strict_types=1);

namespace KiwiCaptcha;

/**
 * Error codes for verification failures.
 */
enum VerifyError: string
{
    case BadSignature = 'bad_signature';
    case Expired = 'expired';
    case WrongScope = 'wrong_scope';
    case IpMismatch = 'ip_mismatch';
    case MissingClientIp = 'missing_client_ip';
    case TooFast = 'too_fast';
    case InsufficientWork = 'insufficient_work';
    case MalformedRecord = 'malformed_record';
    case RecordNotFound = 'record_not_found';
    case MalformedToken = 'malformed_token';
    case UnsupportedArgon2Params = 'unsupported_argon2_params';
    case TooManyAttempts = 'too_many_attempts';
    case TelemetryRejected = 'telemetry_rejected';
    case CapacityExceeded = 'verification capacity exceeded — try again shortly';
}
