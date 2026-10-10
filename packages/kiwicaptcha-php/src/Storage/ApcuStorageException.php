<?php

declare(strict_types=1);

namespace KiwiCaptcha\Storage;

/**
 * The APCu storage backend refused or could not complete a
 * durability-critical operation: the extension is missing or disabled,
 * the segment refused a write, or a transition lock stayed held past
 * the configured timeout.
 *
 * Fail-closed by design: the verifier maps any storage throw to its
 * typed unavailable outcome, so an APCu failure can never surface as a
 * successful verification. The message carries the failing operation
 * and the underlying error, plus the lock-timeout remedy whenever the
 * failure is transition contention.
 */
final class ApcuStorageException extends \RuntimeException
{
}
