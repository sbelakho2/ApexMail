<?php

declare(strict_types=1);

namespace KiwiCaptcha\Storage;

/**
 * The filesystem storage backend refused or could not complete a
 * durability-critical operation: the record lock stayed held past the
 * lock timeout, the storage directory vanished or stopped being
 * writable, the layout guard refused the directory, or the IO layer
 * failed.
 *
 * Fail-closed by design: the verifier maps any storage throw to its
 * typed unavailable outcome, so a filesystem error can never surface
 * as a successful verification. The message carries the failing
 * operation and the underlying error, plus the lock-timeout remedy
 * whenever the failure is lock contention.
 */
final class FilesystemStorageException extends \RuntimeException
{
}
