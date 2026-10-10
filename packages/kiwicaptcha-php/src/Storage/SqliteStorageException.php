<?php

declare(strict_types=1);

namespace KiwiCaptcha\Storage;

/**
 * The SQLite storage backend refused or could not complete a
 * durability-critical operation: the single write lock stayed held
 * past the busy timeout, the database file is corrupt, or the IO
 * layer failed.
 *
 * Fail-closed by design: the verifier maps any storage throw to its
 * typed unavailable outcome, so an SQLite error can never surface as a
 * successful verification. The message carries the failing operation
 * and the driver error, plus the busy-timeout remedy whenever the
 * failure is write-lock contention.
 */
final class SqliteStorageException extends \RuntimeException
{
}
