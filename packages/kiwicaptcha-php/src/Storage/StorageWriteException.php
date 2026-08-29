<?php

declare(strict_types=1);

namespace KiwiCaptcha\Storage;

/**
 * A storage backend refused a durability-critical write without raising
 * its own error — the PSR-6 {@see \Psr\Cache\CacheItemPoolInterface::save()}
 * === false contract.
 *
 * Thrown fail-closed by {@see Psr6Storage} on the two writes whose
 * silent loss would corrupt the one-shot security model.
 *
 *  - store(): a challenge handed to a client whose record never landed
 *    would 404 at verify time, the client did the work for nothing.
 *  - consume(): a pending→consumed flip whose save failed would leave
 *    the record pending while the verifier proceeds as the consume
 *    winner, a sequential replay window.
 *
 * The exception escapes store() before the challenge is returned, and
 * the Verifier maps a consume() throw onto its existing typed
 * indeterminate outcome through the consume catch, so a failed save can
 * never surface as a successful verification.
 */
final class StorageWriteException extends \RuntimeException
{
}
