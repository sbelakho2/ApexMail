<?php

declare(strict_types=1);

namespace KiwiCaptcha;

/**
 * Marker interface for storage backends that guarantee STRICT single-use
 * under concurrency: `consume()` atomically loads and deletes, so two
 * concurrent consumers can never both win and a second call for the same
 * nonce MUST return null.
 *
 * Plain {@see StorageInterface} implementations (e.g. PSR-6 pools) are
 * best-effort: consume() removes the record, but the read and the delete
 * cannot be fused, so racing requests may both observe it.
 */
interface AtomicStorageInterface extends StorageInterface
{
}
