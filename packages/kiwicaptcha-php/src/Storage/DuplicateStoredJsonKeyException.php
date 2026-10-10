<?php

declare(strict_types=1);

namespace KiwiCaptcha\Storage;

/**
 * A stored JSON document carries two members whose keys decode to the
 * same semantic name (an escaped alias such as "st\u0061te" counts as
 * "state"): the document is ambiguous and must never be trusted.
 */
final class DuplicateStoredJsonKeyException extends StoredJsonException
{
    public function __construct(
        public readonly string $key,
    ) {
        parent::__construct(sprintf('the stored JSON document duplicates the semantic key "%s"', $key));
    }
}
