<?php

declare(strict_types=1);

namespace KiwiCaptcha\Storage;

/**
 * Cleanliness cannot be established for the stored JSON document
 * (oversized, malformed, over the depth ceiling): the document is
 * refused, never treated as clean.
 */
final class MalformedStoredJsonException extends StoredJsonException
{
}
