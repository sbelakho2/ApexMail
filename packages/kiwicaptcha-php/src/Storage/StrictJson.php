<?php

declare(strict_types=1);

namespace KiwiCaptcha\Storage;

/**
 * The strict persisted-JSON authority: every stored security-state
 * document is decoded through here, and a document that is oversized,
 * malformed, or carries two members with the same decoded (semantic)
 * name is refused before the collapsed object is trusted.
 *
 * JSON object keys may carry escapes: `{"state":1,"st\u0061te":2}` is
 * the same field written twice, and every decoder (json_decode, cjson,
 * serde) resolves both to `state`, keeping one of them. A decode-then-
 * validate path can therefore never see the ambiguity, and a security
 * state machine that decodes first and validates after can be tricked
 * into reading one semantic value while a later re-encode heals the
 * document into a clean object. The duplicate scan runs on the RAW
 * bytes and compares keys after JSON unescaping, exactly like the HTTP
 * layer's request-body scanner.
 *
 * Fail-closed by design: an unwalkable document (over the byte ceiling,
 * over the depth ceiling, unterminated string, malformed token) throws
 * {@see MalformedStoredJsonException}; a semantic duplicate throws
 * {@see DuplicateStoredJsonKeyException}. Callers that want a nullable
 * decode use {@see decodeObject()}, which converts both to null —
 * "cannot establish cleanliness" is never treated as clean.
 */
final class StrictJson
{
    /**
     * The shared stored-document byte ceiling (the same 128 KiB bound the
     * Rust decoder enforces before parsing and the Lua envelope parser
     * enforces before cjson): a value beyond it is refused before any
     * JSON parse or duplicate scan.
     */
    public const MAX_BYTES = 131072;

    /** The nesting depth ceiling of the duplicate scan. */
    public const MAX_DEPTH = 32;

    /**
     * Decode a stored JSON object strictly: the byte ceiling, the
     * recursive semantic-duplicate scan, then json_decode. Null when the
     * document is oversized, malformed, ambiguous, not an object, or
     * decodes to something other than an array.
     *
     * @return array<string, mixed>|null
     */
    public static function decodeObject(string $raw, int $maxBytes = self::MAX_BYTES): ?array
    {
        // A stored security document is a JSON object: a top-level array
        // is refused here (PHP's assoc decode cannot distinguish it from
        // an object once decoded).
        if (self::skipWhitespace($raw, 0) >= \strlen($raw) || $raw[self::skipWhitespace($raw, 0)] !== '{') {
            return null;
        }
        try {
            self::assertUnique($raw, $maxBytes);
        } catch (StoredJsonException) {
            return null;
        }
        try {
            $decoded = json_decode($raw, true, 512, JSON_THROW_ON_ERROR);
        } catch (\JsonException) {
            return null;
        }

        return \is_array($decoded) ? $decoded : null;
    }

    /**
     * Assert that a raw JSON document carries no semantic duplicate key,
     * at any nesting level, and is not oversized/malformed.
     *
     * @throws DuplicateStoredJsonKeyException on the first repeated decoded key
     * @throws MalformedStoredJsonException    when cleanliness cannot be established
     */
    public static function assertUnique(string $raw, int $maxBytes = self::MAX_BYTES): void
    {
        if (\strlen($raw) > $maxBytes) {
            throw new MalformedStoredJsonException(sprintf(
                'the stored JSON document exceeds the %d-byte ceiling (%d bytes)',
                $maxBytes,
                \strlen($raw),
            ));
        }
        $offset = self::skipWhitespace($raw, 0);
        $end = self::scanValue($raw, $offset, 0);
        $end = self::skipWhitespace($raw, $end);
        if ($end !== \strlen($raw)) {
            throw new MalformedStoredJsonException('trailing bytes after the JSON document');
        }
    }

    /** The index after the value that starts at $offset, or throws. */
    private static function scanValue(string $json, int $offset, int $depth): int
    {
        if ($depth > self::MAX_DEPTH) {
            throw new MalformedStoredJsonException('the stored JSON nests beyond the depth ceiling');
        }
        if ($offset >= \strlen($json)) {
            throw new MalformedStoredJsonException('unexpected end of the stored JSON document');
        }
        $char = $json[$offset];
        if ($char === '{') {
            return self::scanObject($json, $offset, $depth);
        }
        if ($char === '[') {
            return self::scanArray($json, $offset, $depth);
        }
        if ($char === '"') {
            return self::scanString($json, $offset);
        }
        // A bare token: number, true, false, null.
        $end = $offset;
        $length = \strlen($json);
        while ($end < $length) {
            $candidate = $json[$end];
            if ($candidate === ',' || $candidate === '}' || $candidate === ']'
                || $candidate === ' ' || $candidate === "\t" || $candidate === "\r" || $candidate === "\n"
            ) {
                break;
            }
            ++$end;
        }
        if ($end === $offset) {
            throw new MalformedStoredJsonException('empty JSON value');
        }

        return $end;
    }

    private static function scanObject(string $json, int $offset, int $depth): int
    {
        $length = \strlen($json);
        $seen = [];
        $cursor = self::skipWhitespace($json, $offset + 1);
        if ($cursor < $length && $json[$cursor] === '}') {
            return $cursor + 1;
        }
        while (true) {
            $cursor = self::skipWhitespace($json, $cursor);
            if ($cursor >= $length || $json[$cursor] !== '"') {
                throw new MalformedStoredJsonException('expected a JSON object key');
            }
            $keyEnd = self::scanString($json, $cursor);
            $key = self::decodeStringToken($json, $cursor, $keyEnd);
            if (isset($seen[$key])) {
                throw new DuplicateStoredJsonKeyException($key);
            }
            $seen[$key] = true;
            $cursor = self::skipWhitespace($json, $keyEnd);
            if ($cursor >= $length || $json[$cursor] !== ':') {
                throw new MalformedStoredJsonException('expected a colon after the JSON object key');
            }
            $cursor = self::scanValue($json, self::skipWhitespace($json, $cursor + 1), $depth + 1);
            $cursor = self::skipWhitespace($json, $cursor);
            if ($cursor >= $length) {
                throw new MalformedStoredJsonException('unterminated JSON object');
            }
            if ($json[$cursor] === ',') {
                ++$cursor;
                continue;
            }
            if ($json[$cursor] === '}') {
                return $cursor + 1;
            }
            throw new MalformedStoredJsonException('expected a comma or the end of the JSON object');
        }
    }

    private static function scanArray(string $json, int $offset, int $depth): int
    {
        $length = \strlen($json);
        $cursor = self::skipWhitespace($json, $offset + 1);
        if ($cursor < $length && $json[$cursor] === ']') {
            return $cursor + 1;
        }
        while (true) {
            $cursor = self::scanValue($json, self::skipWhitespace($json, $cursor), $depth + 1);
            $cursor = self::skipWhitespace($json, $cursor);
            if ($cursor >= $length) {
                throw new MalformedStoredJsonException('unterminated JSON array');
            }
            if ($json[$cursor] === ',') {
                ++$cursor;
                continue;
            }
            if ($json[$cursor] === ']') {
                return $cursor + 1;
            }
            throw new MalformedStoredJsonException('expected a comma or the end of the JSON array');
        }
    }

    /** The index after the closing quote of the string starting at $offset. */
    private static function scanString(string $json, int $offset): int
    {
        $length = \strlen($json);
        $cursor = $offset + 1;
        while ($cursor < $length) {
            $char = $json[$cursor];
            if ($char === '\\') {
                $cursor += 2;
                continue;
            }
            if ($char === '"') {
                return $cursor + 1;
            }
            ++$cursor;
        }
        throw new MalformedStoredJsonException('unterminated JSON string');
    }

    /** The decoded value of the string token spanning [$start, $end). */
    private static function decodeStringToken(string $json, int $start, int $end): string
    {
        try {
            $decoded = json_decode(substr($json, $start, $end - $start), true, 4, JSON_THROW_ON_ERROR);
        } catch (\JsonException $e) {
            throw new MalformedStoredJsonException('undecodable JSON string token: '.$e->getMessage());
        }
        if (!\is_string($decoded)) {
            throw new MalformedStoredJsonException('a JSON object key must be a string');
        }

        return $decoded;
    }

    private static function skipWhitespace(string $json, int $offset): int
    {
        $length = \strlen($json);
        while ($offset < $length) {
            $char = $json[$offset];
            if ($char !== ' ' && $char !== "\t" && $char !== "\r" && $char !== "\n") {
                break;
            }
            ++$offset;
        }

        return $offset;
    }
}
