<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Http;

/**
 * Duplicate JSON key scanner: a small recursive walk over the RAW JSON
 * document that reports the first object key seen more than once at the
 * same level. json_decode silently keeps the last occurrence, which is
 * exactly the parser ambiguity the security-sensitive endpoints must
 * refuse ({"secret":"A","secret":"B"} parses differently across CDNs,
 * WAFs, proxies and logging layers — first-wins in one, last-wins in
 * another). A decode-then-scan approach can NEVER see a duplicate: the
 * decode has already collapsed the object members, so the walker works
 * directly on the raw bytes.
 *
 * The scanner only needs to be correct on documents json_decode already
 * accepts; a malformed document is handled by the strict json_decode
 * check that follows. The recursion is bounded by the depth cap, so a
 * depth bomb cannot exhaust the stack.
 */
final class JsonDuplicateKeyScanner
{
    private const MAX_DEPTH = 32;

    /**
     * @return string|null the first duplicated key, or null when the
     *                     document is clean or cannot be walked
     */
    public function scanForDuplicateJsonKey(string $json): ?string
    {
        $offset = 0;
        try {
            $this->scanJsonValue($json, $offset, 0);

            return null;
        } catch (DuplicateJsonKeyException $e) {
            return $e->key;
        }
        // MalformedJsonWalkException deliberately PROPAGATES: the caller
        // must distinguish "no duplicate found" from "the scanner could
        // not establish cleanliness" (a >MAX_DEPTH document, a malformed
        // string). Treating the unwalkable document as clean would let a
        // deep-nested first value hide a duplicate from the scanner while
        // the final parser (whose depth ceiling is the SAME 32) still
        // accepts it — the fail-open depth bypass.
    }

    /**
     * Recursive JSON walker: consumes one value starting at $offset and
     * throws {@see DuplicateJsonKeyException} on the first duplicated
     * object key and {@see MalformedJsonWalkException} on anything it
     * cannot walk. Both are internal control flow: the walker never
     * validates the document, it only scans it.
     *
     * @param int $offset position in the raw JSON string (by reference)
     */
    private function scanJsonValue(string $json, int &$offset, int $depth): void
    {
        if ($depth > self::MAX_DEPTH) {
            // Depth bomb: beyond the cap the document is "not walkable",
            // and the strict json_decode below (which has its own depth
            // guard) rejects it.
            throw new MalformedJsonWalkException();
        }
        $length = \strlen($json);
        $this->skipJsonWhitespace($json, $offset);
        if ($offset >= $length) {
            throw new MalformedJsonWalkException();
        }
        $ch = $json[$offset];

        if ($ch === '{') {
            $offset++;
            $this->skipJsonWhitespace($json, $offset);
            if ($offset < $length && $json[$offset] === '}') {
                $offset++;

                return;
            }
            $seen = [];
            while (true) {
                $this->skipJsonWhitespace($json, $offset);
                $key = $this->scanJsonString($json, $offset);
                if ($key === null) {
                    throw new MalformedJsonWalkException();
                }
                if (isset($seen[$key])) {
                    throw new DuplicateJsonKeyException($key);
                }
                $seen[$key] = true;
                $this->skipJsonWhitespace($json, $offset);
                if ($offset >= $length || $json[$offset] !== ':') {
                    throw new MalformedJsonWalkException();
                }
                $offset++;
                $this->scanJsonValue($json, $offset, $depth + 1);
                $this->skipJsonWhitespace($json, $offset);
                if ($offset >= $length) {
                    throw new MalformedJsonWalkException();
                }
                $ch = $json[$offset];
                $offset++;
                if ($ch === '}') {
                    return;
                }
                if ($ch !== ',') {
                    throw new MalformedJsonWalkException();
                }
            }
        }

        if ($ch === '[') {
            $offset++;
            $this->skipJsonWhitespace($json, $offset);
            if ($offset < $length && $json[$offset] === ']') {
                $offset++;

                return;
            }
            while (true) {
                $this->scanJsonValue($json, $offset, $depth + 1);
                $this->skipJsonWhitespace($json, $offset);
                if ($offset >= $length) {
                    throw new MalformedJsonWalkException();
                }
                $ch = $json[$offset];
                $offset++;
                if ($ch === ']') {
                    return;
                }
                if ($ch !== ',') {
                    throw new MalformedJsonWalkException();
                }
            }
        }

        if ($ch === '"') {
            $this->scanJsonString($json, $offset);

            return;
        }

        // number / true / false / null: skip a bare token.
        while ($offset < $length) {
            $ch = $json[$offset];
            if ($ch === ',' || $ch === '}' || $ch === ']' || $ch === ' ' || $ch === "\t" || $ch === "\n" || $ch === "\r") {
                break;
            }
            $offset++;
        }
    }

    /**
     * Consume one JSON string starting at $offset (which must point at the
     * opening quote) and return its decoded content, escape sequences
     * resolved to the actual characters. Duplicate detection compares
     * semantic keys: {"a":1,"\u0061":2} is one key spelled twice, exactly
     * the parser ambiguity the scan refuses (json_decode canonicalizes
     * both spellings into the same key). The JSON string grammar is
     * decoded with json_decode itself, the surrogate-safe canonical
     * decoder. null when the string cannot be walked or its content is
     * not decodable (a malformed document; the strict json_decode check
     * that follows rejects it).
     *
     * @param int $offset position in the raw JSON string (by reference)
     */
    private function scanJsonString(string $json, int &$offset): ?string
    {
        $length = \strlen($json);
        if ($offset >= $length || $json[$offset] !== '"') {
            return null;
        }
        $end = $offset + 1;
        while ($end < $length) {
            $ch = $json[$end];
            if ($ch === '\\') {
                $end += 2;

                continue;
            }
            if ($ch === '"') {
                break;
            }
            $end++;
        }
        if ($end >= $length) {
            return null;
        }
        $raw = substr($json, $offset, $end - $offset + 1);
        try {
            $decoded = json_decode($raw, true, 4, JSON_THROW_ON_ERROR);
        } catch (\JsonException) {
            // A malformed escape, an unpaired surrogate or invalid UTF-8
            // inside a string makes the per-string decode fail: that is a
            // scanner-internal walker failure, translated into the scanner's
            // own malformed sentinel so no JsonException can ever escape the
            // scanner (callers must only ever see DuplicateJsonKeyException
            // or MalformedJsonWalkException).
            throw new MalformedJsonWalkException();
        }
        if (!\is_string($decoded)) {
            return null;
        }
        $offset = $end + 1;

        return $decoded;
    }

    private function skipJsonWhitespace(string $json, int &$offset): void
    {
        $length = \strlen($json);
        while ($offset < $length) {
            $ch = $json[$offset];
            if ($ch !== ' ' && $ch !== "\t" && $ch !== "\n" && $ch !== "\r") {
                break;
            }
            $offset++;
        }
    }
}

final class DuplicateJsonKeyException extends \RuntimeException
{
    public function __construct(public readonly string $key)
    {
        parent::__construct('duplicate JSON object key: '.$key);
    }
}

final class MalformedJsonWalkException extends \RuntimeException
{
}
