<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Http;

use Symfony\Component\HttpFoundation\Request;

/**
 * Resolves a submitted form field whatever its nesting depth.
 *
 * Symfony forms nest their data under the form name
 * (`signup[kiwi_request_binding]` arrives as `['signup' =>
 * ['kiwi_request_binding' => ...]]`), so a flat
 * `$request->request->get($field)` misses every nested submission. The
 * lookup walks the request payload one bounded level of nesting at a
 * time, so both flat and nested bindings resolve.
 *
 * Ambiguity fails closed: two distinct values under the same field name
 * (two forms each carrying one) answer null, never a guess. Non-scalar
 * values are never usable field values and answer null.
 */
final class RequestFieldResolver
{
    /** The maximum nesting depth the lookup walks (form + embedded form). */
    private const MAX_DEPTH = 3;

    /**
     * The scalar string value submitted under $field, whatever its
     * nesting depth. Null when absent, non-scalar, or ambiguous.
     */
    public static function string(Request $request, string $field): ?string
    {
        $found = [];
        self::collect($request->request->all(), $field, $found, self::MAX_DEPTH);
        if ($found === []) {
            // The payload bag merges JSON bodies too; fall back to it
            // for clients that posted nested JSON.
            try {
                self::collect($request->getPayload()->all(), $field, $found, self::MAX_DEPTH);
            } catch (\Throwable) {
                // No payload bag: the form body is the only source.
            }
        }
        if ($found === []) {
            return null;
        }
        $distinct = array_values(array_unique($found));
        if (\count($distinct) !== 1) {
            // Two different values under one name: deterministic null,
            // never a guess.
            return null;
        }

        return $distinct[0];
    }

    /**
     * The submitted values of the configured target fields, keyed by
     * field name — the nested-aware shape of a flat request read.
     *
     * @param list<string> $fields
     *
     * @return array<string, string>
     */
    public static function targetFields(Request $request, array $fields): array
    {
        $resolved = [];
        foreach ($fields as $name) {
            $value = self::string($request, $name);
            if ($value !== null && $value !== '') {
                $resolved[$name] = $value;
            }
        }

        return $resolved;
    }

    /**
     * @param array<mixed>          $data
     * @param array<int, string>    $found
     */
    private static function collect(array $data, string $field, array &$found, int $depth): void
    {
        foreach ($data as $key => $value) {
            if ($key === $field) {
                if (\is_string($value)) {
                    $found[] = $value;
                }
                continue;
            }
            if ($depth > 0 && \is_array($value)) {
                self::collect($value, $field, $found, $depth - 1);
            }
        }
    }
}
