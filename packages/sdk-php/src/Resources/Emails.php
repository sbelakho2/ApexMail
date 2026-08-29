<?php

declare(strict_types=1);

namespace ApexMail\Resources;

use ApexMail\Client;

/**
 * Send and manage transactional emails.
 */
class Emails
{
    public function __construct(private readonly Client $client) {}

    /**
     * Send a single email.
     *
     * The serialized body matches the server's SendMessageRequest exactly:
     * from/to/cc/bcc are sent as BARE address strings (not {email, name}
     * objects), and only fields the API accepts are serialized. Inputs the
     * API does not support are still accepted here for backwards
     * compatibility but are NOT sent: display names (the API has no name
     * fields), template_id/template_data, attachments, priority, and
     * reply_to (no such field on the server). Use html/text for the body;
     * tags are serialized as a list of strings.
     *
     * @param array $params {
     *   @type string|array  $from            Sender ("addr" or ["email" => ..., "name" => ...])
     *   @type string|array  $to              Recipient(s)
     *   @type string        $subject
     *   @type string        $html            HTML body
     *   @type string        $text            Plain-text body
     *   @type array         $tags            List of strings (or {name, value} maps, flattened)
     *   @type string        $scheduled_at    ISO 8601 (snake_case on the wire)
     *   @type array         $metadata
     *   @type string        $idempotency_key
     * }
     * @return array The API response: {id, status, created_at}. When no
     *   idempotency_key is supplied, one is generated automatically so that
     *   transport-level retries can never cause a duplicate send (SDK-B).
     */
    public function send(array $params): array
    {
        // isset + trim checks, NOT empty(): in PHP empty("0") === true, so
        // a transactional email whose subject or body is literally "0"
        // (counters, order states) was rejected as "required field missing".
        // Arrays (recipient lists / address specs) must not be cast to
        // string — non-empty arrays are non-empty by definition.
        $fromSet = isset($params['from'])
            && (is_array($params['from']) ? $params['from'] !== [] : trim((string) $params['from']) !== '');
        $toSet = isset($params['to'])
            && (is_array($params['to']) ? $params['to'] !== [] : trim((string) $params['to']) !== '');
        if (!$fromSet) {
            throw new \InvalidArgumentException('"from" is required');
        }
        if (!$toSet) {
            throw new \InvalidArgumentException('"to" is required');
        }
        if (!isset($params['subject']) || trim((string) $params['subject']) === '') {
            throw new \InvalidArgumentException('"subject" is required');
        }
        $htmlSet = isset($params['html']) && trim((string) $params['html']) !== '';
        $textSet = isset($params['text']) && trim((string) $params['text']) !== '';
        if (!$htmlSet && !$textSet) {
            throw new \InvalidArgumentException('Either "html" or "text" body is required');
        }

        $this->validateRecipients($params['from'], 'from');
        $this->validateRecipients($params['to'], 'to');
        if (!empty($params['cc'])) {
            $this->validateRecipients($params['cc'], 'cc');
        }
        if (!empty($params['bcc'])) {
            $this->validateRecipients($params['bcc'], 'bcc');
        }

        // SDK-B: automatic idempotency key (caller-supplied key wins) so a
        // retried POST can never enqueue the same message twice.
        $idempotencyKey = $params['idempotency_key'] ?? null;
        if ($idempotencyKey === null || $idempotencyKey === '') {
            $idempotencyKey = Client::uuid4();
        }

        return $this->client->request(
            'POST',
            '/v1/messages',
            $this->buildSendPayload($params),
            $idempotencyKey,
        );
    }

    /**
     * Send up to 1,000 emails in a single request.
     *
     * @param array[] $messages  Array of parameter arrays (same shape as send())
     * @param string|null $idempotencyKey Optional caller-supplied key; a random
     *   UUID v4 is generated when omitted (SDK-B).
     * @return array The API response: {accepted, rejected, results: [{index,
     *   id?, status, error?}]}
     */
    public function batch(array $messages, ?string $idempotencyKey = null): array
    {
        return $this->client->request('POST', '/v1/messages/batch', [
            'messages' => array_map([$this, 'buildSendPayload'], $messages),
        ], $idempotencyKey ?? Client::uuid4());
    }

    /** Get an email by ID. */
    public function get(string $id): array
    {
        return $this->client->request('GET', '/v1/messages/' . urlencode($id));
    }

    /**
     * List emails with optional filters.
     *
     * The server's ListMessagesQuery accepts {limit, offset, cursor,
     * status, sort_by} only — unknown query parameters are rejected.
     *
     * @param array $options { status, limit, offset, cursor, sort_by }
     */
    public function list(array $options = []): array
    {
        $query = http_build_query(array_filter([
            'status'  => $options['status']  ?? null,
            'limit'   => $options['limit']   ?? 20,
            'offset'  => $options['offset']  ?? 0,
            'cursor'  => $options['cursor']  ?? null,
            'sort_by' => $options['sort_by'] ?? $options['sortBy'] ?? null,
        ], static fn ($v) => $v !== null && $v !== ''));

        return $this->client->request('GET', '/v1/messages' . ($query ? '?' . $query : ''));
    }

    // ── Private helpers ─────────────────────────────────────────────────────

    /**
     * Build the wire payload for a send, matching the server's
     * SendMessageRequest (messages.rs, `deny_unknown_fields`) exactly:
     * {from: string, to: string[], cc?, bcc?, subject, html?, text?,
     *  tags?: string[], metadata?, scheduled_at?}.
     *
     * Legacy SDK inputs that the API does NOT accept — display names inside
     * {email, name} objects, reply_to, template_id/template_data,
     * attachments, priority — are still validated as inputs but are NOT
     * serialized: sending them would be rejected with 422 by
     * deny_unknown_fields.
     */
    private function buildSendPayload(array $params): array
    {
        $tags = $this->normalizeTags($params['tags'] ?? null);

        return array_filter([
            'from'         => $this->normalizeAddress($params['from'] ?? null),
            'to'           => $this->normalizeRecipients($params['to'] ?? null),
            'cc'           => $this->normalizeRecipients($params['cc'] ?? null),
            'bcc'          => $this->normalizeRecipients($params['bcc'] ?? null),
            'subject'      => $params['subject'] ?? null,
            'html'         => $params['html'] ?? null,
            'text'         => $params['text'] ?? null,
            'tags'         => $tags,
            'scheduled_at' => $params['scheduled_at'] ?? $params['scheduledAt'] ?? null,
            'metadata'     => $params['metadata'] ?? null,
        ], static fn ($v) => $v !== null && $v !== []);
    }

    /**
     * Extract the bare address string from an address input. The API's
     * SendMessageRequest has NO display-name field, so a {email, name}
     * object contributes only its `email` on the wire (the name is accepted
     * as input for backwards compatibility but unused).
     */
    private function normalizeAddress(mixed $addr): ?string
    {
        if ($addr === null) {
            return null;
        }
        if (is_array($addr)) {
            $email = $addr['email'] ?? $addr['address'] ?? null;
            return $email === null ? null : (string) $email;
        }
        return (string) $addr;
    }

    /**
     * Recipients are sent as a plain list of address strings — the API
     * rejects the historical {email, name} object wrappers (422 via
     * deny_unknown_fields).
     */
    private function normalizeRecipients(mixed $recips): ?array
    {
        if ($recips === null) {
            return null;
        }
        $normalized = array_map(
            fn ($recipient) => $this->normalizeAddress($recipient),
            (array) $recips,
        );

        return array_values(array_filter($normalized, static fn ($v) => $v !== null));
    }

    /**
     * The API requires tags to be a Vec<String>. Callers historically passed
     * [{name: ..., value: ...}] objects — keep accepting them on input, but
     * send each tag rendered as "name" or "name=value".
     */
    private function normalizeTags(mixed $tags): ?array
    {
        if ($tags === null) {
            return null;
        }
        $normalized = [];
        foreach ((array) $tags as $tag) {
            if (is_array($tag)) {
                $name = $tag['name'] ?? null;
                if ($name === null) {
                    continue;
                }
                $value = $tag['value'] ?? null;
                $normalized[] = $value === null ? (string) $name : $name . '=' . $value;
            } else {
                $normalized[] = (string) $tag;
            }
        }

        return $normalized === [] ? null : $normalized;
    }

    private function validateRecipients(mixed $recips, string $field): void
    {
        // A single address spec {email: ..., name: ...} is one recipient, not
        // a list of its values — wrapping it first prevents the foreach from
        // validating the display name as an address.
        if (is_array($recips) && array_is_list($recips) === false && isset($recips['email'])) {
            $recips = [$recips];
        }
        $list = (array) $recips;
        if (count($list) === 0) {
            throw new \InvalidArgumentException("\"{$field}\" must include at least one recipient");
        }

        foreach ($list as $recipient) {
            $email = is_array($recipient) ? ($recipient['email'] ?? null) : $recipient;
            if (!$email || !$this->isValidEmail((string) $email)) {
                throw new \InvalidArgumentException("Invalid \"{$field}\" email format: {$email}");
            }
        }
    }

    private function isValidEmail(string $email): bool
    {
        if (filter_var($email, FILTER_VALIDATE_EMAIL)) {
            return true;
        }

        $parts = explode('@', $email);
        if (count($parts) !== 2) {
            return false;
        }

        [$local, $domain] = $parts;
        if ($local === '' || $domain === '') {
            return false;
        }

        if (function_exists('idn_to_ascii')) {
            $asciiDomain = idn_to_ascii($domain, IDNA_DEFAULT, INTL_IDNA_VARIANT_UTS46);
            if ($asciiDomain === false) {
                return false;
            }
            return (bool) filter_var("{$local}@{$asciiDomain}", FILTER_VALIDATE_EMAIL);
        }

        return false;
    }

    private function normalizeSendParams(array $params): array
    {
        return $this->buildSendPayload($params);
    }
}
