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
     * Every accepted option is serialized (F48) — nothing is dropped
     * silently: from/to/cc/bcc/reply_to are sent as address strings with
     * display names preserved as RFC 5322 "Name <addr>" forms
     * (["email" => ..., "name" => ...] inputs keep their name), tags as a
     * list of strings, scheduled_at snake_case, and reply_to, attachments,
     * headers, priority, template_id/template_data under their documented
     * snake_case field names.
     *
     * @param array $params {
     *   @type string|array  $from            Sender ("addr" or ["email" => ..., "name" => ...])
     *   @type string|array  $to              Recipient(s)
     *   @type string        $subject
     *   @type string        $html            HTML body
     *   @type string        $text            Plain-text body
     *   @type string|array  $reply_to        Reply-To address (display-name aware)
     *   @type array         $attachments     [{filename, content, contentType}, ...]
     *   @type array         $headers         Custom email headers
     *   @type int|string    $priority        Queue priority: integer 1-10 or a
     *                                        named level "high"/"normal"/"low"
     *                                        (API queue integers 7/5/3 — F48
     *                                        shared contract)
     *   @type string        $template_id
     *   @type array         $template_data
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
        $replyTo = $params['reply_to'] ?? $params['replyTo'] ?? null;
        if ($replyTo !== null && $replyTo !== '') {
            $this->validateRecipients($replyTo, 'reply_to');
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
     * Build the wire payload for a send (F48: every accepted option is
     * serialized — nothing is dropped silently):
     * {from, to, cc?, bcc?, reply_to?, subject, html?, text?,
     *  attachments?, headers?, priority?, template_id?, template_data?,
     *  tags?: string[], metadata?, scheduled_at?}.
     *
     * Address inputs ("addr" or ["email" => ..., "name" => ...]) serialize
     * as address strings with display names preserved as "Name <addr>"
     * forms. Attachments pass through in their documented shape
     * ({filename, content, contentType}); headers/priority/template
     * options are forwarded under their documented snake_case names.
     */
    private function buildSendPayload(array $params): array
    {
        $tags = $this->normalizeTags($params['tags'] ?? null);
        $scheduledAt = $params['scheduled_at'] ?? $params['scheduledAt'] ?? null;
        $replyTo = $params['reply_to'] ?? $params['replyTo'] ?? null;
        $templateId = $params['template_id'] ?? $params['templateId'] ?? null;
        $templateData = $params['template_data'] ?? $params['templateData'] ?? null;

        return array_filter([
            'from'          => $this->serializeAddress($params['from'] ?? null),
            'to'            => $this->serializeRecipients($params['to'] ?? null),
            'cc'            => $this->serializeRecipients($params['cc'] ?? null),
            'bcc'           => $this->serializeRecipients($params['bcc'] ?? null),
            'reply_to'      => $replyTo === null ? null : $this->serializeAddress($replyTo),
            'subject'       => $params['subject'] ?? null,
            'html'          => $params['html'] ?? null,
            'text'          => $params['text'] ?? null,
            'attachments'   => $params['attachments'] ?? null,
            'headers'       => $params['headers'] ?? null,
            'priority'      => $this->normalizePriority($params['priority'] ?? null),
            'template_id'   => $templateId,
            'template_data' => $templateData,
            'tags'          => $tags,
            'scheduled_at'  => $scheduledAt,
            'metadata'      => $params['metadata'] ?? null,
        ], static fn ($v) => $v !== null && $v !== []);
    }

    /**
     * F48 shared contract (packages/contract/send-contract.json): priority is
     * an integer 1-10 (kept as an int on the wire — the API deserializer
     * takes JSON numbers, not numeric strings) or one of the documented
     * named levels "high"/"normal"/"low" (case-insensitive, canonicalized to
     * lowercase; the API maps them to queue integers 7/5/3). Anything else is
     * rejected client-side with an error naming the contract.
     */
    private function normalizePriority(mixed $priority): int|string|null
    {
        if ($priority === null) {
            return null;
        }
        if (is_bool($priority)) {
            throw new \InvalidArgumentException(self::priorityContract() . " — received the boolean " . var_export($priority, true));
        }
        if (is_int($priority)) {
            if ($priority < 1 || $priority > 10) {
                throw new \InvalidArgumentException(self::priorityContract() . " — received the out-of-range integer {$priority}");
            }
            return $priority;
        }
        if (is_float($priority) || (is_string($priority) && ctype_digit($priority))) {
            throw new \InvalidArgumentException(self::priorityContract() . ' — plain integers must be PHP ints, not numeric strings/floats');
        }
        if (!is_string($priority)) {
            throw new \InvalidArgumentException(self::priorityContract() . ' — received ' . get_debug_type($priority));
        }
        $level = strtolower(trim($priority));
        return match ($level) {
            'high', 'normal', 'low' => $level,
            default => throw new \InvalidArgumentException(self::priorityContract() . " — received '{$priority}'"),
        };
    }

    private static function priorityContract(): string
    {
        return 'priority must be an integer between 1 and 10 or one of the named levels '
            . '"high"/"normal"/"low" (mapped to 7/5/3)';
    }

    /**
     * Serialize one address input, preserving the display name (F48): a
     * ["email" => ..., "name" => ...] array becomes "Name <email>"; a bare
     * string passes through unchanged.
     */
    private function serializeAddress(mixed $addr): ?string
    {
        if ($addr === null) {
            return null;
        }
        if (is_array($addr)) {
            $email = $addr['email'] ?? $addr['address'] ?? null;
            if ($email === null) {
                return null;
            }
            $name = $addr['name'] ?? null;
            if ($name !== null && trim((string) $name) !== '') {
                return "{$name} <{$email}>";
            }
            return (string) $email;
        }
        return (string) $addr;
    }

    /**
     * Recipients are sent as a list of address strings with display names
     * preserved as "Name <addr>" forms (F48).
     */
    private function serializeRecipients(mixed $recips): ?array
    {
        if ($recips === null) {
            return null;
        }
        // A single address spec is one recipient, not a list of its values.
        if (is_array($recips) && array_is_list($recips) === false) {
            $recips = [$recips];
        }
        $normalized = array_map(
            fn ($recipient) => $this->serializeAddress($recipient),
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
            if (!is_string($email)) {
                throw new \InvalidArgumentException("Invalid \"{$field}\" email format: " . var_export($email, true));
            }
            // F48: validate the extracted BARE addr-spec — "Name <addr>"
            // display strings are accepted exactly like the API's mailbox
            // parser accepts them.
            $bare = $this->bareAddress($email);
            if (!$bare || !$this->isValidEmail($bare)) {
                throw new \InvalidArgumentException("Invalid \"{$field}\" email format: {$email}");
            }
        }
    }

    /**
     * Strip an RFC 5322 display-name form to its bare addr-spec
     * ("Name <a@b.c>" → "a@b.c"); bare strings pass through unchanged.
     */
    private function bareAddress(string $value): string
    {
        $value = trim($value);
        $open = strrpos($value, '<');
        if ($open !== false) {
            $close = strrpos($value, '>');
            if ($close === false || $close < $open) {
                return '';
            }
            return trim(substr($value, $open + 1, $close - $open - 1));
        }
        return $value;
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
