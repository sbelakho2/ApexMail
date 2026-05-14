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
     * @param array $params {
     *   @type string|array  $from            Sender ("addr" or ["email" => ..., "name" => ...])
     *   @type string|array  $to              Recipient(s)
     *   @type string        $subject
     *   @type string        $html            HTML body
     *   @type string        $text            Plain-text body
     *   @type string        $template_id
     *   @type array         $template_data
     *   @type array         $attachments
     *   @type array         $tags
     *   @type string        $priority        "high" | "normal" | "low"
     *   @type string        $scheduled_at    ISO 8601
     *   @type string        $idempotency_key
     * }
     * @return array
     */
    public function send(array $params): array
    {
        if (empty($params['from'])) {
            throw new \InvalidArgumentException('"from" is required');
        }
        if (empty($params['to'])) {
            throw new \InvalidArgumentException('"to" is required');
        }
        if (empty($params['subject'])) {
            throw new \InvalidArgumentException('"subject" is required');
        }
        if (empty($params['html']) && empty($params['text'])) {
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

        $idempotencyKey = $params['idempotency_key'] ?? null;

        $body = array_filter([
            'from'         => $this->normalizeAddress($params['from'] ?? null),
            'to'           => $this->normalizeRecipients($params['to'] ?? null),
            'cc'           => $this->normalizeRecipients($params['cc'] ?? null),
            'bcc'          => $this->normalizeRecipients($params['bcc'] ?? null),
            'replyTo'      => $params['reply_to'] ?? $params['replyTo'] ?? null,
            'subject'      => $params['subject'] ?? null,
            'html'         => $params['html'] ?? null,
            'text'         => $params['text'] ?? null,
            'templateId'   => $params['template_id'] ?? $params['templateId'] ?? null,
            'templateData' => $params['template_data'] ?? $params['templateData'] ?? null,
            'attachments'  => $params['attachments'] ?? null,
            'tags'         => $params['tags'] ?? null,
            'priority'     => $params['priority'] ?? null,
            'scheduledAt'  => $params['scheduled_at'] ?? $params['scheduledAt'] ?? null,
            'metadata'     => $params['metadata'] ?? null,
        ], static fn ($v) => $v !== null);

        return $this->client->request('POST', '/v1/messages', $body, $idempotencyKey);
    }

    /**
     * Send up to 1,000 emails in a single request.
     *
     * @param array[] $messages  Array of parameter arrays (same shape as send())
     * @return array
     */
    public function batch(array $messages): array
    {
        return $this->client->request('POST', '/v1/messages/batch', [
            'messages' => array_map([$this, 'normalizeSendParams'], $messages),
        ]);
    }

    /** Get an email by ID. */
    public function get(string $id): array
    {
        return $this->client->request('GET', '/v1/messages/' . urlencode($id));
    }

    /**
     * List emails with optional filters.
     *
     * @param array $options { status, limit, offset, cursor, tag }
     */
    public function list(array $options = []): array
    {
        $query = http_build_query(array_filter([
            'status' => $options['status'] ?? null,
            'limit'  => $options['limit']  ?? 20,
            'offset' => $options['offset'] ?? 0,
            'cursor' => $options['cursor'] ?? null,
            'tag'    => $options['tag']    ?? null,
        ], static fn ($v) => $v !== null && $v !== ''));

        return $this->client->request('GET', '/v1/messages' . ($query ? '?' . $query : ''));
    }

    // ── Private helpers ─────────────────────────────────────────────────────

    private function normalizeAddress(mixed $addr): ?array
    {
        if ($addr === null) return null;
        return is_array($addr) ? $addr : ['email' => $addr];
    }

    private function normalizeRecipients(mixed $recips): ?array
    {
        if ($recips === null) return null;
        return array_map([$this, 'normalizeAddress'], (array) $recips);
    }

    private function validateRecipients(mixed $recips, string $field): void
    {
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
        $params['from'] = $this->normalizeAddress($params['from'] ?? null);
        $params['to']   = $this->normalizeRecipients($params['to'] ?? null);
        return array_filter($params, static fn ($v) => $v !== null);
    }
}
