<?php

declare(strict_types=1);

namespace ApexMail\Resources;

use ApexMail\Client;

/**
 * Manage reusable email templates.
 */
class Templates
{
    public function __construct(private readonly Client $client) {}

    /**
     * Create a new template.
     *
     * The server's CreateTemplateRequest accepts exactly
     * {name, subject, html_body, text_body?} (deny_unknown_fields). Legacy
     * `html` / `text` input keys are accepted and mapped to html_body /
     * text_body; slug / engine / schema inputs are accepted but NOT sent
     * (the API has no such fields).
     *
     * @param array $params {
     *   @type string $name       Human-readable name
     *   @type string $subject    Subject line (supports {{variables}})
     *   @type string $html_body  HTML body (alias: html)
     *   @type string $text_body  Plain-text body (alias: text)
     * }
     */
    public function create(array $params): array
    {
        $body = array_filter([
            'name'       => $params['name'] ?? null,
            'subject'    => $params['subject'] ?? null,
            'html_body'  => $params['html_body'] ?? $params['html'] ?? null,
            'text_body'  => $params['text_body'] ?? $params['text'] ?? null,
        ], static fn ($v) => $v !== null && $v !== '');

        return $this->client->request('POST', '/v1/templates', $body);
    }

    /**
     * List templates.
     *
     * @param array $options { limit, offset, cursor }
     */
    public function list(array $options = []): array
    {
        $query = http_build_query(array_filter([
            'limit'  => $options['limit']  ?? 20,
            'offset' => $options['offset'] ?? 0,
            'cursor' => $options['cursor'] ?? null,
        ], static fn ($v) => $v !== null && $v !== ''));

        return $this->client->request('GET', '/v1/templates' . ($query ? '?' . $query : ''));
    }

    /** Get a template by ID. */
    public function get(string $id): array
    {
        return $this->client->request('GET', '/v1/templates/' . urlencode($id));
    }

    /**
     * Update a template (creates a new version automatically).
     *
     * The server's UpdateTemplateRequest accepts {name?, subject?,
     * html_body?, text_body?}; legacy html/text keys are mapped.
     */
    public function update(string $id, array $params): array
    {
        $body = array_filter([
            'name'       => $params['name'] ?? null,
            'subject'    => $params['subject'] ?? null,
            'html_body'  => $params['html_body'] ?? $params['html'] ?? null,
            'text_body'  => $params['text_body'] ?? $params['text'] ?? null,
        ], static fn ($v) => $v !== null && $v !== '');

        return $this->client->request('PUT', '/v1/templates/' . urlencode($id), $body);
    }

    /** Delete a template and all its versions. */
    public function delete(string $id): array
    {
        return $this->client->request('DELETE', '/v1/templates/' . urlencode($id));
    }

    /**
     * Duplicate a template, creating a copy with a new ID.
     */
    public function duplicate(string $id): array
    {
        return $this->client->request('POST', '/v1/templates/' . urlencode($id) . '/duplicate');
    }

    /**
     * Rollback a template to a previous version.
     *
     * @param int $version  The version number to roll back to
     */
    public function rollback(string $id, int $version): array
    {
        return $this->client->request('POST', '/v1/templates/' . urlencode($id) . '/rollback', ['version' => $version]);
    }

    /**
     * Render a template with given variables (preview / dry-run, does not send).
     *
     * @param array $data  Key-value pairs that fill template variables
     */
    public function render(string $id, array $data = []): array
    {
        return $this->client->request('POST', '/v1/templates/' . urlencode($id) . '/render', ['variables' => $data]);
    }
}
