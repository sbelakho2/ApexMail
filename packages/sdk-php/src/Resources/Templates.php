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
     * @param array $params {
     *   @type string $name       Human-readable name
     *   @type string $subject    Subject line (supports {{variables}})
     *   @type string $html       HTML body
     *   @type string $text       Plain-text body (generated automatically when omitted)
        *   @type string $engine     Template engine name
     *   @type array  $schema     JSON Schema describing available template variables
     * }
     */
    public function create(array $params): array
    {
        return $this->client->request('POST', '/v1/templates', $params);
    }

    /**
     * List templates.
     *
     * @param array $options { limit, offset }
     */
    public function list(array $options = []): array
    {
        $query = http_build_query(array_filter([
            'limit'  => $options['limit']  ?? 20,
            'offset' => $options['offset'] ?? 0,
        ], static fn ($v) => $v !== null && $v !== ''));

        return $this->client->request('GET', '/v1/templates' . ($query ? '?' . $query : ''));
    }

    /** Get a template by ID. */
    public function get(string $id): array
    {
        return $this->client->request('GET', '/v1/templates/' . urlencode($id));
    }

    /** Get a template by its unique slug. */
    public function getBySlug(string $slug): array
    {
        return $this->client->request('GET', '/v1/templates/slug/' . urlencode($slug));
    }

    /**
     * Update a template (creates a new version automatically).
     *
     * @param array $params { name, subject, html, text, engine, schema }
     */
    public function update(string $id, array $params): array
    {
        return $this->client->request('PATCH', '/v1/templates/' . urlencode($id), $params);
    }

    /** Delete a template and all its versions. */
    public function delete(string $id): array
    {
        return $this->client->request('DELETE', '/v1/templates/' . urlencode($id));
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
