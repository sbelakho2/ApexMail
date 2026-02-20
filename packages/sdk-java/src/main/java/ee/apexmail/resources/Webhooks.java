package ee.apexmail.resources;

import ee.apexmail.ApexMailClient;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Map;

/**
 * Manage webhook endpoint registrations.
 *
 * <p>Access via {@code client.webhooks()}
 */
public final class Webhooks {

    private final ApexMailClient client;

    public Webhooks(ApexMailClient client) {
        this.client = client;
    }

    /**
     * Register a new webhook endpoint.
     *
     * @param params  Must include {@code url} and {@code events} list.
     *                Optional: {@code secret}.
     */
    public Map<String, Object> create(Map<String, Object> params) {
        return client.request("POST", "/v1/webhooks", params);
    }

    /** List all registered webhooks. */
    public Map<String, Object> list() {
        return client.request("GET", "/v1/webhooks", null);
    }

    /** Get a webhook by its ID. */
    public Map<String, Object> get(String id) {
        return client.request("GET", "/v1/webhooks/" + encode(id), null);
    }

    /** Update a webhook (URL, events, or active status). */
    public Map<String, Object> update(String id, Map<String, Object> params) {
        return client.request("PATCH", "/v1/webhooks/" + encode(id), params);
    }

    /** Delete a webhook endpoint. */
    public Map<String, Object> delete(String id) {
        return client.request("DELETE", "/v1/webhooks/" + encode(id), null);
    }

    private static String encode(String s) {
        return URLEncoder.encode(s, StandardCharsets.UTF_8);
    }
}
