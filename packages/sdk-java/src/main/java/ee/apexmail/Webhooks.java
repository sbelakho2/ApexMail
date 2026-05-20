package ee.apexmail;

import com.fasterxml.jackson.core.type.TypeReference;

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
    public WebhookResponse create(Map<String, Object> params) {
        return client.request("POST", "/v1/webhooks", params, WebhookResponse.class);
    }

    /** List all registered webhooks. */
    public WebhookListResponse list() {
        return client.request("GET", "/v1/webhooks", null, WebhookListResponse.class);
    }

    /** Get a webhook by its ID. */
    public WebhookResponse get(String id) {
        return client.request("GET", "/v1/webhooks/" + encode(id), null, WebhookResponse.class);
    }

    /** Update a webhook (URL, events, or active status). */
    public WebhookResponse update(String id, Map<String, Object> params) {
        return client.request("PUT", "/v1/webhooks/" + encode(id), params, WebhookResponse.class);
    }

    /** Delete a webhook endpoint. */
    public void delete(String id) {
        client.request("DELETE", "/v1/webhooks/" + encode(id), null, Void.class);
    }

    /** Send a signed test event to a registered webhook endpoint. */
    public Map<String, Object> test(String id) {
        return client.request("POST", "/v1/webhooks/" + encode(id) + "/test", Map.of(), new TypeReference<Map<String, Object>>() {});
    }

    private static String encode(String s) {
        return URLEncoder.encode(s, StandardCharsets.UTF_8);
    }

    public record Webhook(
        String id,
        String url,
        java.util.List<String> events,
        boolean active,
        String createdAt
    ) {}

    public record WebhookResponse(Webhook webhook) {}

    public record WebhookListResponse(java.util.List<Webhook> webhooks) {}
}
