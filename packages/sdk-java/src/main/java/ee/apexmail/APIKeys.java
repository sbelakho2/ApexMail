package ee.apexmail;

import com.fasterxml.jackson.core.type.TypeReference;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Map;

/** Manage API keys for the authenticated account. */
public final class APIKeys {
    private final ApexMailClient client;

    public APIKeys(ApexMailClient client) {
        this.client = client;
    }

    /**
     * Create a new API key.
     *
     * <p>Transmits exactly {name, scopes: string[], expires_in_days?} per
     * the server's CreateApiKeyRequest (auth.rs, deny_unknown_fields) —
     * {@code scopes} is required by the API and defaults to an empty list.
     * The legacy {@code expiresAt} input is ignored; use
     * {@code expires_in_days} (1..365).
     */
    public Map<String, Object> create(Map<String, Object> params) {
        if (params == null || params.get("name") == null || String.valueOf(params.get("name")).isBlank()) {
            throw new IllegalArgumentException("name is required");
        }
        Map<String, Object> body = new java.util.LinkedHashMap<>();
        body.put("name", params.get("name"));
        Object scopes = params.get("scopes");
        body.put("scopes", scopes != null ? scopes : java.util.List.of());
        if (params.get("expires_in_days") != null) {
            body.put("expires_in_days", params.get("expires_in_days"));
        }
        return client.request("POST", "/v1/auth/api-keys", body, new TypeReference<Map<String, Object>>() {});
    }

    public Map<String, Object> list(Map<String, Object> options) {
        String query = options != null && !options.isEmpty() ? "?" + buildQuery(options) : "";
        return client.request("GET", "/v1/auth/api-keys" + query, null, new TypeReference<Map<String, Object>>() {});
    }

    public Map<String, Object> list() {
        return list(Map.of("limit", 50, "offset", 0));
    }

    public void revoke(String id) {
        client.request("DELETE", "/v1/auth/api-keys/" + encode(id), null, Void.class);
    }

    private static String buildQuery(Map<String, Object> params) {
        StringBuilder builder = new StringBuilder();
        params.forEach((key, value) -> {
            if (value != null) {
                if (builder.length() > 0) builder.append('&');
                builder.append(encode(key)).append('=').append(encode(String.valueOf(value)));
            }
        });
        return builder.toString();
    }

    private static String encode(Object value) {
        return URLEncoder.encode(String.valueOf(value), StandardCharsets.UTF_8);
    }
}