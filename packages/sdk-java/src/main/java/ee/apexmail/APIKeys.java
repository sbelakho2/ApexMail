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

    public Map<String, Object> create(Map<String, Object> params) {
        return client.request("POST", "/v1/auth/api-keys", params, new TypeReference<Map<String, Object>>() {});
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