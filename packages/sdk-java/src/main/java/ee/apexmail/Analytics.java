package ee.apexmail;

import com.fasterxml.jackson.core.type.TypeReference;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Map;

/**
 * Query aggregate email analytics.
 *
 * <p>The API requires {@code from} and {@code to} date parameters.
 * Supported options: {@code from}, {@code to}, {@code groupBy}, {@code tag}, {@code domain}.
 */
public final class Analytics {
    private final ApexMailClient client;

    public Analytics(ApexMailClient client) {
        this.client = client;
    }

    public Map<String, Object> get(Map<String, Object> options) {
        String query = options != null && !options.isEmpty() ? "?" + buildQuery(options) : "";
        return client.request("GET", "/v1/analytics" + query, null, new TypeReference<Map<String, Object>>() {});
    }

    public Map<String, Object> get() {
        return get(null);
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