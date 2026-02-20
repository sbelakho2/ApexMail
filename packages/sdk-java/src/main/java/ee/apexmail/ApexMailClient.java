package ee.apexmail;

import ee.apexmail.resources.*;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Map;
import java.util.HashMap;

/**
 * Official Java SDK client for the ApexMail API.
 *
 * <p>Usage:
 * <pre>
 *   ApexMailClient client = new ApexMailClient("am_your_api_key");
 *   Map&lt;String, Object&gt; result = client.emails().send(Map.of(
 *       "from",    "Sender &lt;hello@example.com&gt;",
 *       "to",      "user@example.com",
 *       "subject", "Hello from ApexMail",
 *       "html",    "&lt;p&gt;Hello!&lt;/p&gt;"
 *   ));
 * </pre>
 */
public final class ApexMailClient {

    private static final String DEFAULT_BASE_URL = "https://api.apexmail.ee";
    private static final Duration DEFAULT_TIMEOUT = Duration.ofSeconds(30);

    private final String apiKey;
    private final String baseUrl;
    private final HttpClient httpClient;

    // ── Resource accessors ────────────────────────────────────────────────

    private final Emails       emails;
    private final Domains      domains;
    private final Webhooks     webhooks;
    private final Templates    templates;
    private final Suppressions suppressions;
    private final Events       events;

    // ── Constructors ──────────────────────────────────────────────────────

    public ApexMailClient(String apiKey) {
        this(apiKey, DEFAULT_BASE_URL, DEFAULT_TIMEOUT);
    }

    public ApexMailClient(String apiKey, String baseUrl) {
        this(apiKey, baseUrl, DEFAULT_TIMEOUT);
    }

    public ApexMailClient(String apiKey, String baseUrl, Duration timeout) {
        if (apiKey == null || apiKey.isBlank()) {
            throw new IllegalArgumentException("apiKey must not be blank");
        }
        this.apiKey  = apiKey;
        this.baseUrl = baseUrl.endsWith("/") ? baseUrl.substring(0, baseUrl.length() - 1) : baseUrl;
        this.httpClient = HttpClient.newBuilder()
            .connectTimeout(timeout)
            .version(HttpClient.Version.HTTP_1_1)
            .build();

        this.emails       = new Emails(this);
        this.domains      = new Domains(this);
        this.webhooks     = new Webhooks(this);
        this.templates    = new Templates(this);
        this.suppressions = new Suppressions(this);
        this.events       = new Events(this);
    }

    // ── Public accessors ──────────────────────────────────────────────────

    public Emails       emails()       { return emails; }
    public Domains      domains()      { return domains; }
    public Webhooks     webhooks()     { return webhooks; }
    public Templates    templates()    { return templates; }
    public Suppressions suppressions() { return suppressions; }
    public Events       events()       { return events; }

    // ── HTTP transport (package-private) ──────────────────────────────────

    /**
     * Perform an HTTP request and return the parsed JSON response as a Map.
     *
     * @param method  HTTP method ("GET", "POST", "PATCH", "DELETE")
     * @param path    API path e.g. "/v1/messages"
     * @param body    Request body (will be JSON-encoded), or {@code null}
     * @return Parsed response body as a {@code Map<String, Object>}
     * @throws ApexMailException on API errors
     */
    @SuppressWarnings("unchecked")
    public Map<String, Object> request(String method, String path, Object body) {
        return request(method, path, body, null);
    }

    @SuppressWarnings("unchecked")
    public Map<String, Object> request(String method, String path, Object body,
                                String idempotencyKey) {
        try {
            String jsonBody = body != null ? toJson(body) : "";
            HttpRequest.Builder builder = HttpRequest.newBuilder()
                .uri(URI.create(baseUrl + path))
                .header("Authorization", "Bearer " + apiKey)
                .header("Content-Type", "application/json")
                .header("Accept", "application/json")
                .header("User-Agent", "apexmail-java/1.0.0");

            if (idempotencyKey != null && !idempotencyKey.isBlank()) {
                builder.header("X-Idempotency-Key", idempotencyKey);
            }

            HttpRequest.BodyPublisher publisher =
                jsonBody.isEmpty()
                    ? HttpRequest.BodyPublishers.noBody()
                    : HttpRequest.BodyPublishers.ofString(jsonBody);

            builder.method(method, publisher);

            HttpResponse<String> response = httpClient.send(
                builder.build(),
                HttpResponse.BodyHandlers.ofString()
            );

            int status = response.statusCode();
            String responseBody = response.body();

            Map<String, Object> parsed = responseBody != null && !responseBody.isBlank()
                ? (Map<String, Object>) parseJson(responseBody)
                : new HashMap<>();

            if (status >= 200 && status < 300) {
                return parsed;
            }

            throwApiException(status, parsed);
            return parsed; // unreachable

        } catch (IOException e) {
            throw new ApexMailException("Network error: " + e.getMessage(), e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new ApexMailException("Request interrupted", e);
        }
    }

    // ── Minimal JSON serialiser / deserialiser ────────────────────────────
    // Uses only JDK built-ins — no Jackson or Gson dependency.

    static String toJson(Object obj) {
        if (obj == null) return "null";
        if (obj instanceof String s)  return "\"" + escapeString(s) + "\"";
        if (obj instanceof Number)    return obj.toString();
        if (obj instanceof Boolean)   return obj.toString();
        if (obj instanceof Map<?,?> m) {
            StringBuilder sb = new StringBuilder("{");
            boolean first = true;
            for (Map.Entry<?,?> e : m.entrySet()) {
                if (e.getValue() == null) continue; // omit nulls
                if (!first) sb.append(',');
                first = false;
                sb.append('"').append(escapeString(e.getKey().toString())).append("\":");
                sb.append(toJson(e.getValue()));
            }
            return sb.append('}').toString();
        }
        if (obj instanceof Iterable<?> it) {
            StringBuilder sb = new StringBuilder("[");
            boolean first = true;
            for (Object item : it) {
                if (!first) sb.append(',');
                first = false;
                sb.append(toJson(item));
            }
            return sb.append(']').toString();
        }
        if (obj instanceof Object[] arr) {
            StringBuilder sb = new StringBuilder("[");
            for (int i = 0; i < arr.length; i++) {
                if (i > 0) sb.append(',');
                sb.append(toJson(arr[i]));
            }
            return sb.append(']').toString();
        }
        return "\"" + escapeString(obj.toString()) + "\"";
    }

    private static String escapeString(String s) {
        return s.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t");
    }

    static Object parseJson(String json) {
        return new JsonParser(json.trim()).parse();
    }

    // ── Error mapping ─────────────────────────────────────────────────────

    @SuppressWarnings("unchecked")
    private void throwApiException(int status, Map<String, Object> body) {
        String message = body.containsKey("error")
            ? String.valueOf(body.get("error"))
            : "API error";
        String code = body.containsKey("code")
            ? String.valueOf(body.get("code"))
            : null;

        throw switch (status) {
            case 401 -> new AuthenticationException(message, code, status);
            case 404 -> new NotFoundException(message, code, status);
            case 422 -> new ValidationException(message, code, status);
            case 429 -> new RateLimitException(message, code, status);
            default  -> new ApexMailException(message, code, status);
        };
    }
}
