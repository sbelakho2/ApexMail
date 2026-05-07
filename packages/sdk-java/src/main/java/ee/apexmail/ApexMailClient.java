package ee.apexmail;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jdk8.Jdk8Module;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;


import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.Map;
import java.util.HashMap;
import java.util.Optional;
import java.util.regex.Pattern;

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
public final class ApexMailClient implements AutoCloseable {

    private static final String DEFAULT_BASE_URL = "https://api.apexmail.ee";
    private static final Duration DEFAULT_TIMEOUT = Duration.ofSeconds(30);
    private static final int DEFAULT_MAX_RETRIES = 3;
    private static final Duration DEFAULT_INITIAL_BACKOFF = Duration.ofMillis(500);
    private static final Duration DEFAULT_MAX_BACKOFF = Duration.ofSeconds(5);
    private static final int DEFAULT_MAX_RESPONSE_BYTES = 20 * 1024 * 1024;
    private static final Pattern API_KEY_PATTERN = Pattern.compile("^am_(live|test)_[A-Za-z0-9]{16,}$");

    private final String apiKey;
    private final String baseUrl;
    private final HttpClient httpClient;
    private final ExecutorService executor;
    private final ScheduledExecutorService retryScheduler;
    private final ObjectMapper objectMapper;

    // ── Resource accessors ────────────────────────────────────────────────

    private final Emails       emails;
    private final Domains      domains;
    private final Webhooks     webhooks;
    private final Templates    templates;
    private final Suppressions suppressions;
    private final Events       events;

    // ── Constructors ──────────────────────────────────────────────────────

    public ApexMailClient(String apiKey) {
        this(apiKey, DEFAULT_BASE_URL, DEFAULT_TIMEOUT, null);
    }

    public ApexMailClient(String apiKey, String baseUrl) {
        this(apiKey, baseUrl, DEFAULT_TIMEOUT, null);
    }

    public ApexMailClient(String apiKey, String baseUrl, Duration timeout) {
        this(apiKey, baseUrl, timeout, null);
    }

    public ApexMailClient(String apiKey, HttpClient httpClient) {
        this(apiKey, DEFAULT_BASE_URL, DEFAULT_TIMEOUT, httpClient);
    }

    public ApexMailClient(String apiKey, String baseUrl, Duration timeout, HttpClient httpClient) {
        if (apiKey == null || apiKey.isBlank()) {
            throw new IllegalArgumentException("apiKey must not be blank");
        }
        if (!API_KEY_PATTERN.matcher(apiKey).matches()) {
            throw new IllegalArgumentException("apiKey must match am_live_... or am_test_... format");
        }
        this.apiKey  = apiKey;
        this.baseUrl = baseUrl.endsWith("/") ? baseUrl.substring(0, baseUrl.length() - 1) : baseUrl;
        if (!this.baseUrl.startsWith("https://")) {
            throw new IllegalArgumentException("baseUrl must use HTTPS");
        }
        if (httpClient != null) {
            this.httpClient = httpClient;
            this.executor = null;
        } else {
            this.executor = Executors.newCachedThreadPool();
            this.httpClient = HttpClient.newBuilder()
                .connectTimeout(timeout)
                .version(HttpClient.Version.HTTP_2)
                .executor(this.executor)
                .build();
        }
            this.retryScheduler = Executors.newSingleThreadScheduledExecutor();
        this.objectMapper = new ObjectMapper()
            .registerModule(new JavaTimeModule())
            .registerModule(new Jdk8Module())
            .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);

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

    // ── HTTP transport ────────────────────────────────────────────────────

    /**
     * Perform an HTTP request and return the parsed JSON response as a Map.
     *
     * @param method  HTTP method ("GET", "POST", "PATCH", "DELETE")
     * @param path    API path e.g. "/v1/messages"
     * @param body    Request body (will be JSON-encoded), or {@code null}
     * @return Parsed response body as a typed object
     * @throws ApexMailException on API errors
     */
    <T> T request(String method, String path, Object body, Class<T> responseType) {
        return request(method, path, body, responseType, null);
    }

    <T> T request(String method, String path, Object body, Class<T> responseType,
                          String idempotencyKey) {
        int attempt = 0;
        while (true) {
            try {
                String jsonBody = body != null ? objectMapper.writeValueAsString(body) : "";
                HttpResponse<String> response = httpClient.send(
                    buildRequest(method, path, jsonBody, idempotencyKey),
                    HttpResponse.BodyHandlers.ofString()
                );

                int status = response.statusCode();
                String responseBody = safeResponseBody(response);
                ensureResponseWithinLimit(responseBody);

                if ((status == 429 || status >= 500) && attempt < DEFAULT_MAX_RETRIES) {
                    Duration delay = retryDelay(response, attempt);
                    waitForRetry(delay);
                    attempt++;
                    continue;
                }

                if (status >= 200 && status < 300) {
                    if (responseType == Void.class || responseBody == null || responseBody.isBlank()) {
                        return null;
                    }
                    return objectMapper.readValue(responseBody, responseType);
                }

                Map<String, Object> parsed = parseErrorBody(responseBody);
                throwApiException(status, parsed);
                return null; // unreachable

            } catch (IOException e) {
                if (attempt < DEFAULT_MAX_RETRIES) {
                    try {
                        sleepBackoff(attempt);
                    } catch (InterruptedException interrupted) {
                        Thread.currentThread().interrupt();
                        throw new ApexMailException("Request interrupted", interrupted);
                    }
                    attempt++;
                    continue;
                }
                throw new ApexMailException("Network error: " + e.getMessage(), e);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new ApexMailException("Request interrupted", e);
            }
        }
    }

    <T> T request(String method, String path, Object body, TypeReference<T> responseType) {
        return request(method, path, body, responseType, null);
    }

    <T> T request(String method, String path, Object body, TypeReference<T> responseType,
                          String idempotencyKey) {
        int attempt = 0;
        while (true) {
            try {
                String jsonBody = body != null ? objectMapper.writeValueAsString(body) : "";
                HttpResponse<String> response = httpClient.send(
                    buildRequest(method, path, jsonBody, idempotencyKey),
                    HttpResponse.BodyHandlers.ofString()
                );

                int status = response.statusCode();
                String responseBody = safeResponseBody(response);
                ensureResponseWithinLimit(responseBody);

                if ((status == 429 || status >= 500) && attempt < DEFAULT_MAX_RETRIES) {
                    Duration delay = retryDelay(response, attempt);
                    waitForRetry(delay);
                    attempt++;
                    continue;
                }

                if (status >= 200 && status < 300) {
                    if (responseBody == null || responseBody.isBlank()) {
                        return null;
                    }
                    return objectMapper.readValue(responseBody, responseType);
                }

                Map<String, Object> parsed = parseErrorBody(responseBody);
                throwApiException(status, parsed);
                return null; // unreachable

            } catch (IOException e) {
                if (attempt < DEFAULT_MAX_RETRIES) {
                    try {
                        sleepBackoff(attempt);
                    } catch (InterruptedException interrupted) {
                        Thread.currentThread().interrupt();
                        throw new ApexMailException("Request interrupted", interrupted);
                    }
                    attempt++;
                    continue;
                }
                throw new ApexMailException("Network error: " + e.getMessage(), e);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new ApexMailException("Request interrupted", e);
            }
        }
    }

    private Map<String, Object> parseErrorBody(String responseBody) {
        if (responseBody == null || responseBody.isBlank()) {
            return new HashMap<>();
        }
        try {
            return objectMapper.readValue(responseBody, new TypeReference<Map<String, Object>>() {});
        } catch (IOException parseFailure) {
            Map<String, Object> fallback = new HashMap<>();
            fallback.put("error", responseBody);
            fallback.put("code", "unparseable_error_response");
            fallback.put("parseFailure", parseFailure.getMessage());
            return fallback;
        }
    }

    // ── Error mapping ─────────────────────────────────────────────────────

    @SuppressWarnings("unchecked")
    private void throwApiException(int status, Map<String, Object> body) {
        // The ApexMail error envelope is nested: {"error":{"code":"...","message":"..."}}
        Object errorField = body.get("error");
        String message = "API error";
        String code = null;
        if (errorField instanceof Map) {
            Map<String, Object> errorObj = (Map<String, Object>) errorField;
            Object msgField = errorObj.get("message");
            if (msgField != null) {
                message = String.valueOf(msgField);
            }
            Object codeField = errorObj.get("code");
            if (codeField != null) {
                code = String.valueOf(codeField);
            }
        } else if (errorField != null) {
            message = String.valueOf(errorField);
        }

        throw switch (status) {
            case 401 -> new AuthenticationException(message, code, status);
            case 403 -> new ForbiddenException(message, code, status);
            case 404 -> new NotFoundException(message, code, status);
            case 409 -> new ConflictException(message, code, status);
            case 422 -> new ValidationException(message, code, status);
            case 429 -> new RateLimitException(message, code, status);
            default  -> new ApexMailException(message, code, status);
        };
    }

    private static Duration retryDelay(HttpResponse<String> response, int attempt) {
        Optional<String> retryAfter = response.headers().firstValue("Retry-After");
        if (retryAfter.isPresent()) {
            String header = retryAfter.get();
            try {
                long seconds = Long.parseLong(header.trim());
                return Duration.ofSeconds(seconds).compareTo(DEFAULT_MAX_BACKOFF) > 0
                    ? DEFAULT_MAX_BACKOFF
                    : Duration.ofSeconds(seconds);
            } catch (NumberFormatException ignored) {
                // fall through to backoff
            }
        }
        return calculateBackoff(attempt);
    }

    private static Duration calculateBackoff(int attempt) {
        if (attempt < 0) {
            attempt = 0;
        }
        if (attempt > 30) {
            attempt = 30;
        }
        long multiplier = 1L << attempt;
        Duration delay = DEFAULT_INITIAL_BACKOFF.multipliedBy(multiplier);
        return delay.compareTo(DEFAULT_MAX_BACKOFF) > 0 ? DEFAULT_MAX_BACKOFF : delay;
    }

    private HttpRequest buildRequest(String method, String path, String jsonBody, String idempotencyKey) {
        HttpRequest.Builder builder = HttpRequest.newBuilder()
            .uri(URI.create(baseUrl + path))
            .header("X-API-Key", apiKey)
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

        return builder.method(method, publisher).build();
    }

    private static void ensureResponseWithinLimit(String responseBody) {
        if (responseBody != null && responseBody.getBytes(StandardCharsets.UTF_8).length > DEFAULT_MAX_RESPONSE_BYTES) {
            throw new ApexMailException("Response body exceeds max size limit", "response_too_large", 0);
        }
    }

    private static String safeResponseBody(HttpResponse<String> response) {
        String body = response.body();
        return body == null ? "" : body;
    }

    private void waitForRetry(Duration delay) throws InterruptedException {
        if (delay == null || delay.isNegative() || delay.isZero()) {
            return;
        }

        CompletableFuture<Void> future = new CompletableFuture<>();
        retryScheduler.schedule(() -> future.complete(null), delay.toMillis(), TimeUnit.MILLISECONDS);
        try {
            future.get();
        } catch (ExecutionException e) {
            throw new ApexMailException("Retry scheduling failed", e.getCause());
        }
    }

    private void sleepBackoff(int attempt) throws InterruptedException {
        waitForRetry(calculateBackoff(attempt));
    }

    @Override
    public void close() {
        if (executor != null) {
            executor.shutdown();
        }
        retryScheduler.shutdown();
        try {
            if (!retryScheduler.awaitTermination(5, java.util.concurrent.TimeUnit.SECONDS)) {
                retryScheduler.shutdownNow();
            }
            if (executor != null && !executor.awaitTermination(5, java.util.concurrent.TimeUnit.SECONDS)) {
                executor.shutdownNow();
            }
        } catch (InterruptedException e) {
            retryScheduler.shutdownNow();
            if (executor != null) executor.shutdownNow();
            Thread.currentThread().interrupt();
        }
    }
}
