package ee.apexmail;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jdk8.Jdk8Module;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;


import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.MessageDigest;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.Map;
import java.util.HashMap;
import java.util.Optional;
import java.util.regex.Pattern;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * Official Java SDK client for the ApexMail API.
 *
 * <p>Usage:
 * <pre>
 *   ApexMailClient client = new ApexMailClient("am_your_api_key");
 *   Map&lt;String, Object&gt; result = client.emails().send(Map.of(
 *       "from",    "Sender &lt;hello@example.com&gt;",
 *       "to",      java.util.List.of("user@example.com"),
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
    /**
     * Upper bound for retry delays. The server's Retry-After header is
     * honored in full up to this cap (SDK-F: was capped at 5s, truncating
     * long rate-limit windows).
     */
    private static final Duration DEFAULT_MAX_RETRY_AFTER = Duration.ofSeconds(120);
    private static final int DEFAULT_MAX_RESPONSE_BYTES = 20 * 1024 * 1024;
    private static final Pattern API_KEY_PATTERN = Pattern.compile("^am_(live|test)_[A-Za-z0-9]{16,}$");

    /**
     * Default max thread pool size: 2× available processors.
     * Prevents unbounded thread growth (CachedThreadPool) which can cause OOM.
     */
    private static final int DEFAULT_MAX_THREADS =
        Math.max(4, Runtime.getRuntime().availableProcessors() * 2);

    private final String apiKey;
    private final String baseUrl;
    private final Duration timeout;
    private final HttpClient httpClient;
    private final ExecutorService executor;
    private final ObjectMapper objectMapper;
    private volatile RateLimitInfo lastRateLimit;

    // ── Resource accessors ────────────────────────────────────────────────

    private final Emails       emails;
    private final Domains      domains;
    private final Webhooks     webhooks;
    private final Templates    templates;
    private final Suppressions suppressions;
    private final Events       events;
    private final Analytics    analytics;
    private final APIKeys      apiKeys;

    // ── Constructors ──────────────────────────────────────────────────────

    /**
     * Creates a new ApexMailClient with default configuration.
     *
     * @param apiKey Your ApexMail API key (must match {@code am_(live|test)_[A-Za-z0-9]{16,}})
     */
    public ApexMailClient(String apiKey) {
        this(apiKey, DEFAULT_BASE_URL, DEFAULT_TIMEOUT, DEFAULT_MAX_THREADS, null);
    }

    /**
     * Creates a new ApexMailClient with a custom base URL.
     *
     * @param apiKey  Your ApexMail API key
     * @param baseUrl Custom API base URL
     */
    public ApexMailClient(String apiKey, String baseUrl) {
        this(apiKey, baseUrl, DEFAULT_TIMEOUT, DEFAULT_MAX_THREADS, null);
    }

    /**
     * Creates a new ApexMailClient with a custom timeout.
     *
     * @param apiKey  Your ApexMail API key
     * @param baseUrl Custom API base URL
     * @param timeout Request and connect timeout
     */
    public ApexMailClient(String apiKey, String baseUrl, Duration timeout) {
        this(apiKey, baseUrl, timeout, DEFAULT_MAX_THREADS, null);
    }

    /**
     * Creates a new ApexMailClient with a custom base URL, timeout, and HttpClient.
     *
     * @param apiKey     Your ApexMail API key
     * @param baseUrl    Custom API base URL
     * @param timeout    Request and connect timeout
     * @param httpClient Pre-configured HttpClient instance (the client's own executor is used)
     */
    public ApexMailClient(String apiKey, String baseUrl, Duration timeout, HttpClient httpClient) {
        this(apiKey, baseUrl, timeout, DEFAULT_MAX_THREADS, httpClient);
    }

    /**
     * Creates a new ApexMailClient with a provided HttpClient.
     *
     * @param apiKey     Your ApexMail API key
     * @param httpClient Pre-configured HttpClient instance (the client's own executor is used)
     */
    public ApexMailClient(String apiKey, HttpClient httpClient) {
        this(apiKey, DEFAULT_BASE_URL, DEFAULT_TIMEOUT, DEFAULT_MAX_THREADS, httpClient);
    }

    /**
     * Creates a new ApexMailClient with a custom timeout and max thread count.
     * <p>
     * When no {@code httpClient} is supplied, the client creates a bounded thread pool
     * with the given {@code maxThreads} and a {@link ThreadPoolExecutor.CallerRunsPolicy}
     * rejection handler to prevent unbounded thread growth under high concurrency.
     *
     * @param apiKey     Your ApexMail API key
     * @param baseUrl    Custom API base URL
     * @param timeout    Request and connect timeout
     * @param maxThreads Maximum number of threads in the internal executor pool
     */
    public ApexMailClient(String apiKey, String baseUrl, Duration timeout, int maxThreads) {
        this(apiKey, baseUrl, timeout, maxThreads, null);
    }

    /**
     * Main constructor — all others delegate here.
     */
    public ApexMailClient(String apiKey, String baseUrl, Duration timeout, int maxThreads, HttpClient httpClient) {
        if (apiKey == null || apiKey.isBlank()) {
            throw new IllegalArgumentException("apiKey must not be blank");
        }
        if (!API_KEY_PATTERN.matcher(apiKey).matches()) {
            throw new IllegalArgumentException("apiKey must match am_live_... or am_test_... format");
        }
        if (maxThreads < 1) {
            throw new IllegalArgumentException("maxThreads must be >= 1, got " + maxThreads);
        }
        this.apiKey  = apiKey;
        this.timeout = (timeout == null || timeout.isZero() || timeout.isNegative()) ? DEFAULT_TIMEOUT : timeout;
        this.baseUrl = baseUrl.endsWith("/") ? baseUrl.substring(0, baseUrl.length() - 1) : baseUrl;
        if (!this.baseUrl.startsWith("https://")) {
            throw new IllegalArgumentException("baseUrl must use HTTPS");
        }
        if (httpClient != null) {
            this.httpClient = httpClient;
            this.executor = null;
        } else {
            // Bounded thread pool with CallerRunsPolicy prevents unbounded thread
            // growth (which would cause OOM) under high concurrency.
            this.executor = new ThreadPoolExecutor(
                maxThreads, maxThreads,
                60L, TimeUnit.SECONDS,
                new LinkedBlockingQueue<Runnable>(),
                new ThreadPoolExecutor.CallerRunsPolicy()
            );
            this.httpClient = HttpClient.newBuilder()
                .connectTimeout(timeout)
                .version(HttpClient.Version.HTTP_2)
                .executor(this.executor)
                .build();
        }
        this.objectMapper = new ObjectMapper()
            .registerModule(new JavaTimeModule())
            .registerModule(new Jdk8Module())
            .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false)
            .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);

        this.emails       = new Emails(this);
        this.domains      = new Domains(this);
        this.webhooks     = new Webhooks(this);
        this.templates    = new Templates(this);
        this.suppressions = new Suppressions(this);
        this.events       = new Events(this);
        this.analytics    = new Analytics(this);
        this.apiKeys      = new APIKeys(this);
    }

    // ── Public accessors ──────────────────────────────────────────────────

    public Emails       emails()       { return emails; }
    public Domains      domains()      { return domains; }
    public Webhooks     webhooks()     { return webhooks; }
    public Templates    templates()    { return templates; }
    public Suppressions suppressions() { return suppressions; }
    public Events       events()       { return events; }
    public Analytics    analytics()    { return analytics; }
    public APIKeys      apiKeys()      { return apiKeys; }
    public Optional<RateLimitInfo> getLastRateLimit() { return Optional.ofNullable(lastRateLimit); }

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
        String jsonBody = serializeBody(body);
        TransportResponse transport = execute(method, path, jsonBody,
            autoIdempotencyKey(method, jsonBody, idempotencyKey));

        if (responseType == Void.class || transport.body() == null || transport.body().isBlank()) {
            return null;
        }
        try {
            return objectMapper.readValue(unwrapEnvelope(transport.body()), responseType);
        } catch (IOException e) {
            throw new ApexMailException(
                "Failed to parse response body: " + e.getMessage(),
                "PARSE_ERROR", transport.status(), null, e);
        }
    }

    <T> T request(String method, String path, Object body, TypeReference<T> responseType) {
        return request(method, path, body, responseType, null);
    }

    <T> T request(String method, String path, Object body, TypeReference<T> responseType,
                          String idempotencyKey) {
        String jsonBody = serializeBody(body);
        TransportResponse transport = execute(method, path, jsonBody,
            autoIdempotencyKey(method, jsonBody, idempotencyKey));

        if (transport.body() == null || transport.body().isBlank()) {
            return null;
        }
        try {
            return objectMapper.readValue(unwrapEnvelope(transport.body()), responseType);
        } catch (IOException e) {
            throw new ApexMailException(
                "Failed to parse response body: " + e.getMessage(),
                "PARSE_ERROR", transport.status(), null, e);
        }
    }

    /**
     * Duplicate-side-effect protection for mutating POSTs (SDK-B, matching
     * the PHP SDK): a POST that times out AFTER the server processed it
     * retries blind — creating a second webhook/template/API key. Every
     * non-idempotent request with a body gets a UUID generated BEFORE the
     * retry loop, so all attempts of the same logical operation present
     * the same key and the server can deduplicate.
     */
    private static String autoIdempotencyKey(String method, String jsonBody, String idempotencyKey) {
        if (idempotencyKey != null && !idempotencyKey.isBlank()) {
            return idempotencyKey;
        }
        if ("POST".equalsIgnoreCase(method) && jsonBody != null && !jsonBody.isEmpty()) {
            return java.util.UUID.randomUUID().toString();
        }
        return null;
    }

    /**
     * Serialize the request body once, before any retry loop. Serialization
     * failures are deterministic, so they must NOT be retried (SDK-B).
     */
    private String serializeBody(Object body) {
        if (body == null) {
            return "";
        }
        try {
            return objectMapper.writeValueAsString(body);
        } catch (com.fasterxml.jackson.core.JsonProcessingException e) {
            throw new ApexMailException(
                "Failed to serialize request body: " + e.getMessage(),
                "SERIALIZATION_ERROR", 0, null, e);
        }
    }

    private record TransportResponse(int status, String body) {}

    /**
     * Run the HTTP request with retries (transport errors, 429, 5xx).
     *
     * <p>The retry budget bounds the REQUESTS, not the sleeps (F9): an
     * honored Retry-After — capped at {@link #DEFAULT_MAX_RETRY_AFTER}
     * (120s) by {@link #retryDelay} — is allowed to elapse in full even
     * when it exceeds the configured per-request timeout. The previous
     * loop-level deadline threw RETRY_TIMEOUT before sleeping, so any
     * Retry-After near 120s could never execute. Individual requests are
     * still bounded by the configured timeout (see buildRequest), and a
     * terminal 429 surfaces as the typed RateLimitException, never a
     * generic network error.
     */
    private TransportResponse execute(String method, String path, String jsonBody, String idempotencyKey) {
        int attempt = 0;
        // Overall budget for the REQUEST ATTEMPTS of this call (the sleeps
        // between them are excluded on purpose — see the javadoc above).
        long deadlineNanos = System.nanoTime()
            + this.timeout.multipliedBy(DEFAULT_MAX_RETRIES + 1L).toNanos();

        while (true) {
            if (System.nanoTime() >= deadlineNanos) {
                throw new ApexMailException(
                    "Retry deadline exceeded for " + method + " " + path,
                    "RETRY_TIMEOUT", 0, null);
            }
            try {
                HttpResponse<InputStream> response = httpClient.send(
                    buildRequest(method, path, jsonBody, idempotencyKey),
                    HttpResponse.BodyHandlers.ofInputStream()
                );

                int status = response.statusCode();
                lastRateLimit = RateLimitInfo.from(response);
                String responseBody = readBodyCapped(response);
                ensureResponseWithinLimit(responseBody);

                if ((status == 429 || status >= 500) && attempt < DEFAULT_MAX_RETRIES) {
                    Duration delay = retryDelay(response, attempt);
                    // The delay is already capped at 120s; let it run —
                    // checking it against the request budget here would
                    // defeat honoring the server's Retry-After.
                    waitForRetry(jittered(delay));
                    attempt++;
                    continue;
                }

                if (status >= 200 && status < 300) {
                    return new TransportResponse(status, responseBody);
                }

                Map<String, Object> parsed = parseErrorBody(responseBody);
                throwApiException(status, parsed);
                throw new IllegalStateException("unreachable");

            } catch (IOException e) {
                if (System.nanoTime() >= deadlineNanos) {
                    throw new ApexMailException("Retry deadline exceeded: " + e.getMessage(), "RETRY_TIMEOUT", 0, null, e);
                }
                if (attempt < DEFAULT_MAX_RETRIES) {
                    try {
                        sleepBackoff(attempt);
                    } catch (InterruptedException ie) {
                        Thread.currentThread().interrupt();
                        throw new ApexMailException("Request interrupted", ie);
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

    /**
     * Read the response body stream into a string, aborting as soon as the
     * body is known to exceed the size cap instead of buffering it all
     * (SDK-G: streaming size cap via BodyHandlers.ofInputStream).
     */
    private static String readBodyCapped(HttpResponse<InputStream> response) {
        try (InputStream in = response.body()) {
            if (in == null) {
                return "";
            }
            ByteArrayOutputStream buffer = new ByteArrayOutputStream();
            byte[] chunk = new byte[8192];
            long total = 0;
            int read;
            while ((read = in.read(chunk)) != -1) {
                total += read;
                if (total > DEFAULT_MAX_RESPONSE_BYTES) {
                    throw new ApexMailException(
                        "Response body exceeds max size limit", "response_too_large", 0, null);
                }
                buffer.write(chunk, 0, read);
            }
            return buffer.toString(StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new ApexMailException("Failed to read response body: " + e.getMessage(), "READ_ERROR", 0, null, e);
        }
    }

    /**
     * Unwrap the API envelope if present. If the response is a JSON object
     * containing a "data" key, return the serialized "data" value.
     * Otherwise, return the original response body unchanged.
     */
    private String unwrapEnvelope(String responseBody) {
        try {
            Map<String, Object> parsed = objectMapper.readValue(responseBody, new TypeReference<Map<String, Object>>() {});
            if (parsed.containsKey("data")) {
                Object data = parsed.get("data");
                if (data != null) {
                    return objectMapper.writeValueAsString(data);
                }
                return responseBody; // data is null, return as-is
            }
        } catch (Exception ignored) {
            // Not a JSON object or parse error — return as-is
        }
        return responseBody;
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
        Object details = null;
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
            details = errorObj.get("details");
        } else if (errorField != null) {
            message = String.valueOf(errorField);
        }

        throw switch (status) {
            case 401 -> new AuthenticationException(message, code, status, details);
            case 403 -> new ForbiddenException(message, code, status, details);
            case 404 -> new NotFoundException(message, code, status, details);
            case 409 -> new ConflictException(message, code, status, details);
            case 400, 422 -> new ValidationException(message, code, status, details); // SDK-E: 422 → ValidationException
            case 429 -> new RateLimitException(message, code, status, details);
            default  -> new ApexMailException(message, code, status, details);
        };
    }

    public static boolean verifyWebhookSignature(
        String payload,
        String signatureHeader,
        String secret,
        Duration tolerance
    ) {
        return verifyWebhookSignature(payload, signatureHeader, secret, tolerance, null);
    }

    public static boolean verifyWebhookSignature(String payload, String signatureHeader, String secret) {
        return verifyWebhookSignature(payload, signatureHeader, secret, Duration.ofMinutes(5), null);
    }

    /**
     * Validates a webhook signature in the platform's exact wire format
     * (worker-processors/src/webhook/processor.rs):
     *
     * <pre>
     *   X-ApexMail-Signature: sha256=&lt;hex hmac-sha256&gt;
     *   X-ApexMail-Timestamp: &lt;milliseconds since epoch&gt;
     *   signed message: "{timestamp_millis}.{payload}"
     * </pre>
     *
     * Pass the {@code X-ApexMail-Timestamp} header in {@code timestampHeader}
     * — the platform sends milliseconds (auto-detected and compared against
     * {@code System.currentTimeMillis()}), and the signed string always uses
     * the timestamp digits verbatim. The legacy combined header form
     * {@code "t=<seconds>,v1=<hex>"} remains supported when no separate
     * timestamp header is given.
     */
    public static boolean verifyWebhookSignature(
        String payload,
        String signatureHeader,
        String secret,
        Duration tolerance,
        String timestampHeader
    ) {
        if (payload == null || signatureHeader == null || signatureHeader.isBlank() || secret == null || secret.isBlank()) {
            return false;
        }
        SignatureParts parts = SignatureParts.parse(signatureHeader);
        if (parts.signature() == null || parts.signature().isBlank()) {
            return false;
        }
        // SDK-E: a missing timestamp (neither the platform
        // X-ApexMail-Timestamp header nor a legacy t= field) must be
        // rejected — substituting "now" made the tolerance window vacuous.
        String timestampText = timestampHeader != null && !timestampHeader.isBlank()
            ? timestampHeader.trim()
            : parts.timestampText();
        if (timestampText == null || timestampText.isBlank()) {
            return false;
        }
        long timestamp;
        try {
            timestamp = Long.parseLong(timestampText);
        } catch (NumberFormatException error) {
            return false;
        }
        long toleranceSeconds = tolerance != null ? tolerance.getSeconds() : 300L;
        // Auto-detect seconds vs milliseconds: the platform sends ms.
        long now;
        long toleranceLimit;
        if (timestamp > MS_DETECTION_CUTOFF) {
            now = System.currentTimeMillis();
            toleranceLimit = toleranceSeconds * 1000L;
        } else {
            now = System.currentTimeMillis() / 1000L;
            toleranceLimit = toleranceSeconds;
        }
        if (Math.abs(now - timestamp) > toleranceLimit) {
            return false;
        }

        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
            // Sign with the timestamp digits EXACTLY as delivered (ms on
            // the platform path) — never a normalized form.
            byte[] expected = toHex(mac.doFinal((timestampText + "." + payload).getBytes(StandardCharsets.UTF_8)))
                .getBytes(StandardCharsets.UTF_8);
            byte[] supplied = parts.signature().getBytes(StandardCharsets.UTF_8);
            return MessageDigest.isEqual(expected, supplied);
        } catch (Exception error) {
            return false;
        }
    }

    /** Timestamps above this cannot be epoch seconds (2001-09-09); below it they cannot be epoch ms. */
    private static final long MS_DETECTION_CUTOFF = 1_000_000_000_000L;

    private static String toHex(byte[] bytes) {
        StringBuilder builder = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            builder.append(String.format("%02x", b));
        }
        return builder.toString();
    }

    public record RateLimitInfo(Long limit, Long remaining, Long reset, String retryAfter) {
        static RateLimitInfo from(HttpResponse<?> response) {
            Long limit = headerLong(response, "X-RateLimit-Limit");
            Long remaining = headerLong(response, "X-RateLimit-Remaining");
            Long reset = headerLong(response, "X-RateLimit-Reset");
            String retryAfter = response.headers().firstValue("Retry-After").orElse(null);
            if (limit == null && remaining == null && reset == null && retryAfter == null) {
                return null;
            }
            return new RateLimitInfo(limit, remaining, reset, retryAfter);
        }

        private static Long headerLong(HttpResponse<?> response, String name) {
            return response.headers().firstValue(name).flatMap(value -> {
                try {
                    return Optional.of(Long.parseLong(value.trim()));
                } catch (NumberFormatException ignored) {
                    return Optional.empty();
                }
            }).orElse(null);
        }
    }

    private record SignatureParts(String timestampText, String signature) {
        static SignatureParts parse(String header) {
            String timestampText = null;
            String signature = null;
            for (String part : header.split(",")) {
                String trimmed = part.trim();
                int sep = trimmed.indexOf('=');
                if (sep > 0) {
                    String key = trimmed.substring(0, sep);
                    String value = trimmed.substring(sep + 1);
                    if ("t".equals(key)) {
                        if (value.isBlank() || !value.chars().allMatch(Character::isDigit)) {
                            return new SignatureParts(null, null);
                        }
                        timestampText = value;
                    } else if ("v1".equals(key)) {
                        signature = value;
                    }
                }
            }
            if (signature == null) {
                signature = header.startsWith("sha256=") ? header.substring("sha256=".length()).trim() : header.trim();
            }
            return new SignatureParts(timestampText, signature);
        }
    }

    /**
     * Computes retry delay using the formula:
     * {@code delay = max(retryAfterSeconds, baseDelay * attempt²)},
     * capped at {@link #DEFAULT_MAX_RETRY_AFTER} (120s).
     * <p>
     * The server's requested delay is honored in full up to that cap
     * (SDK-F: previously truncated at 5s) while quadratic backoff on its own
     * remains capped at {@link #DEFAULT_MAX_BACKOFF}.
     * Package-private for unit testing.
     */
    static Duration retryDelay(HttpResponse<?> response, int attempt) {
        long retryAfterSeconds = -1;
        Optional<String> retryAfter = response.headers().firstValue("Retry-After");
        if (retryAfter.isPresent()) {
            String header = retryAfter.get().trim();
            // Try integer seconds first (most common)
            try {
                retryAfterSeconds = Long.parseLong(header);
            } catch (NumberFormatException ignored) {
                // Try HTTP-date format (RFC 1123, e.g. "Wed, 21 Oct 2015 07:28:00 GMT")
                try {
                    ZonedDateTime retryAt = ZonedDateTime.parse(header, DateTimeFormatter.RFC_1123_DATE_TIME);
                    long now = System.currentTimeMillis();
                    long retryAtMs = retryAt.toInstant().toEpochMilli();
                    if (retryAtMs > now) {
                        retryAfterSeconds = (retryAtMs - now + 999) / 1000; // ceil division
                    } else {
                        retryAfterSeconds = 0; // retry time already passed
                    }
                } catch (Exception ignored2) {
                    // Unparseable header — fall through to backoff
                }
            }
        }

        // Compute quadratic backoff: baseDelay * max(1, attempt)² — the
        // first retry must use the base delay, not 0 (F8: a 0-based
        // exponent produced a 0s delay, an immediate hammer at a server
        // that had just said "slow down").
        long backoffMillis = DEFAULT_INITIAL_BACKOFF.toMillis() * (long) (Math.max(1, attempt) * Math.max(1, attempt));

        // Use max(retryAfter, quadraticBackoff), then cap at 120s
        if (retryAfterSeconds > 0) {
            long retryAfterMillis = retryAfterSeconds * 1000L;
            if (retryAfterMillis > backoffMillis) {
                backoffMillis = retryAfterMillis;
            }
        }

        return backoffMillis > DEFAULT_MAX_RETRY_AFTER.toMillis()
            ? DEFAULT_MAX_RETRY_AFTER
            : Duration.ofMillis(backoffMillis);
    }

    /**
     * Quadratic backoff used when no Retry-After header is available
     * (e.g. on network-level IO errors).
     * Formula: {@code baseDelay * max(1, attempt)²}, capped at
     * {@link #DEFAULT_MAX_BACKOFF} — the first retry always waits at least
     * the base delay (F8).
     */
    private static Duration calculateBackoff(int attempt) {
        if (attempt < 1) {
            attempt = 1;
        }
        if (attempt > 30) {
            attempt = 30;
        }
        long millis = DEFAULT_INITIAL_BACKOFF.toMillis() * (long) (attempt * attempt);
        return millis > DEFAULT_MAX_BACKOFF.toMillis()
            ? DEFAULT_MAX_BACKOFF
            : Duration.ofMillis(millis);
    }

    private HttpRequest buildRequest(String method, String path, String jsonBody, String idempotencyKey) {
        HttpRequest.Builder builder = HttpRequest.newBuilder()
            .uri(URI.create(baseUrl + path))
            // SDK-E: bound each request with the configured timeout. Without
            // a request-level timeout only the connect timeout applied and a
            // slow server could hang a request forever.
            .timeout(timeout)
            .header("X-API-Key", apiKey)
            .header("Content-Type", "application/json")
            .header("Accept", "application/json")
            .header("User-Agent", "apexmail-java/1.0.0");

        if (idempotencyKey != null && !idempotencyKey.isBlank()) {
            // Header injection: strip control characters (CR/LF/NUL) from
            // caller-supplied keys before they reach the transport.
            String safeKey = idempotencyKey.codePoints()
                .filter(cp -> cp >= 0x20 && cp != 0x7F)
                .collect(StringBuilder::new, StringBuilder::appendCodePoint, StringBuilder::append)
                .toString();
            if (safeKey.length() > 128) {
                safeKey = safeKey.substring(0, 128);
            }
            if (!safeKey.isBlank()) {
                builder.header("X-Idempotency-Key", safeKey);
            }
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

    private static void waitForRetry(Duration delay) throws InterruptedException {
        if (delay == null || delay.isNegative() || delay.isZero()) {
            return;
        }
        Thread.sleep(delay.toMillis());
    }

    private static void sleepBackoff(int attempt) throws InterruptedException {
        waitForRetry(jittered(calculateBackoff(attempt)));
    }

    /**
     * Applies up to ±20% jitter so clients retrying in lockstep spread out
     * (thundering herd). The delay is never shortened by more than 20%, so
     * an honored Retry-After window is preserved.
     */
    private static Duration jittered(Duration delay) {
        if (delay.isZero() || delay.isNegative()) {
            return delay;
        }
        long jitterNanos = delay.dividedBy(5).toNanos();
        if (jitterNanos <= 0) {
            jitterNanos = 1;
        }
        long delta = (long) ((Math.random() * 2 - 1) * jitterNanos);
        long result = delay.toNanos() + delta;
        return result < 0 ? Duration.ZERO : Duration.ofNanos(result);
    }

    @Override
    public void close() {
        if (executor != null) {
            executor.shutdown();
        }
        try {
            if (executor != null && !executor.awaitTermination(5, TimeUnit.SECONDS)) {
                executor.shutdownNow();
            }
        } catch (InterruptedException e) {
            if (executor != null) executor.shutdownNow();
            Thread.currentThread().interrupt();
        }
    }

    @Override
    public String toString() {
        String masked = apiKey.length() > 8
            ? apiKey.substring(0, 4) + "\u2026\u2026" + apiKey.substring(apiKey.length() - 4)
            : "[REDACTED]";
        return "ApexMailClient{apiKey=" + masked + ", baseUrl=" + baseUrl + "}";
    }
}
