package ee.apexmail;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSession;
import java.io.IOException;
import java.net.Authenticator;
import java.net.CookieHandler;
import java.net.ProxySelector;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpHeaders;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executor;
import java.util.concurrent.Flow;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class TemplatesRenderTest {
    private RecordingHttpClient httpClient;

    @AfterEach
    void tearDown() {
        httpClient = null;
    }

    @Test
    void renderUsesVariablesPayload() throws Exception {
        httpClient = new RecordingHttpClient();

        try (ApexMailClient client = new ApexMailClient(
            "am_test_1234567890abcdef",
            "https://api.apexmail.test",
            Duration.ofSeconds(5),
            httpClient
        )) {
            Templates.RenderResponse response = client.templates().render(
                "template-123",
                Map.of("first_name", "Alice")
            );

            assertEquals("POST", httpClient.method.get());
            assertEquals("/v1/templates/template-123/render", httpClient.path.get());
            assertTrue(httpClient.body.get().contains("\"variables\""), httpClient.body.get());
            assertTrue(httpClient.body.get().contains("\"first_name\":\"Alice\""), httpClient.body.get());
            assertFalse(httpClient.body.get().contains("\"data\""), httpClient.body.get());
            assertEquals("Welcome", response.subject());
            assertEquals("<p>Hello Alice</p>", response.html());
            assertEquals("Hello Alice", response.text());
        }
    }

    @Test
    void renderNilDataSendsEmptyVariablesObject() throws Exception {
        httpClient = new RecordingHttpClient();

        try (ApexMailClient client = new ApexMailClient(
            "am_test_1234567890abcdef",
            "https://api.apexmail.test",
            Duration.ofSeconds(5),
            httpClient
        )) {
            Templates.RenderResponse response = client.templates().render("template-123", null);

            assertEquals("POST", httpClient.method.get());
            assertEquals("/v1/templates/template-123/render", httpClient.path.get());
            assertTrue(httpClient.body.get().contains("\"variables\":{}"), httpClient.body.get());
            assertFalse(httpClient.body.get().contains("\"data\""), httpClient.body.get());
            assertEquals("Welcome", response.subject());
        }
    }

    private static final class RecordingHttpClient extends HttpClient {
        private final AtomicReference<String> method = new AtomicReference<>();
        private final AtomicReference<String> path = new AtomicReference<>();
        private final AtomicReference<String> body = new AtomicReference<>();

        @Override
        public Optional<CookieHandler> cookieHandler() {
            return Optional.empty();
        }

        @Override
        public Optional<Duration> connectTimeout() {
            return Optional.of(Duration.ofSeconds(5));
        }

        @Override
        public HttpClient.Redirect followRedirects() {
            return HttpClient.Redirect.NEVER;
        }

        @Override
        public Optional<ProxySelector> proxy() {
            return Optional.empty();
        }

        @Override
        public SSLContext sslContext() {
            return null;
        }

        @Override
        public SSLParameters sslParameters() {
            return new SSLParameters();
        }

        @Override
        public Optional<Authenticator> authenticator() {
            return Optional.empty();
        }

        @Override
        public HttpClient.Version version() {
            return HttpClient.Version.HTTP_1_1;
        }

        @Override
        public Optional<Executor> executor() {
            return Optional.empty();
        }

        @Override
        @SuppressWarnings("unchecked")
        public <T> HttpResponse<T> send(HttpRequest request, HttpResponse.BodyHandler<T> responseBodyHandler)
            throws IOException {
            method.set(request.method());
            path.set(request.uri().getPath());
            body.set(extractBody(request));
            return (HttpResponse<T>) new SimpleHttpResponse(
                request,
                200,
                "{\"html\":\"<p>Hello Alice</p>\",\"text\":\"Hello Alice\",\"subject\":\"Welcome\"}"
            );
        }

        @Override
        public <T> CompletableFuture<HttpResponse<T>> sendAsync(
            HttpRequest request,
            HttpResponse.BodyHandler<T> responseBodyHandler
        ) {
            try {
                return CompletableFuture.completedFuture(send(request, responseBodyHandler));
            } catch (IOException error) {
                CompletableFuture<HttpResponse<T>> failed = new CompletableFuture<>();
                failed.completeExceptionally(error);
                return failed;
            }
        }

        @Override
        public <T> CompletableFuture<HttpResponse<T>> sendAsync(
            HttpRequest request,
            HttpResponse.BodyHandler<T> responseBodyHandler,
            HttpResponse.PushPromiseHandler<T> pushPromiseHandler
        ) {
            return sendAsync(request, responseBodyHandler);
        }

        private String extractBody(HttpRequest request) throws IOException {
            if (request.bodyPublisher().isEmpty()) {
                return "";
            }

            BodyCollector collector = new BodyCollector();
            request.bodyPublisher().orElseThrow().subscribe(collector);
            return collector.body();
        }
    }

    private static final class SimpleHttpResponse implements HttpResponse<String> {
        private final HttpRequest request;
        private final int statusCode;
        private final String body;

        private SimpleHttpResponse(HttpRequest request, int statusCode, String body) {
            this.request = request;
            this.statusCode = statusCode;
            this.body = body;
        }

        @Override
        public int statusCode() {
            return statusCode;
        }

        @Override
        public HttpRequest request() {
            return request;
        }

        @Override
        public Optional<HttpResponse<String>> previousResponse() {
            return Optional.empty();
        }

        @Override
        public HttpHeaders headers() {
            return HttpHeaders.of(Map.of("Content-Type", List.of("application/json")), (left, right) -> true);
        }

        @Override
        public String body() {
            return body;
        }

        @Override
        public Optional<SSLSession> sslSession() {
            return Optional.empty();
        }

        @Override
        public URI uri() {
            return request.uri();
        }

        @Override
        public HttpClient.Version version() {
            return HttpClient.Version.HTTP_1_1;
        }
    }

    private static final class BodyCollector implements Flow.Subscriber<ByteBuffer> {
        private final StringBuilder content = new StringBuilder();
        private final CompletableFuture<Void> finished = new CompletableFuture<>();

        @Override
        public void onSubscribe(Flow.Subscription subscription) {
            subscription.request(Long.MAX_VALUE);
        }

        @Override
        public void onNext(ByteBuffer item) {
            content.append(StandardCharsets.UTF_8.decode(item.duplicate()));
        }

        @Override
        public void onError(Throwable throwable) {
            finished.completeExceptionally(throwable);
        }

        @Override
        public void onComplete() {
            finished.complete(null);
        }

        private String body() throws IOException {
            try {
                finished.join();
                return content.toString();
            } catch (RuntimeException error) {
                throw new IOException("failed to collect request body", error);
            }
        }
    }
}