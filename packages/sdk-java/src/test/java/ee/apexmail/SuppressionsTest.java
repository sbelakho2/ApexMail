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
import static org.junit.jupiter.api.Assertions.assertTrue;

class SuppressionsTest {
    private RecordingHttpClient httpClient;

    @AfterEach
    void tearDown() {
        httpClient = null;
    }

    @Test
    void checkUsesPathEndpoint() throws Exception {
        httpClient = new RecordingHttpClient();

        try (ApexMailClient client = new ApexMailClient(
            "am_test_1234567890abcdef",
            "https://api.apexmail.test",
            Duration.ofSeconds(5),
            httpClient
        )) {
            Suppressions.CheckResponse response = client.suppressions().check("bad@example.com");

            assertEquals("GET", httpClient.method.get());
            assertEquals("/v1/suppressions/check/bad%40example.com", httpClient.path.get());
            assertEquals("", httpClient.query.get());
            assertTrue(response.suppressed());
            assertEquals("bounce", response.reason());
        }
    }

    private static final class RecordingHttpClient extends HttpClient {
        private final AtomicReference<String> method = new AtomicReference<>();
        private final AtomicReference<String> path = new AtomicReference<>();
        private final AtomicReference<String> query = new AtomicReference<>("");

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
        public <T> HttpResponse<T> send(HttpRequest request, HttpResponse.BodyHandler<T> responseBodyHandler)
            throws IOException {
            method.set(request.method());
            path.set(request.uri().getRawPath());
            query.set(Optional.ofNullable(request.uri().getQuery()).orElse(""));
            return handlerResponse(request, responseBodyHandler, 200,
                "{\"suppressed\":true,\"reason\":\"bounce\"}");
        }

        /**
         * Builds a response by feeding the canned body through the caller's
         * BodyHandler so any handler (ofString, ofInputStream, ...) works.
         */
        private static <T> HttpResponse<T> handlerResponse(
            HttpRequest request,
            HttpResponse.BodyHandler<T> responseBodyHandler,
            int status,
            String body
        ) {
            HttpResponse.ResponseInfo info = new HttpResponse.ResponseInfo() {
                @Override public int statusCode() { return status; }
                @Override public HttpHeaders headers() {
                    return HttpHeaders.of(Map.of("Content-Type", List.of("application/json")), (l, r) -> true);
                }
                @Override public HttpClient.Version version() { return HttpClient.Version.HTTP_1_1; }
            };
            HttpResponse.BodySubscriber<T> subscriber = responseBodyHandler.apply(info);
            subscriber.onSubscribe(new Flow.Subscription() {
                @Override public void request(long n) {}
                @Override public void cancel() {}
            });
            subscriber.onNext(List.of(ByteBuffer.wrap(body.getBytes(StandardCharsets.UTF_8))));
            subscriber.onComplete();
            T parsed = subscriber.getBody().toCompletableFuture().join();
            return new HttpResponse<>() {
                @Override public int statusCode() { return status; }
                @Override public HttpRequest request() { return request; }
                @Override public Optional<HttpResponse<T>> previousResponse() { return Optional.empty(); }
                @Override public HttpHeaders headers() { return info.headers(); }
                @Override public T body() { return parsed; }
                @Override public Optional<SSLSession> sslSession() { return Optional.empty(); }
                @Override public URI uri() { return request.uri(); }
                @Override public HttpClient.Version version() { return HttpClient.Version.HTTP_1_1; }
            };
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
    }

}