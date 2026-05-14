package ee.apexmail;

/** Thrown when rate limit is exceeded (HTTP 429). */
public final class RateLimitException extends ApexMailException {
    public RateLimitException(String message, String code, int statusCode) {
        super(message, code, statusCode);
    }

    public RateLimitException(String message, String code, int statusCode, Object details) {
        super(message, code, statusCode, details);
    }
}
