package ee.apexmail;

/** Thrown when the API key is missing, invalid, or revoked (HTTP 401). */
public final class AuthenticationException extends ApexMailException {
    public AuthenticationException(String message, String code, int statusCode) {
        super(message, code, statusCode);
    }

    public AuthenticationException(String message, String code, int statusCode, Object details) {
        super(message, code, statusCode, details);
    }
}
