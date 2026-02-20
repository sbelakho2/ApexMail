package ee.apexmail;

/** Thrown when request validation fails (HTTP 422). */
public final class ValidationException extends ApexMailException {
    public ValidationException(String message, String code, int statusCode) {
        super(message, code, statusCode);
    }
}
