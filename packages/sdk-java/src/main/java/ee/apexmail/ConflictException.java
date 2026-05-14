package ee.apexmail;

/** Thrown when a conflict occurs (HTTP 409). */
public final class ConflictException extends ApexMailException {
    public ConflictException(String message, String code, int statusCode) {
        super(message, code, statusCode);
    }

    public ConflictException(String message, String code, int statusCode, Object details) {
        super(message, code, statusCode, details);
    }
}
