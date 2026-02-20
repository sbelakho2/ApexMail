package ee.apexmail;

/** Thrown when the requested resource does not exist (HTTP 404). */
public final class NotFoundException extends ApexMailException {
    public NotFoundException(String message, String code, int statusCode) {
        super(message, code, statusCode);
    }
}
