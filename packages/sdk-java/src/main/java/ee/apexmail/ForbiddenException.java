package ee.apexmail;

/** Thrown when access is forbidden (HTTP 403). */
public final class ForbiddenException extends ApexMailException {
    public ForbiddenException(String message, String code, int statusCode) {
        super(message, code, statusCode);
    }
}
