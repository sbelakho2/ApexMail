package ee.apexmail;

/**
 * Base exception for all ApexMail SDK errors.
 */
public class ApexMailException extends RuntimeException {

    private final String code;
    private final int statusCode;

    public ApexMailException(String message) {
        this(message, null, 0);
    }

    public ApexMailException(String message, Throwable cause) {
        super(message, cause);
        this.code       = null;
        this.statusCode = 0;
    }

    public ApexMailException(String message, String code, int statusCode) {
        super(message);
        this.code       = code;
        this.statusCode = statusCode;
    }

    /** Machine-readable error code returned by the API (may be null). */
    public String getCode() { return code; }

    /** HTTP status code (0 for network-level errors). */
    public int getStatusCode() { return statusCode; }

    @Override
    public String toString() {
        return getClass().getSimpleName() +
            "[status=" + statusCode + ", code=" + code + "]: " + getMessage();
    }
}

// ── Typed sub-classes ─────────────────────────────────────────────────────
